//! The pcap ABI, loaded at run time from Npcap or libpcap: native calls and the safe wrappers
//! around them.
#![allow(unsafe_code)]

use libloading::Library;
use std::ffi::{c_char, c_int, c_uchar, c_uint, c_void, CStr, CString};
use std::ptr::{self, NonNull};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

const PCAP_ERROR_BUFFER_SIZE: usize = 256;
const PCAP_IF_LOOPBACK: u32 = 0x0000_0001;
const PCAP_NETMASK_UNKNOWN: u32 = 0xffff_ffff;
#[cfg(windows)]
const ADDRESS_FAMILY_IPV4: i32 = 2;
#[cfg(windows)]
const ADDRESS_FAMILY_IPV6: i32 = 23;
#[cfg(not(windows))]
const ADDRESS_FAMILY_IPV4: i32 = libc::AF_INET;
#[cfg(not(windows))]
const ADDRESS_FAMILY_IPV6: i32 = libc::AF_INET6;

#[repr(C)]
struct PcapInterface {
    next: *mut Self,
    name: *mut c_char,
    description: *mut c_char,
    addresses: *mut PcapAddress,
    flags: c_uint,
}

#[repr(C)]
struct PcapAddress {
    next: *mut Self,
    address: *mut libc::sockaddr,
    netmask: *mut libc::sockaddr,
    broadcast_address: *mut libc::sockaddr,
    destination_address: *mut libc::sockaddr,
}

#[repr(C)]
struct PcapPacketHeader {
    timestamp: libc::timeval,
    captured_length: u32,
    original_length: u32,
}

#[repr(C)]
struct BpfProgram {
    length: c_uint,
    instructions: *mut c_void,
}

#[repr(C)]
#[derive(Default)]
struct PcapStatistics {
    received: u32,
    dropped: u32,
    interface_dropped: u32,
    #[cfg(windows)]
    captured: u32,
    // Npcap SDK 1.16, Include/pcap/pcap.h: Windows has six u_int fields.
    // https://npcap.com/dist/npcap-sdk-1.16.zip
    #[cfg(windows)]
    sent: u32,
    #[cfg(windows)]
    network_dropped: u32,
}

type FindAllDevices = unsafe extern "C" fn(*mut *mut PcapInterface, *mut c_char) -> c_int;
type FreeAllDevices = unsafe extern "C" fn(*mut PcapInterface);
type CreateCapture = unsafe extern "C" fn(*const c_char, *mut c_char) -> *mut c_void;
type SetInteger = unsafe extern "C" fn(*mut c_void, c_int) -> c_int;
type ActivateCapture = unsafe extern "C" fn(*mut c_void) -> c_int;
type CompileFilter =
    unsafe extern "C" fn(*mut c_void, *mut BpfProgram, *const c_char, c_int, u32) -> c_int;
type SetFilter = unsafe extern "C" fn(*mut c_void, *mut BpfProgram) -> c_int;
type FreeFilter = unsafe extern "C" fn(*mut BpfProgram);
type NextPacket =
    unsafe extern "C" fn(*mut c_void, *mut *mut PcapPacketHeader, *mut *const c_uchar) -> c_int;
type DataLink = unsafe extern "C" fn(*mut c_void) -> c_int;
type CaptureStats = unsafe extern "C" fn(*mut c_void, *mut PcapStatistics) -> c_int;
type CaptureError = unsafe extern "C" fn(*mut c_void) -> *const c_char;
type CloseCapture = unsafe extern "C" fn(*mut c_void);
type SetNonblocking = unsafe extern "C" fn(*mut c_void, c_int, *mut c_char) -> c_int;
#[cfg(not(windows))]
type SelectableDescriptor = unsafe extern "C" fn(*mut c_void) -> c_int;
#[cfg(not(windows))]
type RequiredSelectTimeout = unsafe extern "C" fn(*mut c_void) -> *const libc::timeval;
#[cfg(windows)]
type CaptureEvent = unsafe extern "C" fn(*mut c_void) -> *mut c_void;

struct PcapApi {
    _library: Library,
    _dependency_libraries: Vec<Library>,
    find_all_devices: FindAllDevices,
    free_all_devices: FreeAllDevices,
    create_capture: CreateCapture,
    set_snap_length: SetInteger,
    set_promiscuous: SetInteger,
    set_timeout: SetInteger,
    set_buffer_size: SetInteger,
    activate_capture: ActivateCapture,
    compile_filter: CompileFilter,
    set_filter: SetFilter,
    free_filter: FreeFilter,
    next_packet: NextPacket,
    data_link: DataLink,
    capture_stats: CaptureStats,
    capture_error: CaptureError,
    close_capture: CloseCapture,
    set_nonblocking: SetNonblocking,
    #[cfg(not(windows))]
    selectable_descriptor: SelectableDescriptor,
    #[cfg(not(windows))]
    required_select_timeout: RequiredSelectTimeout,
    #[cfg(windows)]
    capture_event: CaptureEvent,
}

#[derive(Debug, Clone)]
pub struct NativeDevice {
    pub name: String,
    pub description: String,
    pub addresses: Vec<String>,
    pub loopback: bool,
}

#[derive(Debug)]
pub struct NativePacket {
    pub timestamp_us: u64,
    pub captured_length: u32,
    pub original_length: u32,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct NativeStatistics {
    pub dropped: u64,
    pub interface_dropped: u64,
}

/// Why [`NativeCapture::open`] could not open a capture.
#[derive(Debug)]
pub enum OpenError {
    /// The caller's filter is not one the capture library accepts.
    InvalidFilter(String),
    /// The library, the interface, or one of its settings failed.
    Failed(String),
}

impl std::fmt::Display for OpenError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidFilter(detail) => write!(formatter, "invalid capture filter: {detail}"),
            Self::Failed(detail) => formatter.write_str(detail),
        }
    }
}

impl From<String> for OpenError {
    fn from(detail: String) -> Self {
        Self::Failed(detail)
    }
}

#[derive(Debug)]
pub enum NextPacketResult {
    Packet(NativePacket),
    Timeout,
}

static PCAP_API: OnceLock<Result<Arc<PcapApi>, String>> = OnceLock::new();

fn library_candidates() -> Vec<String> {
    #[cfg(windows)]
    {
        let mut candidates = Vec::new();
        if let Some(windows_directory) =
            std::env::var_os("SystemRoot").or_else(|| std::env::var_os("WINDIR"))
        {
            let system32 = std::path::PathBuf::from(windows_directory).join("System32");
            candidates.push(
                system32
                    .join("Npcap")
                    .join("wpcap.dll")
                    .to_string_lossy()
                    .into_owned(),
            );
            candidates.push(system32.join("wpcap.dll").to_string_lossy().into_owned());
        }
        candidates
    }
    #[cfg(target_os = "macos")]
    {
        vec![
            "/usr/lib/libpcap.A.dylib".to_owned(),
            "libpcap.dylib".to_owned(),
        ]
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        // The library's own name is `libpcap.so.1`. Debian and Ubuntu kept the name their
        // `libpcap0.8` package had before upstream chose one, and `libpcap.so` exists only
        // where the development package is installed.
        vec![
            "libpcap.so.1".to_owned(),
            "libpcap.so.0.8".to_owned(),
            "libpcap.so".to_owned(),
        ]
    }
}

unsafe fn load_symbol<T: Copy>(library: &Library, name: &[u8]) -> Result<T, String> {
    // SAFETY: Every requested symbol uses the C ABI and signature published by libpcap.
    // The owning Library is retained inside PcapApi for at least as long as these pointers.
    unsafe { library.get::<T>(name) }
        .map(|symbol| *symbol)
        .map_err(|error| error.to_string())
}

fn load_api() -> Result<Arc<PcapApi>, String> {
    let mut failures = Vec::new();
    for candidate in library_candidates() {
        let dependency_libraries = match load_dependency_libraries(&candidate) {
            Ok(libraries) => libraries,
            Err(error) => {
                failures.push(format!("{candidate}: {error}"));
                continue;
            }
        };
        // SAFETY: Library lifetime is retained by PcapApi and all calls use declared C symbols.
        let library = match unsafe { Library::new(&candidate) } {
            Ok(library) => library,
            Err(error) => {
                failures.push(format!("{candidate}: {error}"));
                continue;
            }
        };

        // SAFETY: The symbol types below mirror the corresponding libpcap declarations.
        let loaded = unsafe {
            (|| -> Result<PcapApi, String> {
                Ok(PcapApi {
                    find_all_devices: load_symbol(&library, b"pcap_findalldevs\0")?,
                    free_all_devices: load_symbol(&library, b"pcap_freealldevs\0")?,
                    create_capture: load_symbol(&library, b"pcap_create\0")?,
                    set_snap_length: load_symbol(&library, b"pcap_set_snaplen\0")?,
                    set_promiscuous: load_symbol(&library, b"pcap_set_promisc\0")?,
                    set_timeout: load_symbol(&library, b"pcap_set_timeout\0")?,
                    set_buffer_size: load_symbol(&library, b"pcap_set_buffer_size\0")?,
                    activate_capture: load_symbol(&library, b"pcap_activate\0")?,
                    compile_filter: load_symbol(&library, b"pcap_compile\0")?,
                    set_filter: load_symbol(&library, b"pcap_setfilter\0")?,
                    free_filter: load_symbol(&library, b"pcap_freecode\0")?,
                    next_packet: load_symbol(&library, b"pcap_next_ex\0")?,
                    data_link: load_symbol(&library, b"pcap_datalink\0")?,
                    capture_stats: load_symbol(&library, b"pcap_stats\0")?,
                    capture_error: load_symbol(&library, b"pcap_geterr\0")?,
                    close_capture: load_symbol(&library, b"pcap_close\0")?,
                    set_nonblocking: load_symbol(&library, b"pcap_setnonblock\0")?,
                    #[cfg(not(windows))]
                    selectable_descriptor: load_symbol(&library, b"pcap_get_selectable_fd\0")?,
                    #[cfg(not(windows))]
                    required_select_timeout: load_symbol(
                        &library,
                        b"pcap_get_required_select_timeout\0",
                    )?,
                    #[cfg(windows)]
                    capture_event: load_symbol(&library, b"pcap_getevent\0")?,
                    _library: library,
                    _dependency_libraries: dependency_libraries,
                })
            })()
        };
        match loaded {
            Ok(api) => return Ok(Arc::new(api)),
            Err(error) => failures.push(format!("{candidate}: {error}")),
        }
    }
    Err(format!(
        "could not load libpcap/Npcap ({})",
        failures.join("; ")
    ))
}

#[cfg(windows)]
fn load_dependency_libraries(candidate: &str) -> Result<Vec<Library>, String> {
    let Some(parent) = std::path::Path::new(candidate).parent() else {
        return Ok(Vec::new());
    };
    let packet_library = parent.join("Packet.dll");
    if !packet_library.is_file() {
        return Ok(Vec::new());
    }
    // SAFETY: Packet.dll is loaded from the same absolute system directory as wpcap.dll and is
    // retained for the full lifetime of the dependent capture library.
    unsafe { Library::new(&packet_library) }
        .map(|library| vec![library])
        .map_err(|error| format!("could not load {}: {error}", packet_library.display()))
}

#[cfg(not(windows))]
#[expect(
    clippy::unnecessary_wraps,
    reason = "matches the Windows version, which can fail"
)]
fn load_dependency_libraries(_candidate: &str) -> Result<Vec<Library>, String> {
    Ok(Vec::new())
}

fn api() -> Result<Arc<PcapApi>, String> {
    PCAP_API.get_or_init(load_api).clone()
}

fn error_buffer_message(buffer: &[c_char]) -> String {
    let bytes = buffer
        .iter()
        .take_while(|character| **character != 0)
        .map(|character| character.to_ne_bytes()[0])
        .collect::<Vec<_>>();
    String::from_utf8_lossy(&bytes).into_owned()
}

pub fn discover_devices() -> Result<Vec<NativeDevice>, String> {
    let api = api()?;
    let mut devices = ptr::null_mut();
    let mut error_buffer = [0 as c_char; PCAP_ERROR_BUFFER_SIZE];
    // SAFETY: Pointers refer to initialized storage and remain valid for this call.
    let result = unsafe { (api.find_all_devices)(&raw mut devices, error_buffer.as_mut_ptr()) };
    if result != 0 {
        return Err(error_buffer_message(&error_buffer));
    }

    let mut output = Vec::new();
    let mut current = devices;
    while let Some(device) = NonNull::new(current) {
        // SAFETY: The linked list is owned by libpcap until pcap_freealldevs below.
        let device = unsafe { device.as_ref() };
        if !device.name.is_null() {
            // SAFETY: libpcap device strings are NUL-terminated for the list lifetime.
            let name = unsafe { CStr::from_ptr(device.name) }
                .to_string_lossy()
                .into_owned();
            let description = if device.description.is_null() {
                String::new()
            } else {
                // SAFETY: Same lifetime and termination guarantee as the device name.
                unsafe { CStr::from_ptr(device.description) }
                    .to_string_lossy()
                    .into_owned()
            };
            output.push(NativeDevice {
                name,
                description,
                // SAFETY: the address list belongs to this pcap device and remains live until
                // pcap_freealldevs is called after enumeration completes.
                addresses: unsafe { interface_addresses(device.addresses) },
                loopback: device.flags & PCAP_IF_LOOPBACK != 0,
            });
        }
        current = device.next;
    }
    if !devices.is_null() {
        // SAFETY: devices is the head returned by pcap_findalldevs and is freed exactly once.
        unsafe { (api.free_all_devices)(devices) };
    }
    Ok(output)
}

unsafe fn interface_addresses(mut address: *mut PcapAddress) -> Vec<String> {
    let mut output = Vec::new();
    while let Some(entry) = NonNull::new(address) {
        // SAFETY: callers pass a pcap-owned linked list that remains valid for this traversal.
        let entry = unsafe { entry.as_ref() };
        if let Some(socket_address) = NonNull::new(entry.address) {
            // SAFETY: pcap_addr_t::addr points to a sockaddr matching the reported family.
            let family = i32::from(unsafe { socket_address.as_ref().sa_family });
            match family {
                ADDRESS_FAMILY_IPV4 => {
                    // SAFETY: every supported sockaddr_in layout places the address after the
                    // two-byte family/length pair and two-byte port, at byte offset four.
                    let bytes = unsafe { socket_address.as_ptr().cast::<u8>().add(4) };
                    // SAFETY: an IPv4 address always occupies four bytes at this offset.
                    let octets = unsafe { std::slice::from_raw_parts(bytes, 4) };
                    output.push(
                        std::net::Ipv4Addr::new(octets[0], octets[1], octets[2], octets[3])
                            .to_string(),
                    );
                }
                ADDRESS_FAMILY_IPV6 => {
                    // SAFETY: every supported sockaddr_in6 layout places the address after the
                    // family/length, port, and flow-info fields, at byte offset eight.
                    let bytes = unsafe { socket_address.as_ptr().cast::<u8>().add(8) };
                    // SAFETY: an IPv6 address always occupies sixteen bytes at this offset.
                    let octets = unsafe { std::slice::from_raw_parts(bytes, 16) };
                    let mut address_bytes = [0_u8; 16];
                    address_bytes.copy_from_slice(octets);
                    output.push(std::net::Ipv6Addr::from(address_bytes).to_string());
                }
                _ => {}
            }
        }
        address = entry.next;
    }
    output.sort_unstable();
    output.dedup();
    output
}

pub struct NativeCapture {
    api: Arc<PcapApi>,
    handle: NonNull<c_void>,
    link_layer: u32,
    wait: PacketWait,
}

/// What a capture waits on between reads, for at most `longest`.
///
/// The handle is nonblocking, because a blocking read cannot be relied on to return:
/// pcap(3PCAP) says the packet buffer timeout "cannot be used to cause calls that read
/// packets to return within a limited period of time", and that on some platforms "the timer
/// doesn't start until at least one packet arrives". A worker waiting here instead sees a
/// stop request within `longest` even when no packet ever comes.
struct PacketWait {
    /// From `pcap_get_selectable_fd(3PCAP)`; owned by the pcap handle, never closed here.
    #[cfg(not(windows))]
    descriptor: c_int,
    /// From `pcap_getevent`, which the Npcap API guide calls "the Windows alternative to
    /// `pcap_get_selectable_fd()`"; owned by the pcap handle, never closed here.
    #[cfg(windows)]
    event: *mut c_void,
    longest: Duration,
}

impl PacketWait {
    /// Puts the active `handle` in nonblocking mode and finds what to wait on.
    fn prepare(api: &PcapApi, handle: NonNull<c_void>, timeout_ms: u32) -> Result<Self, String> {
        let mut error_buffer = [0 as c_char; PCAP_ERROR_BUFFER_SIZE];
        // SAFETY: handle is active, and the error buffer is PCAP_ERRBUF_SIZE (256) bytes, as
        // pcap_setnonblock(3PCAP) requires.
        let result =
            unsafe { (api.set_nonblocking)(handle.as_ptr(), 1, error_buffer.as_mut_ptr()) };
        if result != 0 {
            return Err(format!(
                "could not make the capture nonblocking: {}",
                error_buffer_message(&error_buffer)
            ));
        }
        let longest = Duration::from_millis(u64::from(timeout_ms.max(1)));
        Self::platform(api, handle, longest)
    }

    #[cfg(not(windows))]
    fn platform(api: &PcapApi, handle: NonNull<c_void>, longest: Duration) -> Result<Self, String> {
        // SAFETY: handle is active; pcap_get_selectable_fd(3PCAP) returns a descriptor the
        // handle owns, or -1 when there is none.
        let descriptor = unsafe { (api.selectable_descriptor)(handle.as_ptr()) };
        if descriptor < 0 {
            return Err("the capture device has no descriptor to wait on".to_owned());
        }
        // pcap_get_required_select_timeout(3PCAP): a non-null result is the longest a wait
        // may last before reading again, for a device whose descriptor may not become
        // readable on its own.
        // SAFETY: handle is active; the result is null or points to a timeval the handle
        // owns, read here before any other call on the handle.
        let required = unsafe { (api.required_select_timeout)(handle.as_ptr()).as_ref() };
        let longest = required.map_or(longest, |required| {
            let required = Duration::from_secs(u64::try_from(required.tv_sec).unwrap_or(0))
                + Duration::from_micros(u64::try_from(required.tv_usec).unwrap_or(0));
            longest.min(required.max(Duration::from_millis(1)))
        });
        Ok(Self {
            descriptor,
            longest,
        })
    }

    #[cfg(windows)]
    fn platform(api: &PcapApi, handle: NonNull<c_void>, longest: Duration) -> Result<Self, String> {
        // SAFETY: handle is an active live capture; pcap_getevent returns the event it owns.
        let event = unsafe { (api.capture_event)(handle.as_ptr()) };
        if event.is_null() {
            return Err("the capture device has no event to wait on".to_owned());
        }
        Ok(Self { event, longest })
    }

    /// Waits until the device may have packets, or `longest` passes.
    #[cfg(not(windows))]
    fn wait(&self) -> Result<(), String> {
        let mut descriptor = libc::pollfd {
            fd: self.descriptor,
            events: libc::POLLIN,
            revents: 0,
        };
        let millis = c_int::try_from(self.longest.as_millis()).unwrap_or(c_int::MAX);
        // SAFETY: poll(2) reads and writes exactly the one initialized pollfd it is given.
        if unsafe { libc::poll(&raw mut descriptor, 1, millis) } < 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() != std::io::ErrorKind::Interrupted {
                return Err(format!("waiting for packets failed: {error}"));
            }
        }
        Ok(())
    }

    /// Waits until the device may have packets, or `longest` passes.
    #[cfg(windows)]
    fn wait(&self) -> Result<(), String> {
        use windows::Win32::Foundation::{HANDLE, WAIT_FAILED};
        use windows::Win32::System::Threading::WaitForSingleObject;

        let millis = u32::try_from(self.longest.as_millis()).unwrap_or(u32::MAX - 1);
        // SAFETY: the event belongs to the capture handle, which outlives this wait, and
        // WaitForSingleObject only waits on it.
        if unsafe { WaitForSingleObject(HANDLE(self.event), millis) } == WAIT_FAILED {
            return Err(format!(
                "waiting for packets failed: {}",
                std::io::Error::last_os_error()
            ));
        }
        Ok(())
    }
}

impl NativeCapture {
    pub fn open(
        device_name: &str,
        snap_length: u32,
        promiscuous: bool,
        timeout_ms: u32,
        filter: &str,
    ) -> Result<Self, OpenError> {
        let api = api()?;
        let device_name = CString::new(device_name)
            .map_err(|_| "capture device name contains an embedded NUL".to_owned())?;
        let filter = if filter.trim().is_empty() {
            None
        } else {
            Some(
                CString::new(filter)
                    .map_err(|_| OpenError::InvalidFilter("it contains a NUL".to_owned()))?,
            )
        };
        let mut error_buffer = [0 as c_char; PCAP_ERROR_BUFFER_SIZE];
        // SAFETY: CString and error buffer remain valid for the duration of pcap_create.
        let handle =
            unsafe { (api.create_capture)(device_name.as_ptr(), error_buffer.as_mut_ptr()) };
        let handle = NonNull::new(handle).ok_or_else(|| error_buffer_message(&error_buffer))?;

        let configure = |function: SetInteger, value: c_int, setting: &str| {
            // SAFETY: handle is an inactive pcap handle owned by this function.
            let result = unsafe { function(handle.as_ptr(), value) };
            if result == 0 {
                Ok(())
            } else {
                Err(format!("failed to configure {setting}: error {result}"))
            }
        };

        let configuration_result = configure(
            api.set_snap_length,
            c_int::try_from(snap_length).unwrap_or(c_int::MAX),
            "snapshot length",
        )
        .and_then(|()| {
            configure(
                api.set_promiscuous,
                i32::from(promiscuous),
                "promiscuous mode",
            )
        })
        .and_then(|()| {
            configure(
                api.set_timeout,
                c_int::try_from(timeout_ms).unwrap_or(c_int::MAX),
                "read timeout",
            )
        })
        .and_then(|()| configure(api.set_buffer_size, 4 * 1024 * 1024, "capture buffer"));
        if let Err(error) = configuration_result {
            // SAFETY: handle is owned here and has not yet been activated.
            unsafe { (api.close_capture)(handle.as_ptr()) };
            return Err(error.into());
        }

        // SAFETY: handle is fully configured and owned by this function.
        let activation = unsafe { (api.activate_capture)(handle.as_ptr()) };
        if activation < 0 {
            let error = capture_error(&api, handle);
            // SAFETY: handle is owned here and closed exactly once on failure.
            unsafe { (api.close_capture)(handle.as_ptr()) };
            return Err(error.into());
        }
        let wait = match PacketWait::prepare(&api, handle, timeout_ms) {
            Ok(wait) => wait,
            Err(error) => {
                // SAFETY: handle is owned here and closed exactly once on failure.
                unsafe { (api.close_capture)(handle.as_ptr()) };
                return Err(error.into());
            }
        };

        if let Some(filter) = filter.as_ref() {
            let mut program = BpfProgram {
                length: 0,
                instructions: ptr::null_mut(),
            };
            // SAFETY: handle is active; program points to writable storage; filter is valid C text.
            let compile_result = unsafe {
                (api.compile_filter)(
                    handle.as_ptr(),
                    &raw mut program,
                    filter.as_ptr(),
                    1,
                    PCAP_NETMASK_UNKNOWN,
                )
            };
            if compile_result != 0 {
                let error = capture_error(&api, handle);
                // SAFETY: handle is owned here and no compiled program was produced.
                unsafe { (api.close_capture)(handle.as_ptr()) };
                return Err(OpenError::InvalidFilter(error));
            }
            // SAFETY: program was initialized by pcap_compile for this active handle.
            let set_result = unsafe { (api.set_filter)(handle.as_ptr(), &raw mut program) };
            // SAFETY: pcap_compile succeeded, so the program must be released exactly once.
            unsafe { (api.free_filter)(&raw mut program) };
            if set_result != 0 {
                let error = capture_error(&api, handle);
                // SAFETY: handle is owned here and closed exactly once on failure.
                unsafe { (api.close_capture)(handle.as_ptr()) };
                return Err(format!("could not apply capture filter: {error}").into());
            }
        }

        // SAFETY: handle is active and valid for pcap_datalink.
        let link_layer = unsafe { (api.data_link)(handle.as_ptr()) };
        if link_layer < 0 {
            let error = capture_error(&api, handle);
            // SAFETY: handle is owned here and closed exactly once on failure.
            unsafe { (api.close_capture)(handle.as_ptr()) };
            return Err(format!("could not read capture link type: {error}").into());
        }
        Ok(Self {
            api,
            handle,
            link_layer: u32::try_from(link_layer).unwrap_or_default(),
            wait,
        })
    }

    pub fn link_layer(&self) -> u32 {
        self.link_layer
    }

    /// The next packet, or `Timeout` after waiting at most the read timeout for one.
    pub fn next_packet(&mut self) -> Result<NextPacketResult, String> {
        let mut header = ptr::null_mut();
        let mut data = ptr::null();
        // SAFETY: handle is active and header/data point to writable pointer storage.
        let result =
            unsafe { (self.api.next_packet)(self.handle.as_ptr(), &raw mut header, &raw mut data) };
        match result {
            result if result > 0 => {
                let header = NonNull::new(header)
                    .ok_or_else(|| "libpcap returned a packet without a header".to_owned())?;
                // SAFETY: libpcap guarantees header and packet data until the next capture call.
                let header = unsafe { header.as_ref() };
                let length = usize::try_from(header.captured_length).unwrap_or(usize::MAX);
                // SAFETY: libpcap reports captured_length bytes at data for this packet.
                let bytes = unsafe { copy_packet_data(data, length) }?;
                let seconds = u64::try_from(header.timestamp.tv_sec).unwrap_or_default();
                let microseconds = u64::try_from(header.timestamp.tv_usec).unwrap_or_default();
                Ok(NextPacketResult::Packet(NativePacket {
                    timestamp_us: seconds
                        .saturating_mul(1_000_000)
                        .saturating_add(microseconds),
                    captured_length: header.captured_length,
                    original_length: header.original_length,
                    data: bytes,
                }))
            }
            // A nonblocking handle returns 0 when nothing is buffered yet.
            0 => {
                self.wait.wait()?;
                Ok(NextPacketResult::Timeout)
            }
            -2 => Ok(NextPacketResult::Timeout),
            _ => Err(capture_error(&self.api, self.handle)),
        }
    }

    pub fn statistics(&self) -> Result<NativeStatistics, String> {
        let mut statistics = PcapStatistics::default();
        // SAFETY: handle is active and statistics points to writable storage of sufficient size.
        let result = unsafe { (self.api.capture_stats)(self.handle.as_ptr(), &raw mut statistics) };
        if result == 0 {
            Ok(NativeStatistics {
                dropped: u64::from(statistics.dropped),
                interface_dropped: u64::from(statistics.interface_dropped),
            })
        } else {
            Err(capture_error(&self.api, self.handle))
        }
    }
}

impl Drop for NativeCapture {
    fn drop(&mut self) {
        // SAFETY: NativeCapture exclusively owns this active handle and closes it once.
        unsafe { (self.api.close_capture)(self.handle.as_ptr()) };
    }
}

fn capture_error(api: &PcapApi, handle: NonNull<c_void>) -> String {
    // SAFETY: handle is a live pcap handle and pcap_geterr returns an internal C string.
    let error = unsafe { (api.capture_error)(handle.as_ptr()) };
    if error.is_null() {
        "unknown libpcap error".to_owned()
    } else {
        // SAFETY: non-null pcap_geterr results are NUL-terminated for the handle lifetime.
        unsafe { CStr::from_ptr(error) }
            .to_string_lossy()
            .into_owned()
    }
}

/// # Safety
/// For non-zero `length`, non-null `data` must point to that many readable bytes.
unsafe fn copy_packet_data(data: *const c_uchar, length: usize) -> Result<Vec<u8>, String> {
    if length == 0 {
        return Ok(Vec::new());
    }
    if data.is_null() {
        return Err("libpcap returned a packet without data".to_owned());
    }
    // SAFETY: the caller guarantees readable data; empty/null input was handled above.
    Ok(unsafe { std::slice::from_raw_parts(data, length) }.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn packet_data_handles_empty_null_and_nonempty_buffers() {
        // SAFETY: null is explicitly accepted for empty packets and rejected otherwise.
        assert_eq!(
            unsafe { copy_packet_data(ptr::null(), 0) }.unwrap(),
            Vec::<u8>::new()
        );
        // SAFETY: the helper rejects null without dereferencing it.
        assert!(unsafe { copy_packet_data(ptr::null(), 1) }.is_err());
        let bytes = [1, 2, 3];
        // SAFETY: bytes is readable for its full length.
        assert_eq!(
            unsafe { copy_packet_data(bytes.as_ptr(), bytes.len()) }.unwrap(),
            bytes
        );
    }

    #[cfg(windows)]
    #[test]
    fn statistics_layout_matches_npcap_sdk() {
        assert_eq!(std::mem::size_of::<PcapStatistics>(), 24);
        assert_eq!(std::mem::align_of::<PcapStatistics>(), 4);
        assert_eq!(std::mem::offset_of!(PcapStatistics, captured), 12);
        assert_eq!(std::mem::offset_of!(PcapStatistics, sent), 16);
        assert_eq!(std::mem::offset_of!(PcapStatistics, network_dropped), 20);
    }

    #[cfg(windows)]
    #[test]
    fn windows_capture_libraries_use_absolute_system_paths() {
        let candidates = library_candidates();
        assert_ne!(candidates, [] as [String; 0]);
        assert!(candidates
            .iter()
            .all(|candidate| std::path::Path::new(candidate).is_absolute()));
    }
}
