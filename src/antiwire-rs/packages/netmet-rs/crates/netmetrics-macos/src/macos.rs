use crate::bpf_records::{BUFFER_LENGTHS, MIN_BUFFER_LEN};
use crate::flows::{KnownFlows, SeenPacket, SocketCoverage, SocketTable};
use crate::interface_counters::interface_stats;
use crate::pktap;
use crate::process_watch::KernelProcesses;
use crate::processes::Processes;
use libc::{
    BIOCGBLEN, BIOCGDLT, BIOCGSTATS, BIOCIMMEDIATE, BIOCSBLEN, BIOCSETIF, F_GETFL, F_SETFL,
    O_NONBLOCK, c_int, c_ulong, close, fcntl, ioctl, open, read,
};
use netmetrics_core::unix_now_ms;
use netmetrics_core::{
    CookieSource, DegradeReason, DnsCallerIdentity, FlowKey, LocalEndpoint, Protocol, SocketCookie,
    SocketOwnerSnapshot, TcpState,
};
use netmetrics_sys::endpoint_owner::EndpointOwnerSource;
use netmetrics_sys::{
    Backend, BackendConfig, BackendError, BackendErrorKind, BackendEvent, BackgroundRead,
    DnsCapture, EventSink, FlowSources, InterfaceIndexes, NATIVE_RETRY_INTERVAL, StopFlag,
    TotalDelta, run_with_fallback,
};
use std::env;
use std::ffi::CString;
use std::io;
use std::mem;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::process::Command;
use std::time::{Duration, Instant};

/// `_IOC` from XNU's `bsd/sys/ioccom.h`: direction, parameter length, group and number.
const fn ioctl_command(direction: c_ulong, group: u8, number: u8, length: usize) -> c_ulong {
    const IOCPARM_MASK: c_ulong = 0x1fff;
    direction
        | ((length as c_ulong & IOCPARM_MASK) << 16)
        | ((group as c_ulong) << 8)
        | number as c_ulong
}
const IOC_OUT: c_ulong = 0x4000_0000;
const IOC_IN: c_ulong = 0x8000_0000;
const IOC_INOUT: c_ulong = 0xc000_0000;
// The encoder reproduces the public commands libc publishes, so the private ones below,
// which libc does not have, are encoded the same way.
const _: () = assert!(ioctl_command(IOC_IN, b'B', 108, mem::size_of::<libc::ifreq>()) == BIOCSETIF);
const _: () = assert!(ioctl_command(IOC_IN, b'B', 112, mem::size_of::<u32>()) == BIOCIMMEDIATE);

/// `BIOCSWANTPKTAP`, `_IOWR('B', 127, u_int)` in XNU's private `bsd/net/bpf_private.h`. On
/// macOS a BPF descriptor opens without `BPF_WANT_PKTAP`, and binding it to a pktap
/// interface then picks that interface's `DLT_RAW` link instead of `DLT_PKTAP` (`bpf_setif`
/// in `bsd/net/bpf.c`). Apple's libpcap sets it before `BIOCSETIF`, and so does this.
const BIOCSWANTPKTAP: c_ulong = ioctl_command(IOC_INOUT, b'B', 127, mem::size_of::<u32>());

/// `struct bpf_stat` from XNU's `bsd/net/bpf.h`, which `BIOCGSTATS` fills: the packets the
/// descriptor has received and the packets it has dropped.
#[repr(C)]
#[derive(Default)]
struct BpfStat {
    received: u32,
    dropped: u32,
}
// `BIOCGSTATS` is `_IOR('B', 111, struct bpf_stat)`, so its command carries the size.
const _: () = assert!(ioctl_command(IOC_OUT, b'B', 111, mem::size_of::<BpfStat>()) == BIOCGSTATS);

/// `SIOCSDRVSPEC`, `_IOW('i', 123, struct ifdrv)` in XNU's `bsd/sys/sockio.h`.
const SIOCSDRVSPEC: c_ulong = ioctl_command(IOC_IN, b'i', 123, mem::size_of::<IfDrv>());

/// `struct ifdrv` from XNU's `bsd/net/if.h`, which declares it under `#pragma pack(4)`.
#[repr(C, packed(4))]
struct IfDrv {
    name: [libc::c_char; libc::IFNAMSIZ],
    command: c_ulong,
    length: usize,
    data: *mut libc::c_void,
}
const _: () = assert!(mem::size_of::<IfDrv>() == 40);
const _: () = assert!(mem::offset_of!(IfDrv, command) == 16);
const _: () = assert!(mem::offset_of!(IfDrv, length) == 24);
const _: () = assert!(mem::offset_of!(IfDrv, data) == 32);

/// The backend's name in the events it reports.
const BACKEND_NAME: &str = "macos-pktap";
/// The fallback's name in the events it reports.
const SNAPSHOT_SOURCE: &str = "macos-socket-table";

/// PKTAP reader using a non-blocking Berkeley Packet Filter device, with the socket table as
/// its fallback.
#[derive(Debug, Default)]
pub struct MacosBackend;

impl Backend for MacosBackend {
    fn name(&self) -> &'static str {
        BACKEND_NAME
    }

    fn run(
        &mut self,
        config: &BackendConfig,
        sink: EventSink,
        stop: StopFlag,
    ) -> Result<(), BackendError> {
        let max_flows = sink.native_capacity();
        let poll_interval = Duration::from_millis(config.poll_interval_ms.max(250));
        let Some(interface) = env::var_os("NETMETRICS_PKTAP_INTERFACE") else {
            sink.emit(BackendEvent::Degraded(DegradeReason::SnapshotOnly {
                source: SNAPSHOT_SOURCE.to_owned(),
            }));
            if config.dns_hints {
                sink.emit(BackendEvent::Degraded(DegradeReason::SourceUnavailable {
                    source: "macos-dns-hints".to_owned(),
                    detail: "DNS side-channel requires PKTAP packet capture".to_owned(),
                }));
            }
            let mut snapshots = SocketTablePoll::default();
            let mut flows = KnownFlows::new(max_flows);
            while !stop.is_stop_requested() {
                snapshots.poll(&mut flows, &sink);
                stop.wait_timeout(poll_interval);
            }
            return Ok(());
        };
        let (kernel_processes, no_exit_reports) = KernelProcesses::new();
        if let Some(error) = no_exit_reports {
            sink.emit(BackendEvent::Degraded(DegradeReason::SourceUnavailable {
                source: "macos-process-exit".to_owned(),
                detail: format!("kqueue: {error}; process exits are polled for"),
            }));
        }
        let mut sources = PktapSources {
            interface: interface.to_string_lossy().into_owned(),
            dns_hints: config.dns_hints,
            max_flows,
            poll_interval,
            processes: Processes::new(kernel_processes, max_flows),
            snapshots: SocketTablePoll::default(),
        };
        let mut flows = KnownFlows::new(max_flows);
        let result = run_with_fallback(
            &mut sources,
            &mut flows,
            &sink,
            &stop,
            poll_interval,
            NATIVE_RETRY_INTERVAL,
        );
        flows.close_all(unix_now_ms(), &sink);
        result
    }
}

/// PKTAP capture and the socket table, as the backend reads them.
struct PktapSources {
    /// The PKTAP interface `NETMETRICS_PKTAP_INTERFACE` names, not yet checked.
    interface: String,
    dns_hints: bool,
    max_flows: usize,
    poll_interval: Duration,
    /// Kept across both sources: the kernel reports a process's exit whichever one is
    /// running, so a process that exits while capture is down is still reported stopped.
    processes: Processes<KernelProcesses>,
    snapshots: SocketTablePoll,
}

/// A BPF device bound to the PKTAP interface, and the endpoint owners its packets name.
/// Dropping it closes the device and withdraws the owners.
struct BpfDevice {
    descriptor: OwnedFd,
    /// The read size `BIOCGBLEN` requires.
    buffer_len: usize,
    /// Endpoint owners come only from packets, so lookups can use them only while capture
    /// runs: the socket table cannot say who owned an endpoint earlier.
    owners: EndpointOwnerSource,
}

impl FlowSources for PktapSources {
    const BACKEND_NAME: &'static str = BACKEND_NAME;
    const SNAPSHOT_SOURCE: &'static str = SNAPSHOT_SOURCE;
    type Native = BpfDevice;
    /// Both sources keep this one table, so a switch neither announces a flow again nor
    /// leaves one open that the next source would never close.
    type Flows = KnownFlows;

    fn start_native(&mut self, _: &EventSink) -> Result<BpfDevice, BackendError> {
        if !crate::is_safe_interface_name(&self.interface) {
            return Err(BackendError::new(
                BackendErrorKind::Unavailable,
                "pktap-bpf",
                "NETMETRICS_PKTAP_INTERFACE must be 1-15 ASCII letters or digits, starting with a letter",
            ));
        }
        ensure_pktap_interface(&self.interface)?;
        let (descriptor, buffer_len) = open_bpf(&self.interface)?;
        // SAFETY: `open_bpf` returns a descriptor it opened and keeps no copy of, so this is
        // its one owner.
        let descriptor = unsafe { OwnedFd::from_raw_fd(descriptor) };
        Ok(BpfDevice {
            descriptor,
            buffer_len,
            owners: EndpointOwnerSource::default(),
        })
    }

    fn read_native(
        &mut self,
        device: BpfDevice,
        flows: &mut KnownFlows,
        sink: &EventSink,
        stop: &StopFlag,
    ) -> Result<(), BackendError> {
        let owners = &device.owners;
        let fd = device.descriptor.as_raw_fd();
        let mut buffer = vec![0_u8; device.buffer_len];
        // PKTAP captures DNS itself; it is decoded only when asked for.
        let mut dns_capture = self.dns_hints.then(|| DnsCapture::new(self.max_flows));
        let mut next_interface_poll = Instant::now();
        let mut next_socket_poll = Instant::now();
        let mut reported_socket_error = false;
        let mut drops = TotalDelta::default();
        let mut interfaces = InterfaceIndexes::default();
        // Listing every socket of every process takes long enough for the kernel's capture
        // buffers to fill, and what arrives then is dropped. So it runs on a thread of its
        // own, and this one only applies each listing when it is ready.
        let mut socket_listing = BackgroundRead::start("netmetrics-socket-table", || {
            (unix_now_ms(), socket_coverage())
        })
        .map_err(|error| {
            BackendError::new(
                BackendErrorKind::Unavailable,
                SNAPSHOT_SOURCE,
                format!("the socket table thread could not be started: {error}"),
            )
        })?;
        while !stop.is_stop_requested() {
            if Instant::now() >= next_interface_poll {
                emit_interface_stats(sink, unix_now_ms());
                // An interface created again since may have another index.
                interfaces.forget();
                next_interface_poll = Instant::now() + self.poll_interval;
            }
            if Instant::now() >= next_socket_poll {
                if socket_listing.has_stopped() {
                    return Err(BackendError::new(
                        BackendErrorKind::SessionLost,
                        SNAPSHOT_SOURCE,
                        "the socket table thread stopped",
                    ));
                }
                socket_listing.request();
                self.processes.sweep(unix_now_ms(), sink);
                report_capture_drops(fd, &mut drops, sink);
                next_socket_poll = Instant::now() + self.poll_interval;
            }
            match socket_listing.take() {
                Some((read_at, Ok(coverage))) => {
                    flows.close_missing(&coverage, read_at, sink);
                    reported_socket_error = false;
                }
                Some((_, Err(error))) => {
                    flows.expire_idle_udp(unix_now_ms(), sink);
                    if !reported_socket_error {
                        reported_socket_error = true;
                        sink.emit(BackendEvent::Degraded(DegradeReason::SourceUnavailable {
                            source: SNAPSHOT_SOURCE.to_owned(),
                            detail: error.to_string(),
                        }));
                    }
                }
                None => {}
            }
            self.processes.apply_changes(unix_now_ms(), sink);
            owners.processing();
            // SAFETY: buffer is writable for its full length and `fd` stays open while
            // `device` lives.
            let count = unsafe { read(fd, buffer.as_mut_ptr().cast(), buffer.len()) };
            if count < 0 {
                let error = io::Error::last_os_error();
                if error.kind() == io::ErrorKind::WouldBlock {
                    owners.drained();
                    netmetrics_sys::wait_readable(
                        [fd, self.processes.source().readiness_fd()],
                        next_interface_poll.min(next_socket_poll),
                        MAX_READ_WAIT,
                    );
                    continue;
                }
                return Err(BackendError::new(
                    BackendErrorKind::SessionLost,
                    "pktap-bpf",
                    error.to_string(),
                ));
            }
            if count == 0 {
                owners.drained();
                netmetrics_sys::wait_readable(
                    [fd, self.processes.source().readiness_fd()],
                    next_interface_poll.min(next_socket_poll),
                    MAX_READ_WAIT,
                );
                continue;
            }
            parse_bpf_buffer(
                &buffer[..usize::try_from(count).unwrap_or(0)],
                owners,
                sink,
                flows,
                &mut self.processes,
                &mut interfaces,
                dns_capture.as_mut(),
            );
        }
        Ok(())
    }

    /// A table that cannot be read is reported once, and the next poll tries again.
    fn poll_snapshot(
        &mut self,
        flows: &mut KnownFlows,
        sink: &EventSink,
    ) -> Result<(), BackendError> {
        self.snapshots.poll(flows, sink);
        let timestamp = unix_now_ms();
        self.processes.apply_changes(timestamp, sink);
        self.processes.sweep(timestamp, sink);
        Ok(())
    }
}

/// Reads the socket table for the fallback, reporting a failed read once until a read
/// succeeds again.
#[derive(Debug, Default)]
struct SocketTablePoll {
    reported_error: bool,
}

impl SocketTablePoll {
    fn poll(&mut self, flows: &mut KnownFlows, sink: &EventSink) {
        let timestamp = unix_now_ms();
        match socket_table(netstat2::ProtocolFlags::TCP | netstat2::ProtocolFlags::UDP) {
            Ok(table) => {
                self.reported_error = false;
                flows.apply_snapshot(&table, timestamp, sink);
                emit_interface_stats(sink, timestamp);
            }
            Err(error) => {
                if !self.reported_error {
                    self.reported_error = true;
                    sink.emit(BackendEvent::Degraded(DegradeReason::SourceUnavailable {
                        source: SNAPSHOT_SOURCE.to_owned(),
                        detail: error.to_string(),
                    }));
                }
            }
        }
    }
}

/// Creates `interface` if it is missing, brings it up, and sets which interfaces it taps.
fn ensure_pktap_interface(interface: &str) -> Result<(), BackendError> {
    let exists = Command::new("/sbin/ifconfig")
        .arg(interface)
        .output()
        .is_ok_and(|output| output.status.success());
    if !exists {
        ifconfig(interface, "create")?;
    }
    ifconfig(interface, "up")?;
    set_pktap_filters(interface)
}

/// Runs `ifconfig <interface> <action>`. Its output is read, not inherited, so it never
/// reaches the host process's own streams.
fn ifconfig(interface: &str, action: &str) -> Result<(), BackendError> {
    let output = Command::new("/sbin/ifconfig")
        .args([interface, action])
        .output()
        .map_err(|error| {
            BackendError::new(
                BackendErrorKind::Unavailable,
                "pktap-ifconfig",
                error.to_string(),
            )
        })?;
    if output.status.success() {
        Ok(())
    } else {
        Err(BackendError::new(
            BackendErrorKind::Unavailable,
            "pktap-ifconfig",
            format!(
                "ifconfig {interface} {action} failed ({}): {}",
                output.status,
                String::from_utf8_lossy(&output.stderr).trim()
            ),
        ))
    }
}

/// Sets the interface types `interface` taps to [`pktap::filters`], with the
/// `PKTP_CMD_FILTER_SET` driver command (`pktap_setdrvspec` in XNU's `bsd/net/pktap.c`).
fn set_pktap_filters(interface: &str) -> Result<(), BackendError> {
    let mut filters = pktap::filters();
    let mut request = IfDrv {
        name: [0; libc::IFNAMSIZ],
        command: pktap::PKTP_CMD_FILTER_SET,
        length: filters.len(),
        data: filters.as_mut_ptr().cast(),
    };
    // `ensure_pktap_interface`'s caller checked the name: 1-15 ASCII bytes, so it fits with
    // its NUL.
    for (target, source) in request.name.iter_mut().zip(interface.bytes()) {
        *target = libc::c_char::try_from(source).expect("ASCII byte fits c_char");
    }
    // SAFETY: socket(2) takes no pointers; a returned descriptor is owned below.
    let socket = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    if socket < 0 {
        return Err(pktap_filter_error(&io::Error::last_os_error()));
    }
    // SAFETY: `socket` is a fresh descriptor that nothing else owns.
    let socket = unsafe { OwnedFd::from_raw_fd(socket) };
    // SAFETY: `request` is a valid `struct ifdrv` whose `data` points to `length` bytes in
    // `filters`, and both live until the call returns.
    let result = unsafe {
        ioctl(
            std::os::fd::AsRawFd::as_raw_fd(&socket),
            SIOCSDRVSPEC,
            &raw mut request,
        )
    };
    if result < 0 {
        return Err(pktap_filter_error(&io::Error::last_os_error()));
    }
    Ok(())
}

fn pktap_filter_error(error: &io::Error) -> BackendError {
    BackendError::new(
        if error.kind() == io::ErrorKind::PermissionDenied {
            BackendErrorKind::PermissionDenied
        } else {
            BackendErrorKind::Unavailable
        },
        "pktap-filter",
        error.to_string(),
    )
}

fn open_bpf(interface: &str) -> Result<(c_int, usize), BackendError> {
    let mut descriptor = None;
    for index in 0..256 {
        let path = CString::new(format!("/dev/bpf{index}")).expect("static path has no NUL");
        // SAFETY: `path` is NUL terminated and flags request read-only capture.
        let fd = unsafe { open(path.as_ptr(), libc::O_RDONLY) };
        if fd >= 0 {
            descriptor = Some(fd);
            break;
        }
    }
    let fd = descriptor.ok_or_else(|| {
        BackendError::new(
            BackendErrorKind::PermissionDenied,
            "pktap-bpf",
            "no readable /dev/bpf device; root or packet-capture entitlement is required",
        )
    })?;
    // SAFETY: `ifreq` is plain data: a name array and a union of integers, addresses and a
    // pointer, for each of which all zero bytes are a valid value.
    let mut request: libc::ifreq = unsafe { mem::zeroed() };
    if !crate::is_safe_interface_name(interface) {
        // SAFETY: descriptor is owned by this function.
        unsafe {
            close(fd);
        }
        return Err(BackendError::new(
            BackendErrorKind::Unavailable,
            "pktap-bpf",
            "interface name must be 1-15 ASCII letters or digits, starting with a letter",
        ));
    }
    for (target, source) in request.ifr_name.iter_mut().zip(interface.bytes()) {
        *target = libc::c_char::try_from(source).expect("ASCII byte fits c_char");
    }
    let mut enabled: u32 = 1;
    // SAFETY: descriptor and pointer reference an initialized `u_int`, the ioctl's argument.
    let wants_pktap = unsafe { ioctl(fd, BIOCSWANTPKTAP, &raw mut enabled) };
    let configured = attach_with_buffer(fd, &request);
    let mut immediate: u32 = 1;
    // SAFETY: descriptor and pointer reference initialized ioctl ABI values.
    let immediate_result = unsafe { ioctl(fd, BIOCIMMEDIATE, &mut immediate) };
    let mut data_link_type = 0_u32;
    // SAFETY: descriptor and pointer reference initialized ioctl ABI values.
    let dlt_result = unsafe { ioctl(fd, BIOCGDLT, &raw mut data_link_type) };
    let mut buffer_len = 0_u32;
    // SAFETY: descriptor and pointer reference initialized ioctl ABI values.
    let buffer_len_result = unsafe { ioctl(fd, BIOCGBLEN, &raw mut buffer_len) };
    // SAFETY: `fd` is valid; retrieving and restoring flags does not alias memory.
    let flags = unsafe { fcntl(fd, F_GETFL) };
    // SAFETY: `fd` is valid and `flags` came from the preceding call.
    let nonblocking = unsafe { fcntl(fd, F_SETFL, flags | O_NONBLOCK) };
    if dlt_result >= 0
        && let Err(error) = crate::bpf_records::validate_data_link(data_link_type)
    {
        // SAFETY: descriptor is owned by this function.
        unsafe {
            close(fd);
        }
        return Err(BackendError::new(
            BackendErrorKind::Unavailable,
            "pktap-bpf",
            error.to_string(),
        ));
    }
    if wants_pktap < 0
        || configured < 0
        || immediate_result < 0
        || dlt_result < 0
        || buffer_len_result < 0
        || flags < 0
        || nonblocking < 0
    {
        let error = io::Error::last_os_error();
        // SAFETY: descriptor is owned by this function.
        unsafe {
            close(fd);
        }
        return Err(BackendError::new(
            if error.kind() == io::ErrorKind::PermissionDenied {
                BackendErrorKind::PermissionDenied
            } else {
                BackendErrorKind::Unavailable
            },
            "pktap-bpf",
            error.to_string(),
        ));
    }
    // The kernel may give less than was asked for. A buffer too short for a whole packet
    // would lose every packet longer than it, without a word.
    if buffer_len < MIN_BUFFER_LEN {
        // SAFETY: descriptor is owned by this function.
        unsafe {
            close(fd);
        }
        return Err(BackendError::new(
            BackendErrorKind::Unavailable,
            "pktap-bpf",
            format!(
                "the kernel gave a capture buffer of {buffer_len} bytes, and {MIN_BUFFER_LEN} are needed to hold a whole packet"
            ),
        ));
    }
    Ok((fd, usize::try_from(buffer_len).unwrap_or(usize::MAX)))
}

/// Sets the descriptor's buffer length and attaches it to the interface `request` names.
/// Returns what the last ioctl did, and leaves its error in `errno`.
///
/// The length has to be set first: `bpf(4)` says of `BIOCSBLEN` that "the buffer must be
/// set before the file is attached to an interface with BIOCSETIF", and the kernel refuses
/// it afterwards. `BIOCSETIF` is what allocates the buffers (`bpf_allocbufs` in XNU's
/// `bsd/net/bpf.c`). It fails with `ENOMEM` when it cannot, and older kernels with
/// `ENOBUFS`, so each shorter length in [`BUFFER_LENGTHS`] is tried after such a failure.
fn attach_with_buffer(fd: c_int, request: &libc::ifreq) -> c_int {
    let mut attached = -1;
    for length in BUFFER_LENGTHS {
        let mut length = length;
        // SAFETY: descriptor and pointer reference an initialized `u_int`, which the ioctl
        // reads and writes the length it set back to.
        if unsafe { ioctl(fd, BIOCSBLEN, &raw mut length) } < 0 {
            return -1;
        }
        // SAFETY: descriptor and pointer reference an initialized `ifreq`, the ioctl's
        // argument.
        attached = unsafe { ioctl(fd, BIOCSETIF, request) };
        let out_of_memory = matches!(
            io::Error::last_os_error().raw_os_error(),
            Some(libc::ENOMEM | libc::ENOBUFS)
        );
        if attached >= 0 || !out_of_memory {
            break;
        }
    }
    attached
}

/// Reports the packets the kernel dropped from the capture buffer since the last report,
/// from the running total `BIOCGSTATS` gives in `bs_drop`, an unsigned 32-bit count. BPF
/// drops a packet when the reader has not emptied the buffer in time (`bd_dcount` in
/// `catchpacket`). Its bytes were counted nowhere, so flow totals fall short by them.
fn report_capture_drops(fd: c_int, drops: &mut TotalDelta<u32>, sink: &EventSink) {
    let mut stat = BpfStat::default();
    // SAFETY: descriptor and pointer reference an initialized `bpf_stat`, which the ioctl
    // fills.
    if unsafe { ioctl(fd, BIOCGSTATS, &raw mut stat) } < 0 {
        return;
    }
    let dropped = drops.since_last(stat.dropped);
    if dropped > 0 {
        sink.emit(BackendEvent::Degraded(DegradeReason::BufferOverflow {
            dropped,
        }));
    }
}

fn emit_interface_stats(sink: &EventSink, timestamp: u64) {
    match interface_stats(timestamp) {
        Ok(samples) => {
            for sample in samples {
                sink.emit(BackendEvent::Interface(sample));
            }
        }
        Err(error) => {
            sink.emit(BackendEvent::Degraded(DegradeReason::SourceUnavailable {
                source: "macos-interface-mib".to_owned(),
                detail: error.to_string(),
            }));
        }
    }
}

/// Longest wait for packets before the loop checks its stop flag again.
const MAX_READ_WAIT: Duration = Duration::from_millis(250);

fn parse_bpf_buffer(
    buffer: &[u8],
    owners: &EndpointOwnerSource,
    sink: &EventSink,
    flows: &mut KnownFlows,
    processes: &mut Processes<KernelProcesses>,
    interfaces: &mut InterfaceIndexes,
    mut dns_capture: Option<&mut DnsCapture>,
) {
    for record in crate::bpf_records::records(buffer) {
        let Ok(record) = record else {
            break;
        };
        let timestamp = unix_now_ms();
        if let Some(packet) = pktap::decode(record.packet) {
            if let Some(event_at) = record
                .timestamp
                .and_then(netmetrics_sys::endpoint_owner::realtime_event_time)
            {
                owners.record(packet.key, packet.pid, event_at);
            }
            processes.saw(packet.pid, &packet.command, timestamp, sink);
            let cookie = packet.flow_id.map(|flow_id| SocketCookie {
                value: u64::from(flow_id),
                source: CookieSource::MacosFlowId,
            });
            let if_index = interface_index(interfaces, &packet.ifname);
            let delta = flows.saw_packet(
                &SeenPacket {
                    key: packet.key,
                    pid: packet.pid,
                    cookie,
                    if_index,
                    delta: packet.delta,
                    outbound: packet.outbound,
                    tcp_flags: packet.tcp_flags,
                },
                timestamp,
                sink,
            );
            // Nothing is reported for a TCP connection until it is established: bytes
            // would open a flow for it.
            if !delta.is_zero() {
                sink.emit(BackendEvent::Bytes {
                    key: packet.key,
                    pid: packet.pid,
                    delta,
                    timestamp,
                    if_index,
                    // A different flow ID on the same addresses is a new socket that
                    // reused them, and the collector starts a new flow for it.
                    cookie,
                });
            }
            if let (Some(dns), Some(capture)) = (packet.dns, dns_capture.as_deref_mut()) {
                // Only a packet this host sent names who asked. The same query arriving,
                // on loopback or from another host, carries the process it was sent to.
                let caller = if packet.outbound {
                    DnsCallerIdentity {
                        logging_pid: None,
                        requesting_pid: Some(packet.pid).filter(|pid| *pid != 0),
                        resolver_pid: packet.acting_pid,
                    }
                } else {
                    DnsCallerIdentity::default()
                };
                capture.observe(dns, timestamp, sink, |_| caller);
            }
        }
    }
}

fn interface_index(interfaces: &mut InterfaceIndexes, name: &str) -> Option<u32> {
    if !crate::is_safe_interface_name(name) {
        return None;
    }
    interfaces.index(name)
}

/// The state netstat2 reports for a TCP socket.
///
/// netstat2 reads it from `tcpsi_state` of the `tcp_sockinfo` that
/// `proc_pidfdinfo(PROC_PIDFDSOCKETINFO)` fills, which holds a `TSI_S_*` value
/// (`bsd/sys/proc_info.h` in Apple's XNU source): the kernel's own `TCPS_*` state
/// (`bsd/netinet/tcp_fsm.h`). `None` for netstat2's `DeleteTcb` and `Unknown`, which no
/// `TSI_S_*` value becomes.
fn tcp_state(state: netstat2::TcpState) -> Option<TcpState> {
    use netstat2::TcpState as Listed;

    Some(match state {
        Listed::Closed => TcpState::Closed,
        Listed::Listen => TcpState::Listen,
        Listed::SynSent => TcpState::SynSent,
        Listed::SynReceived => TcpState::SynReceived,
        Listed::Established => TcpState::Established,
        Listed::FinWait1 => TcpState::FinWait1,
        Listed::FinWait2 => TcpState::FinWait2,
        Listed::CloseWait => TcpState::CloseWait,
        Listed::Closing => TcpState::Closing,
        Listed::LastAck => TcpState::LastAck,
        Listed::TimeWait => TcpState::TimeWait,
        Listed::DeleteTcb | Listed::Unknown => return None,
    })
}

/// Reads the socket table: its established TCP connections and, when `protocols` has UDP,
/// its bound UDP sockets.
///
/// netstat2 walks every process (`proc_listpids`), each of its descriptors
/// (`proc_pidinfo(PROC_PIDLISTFDS)`) and each socket among those
/// (`proc_pidfdinfo(PROC_PIDFDSOCKETINFO)`), and returns one row per descriptor, naming
/// that one process. So the table holds only sockets a process still has open, and a
/// socket that several descriptors refer to appears once for each; [`SocketTable::list_tcp`]
/// lists it once. A connection that no descriptor refers to is not seen: one a listener
/// has not accepted yet, or one its application has closed.
fn socket_table(protocols: netstat2::ProtocolFlags) -> io::Result<SocketTable> {
    use netstat2::{AddressFamilyFlags, ProtocolSocketInfo, get_sockets_info};

    let sockets = get_sockets_info(
        AddressFamilyFlags::IPV4 | AddressFamilyFlags::IPV6,
        protocols,
    )
    .map_err(io::Error::other)?;
    let mut table = SocketTable::default();
    for socket in sockets {
        match socket.protocol_socket_info {
            ProtocolSocketInfo::Tcp(tcp) => {
                let [pid] = socket.associated_pids.as_slice() else {
                    continue;
                };
                table.list_tcp(
                    FlowKey {
                        protocol: Protocol::Tcp,
                        local_addr: tcp.local_addr,
                        local_port: tcp.local_port,
                        remote_addr: tcp.remote_addr,
                        remote_port: tcp.remote_port,
                    },
                    tcp_state(tcp.state),
                    *pid,
                );
            }
            // Only flows capture announced before it went down use these.
            ProtocolSocketInfo::Udp(udp) if udp.local_port != 0 => {
                table.udp_binds.insert(udp.local_addr, udp.local_port);
            }
            ProtocolSocketInfo::Udp(_) => {}
        }
    }
    Ok(table)
}

/// Reads the socket table for capture, which closes its flows by it.
fn socket_coverage() -> io::Result<SocketCoverage> {
    use netstat2::{AddressFamilyFlags, ProtocolFlags, ProtocolSocketInfo, get_sockets_info};

    let sockets = get_sockets_info(
        AddressFamilyFlags::IPV4 | AddressFamilyFlags::IPV6,
        ProtocolFlags::TCP | ProtocolFlags::UDP,
    )
    .map_err(io::Error::other)?;
    let mut coverage = SocketCoverage::default();
    for socket in sockets {
        match socket.protocol_socket_info {
            ProtocolSocketInfo::Tcp(tcp_socket)
                if tcp_socket.state != netstat2::TcpState::Listen
                    && tcp_socket.local_port != 0
                    && tcp_socket.remote_port != 0 =>
            {
                coverage.tcp.insert(FlowKey {
                    protocol: Protocol::Tcp,
                    local_addr: tcp_socket.local_addr,
                    local_port: tcp_socket.local_port,
                    remote_addr: tcp_socket.remote_addr,
                    remote_port: tcp_socket.remote_port,
                });
            }
            ProtocolSocketInfo::Udp(udp) if udp.local_port != 0 => {
                coverage.udp_binds.insert(udp.local_addr, udp.local_port);
            }
            _ => {}
        }
    }
    Ok(coverage)
}

/// Returns the number of established TCP connections processes on this host hold: the
/// connections the socket-table fallback lists as flows, each counted once however many
/// descriptors refer to it.
///
/// # Errors
///
/// Returns the reason when the socket table cannot be read; that is no count, not zero.
pub fn active_socket_count() -> Result<u32, String> {
    let table = socket_table(netstat2::ProtocolFlags::TCP).map_err(|error| error.to_string())?;
    Ok(u32::try_from(table.connections.len()).unwrap_or(u32::MAX))
}

/// TCP 5-tuple, TCP listener and UDP bind owners from the host socket table.
#[must_use]
pub fn socket_owner_snapshot() -> SocketOwnerSnapshot {
    socket_owners(netstat2::ProtocolFlags::TCP | netstat2::ProtocolFlags::UDP)
}

/// Owners of `protocol`'s sockets only.
///
/// A lookup by local endpoint only ever matches rows of its own protocol, so it gets the
/// same answer from this as from [`socket_owner_snapshot`].
#[must_use]
pub fn socket_owner_snapshot_for(protocol: Protocol) -> SocketOwnerSnapshot {
    socket_owners(match protocol {
        Protocol::Tcp => netstat2::ProtocolFlags::TCP,
        Protocol::Udp => netstat2::ProtocolFlags::UDP,
    })
}

fn socket_owners(protocols: netstat2::ProtocolFlags) -> SocketOwnerSnapshot {
    use netstat2::{AddressFamilyFlags, ProtocolSocketInfo, TcpState, get_sockets_info};

    let Ok(sockets) = get_sockets_info(
        AddressFamilyFlags::IPV4 | AddressFamilyFlags::IPV6,
        protocols,
    ) else {
        return SocketOwnerSnapshot::default();
    };
    let mut snapshot = SocketOwnerSnapshot::default();
    for socket in sockets {
        let [pid] = socket.associated_pids.as_slice() else {
            continue;
        };
        match socket.protocol_socket_info {
            ProtocolSocketInfo::Tcp(tcp)
                if tcp.state != TcpState::Listen && tcp.local_port != 0 && tcp.remote_port != 0 =>
            {
                snapshot.insert_tcp(
                    FlowKey {
                        protocol: Protocol::Tcp,
                        local_addr: tcp.local_addr,
                        local_port: tcp.local_port,
                        remote_addr: tcp.remote_addr,
                        remote_port: tcp.remote_port,
                    },
                    *pid,
                );
            }
            // An inbound connection whose own row has already left the table is attributed
            // to the process listening on its local port.
            ProtocolSocketInfo::Tcp(tcp) if tcp.state == TcpState::Listen => {
                snapshot.insert_tcp_listener(
                    LocalEndpoint {
                        address: tcp.local_addr,
                        port: tcp.local_port,
                    },
                    *pid,
                );
            }
            ProtocolSocketInfo::Udp(udp) if udp.local_port != 0 => {
                snapshot.insert_udp(
                    LocalEndpoint {
                        address: udp.local_addr,
                        port: udp.local_port,
                    },
                    *pid,
                );
            }
            _ => {}
        }
    }
    snapshot
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, TcpListener, TcpStream};

    /// The table as the kernel fills it: a connection this process holds is listed at each
    /// end under this process, also while a second descriptor refers to one end.
    #[test]
    fn the_socket_table_lists_an_established_connection_of_this_process() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("listen");
        let client =
            TcpStream::connect(listener.local_addr().expect("listener address")).expect("connect");
        let (accepted, _) = listener.accept().expect("accept");
        let _second_descriptor = client.try_clone().expect("duplicate the client");

        let table = socket_table(netstat2::ProtocolFlags::TCP).expect("read the socket table");
        for (end, socket) in [("client", &client), ("accepted", &accepted)] {
            let local = socket.local_addr().expect("local address");
            let remote = socket.peer_addr().expect("peer address");
            let key = FlowKey {
                protocol: Protocol::Tcp,
                local_addr: local.ip(),
                local_port: local.port(),
                remote_addr: remote.ip(),
                remote_port: remote.port(),
            };
            assert_eq!(
                table.connections.get(&key),
                Some(&std::process::id()),
                "{end} end"
            );
        }
    }
}
