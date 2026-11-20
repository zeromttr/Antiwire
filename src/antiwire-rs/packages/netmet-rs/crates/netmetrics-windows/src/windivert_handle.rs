//! An open handle on the official `WinDivert` 2.2.2 DLL, shared by the flow-owner
//! listener and the DNS divert.
//!
//! The DLL is loaded at run time from the verified package and never linked, so the
//! LGPL library stays a separate component. Each [`Divert`] holds its own reference
//! to the DLL and releases the handle, the DLL, and the file locks together on drop.

use std::ffi::{CStr, CString};
use std::fs;
use std::io;
use std::iter;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;
use std::ptr;

use crate::divert_error::DivertError;
use crate::windivert_opt_in::refuse_unless_enabled;
use windows::Win32::Foundation::{
    ERROR_ACCESS_DENIED, ERROR_INVALID_IMAGE_HASH, ERROR_INVALID_PARAMETER, FreeLibrary, HANDLE,
    HMODULE, WIN32_ERROR,
};
use windows::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryW};
use windows::core::{PCSTR, PCWSTR};

const SHUTDOWN_RECV: u32 = 0x1;

/// `WINDIVERT_ADDRESS` from `WinDivert` 2.2.2. The trailing 64 bytes are the layer union.
#[repr(C)]
pub(crate) struct DivertAddress {
    pub(crate) timestamp: i64,
    /// `Layer:8`, `Event:8`, then the flag bits documented in `windivert.h`.
    pub(crate) layer_event: u32,
    pub(crate) reserved2: u32,
    pub(crate) data: [u8; 64],
}

impl DivertAddress {
    pub(crate) const fn zeroed() -> Self {
        Self {
            timestamp: 0,
            layer_event: 0,
            reserved2: 0,
            data: [0; 64],
        }
    }
}

type OpenFn = unsafe extern "system" fn(PCSTR, u32, i16, u64) -> HANDLE;
type RecvFn = unsafe extern "system" fn(HANDLE, *mut u8, u32, *mut u32, *mut DivertAddress) -> i32;
type SendFn =
    unsafe extern "system" fn(HANDLE, *const u8, u32, *mut u32, *const DivertAddress) -> i32;
type ChecksumsFn = unsafe extern "system" fn(*mut u8, u32, *mut DivertAddress, u64) -> i32;
type ShutdownFn = unsafe extern "system" fn(HANDLE, u32) -> i32;
type CloseFn = unsafe extern "system" fn(HANDLE) -> i32;

/// A loaded DLL, freed on drop.
struct Library(HMODULE);

impl Library {
    fn load(path: &Path) -> Result<Self, String> {
        let wide: Vec<u16> = path
            .as_os_str()
            .encode_wide()
            .chain(iter::once(0))
            .collect();
        // SAFETY: `wide` is a NUL-terminated path that outlives the call.
        let module = unsafe { LoadLibraryW(PCWSTR(wide.as_ptr())) }
            .map_err(|error| format!("LoadLibrary {} failed: {error}", path.display()))?;
        Ok(Self(module))
    }

    /// Resolves the export `name` as a function pointer of type `T`.
    ///
    /// # Safety
    ///
    /// `T` must be the `unsafe extern "system" fn` type of that export, and the pointer
    /// must not be called after this `Library` is dropped.
    unsafe fn export<T>(&self, name: &CStr) -> Result<T, String> {
        const { assert!(size_of::<T>() == size_of::<usize>()) };
        // SAFETY: the module is loaded and `name` is a NUL-terminated export name.
        let address = unsafe { GetProcAddress(self.0, PCSTR(name.as_ptr().cast())) }
            .ok_or_else(|| format!("WinDivert export {} is missing", name.to_string_lossy()))?;
        // SAFETY: the caller guarantees `T` is the export's function type, and the
        // assertion above keeps `transmute_copy` from reading past the pointer.
        Ok(unsafe { std::mem::transmute_copy(&address) })
    }
}

impl Drop for Library {
    fn drop(&mut self) {
        // SAFETY: the module was loaded in `load` and is freed once, here.
        unsafe {
            let _ = FreeLibrary(self.0);
        }
    }
}

/// An open `WinDivert` handle.
///
/// Share it through an `Arc` with the thread that receives on it: [`Divert::shutdown_recv`]
/// unblocks that thread, and the handle closes once the last reference drops.
pub(crate) struct Divert {
    handle: HANDLE,
    recv: RecvFn,
    send: SendFn,
    checksums: ChecksumsFn,
    shutdown: ShutdownFn,
    close: CloseFn,
    // Fields drop in order after `Drop::drop` has closed the handle: the DLL is freed,
    // then the verified files are unlocked.
    _library: Library,
    _files: (fs::File, fs::File),
}

impl Divert {
    /// Installs the official package if needed and opens a handle with `filter`.
    ///
    /// The DLL and driver stay locked against replacement for as long as the handle is open.
    ///
    /// # Errors
    ///
    /// Refuses, before anything is fetched or loaded, while `WinDivert` is turned off
    /// ([`crate::set_windivert_enabled`]).
    ///
    /// Otherwise says whether a later call could succeed. The manual lists the errors of
    /// `WinDivertOpen` (<https://reqrypt.org/windivert-doc.html#divert_open>): a caller
    /// without Administrator privileges (`ERROR_ACCESS_DENIED`), an invalid filter, layer
    /// or flags (`ERROR_INVALID_PARAMETER`) and a driver without a valid signature
    /// (`ERROR_INVALID_IMAGE_HASH`) fail the same way every time. The others can pass: an
    /// incompatible driver still loaded, a driver blocked by other software, and a Base
    /// Filtering Engine that is not running, which it is not yet early in boot.
    pub(crate) fn open(filter: &str, layer: u32, flags: u64) -> Result<Self, DivertError> {
        refuse_unless_enabled()?;
        let directory = crate::windivert_package::ensure_official_package()?;
        // The download can take minutes, and `WinDivert` may have been turned off
        // meanwhile. Nothing is loaded then.
        refuse_unless_enabled()?;
        // A file replaced or removed since it was verified is verified again, and fetched
        // again, by the next call.
        let files = crate::windivert_package::lock_verified_files(&directory)
            .map_err(DivertError::passing)?;
        let library =
            Library::load(&directory.join("WinDivert.dll")).map_err(DivertError::passing)?;
        // SAFETY: each type matches the prototype in `windivert.h` 2.2, and every pointer
        // is stored beside `library`, which outlives all calls through them.
        let (open, recv, send, checksums, shutdown, close) = unsafe {
            (
                library.export::<OpenFn>(c"WinDivertOpen")?,
                library.export::<RecvFn>(c"WinDivertRecv")?,
                library.export::<SendFn>(c"WinDivertSend")?,
                library.export::<ChecksumsFn>(c"WinDivertHelperCalcChecksums")?,
                library.export::<ShutdownFn>(c"WinDivertShutdown")?,
                library.export::<CloseFn>(c"WinDivertClose")?,
            )
        };
        let filter = CString::new(filter).map_err(|error| error.to_string())?;
        // SAFETY: `filter` is a NUL-terminated string that outlives the call.
        let handle = unsafe { open(PCSTR(filter.as_ptr().cast()), layer, 0, flags) };
        if handle.is_invalid() {
            let error = io::Error::last_os_error();
            let detail = format!("WinDivertOpen failed: {error}");
            let code = error
                .raw_os_error()
                .and_then(|code| u32::try_from(code).ok())
                .map(WIN32_ERROR);
            return Err(
                if matches!(
                    code,
                    Some(ERROR_ACCESS_DENIED | ERROR_INVALID_PARAMETER | ERROR_INVALID_IMAGE_HASH)
                ) {
                    DivertError::lasting(detail)
                } else {
                    DivertError::passing(detail)
                },
            );
        }
        Ok(Self {
            handle,
            recv,
            send,
            checksums,
            shutdown,
            close,
            _library: library,
            _files: files,
        })
    }

    /// Blocks for the next packet or event, returning the byte count `WinDivert` reported.
    ///
    /// An empty `packet` receives the event only, as at the FLOW layer. Returns `None`
    /// once the handle has been shut down or fails.
    pub(crate) fn recv(&self, packet: &mut [u8], address: &mut DivertAddress) -> Option<usize> {
        let (buffer, len) = if packet.is_empty() {
            (ptr::null_mut(), 0)
        } else {
            let len = u32::try_from(packet.len()).unwrap_or(u32::MAX);
            (packet.as_mut_ptr(), len)
        };
        let mut received = 0u32;
        // SAFETY: `buffer` is null or writable for `len` bytes, `received` and `address`
        // are live, and `self` keeps the handle open for the call.
        let ok = unsafe { (self.recv)(self.handle, buffer, len, &raw mut received, address) };
        (ok != 0).then_some(received as usize)
    }

    /// Recomputes the IP and transport checksums of a packet about to be reinjected.
    /// Returns false when `WinDivert` could not, which leaves the old checksums in place.
    pub(crate) fn calc_checksums(&self, packet: &mut [u8], address: &mut DivertAddress) -> bool {
        let Ok(len) = u32::try_from(packet.len()) else {
            return false;
        };
        // SAFETY: `packet` is writable for `len` bytes and `address` is live.
        unsafe { (self.checksums)(packet.as_mut_ptr(), len, address, 0) != 0 }
    }

    /// Reinjects a packet; returns whether `WinDivert` accepted it.
    pub(crate) fn send(&self, packet: &[u8], address: &DivertAddress) -> bool {
        let Ok(len) = u32::try_from(packet.len()) else {
            return false;
        };
        let mut sent = 0u32;
        // SAFETY: `packet` is readable for `len` bytes, `sent` and `address` are live, and
        // `self` keeps the handle open for the call.
        unsafe { (self.send)(self.handle, packet.as_ptr(), len, &raw mut sent, address) != 0 }
    }

    /// Makes a blocked and every later [`Divert::recv`] return `None`.
    pub(crate) fn shutdown_recv(&self) {
        // SAFETY: the handle is open until `Drop`, which cannot run while `&self` is live.
        unsafe {
            (self.shutdown)(self.handle, SHUTDOWN_RECV);
        }
    }
}

impl Drop for Divert {
    fn drop(&mut self) {
        // SAFETY: the last reference is gone, so no call is using the handle, and it is
        // closed once, here, before `_library` frees the code behind `close`.
        unsafe {
            (self.close)(self.handle);
        }
    }
}
