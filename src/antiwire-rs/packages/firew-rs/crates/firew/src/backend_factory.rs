//! Platform backend factory.

use firew_core::Error;
use firew_sys::{Backend, BackendConfig};

#[cfg(all(target_os = "linux", feature = "linux"))]
type PlatformBackend = firew_linux::LinuxBackend;
#[cfg(all(windows, feature = "windows"))]
type PlatformBackend = firew_windows::WindowsBackend;
#[cfg(all(target_os = "macos", feature = "macos"))]
type PlatformBackend = firew_macos::MacOsBackend;

#[cfg(not(any(
    all(target_os = "linux", feature = "linux"),
    all(windows, feature = "windows"),
    all(target_os = "macos", feature = "macos")
)))]
mod stub {
    use firew_core::{Error, ErrorKind};

    pub struct StubBackend;

    firew_sys::unavailable_backend!(
        StubBackend,
        name = "stub",
        reason = "stub",
        open = |_| {
            Error::new(
                ErrorKind::BackendUnavailable,
                "no firewall backend for this target",
            )
        }
    );
}

#[cfg(not(any(
    all(target_os = "linux", feature = "linux"),
    all(windows, feature = "windows"),
    all(target_os = "macos", feature = "macos")
)))]
type PlatformBackend = stub::StubBackend;

/// Opens the platform default backend.
pub fn open_backend(config: &BackendConfig) -> Result<Box<dyn Backend>, Error> {
    Ok(Box::new(PlatformBackend::open(config)?))
}
