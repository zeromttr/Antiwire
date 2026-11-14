//! macOS PF ioctl backend.

#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "macos")]
mod pf_rules;
pub mod pf_table;

#[cfg(target_os = "macos")]
pub use macos::MacOsBackend;

#[cfg(not(target_os = "macos"))]
mod unsupported {
    use firew_core::{Error, ErrorKind};
    use firew_sys::BackendPreference;

    /// Cross-compile stub.
    #[derive(Debug, Default)]
    pub struct MacOsBackend;

    firew_sys::unavailable_backend!(
        MacOsBackend,
        name = "macos-stub",
        reason = "stub",
        open = |config| {
            if !matches!(
                config.prefer_backend,
                BackendPreference::Auto | BackendPreference::Pf
            ) {
                return Error::new(
                    ErrorKind::BackendUnavailable,
                    "invalid backend preference for macos",
                );
            }
            Error::new(
                ErrorKind::BackendUnavailable,
                "macos backend unavailable on this target",
            )
        }
    );
}

#[cfg(not(target_os = "macos"))]
pub use unsupported::MacOsBackend;
