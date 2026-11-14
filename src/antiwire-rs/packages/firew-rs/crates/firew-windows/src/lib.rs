//! Windows `INetFw` and WFP backends.

pub mod naming;

#[cfg(windows)]
mod inetfw;
#[cfg(windows)]
mod sys;
#[cfg(windows)]
mod validation;
#[cfg(windows)]
mod wfp;
#[cfg(windows)]
mod windows;
#[cfg(windows)]
mod worker;

pub use naming::{legacy_display_name, native_display_name, native_group_name};

#[cfg(windows)]
pub use windows::WindowsBackend;

#[cfg(not(windows))]
mod unsupported {
    use firew_core::{Error, ErrorKind};
    use firew_sys::BackendPreference;

    /// Cross-compile stub.
    #[derive(Debug, Default)]
    pub struct WindowsBackend;

    firew_sys::unavailable_backend!(
        WindowsBackend,
        name = "windows-stub",
        reason = "stub",
        open = |config| {
            if !matches!(
                config.prefer_backend,
                BackendPreference::Auto | BackendPreference::InetFw | BackendPreference::Wfp
            ) {
                return Error::new(
                    ErrorKind::BackendUnavailable,
                    "invalid backend preference for windows",
                );
            }
            Error::new(
                ErrorKind::BackendUnavailable,
                "windows backend unavailable on this target",
            )
        }
    );
}

#[cfg(not(windows))]
pub use unsupported::WindowsBackend;
