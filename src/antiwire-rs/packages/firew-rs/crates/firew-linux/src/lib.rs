//! Linux nftables and iptables backends.

pub mod detect;
mod ipset;
mod iptables;
#[cfg(target_os = "linux")]
mod linux;
mod nftables;

#[cfg(target_os = "linux")]
pub use linux::LinuxBackend;

#[cfg(not(target_os = "linux"))]
mod unsupported {
    use firew_core::{Error, ErrorKind};
    use firew_sys::BackendPreference;

    /// Cross-compile stub.
    #[derive(Debug, Default)]
    pub struct LinuxBackend;

    firew_sys::unavailable_backend!(
        LinuxBackend,
        name = "linux-stub",
        reason = "stub",
        open = |config| {
            if !matches!(
                config.prefer_backend,
                BackendPreference::Auto | BackendPreference::Nftables | BackendPreference::Iptables
            ) {
                return Error::new(
                    ErrorKind::BackendUnavailable,
                    "invalid backend preference for linux",
                );
            }
            Error::new(
                ErrorKind::BackendUnavailable,
                "linux backend unavailable on this target",
            )
        }
    );
}

#[cfg(not(target_os = "linux"))]
pub use unsupported::LinuxBackend;
