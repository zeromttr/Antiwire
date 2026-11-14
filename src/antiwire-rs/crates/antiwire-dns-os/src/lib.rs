//! OS DNS resolver backends — Linux, macOS and Windows capture/redirect/restore.
//!
//! Prefer [`backend`] for the active platform. Named platform modules are
//! cfg-gated to their OS (plus `cfg(test)` so unit tests still compile
//! cross-platform). Windows-only boot-heal callers use [`windows`] directly.

#[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
compile_error!("antiwire-dns-os only supports Windows, Linux, and macOS");

mod common;
pub mod redirect_journal;

#[cfg(any(target_os = "linux", test))]
pub mod linux;

#[cfg(any(target_os = "macos", test))]
pub mod macos;

#[cfg(windows)]
pub mod windows;

#[cfg(windows)]
pub use windows as backend;

/// Only Windows registers a boot task to restore DNS. Linux and macOS have
/// nothing to arm or disarm, so their backends offer these as no-ops and
/// callers need no platform check.
#[cfg(not(windows))]
mod no_boot_heal {
    use std::path::Path;

    pub fn register_boot_heal(_data_dir: &Path) {}

    pub fn unregister_boot_heal() {}
}

#[cfg(target_os = "linux")]
pub mod backend {
    pub use crate::linux::{
        apply_redirect, capture_state, flush_cache, plan_redirect, redirect, redirect_capturing,
        restore,
    };
    pub use crate::no_boot_heal::{register_boot_heal, unregister_boot_heal};

    #[must_use]
    pub fn is_elevated() -> bool {
        crate::is_elevated()
    }
}

#[cfg(target_os = "macos")]
pub mod backend {
    pub use crate::macos::{
        apply_redirect, capture_state, flush_cache, plan_redirect, redirect_capturing, restore,
    };
    pub use crate::no_boot_heal::{register_boot_heal, unregister_boot_heal};

    #[must_use]
    pub fn is_elevated() -> bool {
        crate::is_elevated()
    }
}

/// What a redirect changed, as `backend::apply_redirect` reports it when it
/// redirected anything at all.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppliedRedirect {
    /// The snapshot a restore must reverse.
    pub snapshot: String,
    /// Whether the redirect reached every adapter it tried.
    pub coverage: RedirectCoverage,
}

/// How much of its plan a redirect reached.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RedirectCoverage {
    /// Every adapter the plan records and that could be redirected now was:
    /// one that is down or absent is not tried.
    Complete,
    /// Some adapters were redirected and the rest could not be. Those still
    /// resolve through their own DNS, unfiltered, so the caller should apply
    /// the redirect again.
    Partial,
}

impl AppliedRedirect {
    /// A redirect that reached every adapter it tried.
    #[must_use]
    pub fn complete(snapshot: impl Into<String>) -> Self {
        Self {
            snapshot: snapshot.into(),
            coverage: RedirectCoverage::Complete,
        }
    }

    /// Whether the redirect reached every adapter it tried.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.coverage == RedirectCoverage::Complete
    }
}

/// Unix elevation check (`geteuid() == 0`). Windows uses [`windows::is_elevated`].
#[cfg(unix)]
#[must_use]
#[allow(unsafe_code)]
pub(crate) fn is_elevated() -> bool {
    // SAFETY: `geteuid` takes no arguments and has no safety preconditions.
    unsafe { libc::geteuid() == 0 }
}
