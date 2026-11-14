//! The OS calls a redirect is made of.

use std::path::Path;

use antiwire_dns_os::backend as os;
use antiwire_dns_os::AppliedRedirect;

/// Drops answers the OS resolver cached, as when they may have been filtered
/// under a policy that has since changed.
pub use os::flush_cache;

/// The OS calls a redirect makes. Outside tests they are always
/// `RedirectBackend::OS`, the host's own.
///
/// With the `test-support` feature, tests replace some of them, starting from
/// `RedirectBackend::INERT`, to observe a call or to fail it, without changing
/// the host's DNS.
#[derive(Debug, Clone, Copy)]
pub struct RedirectBackend {
    /// Whether this process may change system DNS at all: it must run as
    /// administrator or root.
    pub can_redirect: fn() -> bool,
    /// The snapshot a redirect must be able to reverse, which changes
    /// nothing: `prior`, a snapshot an earlier redirect left recorded, plus
    /// the originals of what it does not cover yet, or a fresh capture
    /// without one. `None` when nothing could be captured.
    pub plan: fn(ipv6: bool, prior: Option<&str>) -> Option<String>,
    /// Points what a plan records, and nothing else, at the loopback
    /// resolver. `None` when nothing was redirected.
    pub apply: fn(ipv6: bool, plan: &str) -> Option<AppliedRedirect>,
    /// Writes a snapshot back. Whether every part of it was confirmed.
    pub restore: fn(snapshot: &str) -> bool,
    /// Arms recovery of the recorded snapshot at the next boot, for a daemon
    /// that may be killed before it restores: on Windows, a boot task that
    /// runs the heal from `data_dir`. Does nothing elsewhere.
    pub arm_boot_recovery: fn(data_dir: &Path),
    /// Disarms boot recovery once nothing is owed a restore.
    pub disarm_boot_recovery: fn(),
}

impl RedirectBackend {
    /// The host's own resolver configuration.
    pub(crate) const OS: Self = Self {
        can_redirect: os::is_elevated,
        // The OS calls take an empty snapshot to mean none.
        plan: |ipv6, prior| os::plan_redirect(ipv6, prior.unwrap_or_default()),
        apply: os::apply_redirect,
        restore: os::restore,
        arm_boot_recovery: os::register_boot_heal,
        disarm_boot_recovery: os::unregister_boot_heal,
    };

    /// Changes nothing: it may not redirect, plans and applies nothing, and
    /// confirms no restore. A base for a test backend to replace calls in.
    #[cfg(any(test, feature = "test-support"))]
    pub const INERT: Self = Self {
        can_redirect: || false,
        plan: |_, _| None,
        apply: |_, _| None,
        restore: |_| false,
        arm_boot_recovery: |_| {},
        disarm_boot_recovery: || {},
    };
}
