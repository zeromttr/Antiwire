//! Maps [`antiwire_policy::EnforcementOp`] intents to host firewall rules via [`firew_rs`].

#![allow(clippy::missing_errors_doc)]

/// Manager tag identifying rules this daemon owns.
///
/// Also the prefix of country rule keys, so the names shown by the OS are
/// recognisably ours.
pub(crate) const MANAGER_PREFIX: &str = "antiwire";

/// Whether a rule on an application can be enforced on this system.
///
/// Such a rule becomes a firewall rule that matches the program, which only the Windows
/// firewall backends have. Elsewhere it is refused when it is added, so the API says so
/// up front and the client offers none.
pub const APPLICATION_RULES_SUPPORTED: bool = firew_rs::APPLICATION_MATCHERS_SUPPORTED;

mod country;
mod error;
mod filter;
mod firew;
mod mapping;
mod worker;

pub use error::{EnforceError, Result};

#[cfg(any(test, feature = "test-support"))]
pub use filter::FirewallFilter;

pub use worker::{EnforcementClient, FailedOp};

/// Removes firewall rules this daemon installed.
///
/// Used when the daemon dies without running its own stop path. Persistent
/// mode is the caller's decision; this always removes the managed set.
///
/// # Errors
///
/// Returns an error when the firewall backend cannot be opened or a removal fails.
pub fn purge_ephemeral_rules() -> Result<()> {
    firew::purge_ephemeral_rules()
}

/// Removes only the firewall rules a dead daemon left that must not outlive
/// its DNS resolver (the `DoH` blocks), keeping the rest.
///
/// Used in place of [`purge_ephemeral_rules`] when rules persist offline.
///
/// # Errors
///
/// Returns an error when the firewall backend cannot be opened or a removal fails.
pub fn purge_resolver_dependent_rules() -> Result<()> {
    firew::purge_resolver_dependent_rules()
}
