//! Points system DNS at Antiwire's resolver, and puts it back.
//!
//! One API on Windows, macOS and Linux for everything that changes the host's
//! DNS configuration:
//!
//! - [`DnsRedirect`] is a resolver's redirect, from the moment the resolver
//!   serves on loopback to the restore when it stops, with the
//!   [`RedirectExtender`] that reaches adapters coming up in between.
//! - [`restore_orphaned`] restores the redirect a daemon that is gone left
//!   behind. The reaper and the boot heal use it.
//! - [`RedirectError`] is why either did not do what was asked.
//! - With the `test-support` feature, `RedirectBackend` replaces the OS calls
//!   both make, so other crates' tests never change the host's DNS.
//!
//! What a platform does is `antiwire-dns-os`'s business: per-adapter settings
//! on Windows, network services on macOS, `/etc/resolv.conf` on Linux. Other
//! crates use this one, so every change to the host's DNS follows the same
//! rules: originals reach disk before anything changes, a record is cleared
//! only after a confirmed restore, and a restore always waits for a change
//! still under way.
//!
//! The record is this crate's own: a table of the store that nothing else
//! writes, and a journal in the daemon's data directory. Both are found
//! through the data directory a caller names, so a running redirect and the
//! recovery of a dead one always look in the same place.

mod backend;
mod blocking;
mod error;
mod extend;
mod host;
mod orphan;
mod record;
mod redirect;
mod restore;
mod restore_retry;
mod state;
#[cfg(test)]
mod test_support;

#[cfg(windows)]
pub use antiwire_dns_os::windows::HEAL_HOST_STATE_FLAG;
pub use backend::flush_cache;
pub use error::RedirectError;
pub use extend::RedirectExtender;
pub use orphan::{restore_orphaned, OrphanedRedirect};
pub use redirect::{DnsRedirect, RedirectOutcome};

#[cfg(any(test, feature = "test-support"))]
pub use antiwire_dns_os::{AppliedRedirect, RedirectCoverage};
#[cfg(any(test, feature = "test-support"))]
pub use backend::RedirectBackend;
