//! Reverts host changes after the daemon process is already gone.
//!
//! Stop-path destructors do not run on kill, crash, or abort. The detached
//! reaper calls this once it observes the daemon pid exit, and, outside
//! Windows, so does `--heal-host-state`.

use std::path::Path;

use antiwire_dns::clear_port53_divert;
use antiwire_dns_redirect::{restore_orphaned, OrphanedRedirect};
use antiwire_platform::DataPaths;
use antiwire_store::{DaemonSetting, Store};
use anyhow::Context;
use tracing::{info, warn};

use crate::keystore::platform_keystore;

/// The parts of the daemon's host changes that are not reverted yet, after
/// a daemon's own stop or after a dead daemon's revert.
#[must_use]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct OrphanedPending {
    /// Adapter DNS is still recorded as redirected and was not confirmed
    /// restored.
    pub dns: bool,
    /// Removing the firewall rules failed.
    pub firewall: bool,
}

impl OrphanedPending {
    /// Whether anything is still owed a revert.
    #[must_use]
    pub const fn any(self) -> bool {
        self.dns || self.firewall
    }

    /// What is still owed, for a stop that reports it.
    pub(crate) fn describe(self) -> String {
        let mut pending = Vec::new();
        if self.dns {
            pending.push("adapter DNS was not confirmed restored");
        }
        if self.firewall {
            pending.push("firewall rules were not removed");
        }
        format!(
            "host state was not fully reverted ({}); recovery will retry",
            pending.join(", ")
        )
    }
}

/// What reverting a dead daemon's host changes achieved.
#[must_use]
#[derive(Debug)]
pub struct OrphanedRevert {
    /// What is not reverted yet. [`retry_orphaned_host_state`] tries again.
    pub pending: OrphanedPending,
    /// Whether the store and its settings could be read.
    pub result: anyhow::Result<()>,
}

/// Restores DNS, removes the port-53 divert, and drops firewall rules unless
/// they were marked persistent. Persistent or not, the rules that depend on
/// the resolver are removed.
///
/// A failed DNS or firewall revert is logged and does not hide the other.
/// Either one that fails is reported in [`OrphanedRevert::pending`] for the
/// caller to retry; the DNS recovery record is kept until then.
///
/// `ANTIWIRE_DATA_DIR` must already name `data_dir`: the macOS pf enable
/// token is found through it. The daemon's `main` publishes it before any
/// thread starts, since setting it here, with threads running, is not
/// thread-safe on Unix.
pub fn revert_orphaned_host_state(data_dir: &Path) -> OrphanedRevert {
    clear_port53_divert();

    let loaded = open_settings(data_dir);
    let pending = OrphanedPending {
        dns: restore_dns(data_dir, &loaded),
        firewall: !revert_firewall(&loaded),
    };
    OrphanedRevert {
        pending,
        result: loaded.map(|_| ()),
    }
}

/// Tries again what `pending` says [`revert_orphaned_host_state`] left
/// undone, and nothing else. Returns what is still pending.
pub fn retry_orphaned_host_state(data_dir: &Path, pending: OrphanedPending) -> OrphanedPending {
    let loaded = open_settings(data_dir);
    OrphanedPending {
        dns: pending.dns && restore_dns(data_dir, &loaded),
        firewall: pending.firewall && !revert_firewall(&loaded),
    }
}

/// Removes the firewall rules the persistence setting says must go. Returns
/// whether that succeeded.
fn revert_firewall(loaded: &anyhow::Result<(Store, DaemonSetting)>) -> bool {
    let persist = if let Ok((_, settings)) = loaded {
        settings.persist_rules_offline
    } else {
        warn!("reaper: settings unavailable; removing managed firewall rules");
        false
    };
    finish_revert(
        persist,
        || antiwire_enforce::purge_ephemeral_rules().map_err(Into::into),
        || antiwire_enforce::purge_resolver_dependent_rules().map_err(Into::into),
    )
}

fn open_settings(data_dir: &Path) -> anyhow::Result<(Store, DaemonSetting)> {
    let paths = DataPaths::new(data_dir.to_path_buf());
    paths.ensure_root().context("data dir")?;
    let keystore = platform_keystore(&paths);
    let store = Store::open_with_keystore(paths.database(), &keystore).context("open store")?;
    let settings = store.get_settings().context("settings")?;
    Ok((store, settings))
}

/// Restores the recorded redirect, from the database or, when that cannot be
/// opened, from the journal beside it in `data_dir`. Returns whether a
/// restore is still owed.
fn restore_dns(data_dir: &Path, loaded: &anyhow::Result<(Store, DaemonSetting)>) -> bool {
    if let Err(error) = loaded {
        warn!(%error, "reaper: database unavailable; looking for the redirect journal");
    }
    let store = loaded.as_ref().ok().map(|(store, _)| store);
    match restore_orphaned(store, data_dir) {
        Ok(OrphanedRedirect::Clean) => false,
        Ok(outcome) => {
            info!(?outcome, "reaper: DNS redirect recovery finished");
            false
        }
        Err(error) => {
            warn!(%error, "reaper: DNS redirect recovery did not finish");
            error.is_retryable()
        }
    }
}

/// Runs the purge `persist` calls for. Returns whether it succeeded.
fn finish_revert(
    persist: bool,
    purge: impl FnOnce() -> anyhow::Result<()>,
    purge_resolver_dependent: impl FnOnce() -> anyhow::Result<()>,
) -> bool {
    if persist {
        match purge_resolver_dependent() {
            Ok(()) => {
                info!("reaper: firewall rules left in place (persist enabled)");
                true
            }
            Err(error) => {
                warn!(
                    error = %error,
                    "reaper: firewall rules left in place, but DoH block removal failed"
                );
                false
            }
        }
    } else if let Err(error) = purge() {
        warn!(error = %error, "reaper: firewall rule removal failed");
        false
    } else {
        info!("reaper: firewall rules removed");
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    #[test]
    fn store_failure_still_attempts_firewall_cleanup() {
        let called = Cell::new(false);
        let removed = finish_revert(
            false,
            || {
                called.set(true);
                Ok(())
            },
            || panic!("without settings every managed rule is removed"),
        );
        assert!(removed);
        assert!(called.get());
    }

    #[test]
    fn a_failed_firewall_cleanup_is_reported() {
        let failed = || Err(anyhow::anyhow!("firewall unavailable"));
        assert!(!finish_revert(false, failed, || Ok(())));
        assert!(!finish_revert(true, || Ok(()), failed));
    }

    #[test]
    fn persistent_rules_survive_orphan_cleanup() {
        let resolver_dependent = Cell::new(false);
        let removed = finish_revert(
            true,
            || panic!("persistent firewall rules must not be removed"),
            || {
                resolver_dependent.set(true);
                Ok(())
            },
        );
        assert!(removed);
        assert!(
            resolver_dependent.get(),
            "DoH blocks must not outlive the resolver"
        );
    }

    #[test]
    fn a_missing_journal_and_store_owe_no_dns_restore() {
        let dir = tempfile::tempdir().expect("tempdir");
        let loaded = Err(anyhow::anyhow!("store failed"));
        assert!(!restore_dns(dir.path(), &loaded));
    }
}
