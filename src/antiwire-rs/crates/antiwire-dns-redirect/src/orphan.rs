//! The redirect a daemon that is gone left behind.

use std::path::Path;

use antiwire_dns_os::redirect_journal;
use antiwire_store::Store;
use tracing::{info, warn};

use crate::backend::RedirectBackend;
use crate::{record, RedirectError};

/// What [`restore_orphaned`] found and restored.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OrphanedRedirect {
    /// No redirect was recorded. A journal or boot recovery left over from
    /// one is cleared.
    Clean,
    /// System DNS was restored, and its record, the journal and boot
    /// recovery cleared.
    Restored,
    /// The database could not be read, and system DNS was restored from the
    /// journal beside it. The journal and boot recovery are cleared; a
    /// database that can be read later still holds its record, and the next
    /// start restores again from it.
    RestoredFromJournal,
}

/// Restores the redirect a daemon that is no longer running left behind.
///
/// The record is read from `store`, or, when there is none or it cannot be
/// read, from the journal in `data_dir`, the daemon's data directory. A
/// confirmed restore clears the record first, then the journal and boot
/// recovery, as a running daemon's own restore does.
///
/// Blocking: it rewrites adapter DNS and may wait on OS tools. The reaper and
/// the boot heal run it on threads of their own.
///
/// # Errors
///
/// - [`RedirectError::RestoreNotConfirmed`]: the restore ran and was not
///   confirmed. Everything is kept for a retry.
/// - [`RedirectError::RecordNotCleared`]: DNS was restored, but its record
///   could not be cleared. The journal and boot recovery are kept with it, so
///   the next start or boot restores again, which writes the same servers.
/// - [`RedirectError::NoRecord`]: the database could not be read and there is
///   no journal beside it, so there is nothing to restore from.
pub fn restore_orphaned(
    store: Option<&Store>,
    data_dir: &Path,
) -> Result<OrphanedRedirect, RedirectError> {
    restore_orphaned_with(store, data_dir, RedirectBackend::OS)
}

/// [`restore_orphaned`] through `backend`, which tests replace.
fn restore_orphaned_with(
    store: Option<&Store>,
    data_dir: &Path,
    backend: RedirectBackend,
) -> Result<OrphanedRedirect, RedirectError> {
    let Some(store) = store else {
        return restore_from_journal(data_dir, backend);
    };
    let recorded = match record::load(store) {
        Ok(recorded) => recorded,
        Err(error) => {
            warn!(%error, "the redirect record could not be read");
            return restore_from_journal(data_dir, backend);
        }
    };
    let Some(snapshot) = recorded else {
        redirect_journal::remove(data_dir);
        (backend.disarm_boot_recovery)();
        return Ok(OrphanedRedirect::Clean);
    };

    info!("restoring the DNS redirect a stopped daemon left behind");
    if !(backend.restore)(&snapshot) {
        warn!("DNS restore was not confirmed; the redirect record is kept");
        return Err(RedirectError::RestoreNotConfirmed);
    }
    record::clear(store, data_dir).map_err(RedirectError::RecordNotCleared)?;
    (backend.disarm_boot_recovery)();
    info!("DNS restored");
    Ok(OrphanedRedirect::Restored)
}

/// Restores from the journal, the only record of the adapters' real DNS
/// when the database cannot be read.
fn restore_from_journal(
    data_dir: &Path,
    backend: RedirectBackend,
) -> Result<OrphanedRedirect, RedirectError> {
    let saved = redirect_journal::read(data_dir).ok_or(RedirectError::NoRecord)?;
    warn!("the database is unavailable; restoring DNS from the redirect journal");
    if !(backend.restore)(&saved) {
        warn!("DNS restore from the redirect journal was not confirmed");
        return Err(RedirectError::RestoreNotConfirmed);
    }
    redirect_journal::remove(data_dir);
    (backend.disarm_boot_recovery)();
    info!("DNS restored from the redirect journal");
    Ok(OrphanedRedirect::RestoredFromJournal)
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;
    use crate::test_support::{restoring, temp_store};

    fn journal_exists(data_dir: &Path) -> bool {
        data_dir.join("dns-redirect-state.json").exists()
    }

    #[test]
    fn a_recorded_redirect_is_restored_and_its_record_cleared() {
        static DISARMED: AtomicUsize = AtomicUsize::new(0);
        let (dir, store) = temp_store();
        record::save(&store, dir.path(), "adapters").expect("record");
        assert!(journal_exists(dir.path()));
        let backend = RedirectBackend {
            restore: |snapshot| snapshot == "adapters",
            disarm_boot_recovery: || {
                DISARMED.fetch_add(1, Ordering::SeqCst);
            },
            ..RedirectBackend::INERT
        };

        let restored = restore_orphaned_with(Some(&store), dir.path(), backend);

        assert_eq!(restored.ok(), Some(OrphanedRedirect::Restored));
        assert_eq!(store.get_dns_redirect().expect("record"), None);
        assert!(!journal_exists(dir.path()));
        assert_eq!(DISARMED.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn an_unconfirmed_restore_keeps_everything_for_a_retry() {
        let (dir, store) = temp_store();
        record::save(&store, dir.path(), "adapters").expect("record");

        let restored = restore_orphaned_with(Some(&store), dir.path(), restoring(|_| false));

        let error = restored.expect_err("the restore was not confirmed");
        assert!(matches!(error, RedirectError::RestoreNotConfirmed));
        assert!(error.is_retryable());
        assert!(store.get_dns_redirect().expect("record").is_some());
        assert!(journal_exists(dir.path()));
    }

    #[test]
    fn without_a_recorded_redirect_a_leftover_journal_is_cleared() {
        let (dir, store) = temp_store();
        redirect_journal::write(dir.path(), "stale").expect("journal");

        let restored = restore_orphaned_with(
            Some(&store),
            dir.path(),
            restoring(|_| panic!("nothing is recorded as redirected")),
        );

        assert_eq!(restored.ok(), Some(OrphanedRedirect::Clean));
        assert!(!journal_exists(dir.path()));
    }

    #[test]
    fn without_a_database_the_journal_is_restored() {
        let (dir, store) = temp_store();
        record::save(&store, dir.path(), "adapters").expect("record");
        let journaled = redirect_journal::read(dir.path());
        drop(store);

        let restored = restore_orphaned_with(None, dir.path(), restoring(|_| true));

        if journaled.is_some() {
            assert_eq!(restored.ok(), Some(OrphanedRedirect::RestoredFromJournal));
            assert!(!journal_exists(dir.path()));
        } else {
            // The journal is trusted only when a privileged account owns it,
            // which a test run by an ordinary user may not satisfy.
            assert!(matches!(restored, Err(RedirectError::NoRecord)));
        }
    }

    #[test]
    fn without_a_database_or_a_journal_there_is_nothing_to_restore() {
        let dir = tempfile::tempdir().expect("tempdir");
        let restored = restore_orphaned_with(
            None,
            dir.path(),
            restoring(|_| panic!("nothing to restore from")),
        );
        let error = restored.expect_err("nothing records a redirect");
        assert!(matches!(error, RedirectError::NoRecord));
        assert!(!error.is_retryable());
    }
}
