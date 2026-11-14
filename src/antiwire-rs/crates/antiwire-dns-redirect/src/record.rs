//! The redirect's record on disk: the adapters' original DNS, which a restore
//! writes back.
//!
//! The database holds it, and a journal file in the daemon's data directory
//! holds a copy, for recovery to restore from when the database cannot be
//! opened.

use std::path::Path;

use antiwire_dns_os::redirect_journal;
use antiwire_store::{Store, StoreError};
use tracing::warn;

/// The snapshot that restores the redirect recorded in `store`, if any. An
/// empty one restores nothing, so it counts as none.
pub(crate) fn load(store: &Store) -> Result<Option<String>, StoreError> {
    Ok(store
        .get_dns_redirect()?
        .filter(|snapshot| !snapshot.is_empty()))
}

/// Records `snapshot` as a redirect in place, in the database and in the
/// journal in `data_dir`.
///
/// The database is authoritative, so only its failure is an error. The
/// journal is the fallback for a database recovery cannot open.
pub(crate) fn save(store: &Store, data_dir: &Path, snapshot: &str) -> Result<(), StoreError> {
    store.set_dns_redirect(snapshot)?;
    if let Err(error) = redirect_journal::write(data_dir, snapshot) {
        warn!(%error, "could not write the DNS redirect journal");
    }
    Ok(())
}

/// Clears the record once a restore is confirmed: the database first, then
/// the journal in `data_dir`, which is kept when the database cannot be
/// written.
pub(crate) fn clear(store: &Store, data_dir: &Path) -> Result<(), StoreError> {
    store.clear_dns_redirect()?;
    redirect_journal::remove(data_dir);
    Ok(())
}
