//! Fixtures shared by the crate's unit tests.

use std::sync::Arc;
use std::time::{Duration, Instant};

use antiwire_secrets::UnixSecureFileKeyProvider;
use antiwire_store::Store;
use tempfile::TempDir;

use crate::host::Host;
use crate::RedirectBackend;

/// A store in a fresh temporary directory, which is also its data directory.
/// Keep the directory alive for as long as the store is used.
pub(crate) fn temp_store() -> (TempDir, Arc<Store>) {
    let dir = tempfile::tempdir().expect("tempdir");
    let keystore = UnixSecureFileKeyProvider::new(dir.path().join("key"));
    let store = Store::open_with_keystore(dir.path().join("db.sqlite"), &keystore).expect("store");
    (dir, Arc::new(store))
}

/// Later than any retry a test schedules.
pub(crate) fn far_future() -> Instant {
    Instant::now() + Duration::from_secs(24 * 60 * 60)
}

/// What a redirect recorded in `store` changes through `backend`, with its
/// journal beside the store and no boot recovery.
pub(crate) fn host(store: &Arc<Store>, backend: RedirectBackend) -> Host {
    let data_dir = store.path().parent().expect("the store's directory");
    Host::new(Arc::clone(store), data_dir, backend, false)
}

/// A backend that only restores, through `restore`.
pub(crate) fn restoring(restore: fn(&str) -> bool) -> RedirectBackend {
    RedirectBackend {
        restore,
        ..RedirectBackend::INERT
    }
}
