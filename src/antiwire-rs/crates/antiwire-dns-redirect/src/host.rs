//! [`Host`]: the OS calls a redirect makes, and where it records what they
//! changed.

use std::path::Path;
use std::sync::Arc;

use antiwire_store::{Store, StoreError};

use crate::backend::RedirectBackend;
use crate::record;

/// What every change to a redirect goes through: the OS calls, and the
/// record of what they changed, in the database and in the journal in the
/// daemon's data directory. Cheap to clone into the blocking jobs that make
/// those changes.
#[derive(Clone)]
pub(crate) struct Host {
    store: Arc<Store>,
    data_dir: Arc<Path>,
    pub(crate) backend: RedirectBackend,
    /// Whether to arm boot recovery once a redirect is made: for a daemon
    /// that is not a service, which nothing stops cleanly at shutdown.
    boot_recovery: bool,
}

impl Host {
    pub(crate) fn new(
        store: Arc<Store>,
        data_dir: &Path,
        backend: RedirectBackend,
        boot_recovery: bool,
    ) -> Self {
        Self {
            store,
            data_dir: Arc::from(data_dir),
            backend,
            boot_recovery,
        }
    }

    pub(crate) const fn arms_boot_recovery(&self) -> bool {
        self.boot_recovery
    }

    /// The snapshot that restores a redirect an earlier run left recorded.
    pub(crate) fn load_record(&self) -> Result<Option<String>, StoreError> {
        record::load(&self.store)
    }

    /// Records a redirect in place that `snapshot` restores.
    pub(crate) fn save_record(&self, snapshot: &str) -> Result<(), StoreError> {
        record::save(&self.store, &self.data_dir, snapshot)
    }

    /// Clears the record of a redirect that is restored.
    pub(crate) fn clear_record(&self) -> Result<(), StoreError> {
        record::clear(&self.store, &self.data_dir)
    }

    /// Arms recovery of the recorded snapshot at the next boot, when this
    /// redirect arms it at all. Blocking: it may start an OS tool.
    pub(crate) fn arm_boot_recovery(&self) {
        if self.boot_recovery {
            (self.backend.arm_boot_recovery)(&self.data_dir);
        }
    }

    /// Disarms boot recovery once nothing is owed a restore. Blocking: it may
    /// start an OS tool.
    pub(crate) fn disarm_boot_recovery(&self) {
        (self.backend.disarm_boot_recovery)();
    }
}
