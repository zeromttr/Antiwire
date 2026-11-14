use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::time::Instant;

use antiwire_secrets::{KeyStore, KeyStoreError, SecretBytes, DB_KEY_LEN};
use parking_lot::Mutex;
use rusqlite::Row;
use time::OffsetDateTime;

use crate::db::Db;
use crate::error::{Result, StoreError};
use crate::models::parse_timestamp;

mod query;

pub use query::domain_decisions::normalize_domain_key;
pub use query::{DeletionFence, Resident, ResidentDecision, SeenSubdomain};

/// Applied, in ascending order, to bring a database up to date.
///
/// The first entry is the baseline schema applied to fresh databases; every
/// entry after it is an incremental change. To ship a schema change: add
/// `migrations/NNN_description.sql`, then append one
/// `(version, include_str!(..))` pair here. Never edit, reorder or remove an
/// entry, the baseline included: databases stamp the version after each step
/// applies, so a rewrite silently diverges from the layouts already on disk.
const MIGRATIONS: &[(i64, &str)] = &[(1, include_str!("../migrations/001_initial.sql"))];

/// Version a fresh database ends up at once every migration has applied.
pub(crate) fn latest_migration_version() -> i64 {
    MIGRATIONS[MIGRATIONS.len() - 1].0
}

/// How many distinct executable locations are retained per application.
///
/// Distinct rather than most-recent-sightings: an app alternating between two
/// paths would otherwise fill every slot with those two and evict the older
/// locations that make a relocation visible.
pub(crate) const APPLICATION_PATH_HISTORY_LIMIT: i64 = 10;

/// Embedded `SQLite` persistence layer for the Antiwire daemon.
pub struct Store {
    path: PathBuf,
    db: Db,
    db_key: Option<SecretBytes>,
    dns_front: crate::dns_front::DnsFrontCache,
    decision_cache: crate::store::query::domain_decisions::DecisionCache,
    /// Orders decision writes and cache-miss fills without blocking cache hits.
    decision_write_lock: Mutex<()>,
    /// Serializes DNS database commits with front-cache publication. This
    /// keeps commit order and publication order identical for equal timestamps.
    dns_write_lock: Mutex<()>,
    /// Serializes writes to the settings row, so a read-merge-write cannot
    /// overwrite a column saved in between.
    settings_write_lock: Mutex<()>,
    /// Triples (`conn_id`, `conn_pid`, connection start) with a tracked-flow
    /// write in this process lifetime. Drives `ConnectionLog::is_active`:
    /// a row is active only when it is unclosed *and* its triple is present
    /// here. Never persisted — a fresh `Store` starts empty so historical
    /// rows are `unknown`, never `active`.
    active_conns: Mutex<HashSet<(i64, i32, String)>>,
    #[cfg(test)]
    dns_after_commit: Mutex<Option<Box<dyn FnOnce() + Send>>>,
    /// Last retention-purge attempt for `dns_cache_entries`. Starts unset so
    /// the first write pass purges immediately and bounds restart growth.
    dns_purge_at: Mutex<Option<Instant>>,
}

impl Store {
    /// Opens (or creates) a database at `path` and applies pending migrations.
    /// Removes unreferenced resolution placeholders before runtime consumers
    /// can retain application IDs. Call only during database startup.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        let db = Db::open_local(&path)?;
        let mut store = Self {
            path,
            db,
            db_key: None,
            dns_front: crate::dns_front::DnsFrontCache::new(),
            decision_cache: crate::store::query::domain_decisions::DecisionCache::new(),
            decision_write_lock: Mutex::new(()),
            dns_write_lock: Mutex::new(()),
            settings_write_lock: Mutex::new(()),
            active_conns: Mutex::new(HashSet::new()),
            #[cfg(test)]
            dns_after_commit: Mutex::new(None),
            dns_purge_at: Mutex::new(None),
        };
        store.migrate()?;
        store.prune_startup_placeholders()?;
        Ok(store)
    }

    /// Opens the database with the key from secure storage, which encrypts the
    /// stored secrets: the AI API key and the SIEM auth token. Other columns,
    /// connection history included, are not encrypted; the database file's own
    /// ACL protects them.
    /// Performs the same startup placeholder cleanup as [`Self::open`].
    pub fn open_with_keystore(path: impl AsRef<Path>, keystore: &dyn KeyStore) -> Result<Self> {
        let key = resolve_db_key(keystore)?;
        let path = path.as_ref().to_path_buf();
        let db = Db::open_local(&path)?;
        let mut store = Self {
            path,
            db,
            db_key: Some(key),
            dns_front: crate::dns_front::DnsFrontCache::new(),
            decision_cache: crate::store::query::domain_decisions::DecisionCache::new(),
            decision_write_lock: Mutex::new(()),
            dns_write_lock: Mutex::new(()),
            settings_write_lock: Mutex::new(()),
            active_conns: Mutex::new(HashSet::new()),
            #[cfg(test)]
            dns_after_commit: Mutex::new(None),
            dns_purge_at: Mutex::new(None),
        };
        store.migrate()?;
        store.prune_startup_placeholders()?;
        Ok(store)
    }

    /// Returns the filesystem path backing this store.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Bytes the database occupies on disk: the main file plus its `-wal` and
    /// `-shm` companions, which hold recent writes until a checkpoint.
    ///
    /// `None` when the main file cannot be read, for example an in-memory store.
    #[must_use]
    pub fn disk_size_bytes(&self) -> Option<u64> {
        let main = std::fs::metadata(&self.path).ok()?.len();
        let companions = ["-wal", "-shm"].iter().map(|suffix| {
            let mut name = self.path.as_os_str().to_owned();
            name.push(suffix);
            std::fs::metadata(PathBuf::from(name)).map_or(0, |meta| meta.len())
        });
        Some(main + companions.sum::<u64>())
    }

    /// Highest applied migration version, or 0 for a fresh database.
    fn current_schema_version(&self) -> Result<i64> {
        self.db.query_row(
            "SELECT COALESCE(MAX(version), 0) FROM schema_migrations",
            [],
            |row| row.get(0),
        )
    }

    /// Brings the database up to [`latest_migration_version`].
    ///
    /// A fresh database applies every migration from scratch. An existing one
    /// applies only the entries newer than its stamped version, each in its
    /// own transaction so a failed step leaves the previous version intact.
    ///
    /// Two mismatches are refused with actionable errors rather than guessed
    /// at: a database older than the baseline was written before the schema
    /// was consolidated and cannot be upgraded incrementally, and a database
    /// newer than this build must not be opened by older code.
    fn migrate(&self) -> Result<()> {
        self.db.execute_batch(
            "CREATE TABLE IF NOT EXISTS schema_migrations (
                version INTEGER PRIMARY KEY NOT NULL,
                applied_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
            );",
        )?;

        let baseline = MIGRATIONS[0].0;
        let latest = latest_migration_version();
        let current = self.current_schema_version()?;
        if current != 0 && current < baseline {
            return Err(StoreError::Database(format!(
                "database at {} has schema version {current}, which predates this \
                 build's baseline of {baseline}; delete the file so the next start \
                 recreates it",
                self.path.display()
            )));
        }
        if current > latest {
            return Err(StoreError::Database(format!(
                "database at {} has schema version {current}, but this build only \
                 knows up to {latest}; upgrade the daemon before opening it",
                self.path.display()
            )));
        }

        self.apply_new_migrations(MIGRATIONS)
    }

    /// Applies every entry newer than the stamped version, oldest first.
    ///
    /// Each step runs in its own transaction together with its version stamp,
    /// so a failed step leaves the database at its previous version.
    fn apply_new_migrations(&self, migrations: &[(i64, &str)]) -> Result<()> {
        let current = self.current_schema_version()?;
        for &(version, sql) in migrations {
            if version <= current {
                continue;
            }
            self.db.transaction_with(|tx| {
                tx.execute_batch(sql)?;
                tx.execute(
                    "INSERT INTO schema_migrations (version) VALUES (?1)",
                    [version],
                )?;
                Ok(())
            })?;
        }
        Ok(())
    }
}

fn row_id_to_i32(row_id: i64) -> Result<i32> {
    i32::try_from(row_id)
        .map_err(|_| StoreError::Database(format!("SQLite row id {row_id} exceeds i32")))
}

/// Loads an existing database key or creates and persists a new one.
fn resolve_db_key(keystore: &dyn KeyStore) -> std::result::Result<SecretBytes, KeyStoreError> {
    if let Some(key) = keystore.load_key()? {
        return Ok(key);
    }

    let key = SecretBytes::new(random_key_bytes()?);
    keystore.save_key(key.expose_secret())?;
    Ok(key)
}

fn random_key_bytes() -> std::result::Result<Vec<u8>, KeyStoreError> {
    let mut key = vec![0_u8; DB_KEY_LEN];
    getrandom::fill(&mut key).map_err(|error| KeyStoreError::Entropy(error.to_string()))?;
    Ok(key)
}

fn get_timestamp(row: &Row<'_>, index: usize) -> rusqlite::Result<OffsetDateTime> {
    let raw: String = row.get(index)?;
    parse_timestamp(&raw).map_err(|_| rusqlite::Error::InvalidColumnIndex(index))
}

#[cfg(test)]
mod tests;
