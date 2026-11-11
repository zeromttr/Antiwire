use std::path::PathBuf;

/// Crash log written for panics and fatal errors that end the daemon.
pub const CRASH_LOG_FILE: &str = "crash.log";

/// Resolved data-directory paths for daemon artifacts.
#[derive(Debug, Clone)]
pub struct DataPaths {
    pub root: PathBuf,
}

impl DataPaths {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    pub fn database(&self) -> PathBuf {
        self.root.join("antiwire.libsql")
    }

    /// Legacy rusqlite database path used for one-time migration.
    pub fn legacy_database(&self) -> PathBuf {
        self.root.join("antiwire.db")
    }

    pub fn db_key(&self) -> PathBuf {
        self.root.join("db.key")
    }

    /// Crash log for errors that take the daemon down entirely.
    ///
    /// It sits next to the database rather than in a log directory so support can
    /// find the evidence of a crash wherever the database was configured to live,
    /// including `--data-dir` overrides.
    pub fn crash_log(&self) -> PathBuf {
        self.root.join(CRASH_LOG_FILE)
    }

    pub fn ensure_root(&self) -> std::io::Result<()> {
        std::fs::create_dir_all(&self.root)?;
        Ok(())
    }

    pub fn blocklists_dir(&self) -> PathBuf {
        self.root.join("blocklists")
    }

    pub fn ensure_blocklists_dir(&self) -> std::io::Result<()> {
        std::fs::create_dir_all(self.blocklists_dir())?;
        Ok(())
    }

    /// Restricts the database and its sidecars to `SYSTEM`, Administrators, and the owner.
    ///
    /// The data directory itself cannot be locked down, because the UI reads `ipc.token`
    /// and `ipc.crt` out of it without elevation, so the database carries its own ACL
    /// instead of inheriting one. Only the connection database is covered: `ipc.token`
    /// and `ipc.crt` are deliberately left readable, and the blocklist and GeoIP
    /// downloads are public data.
    ///
    /// Call this after opening the store as well as before. SQLite creates the `-wal` and
    /// `-shm` sidecars when the connection enters WAL mode, and they hold recent
    /// transactions in the clear just as the database does.
    ///
    /// Failures are reported but not fatal: unlike the database key, which is worthless
    /// to protect if it is already exposed, refusing to run over an unprotectable
    /// database would leave the machine with no firewall at all.
    pub fn secure_database(&self) {
        for path in self.database_files() {
            if !path.exists() {
                continue;
            }
            if let Err(error) = antiwire_secrets::restrict_to_owner_and_admins(&path) {
                tracing::warn!(
                    path = %path.display(),
                    %error,
                    "could not restrict database permissions; it may be readable by other users"
                );
            }
        }
    }

    /// Every file [`Self::secure_database`] covers, whether or not it exists yet.
    ///
    /// SQLite names its sidecars by appending to the whole filename rather than replacing
    /// an extension, so these are `antiwire.libsql-wal` and `antiwire.libsql-shm` — not
    /// `antiwire-wal.libsql`, which is what `with_extension` would produce.
    fn database_files(&self) -> Vec<PathBuf> {
        let database = self.database();
        let sidecar = |suffix: &str| {
            let mut name = database.clone().into_os_string();
            name.push(suffix);
            PathBuf::from(name)
        };

        vec![
            database.clone(),
            sidecar("-wal"),
            sidecar("-shm"),
            self.legacy_database(),
        ]
    }

    pub fn geoip_dir(&self) -> PathBuf {
        self.root.join("geoip")
    }

    pub fn ensure_geoip_dir(&self) -> std::io::Result<()> {
        std::fs::create_dir_all(self.geoip_dir())?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `secure_database` runs on every bootstrap, including the first one, when none of
    /// the files it covers exist yet.
    #[test]
    fn secure_database_ignores_absent_files() {
        let dir = tempfile::tempdir().expect("tempdir");
        DataPaths::new(dir.path()).secure_database();
    }

    /// A sidecar named wrongly would be silently skipped by the `exists()` check in
    /// `secure_database`, leaving recent transactions readable with nothing to show for
    /// it. These are the names SQLite actually uses.
    #[test]
    fn database_files_cover_the_wal_sidecars() {
        let paths = DataPaths::new("/data");
        let names: Vec<String> = paths
            .database_files()
            .iter()
            .map(|path| {
                path.file_name()
                    .expect("file name")
                    .to_string_lossy()
                    .into_owned()
            })
            .collect();

        assert_eq!(
            names,
            [
                "antiwire.libsql",
                "antiwire.libsql-wal",
                "antiwire.libsql-shm",
                "antiwire.db",
            ]
        );
    }

    /// The crash log is meant to be found alongside the database, not under a
    /// separate log directory, so the two paths must share a parent.
    #[test]
    fn crash_log_lives_beside_the_database() {
        let paths = DataPaths::new("/data");
        assert_eq!(paths.crash_log(), PathBuf::from("/data/crash.log"));
        assert_eq!(paths.crash_log().parent(), paths.database().parent());
    }

    /// The daemon has to keep working against a database it has just restricted, and so
    /// does an unelevated `cargo test` — which is what the owner ACE is there for.
    #[test]
    fn secure_database_leaves_the_database_usable() {
        let dir = tempfile::tempdir().expect("tempdir");
        let paths = DataPaths::new(dir.path());
        paths.ensure_root().expect("root");
        std::fs::write(paths.database(), b"page").expect("seed database");

        paths.secure_database();

        assert_eq!(
            std::fs::read(paths.database()).expect("database is still readable"),
            b"page"
        );
    }
}
