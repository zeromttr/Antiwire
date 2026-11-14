//! Embedded `SQLite` connection wrapper (libSQL/Turso-compatible file format).

use std::path::Path;
#[cfg(test)]
use std::time::{Duration, Instant};

use parking_lot::Mutex;
#[cfg(test)]
use rusqlite::StatementStatus;
use rusqlite::{Connection, OpenFlags, OptionalExtension, Row, Transaction};

use crate::error::{Result, StoreError};

/// Embedded `SQLite` database handle using the libSQL-compatible on-disk format.
pub(crate) struct Db {
    conn: Mutex<Connection>,
    // WAL readers see committed data without waiting for the writer's batch.
    // Private in-memory databases must continue using their single connection.
    reader: Option<Mutex<Connection>>,
}

impl Db {
    /// Opens a local database file. Field-level encryption is applied in the store layer.
    pub(crate) fn open_local(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let conn = Connection::open(path)?;
        let tables: i64 = conn.query_row(
            "SELECT COUNT(*) FROM sqlite_schema WHERE type = 'table'",
            [],
            |row| row.get(0),
        )?;
        if tables == 0 {
            conn.execute_batch("PRAGMA auto_vacuum = INCREMENTAL;")?;
        }
        conn.execute_batch(
            "PRAGMA foreign_keys = ON;
             PRAGMA journal_mode = WAL;
             PRAGMA synchronous = NORMAL;",
        )?;

        let reader = if path == Path::new(":memory:") || path.as_os_str().is_empty() {
            None
        } else {
            let reader = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
            reader.execute_batch("PRAGMA query_only = ON;")?;
            reader.set_prepared_statement_cache_capacity(128);
            Some(Mutex::new(reader))
        };
        conn.set_prepared_statement_cache_capacity(128);
        Ok(Self {
            conn: Mutex::new(conn),
            reader,
        })
    }

    pub(crate) fn execute_batch(&self, sql: &str) -> Result<()> {
        let conn = self.conn.lock();
        conn.execute_batch(sql)?;
        Ok(())
    }

    /// Reclaims a bounded number of free pages without a full database VACUUM.
    pub(crate) fn reclaim_pages(&self) -> Result<()> {
        let conn = self.conn.lock();
        conn.execute_batch("PRAGMA incremental_vacuum(128);")?;
        // Never wait for readers when attempting to release the WAL file.
        let timeout: i64 = conn.query_row("PRAGMA busy_timeout", [], |row| row.get(0))?;
        conn.execute_batch("PRAGMA busy_timeout = 0;")?;
        let checkpoint = conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);");
        conn.pragma_update(None, "busy_timeout", timeout)?;
        checkpoint?;
        Ok(())
    }

    pub(crate) fn execute<P: rusqlite::Params>(&self, sql: &str, params: P) -> Result<u64> {
        let conn = self.conn.lock();
        let affected = conn.execute(sql, params)?;
        Ok(affected as u64)
    }

    /// Like [`Self::execute`] but reuses a cached prepared statement, for
    /// statements executed repeatedly on the write path.
    pub(crate) fn execute_cached<P: rusqlite::Params>(&self, sql: &str, params: P) -> Result<u64> {
        let conn = self.conn.lock();
        let mut statement = conn.prepare_cached(sql)?;
        let affected = statement.execute(params)?;
        Ok(affected as u64)
    }

    #[cfg(test)]
    pub(crate) fn execute_profiled<P: rusqlite::Params>(
        &self,
        sql: &str,
        params: P,
    ) -> Result<(u64, i32, i32, Duration)> {
        let conn = self.conn.lock();
        let started = Instant::now();
        let mut statement = conn.prepare(sql)?;
        let affected = statement.execute(params)? as u64;
        let vm_steps = statement.get_status(StatementStatus::VmStep);
        let fullscan_steps = statement.get_status(StatementStatus::FullscanStep);
        Ok((affected, vm_steps, fullscan_steps, started.elapsed()))
    }

    /// Executes one insert and returns its row id while holding the connection lock.
    pub(crate) fn execute_insert<P: rusqlite::Params>(&self, sql: &str, params: P) -> Result<i64> {
        let conn = self.conn.lock();
        conn.execute(sql, params)?;
        Ok(conn.last_insert_rowid())
    }

    pub(crate) fn query_row<T, F, P>(&self, sql: &str, params: P, map: F) -> Result<T>
    where
        P: rusqlite::Params,
        F: FnOnce(&Row<'_>) -> rusqlite::Result<T>,
    {
        let conn = self.reader.as_ref().unwrap_or(&self.conn).lock();
        let mut statement = conn.prepare_cached(sql)?;
        statement.query_row(params, map).map_err(StoreError::from)
    }

    pub(crate) fn query_optional<T, F, P>(&self, sql: &str, params: P, map: F) -> Result<Option<T>>
    where
        P: rusqlite::Params,
        F: FnOnce(&Row<'_>) -> rusqlite::Result<T>,
    {
        let conn = self.reader.as_ref().unwrap_or(&self.conn).lock();
        let mut statement = conn.prepare_cached(sql)?;
        statement
            .query_row(params, map)
            .optional()
            .map_err(StoreError::from)
    }

    pub(crate) fn query_map<T, F, P>(&self, sql: &str, params: P, map: F) -> Result<Vec<T>>
    where
        P: rusqlite::Params,
        F: FnMut(&Row<'_>) -> rusqlite::Result<T>,
    {
        let conn = self.reader.as_ref().unwrap_or(&self.conn).lock();
        let mut stmt = conn.prepare_cached(sql)?;
        let rows = stmt.query_map(params, map)?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .map_err(StoreError::from)
    }

    pub(crate) fn transaction<F>(&self, f: F) -> Result<()>
    where
        F: FnOnce(&Transaction<'_>) -> Result<()>,
    {
        self.transaction_with(f)
    }

    /// Reads multiple results from one committed WAL snapshot.
    pub(crate) fn read_snapshot<T, F>(&self, read: F) -> Result<T>
    where
        F: FnOnce(&Transaction<'_>) -> Result<T>,
    {
        let conn = self.reader.as_ref().unwrap_or(&self.conn).lock();
        let tx = conn.unchecked_transaction()?;
        let value = read(&tx)?;
        tx.commit()?;
        Ok(value)
    }

    /// Runs `f` in a transaction and returns its value.
    ///
    /// Use when the work inside the transaction produces something the caller
    /// needs — an inserted row id, say — which [`Self::transaction`] cannot
    /// hand back.
    pub(crate) fn transaction_with<T, F>(&self, f: F) -> Result<T>
    where
        F: FnOnce(&Transaction<'_>) -> Result<T>,
    {
        let conn = self.conn.lock();
        let tx = conn.unchecked_transaction()?;
        let value = f(&tx)?;
        tx.commit()?;
        Ok(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{mpsc, Arc};

    #[test]
    fn reader_sees_committed_data_without_waiting_for_writer() {
        let dir = tempfile::tempdir().unwrap();
        let db = Arc::new(Db::open_local(dir.path().join("store.db")).unwrap());
        db.execute_batch("CREATE TABLE items (value INTEGER); INSERT INTO items VALUES (1);")
            .unwrap();
        let (entered, ready) = mpsc::channel();
        let (release, wait) = mpsc::channel();
        let writer_db = Arc::clone(&db);
        let writer = std::thread::spawn(move || {
            writer_db
                .transaction(|tx| {
                    tx.execute("UPDATE items SET value = 2", [])?;
                    entered.send(()).unwrap();
                    wait.recv_timeout(Duration::from_secs(5)).unwrap();
                    Ok(())
                })
                .unwrap();
        });
        ready.recv_timeout(Duration::from_secs(5)).unwrap();
        let (read_tx, read_rx) = mpsc::channel();
        let reader_db = Arc::clone(&db);
        let reader = std::thread::spawn(move || {
            read_tx
                .send(
                    reader_db.query_row("SELECT value FROM items", [], |row| row.get::<_, i64>(0)),
                )
                .unwrap();
        });
        let result = read_rx.recv_timeout(Duration::from_secs(1));
        release.send(()).unwrap();
        writer.join().unwrap();
        reader.join().unwrap();
        assert_eq!(result.unwrap().unwrap(), 1);
        assert_eq!(
            db.query_row("SELECT value FROM items", [], |row| row.get::<_, i64>(0))
                .unwrap(),
            2
        );
    }

    #[test]
    fn cached_reads_preserve_optional_mapping_and_memory_databases() {
        let db = Db::open_local(":memory:").unwrap();
        db.execute_batch("CREATE TABLE items (value INTEGER); INSERT INTO items VALUES (1),(2);")
            .unwrap();
        for _ in 0..3 {
            assert_eq!(
                db.query_map("SELECT value FROM items ORDER BY value", [], |row| row
                    .get::<_, i64>(0))
                    .unwrap(),
                [1, 2]
            );
            assert_eq!(
                db.query_optional("SELECT value FROM items WHERE value = ?1", [3], |row| row
                    .get::<_, i64>(
                    0
                ))
                .unwrap(),
                None
            );
        }
        db.execute_batch("ALTER TABLE items ADD COLUMN extra INTEGER;")
            .unwrap();
        assert_eq!(
            db.query_row("SELECT COUNT(*) FROM items", [], |row| row.get::<_, i64>(0))
                .unwrap(),
            2
        );
    }
}
