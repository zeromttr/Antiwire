//! User-requested deletion of recent or all history.
//!
//! Covers what a user reads as their activity record: connection logs, the
//! dashboard activity buckets built from them, and alerts. Rules, settings,
//! applications, AI decisions, network devices and DNS state are kept, for the
//! reasons given in `retention`: they are policy, or deleting them would change
//! what the daemon announces or attributes next.

use time::OffsetDateTime;

use crate::models::{activity_bucket_start, format_timestamp};
use crate::{Store, StoreError};

/// Rows per DELETE when deleting a time range, so live flushes, which need
/// the same write lock, are not held up behind one long statement.
const DELETE_BATCH: u32 = 5000;

impl Store {
    /// Deletes connection logs active at or after `since`, the activity
    /// buckets from the one holding `since` onwards, and alerts raised at or
    /// after `since`. `None` deletes all of them. Returns the rows removed.
    ///
    /// A connection still open keeps flushing, so it reappears as a new row
    /// carrying only the traffic sent after the deletion.
    pub fn delete_history(&self, since: Option<OffsetDateTime>) -> Result<u64, StoreError> {
        let removed = match since {
            None => {
                // No WHERE clause, so SQLite drops the table's pages at once.
                let mut removed = 0;
                for table in ["connection_logs", "activity_buckets", "alerts"] {
                    removed += self.db.execute(&format!("DELETE FROM {table}"), [])?;
                }
                removed
            }
            Some(since) => {
                let since_logs = format_timestamp(since);
                let since_bucket = format_timestamp(activity_bucket_start(since));
                [
                    (
                        "DELETE FROM connection_logs WHERE id IN (
                            SELECT id FROM connection_logs WHERE last_seen >= ?1 LIMIT ?2)",
                        &since_logs,
                    ),
                    (
                        "DELETE FROM activity_buckets WHERE bucket_start IN (
                            SELECT bucket_start FROM activity_buckets WHERE bucket_start >= ?1 LIMIT ?2)",
                        &since_bucket,
                    ),
                    (
                        "DELETE FROM alerts WHERE id IN (
                            SELECT id FROM alerts WHERE timestamp >= ?1 LIMIT ?2)",
                        &since_logs,
                    ),
                ]
                .into_iter()
                .map(|(sql, since)| self.delete_in_batches(sql, since))
                .sum::<Result<u64, StoreError>>()?
            }
        };
        if removed > 0 {
            self.db.reclaim_pages()?;
        }
        Ok(removed)
    }

    fn delete_in_batches(&self, sql: &str, since: &str) -> Result<u64, StoreError> {
        let mut removed = 0;
        loop {
            let batch = self
                .db
                .execute_cached(sql, rusqlite::params![since, DELETE_BATCH])?;
            removed += batch;
            if batch < u64::from(DELETE_BATCH) {
                return Ok(removed);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn count(store: &Store, table: &str) -> i64 {
        store
            .db
            .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                row.get(0)
            })
            .unwrap()
    }

    fn seeded() -> (tempfile::TempDir, Store) {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path().join("db.sqlite")).unwrap();
        // One old row and one recent row in each table, plus a connection that
        // started long ago but was still active recently.
        store
            .db
            .execute_batch(
                "INSERT INTO connection_logs(timestamp, last_seen) VALUES
                    ('2000-01-01T00:00:00.000000000Z', '2000-01-01T00:10:00.000000000Z'),
                    ('2000-01-01T00:00:00.000000000Z', '2030-01-01T00:10:00.000000000Z'),
                    ('2030-01-01T00:05:00.000000000Z', '2030-01-01T00:06:00.000000000Z');
                 INSERT INTO activity_buckets(bucket_start) VALUES
                    ('2000-01-01T00:00:00.000000000Z'),
                    ('2030-01-01T00:00:00.000000000Z'),
                    ('2030-01-01T00:30:00.000000000Z');
                 INSERT INTO alerts(alert_type, title, message, timestamp, severity) VALUES
                    ('test', 'old', '', '2000-01-01T00:00:00.000000000Z', 'low'),
                    ('test', 'new', '', '2030-01-01T00:20:00.000000000Z', 'low');
                 INSERT INTO seen_domains(domain, first_seen) VALUES
                    ('kept.test', '2030-01-01T00:00:00.000000000Z');",
            )
            .unwrap();
        (dir, store)
    }

    #[test]
    fn a_range_deletes_rows_active_since_its_start_and_keeps_older_ones() {
        let (_dir, store) = seeded();
        let since = time::macros::datetime!(2030-01-01 00:05 UTC);

        // Two connection rows, the two buckets from 00:00 on, and one alert.
        assert_eq!(store.delete_history(Some(since)).unwrap(), 5);
        assert_eq!(count(&store, "connection_logs"), 1);
        assert_eq!(count(&store, "activity_buckets"), 1);
        assert_eq!(count(&store, "alerts"), 1);
        assert_eq!(count(&store, "seen_domains"), 1);
        assert_eq!(store.list_alerts().unwrap()[0].title, "old");
    }

    #[test]
    fn none_deletes_all_history_and_keeps_other_tables() {
        let (_dir, store) = seeded();

        assert_eq!(store.delete_history(None).unwrap(), 8);
        for table in ["connection_logs", "activity_buckets", "alerts"] {
            assert_eq!(count(&store, table), 0, "{table}");
        }
        assert_eq!(count(&store, "seen_domains"), 1);
    }

    #[test]
    fn a_range_larger_than_one_batch_is_deleted_completely() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path().join("db.sqlite")).unwrap();
        store
            .db
            .execute_batch(
                "WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x < 12000)
                 INSERT INTO connection_logs(timestamp, last_seen)
                 SELECT '2030-01-01T00:00:00.000000000Z', '2030-01-01T00:00:00.000000000Z' FROM n;",
            )
            .unwrap();

        let since = time::macros::datetime!(2029-12-31 00:00 UTC);
        assert_eq!(store.delete_history(Some(since)).unwrap(), 12000);
        assert_eq!(count(&store, "connection_logs"), 0);
    }
}
