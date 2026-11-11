//! Bounded retention for disposable history. Active policy and presence watches survive.
//!
//! Two tables are deliberately left out. `seen_domains` is the baseline for
//! "new domain" events, so deleting a row would announce a familiar domain as
//! new; it holds one small row per distinct domain. `domain_decisions` doubles
//! as the AI classification cache and audit trail, and deleting a row would
//! send that domain to the paid classifier again.

use antiwire_tuning::LOG_RETENTION_PURGE_BATCH_SIZE;

use crate::models::format_timestamp;
use crate::{Store, StoreError};
use time::OffsetDateTime;

impl Store {
    /// Runs one retention batch per auxiliary history table, using the log policy.
    pub fn purge_history_before(&self, cutoff: Option<OffsetDateTime>) -> Result<u64, StoreError> {
        let Some(cutoff) = cutoff else {
            return Ok(0);
        };
        let cutoff = format_timestamp(cutoff);
        let mut removed = 0;
        for sql in [
            "DELETE FROM alerts WHERE id IN (SELECT id FROM alerts WHERE timestamp < ?1 ORDER BY timestamp LIMIT ?2)",
            "DELETE FROM domain_lookups WHERE domain IN (SELECT domain FROM domain_lookups WHERE fetched_at < ?1 ORDER BY fetched_at LIMIT ?2)",
            "DELETE FROM network_devices WHERE mac_address IN (
                SELECT d.mac_address FROM network_devices d WHERE d.present = 0 AND d.last_seen < ?1
                AND NOT EXISTS (SELECT 1 FROM network_device_watches w WHERE
                    (w.mac_address <> '' AND LOWER(w.mac_address) = LOWER(d.mac_address)) OR
                    (w.ip_address <> '' AND w.ip_address = d.ip_address))
                ORDER BY d.last_seen LIMIT ?2)",
        ] {
            removed += self
                .db
                .execute_cached(sql, rusqlite::params![cutoff, LOG_RETENTION_PURGE_BATCH_SIZE])?;
        }
        if removed > 0 {
            self.db.reclaim_pages()?;
        }
        Ok(removed)
    }

    /// Incremental compaction for databases created with incremental auto-vacuum.
    pub fn reclaim_history_space(&self) -> Result<(), StoreError> {
        self.db.reclaim_pages()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retention_batches_are_bounded_and_none_disables_deletion() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path().join("db.sqlite")).unwrap();
        store.db.execute_batch("WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<1005)
            INSERT INTO alerts(alert_type,title,message,timestamp,severity)
            SELECT 'test','test','','2000-01-01T00:00:00Z','low' FROM n;
            WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<1005)
            INSERT INTO connection_logs(timestamp,last_seen) SELECT '2000-01-01T00:00:00Z','2000-01-01T00:00:00Z' FROM n;").unwrap();
        assert_eq!(store.purge_history_before(None).unwrap(), 0);
        assert_eq!(store.purge_connection_logs_before(None).unwrap(), 0);
        let cutoff = Some(OffsetDateTime::now_utc());
        assert_eq!(store.purge_history_before(cutoff).unwrap(), 1000);
        assert_eq!(store.list_alerts().unwrap().len(), 5);
        assert_eq!(store.purge_connection_logs_before(cutoff).unwrap(), 1000);
        assert_eq!(
            store
                .query_connection_logs(&crate::ConnectionLogQuery::default())
                .unwrap()
                .total_count,
            5
        );
        assert_eq!(store.purge_history_before(cutoff).unwrap(), 5);
        assert_eq!(store.purge_connection_logs_before(cutoff).unwrap(), 5);
    }

    #[test]
    fn retention_keeps_ai_decisions_sightings_and_watched_or_online_devices() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path().join("db.sqlite")).unwrap();
        store.db.execute_batch("INSERT INTO domain_decisions(domain, verdict, first_seen, updated_at) VALUES
            ('blocked.test','block','2000-01-01T00:00:00Z','2000-01-01T00:00:00Z'),
            ('old.test','record','2000-01-01T00:00:00Z','2000-01-01T00:00:00Z');
            INSERT INTO network_devices(mac_address, ip_address, first_seen, last_seen, present) VALUES
            ('stale','192.168.1.1','2000-01-01T00:00:00Z','2000-01-01T00:00:00Z',0),
            ('watched','192.168.1.2','2000-01-01T00:00:00Z','2000-01-01T00:00:00Z',0),
            ('online','192.168.1.3','2000-01-01T00:00:00Z','2000-01-01T00:00:00Z',1);
            INSERT INTO network_device_watches(mac_address) VALUES ('watched');
            INSERT INTO seen_domains(domain, first_seen) VALUES ('daily.test','2000-01-01T00:00:00Z');").unwrap();
        assert_eq!(store.purge_history_before(None).unwrap(), 0);
        assert_eq!(
            store
                .purge_history_before(Some(OffsetDateTime::now_utc()))
                .unwrap(),
            1
        );
        assert_eq!(store.list_network_devices().unwrap().len(), 2);
        let count = |table: &str| {
            store
                .db
                .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                    row.get::<_, i64>(0)
                })
                .unwrap()
        };
        assert_eq!(count("domain_decisions"), 2);
        assert_eq!(count("seen_domains"), 1);
        assert_eq!(
            store
                .db
                .query_row("PRAGMA auto_vacuum", [], |row| row.get::<_, i64>(0))
                .unwrap(),
            2
        );
    }
}
