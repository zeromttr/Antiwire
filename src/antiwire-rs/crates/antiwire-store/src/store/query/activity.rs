//! Pre-aggregated 30-minute activity buckets.
//!
//! Every write path funnels increments through [`ActivityDelta`] so the
//! dashboard heatmap reads one table instead of scanning connection logs.

use std::collections::HashMap;

use rusqlite::Row;
use time::OffsetDateTime;

use antiwire_tuning::LOG_RETENTION_PURGE_BATCH_SIZE;

use crate::error::Result;
use crate::models::{format_timestamp, ActivityBucket};

use crate::store::get_timestamp;
use crate::store::Store;

impl Store {
    /// Deletes one batch of activity buckets that start before `cutoff`.
    pub fn purge_activity_buckets_before(&self, cutoff: Option<OffsetDateTime>) -> Result<u64> {
        let Some(cutoff) = cutoff else {
            return Ok(0);
        };
        let cutoff = format_timestamp(cutoff);
        self.db.execute(
            "DELETE FROM activity_buckets WHERE bucket_start IN (
                SELECT bucket_start FROM activity_buckets WHERE bucket_start < ?1 ORDER BY bucket_start LIMIT ?2
             )",
            rusqlite::params![cutoff, LOG_RETENTION_PURGE_BATCH_SIZE],
        )
    }

    /// Returns 30-minute activity buckets from `since` (inclusive) through `until` (exclusive).
    ///
    /// The result is bounded: an inverted window returns no rows without
    /// touching the table. At most the newest 20,000 buckets are returned,
    /// in chronological order (one year is ~17.6k rows).
    pub fn query_activity_buckets(
        &self,
        since: OffsetDateTime,
        until: OffsetDateTime,
    ) -> Result<Vec<ActivityBucket>> {
        if since >= until {
            return Ok(Vec::new());
        }
        let mut buckets = self.db.query_map(
            "SELECT bucket_start, event_count, bytes_sent, bytes_received, blocked_count
             FROM activity_buckets
             WHERE bucket_start >= ?1 AND bucket_start < ?2
             ORDER BY bucket_start DESC
             LIMIT 20000",
            rusqlite::params![format_timestamp(since), format_timestamp(until)],
            map_activity_bucket,
        )?;
        buckets.reverse();
        Ok(buckets)
    }
}

#[derive(Debug, Default)]
pub(crate) struct ActivityDelta {
    pub(crate) event_count: u64,
    pub(crate) bytes_sent: u64,
    pub(crate) bytes_received: u64,
    pub(crate) blocked_count: u64,
}

/// Applies accumulated deltas inside the caller's transaction.
pub(crate) fn apply_activity_deltas(
    tx: &rusqlite::Transaction<'_>,
    deltas: &HashMap<OffsetDateTime, ActivityDelta>,
) -> Result<()> {
    if deltas.is_empty() {
        return Ok(());
    }

    let mut upsert = tx.prepare(
        "INSERT INTO activity_buckets (
             bucket_start, event_count, bytes_sent, bytes_received, blocked_count
         ) VALUES (?1, ?2, ?3, ?4, ?5)
         ON CONFLICT(bucket_start) DO UPDATE SET
             event_count = event_count + excluded.event_count,
             bytes_sent = bytes_sent + excluded.bytes_sent,
             bytes_received = bytes_received + excluded.bytes_received,
             blocked_count = blocked_count + excluded.blocked_count",
    )?;

    for (bucket, delta) in deltas {
        upsert.execute(rusqlite::params![
            format_timestamp(*bucket),
            i64::try_from(delta.event_count).unwrap_or(i64::MAX),
            i64::try_from(delta.bytes_sent).unwrap_or(i64::MAX),
            i64::try_from(delta.bytes_received).unwrap_or(i64::MAX),
            i64::try_from(delta.blocked_count).unwrap_or(i64::MAX),
        ])?;
    }

    Ok(())
}

fn map_activity_bucket(row: &Row) -> std::result::Result<ActivityBucket, rusqlite::Error> {
    Ok(ActivityBucket {
        bucket_start: get_timestamp(row, 0)?,
        event_count: u64::try_from(row.get::<_, i64>(1)?).unwrap_or(0),
        bytes_sent: u64::try_from(row.get::<_, i64>(2)?).unwrap_or(0),
        bytes_received: u64::try_from(row.get::<_, i64>(3)?).unwrap_or(0),
        blocked_count: u64::try_from(row.get::<_, i64>(4)?).unwrap_or(0),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capped_range_keeps_newest_buckets_in_chronological_order() {
        let store = Store::open(":memory:").unwrap();
        let start = OffsetDateTime::UNIX_EPOCH;
        store
            .db
            .transaction(|tx| {
                let mut insert =
                    tx.prepare("INSERT INTO activity_buckets VALUES (?1, 1, 2, 3, 4)")?;
                for index in 0..20_005 {
                    insert.execute([format_timestamp(
                        start + time::Duration::minutes(index * 30),
                    )])?;
                }
                Ok(())
            })
            .unwrap();
        let end = start + time::Duration::minutes(20_005 * 30);
        let rows = store.query_activity_buckets(start, end).unwrap();
        assert_eq!(rows.len(), 20_000);
        assert_eq!(
            rows[0].bucket_start,
            start + time::Duration::minutes(5 * 30)
        );
        assert_eq!(
            rows.last().unwrap().bucket_start,
            end - time::Duration::minutes(30)
        );
        assert!(rows
            .windows(2)
            .all(|pair| pair[0].bucket_start < pair[1].bucket_start));

        let rows = store
            .query_activity_buckets(end - time::Duration::hours(1), end)
            .unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(
            (
                rows[0].event_count,
                rows[0].bytes_sent,
                rows[0].bytes_received,
                rows[0].blocked_count
            ),
            (1, 2, 3, 4)
        );
    }

    #[test]
    fn inverted_window_returns_empty_without_query_failure() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = Store::open(dir.path().join("activity.sqlite")).expect("open store");
        let now = OffsetDateTime::now_utc();
        let rows = store
            .query_activity_buckets(now, now)
            .expect("equal bounds return empty");
        assert!(rows.is_empty());
        let rows = store
            .query_activity_buckets(now, now - time::Duration::seconds(1))
            .expect("inverted bounds return empty");
        assert!(rows.is_empty());
    }
}
