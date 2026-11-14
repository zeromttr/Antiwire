//! DNS-layer persistence: block rows, seen domains, and the IP-keyed cache.

use std::net::IpAddr;
use std::time::Instant;

use antiwire_tuning::{
    DNS_INFERENCE_MAX_AGE, DNS_INFERENCE_PURGE_BATCH_SIZE, DNS_INFERENCE_PURGE_INTERVAL,
    DNS_PERSISTENT_LAST_SEEN_INTERVAL,
};
use rusqlite::OptionalExtension;
use rusqlite::Row;
use time::OffsetDateTime;

use crate::dns_front::FrontLookup;
use crate::error::Result;
use crate::models::{format_dns_timestamp, format_timestamp, DnsCacheEntry};

use crate::store::get_timestamp;
use crate::store::Store;
const SELECT_DNS_CACHE_ENTRY: &str = "SELECT id, domain, last_seen, latest_seen
     FROM dns_cache_entries
     WHERE id = ?1";

/// Canonical storage key for a DNS cache id: parsed addresses are stored in
/// their canonical spelling so equivalent IPv6 forms match on lookup.
/// Unparseable ids pass through unchanged for backwards compatibility.
fn canonical_dns_id(id: &str) -> String {
    id.parse::<IpAddr>()
        .map_or_else(|_| id.to_owned(), |ip| ip.to_string())
}

impl Store {
    pub(crate) const DNS_RETENTION_SQL: &'static str = "DELETE FROM dns_cache_entries
        WHERE rowid IN (
            SELECT rowid FROM dns_cache_entries
            WHERE latest_seen < ?1
            ORDER BY latest_seen ASC
            LIMIT ?2
        )";

    /// Records a DNS-layer block (`protocol = DNS`) as its own history row.
    ///
    /// Every blocked query appends a row so rewind shows each event; repeats
    /// for the same app and domain are not folded into an earlier row.
    #[cfg(any(test, feature = "test-support"))]
    pub fn insert_dns_block_log(
        &self,
        app_id: i32,
        app_path: &str,
        domain: &str,
        last_seen: OffsetDateTime,
        blocklist_names: &str,
    ) -> Result<()> {
        self.insert_dns_block_logs(&[(
            app_id,
            domain.to_owned(),
            last_seen,
            blocklist_names.to_owned(),
            app_path.to_owned(),
        )])
        .map(|_| ())
    }

    /// Atomically appends a batch of completed DNS events and their activity totals.
    ///
    /// Each entry is `(app_id, domain, timestamp, blocklist_names, app_path)`;
    /// the path is captured at block time so the record keeps the version it
    /// ran from after an update.
    pub fn insert_dns_block_logs(
        &self,
        logs: &[(i32, String, OffsetDateTime, String, String)],
    ) -> Result<Vec<bool>> {
        if logs.is_empty() {
            return Ok(Vec::new());
        }
        self.db.transaction_with(|tx| {
            let mut insert = tx.prepare_cached(
                "INSERT INTO connection_logs (
                timestamp, app_id, protocol, src_ip, src_port, dst_ip, dst_port, dst_domain,
                bytes_sent, bytes_received, action_taken, last_seen, country_code, isp,
                blocklist_names, closed_at, app_path
             ) VALUES (?1, ?2, 'DNS', '', 0, '', 0, ?3, 0, 0, 'BLOCKED', ?1, '', '', ?4, ?1, ?5)",
            )?;
            let mut sighting = tx.prepare_cached(
                "INSERT OR IGNORE INTO seen_domains (domain, first_seen) VALUES (?1, ?2)",
            )?;
            let mut activity =
                std::collections::HashMap::<_, super::activity::ActivityDelta>::new();
            let mut first_sightings = Vec::with_capacity(logs.len());
            for (app_id, domain, seen, names, app_path) in logs {
                let timestamp = format_timestamp(*seen);
                insert.execute(rusqlite::params![
                    timestamp, app_id, domain, names, app_path
                ])?;
                first_sightings.push(
                    sighting.execute(rusqlite::params![
                        domain.trim().to_ascii_lowercase(),
                        timestamp
                    ])? > 0,
                );
                let delta = activity
                    .entry(crate::models::activity_bucket_start(*seen))
                    .or_default();
                delta.event_count += 1;
                delta.blocked_count += 1;
            }
            super::activity::apply_activity_deltas(tx, &activity)?;
            Ok(first_sightings)
        })
    }

    /// Records a domain sighting. Returns `true` when this is the first time the domain
    /// has been seen (insert succeeded).
    pub fn record_domain_sighting(&self, domain: &str, seen_at: OffsetDateTime) -> Result<bool> {
        let domain = domain.trim().to_ascii_lowercase();
        if domain.is_empty() {
            return Ok(false);
        }
        let inserted = self.db.execute_cached(
            "INSERT OR IGNORE INTO seen_domains (domain, first_seen) VALUES (?1, ?2)",
            rusqlite::params![domain, format_timestamp(seen_at)],
        )?;
        Ok(inserted > 0)
    }

    /// Inserts or updates a DNS cache entry keyed by IP address.
    ///
    /// The persisted `last_seen` refresh is throttled for unchanged domains.
    /// Latest-observation metadata is durable on every newer observation so
    /// delayed changes remain rejected after cache eviction or restart.
    #[cfg(any(test, feature = "test-support"))]
    pub fn upsert_dns_cache(&self, entry: &DnsCacheEntry) -> Result<()> {
        self.upsert_dns_cache_batch(std::slice::from_ref(entry))
    }

    /// Inserts or updates multiple DNS cache entries in one transaction.
    ///
    /// The same unchanged-domain throttle as [`Self::upsert_dns_cache`] is
    /// applied per entry, while one connection lock and commit cover the
    /// complete batch. Each row goes through the same exact Rust comparison, so
    /// out-of-order entries converge on the newest observation regardless of
    /// batch order. Front-cache updates run only after the commit, so a
    /// rolled-back batch never populates the cache with uncommitted mappings.
    pub fn upsert_dns_cache_batch(&self, entries: &[DnsCacheEntry]) -> Result<()> {
        if entries.is_empty() {
            return Ok(());
        }

        let write_guard = self.dns_write_lock.lock();
        let normalized: Vec<DnsCacheEntry> = entries
            .iter()
            .map(|entry| DnsCacheEntry {
                id: canonical_dns_id(&entry.id),
                domain: entry.domain.clone(),
                last_seen: entry.last_seen,
            })
            .collect();

        // Publish only accepted observations after a successful commit, while
        // retaining the writer lock so another writer cannot publish first.
        let observations: Vec<DnsCacheEntry> =
            self.db.transaction_with(|tx| {
                let mut select = tx.prepare(SELECT_DNS_CACHE_ENTRY)?;
                let mut observations = Vec::with_capacity(normalized.len());

                for entry in &normalized {
                    let existing = select
                        .query_row(rusqlite::params![entry.id], map_stored_dns_row)
                        .optional()?;
                    let publish = match existing.as_ref() {
                        None => {
                            tx.execute(
                                "INSERT INTO dns_cache_entries (id, domain, last_seen, latest_seen)
                                 VALUES (?1, ?2, ?3, ?4)",
                                rusqlite::params![entry.id, entry.domain, format_timestamp(entry.last_seen), format_dns_timestamp(entry.last_seen)],
                            )?;
                            true
                        }
                        Some(row) if entry.last_seen >= row.latest_seen => {
                            let refresh = !row.domain.eq_ignore_ascii_case(&entry.domain)
                                || entry.last_seen - row.last_seen >= DNS_PERSISTENT_LAST_SEEN_INTERVAL;
                            tx.execute(
                                if refresh {
                                    "UPDATE dns_cache_entries SET domain = ?2, last_seen = ?3, latest_seen = ?4 WHERE id = ?1"
                                } else {
                                    "UPDATE dns_cache_entries SET latest_seen = ?4 WHERE id = ?1"
                                },
                                rusqlite::params![entry.id, entry.domain, format_timestamp(entry.last_seen), format_dns_timestamp(entry.last_seen)],
                            )?;
                            true
                        }
                        Some(_) => false,
                    };
                    if publish {
                        let mut published = entry.clone();
                        if let Some(row) = existing.as_ref() {
                            if row.domain.eq_ignore_ascii_case(&entry.domain)
                                && entry.last_seen - row.last_seen < DNS_PERSISTENT_LAST_SEEN_INTERVAL
                            {
                                published.domain.clone_from(&row.domain);
                            }
                        }
                        observations.push(published);
                    }
                }
                Ok(observations)
            })?;

        #[cfg(test)]
        {
            let hook = self.dns_after_commit.lock().take();
            if let Some(hook) = hook {
                hook();
            }
        }
        for entry in &observations {
            self.note_dns_observation(&entry.id, &entry.domain, entry.last_seen);
        }
        drop(write_guard);
        self.maybe_purge_expired_dns_cache();
        Ok(())
    }

    /// Publishes an observation already accepted by the transaction.
    fn note_dns_observation(&self, id: &str, domain: &str, observed_at: OffsetDateTime) {
        if let Ok(ip) = id.parse::<IpAddr>() {
            self.dns_front.apply_write(&ip, domain, observed_at);
        }
    }

    /// Direct table read bypassing the front cache, for the upsert throttle
    /// (see above) and tests asserting the stored row. `id` must already be
    /// canonical.
    #[cfg(test)]
    pub(crate) fn get_dns_cache_row(&self, id: &str) -> Result<Option<StoredDnsRow>> {
        self.db.query_optional(
            SELECT_DNS_CACHE_ENTRY,
            rusqlite::params![id],
            map_stored_dns_row,
        )
    }

    /// Returns a DNS cache entry by IP address id.
    ///
    /// Parseable ids go through the shared front cache: resident positives and
    /// negatives avoid SQLite entirely, while misses populate it — unless a
    /// concurrent write landed first, in which case the stale read is dropped.
    /// A miss takes the publication lock and rechecks the cache before touching
    /// SQLite, so it cannot observe a commit that is not yet published or
    /// refill the cache from a snapshot taken before that commit. Database
    /// errors never populate the cache. Rows written before address
    /// canonicalization fall back to the raw id spelling.
    pub fn get_dns_cache(&self, id: &str) -> Result<Option<DnsCacheEntry>> {
        let Ok(ip) = id.parse::<IpAddr>() else {
            return self.db.query_optional(
                SELECT_DNS_CACHE_ENTRY,
                rusqlite::params![id],
                map_dns_cache_entry,
            );
        };
        if let CachedLookup::Ready(hit) =
            front_hit(&ip, self.dns_front.lookup(&ip, OffsetDateTime::now_utc()))
        {
            return Ok(hit);
        }
        // Hits stay lock-free. The publication lock is only for the fill, and
        // it is acquired before the SQLite read so commit order and the
        // snapshot a miss observes cannot diverge.
        let _publish = self.dns_write_lock.lock();
        if let CachedLookup::Ready(hit) =
            front_hit(&ip, self.dns_front.lookup(&ip, OffsetDateTime::now_utc()))
        {
            return Ok(hit);
        }
        let version = self.dns_front.begin_read();
        let canonical = ip.to_string();
        let mut row: Option<DnsCacheEntry> = self.db.query_optional(
            SELECT_DNS_CACHE_ENTRY,
            rusqlite::params![canonical],
            map_dns_cache_entry,
        )?;
        self.dns_front.note_sqlite_read();
        if row.is_none() && canonical != id {
            row = self.db.query_optional(
                SELECT_DNS_CACHE_ENTRY,
                rusqlite::params![id],
                map_dns_cache_entry,
            )?;
            self.dns_front.note_sqlite_read();
        }
        self.dns_front.fill_from_read(
            &ip,
            row.as_ref()
                .map(|entry| (entry.domain.as_str(), entry.last_seen)),
            version,
        );
        Ok(row)
    }

    /// Deletes up to `limit` DNS cache rows older than `cutoff`, oldest first,
    /// and drops the matching front-cache entries. Returns the rows removed.
    ///
    /// `latest_seen` is stored in the canonical UTC representation used by the
    /// write path, so the plain timestamp index can satisfy the range scan.
    /// The bound lives in a subselect because this SQLite build rejects
    /// `LIMIT` directly on `DELETE`. Callers release the connection between
    /// batches and repeat until the return is smaller than the limit.
    pub fn purge_expired_dns_cache(&self, cutoff: OffsetDateTime, limit: u32) -> Result<u64> {
        let _write_guard = self.dns_write_lock.lock();
        let removed = self.db.execute(
            Self::DNS_RETENTION_SQL,
            rusqlite::params![format_dns_timestamp(cutoff), i64::from(limit)],
        )?;
        self.dns_front.purge_older_than(cutoff);
        Ok(removed)
    }

    /// Runs one bounded retention pass when the interval has elapsed since the
    /// last one. Retention matches the inference policy: rows older than
    /// [`DNS_INFERENCE_MAX_AGE`] can never back inference, so they are dead
    /// weight. The runtime's independent retention worker drains backlogs
    /// even without writes; this method only supplies an opportunistic pass.
    fn maybe_purge_expired_dns_cache(&self) {
        {
            let mut last = self.dns_purge_at.lock();
            let now = Instant::now();
            if last.is_some_and(|at| now.duration_since(at) < DNS_INFERENCE_PURGE_INTERVAL) {
                return;
            }
            *last = Some(now);
        }
        let cutoff = OffsetDateTime::now_utc()
            - time::Duration::new(
                i64::try_from(DNS_INFERENCE_MAX_AGE.as_secs()).unwrap_or(i64::MAX),
                0,
            );
        match self.purge_expired_dns_cache(
            cutoff,
            u32::try_from(DNS_INFERENCE_PURGE_BATCH_SIZE).unwrap_or(u32::MAX),
        ) {
            Ok(_) => {}
            Err(error) => {
                tracing::warn!(error = %error, "dns cache retention purge failed");
            }
        }
    }
}

enum CachedLookup {
    /// A resident positive or a cached absence. The miss arm is the SQLite path.
    Ready(Option<DnsCacheEntry>),
    Miss,
}

fn front_hit(ip: &IpAddr, lookup: FrontLookup) -> CachedLookup {
    match lookup {
        FrontLookup::Positive {
            domain,
            observed_at,
        } => CachedLookup::Ready(Some(DnsCacheEntry {
            id: ip.to_string(),
            domain,
            last_seen: observed_at,
        })),
        FrontLookup::Negative => CachedLookup::Ready(None),
        FrontLookup::Miss => CachedLookup::Miss,
    }
}

fn map_dns_cache_entry(row: &Row) -> std::result::Result<DnsCacheEntry, rusqlite::Error> {
    Ok(DnsCacheEntry {
        id: row.get(0)?,
        domain: row.get(1)?,
        last_seen: get_timestamp(row, 3)?,
    })
}

#[derive(Debug, Clone)]
pub(crate) struct StoredDnsRow {
    pub(crate) domain: String,
    pub(crate) last_seen: OffsetDateTime,
    pub(crate) latest_seen: OffsetDateTime,
}

fn map_stored_dns_row(row: &Row) -> std::result::Result<StoredDnsRow, rusqlite::Error> {
    Ok(StoredDnsRow {
        domain: row.get(1)?,
        last_seen: get_timestamp(row, 2)?,
        latest_seen: get_timestamp(row, 3)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{mpsc, Arc, Barrier};

    #[test]
    fn commit_and_publication_remain_ordered_for_both_write_apis() {
        for first_batch in [false, true] {
            for second_batch in [false, true] {
                let dir = tempfile::tempdir().unwrap();
                let path = dir.path().join("order.sqlite");
                let store = Arc::new(Store::open(&path).unwrap());
                let committed = Arc::new(Barrier::new(2));
                let resume = Arc::new(Barrier::new(2));
                let committed_hook = Arc::clone(&committed);
                let resume_hook = Arc::clone(&resume);
                *store.dns_after_commit.lock() = Some(Box::new(move || {
                    committed_hook.wait();
                    resume_hook.wait();
                }));
                let at = OffsetDateTime::now_utc();
                let write = move |store: &Store, batch, domain: &str| {
                    let entry = DnsCacheEntry {
                        id: "192.0.2.10".into(),
                        domain: domain.into(),
                        last_seen: at,
                    };
                    if batch {
                        store.upsert_dns_cache_batch(&[entry]).unwrap();
                    } else {
                        store.upsert_dns_cache(&entry).unwrap();
                    }
                };
                let a_store = Arc::clone(&store);
                let a = std::thread::spawn(move || write(&a_store, first_batch, "a.test"));
                committed.wait();
                // A is committed and paused before publication. The database
                // lock is free, but the publication lock must still be held.
                assert_eq!(
                    store
                        .get_dns_cache_row("192.0.2.10")
                        .unwrap()
                        .unwrap()
                        .domain,
                    "a.test"
                );
                let publication_locked = store.dns_write_lock.try_lock().is_none();
                let (started_tx, started_rx) = mpsc::channel();
                let b_store = Arc::clone(&store);
                let b = std::thread::spawn(move || {
                    started_tx.send(()).unwrap();
                    write(&b_store, second_batch, "b.test");
                });
                started_rx.recv().unwrap();
                resume.wait();
                a.join().unwrap();
                b.join().unwrap();
                assert!(
                    publication_locked,
                    "commit must retain the publication lock"
                );
                assert_eq!(
                    store.get_dns_cache("192.0.2.10").unwrap().unwrap().domain,
                    "b.test"
                );
                drop(store);
                let reopened = Store::open(path).unwrap();
                assert_eq!(
                    reopened
                        .get_dns_cache("192.0.2.10")
                        .unwrap()
                        .unwrap()
                        .domain,
                    "b.test"
                );
            }
        }
    }
}
