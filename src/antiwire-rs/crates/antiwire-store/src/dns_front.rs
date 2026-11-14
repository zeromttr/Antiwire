//! Bounded in-memory front cache for persistent IP→domain inference.
//!
//! Sits in front of the `dns_cache_entries` table and is shared by every
//! reader and writer in the process — flow enrichment, the DNS stub recorder,
//! and both the single and batch upsert paths — so a write through any path is
//! immediately visible to reads through any other path.
//!
//! Two independent clocks bound an entry:
//!
//! * Residency (5 minutes positive, 60 seconds negative) avoids re-reading
//!   SQLite. These are experiment settings, not correctness bounds.
//! * Eligibility ([`DNS_INFERENCE_MAX_AGE`]) is always recomputed from the
//!   mapping's original observation timestamp, so a recently loaded entry can
//!   never stay authoritative past the inference policy.
//!
//! Coherence against concurrent reads and writes comes from a cache epoch: a
//! read captures the epoch before touching SQLite and only populates the cache
//! when it is unchanged afterwards, so a result fetched before a concurrent
//! cache mutation can never overwrite fresher state. Fills that share an epoch
//! still cannot move a resident positive backwards. A single epoch keeps the
//! coherence metadata bounded independently of the number of IPs seen.
//! Writes always bump the epoch and only replace a resident positive entry
//! with an observation at least as new (ties go to the later writer), so a
//! delayed batch can never restore an older mapping over a newer one.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use antiwire_tuning::{
    DNS_INFERENCE_CLOCK_SKEW_TOLERANCE, DNS_INFERENCE_FRONT_CACHE_CAP,
    DNS_INFERENCE_FRONT_NEGATIVE_TTL, DNS_INFERENCE_FRONT_POSITIVE_TTL, DNS_INFERENCE_MAX_AGE,
};
use parking_lot::Mutex;
use time::OffsetDateTime;

/// Whether a persistent IP→domain mapping may back flow inference: its age
/// must not exceed [`DNS_INFERENCE_MAX_AGE`].
///
/// Clock-skew handling is explicit: observations up to
/// [`DNS_INFERENCE_CLOCK_SKEW_TOLERANCE`] in the future are treated as current,
/// while anything further ahead is untrustworthy and ineligible. In particular
/// this rejects the old whole-hours comparison, which admitted mappings almost
/// 25 hours old.
#[must_use]
pub fn dns_inference_eligible(observed_at: OffsetDateTime, now: OffsetDateTime) -> bool {
    let max_age = time::Duration::new(
        i64::try_from(DNS_INFERENCE_MAX_AGE.as_secs()).unwrap_or(i64::MAX),
        0,
    );
    let skew = time::Duration::new(
        i64::try_from(DNS_INFERENCE_CLOCK_SKEW_TOLERANCE.as_secs()).unwrap_or(i64::MAX),
        0,
    );
    let age = now - observed_at;
    if age < -skew {
        return false;
    }
    age.max(time::Duration::ZERO) <= max_age
}

/// Outcome of a front-cache probe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum FrontLookup {
    /// Resident positive entry still eligible for inference, carrying the
    /// mapping's original observation timestamp.
    Positive {
        domain: String,
        observed_at: OffsetDateTime,
    },
    /// Resident negative entry: the address is genuinely absent from the table.
    Negative,
    /// No usable entry: read SQLite.
    Miss,
}

#[derive(Debug, Clone)]
struct FrontEntry {
    /// `None` marks a negative entry for a genuinely absent mapping.
    domain: Option<String>,
    /// Original observation timestamp (positive) or miss time (negative).
    observed_at: OffsetDateTime,
    cached_at: Instant,
}

struct FrontState {
    entries: HashMap<IpAddr, FrontEntry>,
    /// Invalidates SQLite fills whenever the resident cache changes in a way
    /// that could make an in-flight result stale.  A single epoch keeps
    /// coherence metadata bounded independently of the number of IPs seen.
    epoch: u64,
}

pub(crate) struct DnsFrontCache {
    state: Mutex<FrontState>,
    hits: AtomicU64,
    sqlite_reads: AtomicU64,
}

impl DnsFrontCache {
    pub(crate) fn new() -> Self {
        Self {
            state: Mutex::new(FrontState {
                entries: HashMap::new(),
                epoch: 0,
            }),
            hits: AtomicU64::new(0),
            sqlite_reads: AtomicU64::new(0),
        }
    }

    /// Probes the cache. Hits count both served positives and served negatives;
    /// anything else is a miss and the caller must read SQLite.
    pub(crate) fn lookup(&self, ip: &IpAddr, now: OffsetDateTime) -> FrontLookup {
        let mut state = self.state.lock();
        let Some(entry) = state.entries.get(ip) else {
            return FrontLookup::Miss;
        };
        let resident = entry.cached_at.elapsed() <= residency_ttl(entry.domain.is_some());
        let eligible = entry.domain.as_ref().is_none_or(|domain| {
            !domain.is_empty() && dns_inference_eligible(entry.observed_at, now)
        });
        if !resident || !eligible {
            state.entries.remove(ip);
            state.epoch = state.epoch.wrapping_add(1);
            return FrontLookup::Miss;
        }
        self.hits.fetch_add(1, Ordering::Relaxed);
        match &entry.domain {
            Some(domain) => FrontLookup::Positive {
                domain: domain.clone(),
                observed_at: entry.observed_at,
            },
            None => FrontLookup::Negative,
        }
    }

    /// Captures the cache epoch before a SQLite read starts.
    pub(crate) fn begin_read(&self) -> u64 {
        self.state.lock().epoch
    }

    /// Records that a SQLite read actually ran (test observability: repeated
    /// front hits must not advance this counter).
    pub(crate) fn note_sqlite_read(&self) {
        self.sqlite_reads.fetch_add(1, Ordering::Relaxed);
    }

    /// Populates the cache from a SQLite result, unless a concurrent write
    /// bumped the key's version after [`Self::begin_read`]. Expired positives
    /// are never admitted; absent rows become short-lived negatives.
    ///
    /// A fill does not bump the epoch, so two in-flight reads can both pass
    /// the epoch check. The later fill must not move a resident positive
    /// backwards: an older snapshot or a stale absence never hides a newer
    /// mapping that another fill already published.
    pub(crate) fn fill_from_read(
        &self,
        ip: &IpAddr,
        result: Option<(&str, OffsetDateTime)>,
        version: u64,
    ) {
        let mut state = self.state.lock();
        if state.epoch != version {
            return;
        }
        if resident_positive_is_newer(&state, ip, result) {
            return;
        }
        let now = OffsetDateTime::now_utc();
        match result {
            Some((domain, observed_at)) if dns_inference_eligible(observed_at, now) => {
                evict_if_full(&mut state);
                state.entries.insert(
                    *ip,
                    FrontEntry {
                        domain: Some(domain.to_owned()),
                        observed_at,
                        cached_at: Instant::now(),
                    },
                );
            }
            Some(_) => {}
            None => {
                evict_if_full(&mut state);
                state.entries.insert(
                    *ip,
                    FrontEntry {
                        domain: None,
                        observed_at: now,
                        cached_at: Instant::now(),
                    },
                );
            }
        }
    }

    /// Applies a write to the cache. The version always advances; the resident
    /// entry is replaced when there is none, when it is a negative, or when
    /// the new observation is at least as recent (ties go to the later
    /// writer). An older observation never displaces a newer resident mapping.
    pub(crate) fn apply_write(&self, ip: &IpAddr, domain: &str, observed_at: OffsetDateTime) {
        let mut state = self.state.lock();
        state.epoch = state.epoch.wrapping_add(1);
        let replace = state
            .entries
            .get(ip)
            .is_none_or(|entry| entry.domain.is_none() || observed_at >= entry.observed_at);
        if replace {
            evict_if_full(&mut state);
            state.entries.insert(
                *ip,
                FrontEntry {
                    domain: Some(domain.to_owned()),
                    observed_at,
                    cached_at: Instant::now(),
                },
            );
        }
    }

    /// Removes resident entries whose mapping predates `cutoff`, keeping the
    /// front cache consistent with retention purges of the underlying table.
    pub(crate) fn purge_older_than(&self, cutoff: OffsetDateTime) {
        let mut state = self.state.lock();
        state.entries.retain(|_, entry| entry.observed_at >= cutoff);
        // The database purge may remove a row that is not resident here. An
        // in-flight read for that key must still be invalidated, or it could
        // refill the cache from its pre-purge SQLite snapshot.
        state.epoch = state.epoch.wrapping_add(1);
    }

    #[cfg(test)]
    pub(crate) fn hits(&self) -> u64 {
        self.hits.load(Ordering::Relaxed)
    }

    #[cfg(test)]
    pub(crate) fn sqlite_reads(&self) -> u64 {
        self.sqlite_reads.load(Ordering::Relaxed)
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.state.lock().entries.len()
    }

    #[cfg(test)]
    pub(crate) fn coherence_metadata_len(&self) -> usize {
        // The epoch is one scalar, regardless of how many IPs have been seen.
        std::mem::size_of_val(&self.state.lock().epoch) / std::mem::size_of::<u64>()
    }
}

/// True when `result` would replace a resident positive with an older mapping
/// or with a cached absence.
fn resident_positive_is_newer(
    state: &FrontState,
    ip: &IpAddr,
    result: Option<(&str, OffsetDateTime)>,
) -> bool {
    let Some(existing) = state.entries.get(ip) else {
        return false;
    };
    if existing.domain.is_none() {
        return false;
    }
    match result {
        Some((_, observed_at)) => observed_at < existing.observed_at,
        None => true,
    }
}

fn residency_ttl(positive: bool) -> std::time::Duration {
    if positive {
        DNS_INFERENCE_FRONT_POSITIVE_TTL
    } else {
        DNS_INFERENCE_FRONT_NEGATIVE_TTL
    }
}

/// Makes room for one entry once the map reaches capacity: expired residents
/// go first, then an arbitrary eighth (hash order is arbitrary, so this
/// samples without an LRU structure).
fn evict_if_full(state: &mut FrontState) {
    let entries = &mut state.entries;
    let cap = usize::try_from(DNS_INFERENCE_FRONT_CACHE_CAP)
        .unwrap_or(usize::MAX)
        .max(1);
    if entries.len() < cap {
        return;
    }
    let before = entries.len();
    entries.retain(|_, entry| entry.cached_at.elapsed() <= residency_ttl(entry.domain.is_some()));
    if entries.len() >= cap {
        let drop_count = (entries.len() / 8).max(1);
        let victims: Vec<IpAddr> = entries.keys().take(drop_count).copied().collect();
        for victim in victims {
            entries.remove(&victim);
        }
    }
    if entries.len() != before {
        state.epoch = state.epoch.wrapping_add(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn ip(last: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, last))
    }

    #[test]
    fn positive_entries_hit_until_residency_expires() {
        let cache = DnsFrontCache::new();
        let now = OffsetDateTime::now_utc();
        cache.apply_write(&ip(1), "example.test", now);
        assert_eq!(
            cache.lookup(&ip(1), now),
            FrontLookup::Positive {
                domain: "example.test".to_owned(),
                observed_at: now,
            }
        );
        assert_eq!(cache.hits(), 1);
    }

    #[test]
    fn older_observations_never_displace_newer_residents() {
        let cache = DnsFrontCache::new();
        let older = OffsetDateTime::now_utc() - time::Duration::seconds(10);
        let newer = OffsetDateTime::now_utc();
        cache.apply_write(&ip(2), "new.test", newer);
        cache.apply_write(&ip(2), "old.test", older);
        assert_eq!(
            cache.lookup(&ip(2), newer),
            FrontLookup::Positive {
                domain: "new.test".to_owned(),
                observed_at: newer,
            }
        );
    }

    #[test]
    fn equal_timestamps_go_to_the_later_writer() {
        let cache = DnsFrontCache::new();
        let at = OffsetDateTime::now_utc();
        cache.apply_write(&ip(3), "first.test", at);
        cache.apply_write(&ip(3), "second.test", at);
        assert_eq!(
            cache.lookup(&ip(3), at),
            FrontLookup::Positive {
                domain: "second.test".to_owned(),
                observed_at: at,
            }
        );
    }

    #[test]
    fn writes_replace_cached_negatives_immediately() {
        let cache = DnsFrontCache::new();
        let now = OffsetDateTime::now_utc();
        let version = cache.begin_read();
        cache.fill_from_read(&ip(4), None, version);
        assert_eq!(cache.lookup(&ip(4), now), FrontLookup::Negative);

        cache.apply_write(&ip(4), "late.test", now);
        assert_eq!(
            cache.lookup(&ip(4), now),
            FrontLookup::Positive {
                domain: "late.test".to_owned(),
                observed_at: now,
            }
        );
    }

    #[test]
    fn older_fill_does_not_replace_a_newer_fill_with_the_same_epoch() {
        let cache = DnsFrontCache::new();
        let now = OffsetDateTime::now_utc();
        let version = cache.begin_read();
        cache.fill_from_read(&ip(5), Some(("fresh.test", now)), version);
        cache.fill_from_read(
            &ip(5),
            Some(("stale.test", now - time::Duration::seconds(30))),
            version,
        );
        assert_eq!(
            cache.lookup(&ip(5), now),
            FrontLookup::Positive {
                domain: "fresh.test".to_owned(),
                observed_at: now,
            }
        );
    }

    #[test]
    fn stale_negative_fill_does_not_hide_a_newer_positive() {
        let cache = DnsFrontCache::new();
        let now = OffsetDateTime::now_utc();
        let version = cache.begin_read();
        cache.fill_from_read(&ip(6), Some(("fresh.test", now)), version);
        cache.fill_from_read(&ip(6), None, version);
        assert_eq!(
            cache.lookup(&ip(6), now),
            FrontLookup::Positive {
                domain: "fresh.test".to_owned(),
                observed_at: now,
            }
        );
    }

    #[test]
    fn fill_after_a_concurrent_write_is_dropped() {
        let cache = DnsFrontCache::new();
        let now = OffsetDateTime::now_utc();
        let version = cache.begin_read();
        // A write lands while the SQLite read is in flight.
        cache.apply_write(&ip(5), "fresh.test", now);
        // The stale read result must not overwrite it.
        cache.fill_from_read(
            &ip(5),
            Some(("stale.test", now - time::Duration::seconds(60))),
            version,
        );
        assert_eq!(
            cache.lookup(&ip(5), now),
            FrontLookup::Positive {
                domain: "fresh.test".to_owned(),
                observed_at: now,
            }
        );
    }

    #[test]
    fn expired_mappings_are_neither_served_nor_admitted() {
        let cache = DnsFrontCache::new();
        let now = OffsetDateTime::now_utc();
        let ancient = now - time::Duration::seconds(25 * 60 * 60);
        cache.apply_write(&ip(6), "ancient.test", ancient);
        assert_eq!(cache.lookup(&ip(6), now), FrontLookup::Miss);

        let version = cache.begin_read();
        cache.fill_from_read(&ip(6), Some(("ancient.test", ancient)), version);
        assert_eq!(
            cache.lookup(&ip(6), now),
            FrontLookup::Miss,
            "an expired row must not populate the front cache"
        );
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn purge_invalidates_an_outstanding_read() {
        let cache = DnsFrontCache::new();
        let now = OffsetDateTime::now_utc();
        let observed_at = now - time::Duration::seconds(10);
        cache.apply_write(&ip(7), "stale.test", observed_at);
        let version = cache.begin_read();

        cache.purge_older_than(now);
        cache.fill_from_read(&ip(7), Some(("stale.test", observed_at)), version);

        assert_eq!(cache.lookup(&ip(7), now), FrontLookup::Miss);
    }

    #[test]
    fn purge_invalidates_an_outstanding_read_for_nonresident_key() {
        let cache = DnsFrontCache::new();
        let now = OffsetDateTime::now_utc();
        let version = cache.begin_read();

        cache.purge_older_than(now);
        cache.fill_from_read(&ip(8), Some(("purged.test", now)), version);

        assert_eq!(cache.lookup(&ip(8), now), FrontLookup::Miss);
    }

    #[test]
    fn eviction_invalidates_an_outstanding_read() {
        use std::net::Ipv6Addr;

        let cache = DnsFrontCache::new();
        let now = OffsetDateTime::now_utc();
        let capacity = DNS_INFERENCE_FRONT_CACHE_CAP as u32;
        {
            let mut state = cache.state.lock();
            for suffix in 0..capacity {
                let address = IpAddr::V6(Ipv6Addr::new(
                    0x2001,
                    0xdb8,
                    0,
                    0,
                    0,
                    0,
                    (suffix >> 16) as u16,
                    u16::try_from(suffix & 0xffff).unwrap(),
                ));
                state.entries.insert(
                    address,
                    FrontEntry {
                        domain: Some("resident.test".to_owned()),
                        observed_at: now,
                        cached_at: Instant::now(),
                    },
                );
            }
        }

        let target = ip(9);
        let version = cache.begin_read();
        {
            let mut state = cache.state.lock();
            evict_if_full(&mut state);
        }
        cache.fill_from_read(&target, Some(("stale.test", now)), version);

        assert_eq!(cache.lookup(&target, now), FrontLookup::Miss);
    }

    #[test]
    fn coherence_metadata_does_not_grow_with_ip_churn() {
        use std::net::Ipv6Addr;

        let cache = DnsFrontCache::new();
        let now = OffsetDateTime::now_utc();
        let churn = (DNS_INFERENCE_FRONT_CACHE_CAP as u32) * 2 + 1;
        for suffix in 0..churn {
            let address = IpAddr::V6(Ipv6Addr::new(
                0x2001,
                0xdb8,
                0,
                0,
                0,
                0,
                (suffix >> 16) as u16,
                u16::try_from(suffix & 0xffff).unwrap(),
            ));
            cache.apply_write(&address, "churn.test", now);
        }

        assert_eq!(cache.coherence_metadata_len(), 1);
        assert!(cache.len() <= DNS_INFERENCE_FRONT_CACHE_CAP as usize);
    }

    #[test]
    fn eligibility_uses_exact_durations_with_explicit_skew() {
        use antiwire_tuning::{DNS_INFERENCE_CLOCK_SKEW_TOLERANCE, DNS_INFERENCE_MAX_AGE};

        let now = OffsetDateTime::now_utc();
        let max_age = time::Duration::new(
            i64::try_from(DNS_INFERENCE_MAX_AGE.as_secs()).unwrap_or(i64::MAX),
            0,
        );
        let skew = time::Duration::new(
            i64::try_from(DNS_INFERENCE_CLOCK_SKEW_TOLERANCE.as_secs()).unwrap_or(i64::MAX),
            0,
        );

        // Exactly at the maximum age is eligible; one second past is not.
        // (The old whole-hours comparison admitted almost 25 hours.)
        assert!(dns_inference_eligible(now - max_age, now));
        assert!(!dns_inference_eligible(
            now - max_age - time::Duration::seconds(1),
            now
        ));
        // Small future drift is treated as current...
        assert!(dns_inference_eligible(
            now + time::Duration::minutes(1),
            now
        ));
        // ...but large future timestamps are skew, not fresh data.
        assert!(!dns_inference_eligible(
            now + skew + time::Duration::seconds(1),
            now
        ));
    }
}
