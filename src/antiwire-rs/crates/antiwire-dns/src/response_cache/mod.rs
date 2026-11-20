//! Moka-backed DNS response cache with serve-stale and prefetch semantics.
//!
//! Concerns are split by module: [`key`] defines lookup keys, [`entry`] the
//! cached answer and its admission, [`aging`] the TTL countdown and negative
//! TTLs, [`coalesce`] the in-flight fetch sharing and generation gating,
//! [`prefetch`] the background refresh reservations, and [`failure`] the
//! cached resolution failures that keep a failing name from being re-asked.

mod aging;
mod coalesce;
mod entry;
mod failure;
mod key;
mod prefetch;
#[cfg(test)]
mod tests;

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

use dashmap::DashMap;
use moka::sync::Cache;
use parking_lot::RwLock;

use antiwire_tuning::DNS_RESPONSE_CACHE_BYTE_CAP;

use self::coalesce::InflightCell;
use self::entry::{cache_entry_weight, AnswerExpiry};
use self::failure::{new_failure_cache, ResolutionFailure};
use self::prefetch::{new_backoff_cache, PrefetchBackoff};

pub(crate) use self::aging::AgedSections;
pub(crate) use self::coalesce::{Fetched, SharedOutcome, FETCH_GENERATION_ATTEMPTS};
pub(crate) use self::entry::{CacheProbe, CachedAnswer};
pub(crate) use self::key::{CacheKey, QueryFlags};
pub(crate) use self::prefetch::PrefetchReservation;

/// In-memory wire-format response cache with Moka eviction and miss coalescing.
pub(crate) struct ResponseCache {
    inner: Cache<CacheKey, CachedAnswer>,
    generation: AtomicU64,
    generation_gate: RwLock<()>,
    inflight: DashMap<CacheKey, InflightCell>,
    prefetching: Arc<DashMap<CacheKey, Arc<()>>>,
    prefetch_backoff: Arc<Cache<CacheKey, PrefetchBackoff>>,
    failures: Cache<CacheKey, ResolutionFailure>,
}

impl ResponseCache {
    #[must_use]
    pub(crate) fn new() -> Self {
        let cache = Cache::builder()
            .weigher(cache_entry_weight)
            .max_capacity(DNS_RESPONSE_CACHE_BYTE_CAP as u64)
            .expire_after(AnswerExpiry)
            .build();

        Self {
            inner: cache,
            generation: AtomicU64::new(0),
            generation_gate: RwLock::new(()),
            inflight: DashMap::new(),
            prefetching: Arc::new(DashMap::new()),
            prefetch_backoff: Arc::new(new_backoff_cache()),
            failures: new_failure_cache(),
        }
    }

    /// Retires everything cached for the previous network: entries, in-flight
    /// coalescing cells, prefetch reservations, and held failures.
    ///
    /// The whole flush runs under `generation_gate`, so a concurrent
    /// [`Self::resolve_once`] sees either the old generation intact or the
    /// new one already emptied, never the half-applied state in between.
    pub(crate) fn bump_generation(&self) {
        let _generation_guard = self.generation_gate.write();
        self.generation.fetch_add(1, Ordering::AcqRel);
        self.inner.invalidate_all();
        self.inflight.clear();
        self.prefetching.clear();
        self.prefetch_backoff.invalidate_all();
        // Failures seen on the old network say nothing about the new one.
        self.failures.invalidate_all();
    }

    #[must_use]
    pub(crate) fn current_generation(&self) -> u64 {
        self.generation.load(Ordering::Acquire)
    }

    /// Synchronous cache probe for the fast path.
    #[must_use]
    pub(crate) fn probe(&self, key: &CacheKey) -> CacheProbe {
        let Some(entry) = self.inner.get(key) else {
            return CacheProbe::Miss;
        };

        let now = Instant::now();
        if now < entry.fresh_until {
            return CacheProbe::Fresh(entry);
        }
        if entry.serve_stale && now < entry.stale_until {
            return CacheProbe::Stale(entry);
        }
        CacheProbe::Miss
    }

    /// Inserts or replaces a cache entry.
    #[cfg(any(test, feature = "bench-internals"))]
    pub(crate) fn insert(&self, key: CacheKey, value: CachedAnswer) {
        self.inner.insert(key, value);
    }

    /// Whether an upstream fetch for `key` is in flight for callers to join.
    #[must_use]
    pub(crate) fn fetch_in_flight(&self, key: &CacheKey) -> bool {
        self.inflight.contains_key(key)
    }

    /// Returns a stale entry after upstream failure when within the grace window.
    pub(crate) fn stale_after_failure(&self, key: &CacheKey) -> Option<CachedAnswer> {
        match self.probe(key) {
            CacheProbe::Fresh(entry) | CacheProbe::Stale(entry)
                if entry.serve_stale && Instant::now() < entry.stale_until =>
            {
                Some(entry)
            }
            _ => None,
        }
    }
}

impl Default for ResponseCache {
    fn default() -> Self {
        Self::new()
    }
}
