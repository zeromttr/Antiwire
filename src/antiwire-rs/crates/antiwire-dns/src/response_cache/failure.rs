//! Cached resolution failures (RFC 9520) and the serve-stale failure recheck
//! timer (RFC 8767 §5).
//!
//! A failed upstream fetch holds its key for a while. During the hold the
//! name is not asked upstream again: a stale answer is served at once if one
//! is cached, and SERVFAIL otherwise. A successful fetch clears the hold.

use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use moka::sync::Cache;

use antiwire_tuning::{
    DNS_RESOLUTION_FAILURE_HOLD, DNS_RESOLUTION_FAILURE_MAX_HOLD, DNS_RESPONSE_CACHE_HARD_CAP,
    DNS_STALE_FAILURE_RECHECK,
};

use super::key::CacheKey;

#[derive(Clone, Copy)]
pub(super) struct ResolutionFailure {
    /// Consecutive failures, which set the length of the next hold.
    pub(super) failures: u32,
    pub(super) held_until: Instant,
}

/// Builds the failure cache. An entry outlives its hold so a name that fails
/// again soon after keeps its backoff, and is forgotten once it has resolved
/// or gone unasked for a while.
pub(super) fn new_failure_cache() -> Cache<CacheKey, ResolutionFailure> {
    Cache::builder()
        .max_capacity(u64::try_from(DNS_RESPONSE_CACHE_HARD_CAP).unwrap_or(1))
        .time_to_live(DNS_RESOLUTION_FAILURE_MAX_HOLD.max(DNS_STALE_FAILURE_RECHECK) * 4)
        .build()
}

/// Hold after the `failures`th consecutive failure of a name with no stale
/// answer: doubling from the RFC 9520 starting hold up to the ceiling.
pub(super) fn failure_hold(failures: u32) -> Duration {
    let shift = failures.saturating_sub(1).min(16);
    DNS_RESOLUTION_FAILURE_HOLD
        .saturating_mul(1 << shift)
        .min(DNS_RESOLUTION_FAILURE_MAX_HOLD)
}

impl super::ResponseCache {
    /// Records that one upstream fetch for `key`, started under `generation`,
    /// failed.
    ///
    /// Call once per fetch, not once per coalesced waiter, or the backoff
    /// would count one failure several times. With a stale answer to serve,
    /// the hold is the RFC 8767 failure recheck timer; otherwise it backs off
    /// as RFC 9520 §3.2 asks. A fetch over a network that has since been
    /// retired records nothing, as its answer would not be cached either.
    pub(crate) fn record_failure(&self, key: &CacheKey, generation: u64) {
        let _generation_guard = self.generation_gate.read();
        if self.generation.load(Ordering::Acquire) != generation {
            return;
        }
        let failures = self
            .failures
            .get(key)
            .map_or(0, |failure| failure.failures)
            .saturating_add(1);
        let hold = if self.stale_after_failure(key).is_some() {
            DNS_STALE_FAILURE_RECHECK
        } else {
            failure_hold(failures)
        };
        self.failures.insert(
            key.clone(),
            ResolutionFailure {
                failures,
                held_until: Instant::now() + hold,
            },
        );
    }

    /// True while a recent failure says not to ask upstream for `key`.
    #[must_use]
    pub(crate) fn failure_held(&self, key: &CacheKey) -> bool {
        self.failures
            .get(key)
            .is_some_and(|failure| Instant::now() < failure.held_until)
    }

    pub(super) fn clear_failure(&self, key: &CacheKey) {
        self.failures.invalidate(key);
    }
}
