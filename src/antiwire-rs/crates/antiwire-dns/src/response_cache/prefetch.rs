//! Background prefetch reservations and their bounded retry backoff.

use std::sync::Arc;
use std::time::{Duration, Instant};

use dashmap::mapref::entry::Entry;
use dashmap::DashMap;
use moka::sync::Cache;

use antiwire_tuning::{
    Backoff, DNS_REFRESH_RETRY_BASE_DELAY_MS, DNS_REFRESH_RETRY_MAX_DELAY_MS,
    DNS_RESPONSE_CACHE_HARD_CAP,
};

use super::entry::CachedAnswer;
use super::key::CacheKey;

#[derive(Clone, Copy)]
pub(super) struct PrefetchBackoff {
    pub(super) failures: u32,
    pub(super) retry_after: Instant,
}

fn prefetch_retry_delay(failures: u32) -> Duration {
    let base = Duration::from_millis(u64::try_from(DNS_REFRESH_RETRY_BASE_DELAY_MS).unwrap_or(1));
    let cap = Duration::from_millis(u64::try_from(DNS_REFRESH_RETRY_MAX_DELAY_MS).unwrap_or(0));
    Backoff::new(base, cap.max(base)).delay(failures)
}

/// Builds the backoff cache with an idle TTL long enough to outlive any
/// configured retry delay.
pub(super) fn new_backoff_cache() -> Cache<CacheKey, PrefetchBackoff> {
    let retry_state_ttl = Duration::from_millis(
        u64::try_from(DNS_REFRESH_RETRY_MAX_DELAY_MS)
            .unwrap_or(30_000)
            .saturating_mul(2),
    );
    Cache::builder()
        .max_capacity(u64::try_from(DNS_RESPONSE_CACHE_HARD_CAP).unwrap_or(1))
        .time_to_idle(retry_state_ttl)
        .build()
}

impl CachedAnswer {
    /// Returns true when a fresh hit on this entry should schedule a
    /// background refresh.
    #[must_use]
    pub(crate) fn should_prefetch(&self) -> bool {
        Instant::now() >= self.prefetch_at
    }
}

impl super::ResponseCache {
    /// Test hook: true while a background prefetch for `key` still holds its
    /// reservation, so a test can await the refresh instead of sleeping.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn prefetch_in_flight(&self, key: &CacheKey) -> bool {
        self.prefetching.contains_key(key)
    }

    /// Reserves one background refresh for `key`.
    #[must_use]
    pub(crate) fn try_reserve_prefetch(&self, key: &CacheKey) -> Option<PrefetchReservation> {
        // RFC 9520 §3.2: no outgoing query while a failure is held.
        if self.failure_held(key) {
            return None;
        }
        let now = Instant::now();
        let failures = match self.prefetch_backoff.get(key) {
            Some(backoff) if now < backoff.retry_after => return None,
            Some(backoff) => backoff.failures,
            None => 0,
        };

        match self.prefetching.entry(key.clone()) {
            Entry::Occupied(_) => None,
            Entry::Vacant(entry) => {
                let token = Arc::new(());
                entry.insert(Arc::clone(&token));
                Some(PrefetchReservation {
                    key: key.clone(),
                    prefetching: Arc::clone(&self.prefetching),
                    prefetch_backoff: Arc::clone(&self.prefetch_backoff),
                    token,
                    failures,
                    completed: false,
                })
            }
        }
    }
}

/// Keeps a prefetch key reserved until its background task finishes or is cancelled.
pub(crate) struct PrefetchReservation {
    key: CacheKey,
    prefetching: Arc<DashMap<CacheKey, Arc<()>>>,
    prefetch_backoff: Arc<Cache<CacheKey, PrefetchBackoff>>,
    token: Arc<()>,
    failures: u32,
    completed: bool,
}

impl PrefetchReservation {
    /// Records the refresh outcome. Success removes the reservation; failure
    /// leaves a bounded exponential retry gate. A reservation dropped by task
    /// cancellation is treated as a failure by [`Drop`].
    pub(crate) fn complete(mut self, succeeded: bool) {
        self.record_outcome(succeeded);
        self.completed = true;
    }

    fn record_outcome(&self, succeeded: bool) {
        let removed = self
            .prefetching
            .remove_if(&self.key, |_, token| Arc::ptr_eq(token, &self.token))
            .is_some();
        if !removed {
            return;
        }

        if succeeded {
            self.prefetch_backoff.invalidate(&self.key);
        } else {
            let failures = self.failures.saturating_add(1);
            self.prefetch_backoff.insert(
                self.key.clone(),
                PrefetchBackoff {
                    failures,
                    retry_after: Instant::now() + prefetch_retry_delay(failures),
                },
            );
        }
    }
}

impl Drop for PrefetchReservation {
    fn drop(&mut self) {
        if !self.completed {
            self.record_outcome(false);
        }
    }
}
