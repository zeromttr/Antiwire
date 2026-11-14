//! Small typed, bounded recency cache shared by event deduplication paths.

use std::borrow::Borrow;
use std::hash::Hash;
use std::num::NonZeroUsize;
use std::time::{Duration, Instant};

use lru::LruCache;

/// Bounded LRU cache that admits a key once per configured time window.
pub struct RecentLru<K> {
    entries: LruCache<K, Instant>,
}

impl<K: Eq + Hash> RecentLru<K> {
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        Self {
            entries: LruCache::new(NonZeroUsize::new(capacity).unwrap_or(NonZeroUsize::MIN)),
        }
    }

    /// Returns `true` and records the key unless its current entry is still fresh.
    ///
    /// Takes the key by value for callers that already own one. When the key
    /// is only borrowed, prefer [`RecentLru::should_admit_borrowed`], which
    /// defers the owned copy until the entry is actually inserted.
    pub fn should_admit(&mut self, key: K, now: Instant, window: Duration) -> bool {
        if self.is_fresh(&key, now, window) {
            return false;
        }
        self.entries.put(key, now);
        true
    }

    /// Borrowing form of [`RecentLru::should_admit`]: probes with `key` as-is
    /// and allocates an owned key only when it is admitted. A throttled repeat
    /// (the common case on a hot path) allocates nothing.
    pub fn should_admit_borrowed<Q>(&mut self, key: &Q, now: Instant, window: Duration) -> bool
    where
        K: Borrow<Q>,
        Q: ?Sized + Hash + Eq + ToOwned<Owned = K>,
    {
        if self.is_fresh(key, now, window) {
            return false;
        }
        self.entries.put(key.to_owned(), now);
        true
    }

    /// Touches `key` and reports whether its entry is still inside `window`.
    fn is_fresh<Q>(&mut self, key: &Q, now: Instant, window: Duration) -> bool
    where
        K: Borrow<Q>,
        Q: ?Sized + Hash + Eq,
    {
        self.entries
            .get(key)
            .is_some_and(|recorded| now.saturating_duration_since(*recorded) < window)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn borrowed_probe_matches_owned_semantics() {
        let mut recent: RecentLru<String> = RecentLru::new(2);
        let now = Instant::now();
        let window = Duration::from_secs(30);

        assert!(recent.should_admit_borrowed("one.example", now, window));
        assert!(!recent.should_admit_borrowed("one.example", now, window));
        // Owned and borrowed forms share one table.
        assert!(!recent.should_admit("one.example".to_owned(), now, window));
        assert!(recent.should_admit_borrowed("one.example", now + window, window));
    }

    #[test]
    fn borrowed_probe_respects_capacity() {
        let mut recent: RecentLru<String> = RecentLru::new(2);
        let now = Instant::now();
        let window = Duration::from_secs(30);

        assert!(recent.should_admit_borrowed("one", now, window));
        assert!(recent.should_admit_borrowed("two", now, window));
        assert!(recent.should_admit_borrowed("three", now, window));
        assert!(recent.should_admit_borrowed("one", now, window), "evicted");
        assert!(!recent.should_admit_borrowed("three", now, window));
    }
}
