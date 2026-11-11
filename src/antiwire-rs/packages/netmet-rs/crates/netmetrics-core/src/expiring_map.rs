//! Bounded map whose entries each carry an expiry deadline.

use std::collections::{BTreeSet, HashMap};
use std::hash::Hash;
use std::time::Instant;

/// At most `CAPACITY` entries, each dropped once its deadline passes.
///
/// Deadlines are kept in order beside the entries, so expiring and evicting the
/// soonest-to-expire entry are both `O(log n)`. Every entry has exactly one
/// deadline, including after it is refreshed. When the map is full, inserting
/// a new key evicts the entry closest to expiry.
#[derive(Debug)]
pub struct ExpiringMap<K, V, const CAPACITY: usize> {
    entries: HashMap<K, (V, Instant)>,
    deadlines: BTreeSet<(Instant, K)>,
}

impl<K, V, const CAPACITY: usize> Default for ExpiringMap<K, V, CAPACITY> {
    fn default() -> Self {
        Self {
            entries: HashMap::new(),
            deadlines: BTreeSet::new(),
        }
    }
}

impl<K: Copy + Eq + Hash + Ord, V, const CAPACITY: usize> ExpiringMap<K, V, CAPACITY> {
    /// Drops every entry whose deadline is at or before `now`.
    pub fn expire(&mut self, now: Instant) {
        while self
            .deadlines
            .first()
            .is_some_and(|(deadline, _)| *deadline <= now)
        {
            self.evict_soonest();
        }
    }

    /// Stores `value` under `key` until `expires_at`, replacing any earlier value.
    pub fn insert(&mut self, key: K, value: V, expires_at: Instant) {
        if let Some((stored, deadline)) = self.entries.get_mut(&key) {
            *stored = value;
            let previous = std::mem::replace(deadline, expires_at);
            self.deadlines.remove(&(previous, key));
            self.deadlines.insert((expires_at, key));
            return;
        }
        if self.entries.len() >= CAPACITY {
            self.evict_soonest();
        }
        self.entries.insert(key, (value, expires_at));
        self.deadlines.insert((expires_at, key));
    }

    pub fn get(&self, key: &K) -> Option<&V> {
        self.entries.get(key).map(|(value, _)| value)
    }

    pub fn get_mut(&mut self, key: &K) -> Option<&mut V> {
        self.entries.get_mut(key).map(|(value, _)| value)
    }

    pub fn contains_key(&self, key: &K) -> bool {
        self.entries.contains_key(key)
    }

    /// When `key` expires, if it is present.
    pub fn deadline(&self, key: &K) -> Option<Instant> {
        self.entries.get(key).map(|(_, deadline)| *deadline)
    }

    /// Moves `key`'s deadline to `expires_at`. Returns false when `key` is absent.
    pub fn set_deadline(&mut self, key: &K, expires_at: Instant) -> bool {
        let Some((_, deadline)) = self.entries.get_mut(key) else {
            return false;
        };
        let previous = std::mem::replace(deadline, expires_at);
        self.deadlines.remove(&(previous, *key));
        self.deadlines.insert((expires_at, *key));
        true
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn values(&self) -> impl Iterator<Item = &V> {
        self.entries.values().map(|(value, _)| value)
    }

    /// Number of tracked deadlines, which always equals [`Self::len`].
    pub fn deadline_count(&self) -> usize {
        self.deadlines.len()
    }

    fn evict_soonest(&mut self) {
        if let Some((_, key)) = self.deadlines.pop_first() {
            self.entries.remove(&key);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    #[test]
    fn expires_entries_at_their_deadline() {
        let now = Instant::now();
        let mut map = ExpiringMap::<u32, &str, 4>::default();
        map.insert(1, "a", now + Duration::from_secs(1));
        map.insert(2, "b", now + Duration::from_secs(2));
        map.expire(now + Duration::from_secs(1));
        assert_eq!(map.get(&1), None);
        assert_eq!(map.get(&2), Some(&"b"));
        assert_eq!(map.deadline_count(), map.len());
    }

    #[test]
    fn refreshing_keeps_one_deadline_per_entry() {
        let now = Instant::now();
        let mut map = ExpiringMap::<u32, u32, 4>::default();
        map.insert(1, 10, now + Duration::from_secs(1));
        map.insert(1, 11, now + Duration::from_secs(5));
        assert!(map.set_deadline(&1, now + Duration::from_secs(3)));
        assert!(!map.set_deadline(&2, now));
        assert_eq!((map.len(), map.deadline_count()), (1, 1));
        assert_eq!(map.get(&1), Some(&11));
        assert_eq!(map.deadline(&1), Some(now + Duration::from_secs(3)));
    }

    #[test]
    fn a_full_map_evicts_the_entry_closest_to_expiry() {
        let now = Instant::now();
        let mut map = ExpiringMap::<u32, (), 2>::default();
        map.insert(1, (), now + Duration::from_secs(9));
        map.insert(2, (), now + Duration::from_secs(1));
        map.insert(3, (), now + Duration::from_secs(5));
        assert!(map.contains_key(&1) && map.contains_key(&3));
        assert!(!map.contains_key(&2));
        // Replacing an existing key never evicts.
        map.insert(1, (), now + Duration::from_secs(2));
        assert_eq!(map.len(), 2);
    }
}
