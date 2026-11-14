//! Drift bookkeeping shared by every native backend.

use std::collections::{BTreeSet, HashSet};

/// Tracks which native rule names are drifted and which have not been reported yet.
///
/// A backend calls [`DriftTracker::observe`] with everything it found drifted on
/// each native refresh. A name is reported once from [`DriftTracker::take`] when
/// it first appears, and again only after it stops drifting and comes back.
#[derive(Debug, Default)]
pub struct DriftTracker {
    active: HashSet<String>,
    pending: Vec<String>,
}

impl DriftTracker {
    /// Creates a tracker with nothing drifted.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Replaces the drifted set with `current`, queueing names not seen before.
    ///
    /// New names are queued in sorted order, without duplicates.
    pub fn observe(&mut self, current: impl IntoIterator<Item = String>) {
        let current: BTreeSet<String> = current.into_iter().collect();
        for name in &current {
            if !self.active.contains(name) && !self.pending.contains(name) {
                self.pending.push(name.clone());
            }
        }
        self.active = current.into_iter().collect();
    }

    /// Forgets that `name` is drifted, so it is reported again if it drifts later.
    pub fn resolve(&mut self, name: &str) {
        self.active.remove(name);
    }

    /// Names drifted as of the last [`DriftTracker::observe`], in no order.
    pub fn active(&self) -> impl Iterator<Item = &str> {
        self.active.iter().map(String::as_str)
    }

    /// Drains the names queued since the last call.
    pub fn take(&mut self) -> Vec<String> {
        std::mem::take(&mut self.pending)
    }

    /// Forgets every drifted and queued name.
    pub fn clear(&mut self) {
        self.active.clear();
        self.pending.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn names(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_owned()).collect()
    }

    #[test]
    fn reports_each_drifted_name_once_in_sorted_order() {
        let mut drift = DriftTracker::new();
        drift.observe(names(&["b", "a", "b"]));
        drift.observe(names(&["a", "b"]));
        assert_eq!(drift.take(), names(&["a", "b"]));
        drift.observe(names(&["a", "b"]));
        assert!(drift.take().is_empty());
    }

    #[test]
    fn reports_again_after_the_name_recovers() {
        let mut drift = DriftTracker::new();
        drift.observe(names(&["a"]));
        assert_eq!(drift.take(), names(&["a"]));
        drift.observe(Vec::new());
        drift.observe(names(&["a"]));
        assert_eq!(drift.take(), names(&["a"]));
    }

    #[test]
    fn resolve_rearms_a_name_still_reported_by_the_next_refresh() {
        let mut drift = DriftTracker::new();
        drift.observe(names(&["a"]));
        let _ = drift.take();
        drift.resolve("a");
        drift.observe(names(&["a"]));
        assert_eq!(drift.take(), names(&["a"]));
    }

    #[test]
    fn clear_drops_queued_names() {
        let mut drift = DriftTracker::new();
        drift.observe(names(&["a"]));
        drift.clear();
        assert!(drift.take().is_empty());
    }
}
