//! Capacity-bounded flow storage shared by every platform backend.

use crate::{FlowKey, FlowMeta, FlowRecord, FlowState};
use std::collections::{BTreeSet, HashMap, VecDeque};
use std::sync::Arc;

mod accounting;
mod attribution;
mod lifecycle;
mod snapshot;
#[cfg(test)]
mod tests;

#[doc(hidden)]
pub use snapshot::FlowSnapshotSeed;

#[derive(Clone, Debug)]
struct FlowEntry {
    meta: Arc<FlowMeta>,
    bytes_sent: u64,
    bytes_received: u64,
    last_seen_ts: u64,
    generation: u64,
    identity_generation: u64,
    /// True once `if_index` came from the interface that owns the local address,
    /// or from an index the backend observed on the event. A route estimate stays false.
    interface_bound: bool,
    /// True once the backend reported the connection no longer established
    /// ([`FlowTable::finish`]).
    finishing: bool,
}

impl FlowEntry {
    /// The state of a flow still in the table.
    fn live_state(&self) -> FlowState {
        if self.finishing {
            FlowState::Finishing
        } else {
            FlowState::Open
        }
    }

    fn record(&self, key: FlowKey, state: FlowState) -> FlowRecord {
        FlowRecord {
            key,
            meta: (*self.meta).clone(),
            bytes_sent: self.bytes_sent,
            bytes_received: self.bytes_received,
            last_seen_ts: self.last_seen_ts,
            state,
        }
    }
}

/// Result of inserting or implicitly creating a flow row.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UpsertOutcome {
    /// Canonical key used by the table after tuple-orientation reconciliation.
    pub key: FlowKey,
    /// Whether the requested key was newly inserted.
    pub inserted: bool,
    /// Whether a pre-existing flow gained or changed PID/process attribution.
    pub attribution_changed: bool,
    /// Whether a pre-existing flow adopted a socket cookie it did not previously have.
    pub cookie_learned: bool,
    /// Least-recently-used row displaced by the insert.
    pub evicted: Option<FlowRecord>,
    /// Row displaced because its cookie proved the tuple is now a different socket.
    ///
    /// Distinct from [`UpsertOutcome::evicted`], which signals capacity pressure.
    pub superseded: Option<FlowRecord>,
    /// Stable identity generation for this socket instance.
    ///
    /// Unchanged by byte updates. A delayed interface estimate must match this
    /// value or it is ignored.
    pub identity_generation: u64,
}

/// Flow table operational counters.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct FlowTableStats {
    /// Entries evicted because the table was full.
    pub evicted: u64,
    /// Byte events that implicitly opened a previously unseen flow.
    pub inferred_opens: u64,
}

/// Single-owner, capacity-bounded flow accounting table.
#[derive(Debug)]
pub struct FlowTable {
    entries: HashMap<FlowKey, FlowEntry>,
    ordered_keys: BTreeSet<FlowKey>,
    lru: VecDeque<(FlowKey, u64)>,
    generation: u64,
    max_flows: usize,
    stats: FlowTableStats,
}

impl FlowTable {
    /// Creates a table.
    ///
    /// # Panics
    ///
    /// Panics when `max_flows` is zero.
    pub fn new(max_flows: usize) -> Self {
        assert!(max_flows > 0, "flow capacity must be non-zero");
        Self {
            entries: HashMap::with_capacity(max_flows.min(4096)),
            ordered_keys: BTreeSet::new(),
            lru: VecDeque::with_capacity(max_flows.min(4096)),
            generation: 0,
            max_flows,
            stats: FlowTableStats::default(),
        }
    }

    /// Returns the number of active flow rows.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns true when no active rows exist.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Returns operational counters.
    pub fn stats(&self) -> FlowTableStats {
        self.stats
    }

    fn ensure_capacity(&mut self) -> Option<FlowRecord> {
        if self.entries.len() < self.max_flows {
            return None;
        }
        while let Some((key, generation)) = self.lru.pop_front() {
            if self
                .entries
                .get(&key)
                .is_none_or(|entry| entry.generation != generation)
            {
                continue;
            }
            let Some(entry) = self.entries.remove(&key) else {
                continue;
            };
            self.ordered_keys.remove(&key);
            self.stats.evicted = self.stats.evicted.saturating_add(1);
            return Some(entry.record(key, FlowState::Closed));
        }
        None
    }

    fn next_generation(&mut self) -> u64 {
        self.generation = self.generation.wrapping_add(1);
        self.generation
    }

    fn record_access(&mut self, key: FlowKey, generation: u64) {
        let queue_cap = self.max_flows.saturating_mul(4).max(self.max_flows);
        if self.lru.len() >= queue_cap {
            let mut live: Vec<_> = self
                .entries
                .iter()
                .map(|(key, entry)| (entry.generation, *key))
                .collect();
            live.sort_unstable();
            self.lru = live
                .into_iter()
                .map(|(generation, key)| (key, generation))
                .collect();
        }
        self.lru.push_back((key, generation));
    }

    /// Maps a byte/disconnect tuple to an already-open flow when a backend reports
    /// the reverse orientation (UDP Recv, or a TCP event that missed Connect).
    fn resolve_existing_key(&self, key: FlowKey) -> FlowKey {
        if self.entries.contains_key(&key) {
            return key;
        }
        let reversed = key.reverse();
        if self.entries.contains_key(&reversed) {
            return reversed;
        }
        key
    }
}
