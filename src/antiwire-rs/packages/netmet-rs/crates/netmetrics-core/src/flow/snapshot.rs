//! Immutable snapshot capture and deferred materialization of flow records.

use super::FlowTable;
use crate::{FlowKey, FlowMeta, FlowRecord, FlowSnapshot, FlowState};
use std::sync::Arc;

#[derive(Debug)]
struct SharedFlowRecord {
    key: FlowKey,
    meta: Arc<FlowMeta>,
    bytes_sent: u64,
    bytes_received: u64,
    last_seen_ts: u64,
    state: FlowState,
}

/// Cheap, immutable capture of a flow table for deferred snapshot materialization.
///
/// Metadata remains reference-counted until [`FlowSnapshotSeed::into_snapshot`] runs, so the
/// collector's ingress owner does not clone process strings while accepting native events.
#[doc(hidden)]
#[derive(Debug)]
pub struct FlowSnapshotSeed {
    captured_at: u64,
    flows: Vec<SharedFlowRecord>,
    evicted_flows: u64,
}

impl FlowSnapshotSeed {
    /// Materializes an owned public snapshot.
    #[must_use]
    pub fn into_snapshot(self) -> FlowSnapshot {
        FlowSnapshot {
            captured_at: self.captured_at,
            flows: self
                .flows
                .into_iter()
                .map(|flow| FlowRecord {
                    key: flow.key,
                    meta: (*flow.meta).clone(),
                    bytes_sent: flow.bytes_sent,
                    bytes_received: flow.bytes_received,
                    last_seen_ts: flow.last_seen_ts,
                    state: flow.state,
                })
                .collect(),
            evicted_flows: self.evicted_flows,
        }
    }
}

impl FlowTable {
    /// Looks up a flow record.
    pub fn get(&self, key: &FlowKey) -> Option<FlowRecord> {
        self.entries
            .get(key)
            .map(|entry| entry.record(*key, entry.live_state()))
    }

    /// Copies all active rows in deterministic key order.
    ///
    /// Keys are maintained incrementally, so publication is linear rather than sorting the
    /// complete active table on the collector's ingress thread.
    pub fn snapshot(&self, captured_at: u64) -> FlowSnapshot {
        self.snapshot_seed(captured_at).into_snapshot()
    }

    /// Captures active rows without cloning process metadata strings.
    #[doc(hidden)]
    pub fn snapshot_seed(&self, captured_at: u64) -> FlowSnapshotSeed {
        let flows = self
            .ordered_keys
            .iter()
            .filter_map(|key| {
                self.entries.get(key).map(|entry| SharedFlowRecord {
                    key: *key,
                    meta: Arc::clone(&entry.meta),
                    bytes_sent: entry.bytes_sent,
                    bytes_received: entry.bytes_received,
                    last_seen_ts: entry.last_seen_ts,
                    state: entry.live_state(),
                })
            })
            .collect();
        FlowSnapshotSeed {
            captured_at,
            flows,
            evicted_flows: self.stats.evicted,
        }
    }
}
