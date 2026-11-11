//! Flow opens, closes, and replacement when a socket cookie proves tuple reuse.

use super::{FlowEntry, FlowTable, UpsertOutcome};
use crate::{FlowKey, FlowMeta, FlowRecord, FlowState, ProcessIdentity, Protocol, SocketCookie};
use std::net::IpAddr;
use std::sync::Arc;

impl FlowTable {
    /// Inserts or refreshes an open flow.
    ///
    /// When `cookie` contradicts the cookie already stored for `key`, the tuple has been
    /// recycled onto a different socket: the previous row is closed and returned as
    /// [`UpsertOutcome::superseded`], and a zeroed row takes its place.
    pub fn open(
        &mut self,
        key: FlowKey,
        pid: u32,
        process: Option<ProcessIdentity>,
        cookie: Option<SocketCookie>,
        timestamp: u64,
    ) -> UpsertOutcome {
        let superseded = self.take_superseded(key, cookie, timestamp);
        if superseded.is_none() && self.entries.contains_key(&key) {
            let generation = self.next_generation();
            if let Some(entry) = self.entries.get_mut(&key) {
                let pid_changed = pid != 0 && entry.meta.pid == 0;
                let process_changed =
                    Self::should_update_process(&entry.meta, pid, process.as_ref());
                let cookie_learned = Self::should_upgrade_cookie(entry.meta.cookie, cookie);
                let open_ts = entry.meta.open_ts.min(timestamp);
                if pid_changed || process_changed || cookie_learned || open_ts != entry.meta.open_ts
                {
                    let meta = Arc::make_mut(&mut entry.meta);
                    if pid_changed {
                        meta.pid = pid;
                    }
                    if process_changed {
                        meta.process = process;
                    }
                    if cookie_learned {
                        meta.cookie = cookie;
                    }
                    meta.open_ts = open_ts;
                }
                entry.last_seen_ts = entry.last_seen_ts.max(timestamp);
                entry.generation = generation;
                let identity_generation = entry.identity_generation;
                self.record_access(key, generation);
                return UpsertOutcome {
                    key,
                    inserted: false,
                    attribution_changed: pid_changed || process_changed,
                    cookie_learned,
                    evicted: None,
                    superseded: None,
                    identity_generation,
                };
            }
        }

        // As in `should_update_process`: a process created after the flow
        // opened is a later holder of the PID, not the flow's owner.
        let process = process.filter(|process| process.start_ts <= timestamp);
        let evicted = self.ensure_capacity();
        let generation = self.next_generation();
        self.entries.insert(
            key,
            FlowEntry {
                meta: Arc::new(FlowMeta {
                    pid,
                    process,
                    open_ts: timestamp,
                    cookie,
                    if_index: None,
                }),
                bytes_sent: 0,
                bytes_received: 0,
                last_seen_ts: timestamp,
                generation,
                identity_generation: generation,
                interface_bound: false,
            },
        );
        self.ordered_keys.insert(key);
        self.record_access(key, generation);
        UpsertOutcome {
            key,
            inserted: true,
            attribution_changed: false,
            cookie_learned: false,
            evicted,
            superseded,
            identity_generation: generation,
        }
    }

    /// Applies a cookie learned from a side channel to an already-tracked flow.
    ///
    /// Unlike [`FlowTable::open`] this never inserts: a cookie source that enumerates the
    /// whole system socket table must not start tracking flows the lifecycle source never
    /// reported. Returns `None` when `key` is untracked.
    pub fn learn_cookie(
        &mut self,
        key: FlowKey,
        pid: u32,
        cookie: SocketCookie,
        timestamp: u64,
    ) -> Option<UpsertOutcome> {
        let key = self.resolve_existing_key(key);
        if !self.entries.contains_key(&key) {
            return None;
        }
        // `pid` matters most when the cookie contradicts: the replacement row would otherwise
        // start unattributed even though the caller knows who owns the new socket.
        Some(self.open(key, pid, None, Some(cookie), timestamp))
    }

    /// Removes and closes the row at `key` when `cookie` proves it is a different socket.
    ///
    /// Returns `None` whenever either side is unknown, so a missing cookie never splits a
    /// flow.
    fn take_superseded(
        &mut self,
        key: FlowKey,
        cookie: Option<SocketCookie>,
        timestamp: u64,
    ) -> Option<FlowRecord> {
        let incoming = cookie?;
        let stored = self.entries.get(&key)?.meta.cookie?;
        if !stored.contradicts(incoming) {
            return None;
        }
        self.entries.remove(&key).map(|mut entry| {
            entry.last_seen_ts = entry.last_seen_ts.max(timestamp);
            entry.record(key, FlowState::Closed)
        })
    }

    pub(super) fn cookie_contradicts_stored(
        stored: Option<SocketCookie>,
        incoming: Option<SocketCookie>,
    ) -> bool {
        match (stored, incoming) {
            (Some(stored), Some(incoming)) => stored.contradicts(incoming),
            _ => false,
        }
    }

    /// Closes every flow whose local bind matches `protocol`, `local_addr`, and `local_port`.
    ///
    /// An unspecified `local_addr` matches every address in that family on `local_port`, which
    /// is how a wildcard UDP bind disappearing is reported.
    pub fn close_local_endpoint(
        &mut self,
        protocol: Protocol,
        local_addr: IpAddr,
        local_port: u16,
        timestamp: u64,
        cookie: Option<SocketCookie>,
    ) -> Vec<FlowRecord> {
        let keys: Vec<FlowKey> = self
            .entries
            .iter()
            .filter_map(|(key, entry)| {
                let bind_matches = key.protocol == protocol
                    && key.local_port == local_port
                    && (key.local_addr == local_addr
                        || (local_addr.is_unspecified()
                            && key.local_addr.is_ipv4() == local_addr.is_ipv4()));
                if !bind_matches {
                    return None;
                }
                if let Some(vanished) = cookie
                    && let Some(stored) = entry.meta.cookie
                    && stored.contradicts(vanished)
                {
                    return None;
                }
                Some(*key)
            })
            .collect();
        keys.into_iter()
            .filter_map(|key| self.close(&key, timestamp))
            .collect()
    }

    /// Removes and returns a terminal record for a flow.
    pub fn close(&mut self, key: &FlowKey, timestamp: u64) -> Option<FlowRecord> {
        let key = self.resolve_existing_key(*key);
        let closed = self.entries.remove(&key).map(|mut entry| {
            entry.last_seen_ts = entry.last_seen_ts.max(timestamp);
            entry.record(key, FlowState::Closed)
        });
        if closed.is_some() {
            self.ordered_keys.remove(&key);
        }
        closed
    }

    /// Removes every active flow and returns terminal records in deterministic key order.
    #[doc(hidden)]
    pub fn close_all(&mut self, timestamp: u64) -> Vec<FlowRecord> {
        let keys: Vec<_> = self.ordered_keys.iter().copied().collect();
        keys.into_iter()
            .filter_map(|key| self.close(&key, timestamp))
            .collect()
    }
}
