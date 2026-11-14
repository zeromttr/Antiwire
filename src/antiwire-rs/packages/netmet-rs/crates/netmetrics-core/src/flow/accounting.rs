//! Byte accounting and inferred opens for out-of-order observations.

use super::{FlowTable, UpsertOutcome};
use crate::{ByteDelta, FlowKey, ProcessIdentity, SocketCookie};
use std::sync::Arc;

impl FlowTable {
    /// Adds byte counts, creating an unattributed row if lifecycle arrived out of order.
    pub fn add_bytes(&mut self, key: FlowKey, delta: ByteDelta, timestamp: u64) -> UpsertOutcome {
        self.add_attributed_bytes(key, 0, None, delta, timestamp)
    }

    /// Adds byte counts and applies any PID/process attribution carried by the observation.
    #[allow(clippy::needless_pass_by_value)]
    pub fn add_attributed_bytes(
        &mut self,
        key: FlowKey,
        pid: u32,
        process: Option<ProcessIdentity>,
        delta: ByteDelta,
        timestamp: u64,
    ) -> UpsertOutcome {
        self.add_attributed_bytes_ref(key, pid, process.as_ref(), delta, timestamp, None)
    }

    /// Adds byte counts while borrowing process identity from an attribution cache.
    ///
    /// Existing rows clone identity strings only when attribution actually changes.
    /// A matching cookie is compared against borrowed metadata and does not take the
    /// replacement path. A contradicting cookie splits the old identity before the
    /// delta is charged. Inferred opens adopt the cookie.
    pub fn add_attributed_bytes_ref(
        &mut self,
        key: FlowKey,
        pid: u32,
        process: Option<&ProcessIdentity>,
        delta: ByteDelta,
        timestamp: u64,
        cookie: Option<SocketCookie>,
    ) -> UpsertOutcome {
        let key = self.resolve_existing_key(key);
        if self.entries.contains_key(&key) {
            if Self::cookie_contradicts_stored(
                self.entries.get(&key).and_then(|entry| entry.meta.cookie),
                cookie,
            ) {
                return self.replace_and_add_bytes(key, pid, process, delta, timestamp, cookie);
            }
            return self.add_bytes_to_existing(key, pid, process, delta, timestamp, cookie);
        }
        let mut outcome = self.open(key, pid, process.cloned(), cookie, timestamp);
        self.stats.inferred_opens = self.stats.inferred_opens.saturating_add(1);
        self.charge_bytes(key, delta, timestamp);
        outcome.key = key;
        outcome
    }

    fn replace_and_add_bytes(
        &mut self,
        key: FlowKey,
        pid: u32,
        process: Option<&ProcessIdentity>,
        delta: ByteDelta,
        timestamp: u64,
        cookie: Option<SocketCookie>,
    ) -> UpsertOutcome {
        let mut outcome = self.open(key, pid, process.cloned(), cookie, timestamp);
        self.charge_bytes(key, delta, timestamp);
        outcome.key = key;
        outcome
    }

    fn add_bytes_to_existing(
        &mut self,
        key: FlowKey,
        pid: u32,
        process: Option<&ProcessIdentity>,
        delta: ByteDelta,
        timestamp: u64,
        cookie: Option<SocketCookie>,
    ) -> UpsertOutcome {
        let generation = self.next_generation();
        let Some(entry) = self.entries.get_mut(&key) else {
            return UpsertOutcome {
                key,
                inserted: false,
                attribution_changed: false,
                cookie_learned: false,
                evicted: None,
                superseded: None,
                identity_generation: 0,
            };
        };
        let pid_changed = pid != 0 && entry.meta.pid == 0;
        let process_changed = Self::should_update_process(&entry.meta, pid, process);
        let cookie_learned = Self::should_upgrade_cookie(entry.meta.cookie, cookie);
        if pid_changed || process_changed || cookie_learned {
            let meta = Arc::make_mut(&mut entry.meta);
            if pid_changed {
                meta.pid = pid;
            }
            if process_changed {
                meta.process = process.cloned();
            }
            if cookie_learned {
                meta.cookie = cookie;
            }
        }
        entry.bytes_sent = entry.bytes_sent.saturating_add(delta.sent);
        entry.bytes_received = entry.bytes_received.saturating_add(delta.received);
        entry.last_seen_ts = entry.last_seen_ts.max(timestamp);
        entry.generation = generation;
        let identity_generation = entry.identity_generation;
        self.record_access(key, generation);
        UpsertOutcome {
            key,
            inserted: false,
            attribution_changed: pid_changed || process_changed,
            cookie_learned,
            evicted: None,
            superseded: None,
            identity_generation,
        }
    }

    fn charge_bytes(&mut self, key: FlowKey, delta: ByteDelta, timestamp: u64) {
        if let Some(entry) = self.entries.get_mut(&key) {
            entry.bytes_sent = entry.bytes_sent.saturating_add(delta.sent);
            entry.bytes_received = entry.bytes_received.saturating_add(delta.received);
            entry.last_seen_ts = entry.last_seen_ts.max(timestamp);
        }
    }
}
