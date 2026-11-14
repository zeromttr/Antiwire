//! Process, cookie, and interface enrichment guarded by socket identity.

use super::FlowTable;
use crate::{CookieSource, FlowKey, FlowMeta, ProcessIdentity, SocketCookie};
use std::sync::Arc;

impl FlowTable {
    pub(super) fn should_update_process(
        meta: &FlowMeta,
        incoming_pid: u32,
        incoming: Option<&ProcessIdentity>,
    ) -> bool {
        let Some(incoming) = incoming else {
            return false;
        };
        if incoming_pid == 0 || (meta.pid != 0 && meta.pid != incoming_pid) {
            return false;
        }
        match meta.process.as_ref() {
            Some(current) => {
                let same_instance = current.start_ts == incoming.start_ts
                    || (current.start_ts == 0 && incoming.start_ts <= meta.open_ts);
                let keeps_path = !current.executable.contains(['\\', '/'])
                    || incoming.executable.contains(['\\', '/']);
                same_instance && keeps_path && current != incoming
            }
            None => incoming.start_ts == 0 || incoming.start_ts <= meta.open_ts,
        }
    }

    pub(super) fn should_upgrade_cookie(
        stored: Option<SocketCookie>,
        incoming: Option<SocketCookie>,
    ) -> bool {
        match (stored, incoming) {
            (None, Some(_)) => true,
            (Some(stored), Some(incoming)) => {
                stored.source == CookieSource::LinuxInode
                    && incoming.source == CookieSource::LinuxSockCookie
            }
            _ => false,
        }
    }

    /// Records an observed interface for an already-tracked flow.
    ///
    /// An index carried on the open or byte event is treated as bound to the
    /// flow. It replaces a route estimate and is not itself replaced later.
    /// Returns true when the index changed.
    pub fn remember_interface(&mut self, key: FlowKey, if_index: u32) -> bool {
        self.store_interface(key, if_index, None, true)
    }

    /// Records an interface lookup only when `identity_generation` still matches.
    ///
    /// A delayed lookup must not annotate a recycled tuple. A bound answer
    /// replaces a route estimate; a route estimate does not replace either a
    /// bound answer or an earlier estimate. Returns true when the index changed.
    pub fn remember_interface_if_generation(
        &mut self,
        key: FlowKey,
        if_index: u32,
        identity_generation: u64,
        bound: bool,
    ) -> bool {
        self.store_interface(key, if_index, Some(identity_generation), bound)
    }

    fn store_interface(
        &mut self,
        key: FlowKey,
        if_index: u32,
        identity_generation: Option<u64>,
        bound: bool,
    ) -> bool {
        let key = self.resolve_existing_key(key);
        let Some(entry) = self.entries.get_mut(&key) else {
            return false;
        };
        if identity_generation.is_some_and(|generation| entry.identity_generation != generation) {
            return false;
        }
        if entry.interface_bound || (entry.meta.if_index.is_some() && !bound) {
            return false;
        }
        if entry.meta.if_index == Some(if_index) && entry.interface_bound == bound {
            return false;
        }
        Arc::make_mut(&mut entry.meta).if_index = Some(if_index);
        entry.interface_bound = bound;
        true
    }

    /// Identity generation of the live row at `key`, if any.
    #[must_use]
    pub fn identity_generation(&self, key: FlowKey) -> Option<u64> {
        let key = self.resolve_existing_key(key);
        self.entries
            .get(&key)
            .map(|entry| entry.identity_generation)
    }

    /// Records `pid` on a flow that is already tracked and still unowned.
    ///
    /// Returns false when the flow is absent or already has an owner, so a
    /// close cannot create a connection that was never opened here.
    pub fn adopt_pid_if_present(
        &mut self,
        key: FlowKey,
        pid: u32,
        process: Option<ProcessIdentity>,
    ) -> bool {
        if pid == 0 {
            return false;
        }
        let key = self.resolve_existing_key(key);
        let Some(entry) = self.entries.get_mut(&key) else {
            return false;
        };
        if entry.meta.pid != 0 {
            return false;
        }
        let process_changed = Self::should_update_process(&entry.meta, pid, process.as_ref());
        let meta = Arc::make_mut(&mut entry.meta);
        meta.pid = pid;
        if process_changed {
            meta.process = process;
        }
        true
    }

    /// Backfills process identity on active rows attributed to `pid`.
    pub fn update_process(&mut self, pid: u32, process: &ProcessIdentity) -> usize {
        let mut updated = 0;
        for entry in self.entries.values_mut() {
            if entry.meta.pid == pid && Self::should_update_process(&entry.meta, pid, Some(process))
            {
                Arc::make_mut(&mut entry.meta).process = Some(process.clone());
                updated += 1;
            }
        }
        updated
    }
}
