//! Test-only accessors into tracker state. Compiled only under cfg(test).

use super::attribution::needs_socket_attribution;
use super::FlowTracker;
use super::MAX_SOCKET_LOOKUP_ATTEMPTS;
use crate::process_resolver::ProcessIdentities;
use crate::store::FlowStore;
use antiwire_tuning::UNKNOWN_SOCKET_ATTRIBUTION_DELAY;
use netmetrics_core::FlowKey;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

impl<S: FlowStore> FlowTracker<S> {
    /// The process evidence this tracker's processor resolves from.
    #[cfg(test)]
    pub(crate) fn processes_for_test(&self) -> &ProcessIdentities {
        self.processor
            .as_ref()
            .expect("a tracker with a processor")
            .processes()
    }

    #[cfg(test)]
    pub(crate) fn flow_pid_for_test(&self, key: &FlowKey) -> Option<u32> {
        self.active.lock().get(key).map(|flow| flow.pid)
    }

    #[cfg(test)]
    pub(crate) fn remember_port_pid_for_test(&self, key: &FlowKey, pid: u32) {
        self.port_pid_cache.lock().remember(key, pid);
    }

    #[cfg(test)]
    pub(crate) fn flow_lookup_retry_pending_for_test(&self, key: &FlowKey) -> bool {
        self.active.lock().get(key).is_some_and(|flow| {
            needs_socket_attribution(flow)
                && !flow.unknown_socket_lookup_done
                && flow.socket_lookup_attempts < MAX_SOCKET_LOOKUP_ATTEMPTS
        })
    }

    #[cfg(test)]
    pub(crate) fn expire_unknown_grace_for_test(&self, key: &FlowKey) {
        if let Some(flow) = self.active.lock().get_mut(key) {
            flow.unknown_since = Some(
                Instant::now()
                    .checked_sub(UNKNOWN_SOCKET_ATTRIBUTION_DELAY + Duration::from_millis(1))
                    .unwrap_or_else(Instant::now),
            );
        }
    }

    #[cfg(test)]
    pub(crate) fn socket_snapshot_calls_for_test(&self) -> u64 {
        self.socket_snapshot_calls.load(Ordering::Relaxed)
    }

    #[cfg(test)]
    pub(crate) fn flow_identity_for_test(&self, key: &FlowKey) -> Option<(i32, String, String)> {
        self.active
            .lock()
            .get(key)
            .map(|flow| (flow.app_id, flow.app_path.clone(), flow.app_name.clone()))
    }

    #[cfg(test)]
    pub(crate) fn identity_attempts_for_test(&self, key: &FlowKey) -> Option<u8> {
        self.active
            .lock()
            .get(key)
            .map(|flow| flow.identity_lookup_attempts)
    }

    #[cfg(test)]
    pub(crate) fn expire_identity_retry_for_test(&self, key: &FlowKey) {
        if let Some(flow) = self.active.lock().get_mut(key) {
            flow.next_identity_retry = Some(
                Instant::now()
                    .checked_sub(Duration::from_millis(1))
                    .unwrap_or_else(Instant::now),
            );
        }
    }
}
