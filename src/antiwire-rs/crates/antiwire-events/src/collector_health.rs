//! Collector capability status surfaced to the dashboard.
//!
//! The flow collector degrades rather than failing when the host denies it a data source.
//! The most consequential loss is byte accounting: on Windows the kernel ETW session needs
//! Administrator, and the IP Helper fallback reports connections but no byte counts at all.
//! Without somewhere to record that, the UI shows zeros with no explanation.

use parking_lot::Mutex;

/// Shared, cheap-to-read view of what the flow collector can currently observe.
///
/// A healthy collector reports nothing, so every capability starts available and is only
/// ever cleared when a backend says it lost one.
///
/// The causes are tracked separately because they recover differently. A collector that was
/// denied elevation stays denied for the life of the process; a collector polling snapshots
/// returns to its native source when that source can start again; a store that is rejecting
/// writes usually comes back; shed records at a full queue come back once it drains. Folding
/// them into one flag meant a transient disk problem left the UI permanently claiming byte
/// accounting was unavailable, and one subsystem's recovery could retract another's fault.
#[derive(Debug, Default)]
pub struct CollectorHealth {
    /// Why the flow tracker itself stopped, if it did. Never cleared: only a daemon
    /// restart can bring the tracker task back.
    tracker: Mutex<Option<String>>,
    /// Why the flow tracker is not making progress, if it is not. Cleared when it
    /// resumes, so a slow flush does not leave the dashboard wrong forever.
    stalled: Mutex<Option<String>>,
    /// Why a native collector source refused access, if one did. Never cleared: the daemon
    /// lacks the privilege until it restarts with it.
    elevation: Mutex<Option<String>>,
    /// Why the collector is polling socket snapshots instead of its native source, if it is.
    /// Cleared when the native source is back.
    fallback: Mutex<Option<String>>,
    /// Why byte counts were dropped between the collector and the tracker, if any were.
    /// Never cleared: those bytes are missing from the totals for good.
    dropped_bytes: Mutex<Option<String>>,
    /// Why local persistence is failing, if it is. Cleared on recovery.
    store: Mutex<Option<String>>,
    /// Why recorded events are being shed, if they are. Kept apart from `store` so the
    /// flow tracker and the DNS block recorder cannot clear each other's fault.
    shed: Mutex<Option<String>>,
}

impl CollectorHealth {
    /// Records that the flow tracker stopped while the daemon was still running.
    ///
    /// Unlike a store outage this never clears: the task is gone, so every later
    /// connection goes unrecorded until the process restarts.
    pub fn mark_flow_tracker_stopped(&self, detail: impl Into<String>) {
        let mut current = self.tracker.lock();
        if current.is_none() {
            *current = Some(detail.into());
        }
    }

    /// Records that the flow tracker has not made progress for a sustained period.
    ///
    /// A wedged task records nothing else — no panic, no flush failure — so without
    /// this the dashboard would keep reporting healthy while no flow is processed.
    /// Cleared by [`Self::clear_flow_tracker_stalled`] once progress resumes.
    pub fn mark_flow_tracker_stalled(&self, detail: impl Into<String>) {
        let mut current = self.stalled.lock();
        if current.is_none() {
            *current = Some(detail.into());
        }
    }

    /// Clears a stall report after the tracker makes progress again.
    ///
    /// Leaves a stopped-tracker fault in place: a task that died mid-stall never
    /// resumes, so clearing here would only hide it.
    pub fn clear_flow_tracker_stalled(&self) {
        *self.stalled.lock() = None;
    }

    /// Records that a native collector source refused access for lack of privilege.
    ///
    /// Connection lifecycle and attribution still work through a fallback; the sent/received
    /// counters are what is lost. There is no way to clear this: a daemon that lacks the
    /// privilege keeps lacking it until it restarts with it, whatever its fallback does.
    pub fn mark_collector_needs_elevation(&self, detail: impl Into<String>) {
        let mut current = self.elevation.lock();
        if current.is_none() {
            *current = Some(detail.into());
        }
    }

    /// Records that the collector is polling socket snapshots, which carry no byte counts,
    /// because its native source is down.
    pub fn mark_snapshot_fallback(&self, detail: impl Into<String>) {
        let mut current = self.fallback.lock();
        if current.is_none() {
            *current = Some(detail.into());
        }
    }

    /// Clears a snapshot fallback after the collector's native source is back.
    ///
    /// Leaves a missing privilege and dropped byte counts in place: neither is undone by the
    /// source coming back.
    pub fn clear_snapshot_fallback(&self) {
        *self.fallback.lock() = None;
    }

    /// Records that byte counts were dropped on their way from the collector, so traffic
    /// totals are lower than the real volume.
    ///
    /// Never cleared: the dropped counts are not recovered.
    pub fn mark_bytes_dropped(&self, detail: impl Into<String>) {
        let mut current = self.dropped_bytes.lock();
        if current.is_none() {
            *current = Some(detail.into());
        }
    }

    /// Records that observed traffic cannot be written to the local database.
    ///
    /// Separate from the collector's faults so that [`Self::clear_store_unavailable`] cannot
    /// erase one it did not cause.
    pub fn mark_store_unavailable(&self, detail: impl Into<String>) {
        let mut current = self.store.lock();
        if current.is_none() {
            *current = Some(detail.into());
        }
    }

    /// Clears a store fault after writes start succeeding again.
    ///
    /// Leaves any collector fault in place — a daemon that needs elevation still needs it
    /// no matter what the database is doing.
    pub fn clear_store_unavailable(&self) {
        *self.store.lock() = None;
    }

    /// Records that observed events are being dropped because a bounded queue is full or
    /// its worker could not start.
    ///
    /// Distinct from [`Self::mark_store_unavailable`]: shedding is a local capacity
    /// failure. The two are tracked separately so a recovery in one subsystem cannot
    /// retract an outage that belongs to the other.
    pub fn mark_records_shed(&self, detail: impl Into<String>) {
        let mut current = self.shed.lock();
        if current.is_none() {
            *current = Some(detail.into());
        }
    }

    /// Clears a shed report after events are being persisted again.
    pub fn clear_records_shed(&self) {
        *self.shed.lock() = None;
    }

    /// Returns false when sent/received figures will stay at zero or records are being
    /// dropped, so the dashboard still surfaces the explanation.
    pub fn byte_accounting_available(&self) -> bool {
        self.by_priority()
            .into_iter()
            .all(|fault| fault.lock().is_none())
    }

    /// Returns the user-facing explanation, empty while nothing is degraded.
    ///
    /// The fault [`Self::by_priority`] puts first wins.
    pub fn detail(&self) -> String {
        self.by_priority()
            .into_iter()
            .find_map(|fault| fault.lock().clone())
            .unwrap_or_default()
    }

    /// Every fault, the one to explain first leading.
    ///
    /// A stopped tracker leads, then a stalled one: nothing downstream of either can run
    /// while they last. The collector's faults are next, a missing privilege first: the user
    /// can act on it, and it is the cause of the fallback that usually follows it. All of
    /// those outrank a store or shed fault, which usually clear themselves.
    fn by_priority(&self) -> [&Mutex<Option<String>>; 7] {
        [
            &self.tracker,
            &self.stalled,
            &self.elevation,
            &self.fallback,
            &self.dropped_bytes,
            &self.store,
            &self.shed,
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn starts_healthy() {
        let health = CollectorHealth::default();
        assert!(health.byte_accounting_available());
        assert_eq!(health.detail(), "");
    }

    /// The missing privilege is what the user can act on, so it is explained ahead of the
    /// fallback it caused, whichever was reported first.
    #[test]
    fn the_actionable_cause_leads_the_fallback_it_caused() {
        let health = CollectorHealth::default();
        health.mark_snapshot_fallback("snapshot only");
        health.mark_collector_needs_elevation("needs Administrator");

        assert!(!health.byte_accounting_available());
        assert_eq!(health.detail(), "needs Administrator");
    }

    /// A native source can come back, so its fallback has to be retractable, and a later
    /// loss has to be reported again.
    #[test]
    fn a_snapshot_fallback_clears_when_the_native_source_is_back() {
        let health = CollectorHealth::default();
        health.mark_snapshot_fallback("snapshot only");
        assert!(!health.byte_accounting_available());

        health.clear_snapshot_fallback();
        assert!(health.byte_accounting_available());
        assert_eq!(health.detail(), "");

        health.mark_snapshot_fallback("snapshot only again");
        assert!(!health.byte_accounting_available());
        assert_eq!(health.detail(), "snapshot only again");
    }

    /// The source coming back neither grants the privilege nor recovers dropped counts.
    #[test]
    fn clearing_the_fallback_leaves_a_missing_privilege_and_dropped_bytes_alone() {
        let health = CollectorHealth::default();
        health.mark_collector_needs_elevation("needs Administrator");
        health.mark_snapshot_fallback("snapshot only");
        health.clear_snapshot_fallback();
        assert_eq!(health.detail(), "needs Administrator");

        let health = CollectorHealth::default();
        health.mark_bytes_dropped("some bytes were not counted");
        health.mark_snapshot_fallback("snapshot only");
        health.clear_snapshot_fallback();
        assert!(!health.byte_accounting_available());
        assert_eq!(health.detail(), "some bytes were not counted");
    }

    /// A store outage is transient, so its report has to be retractable — otherwise a
    /// few seconds of disk trouble leaves the UI wrong until the daemon restarts.
    #[test]
    fn a_store_fault_clears_once_writes_recover() {
        let health = CollectorHealth::default();
        health.mark_store_unavailable("database is unwritable");

        assert!(!health.byte_accounting_available());
        assert_eq!(health.detail(), "database is unwritable");

        health.clear_store_unavailable();
        assert!(health.byte_accounting_available());
        assert_eq!(health.detail(), "");
    }

    /// Clearing the store fault must not resurrect a collector that is still degraded.
    #[test]
    fn clearing_a_store_fault_leaves_a_collector_fault_alone() {
        let health = CollectorHealth::default();
        health.mark_collector_needs_elevation("needs Administrator");
        health.mark_store_unavailable("database is unwritable");

        health.clear_store_unavailable();

        assert!(
            !health.byte_accounting_available(),
            "the collector is still degraded"
        );
        assert_eq!(health.detail(), "needs Administrator");
    }

    /// Order must not matter: a store fault reported first cannot mask, or be masked by,
    /// a later collector fault.
    #[test]
    fn a_collector_fault_leads_regardless_of_report_order() {
        let health = CollectorHealth::default();
        health.mark_store_unavailable("database is unwritable");
        health.mark_collector_needs_elevation("needs Administrator");

        assert_eq!(health.detail(), "needs Administrator");

        health.clear_store_unavailable();
        assert!(!health.byte_accounting_available());
        assert_eq!(health.detail(), "needs Administrator");
    }

    /// A dead tracker is total loss, so it has to be reported and can never be
    /// retracted: only a restart brings the task back.
    #[test]
    fn a_stopped_tracker_is_reported_and_never_clears() {
        let health = CollectorHealth::default();
        health.mark_flow_tracker_stopped("flow recording stopped");
        health.mark_flow_tracker_stopped("another explanation");

        assert!(!health.byte_accounting_available());
        assert_eq!(health.detail(), "flow recording stopped");
    }

    /// The tracker leads over every other fault: nothing downstream of it runs.
    #[test]
    fn a_tracker_fault_leads_over_a_store_fault() {
        let health = CollectorHealth::default();
        health.mark_store_unavailable("database is unwritable");
        health.mark_flow_tracker_stopped("flow recording stopped");

        assert!(!health.byte_accounting_available());
        assert_eq!(health.detail(), "flow recording stopped");
    }

    /// A stall is reported while it lasts and retracted as soon as progress resumes.
    #[test]
    fn a_stalled_tracker_is_reported_and_cleared_on_recovery() {
        let health = CollectorHealth::default();
        health.mark_flow_tracker_stalled("flow tracking is not making progress");

        assert!(!health.byte_accounting_available());
        assert_eq!(health.detail(), "flow tracking is not making progress");

        health.clear_flow_tracker_stalled();
        assert!(health.byte_accounting_available());
        assert_eq!(health.detail(), "");
    }

    /// Clearing a stall must not retract a tracker that actually died.
    #[test]
    fn clearing_a_stall_leaves_a_stopped_tracker_alone() {
        let health = CollectorHealth::default();
        health.mark_flow_tracker_stopped("flow recording stopped");
        health.mark_flow_tracker_stalled("flow tracking is not making progress");

        health.clear_flow_tracker_stalled();

        assert!(!health.byte_accounting_available());
        assert_eq!(health.detail(), "flow recording stopped");
    }

    /// A shed report is a degradation the user has to see, and it clears independently.
    #[test]
    fn a_shed_report_is_surfaced_and_recovered() {
        let health = CollectorHealth::default();
        health.mark_records_shed("blocked DNS history is incomplete");

        assert!(!health.byte_accounting_available());
        assert_eq!(health.detail(), "blocked DNS history is incomplete");

        health.clear_records_shed();
        assert!(health.byte_accounting_available());
        assert_eq!(health.detail(), "");
    }

    /// Clearing a shed report must not disturb an unrelated store fault.
    #[test]
    fn clearing_a_shed_report_leaves_a_store_fault_alone() {
        let health = CollectorHealth::default();
        health.mark_store_unavailable("database is unwritable");
        health.mark_records_shed("blocked DNS history is incomplete");

        health.clear_records_shed();

        assert!(!health.byte_accounting_available());
        assert_eq!(health.detail(), "database is unwritable");
    }
}
