//! The `RuleService` handle and the gate every rule change holds.

use std::sync::Arc;

use antiwire_enforce::EnforcementClient;
use antiwire_events::{Alert, AlertKind, AlertPublisher, Severity};
use antiwire_policy::RuleEngine;
use antiwire_store::Store;
use parking_lot::{Mutex, MutexGuard, RwLock};

/// Owns the user's firewall rules: what is saved, what the policy engine
/// evaluates, and what the native firewall enforces, kept in agreement.
pub struct RuleService {
    pub(super) store: Arc<Store>,
    pub(super) engine: Arc<RwLock<RuleEngine>>,
    pub(super) enforce: EnforcementClient,
    alerts: AlertPublisher,
    /// Held for the whole of every change and every listing. A change spans
    /// the store, the engine, and the firewall, each with its own lock;
    /// without this, two changes could interleave between them, and a
    /// listing could show a row whose change is about to be undone.
    gate: Mutex<()>,
}

impl RuleService {
    #[must_use]
    pub fn new(
        store: Arc<Store>,
        engine: Arc<RwLock<RuleEngine>>,
        enforce: EnforcementClient,
        alerts: AlertPublisher,
    ) -> Self {
        Self {
            store,
            engine,
            enforce,
            alerts,
            gate: Mutex::new(()),
        }
    }

    /// Holds the gate for one change. When the change ends, any firewall rule
    /// the backend found modified outside Antiwire is reported.
    pub(super) fn begin_change(&self) -> ChangeGuard<'_> {
        ChangeGuard {
            service: self,
            _gate: self.gate.lock(),
        }
    }

    /// Holds the gate for a read, so it never sees a change halfway through.
    pub(super) fn read_gate(&self) -> MutexGuard<'_, ()> {
        self.gate.lock()
    }

    /// Reports rules the backend found renamed or edited outside Antiwire.
    ///
    /// Such a rule stops being recognisable as ours, so the backend skips it
    /// rather than failing every later change. Without this the user would
    /// not know a rule they rely on quietly stopped being enforced. Each name
    /// is reported once.
    fn report_drift(&self) {
        let drifted = match self.enforce.take_drift() {
            Ok(drifted) => drifted,
            Err(error) => {
                tracing::warn!(%error, "could not read firewall rule drift");
                return;
            }
        };
        if drifted.is_empty() {
            return;
        }
        tracing::warn!(
            count = drifted.len(),
            rules = ?drifted,
            "firewall rules were modified outside antiwire and are no longer managed"
        );
        let message = match drifted.as_slice() {
            [only] => format!(
                "\"{only}\" was changed outside Antiwire and is no longer managed. \
                 Delete it in Windows Firewall, then re-create the rule here."
            ),
            many => format!(
                "{} firewall rules were changed outside Antiwire and are no longer managed. \
                 Delete them in Windows Firewall, then re-create the rules here.",
                many.len()
            ),
        };
        self.alerts.publish(Alert::new(
            AlertKind::FirewallRuleDrift,
            Severity::Warning,
            "Firewall rule modified outside Antiwire",
            message,
        ));
    }
}

/// Proof that the caller holds the rule service's gate for a change.
pub(super) struct ChangeGuard<'a> {
    service: &'a RuleService,
    _gate: MutexGuard<'a, ()>,
}

impl<'a> ChangeGuard<'a> {
    pub(super) fn service(&self) -> &'a RuleService {
        self.service
    }
}

impl Drop for ChangeGuard<'_> {
    fn drop(&mut self) {
        // Every change talks to the firewall, which is where drift surfaces.
        self.service.report_drift();
    }
}
