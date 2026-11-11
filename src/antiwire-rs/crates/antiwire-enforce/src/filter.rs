use antiwire_policy::EnforcementOp;

use crate::Result;

/// Platform firewall surface consumed by the policy layer.
pub trait FirewallFilter: Send {
    /// Brings the native firewall backend online.
    fn start(&mut self) -> Result<()>;

    /// Brings the backend online for a daemon whose "persist rules offline"
    /// setting is `keep_rules_offline`.
    ///
    /// A backend that can tie its rules to this process, so that they go
    /// when it dies, does so only when the setting is off.
    ///
    /// Defaults to [`Self::start`] for backends with no such choice.
    fn start_with_persistence(&mut self, keep_rules_offline: bool) -> Result<()> {
        let _ = keep_rules_offline;
        self.start()
    }

    /// Removes managed rules and tears down the backend.
    fn stop(&mut self) -> Result<()>;

    /// Tears down the backend but leaves the rules meant to protect the host
    /// while the daemon is offline installed. Rules that only make sense
    /// while Antiwire's resolver runs are still removed.
    ///
    /// Cleanup errors must not cause subsequent shutdown or drop to remove
    /// the rules intended to persist.
    ///
    /// Defaults to [`Self::stop`] for backends that own no host state.
    fn stop_keeping_rules(&mut self) -> Result<()> {
        self.stop()
    }

    /// True when kernel rules are actually being applied.
    fn is_enforcing(&self) -> bool;

    /// Applies one enforcement intent.
    fn apply(&mut self, op: EnforcementOp) -> Result<()>;

    /// Removes every rule in this manager's namespace, leaving the backend open.
    ///
    /// Unlike [`Self::stop`] this keeps enforcement running, so a caller can
    /// clear rules a previous process left installed and then apply the set it
    /// actually wants. Defaults to a no-op for backends that own no host state.
    fn remove_all_managed(&mut self) -> Result<()> {
        Ok(())
    }

    /// Drains managed rules that drifted out of recognition.
    ///
    /// Returns the native names of rules still carrying our ownership grouping
    /// whose marker no longer parses — normally because they were renamed or
    /// edited outside the app. Reported rather than treated as corruption, so
    /// the daemon can tell the user without losing enforcement.
    fn take_drift(&mut self) -> Result<Vec<String>> {
        Ok(Vec::new())
    }
}
