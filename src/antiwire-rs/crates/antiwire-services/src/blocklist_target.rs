//! The part of the policy engine the hosts blocklist service owns.

use antiwire_policy::{PreparedBlocklist, RuleEngine};
use parking_lot::RwLock;

/// The published hosts blocklist and the fail-closed boot gate.
///
/// Only [`HostsBlocklistService`](crate::HostsBlocklistService) writes these,
/// so the rule "DNS stays fail-closed until the selected lists load" has one
/// owner.
pub trait BlocklistTarget: Send + Sync {
    /// Replaces the published blocklist.
    fn publish(&self, prepared: PreparedBlocklist);
    /// Blocks every DNS answer, except for `allow_hosts`, until cleared.
    fn arm_boot_gate(&self, allow_hosts: Vec<String>);
    fn clear_boot_gate(&self);
    fn boot_gate_armed(&self) -> bool;
    /// Unique domains in the published blocklist.
    fn domain_count(&self) -> usize;
}

impl BlocklistTarget for RwLock<RuleEngine> {
    fn publish(&self, prepared: PreparedBlocklist) {
        self.write().publish_blocklist(prepared);
    }

    fn arm_boot_gate(&self, allow_hosts: Vec<String>) {
        tracing::debug!(
            "hosts blocklist boot gate armed; DNS answers are blocked until blocklists load"
        );
        self.read()
            .arm_blocklist_boot_gate(allow_hosts.into_iter().collect());
    }

    fn clear_boot_gate(&self) {
        let engine = self.read();
        if engine.blocklist_boot_gate_active() {
            tracing::debug!("hosts blocklist boot gate cleared");
        }
        engine.clear_blocklist_boot_gate();
    }

    fn boot_gate_armed(&self) -> bool {
        self.read().blocklist_boot_gate_active()
    }

    fn domain_count(&self) -> usize {
        self.read().blocklist_domain_count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use antiwire_policy::{BlocklistBuilder, Verdict};

    #[test]
    fn the_engine_serves_what_is_published_and_the_gate() {
        let engine = RwLock::new(RuleEngine::new());
        let target: &dyn BlocklistTarget = &engine;
        let mut builder = BlocklistBuilder::new(1);
        builder.add_domain("blocklist-commit.test");

        target.publish(builder.prepare().expect("prepare"));
        target.arm_boot_gate(vec!["cdn.jsdelivr.net".to_owned()]);

        assert_eq!(target.domain_count(), 1);
        assert!(target.boot_gate_armed());
        assert_eq!(
            engine.read().evaluate_domain("blocklist-commit.test"),
            Some(Verdict::Block)
        );
        target.clear_boot_gate();
        assert!(!target.boot_gate_armed());
    }
}
