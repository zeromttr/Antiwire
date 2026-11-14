//! Immutable DNS evaluation snapshot published independently of the engine lock.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use arc_swap::ArcSwap;

use crate::blocklist::BlocklistSnapshot;
use crate::normalize::with_normalized_domain;

use super::boot_gate::BlocklistBootGateSnapshot;
use super::dns_index::{decide_normalized_domain, DnsRuleMap};
use super::domain::DomainDecision;
use super::RuleEngine;

/// Published DNS policy: user domain rules, blocklist, and boot-gate together.
pub struct DnsPolicyView {
    generation: u64,
    dns_rules: DnsRuleMap,
    dns_wildcards: DnsRuleMap,
    blocklist: Arc<BlocklistSnapshot>,
    boot_gate: Arc<BlocklistBootGateSnapshot>,
}

impl DnsPolicyView {
    fn from_engine(engine: &RuleEngine, generation: u64) -> Self {
        Self {
            generation,
            dns_rules: engine.dns_rules.clone(),
            dns_wildcards: engine.dns_wildcards.clone(),
            blocklist: engine.blocklist.load_full(),
            boot_gate: engine.blocklist_boot_gate.load_full(),
        }
    }

    #[must_use]
    pub fn evaluate_domain_with_source(&self, domain: &str) -> Option<DomainDecision> {
        with_normalized_domain(domain, |domain| {
            self.evaluate_normalized_domain_with_source(domain)
        })
    }

    #[must_use]
    pub fn evaluate_normalized_domain_with_source(&self, domain: &str) -> Option<DomainDecision> {
        decide_normalized_domain(
            &self.dns_rules,
            &self.dns_wildcards,
            domain,
            |domain| self.boot_gate.blocks_normalized(domain),
            |domain| self.blocklist.lookup::<true>(domain),
        )
    }

    #[must_use]
    pub fn matching_normalized_blocklists(&self, domain: &str) -> Vec<String> {
        self.blocklist.matching::<true>(domain)
    }
}

/// Handle cloned into DNS adapters so evaluation does not take the engine lock.
#[derive(Clone)]
pub struct DnsPolicyHandle {
    inner: Arc<ArcSwap<DnsPolicyView>>,
    generation: Arc<AtomicU64>,
}

impl DnsPolicyHandle {
    pub(super) fn new() -> Self {
        let empty = DnsPolicyView {
            generation: 0,
            dns_rules: DnsRuleMap::default(),
            dns_wildcards: DnsRuleMap::default(),
            blocklist: Arc::new(BlocklistSnapshot::empty()),
            boot_gate: Arc::new(BlocklistBootGateSnapshot {
                active: false,
                allow_hosts: ahash::AHashSet::new(),
            }),
        };
        Self {
            inner: Arc::new(ArcSwap::from_pointee(empty)),
            generation: Arc::new(AtomicU64::new(0)),
        }
    }

    pub(super) fn publish(&self, engine: &RuleEngine) {
        let generation = self.generation.fetch_add(1, Ordering::AcqRel) + 1;
        let view = Arc::new(DnsPolicyView::from_engine(engine, generation));
        self.install(&view);
    }

    fn install(&self, view: &Arc<DnsPolicyView>) {
        let generation = view.generation;
        self.inner.rcu(|current| {
            if current.generation >= generation {
                Arc::clone(current)
            } else {
                Arc::clone(view)
            }
        });
    }

    #[must_use]
    pub fn load(&self) -> arc_swap::Guard<Arc<DnsPolicyView>> {
        self.inner.load()
    }

    #[cfg(test)]
    #[must_use]
    pub fn generation(&self) -> u64 {
        self.generation.load(Ordering::Acquire)
    }

    #[cfg(test)]
    pub fn install_stale_empty_for_test(&self, generation: u64) {
        self.install(&Arc::new(DnsPolicyView {
            generation,
            dns_rules: DnsRuleMap::default(),
            dns_wildcards: DnsRuleMap::default(),
            blocklist: Arc::new(BlocklistSnapshot::empty()),
            boot_gate: Arc::new(BlocklistBootGateSnapshot {
                active: false,
                allow_hosts: ahash::AHashSet::new(),
            }),
        }));
    }
}

impl RuleEngine {
    #[must_use]
    pub fn dns_policy_handle(&self) -> DnsPolicyHandle {
        self.dns_view.clone()
    }

    pub(super) fn republish_dns_view(&self) {
        self.dns_view.publish(self);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{RuleDirection, RuleSnapshot, TargetType, Verdict};

    #[test]
    fn snapshots_share_unchanged_rules_and_keep_old_verdicts() {
        let mut engine = RuleEngine::new();
        for id in 1..=256 {
            let _ = engine.upsert_rule(RuleSnapshot::new(
                id,
                TargetType::Dns,
                format!("{id}.test"),
                Verdict::Block,
                RuleDirection::Both,
            ));
        }
        let handle = engine.dns_policy_handle();
        let old = handle.load();
        assert!(old.dns_rules.ptr_eq(&engine.dns_rules));
        let unchanged = Arc::clone(old.dns_rules.get("2.test").unwrap());
        let replacement = RuleSnapshot::new(
            1,
            TargetType::Dns,
            "1.test",
            Verdict::Allow,
            RuleDirection::Both,
        );
        let _ = engine.upsert_rule(replacement.clone());
        let updated = handle.load();
        assert!(Arc::ptr_eq(
            &unchanged,
            updated.dns_rules.get("2.test").unwrap()
        ));
        assert_eq!(
            old.evaluate_normalized_domain_with_source("1.test")
                .unwrap()
                .verdict,
            Verdict::Block
        );
        assert_eq!(
            updated
                .evaluate_normalized_domain_with_source("1.test")
                .unwrap()
                .verdict,
            Verdict::Allow
        );
        let _ = engine.remove_rule(&replacement);
        assert!(handle
            .load()
            .evaluate_normalized_domain_with_source("1.test")
            .is_none());
        assert_eq!(
            updated
                .evaluate_normalized_domain_with_source("1.test")
                .unwrap()
                .verdict,
            Verdict::Allow
        );
    }

    #[test]
    fn view_and_engine_agree_on_fully_qualified_and_mixed_case_names() {
        let mut engine = RuleEngine::new();
        let _ = engine.upsert_rule(RuleSnapshot::new(
            1,
            TargetType::Dns,
            "example.com",
            Verdict::Block,
            RuleDirection::Both,
        ));
        let handle = engine.dns_policy_handle();
        let view = handle.load();
        for name in [
            "example.com",
            "example.com.",
            "Example.COM.",
            "www.example.com.",
        ] {
            assert_eq!(
                view.evaluate_domain_with_source(name),
                engine.evaluate_domain_with_source(name),
                "{name}"
            );
            assert_eq!(
                view.evaluate_domain_with_source(name).map(|d| d.verdict),
                Some(Verdict::Block),
                "{name}"
            );
        }
        assert_eq!(view.evaluate_domain_with_source("."), None);
    }
}
