//! Authoritative policy evaluator shared by DNS and connection enforcement paths.

mod boot_gate;
mod dns_index;
mod dns_view;
mod domain;
mod evaluate;
mod mutate;

#[cfg(test)]
mod country_tests;
#[cfg(test)]
mod policy_trait_tests;
#[cfg(test)]
mod tests;

use ahash::{AHashMap, AHashSet};
use ipnet::IpNet;
use prefix_trie::joint::JointPrefixMap;

use crate::blocklist::BlocklistEngine;
use crate::rule::{CountrySnapshot, RuleSnapshot};
use crate::rule_index::IpRuleEntry;

use boot_gate::BlocklistBootGate;
use dns_index::DnsRuleMap;
use dns_view::DnsPolicyHandle;

pub use dns_view::{DnsPolicyHandle as PublishedDnsPolicyHandle, DnsPolicyView};
pub use domain::{
    DomainBlockSource, DomainDecision, PolicyEngine, AI_BLOCK_LABEL, FIREWALL_RULE_LABEL,
    LOADING_BLOCKLISTS_LABEL,
};

/// Authoritative policy evaluator shared by DNS and connection enforcement paths.
pub struct RuleEngine {
    rules_by_id: AHashMap<i32, RuleSnapshot>,
    app_rules: AHashMap<u64, Vec<RuleSnapshot>>,
    /// App rules keyed by version family, so a rule created for one install
    /// version keeps matching after an in-place update.
    app_rules_normalized: AHashMap<String, Vec<RuleSnapshot>>,
    /// Application rules that block. Only a block carries over to another
    /// version, so with none the version-family lookup is skipped.
    app_block_rules: usize,
    /// Bare user domain rules (`example.com`): this host and all subdomains.
    /// Name-only: never emitted as [`crate::EnforcementOp`].
    dns_rules: DnsRuleMap,
    /// `*.suffix` user rules: children only, keyed by the suffix (`com`, `example.com`).
    dns_wildcards: DnsRuleMap,
    ip_rules: JointPrefixMap<IpNet, Vec<IpRuleEntry>>,
    country_ip_rules: JointPrefixMap<IpNet, Vec<IpRuleEntry>>,
    country_rules: AHashMap<i32, CountrySnapshot>,
    blocklist: BlocklistEngine,
    blocklist_boot_gate: BlocklistBootGate,
    dns_view: DnsPolicyHandle,
}

impl Default for RuleEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl RuleEngine {
    #[must_use]
    pub fn new() -> Self {
        let engine = Self {
            rules_by_id: AHashMap::new(),
            app_rules: AHashMap::new(),
            app_rules_normalized: AHashMap::new(),
            app_block_rules: 0,
            dns_rules: DnsRuleMap::default(),
            dns_wildcards: DnsRuleMap::default(),
            ip_rules: JointPrefixMap::new(),
            country_ip_rules: JointPrefixMap::new(),
            country_rules: AHashMap::new(),
            blocklist: BlocklistEngine::new(),
            blocklist_boot_gate: BlocklistBootGate::new(),
            dns_view: DnsPolicyHandle::new(),
        };
        engine.republish_dns_view();
        engine
    }

    /// Arms fail-closed DNS blocking until hosts blocklists finish loading/syncing.
    ///
    /// Domains in `allow_hosts` (blocklist CDN / custom list hosts) remain resolvable.
    pub fn arm_blocklist_boot_gate(&self, allow_hosts: AHashSet<String>) {
        self.blocklist_boot_gate.arm(allow_hosts);
        self.republish_dns_view();
    }

    /// Clears the fail-closed boot gate after a successful cache load or sync reload.
    pub fn clear_blocklist_boot_gate(&self) {
        self.blocklist_boot_gate.clear();
        self.republish_dns_view();
    }

    #[must_use]
    pub fn blocklist_boot_gate_active(&self) -> bool {
        self.blocklist_boot_gate.is_active()
    }

    /// Clears user-defined rules while preserving blocklist state.
    pub fn clear_user_rules(&mut self) {
        self.clear_user_indexes();
        self.republish_dns_view();
    }

    fn clear_user_indexes(&mut self) {
        self.rules_by_id.clear();
        self.app_rules.clear();
        self.app_rules_normalized.clear();
        self.app_block_rules = 0;
        self.dns_rules = DnsRuleMap::default();
        self.dns_wildcards = DnsRuleMap::default();
        self.ip_rules.clear();
        self.country_ip_rules.clear();
        self.country_rules.clear();
    }

    /// Number of logical rules.
    ///
    /// A country counts once, not once per network, so the figure matches what
    /// the user sees in the rules list.
    #[must_use]
    pub fn rule_count(&self) -> usize {
        self.rules_by_id.len() + self.country_rules.len()
    }
}
