use std::hash::Hash;

use ahash::AHashMap;
use ipnet::IpNet;
use prefix_trie::joint::JointPrefixMap;

use crate::rule::{RuleSnapshot, Verdict};

/// Compact value stored per network in the IP trie.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct IpRuleEntry {
    pub(crate) id: i32,
    pub(crate) verdict: Verdict,
}

pub(crate) fn upsert_keyed_rule<K: Eq + Hash>(
    rules_by_target: &mut AHashMap<K, Vec<RuleSnapshot>>,
    target: K,
    rule: RuleSnapshot,
) {
    let rules = rules_by_target.entry(target).or_default();
    rules.retain(|existing| existing.id != rule.id);
    rules.push(rule);
}

pub(crate) fn remove_keyed_rule<K: Eq + Hash>(
    rules_by_target: &mut AHashMap<K, Vec<RuleSnapshot>>,
    target: &K,
    rule_id: i32,
) {
    let should_remove_target = rules_by_target.get_mut(target).is_some_and(|rules| {
        rules.retain(|rule| rule.id != rule_id);
        rules.is_empty()
    });
    if should_remove_target {
        rules_by_target.remove(target);
    }
}

pub(crate) fn upsert_ip_entry(
    rules: &mut JointPrefixMap<IpNet, Vec<IpRuleEntry>>,
    network: IpNet,
    entry: IpRuleEntry,
) {
    if let Some(entries) = rules.get_mut(&network) {
        entries.retain(|existing| existing.id != entry.id);
        entries.push(entry);
    } else {
        rules.insert(network, vec![entry]);
    }
}

pub(crate) fn remove_ip_entry(
    rules: &mut JointPrefixMap<IpNet, Vec<IpRuleEntry>>,
    network: &IpNet,
    rule_id: i32,
) {
    let Some(entries) = rules.get_mut(network) else {
        return;
    };
    entries.retain(|entry| entry.id != rule_id);
    if entries.is_empty() {
        rules.remove(network);
    }
}
