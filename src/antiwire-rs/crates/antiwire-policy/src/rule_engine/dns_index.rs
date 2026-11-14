use std::sync::Arc;

use crate::rule::{RuleSnapshot, Verdict};

use super::domain::{DomainBlockSource, DomainDecision};
// Persistent hash tries share untouched branches with published snapshots.
// Values share each domain's rule stack, so path copying never clones unrelated rules.
pub(super) type DnsRuleMap =
    rpds::HashTrieMapSync<String, Arc<Vec<RuleSnapshot>>, ahash::RandomState>;

pub(super) fn upsert_dns_rule(
    exact: &mut DnsRuleMap,
    wildcards: &mut DnsRuleMap,
    rule: RuleSnapshot,
) {
    let (index, key) = match dns_rule_index_key(&rule.target) {
        DnsRuleKey::Exact(key) => (exact, key),
        DnsRuleKey::Wildcard(key) => (wildcards, key),
    };
    if let Some(rules) = index.get_mut(&key) {
        let rules = Arc::make_mut(rules);
        rules.retain(|existing| existing.id != rule.id);
        rules.push(rule);
    } else {
        index.insert_mut(key, Arc::new(vec![rule]));
    }
}

pub(super) fn remove_dns_rule(
    exact: &mut DnsRuleMap,
    wildcards: &mut DnsRuleMap,
    rule: &RuleSnapshot,
) {
    let (index, key) = match dns_rule_index_key(&rule.target) {
        DnsRuleKey::Exact(key) => (exact, key),
        DnsRuleKey::Wildcard(key) => (wildcards, key),
    };
    if let Some(rules) = index.get_mut(&key) {
        let rules = Arc::make_mut(rules);
        rules.retain(|existing| existing.id != rule.id);
        if rules.is_empty() {
            index.remove_mut(&key);
        }
    }
}

enum DnsRuleKey {
    Exact(String),
    Wildcard(String),
}

fn dns_rule_index_key(target: &str) -> DnsRuleKey {
    let lower = target.to_ascii_lowercase();
    match lower.strip_prefix("*.") {
        Some(suffix) => DnsRuleKey::Wildcard(suffix.to_owned()),
        None => DnsRuleKey::Exact(lower),
    }
}

/// Decision for an already-normalized `domain`, in precedence order: user DNS
/// rules, then the fail-closed boot gate, then the hosts blocklist.
///
/// The gate and blocklist are closures so a caller holding them behind an
/// `ArcSwap` only loads what the earlier steps did not already decide.
pub(super) fn decide_normalized_domain(
    exact: &DnsRuleMap,
    wildcards: &DnsRuleMap,
    domain: &str,
    boot_gate_blocks: impl FnOnce(&str) -> bool,
    blocklist_blocks: impl FnOnce(&str) -> bool,
) -> Option<DomainDecision> {
    if domain.is_empty() {
        return None;
    }
    if let Some(rule) = lookup_user_dns_rule(exact, wildcards, domain) {
        return Some(DomainDecision {
            verdict: rule.verdict,
            source: (rule.verdict == Verdict::Block).then_some(DomainBlockSource::DnsRule),
        });
    }
    let source = if boot_gate_blocks(domain) {
        DomainBlockSource::BlocklistPending
    } else if blocklist_blocks(domain) {
        DomainBlockSource::Blocklist
    } else {
        return None;
    };
    Some(DomainDecision {
        verdict: Verdict::Block,
        source: Some(source),
    })
}

pub(super) fn lookup_user_dns_rule<'a>(
    exact: &'a DnsRuleMap,
    wildcards: &'a DnsRuleMap,
    domain: &str,
) -> Option<&'a RuleSnapshot> {
    if let Some(rule) = exact.get(domain).and_then(|rules| rules.last()) {
        return Some(rule);
    }

    let bytes = domain.as_bytes();
    let mut start = 0;
    while let Some(dot) = bytes[start..].iter().position(|&byte| byte == b'.') {
        start += dot + 1;
        if start >= bytes.len() {
            break;
        }
        let suffix = &domain[start..];
        // Children-only `*.suffix` is narrower than a bare parent rule at the
        // same label, so it wins for subdomain queries.
        if let Some(rule) = wildcards.get(suffix).and_then(|rules| rules.last()) {
            return Some(rule);
        }
        if let Some(rule) = exact.get(suffix).and_then(|rules| rules.last()) {
            return Some(rule);
        }
    }

    None
}
