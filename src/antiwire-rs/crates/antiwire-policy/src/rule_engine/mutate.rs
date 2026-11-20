use std::sync::Arc;

use crate::blocklist::PreparedBlocklist;
use crate::eviction::EnforcementOp;
use crate::hash::reverse_hash_pair;
use crate::normalize::parse_ip_net;
use crate::rule::{CountrySnapshot, RuleSnapshot, TargetType, Verdict};
use crate::rule_index::{
    remove_ip_entry, remove_keyed_rule, upsert_ip_entry, upsert_keyed_rule, IpRuleEntry,
};

use super::dns_index::{remove_dns_rule, upsert_dns_rule};
use super::RuleEngine;

impl RuleEngine {
    /// Inserts or replaces a normalized rule and returns its enforcement delta.
    ///
    /// IP snapshots must have been constructed through [`crate::normalize_rule`].
    ///
    /// # Panics
    ///
    /// Panics when an IP snapshot bypasses validation and contains an invalid network.
    #[must_use]
    pub fn upsert_rule(&mut self, rule: RuleSnapshot) -> Vec<EnforcementOp> {
        let ops = self.upsert_rule_inner(rule);
        self.republish_dns_view();
        ops
    }

    /// Replaces every user rule and publishes one DNS view for the complete set.
    ///
    /// The previously published snapshot stays visible until this method
    /// finishes, so DNS readers never observe a cleared or prefix-built ruleset.
    pub fn replace_user_rules(
        &mut self,
        snapshots: impl IntoIterator<Item = RuleSnapshot>,
        countries: impl IntoIterator<Item = CountrySnapshot>,
    ) {
        self.clear_user_indexes();
        for snapshot in snapshots {
            let _ = self.upsert_rule_inner(snapshot);
        }
        for country in countries {
            let _ = self.upsert_country_rule(&country);
        }
        self.republish_dns_view();
    }

    fn upsert_rule_inner(&mut self, rule: RuleSnapshot) -> Vec<EnforcementOp> {
        let mut ops = Vec::with_capacity(2);
        if let Some(previous) = self.rules_by_id.remove(&rule.id) {
            self.remove_rule_from_index(&previous);
            if let Some(op) = EnforcementOp::native_remove(&previous) {
                ops.push(op);
            }
        }

        match rule.target_type {
            TargetType::App => {
                upsert_keyed_rule(
                    &mut self.app_rules,
                    reverse_hash_pair(&rule.target),
                    rule.clone(),
                );
                upsert_keyed_rule(
                    &mut self.app_rules_normalized,
                    crate::app_rule_identity(&rule.target),
                    rule.clone(),
                );
                self.app_block_rules += usize::from(rule.verdict == Verdict::Block);
            }
            TargetType::Dns => {
                upsert_dns_rule(&mut self.dns_rules, &mut self.dns_wildcards, rule.clone());
            }
            TargetType::Ip => {
                let network = parse_ip_net(&rule.target)
                    .expect("IP rule snapshots must contain normalized IP networks");
                upsert_ip_entry(
                    &mut self.ip_rules,
                    network,
                    IpRuleEntry {
                        id: rule.id,
                        verdict: rule.verdict,
                    },
                );
            }
        }
        if let Some(add_op) = EnforcementOp::native_add(&rule) {
            ops.push(add_op);
        }
        self.rules_by_id.insert(rule.id, rule);
        ops
    }

    pub fn remove_rule(&mut self, rule: &RuleSnapshot) -> Vec<EnforcementOp> {
        let Some(stored) = self.rules_by_id.remove(&rule.id) else {
            return Vec::new();
        };
        self.remove_rule_from_index(&stored);
        self.republish_dns_view();
        EnforcementOp::native_remove(&stored).into_iter().collect()
    }

    fn remove_rule_from_index(&mut self, rule: &RuleSnapshot) {
        match rule.target_type {
            TargetType::App => {
                remove_keyed_rule(
                    &mut self.app_rules,
                    &reverse_hash_pair(&rule.target),
                    rule.id,
                );
                remove_keyed_rule(
                    &mut self.app_rules_normalized,
                    &crate::app_rule_identity(&rule.target),
                    rule.id,
                );
                self.app_block_rules -= usize::from(rule.verdict == Verdict::Block);
            }
            TargetType::Dns => {
                remove_dns_rule(&mut self.dns_rules, &mut self.dns_wildcards, rule);
            }
            TargetType::Ip => {
                if let Some(network) = parse_ip_net(&rule.target) {
                    remove_ip_entry(&mut self.ip_rules, &network, rule.id);
                }
            }
        }
    }

    /// Inserts a country rule and returns the op that installs it natively.
    ///
    /// Replaces any existing rule with the same id, so re-applying a country is
    /// idempotent.
    pub fn upsert_country_rule(&mut self, country: &CountrySnapshot) -> EnforcementOp {
        // Drop the previous generation's networks first so a shrinking list
        // does not leave stale prefixes behind.
        self.forget_country_networks(country.id);

        for network in country.networks.iter() {
            upsert_ip_entry(
                &mut self.country_ip_rules,
                *network,
                IpRuleEntry {
                    id: country.id,
                    verdict: country.verdict,
                },
            );
        }
        self.country_rules.insert(country.id, country.clone());

        EnforcementOp::country_add(country)
    }

    /// Removes a country rule and returns the ops that tear it down.
    pub fn remove_country_rule(&mut self, id: i32) -> Vec<EnforcementOp> {
        // Drop the trie entries first: `forget_country_networks` reads the
        // rule's network list out of `country_rules`, so removing the entry
        // beforehand would leave every prefix installed.
        self.forget_country_networks(id);
        let Some(country) = self.country_rules.remove(&id) else {
            return Vec::new();
        };
        vec![EnforcementOp::RemoveCountryBlock {
            rule_id: id,
            code: country.code,
        }]
    }

    /// Drops trie entries still owned by country `id`.
    ///
    /// Only entries this country still owns are removed: a user IP rule added
    /// later for the same network must survive the country going away.
    fn forget_country_networks(&mut self, id: i32) {
        let Some(existing) = self.country_rules.get(&id) else {
            return;
        };
        let networks = Arc::clone(&existing.networks);
        for network in networks.iter() {
            remove_ip_entry(&mut self.country_ip_rules, network, id);
        }
    }

    pub fn publish_blocklist(&mut self, prepared: PreparedBlocklist) {
        self.blocklist.publish(prepared);
        self.republish_dns_view();
    }

    /// The simple rule with `id`, as the engine holds it.
    #[must_use]
    pub fn rule(&self, id: i32) -> Option<&RuleSnapshot> {
        self.rules_by_id.get(&id)
    }

    /// The country rule with `id`, as the engine holds it.
    #[must_use]
    pub fn country_rule(&self, id: i32) -> Option<&CountrySnapshot> {
        self.country_rules.get(&id)
    }

    /// Number of unique domains in the live blocklist snapshot.
    #[must_use]
    pub fn blocklist_domain_count(&self) -> usize {
        self.blocklist.len()
    }
}
