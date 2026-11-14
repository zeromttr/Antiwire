//! Saved rule rows as policy snapshots.

use std::collections::HashMap;

use antiwire_policy::{
    normalize_rule, CountrySnapshot, RuleDirection, RuleSnapshot, RuleTargetKind, TargetType,
    Verdict,
};
use antiwire_store::FirewallRule;

use super::country::{normalize_country_code, normalize_country_networks};
use super::error::{Result, RuleServiceError};

/// A saved rule as the engine holds it.
pub(super) enum StoredRule {
    Simple(RuleSnapshot),
    Country(CountrySnapshot),
}

/// A simple rule's normalized snapshot.
///
/// # Errors
///
/// [`RuleServiceError::Invalid`] for a country row, or a target that does
/// not normalize.
pub(super) fn rule_snapshot(rule: &FirewallRule) -> Result<RuleSnapshot> {
    let Some(target_type) = rule.target_type.target_type() else {
        return Err(RuleServiceError::invalid(format!(
            "rule {} is a country block",
            rule.id
        )));
    };
    normalize_rule(target_type, &rule.target_value, rule.action, rule.direction)
        .map(|snapshot| RuleSnapshot {
            id: rule.id,
            ..snapshot
        })
        .ok_or_else(|| invalid_target(target_type, &rule.target_value))
}

/// `target` normalized the way a saved rule of `target_type` holds it.
pub(super) fn normalize_target(target_type: TargetType, target: &str) -> Result<String> {
    normalize_rule(target_type, target, Verdict::Block, RuleDirection::Outbound)
        .map(|snapshot| snapshot.target)
        .ok_or_else(|| invalid_target(target_type, target))
}

fn invalid_target(target_type: TargetType, target: &str) -> RuleServiceError {
    RuleServiceError::invalid(format!("invalid {target_type} target: {target}"))
}

/// A country row's snapshot, from the networks saved with it.
pub(super) fn country_snapshot(
    rule: &FirewallRule,
    networks: &[String],
) -> Result<CountrySnapshot> {
    let code = normalize_country_code(&rule.target_value)?;
    let networks = normalize_country_networks(networks)?;
    Ok(CountrySnapshot::new(
        rule.id,
        code,
        networks,
        rule.action,
        rule.direction,
    ))
}

pub(super) fn stored_rule(rule: &FirewallRule, networks: &[String]) -> Result<StoredRule> {
    match rule.target_type {
        RuleTargetKind::Country => country_snapshot(rule, networks).map(StoredRule::Country),
        RuleTargetKind::Application | RuleTargetKind::Dns | RuleTargetKind::Ip => {
            rule_snapshot(rule).map(StoredRule::Simple)
        }
    }
}

/// Every saved rule as engine snapshots.
///
/// A row that will not parse is logged and skipped rather than failing the
/// whole set: one bad row would otherwise take every other rule down with it,
/// and leave the user no way to delete it.
pub(super) fn snapshots(
    rules: &[FirewallRule],
    networks: &HashMap<i32, Vec<String>>,
) -> (Vec<RuleSnapshot>, Vec<CountrySnapshot>) {
    let mut simple = Vec::new();
    let mut countries = Vec::new();
    for rule in rules {
        let rule_networks = networks.get(&rule.id).map_or(&[][..], Vec::as_slice);
        match stored_rule(rule, rule_networks) {
            Ok(StoredRule::Simple(snapshot)) => simple.push(snapshot),
            Ok(StoredRule::Country(country)) => countries.push(country),
            Err(error) => tracing::warn!(
                rule_id = rule.id,
                target_type = %rule.target_type,
                %error,
                "skipping unloadable firewall rule"
            ),
        }
    }
    (simple, countries)
}
