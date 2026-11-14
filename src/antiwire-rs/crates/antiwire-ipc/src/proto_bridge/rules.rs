//! Firewall rule requests and listings, between wire and domain types.
//!
//! Requests are parsed here, once, into typed values; the rule service never
//! sees a target type, action, or direction as a string.

use antiwire_policy::{RuleDirection, RuleTargetKind, Verdict};
use antiwire_proto::{CountryRule, CountryRuleSummary, Rule};
use antiwire_services::{CountrySelector, NewCountryBlock, NewRule, RuleSelector};
use antiwire_store::FirewallRule;

use super::scalars::{id_from_proto, id_to_proto};

pub(crate) fn rule_to_proto(rule: &FirewallRule) -> Rule {
    Rule {
        id: id_to_proto(rule.id),
        target_type: rule.target_type.as_str().to_owned(),
        target_value: rule.target_value.clone(),
        action: rule.action.as_str().to_owned(),
        direction: rule.direction.as_str().to_owned(),
    }
}

pub(crate) fn country_summary_to_proto(
    summary: &antiwire_services::CountryRuleSummary,
) -> CountryRuleSummary {
    CountryRuleSummary {
        id: id_to_proto(summary.id),
        country_code: summary.code.clone(),
        action: summary.verdict.as_str().to_owned(),
        direction: summary.direction.as_str().to_owned(),
        cidr_count: summary.network_count,
    }
}

/// A rule to add. Fails with a message the user can read.
pub(crate) fn new_rule_from_proto(rule: Rule) -> Result<NewRule, String> {
    Ok(NewRule {
        target_type: simple_target_type(&rule.target_type)?,
        target: rule.target_value,
        verdict: verdict(&rule.action)?,
        direction: direction(&rule.direction)?,
    })
}

/// The rule to remove: by id when one is given, otherwise by target.
pub(crate) fn rule_selector_from_proto(rule: Rule) -> Result<RuleSelector, String> {
    if rule.id != 0 {
        return id_from_proto(rule.id).map(RuleSelector::Id);
    }
    Ok(RuleSelector::Target {
        target_type: simple_target_type(&rule.target_type)?,
        target: rule.target_value,
    })
}

pub(crate) fn new_country_block_from_proto(rule: CountryRule) -> Result<NewCountryBlock, String> {
    Ok(NewCountryBlock {
        code: rule.country_code,
        networks: rule.cidrs,
        verdict: verdict(&rule.action)?,
        direction: direction(&rule.direction)?,
    })
}

/// The country block to remove: by id when one is given, otherwise by code.
pub(crate) fn country_selector_from_proto(rule: CountryRule) -> Result<CountrySelector, String> {
    if rule.id != 0 {
        return id_from_proto(rule.id).map(CountrySelector::Id);
    }
    Ok(CountrySelector::Code(rule.country_code))
}

fn simple_target_type(value: &str) -> Result<antiwire_policy::TargetType, String> {
    RuleTargetKind::parse(value)
        .and_then(RuleTargetKind::target_type)
        .ok_or_else(|| format!("unsupported target type: {value}"))
}

fn verdict(value: &str) -> Result<Verdict, String> {
    Verdict::parse(value).ok_or_else(|| format!("unsupported action: {value}"))
}

fn direction(value: &str) -> Result<RuleDirection, String> {
    RuleDirection::parse(value).ok_or_else(|| format!("unsupported direction: {value}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use antiwire_policy::TargetType;

    fn proto(target_type: &str, action: &str, direction: &str) -> Rule {
        Rule {
            id: 0,
            target_type: target_type.to_owned(),
            target_value: "example.test".to_owned(),
            action: action.to_owned(),
            direction: direction.to_owned(),
        }
    }

    #[test]
    fn requests_parse_aliases_and_reject_unknown_values() {
        let rule = new_rule_from_proto(proto("app", "block", "")).expect("valid");
        assert_eq!(rule.target_type, TargetType::App);
        assert_eq!(rule.verdict, Verdict::Block);
        assert_eq!(rule.direction, RuleDirection::Outbound);

        for (target_type, action, direction) in [
            ("UNKNOWN", "BLOCK", "OUTBOUND"),
            ("COUNTRY", "BLOCK", "OUTBOUND"),
            ("DNS", "DENY", "OUTBOUND"),
            ("DNS", "BLOCK", "SIDEWAYS"),
        ] {
            assert!(
                new_rule_from_proto(proto(target_type, action, direction)).is_err(),
                "{target_type} {action} {direction}"
            );
        }
    }

    #[test]
    fn a_selector_prefers_the_id_and_rejects_one_out_of_range() {
        let mut rule = proto("DNS", "", "");
        rule.id = 7;
        assert_eq!(
            rule_selector_from_proto(rule.clone()),
            Ok(RuleSelector::Id(7))
        );
        rule.id = u32::MAX;
        assert!(rule_selector_from_proto(rule.clone()).is_err());
        rule.id = 0;
        assert!(matches!(
            rule_selector_from_proto(rule),
            Ok(RuleSelector::Target { .. })
        ));
    }
}
