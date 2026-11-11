//! Rules on one application, address, or domain.

use antiwire_policy::{
    DomainBlockSource, EnforcementOp, RuleTargetKind, TargetType, Verdict, FIREWALL_RULE_LABEL,
};
use antiwire_store::FirewallRule;
use time::OffsetDateTime;

use super::{harness, is_add, rule};
use crate::rule_service::{RuleSelector, RuleServiceError};

#[test]
fn invalid_targets_are_refused_before_anything_is_saved() {
    let h = harness();

    let error = h
        .service
        .add_rule(&rule(TargetType::Ip, "not-a-network", Verdict::Block))
        .expect_err("not a network");

    assert!(matches!(error, RuleServiceError::Invalid(_)));
    assert!(h.store.list_rules().expect("rules").is_empty());
    assert!(h.firewall.applied().is_empty());
}

#[test]
fn a_rule_is_saved_normalized_and_enforced() {
    let h = harness();

    let saved = h
        .service
        .add_rule(&rule(TargetType::Ip, "203.0.113.1", Verdict::Block))
        .expect("add");

    assert_eq!(saved.target_type, RuleTargetKind::Ip);
    assert_eq!(saved.target_value, "203.0.113.1/32");
    assert_eq!(h.store.list_rules().expect("rules"), vec![saved]);
    assert_eq!(
        h.engine.read().evaluate("", "203.0.113.1", ""),
        Some(Verdict::Block)
    );
    assert!(matches!(
        h.firewall.applied().as_slice(),
        [EnforcementOp::AddIpRule { ip, .. }] if ip == "203.0.113.1/32"
    ));
}

#[test]
fn a_failed_install_undoes_the_saved_row_and_the_engine() {
    let h = harness();
    h.firewall.fail(1, is_add);

    let error = h
        .service
        .add_rule(&rule(TargetType::Ip, "203.0.113.1", Verdict::Block))
        .expect_err("install fails");

    assert!(matches!(error, RuleServiceError::Enforce(_)));
    assert!(h.store.list_rules().expect("rules").is_empty());
    assert_eq!(h.engine.read().evaluate("", "203.0.113.1", ""), None);
}

#[test]
fn a_domain_rule_stays_in_the_engine_but_its_removal_drops_leftover_keys() {
    let h = harness();

    let saved = h
        .service
        .add_rule(&rule(TargetType::Dns, "blocked.test", Verdict::Block))
        .expect("dns rule");
    assert!(
        h.firewall.applied().is_empty(),
        "domain rules must not become native firewall ops"
    );
    assert_eq!(
        h.engine.read().evaluate_domain("blocked.test"),
        Some(Verdict::Block)
    );

    assert!(h
        .service
        .remove_rule(&RuleSelector::Id(saved.id))
        .expect("remove"));
    assert!(
        matches!(
            h.firewall.applied().as_slice(),
            [EnforcementOp::RemoveDnsRule { domain, .. }] if domain == "blocked.test"
        ),
        "deleting a domain rule must still drop leftover native dr* keys"
    );
    assert_eq!(h.engine.read().evaluate_domain("blocked.test"), None);
}

#[test]
fn removal_by_target_matches_the_normalized_target() {
    // Removal by value used to compare the raw input, so a mixed-case path
    // or an alias reported a rule that exists as not found.
    let h = harness();
    h.service
        .add_rule(&rule(TargetType::App, r"C:\Apps\App.exe", Verdict::Block))
        .expect("add");

    let removed = h
        .service
        .remove_rule(&RuleSelector::Target {
            target_type: TargetType::App,
            target: r"c:\apps\APP.EXE".to_owned(),
        })
        .expect("remove");

    assert!(removed);
    assert!(h.store.list_rules().expect("rules").is_empty());
}

#[test]
fn removing_a_missing_rule_reports_false() {
    let h = harness();

    assert!(!h
        .service
        .remove_rule(&RuleSelector::Id(42))
        .expect("remove"));
}

#[test]
fn a_failed_removal_restores_the_rule_everywhere() {
    let h = harness();
    let saved = h
        .service
        .add_rule(&rule(TargetType::Ip, "203.0.113.1", Verdict::Block))
        .expect("add");
    h.firewall
        .fail(1, |op| matches!(op, EnforcementOp::RemoveIpRule { .. }));

    h.service
        .remove_rule(&RuleSelector::Id(saved.id))
        .expect_err("removal fails");

    assert_eq!(h.store.list_rules().expect("rules").len(), 1);
    assert_eq!(
        h.engine.read().evaluate("", "203.0.113.1", ""),
        Some(Verdict::Block)
    );
}

#[test]
fn a_row_that_never_loaded_can_still_be_removed() {
    let h = harness();
    let id = h
        .store
        .insert_rule(&FirewallRule {
            id: 0,
            target_type: RuleTargetKind::Ip,
            target_value: "not-a-network".to_owned(),
            action: Verdict::Block,
            direction: antiwire_policy::RuleDirection::Both,
            created_at: OffsetDateTime::now_utc(),
        })
        .expect("bad row");

    assert!(h
        .service
        .remove_rule(&RuleSelector::Id(id))
        .expect("remove"));
    assert!(h.store.list_rules().expect("rules").is_empty());
}

#[test]
fn a_country_block_is_not_removed_as_a_simple_rule() {
    let h = harness();
    let summary = h
        .service
        .add_country_rule(&super::country("KP", &["175.45.176.0/22"]))
        .expect("country");

    let error = h
        .service
        .remove_rule(&RuleSelector::Id(summary.id))
        .expect_err("refused");

    assert!(matches!(error, RuleServiceError::Invalid(_)));
    assert_eq!(h.store.list_rules().expect("rules").len(), 1);
}

#[test]
fn the_listing_separates_country_blocks_from_simple_rules() {
    let h = harness();
    h.service
        .add_rule(&rule(TargetType::Dns, "blocked.test", Verdict::Block))
        .expect("dns rule");
    h.service
        .add_country_rule(&super::country(
            "KP",
            &["175.45.176.0/22", "210.52.109.0/24"],
        ))
        .expect("country");

    let listing = h.service.list().expect("list");

    assert_eq!(listing.rules.len(), 1);
    assert_eq!(listing.rules[0].target_type, RuleTargetKind::Dns);
    assert_eq!(listing.countries.len(), 1);
    assert_eq!(listing.countries[0].code, "KP");
    assert_eq!(listing.countries[0].network_count, 2);
}

#[test]
fn a_blocked_domain_is_explained_by_its_rule() {
    let h = harness();
    h.service
        .add_rule(&rule(TargetType::Dns, "blocked.test", Verdict::Block))
        .expect("dns rule");

    let block = h
        .service
        .explain_domain_block(" blocked.test ")
        .expect("blocked");

    assert_eq!(block.source, Some(DomainBlockSource::DnsRule));
    assert_eq!(block.blocklist_names, vec![FIREWALL_RULE_LABEL.to_owned()]);
    assert_eq!(h.service.explain_domain_block("allowed.test"), None);
    assert_eq!(h.service.explain_domain_block(""), None);
}
