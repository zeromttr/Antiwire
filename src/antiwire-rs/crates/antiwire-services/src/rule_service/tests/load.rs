//! Startup: installing the saved rules.

use antiwire_policy::{EnforcementOp, RuleDirection, RuleTargetKind, TargetType, Verdict};
use antiwire_store::FirewallRule;
use time::OffsetDateTime;

use super::{country, harness, rule};

fn saved_rule(target_type: RuleTargetKind, target: &str) -> FirewallRule {
    FirewallRule {
        id: 0,
        target_type,
        target_value: target.to_owned(),
        action: Verdict::Block,
        direction: RuleDirection::Outbound,
        created_at: OffsetDateTime::now_utc(),
    }
}

#[test]
fn a_restart_rebuilds_every_rule_from_the_store_alone() {
    let h = harness();
    h.service
        .add_rule(&rule(TargetType::Dns, "blocked.test", Verdict::Block))
        .expect("dns rule");
    h.service
        .add_country_rule(&country("KP", &["175.45.176.0/22"]))
        .expect("country");
    h.engine.write().clear_user_rules();
    h.firewall.clear();

    h.service.install_saved_rules().expect("install");

    let engine = h.engine.read();
    assert_eq!(engine.rule_count(), 2);
    assert_eq!(engine.evaluate_domain("blocked.test"), Some(Verdict::Block));
    assert_eq!(
        engine.evaluate("app.exe", "175.45.176.5", ""),
        Some(Verdict::Block)
    );
    assert!(
        h.firewall
            .applied()
            .iter()
            .all(|op| matches!(op, EnforcementOp::AddCountryBlock { .. })),
        "the domain rule is never installed natively"
    );
}

#[test]
fn an_unloadable_row_does_not_stop_other_rules_loading() {
    // Startup used to abort on the first unparseable row, which would take
    // every other rule down with it and leave no way to delete the bad one.
    let h = harness();
    h.store
        .insert_rule(&saved_rule(RuleTargetKind::Country, "not-a-country"))
        .expect("bad row");
    h.store
        .insert_rule(&saved_rule(RuleTargetKind::Dns, "blocked.test"))
        .expect("good row");

    h.service
        .install_saved_rules()
        .expect("install survives the bad row");

    assert_eq!(
        h.engine.read().evaluate_domain("blocked.test"),
        Some(Verdict::Block)
    );
}

#[test]
fn a_rule_the_firewall_rejects_is_not_evaluated_as_enforced() {
    // A rejected rule used to stay in the engine, which kept answering as if
    // the firewall enforced it.
    let h = harness();
    for ip in ["203.0.113.1", "203.0.113.2"] {
        h.store
            .insert_rule(&saved_rule(RuleTargetKind::Ip, ip))
            .expect("rule row");
    }
    h.firewall.fail(
        1,
        |op| matches!(op, EnforcementOp::AddIpRule { ip, .. } if ip == "203.0.113.1/32"),
    );

    h.service
        .install_saved_rules()
        .expect("install survives a rejected rule");

    let engine = h.engine.read();
    assert_eq!(engine.evaluate("", "203.0.113.1", ""), None);
    assert_eq!(engine.evaluate("", "203.0.113.2", ""), Some(Verdict::Block));
    assert!(h
        .firewall
        .applied()
        .iter()
        .any(|op| matches!(op, EnforcementOp::AddIpRule { ip, .. } if ip == "203.0.113.2/32")));
}

#[test]
fn rules_a_previous_run_left_behind_are_cleared_before_installing() {
    // The backend refuses to add a key it can already see, so a start that
    // skipped the clear would fail on the first duplicate and leave the
    // orphans enforcing whatever the last run wanted.
    let h = harness();
    h.service
        .add_rule(&rule(TargetType::Ip, "203.0.113.1", Verdict::Block))
        .expect("ip rule");
    h.firewall.clear();

    h.service.install_saved_rules().expect("install");

    let events = h.firewall.events();
    let clear = events
        .iter()
        .position(|event| *event == "remove_all_managed")
        .expect("startup clears the managed namespace");
    let first_apply = events
        .iter()
        .position(|event| *event == "apply")
        .expect("startup installs the saved rules");
    assert!(clear < first_apply, "{events:?}");
}
