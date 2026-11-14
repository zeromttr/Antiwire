//! Private Relay compatibility: no rule is loaded into the host's packet filter.

use antiwire_policy::{EnforcementOp, TargetType, Verdict};

use super::{app, country, harness, is_add, rule, Harness};
use crate::rule_service::{CountrySelector, RuleSelector, RuleServiceError};

const APP: &str = r"C:\Users\me\app-1.0\app.exe";
const APP_MOVED: &str = r"C:\Users\me\app-2.0\app.exe";
const NO_EVENTS: [&str; 0] = [];

/// One saved rule of each kind, with packet rules still on.
fn one_rule_of_each_kind(h: &Harness) {
    for new in [
        rule(TargetType::Dns, "blocked.test", Verdict::Block),
        rule(TargetType::Ip, "203.0.113.7", Verdict::Block),
        app(APP, Verdict::Block),
    ] {
        h.service.add_rule(&new).expect("rule");
    }
    h.service
        .add_country_rule(&country("KP", &["175.45.176.0/22"]))
        .expect("country");
}

#[test]
fn turning_it_on_stops_the_firewall_and_leaves_only_domain_rules_in_effect() {
    let h = harness();
    one_rule_of_each_kind(&h);
    h.firewall.clear();

    h.set_private_relay_compatibility(true);

    assert_eq!(
        h.firewall.events(),
        ["stop"],
        "stopping the firewall takes out every rule it held, and nothing is installed"
    );
    let engine = h.engine.read();
    assert_eq!(engine.rule_count(), 1);
    assert_eq!(engine.evaluate_domain("blocked.test"), Some(Verdict::Block));
    assert_eq!(engine.evaluate("", "203.0.113.7", ""), None);
    assert_eq!(engine.evaluate(APP, "", ""), None);
    assert_eq!(engine.evaluate("", "175.45.176.5", ""), None);
    assert_eq!(
        h.store.list_rules().expect("rules").len(),
        4,
        "the rules stay saved for when packet rules come back"
    );
}

#[test]
fn a_restart_with_it_on_never_starts_the_firewall() {
    let h = harness();
    one_rule_of_each_kind(&h);
    h.set_private_relay_compatibility(true);
    h.engine.write().clear_user_rules();
    h.firewall.clear();

    h.service.install_saved_rules().expect("install");

    assert_eq!(h.firewall.events(), NO_EVENTS);
    assert_eq!(
        h.engine.read().evaluate_domain("blocked.test"),
        Some(Verdict::Block)
    );
    assert_eq!(h.engine.read().rule_count(), 1);
}

#[test]
fn a_new_rule_the_firewall_would_enforce_is_refused_and_not_saved() {
    let h = harness();
    h.set_private_relay_compatibility(true);
    h.firewall.clear();

    for new in [
        rule(TargetType::Ip, "203.0.113.7", Verdict::Block),
        rule(TargetType::Ip, "203.0.113.7", Verdict::Allow),
        app(APP, Verdict::Block),
    ] {
        let error = h.service.add_rule(&new).expect_err("refused");
        assert!(matches!(error, RuleServiceError::Invalid(_)), "{error}");
        assert!(
            error.to_string().contains("Private Relay compatibility"),
            "the refusal names its reason: {error}"
        );
    }
    let error = h
        .service
        .add_country_rule(&country("KP", &["175.45.176.0/22"]))
        .expect_err("refused");
    assert!(matches!(error, RuleServiceError::Invalid(_)), "{error}");

    assert_eq!(h.store.list_rules().expect("rules"), []);
    assert_eq!(h.engine.read().rule_count(), 0);
    assert_eq!(h.firewall.events(), NO_EVENTS);
}

#[test]
fn domain_rules_are_added_and_removed_as_before() {
    let h = harness();
    h.set_private_relay_compatibility(true);

    let saved = h
        .service
        .add_rule(&rule(TargetType::Dns, "blocked.test", Verdict::Block))
        .expect("dns rule");
    assert_eq!(
        h.engine.read().evaluate_domain("blocked.test"),
        Some(Verdict::Block)
    );

    assert!(h
        .service
        .remove_rule(&RuleSelector::Id(saved.id))
        .expect("remove"));
    assert_eq!(h.engine.read().evaluate_domain("blocked.test"), None);
    assert_eq!(h.store.list_rules().expect("rules"), []);
    assert_eq!(
        h.domain_rule_changes
            .load(std::sync::atomic::Ordering::SeqCst),
        2,
        "the system's cached answers are still dropped for each change"
    );
}

#[test]
fn rules_saved_before_can_still_be_deleted() {
    let h = harness();
    one_rule_of_each_kind(&h);
    h.set_private_relay_compatibility(true);
    h.firewall.clear();

    for saved in h.store.list_rules().expect("rules") {
        let removed = if saved.target_value == "KP" {
            h.service
                .remove_country_rule(&CountrySelector::Id(saved.id))
        } else {
            h.service.remove_rule(&RuleSelector::Id(saved.id))
        };
        assert!(removed.expect("remove"), "{}", saved.target_value);
    }

    assert_eq!(h.store.list_rules().expect("rules"), []);
    assert!(!h.firewall.applied().iter().any(is_add));
}

#[test]
fn turning_it_off_starts_the_firewall_and_installs_every_saved_rule() {
    let h = harness();
    one_rule_of_each_kind(&h);
    h.set_private_relay_compatibility(true);
    h.firewall.clear();

    h.set_private_relay_compatibility(false);

    assert_eq!(h.firewall.events().first(), Some(&"start"));
    let applied = h.firewall.applied();
    assert!(applied
        .iter()
        .any(|op| matches!(op, EnforcementOp::AddIpRule { .. })));
    assert!(applied
        .iter()
        .any(|op| matches!(op, EnforcementOp::AddAppRule { .. })));
    assert!(applied
        .iter()
        .any(|op| matches!(op, EnforcementOp::AddCountryBlock { .. })));
    let engine = h.engine.read();
    assert_eq!(engine.rule_count(), 4);
    assert_eq!(engine.evaluate("", "203.0.113.7", ""), Some(Verdict::Block));
    assert_eq!(engine.evaluate_domain("blocked.test"), Some(Verdict::Block));
}

/// An application that updates while the mode is on must not leave its rule on the old
/// path, or the rule would come back pointing at an executable that is gone.
#[test]
fn an_application_rule_follows_its_executable_and_is_installed_there_later() {
    let h = harness();
    h.service.add_rule(&app(APP, Verdict::Block)).expect("add");
    h.set_private_relay_compatibility(true);
    h.firewall.clear();

    let outcome = h
        .service
        .retarget_app_rules(APP, APP_MOVED, true)
        .expect("retarget");

    assert_eq!(outcome.moved, 1);
    assert_eq!(
        h.store.list_rules().expect("rules")[0].target_value,
        r"c:\users\me\app-2.0\app.exe"
    );
    assert_eq!(h.firewall.events(), NO_EVENTS);
    assert_eq!(h.engine.read().rule_count(), 0);

    h.set_private_relay_compatibility(false);
    assert!(h.firewall.applied().iter().any(|op| matches!(
        op,
        EnforcementOp::AddAppRule { app_path, .. } if app_path.ends_with(r"app-2.0\app.exe")
    )));
}
