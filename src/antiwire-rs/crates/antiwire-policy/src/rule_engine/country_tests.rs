use std::sync::Arc;

use ahash::AHashSet;
use ipnet::IpNet;

use super::*;
use crate::rule::{CountrySnapshot, RuleSnapshot, TargetType, Verdict};
use crate::{normalize_rule, EnforcementOp, RuleDirection};

fn nets(list: &[&str]) -> Arc<[IpNet]> {
    list.iter()
        .map(|n| n.parse::<IpNet>().expect("net"))
        .collect()
}

fn country(id: i32, code: &str, list: &[&str]) -> CountrySnapshot {
    CountrySnapshot::new(id, code, nets(list), Verdict::Block, RuleDirection::Both)
}

#[test]
fn country_networks_are_evaluated_by_longest_prefix() {
    let mut engine = RuleEngine::new();
    let _ = engine.upsert_country_rule(&country(1, "KP", &["175.45.176.0/22", "210.52.109.0/24"]));

    assert_eq!(
        engine.evaluate("app.exe", "175.45.176.5", ""),
        Some(Verdict::Block)
    );
    assert_eq!(
        engine.evaluate("app.exe", "210.52.109.9", ""),
        Some(Verdict::Block)
    );
    assert_eq!(engine.evaluate("app.exe", "8.8.8.8", ""), None);
}

#[test]
fn a_country_counts_as_one_rule_not_one_per_network() {
    let mut engine = RuleEngine::new();
    let _ = engine.upsert_country_rule(&country(
        1,
        "KP",
        &["175.45.176.0/22", "210.52.109.0/24", "77.94.35.0/24"],
    ));

    assert_eq!(engine.rule_count(), 1);
    assert_eq!(
        engine.evaluate("app.exe", "175.45.176.5", ""),
        Some(Verdict::Block)
    );
    assert_eq!(
        engine.evaluate("app.exe", "210.52.109.9", ""),
        Some(Verdict::Block)
    );
    assert_eq!(
        engine.evaluate("app.exe", "77.94.35.1", ""),
        Some(Verdict::Block)
    );
}

#[test]
fn a_narrower_user_allow_still_beats_a_country_block() {
    // The whole point of an exception: blocking a country must not make an
    // explicitly allowed host unreachable.
    let mut engine = RuleEngine::new();
    let _ = engine.upsert_country_rule(&country(1, "KP", &["175.45.176.0/22"]));
    let allow = normalize_rule(
        TargetType::Ip,
        "175.45.176.5",
        Verdict::Allow,
        RuleDirection::Outbound,
    )
    .expect("allow rule");
    let _ = engine.upsert_rule(RuleSnapshot { id: 2, ..allow });

    assert_eq!(
        engine.evaluate("app.exe", "175.45.176.5", ""),
        Some(Verdict::Allow)
    );
    assert_eq!(
        engine.evaluate("app.exe", "175.45.176.6", ""),
        Some(Verdict::Block)
    );
}

#[test]
fn removing_a_country_leaves_an_overlapping_user_rule_intact() {
    let mut engine = RuleEngine::new();
    let _ = engine.upsert_country_rule(&country(1, "KP", &["175.45.176.0/22"]));
    let user = normalize_rule(
        TargetType::Ip,
        "175.45.176.0/22",
        Verdict::Allow,
        RuleDirection::Outbound,
    )
    .expect("user rule");
    let _ = engine.upsert_rule(RuleSnapshot { id: 2, ..user });

    let ops = engine.remove_country_rule(1);
    assert!(ops
        .iter()
        .any(|op| matches!(op, EnforcementOp::RemoveCountryBlock { rule_id: 1, .. })));

    // The user rule took ownership of that network, so it must survive.
    assert_eq!(
        engine.evaluate("app.exe", "175.45.176.5", ""),
        Some(Verdict::Allow)
    );
    assert_eq!(engine.rule_count(), 1);
}

#[test]
fn equal_prefix_user_rule_wins_when_country_is_inserted_later() {
    let mut engine = RuleEngine::new();
    let user = normalize_rule(
        TargetType::Ip,
        "175.45.176.0/22",
        Verdict::Allow,
        RuleDirection::Outbound,
    )
    .expect("user rule");
    let _ = engine.upsert_rule(RuleSnapshot { id: 2, ..user });

    let _ = engine.upsert_country_rule(&country(1, "KP", &["175.45.176.0/22"]));

    assert_eq!(
        engine.evaluate("app.exe", "175.45.176.5", ""),
        Some(Verdict::Allow)
    );
}

#[test]
fn removing_equal_prefix_user_rule_restores_country_rule() {
    let mut engine = RuleEngine::new();
    let _ = engine.upsert_country_rule(&country(1, "KP", &["175.45.176.0/22"]));
    let user = RuleSnapshot::new(
        2,
        TargetType::Ip,
        "175.45.176.0/22",
        Verdict::Allow,
        RuleDirection::Outbound,
    );
    let _ = engine.upsert_rule(user.clone());
    assert_eq!(
        engine.evaluate("app.exe", "175.45.176.5", ""),
        Some(Verdict::Allow)
    );

    let _ = engine.remove_rule(&user);

    assert_eq!(
        engine.evaluate("app.exe", "175.45.176.5", ""),
        Some(Verdict::Block)
    );
}

#[test]
fn reapplying_a_country_drops_networks_that_left_the_list() {
    let mut engine = RuleEngine::new();
    let _ = engine.upsert_country_rule(&country(1, "KP", &["1.0.0.0/24", "2.0.0.0/24"]));
    assert_eq!(
        engine.evaluate("app.exe", "2.0.0.1", ""),
        Some(Verdict::Block)
    );

    let _ = engine.upsert_country_rule(&country(1, "KP", &["1.0.0.0/24"]));
    assert_eq!(engine.evaluate("app.exe", "2.0.0.1", ""), None);
    assert_eq!(
        engine.evaluate("app.exe", "1.0.0.1", ""),
        Some(Verdict::Block)
    );
}

#[test]
fn clearing_user_rules_clears_country_state() {
    let mut engine = RuleEngine::new();
    let _ = engine.upsert_country_rule(&country(1, "KP", &["1.0.0.0/24"]));
    engine.clear_user_rules();

    assert_eq!(engine.rule_count(), 0);
    assert_eq!(engine.evaluate("app.exe", "1.0.0.1", ""), None);
}

#[test]
fn removing_an_unknown_country_is_a_no_op() {
    let mut engine = RuleEngine::new();
    assert!(engine.remove_country_rule(404).is_empty());
}

#[test]
fn boot_gate_blocks_until_cleared_except_allow_hosts() {
    let engine = RuleEngine::new();
    let mut allow = AHashSet::new();
    allow.insert("cdn.jsdelivr.net".to_owned());
    engine.arm_blocklist_boot_gate(allow);

    assert!(engine.blocklist_boot_gate_active());
    assert_eq!(
        engine.evaluate_domain("ads.tracker.test"),
        Some(Verdict::Block)
    );
    assert_eq!(
        engine
            .evaluate_domain_with_source("ads.tracker.test")
            .and_then(|decision| decision.source),
        Some(DomainBlockSource::BlocklistPending)
    );
    assert_eq!(engine.evaluate_domain("cdn.jsdelivr.net"), None);
    assert_eq!(
        engine.evaluate("app.exe", "1.2.3.4", "evil.example"),
        Some(Verdict::Block)
    );

    engine.clear_blocklist_boot_gate();
    assert!(!engine.blocklist_boot_gate_active());
    assert_eq!(engine.evaluate_domain("ads.tracker.test"), None);
}

#[test]
fn reported_blocklist_names_use_firewall_label_for_dns_rules() {
    assert_eq!(
        DomainBlockSource::DnsRule.reported_blocklist_names(vec!["hagezi_light".to_owned()]),
        vec![FIREWALL_RULE_LABEL.to_owned()]
    );
    assert_eq!(
        DomainBlockSource::Blocklist.reported_blocklist_names(vec!["hagezi_light".to_owned()]),
        vec!["hagezi_light".to_owned()]
    );
    assert_eq!(
        DomainBlockSource::BlocklistPending
            .reported_blocklist_names(vec!["hagezi_light".to_owned()]),
        vec![LOADING_BLOCKLISTS_LABEL.to_owned()]
    );
}

#[test]
fn matching_blocklists_follow_published_named_sources() {
    let mut engine = RuleEngine::new();
    let mut builder = crate::BlocklistBuilder::new(2);
    builder.add_from_list("hagezi_light", "ads.example");
    engine.publish_blocklist(builder.prepare().expect("prepare"));

    assert_eq!(
        engine.matching_blocklists("SUB.ADS.EXAMPLE"),
        vec!["hagezi_light".to_owned()]
    );
    assert!(engine.matching_blocklists("other.example").is_empty());
}

#[test]
fn dns_allow_rule_bypasses_boot_gate() {
    let mut engine = RuleEngine::new();
    engine.arm_blocklist_boot_gate(AHashSet::new());
    let allow = normalize_rule(
        TargetType::Dns,
        "keep.example",
        Verdict::Allow,
        RuleDirection::Outbound,
    )
    .expect("dns allow");
    let _ = engine.upsert_rule(RuleSnapshot { id: 1, ..allow });

    assert_eq!(engine.evaluate_domain("keep.example"), Some(Verdict::Allow));
    assert_eq!(
        engine.evaluate_domain("other.example"),
        Some(Verdict::Block)
    );
}

/// The regression this guards: an allowed application or domain reported Allow
/// for a connection to a blocked country, while the host firewall, which lets
/// any block win, actually blocked it.
#[test]
fn an_address_or_country_block_overrides_an_app_or_domain_allow() {
    let mut engine = RuleEngine::new();
    let _ = engine.upsert_country_rule(&country(1, "KP", &["175.45.176.0/22"]));
    let app = normalize_rule(
        TargetType::App,
        r"C:\Apps\allowed.exe",
        Verdict::Allow,
        RuleDirection::Outbound,
    )
    .expect("app rule");
    let _ = engine.upsert_rule(RuleSnapshot { id: 2, ..app });
    let domain = normalize_rule(
        TargetType::Dns,
        "allowed.example",
        Verdict::Allow,
        RuleDirection::Outbound,
    )
    .expect("domain rule");
    let _ = engine.upsert_rule(RuleSnapshot { id: 3, ..domain });
    let blocked_ip = normalize_rule(
        TargetType::Ip,
        "203.0.113.9",
        Verdict::Block,
        RuleDirection::Outbound,
    )
    .expect("ip rule");
    let _ = engine.upsert_rule(RuleSnapshot {
        id: 4,
        ..blocked_ip
    });

    assert_eq!(
        engine.evaluate(r"C:\Apps\allowed.exe", "175.45.176.5", ""),
        Some(Verdict::Block)
    );
    assert_eq!(
        engine.evaluate("other.exe", "203.0.113.9", "allowed.example"),
        Some(Verdict::Block)
    );
    // With no address block in play, the allows still decide.
    assert_eq!(
        engine.evaluate(r"C:\Apps\allowed.exe", "8.8.8.8", ""),
        Some(Verdict::Allow)
    );
    assert_eq!(
        engine.evaluate("other.exe", "8.8.8.8", "allowed.example"),
        Some(Verdict::Allow)
    );
}
