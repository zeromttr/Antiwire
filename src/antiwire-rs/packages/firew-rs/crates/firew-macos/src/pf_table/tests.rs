use std::collections::BTreeMap;

use firew_core::{Action, Direction, ErrorKind, PortRange, Protocol, Rule, RuleKey};
use firew_sys::ManagedNamespace;
use ipnet::IpNet;

use super::*;

fn test_ns() -> ManagedNamespace {
    ManagedNamespace::derive("manager", "app")
}

fn rule_with(direction: Direction, nets: &[&str]) -> Rule {
    Rule::builder("cb0000100000", Action::Block, direction)
        .remote_address_set(nets.iter().map(|n| n.parse::<IpNet>().expect("net")))
        .build()
        .expect("rule")
}

fn anchor_for(rule: Rule) -> String {
    let mut rules = BTreeMap::new();
    rules.insert(rule.logical_key().clone(), rule);
    render_anchor(&rules, &test_ns()).expect("render")
}

#[test]
fn renders_table_and_outbound_rule_with_scoped_table_and_label() {
    let ns = test_ns();
    let rule = rule_with(Direction::Outbound, &["203.0.113.0/24", "198.51.100.7/32"]);
    let table = table_name_for(&ns, rule.logical_key());
    assert_eq!(table.len(), 19);
    assert!(table.len() <= MAX_PF_TABLE_NAME_LEN);

    let text = anchor_for(rule);
    assert!(
        text.contains(&format!(
            "table <{table}> persist {{ 198.51.100.7, 203.0.113.0/24 }}"
        )),
        "unexpected table line in:\n{text}"
    );
    assert!(
        text.contains(&format!(
            "block drop out quick inet from any to <{table}> label \"fw1:"
        )),
        "unexpected rule line in:\n{text}"
    );
}

#[test]
fn max_length_rule_key_table_name_fits_pf_table_name_size() {
    let ns = test_ns();
    let long_key = RuleKey::try_from("k".repeat(32)).expect("32-char key");
    let table = table_name_for(&ns, &long_key);
    assert!(
        table.len() <= MAX_PF_TABLE_NAME_LEN,
        "table name {table} ({}) exceeds {MAX_PF_TABLE_NAME_LEN}",
        table.len()
    );
}

#[test]
fn set_rules_differing_in_local_addresses_and_local_ports_render_distinct_text_and_round_trip() {
    let ns = test_ns();
    let rule_a = Rule::builder("set-a", Action::Block, Direction::Outbound)
        .protocol(Protocol::Tcp)
        .remote_address_set(["203.0.113.0/24".parse::<IpNet>().expect("net")])
        .local_address("10.0.0.1/32".parse::<IpNet>().expect("local a"))
        .local_port(PortRange::single(1000).expect("port a"))
        .remote_port(PortRange::single(80).expect("rport 1"))
        .remote_port(PortRange::single(443).expect("rport 2"))
        .build()
        .expect("rule a");

    let rule_b = Rule::builder("set-a", Action::Block, Direction::Outbound)
        .protocol(Protocol::Tcp)
        .remote_address_set(["203.0.113.0/24".parse::<IpNet>().expect("net")])
        .local_address("10.0.0.2/32".parse::<IpNet>().expect("local b"))
        .local_port(PortRange::single(2000).expect("port b"))
        .remote_port(PortRange::single(80).expect("rport 1"))
        .remote_port(PortRange::single(443).expect("rport 2"))
        .build()
        .expect("rule b");

    let text_a = anchor_for(rule_a.clone());
    let text_b = anchor_for(rule_b);
    assert_ne!(text_a, text_b);
    assert!(text_a.contains("from 10.0.0.1 port = 1000 to <"));
    assert!(text_a.contains("port = 80"));
    assert!(text_a.contains("port = 443"));

    let listing = reconstruct_anchor_text(&text_a, &ns, |_| Ok(None)).expect("reconstruct");
    assert!(listing.drifted.is_empty());
    assert_eq!(listing.rules.get(rule_a.logical_key()), Some(&rule_a));
}

#[test]
fn bidirectional_rules_reference_the_table_on_both_sides() {
    let ns = test_ns();
    let rule = rule_with(Direction::Both, &["203.0.113.0/24"]);
    let table = table_name_for(&ns, rule.logical_key());
    let text = anchor_for(rule);
    assert!(text.contains(&format!("block drop in quick inet from <{table}> to any")));
    assert!(text.contains(&format!("block drop out quick inet from any to <{table}>")));
}

#[test]
fn tables_precede_the_rules_that_reference_them() {
    let text = anchor_for(rule_with(Direction::Outbound, &["203.0.113.0/24"]));
    let table_at = text.find("table <").expect("table line");
    let rule_at = text.find("block drop").expect("rule line");
    assert!(table_at < rule_at, "table must be declared first:\n{text}");
}

#[test]
fn full_anchor_renders_and_reconstructs_mixed_cartesian_and_set_rules() {
    let ns = test_ns();
    let cartesian = Rule::builder("plain", Action::Allow, Direction::Both)
        .protocol(Protocol::Udp)
        .remote_address("203.0.113.1/32".parse::<IpNet>().expect("net"))
        .remote_port(PortRange::range(1000, 2000).expect("range"))
        .build()
        .expect("cartesian");
    let set_rule = rule_with(Direction::Outbound, &["198.51.100.0/24"]);

    let mut map = BTreeMap::new();
    map.insert(cartesian.logical_key().clone(), cartesian.clone());
    map.insert(set_rule.logical_key().clone(), set_rule.clone());

    let text = render_full_anchor(&map, &ns).expect("render full");
    let listing = reconstruct_anchor_text(&text, &ns, |_| Ok(None)).expect("reconstruct");
    assert!(listing.drifted.is_empty());
    assert!(listing.unrecognized.is_empty());
    assert_eq!(listing.rules, map);
}

#[test]
fn unparsed_lines_are_kept_verbatim_with_their_key() {
    let ns = test_ns();
    let kept = Rule::builder("kept", Action::Block, Direction::Outbound)
        .remote_address("203.0.113.1/32".parse::<IpNet>().expect("net"))
        .build()
        .expect("rule");
    let edited = Rule::builder("edited", Action::Block, Direction::Outbound)
        .remote_address("203.0.113.2/32".parse::<IpNet>().expect("net"))
        .build()
        .expect("rule");
    let mut map = BTreeMap::new();
    map.insert(kept.logical_key().clone(), kept.clone());
    map.insert(edited.logical_key().clone(), edited.clone());
    let text = render_full_anchor(&map, &ns).expect("render");
    // Someone dropped `quick` from one managed rule and added a foreign one.
    let edited_line = text
        .lines()
        .find(|line| line.contains("203.0.113.2"))
        .expect("edited line")
        .replace(" quick", "");
    let foreign = "pass out proto tcp from any to 192.0.2.7";
    let mut listed = String::new();
    for line in text
        .lines()
        .filter(|line| !line.contains("203.0.113.2"))
        .chain([edited_line.as_str(), foreign])
    {
        listed.push_str(line);
        listed.push('\n');
    }

    let listing = reconstruct_anchor_text(&listed, &ns, |_| Ok(None)).expect("reconstruct");

    assert_eq!(listing.rules.len(), 1);
    assert_eq!(listing.rules.get(kept.logical_key()), Some(&kept));
    assert_eq!(
        listing.unrecognized,
        vec![
            (Some(edited.logical_key().clone()), edited_line.clone()),
            (None, foreign.to_owned()),
        ]
    );
}

#[test]
fn table_reads_fail_unless_the_table_is_missing() {
    assert_eq!(
        table_show_outcome("t", true, "   192.0.2.0/24\n", "").expect("listed"),
        Some(vec!["192.0.2.0/24".parse::<IpNet>().expect("net")])
    );
    assert_eq!(
        table_show_outcome("t", false, "", "pfctl: Table does not exist.").expect("missing"),
        None
    );
    let error = table_show_outcome("t", false, "", "pfctl: Permission denied")
        .expect_err("not a missing table");
    assert_eq!(error.kind(), ErrorKind::PermissionDenied);
}

/// The full anchor holding only `rule`.
fn full_anchor_for(rule: &Rule) -> String {
    let rules = BTreeMap::from([(rule.logical_key().clone(), rule.clone())]);
    render_full_anchor(&rules, &test_ns()).expect("render")
}

/// Whether listing `text` reads `rule` back unchanged.
fn reads_back(text: &str, rule: &Rule) -> bool {
    let listing = reconstruct_anchor_text(text, &test_ns(), |_| Ok(None)).expect("reconstruct");
    listing.rules.get(rule.logical_key()) == Some(rule)
}

fn https_pass_rule() -> Rule {
    Rule::builder("pf-edit", Action::Allow, Direction::Outbound)
        .protocol(Protocol::Tcp)
        .remote_address("203.0.113.9/32".parse::<IpNet>().expect("net"))
        .remote_port(PortRange::single(443).expect("port"))
        .build()
        .expect("rule")
}

#[test]
fn state_options_pfctl_adds_to_pass_rules_still_read_back() {
    let rule = https_pass_rule();
    let listed = full_anchor_for(&rule).replace(" label", " flags S/SA keep state label");
    assert!(reads_back(&listed, &rule), "{listed}");
}

#[test]
fn restrictions_after_the_endpoints_are_not_dropped() {
    let rule = https_pass_rule();
    for restriction in [" user = 501", " group = 20", " flags S/S", " tos 0x10"] {
        let listed = full_anchor_for(&rule).replace(" label", &format!("{restriction} label"));
        assert!(
            !reads_back(&listed, &rule),
            "`{restriction}` narrows the rule: {listed}"
        );
    }
}

#[test]
fn options_after_the_label_are_not_dropped() {
    let rule = https_pass_rule();
    let listed = format!("{} tagged evil", full_anchor_for(&rule).trim_end());
    assert!(!reads_back(&listed, &rule), "{listed}");
}

#[test]
fn a_changed_address_family_is_not_dropped() {
    let rule = Rule::builder("pf-family", Action::Block, Direction::Outbound)
        .protocol(Protocol::Tcp)
        .remote_port(PortRange::single(25).expect("port"))
        .build()
        .expect("rule");
    let text = full_anchor_for(&rule);
    assert!(reads_back(&text, &rule), "{text}");
    // `inet6` limits a rule meant for both families to IPv6.
    let narrowed = text.replace(" quick", " quick inet6");
    assert!(!reads_back(&narrowed, &rule), "{narrowed}");
}
