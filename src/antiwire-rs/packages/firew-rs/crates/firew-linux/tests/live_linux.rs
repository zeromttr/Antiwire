//! Live Linux firewall tests (`CAP_NET_ADMIN` / root required).
#![cfg(target_os = "linux")]

use std::net::IpAddr;

use firew_core::{
    Action, BulkOperation, BulkOutcome, BulkRequest, Direction, Protocol, Rule, RuleKey,
};
use firew_rs::{Firewall, RuleFilter};
use firew_sys::BackendPreference;
use ipnet::IpNet;

const TEST_PREFIX: &str = "firew_live_linux";

fn host_net(host: &str) -> IpNet {
    IpNet::from(host.parse::<IpAddr>().expect("ip"))
}

#[test]
#[ignore = "requires CAP_NET_ADMIN; run in docker with --cap-add=NET_ADMIN"]
fn live_auto_backend_add_remove() {
    let mut fw = Firewall::builder()
        .name_prefix(TEST_PREFIX)
        .memory_mode(true)
        .build()
        .expect("open");

    let rule = Rule::builder("linux-block", Action::Block, Direction::Outbound)
        .remote_address(host_net("203.0.113.90"))
        .protocol(Protocol::Tcp)
        .build()
        .expect("rule");

    let id = fw.add_rule(rule.clone()).expect("add");
    assert_eq!(fw.get_rule(&id).expect("get"), rule);

    let listed = fw
        .list_rules(
            &RuleFilter::new().with_key_prefix(RuleKey::try_from("linux-block").expect("key")),
        )
        .expect("list");
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].1, rule);

    fw.remove_rule(&id).expect("remove");
    fw.close().expect("close");
}

#[test]
#[ignore = "requires CAP_NET_ADMIN; run in docker with --cap-add=NET_ADMIN"]
fn live_nftables_preferred_over_iptables() {
    if !firew_linux::detect::nftables_available() {
        eprintln!("skipping live_nftables_preferred_over_iptables: nftables not operational");
        return;
    }

    let mut fw = Firewall::builder()
        .name_prefix(TEST_PREFIX)
        .prefer_backend(BackendPreference::Nftables)
        .build()
        .expect("nft backend");
    assert_eq!(fw.backend_name(), "nftables");
    assert!(fw.max_address_set_entries().is_some());
    fw.close().expect("close");
}

#[test]
#[ignore = "requires CAP_NET_ADMIN and iptables; run in docker with --cap-add=NET_ADMIN"]
fn live_iptables_fallback_backend() {
    let mut fw = Firewall::builder()
        .name_prefix(TEST_PREFIX)
        .prefer_backend(BackendPreference::Iptables)
        .build()
        .expect("iptables backend");
    assert_eq!(fw.backend_name(), "iptables");
    fw.close().expect("close");
}

#[test]
#[ignore = "requires CAP_NET_ADMIN; run in docker with --cap-add=NET_ADMIN"]
fn live_bulk_atomic_create_delete() {
    let mut fw = Firewall::builder()
        .name_prefix(TEST_PREFIX)
        .memory_mode(true)
        .build()
        .expect("open");

    let rules = vec![
        Rule::builder("lbulk-1", Action::Block, Direction::Outbound)
            .remote_address(host_net("203.0.113.91"))
            .build()
            .expect("rule"),
        Rule::builder("lbulk-2", Action::Block, Direction::Outbound)
            .remote_address(host_net("203.0.113.92"))
            .build()
            .expect("rule"),
    ];

    let created = fw
        .execute_bulk(&BulkRequest::prefer_native(vec![BulkOperation::Create(
            rules,
        )]))
        .expect("bulk create");
    assert_eq!(created.results.len(), 2);
    for item in &created.results {
        assert!(
            matches!(item.outcome, Ok(BulkOutcome::Created(_))),
            "unexpected bulk create outcome: {:?}",
            item.outcome
        );
    }

    let deleted = fw
        .execute_bulk(&BulkRequest::new(vec![BulkOperation::Delete(vec![
            RuleKey::try_from("lbulk-1").expect("key"),
            RuleKey::try_from("lbulk-2").expect("key"),
        ])]))
        .expect("bulk delete");
    assert_eq!(deleted.results.len(), 2);
    for item in &deleted.results {
        assert!(
            matches!(item.outcome, Ok(BulkOutcome::Deleted(_))),
            "unexpected bulk delete outcome: {:?}",
            item.outcome
        );
    }
    fw.close().expect("close");
}

/// What a crashed owner installed is removed by a later process that never
/// saw those rules in memory, and only its own namespace is touched.
fn fresh_process_removes_rules_left_by_another(preference: BackendPreference) {
    let open = |prefix: &str| {
        Firewall::builder()
            .name_prefix(prefix)
            .prefer_backend(preference)
            .memory_mode(false)
            .build()
            .expect("open")
    };
    let rule = |key: &str, host: &str| {
        Rule::builder(key, Action::Block, Direction::Outbound)
            .remote_address(host_net(host))
            .protocol(Protocol::Tcp)
            .build()
            .expect("rule")
    };
    let owner = "firew_live_crash_owner";
    let neighbour = "firew_live_crash_neighbour";

    let mut crashed = open(owner);
    crashed
        .add_rule(rule("left-a", "203.0.113.91"))
        .expect("add a");
    crashed
        .add_rule(rule("left-b", "203.0.113.92"))
        .expect("add b");
    // Not memory mode, so closing leaves both rules installed, as a crash would.
    crashed.close().expect("close crashed owner");

    let mut other = open(neighbour);
    other
        .add_rule(rule("kept", "203.0.113.93"))
        .expect("add neighbour");

    let mut reaper = open(owner);
    reaper.remove_all_rules().expect("remove left rules");
    reaper.close().expect("close reaper");

    let check = open(owner);
    assert!(
        check
            .list_rules(&RuleFilter::new())
            .expect("list owner")
            .is_empty(),
        "{preference:?}: rules from the crashed owner are still installed"
    );
    assert_eq!(
        other
            .list_rules(&RuleFilter::new())
            .expect("list neighbour")
            .len(),
        1,
        "{preference:?}: another namespace's rule was removed"
    );
    other.remove_all_rules().expect("clean neighbour");
}

#[test]
#[ignore = "requires CAP_NET_ADMIN; run in docker with --cap-add=NET_ADMIN"]
fn live_nftables_fresh_process_removes_crashed_rules() {
    if !firew_linux::detect::nftables_available() {
        eprintln!("skipping: nftables not operational");
        return;
    }
    fresh_process_removes_rules_left_by_another(BackendPreference::Nftables);
}

#[test]
#[ignore = "requires CAP_NET_ADMIN and iptables; run in docker with --cap-add=NET_ADMIN"]
fn live_iptables_fresh_process_removes_crashed_rules() {
    fresh_process_removes_rules_left_by_another(BackendPreference::Iptables);
}
