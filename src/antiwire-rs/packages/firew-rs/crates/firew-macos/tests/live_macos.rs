//! Live macOS PF tests (root required).
#![cfg(target_os = "macos")]

use std::net::IpAddr;

use firew_core::{
    Action, BulkOperation, BulkOutcome, BulkRequest, Direction, ExecutionAtomicity, Rule,
    TransactionMode,
};
use firew_rs::{Firewall, RuleFilter};
use ipnet::IpNet;

const TEST_PREFIX: &str = "firew_live_test";

fn host_net(host: &str) -> IpNet {
    IpNet::from(host.parse::<IpAddr>().expect("ip"))
}

fn test_firewall() -> Firewall {
    Firewall::builder()
        .name_prefix(TEST_PREFIX)
        .application_name("firew_test")
        .memory_mode(true)
        .build()
        .expect("open macos pf backend")
}

#[test]
#[ignore = "requires root; native PF ioctl access"]
fn live_pf_add_list_remove() {
    let mut fw = test_firewall();
    let key = "live-pf-block";
    let rule = Rule::builder(key, Action::Block, Direction::Outbound)
        .remote_address(host_net("203.0.113.90"))
        .build()
        .expect("rule");

    let id = fw.add_rule(rule.clone()).expect("add");
    assert_eq!(id.key(), key);
    assert_eq!(fw.get_rule(&id).expect("get"), rule);

    let listed = fw
        .list_rules(
            &RuleFilter::new().with_key_prefix(firew_core::RuleKey::try_from(key).expect("key")),
        )
        .expect("list");
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].1, rule);

    fw.remove_rule(&id).expect("remove");
    fw.close().expect("close");
}

#[test]
#[ignore = "requires root; native PF ioctl access"]
fn live_pf_transaction_commit() {
    let mut fw = test_firewall();
    let rule = Rule::builder("pf-tx", Action::Block, Direction::Outbound)
        .remote_address(host_net("203.0.113.91"))
        .build()
        .expect("rule");
    let execution = fw
        .execute_bulk(
            &BulkRequest::new(vec![BulkOperation::Create(vec![rule.clone()])])
                .with_transaction_mode(TransactionMode::RequireNative),
        )
        .expect("transaction");
    assert_eq!(execution.atomicity, ExecutionAtomicity::NativeAtomic);
    assert_eq!(execution.results.len(), 1);
    assert!(matches!(
        execution.results[0].outcome,
        Ok(BulkOutcome::Created(_))
    ));
    let id = fw
        .list_rules(
            &RuleFilter::new()
                .with_key_prefix(firew_core::RuleKey::try_from("pf-tx").expect("key")),
        )
        .expect("list")
        .pop()
        .expect("created rule")
        .0;
    assert_eq!(fw.get_rule(&id).expect("get"), rule);
    fw.remove_rule(&id).expect("remove");
    fw.close().expect("close");
}
