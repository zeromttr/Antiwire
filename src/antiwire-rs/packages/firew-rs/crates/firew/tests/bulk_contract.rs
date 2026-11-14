//! Offline bulk operation contract tests.

use firew_core::{
    Action, BulkOperation, BulkRead, BulkRequest, BulkUpdate, Direction, Rule, RuleKey,
};
use ipnet::IpNet;
use std::net::IpAddr;

fn host_net(host: &str) -> IpNet {
    IpNet::from(host.parse::<IpAddr>().expect("ip"))
}

fn sample_rule(key: &str) -> Rule {
    Rule::builder(key, Action::Block, Direction::Outbound)
        .remote_address(host_net("203.0.113.1"))
        .build()
        .expect("rule")
}

#[test]
fn bulk_request_preserves_operation_count() {
    let req = BulkRequest::new(vec![
        BulkOperation::Create(vec![sample_rule("a")]),
        BulkOperation::Read(BulkRead::default()),
        BulkOperation::Delete(vec![RuleKey::try_from("a").expect("key")]),
    ]);
    assert_eq!(req.operations.len(), 3);
}

#[test]
fn bulk_update_carries_logical_key() {
    let update = BulkUpdate {
        logical_key: RuleKey::try_from("rule-1").expect("key"),
        rule: sample_rule("rule-1"),
    };
    assert_eq!(update.logical_key, "rule-1");
}

#[test]
fn bulk_read_filter_optional_fields_default_empty() {
    let read = BulkRead::default();
    assert!(read.key_prefix.is_none());
    assert!(read.direction.is_none());
}
