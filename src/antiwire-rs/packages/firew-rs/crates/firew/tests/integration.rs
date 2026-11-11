//! Integration tests for firew-rs facade.

use std::net::IpAddr;

use firew_core::{
    Action, BulkOperation, BulkOutcome, BulkRead, BulkRequest, Direction, ErrorKind, Rule, RuleKey,
};
use firew_rs::{BackendPreference, Firewall, RuleFilter};
use ipnet::IpNet;

fn test_net(host: &str) -> IpNet {
    IpNet::from(host.parse::<IpAddr>().expect("ip"))
}

#[test]
fn mock_style_builder_contract() {
    let rule = Rule::builder("test-key", Action::Block, Direction::Outbound)
        .remote_address(test_net("192.0.2.1"))
        .build()
        .expect("rule");
    assert_eq!(rule.logical_key(), "test-key");
}

#[test]
fn offline_rule_filter_and_foreign_backend_preference_reject_without_mutation() {
    let filter = RuleFilter::new()
        .with_key_prefix(RuleKey::try_from("offline-").expect("key"))
        .with_direction(Direction::Outbound);
    assert_eq!(filter.direction, Some(Direction::Outbound));

    #[cfg(windows)]
    let foreign = BackendPreference::Pf;
    #[cfg(not(windows))]
    let foreign = BackendPreference::InetFw;

    let Err(err) = Firewall::builder()
        .name_prefix("offline-noop")
        .prefer_backend(foreign)
        .build()
    else {
        panic!("foreign preference must be rejected before native open");
    };
    assert_eq!(err.kind(), ErrorKind::BackendUnavailable);
}

#[test]
#[ignore = "requires native firewall privileges"]
fn live_add_remove_rule() {
    let mut fw = Firewall::builder()
        .name_prefix("firew_test")
        .memory_mode(true)
        .build()
        .expect("open");
    let rule = Rule::builder("live-1", Action::Block, Direction::Outbound)
        .remote_address(test_net("203.0.113.99"))
        .build()
        .expect("rule");
    let id = fw.add_rule(rule.clone()).expect("add");
    assert_eq!(fw.get_rule(&id).expect("get"), rule);
    fw.remove_rule(&id).expect("remove");
    assert!(fw.get_rule(&id).is_err());
    fw.close().expect("close");
}

#[test]
#[ignore = "requires native firewall privileges"]
fn live_bulk_create_delete() {
    let mut fw = Firewall::builder()
        .name_prefix("firew_bulk")
        .memory_mode(true)
        .build()
        .expect("open");
    let rules = vec![
        Rule::builder("bulk-a", Action::Block, Direction::Outbound)
            .remote_address(test_net("203.0.113.10"))
            .build()
            .expect("rule"),
        Rule::builder("bulk-b", Action::Block, Direction::Outbound)
            .remote_address(test_net("203.0.113.11"))
            .build()
            .expect("rule"),
    ];
    let request = BulkRequest::prefer_native(vec![
        BulkOperation::Create(rules.clone()),
        BulkOperation::Read(BulkRead {
            key_prefix: Some(RuleKey::try_from("bulk-").expect("prefix")),
            direction: None,
        }),
    ]);
    let results = fw.execute_bulk(&request).expect("bulk");
    assert_eq!(results.results.len(), 3);
    assert_eq!(
        results.results[0].outcome.as_ref().expect("create a"),
        &BulkOutcome::Created(RuleKey::try_from("bulk-a").expect("key"))
    );
    assert_eq!(
        results.results[1].outcome.as_ref().expect("create b"),
        &BulkOutcome::Created(RuleKey::try_from("bulk-b").expect("key"))
    );
    match results.results[2].outcome.as_ref().expect("read") {
        BulkOutcome::Read(read_rules) => assert_eq!(read_rules.len(), 2),
        other => panic!("unexpected read outcome: {other:?}"),
    }

    let delete = BulkRequest::new(vec![BulkOperation::Delete(vec![
        RuleKey::try_from("bulk-a").expect("key"),
        RuleKey::try_from("bulk-b").expect("key"),
    ])]);
    let del_exec = fw.execute_bulk(&delete).expect("delete");
    for item in &del_exec.results {
        assert!(matches!(item.outcome, Ok(BulkOutcome::Deleted(_))));
    }
    fw.close().expect("close");
}
