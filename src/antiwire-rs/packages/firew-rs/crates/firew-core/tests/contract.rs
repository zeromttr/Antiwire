//! Offline contract tests for portable rule types.

use std::net::IpAddr;

use firew_core::{
    normalize_domain, Action, BulkOperation, BulkRead, BulkRequest, Direction, ErrorKind,
    PortRange, Protocol, Rule, RuleKey, TransactionMode,
};
use ipnet::IpNet;
use proptest::prelude::*;

fn host_net(host: &str) -> IpNet {
    IpNet::from(host.parse::<IpAddr>().expect("ip"))
}

#[test]
fn rejects_parent_dir_in_application_path() {
    let err = Rule::builder("k", Action::Block, Direction::Outbound)
        .application_path("../etc/passwd")
        .remote_address(host_net("10.0.0.1"))
        .build()
        .unwrap_err();
    assert_eq!(err.kind(), ErrorKind::InvalidRule);
}

#[test]
fn cidr_remote_address_accepted() {
    let net: IpNet = "10.0.0.0/8".parse().expect("cidr");
    let rule = Rule::builder("cidr", Action::Block, Direction::Outbound)
        .remote_address(net)
        .build()
        .expect("rule");
    assert_eq!(rule.remote_addresses().len(), 1);
}

#[test]
fn port_range_rejects_zero() {
    assert!(PortRange::single(0).is_err());
    assert!(PortRange::range(0, 10).is_err());
    assert!(PortRange::range(10, 0).is_err());
}

#[test]
fn rule_key_rejects_non_portable_values() {
    assert!(RuleKey::try_from("").is_err());
    assert!(RuleKey::try_from("contains space").is_err());
    assert!(RuleKey::try_from("é").is_err());
    assert!(RuleKey::try_from("x".repeat(33)).is_err());
}

#[test]
fn serde_cannot_bypass_port_invariants() {
    let invalid = r#"{"start":0,"end":443}"#;
    assert!(serde_json::from_str::<PortRange>(invalid).is_err());
}

#[test]
fn serde_cannot_bypass_rule_invariants() {
    let rule = Rule::builder("serde", Action::Block, Direction::Outbound)
        .remote_address(host_net("192.0.2.1"))
        .build()
        .expect("rule");
    let mut value = serde_json::to_value(rule).expect("serialize");
    value["remote_addresses"] = serde_json::json!([]);
    assert!(serde_json::from_value::<Rule>(value).is_err());
}

#[test]
fn domain_normalization_lowercases_and_strips_dot() {
    let d = normalize_domain("Example.COM.").expect("domain");
    assert_eq!(d, "example.com");
}

#[test]
fn domain_validation_rejects_literals_and_invalid_labels() {
    for invalid in [
        "192.0.2.1",
        "2001:db8::1",
        "-start.example",
        "end-.example",
        "two..dots",
        "under_score.example",
        ".",
    ] {
        assert!(normalize_domain(invalid).is_err(), "{invalid}");
    }
    let oversized_label = format!("{}.example", "a".repeat(64));
    assert!(normalize_domain(&oversized_label).is_err());
    assert!(normalize_domain(&format!("{}.com", "a".repeat(250))).is_err());
}

#[test]
fn port_matchers_require_tcp_or_udp() {
    let port = PortRange::single(443).expect("port");
    for protocol in [
        Protocol::Any,
        Protocol::IcmpV4,
        Protocol::IcmpV6,
        Protocol::Other(132),
    ] {
        let error = Rule::builder("port", Action::Allow, Direction::Outbound)
            .protocol(protocol)
            .remote_port(port)
            .build()
            .expect_err("protocol must reject ports");
        assert_eq!(error.kind(), ErrorKind::InvalidRule);
    }
}

#[test]
fn expansion_is_cartesian_and_bounded() {
    let port_80 = PortRange::single(80).expect("port");
    let port_443 = PortRange::single(443).expect("port");
    let rule = Rule::builder("expand", Action::Allow, Direction::Both)
        .protocol(Protocol::Tcp)
        .remote_address(host_net("192.0.2.1"))
        .remote_address(host_net("192.0.2.2"))
        .local_address(host_net("198.51.100.1"))
        .remote_port(port_80)
        .remote_port(port_443)
        .local_port(PortRange::single(50_000).expect("port"))
        .build()
        .expect("within expansion limit");
    assert_eq!(rule.native_expansion().expect("expansion"), 8);

    let mut builder =
        Rule::builder("too-large", Action::Allow, Direction::Both).protocol(Protocol::Tcp);
    for index in 1..=17 {
        builder = builder.remote_address(host_net(&format!("192.0.2.{index}")));
        builder = builder.remote_port(PortRange::single(index).expect("port"));
    }
    assert_eq!(
        builder
            .build()
            .expect_err("Cartesian expansion exceeds the portable limit")
            .kind(),
        ErrorKind::LimitExceeded
    );
}

#[test]
fn label_is_non_semantic_but_validated() {
    let address = host_net("192.0.2.10");
    let plain = Rule::builder("same", Action::Block, Direction::Outbound)
        .remote_address(address)
        .build()
        .expect("plain");
    let labelled = Rule::builder("same", Action::Block, Direction::Outbound)
        .label("display only")
        .remote_address(address)
        .build()
        .expect("labelled");
    assert_eq!(plain, labelled);

    assert_eq!(
        Rule::builder("long-label", Action::Block, Direction::Outbound)
            .label("x".repeat(129))
            .remote_address(address)
            .build()
            .expect_err("oversized label")
            .kind(),
        ErrorKind::LimitExceeded
    );
}

#[test]
fn bulk_request_transaction_mode() {
    let req = BulkRequest::prefer_native(vec![BulkOperation::Read(BulkRead::default())]);
    assert_eq!(req.transaction_mode, TransactionMode::PreferNative);
}

#[test]
fn protocol_numbers_are_stable() {
    assert_eq!(Protocol::Tcp.number(), Some(6));
    assert_eq!(Protocol::Udp.number(), Some(17));
    assert_eq!(Protocol::IcmpV4.number(), Some(1));
    assert_eq!(Protocol::Any.number(), None);
}

proptest! {
    #[test]
    fn valid_port_ranges_accept(start in 1u16..=65535, span in 0u16..100) {
        let end = start.saturating_add(span);
        let range = PortRange::range(start, end).expect("valid range");
        prop_assert!(range.start() <= range.end());
    }

    #[test]
    fn reject_invalid_port_ranges(start in 2u16..=65535) {
        prop_assert!(PortRange::range(start, start - 1).is_err());
    }
}
