use super::*;
use crate::error::ErrorKind;
use ipnet::IpNet;

#[test]
fn to_builder_round_trips_and_derives_changed_copies() {
    let net: IpNet = "192.0.2.0/24".parse().expect("net");
    let rule = Rule::builder("k", Action::Block, Direction::Outbound)
        .label("web")
        .protocol(Protocol::Tcp)
        .remote_address_set([net])
        .remote_port(PortRange::single(443).expect("port"))
        .build()
        .expect("rule");
    assert_eq!(rule.to_builder().build().expect("copy"), rule);

    let inbound = rule
        .to_builder()
        .direction(Direction::Inbound)
        .without_remote_addresses()
        .remote_address(net)
        .build()
        .expect("inbound");
    assert_eq!(inbound.direction(), Direction::Inbound);
    assert_eq!(inbound.address_set_mode(), AddressSetMode::Cartesian);
    assert_eq!(inbound.label(), Some("web"));
    assert_eq!(inbound.remote_ports(), rule.remote_ports());
}

#[test]
fn cartesian_limits_count_every_combination() {
    assert!(!cartesian_exceeds_limits(Direction::Outbound, 2, 0, 1, 0));
    assert!(cartesian_exceeds_limits(
        Direction::Outbound,
        MAX_MATCHERS_PER_FIELD + 1,
        0,
        0,
        0
    ));
    assert!(cartesian_exceeds_limits(Direction::Both, 30, 1, 5, 1));
    assert!(!cartesian_exceeds_limits(Direction::Outbound, 30, 1, 5, 1));
}

#[test]
fn builder_requires_matchers() {
    let err = Rule::builder("k", Action::Block, Direction::Outbound)
        .build()
        .unwrap_err();
    assert_eq!(err.kind(), ErrorKind::InvalidRule);
}

#[test]
fn remote_address_rule_builds() {
    let ip: std::net::IpAddr = "10.0.0.0".parse().expect("ip");
    let net = IpNet::new(ip, 8).expect("cidr");
    let rule = Rule::builder("k", Action::Allow, Direction::Outbound)
        .remote_address(net)
        .build()
        .expect("rule");
    assert_eq!(rule.remote_addresses().len(), 1);
}

#[test]
fn clone_shares_immutable_rule_storage() {
    let rule = Rule::builder("k", Action::Allow, Direction::Outbound)
        .remote_address("10.0.0.0/8".parse().expect("cidr"))
        .build()
        .expect("rule");
    let cloned = rule.clone();

    assert!(Arc::ptr_eq(&rule.inner, &cloned.inner));
    assert_eq!(rule, cloned);
}

fn nets(count: usize) -> Vec<IpNet> {
    (0..count)
        .map(|index| {
            let octets = u32::try_from(index).expect("index").to_be_bytes();
            IpNet::new(
                std::net::Ipv4Addr::new(10, octets[1], octets[2], octets[3]).into(),
                32,
            )
            .expect("net")
        })
        .collect()
}

#[test]
fn cartesian_mode_still_caps_remote_addresses() {
    let mut builder = Rule::builder("cap", Action::Block, Direction::Outbound);
    for net in nets(MAX_MATCHERS_PER_FIELD + 1) {
        builder = builder.remote_address(net);
    }
    assert_eq!(
        builder.build().expect_err("over cap").kind(),
        ErrorKind::LimitExceeded
    );
}

#[test]
fn set_mode_accepts_far_more_than_the_field_cap() {
    let rule = Rule::builder("set", Action::Block, Direction::Outbound)
        .remote_address_set(nets(10_000))
        .build()
        .expect("large address set builds");

    assert_eq!(rule.address_set_mode(), AddressSetMode::Set);
    assert_eq!(rule.remote_addresses().len(), 10_000);
    // The whole point: the set counts as one native row, not 10,000.
    assert_eq!(rule.native_expansion().expect("expansion"), 1);
}

#[test]
fn set_mode_collapses_expansion_but_still_multiplies_other_fields() {
    let rule = Rule::builder("mixed", Action::Block, Direction::Both)
        .protocol(Protocol::Tcp)
        .remote_address_set(nets(5_000))
        .remote_port(PortRange::single(80).expect("port"))
        .remote_port(PortRange::single(443).expect("port"))
        .build()
        .expect("builds");

    // 2 (Both) x 1 (set) x 2 ports
    assert_eq!(rule.native_expansion().expect("expansion"), 4);
}

#[test]
fn set_mode_rejects_empty_and_oversized() {
    let empty = Rule::builder("empty", Action::Block, Direction::Outbound)
        .remote_address_set(Vec::new())
        .build()
        .expect_err("empty set");
    assert_eq!(empty.kind(), ErrorKind::InvalidRule);

    let oversized = Rule::builder("huge", Action::Block, Direction::Outbound)
        .remote_address_set(nets(MAX_ADDRESS_SET_ENTRIES + 1))
        .build()
        .expect_err("over the set cap");
    assert_eq!(oversized.kind(), ErrorKind::LimitExceeded);
}

#[test]
fn set_mode_sorts_and_deduplicates() {
    let a: IpNet = "10.0.0.5/32".parse().expect("net");
    let b: IpNet = "10.0.0.1/32".parse().expect("net");
    let rule = Rule::builder("sorted", Action::Block, Direction::Outbound)
        .remote_address_set([a, b, a])
        .build()
        .expect("builds");

    assert_eq!(rule.remote_addresses(), &[b, a]);
}

#[test]
fn equality_ignores_address_set_mode() {
    // A set rule and a Cartesian rule with the same addresses match the same
    // traffic. Native read-back cannot always recover the mode, so treating
    // them as different would make reconcile rewrite the rule every pass.
    let addresses = nets(3);
    let set = Rule::builder("same", Action::Block, Direction::Outbound)
        .remote_address_set(addresses.clone())
        .build()
        .expect("set rule");
    let mut builder = Rule::builder("same", Action::Block, Direction::Outbound);
    for net in addresses {
        builder = builder.remote_address(net);
    }
    let cartesian = builder.build().expect("cartesian rule");

    assert_ne!(set.address_set_mode(), cartesian.address_set_mode());
    assert_eq!(set, cartesian);
}

#[test]
fn serde_round_trips_set_mode_and_defaults_to_cartesian() {
    let rule = Rule::builder("ser", Action::Block, Direction::Outbound)
        .remote_address_set(nets(100))
        .build()
        .expect("rule");
    let json = serde_json::to_string(&rule).expect("serialize");
    let restored: Rule = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(restored.address_set_mode(), AddressSetMode::Set);
    assert_eq!(restored.remote_addresses().len(), 100);

    // A payload written before address sets existed has no mode field at
    // all. Drop the key from a real serialization rather than hand-writing
    // JSON, so this stays correct if the wire format changes.
    let small = Rule::builder("legacy", Action::Block, Direction::Outbound)
        .remote_address(nets(1)[0])
        .build()
        .expect("rule");
    let mut legacy = serde_json::to_value(&small).expect("serialize");
    legacy
        .as_object_mut()
        .expect("object")
        .remove("address_set_mode")
        .expect("field was present");
    let restored: Rule = serde_json::from_value(legacy).expect("legacy payload");
    assert_eq!(restored.address_set_mode(), AddressSetMode::Cartesian);
}

#[test]
fn deserializing_unnormalized_set_canonicalizes_and_equals_builder_rule() {
    let a: IpNet = "10.0.0.5/32".parse().expect("net");
    let b: IpNet = "10.0.0.1/32".parse().expect("net");
    let built = Rule::builder("canon", Action::Block, Direction::Outbound)
        .remote_address_set([b, a])
        .build()
        .expect("built");

    let mut raw = serde_json::to_value(&built).expect("serialize");
    raw["remote_addresses"] = serde_json::json!(["10.0.0.5/32", "10.0.0.1/32", "10.0.0.5/32"]);
    let deserialized: Rule = serde_json::from_value(raw).expect("deserialize");

    assert_eq!(deserialized, built);
    assert_eq!(deserialized.remote_addresses(), &[b, a]);
}

#[test]
fn cidrs_are_truncated_and_contained_set_prefixes_collapsed() {
    let rule = Rule::builder("trunc", Action::Block, Direction::Outbound)
        .remote_address_set([
            "192.0.2.5/24".parse::<IpNet>().expect("net"),
            "192.0.2.99/32".parse::<IpNet>().expect("subnet"),
        ])
        .local_address("10.1.2.3/8".parse::<IpNet>().expect("local"))
        .build()
        .expect("builds");

    assert_eq!(
        rule.remote_addresses(),
        &["192.0.2.0/24".parse::<IpNet>().expect("canonical")]
    );
    assert_eq!(
        rule.local_addresses(),
        &["10.0.0.0/8".parse::<IpNet>().expect("canonical")]
    );
}

#[test]
fn protocol_canonicalizes_known_numbers_and_rejects_zero() {
    for (raw, expected) in [
        (Protocol::Other(6), Protocol::Tcp),
        (Protocol::Other(17), Protocol::Udp),
        (Protocol::Other(1), Protocol::IcmpV4),
        (Protocol::Other(58), Protocol::IcmpV6),
    ] {
        let addr = if expected == Protocol::IcmpV6 {
            "2001:db8::1/128".parse::<IpNet>().expect("v6")
        } else {
            "192.0.2.1/32".parse::<IpNet>().expect("v4")
        };
        let rule = Rule::builder("proto", Action::Block, Direction::Outbound)
            .protocol(raw)
            .remote_address(addr)
            .build()
            .expect("builds");
        assert_eq!(rule.protocol(), expected);
    }

    let err = Rule::builder("zero", Action::Block, Direction::Outbound)
        .protocol(Protocol::Other(0))
        .remote_address("192.0.2.1/32".parse::<IpNet>().expect("v4"))
        .build()
        .expect_err("protocol 0 must be rejected");
    assert_eq!(err.kind(), ErrorKind::InvalidRule);
}

#[test]
fn rejects_incompatible_address_families_and_counts_same_family_pairs() {
    let v4: IpNet = "192.0.2.1/32".parse().expect("v4");
    let v6: IpNet = "2001:db8::1/128".parse().expect("v6");

    assert_eq!(
        Rule::builder("icmp4-v6", Action::Block, Direction::Outbound)
            .protocol(Protocol::IcmpV4)
            .remote_address(v6)
            .build()
            .expect_err("icmpv4 + v6")
            .kind(),
        ErrorKind::InvalidRule
    );
    assert_eq!(
        Rule::builder("icmp6-v4", Action::Block, Direction::Outbound)
            .protocol(Protocol::IcmpV6)
            .remote_address(v4)
            .build()
            .expect_err("icmpv6 + v4")
            .kind(),
        ErrorKind::InvalidRule
    );
    assert_eq!(
        Rule::builder("disjoint", Action::Block, Direction::Outbound)
            .remote_address(v4)
            .local_address(v6)
            .build()
            .expect_err("disjoint families")
            .kind(),
        ErrorKind::InvalidRule
    );

    let dual_stack = Rule::builder("dual", Action::Block, Direction::Outbound)
        .remote_address(v4)
        .remote_address(v6)
        .local_address("198.51.100.1/32".parse().expect("v4"))
        .local_address("2001:db8::2/128".parse().expect("v6"))
        .build()
        .expect("shared families");
    // (1 v4 * 1 v4) + (1 v6 * 1 v6) = 2 pairs, not 4.
    assert_eq!(dual_stack.native_expansion().expect("expansion"), 2);
}
