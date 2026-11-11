use super::*;

#[test]
fn first_interface_index_sticks_and_local_close_drains_matching_udp() {
    let mut table = FlowTable::new(4);
    table.open(key(1), 42, None, None, 10);
    table.remember_interface(key(1), 7);
    table.remember_interface(key(1), 9);
    assert_eq!(table.get(&key(1)).expect("flow").meta.if_index, Some(7));

    let udp = FlowKey {
        protocol: Protocol::Udp,
        local_addr: std::net::IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 10)),
        local_port: 50_000,
        remote_addr: std::net::IpAddr::V4(std::net::Ipv4Addr::new(1, 1, 1, 1)),
        remote_port: 53,
    };
    table.open(udp, 42, None, None, 10);
    let closed = table.close_local_endpoint(
        Protocol::Udp,
        std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
        50_000,
        11,
        None,
    );
    assert_eq!(closed.len(), 1);
    assert_eq!(table.len(), 1);
}

#[test]
fn delayed_interface_estimate_does_not_annotate_a_recycled_tuple() {
    let mut table = FlowTable::new(4);
    let first = table.open(key(1), 42, None, Some(cookie(1)), 10);
    table.remember_interface_if_generation(key(1), 7, first.identity_generation, false);
    assert_eq!(table.get(&key(1)).expect("flow").meta.if_index, Some(7));

    let recycled = table.open(key(1), 43, None, Some(cookie(2)), 20);
    assert!(recycled.superseded.is_some());
    table.remember_interface_if_generation(key(1), 9, first.identity_generation, false);
    assert_eq!(table.get(&key(1)).expect("new flow").meta.if_index, None);
    table.remember_interface_if_generation(key(1), 11, recycled.identity_generation, true);
    assert_eq!(
        table.get(&key(1)).expect("new flow").meta.if_index,
        Some(11)
    );
}

#[test]
fn bound_interface_replaces_a_route_estimate_and_then_sticks() {
    let mut table = FlowTable::new(4);
    let opened = table.open(key(1), 42, None, None, 10);
    assert!(table.remember_interface_if_generation(key(1), 4, opened.identity_generation, false));
    assert!(table.remember_interface_if_generation(key(1), 12, opened.identity_generation, true));
    assert_eq!(table.get(&key(1)).expect("flow").meta.if_index, Some(12));
    assert!(!table.remember_interface_if_generation(key(1), 4, opened.identity_generation, false));
    assert!(!table.remember_interface_if_generation(key(1), 9, opened.identity_generation, true));
    assert_eq!(table.get(&key(1)).expect("flow").meta.if_index, Some(12));
}

#[test]
fn delayed_local_close_does_not_drain_a_newer_bind_cookie() {
    let mut table = FlowTable::new(4);
    let udp = FlowKey {
        protocol: Protocol::Udp,
        local_addr: std::net::IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 10)),
        local_port: 50_000,
        remote_addr: std::net::IpAddr::V4(std::net::Ipv4Addr::new(1, 1, 1, 1)),
        remote_port: 53,
    };
    table.open(udp, 42, None, Some(cookie(1)), 10);
    table.open(udp, 43, None, Some(cookie(2)), 20);
    let closed = table.close_local_endpoint(
        Protocol::Udp,
        udp.local_addr,
        udp.local_port,
        21,
        Some(cookie(1)),
    );
    assert!(closed.is_empty());
    assert_eq!(
        table.get(&udp).expect("newer bind").meta.cookie,
        Some(cookie(2))
    );
}
