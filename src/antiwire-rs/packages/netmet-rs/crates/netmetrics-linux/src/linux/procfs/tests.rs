use super::*;

#[test]
fn a_snapshot_row_is_news_for_a_new_socket_or_a_newly_found_owner() {
    assert!(snapshot_row_is_news(None, 0, 7));
    assert!(
        snapshot_row_is_news(Some(&(42, 7)), 42, 8),
        "recycled tuple"
    );
    assert!(
        snapshot_row_is_news(Some(&(0, 7)), 42, 7),
        "owner found later"
    );
    assert!(!snapshot_row_is_news(Some(&(42, 7)), 42, 7));
    assert!(!snapshot_row_is_news(Some(&(42, 7)), 0, 7), "now shared");
    assert!(!snapshot_row_is_news(Some(&(42, 7)), 43, 7));
    assert!(!snapshot_row_is_news(Some(&(0, 7)), 0, 7));
}

#[test]
fn parses_proc_ipv4_endpoint() {
    assert_eq!(
        parse_endpoint("0100007F:C350", false),
        Some((IpAddr::V4(Ipv4Addr::LOCALHOST), 50_000))
    );
}

#[test]
fn parses_proc_ipv6_endpoint_word_endianness() {
    assert_eq!(
        parse_endpoint("00000000000000000000000001000000:01BB", true),
        Some((IpAddr::V6(Ipv6Addr::LOCALHOST), 443))
    );
}

#[test]
fn parses_socket_row_and_ignores_listeners() {
    let established =
        "0: 0100007F:C350 0200007F:01BB 01 00000000:00000000 00:00000000 00000000 1000 0 12345 1";
    let row = SocketRow::parse(established, Protocol::Tcp, false).expect("socket row");
    assert_eq!(row.inode, 12_345);
    let key = row.flow_key().expect("flow row");
    assert_eq!(key.local_port, 50_000);
    assert_eq!(key.remote_port, 443);

    let listener =
        "0: 0100007F:01BB 00000000:0000 0A 00000000:00000000 00:00000000 00000000 1000 0 12345 1";
    let listener = SocketRow::parse(listener, Protocol::Tcp, false).expect("socket row");
    assert!(listener.flow_key().is_none());
    // The same unconnected row is still a bind as far as UDP ownership goes.
    let bind = SocketRow {
        protocol: Protocol::Udp,
        ..listener
    };
    assert!(bind.flow_key().is_none());
    assert_eq!(
        bind.bound_endpoint(),
        Some(LocalEndpoint {
            address: IpAddr::V4(Ipv4Addr::LOCALHOST),
            port: 443
        })
    );
}

#[test]
fn shared_inode_ownership_is_deterministically_unknown() {
    let mut owners = HashMap::new();
    record_inode_owner(&mut owners, 10, 42);
    record_inode_owner(&mut owners, 10, 42);
    assert_eq!(owners.get(&10), Some(&42));
    record_inode_owner(&mut owners, 10, 7);
    record_inode_owner(&mut owners, 10, 42);
    assert_eq!(owners.get(&10), Some(&0));

    let mut reversed = HashMap::new();
    record_inode_owner(&mut reversed, 10, 7);
    record_inode_owner(&mut reversed, 10, 42);
    assert_eq!(reversed.get(&10), Some(&0));
}
