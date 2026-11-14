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

/// A `/proc/net` stand-in holding a TCP listener and a row of every other TCP state, a
/// UDP bind and a connected UDP socket.
///
/// Rows 2 to 13 of `tcp` are printed as the kernel prints each kind of socket, line padding
/// aside: a full socket by `get_tcp4_sock`, a time-wait socket by `get_timewait4_sock`
/// (inode zero), a request socket by `get_openreq4` (`SYN_RECV`, inode zero), all in
/// `net/ipv4/tcp_ipv4.c`. The client rows run from `127.0.0.1:500xx` to `127.0.0.2:443`, the
/// port giving the row: 50002 `SYN_SENT`; 50004 `FIN_WAIT1` after `shutdown(SHUT_WR)`;
/// 50005 `FIN_WAIT1` after `close`; 50006 `FIN_WAIT2` after `shutdown(SHUT_WR)`; 50007 a
/// time-wait socket in sub-state `FIN_WAIT2`; 50008 one in `TIME_WAIT`; 50009 `CLOSE`;
/// 50010 `CLOSE_WAIT`; 50011 `LAST_ACK` and 50012 `CLOSING`, both after `close`. The
/// server rows run from `127.0.0.1:443` back to `127.0.0.2`: 50003 a request socket, 50013
/// a connection the listener has not yet handed to `accept`.
fn socket_tables() -> std::path::PathBuf {
    static NEXT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    let root = std::env::temp_dir().join(format!(
        "netmetrics-procfs-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    fs::create_dir_all(&root).expect("create table directory");
    let header = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n";
    fs::write(
        root.join("tcp"),
        format!(
            "{header}\
             0: 00000000:01BB 00000000:0000 0A 00000000:00000000 00:00000000 00000000 0 0 100 1\n\
             1: 0100007F:C350 0200007F:01BB 01 00000000:00000000 00:00000000 00000000 0 0 200 1\n   \
             2: 0100007F:C352 0200007F:01BB 02 00000001:00000000 01:00000064 00000002     0        0 202 2 0 100 0 0 10 -1\n   \
             3: 0100007F:01BB 0200007F:C353 03 00000000:00000000 01:00000064 00000000     0        0 0 0 0\n   \
             4: 0100007F:C354 0200007F:01BB 04 00000001:00000000 01:00000014 00000000     0        0 204 2 0 20 4 0 10 -1\n   \
             5: 0100007F:C355 0200007F:01BB 04 00000001:00000000 01:00000014 00000000     0        0 0 1 0 20 4 0 10 -1\n   \
             6: 0100007F:C356 0200007F:01BB 05 00000000:00000000 00:00000000 00000000     0        0 206 1 0 20 4 0 10 -1\n   \
             7: 0100007F:C357 0200007F:01BB 05 00000000:00000000 03:00001770 00000000     0        0 0 3 0\n   \
             8: 0100007F:C358 0200007F:01BB 06 00000000:00000000 03:00001770 00000000     0        0 0 3 0\n   \
             9: 0100007F:C359 0200007F:01BB 07 00000000:00000000 00:00000000 00000000     0        0 209 1 0 20 4 0 10 -1\n  \
             10: 0100007F:C35A 0200007F:01BB 08 00000000:00000001 00:00000000 00000000     0        0 210 1 0 20 4 0 10 -1\n  \
             11: 0100007F:C35B 0200007F:01BB 09 00000001:00000000 01:00000014 00000000     0        0 0 1 0 20 4 0 10 -1\n  \
             12: 0100007F:C35C 0200007F:01BB 0B 00000001:00000000 01:00000014 00000000     0        0 0 1 0 20 4 0 10 -1\n  \
             13: 0100007F:01BB 0200007F:C35D 01 00000000:00000000 00:00000000 00000000     0        0 0 2 0 20 4 0 10 -1\n"
        ),
    )
    .expect("write tcp table");
    fs::write(
        root.join("udp"),
        format!(
            "{header}\
             0: 0100007F:0035 00000000:0000 07 00000000:00000000 00:00000000 00000000 0 0 300 2\n  \
             1: 0100007F:D431 08080808:0035 01 00000000:00000000 00:00000000 00000000     0        0 301 2 0 0\n"
        ),
    )
    .expect("write udp table");
    root
}

#[test]
fn a_listener_owns_inbound_connections_that_left_the_table() {
    let root = socket_tables();
    let inode_pids = HashMap::from([(100, 41), (200, 42), (300, 43)]);
    let snapshot = read_socket_owners(&root, &inode_pids, None).expect("socket owners");
    fs::remove_dir_all(&root).expect("remove table directory");

    let inbound = FlowKey {
        protocol: Protocol::Tcp,
        local_addr: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
        local_port: 443,
        remote_addr: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7)),
        remote_port: 51_000,
    };
    assert_eq!(
        snapshot.lookup_owner_pid(&inbound),
        Some(41),
        "the wildcard listener on the port owns it"
    );
    let established = FlowKey {
        protocol: Protocol::Tcp,
        local_addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
        local_port: 50_000,
        remote_addr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)),
        remote_port: 443,
    };
    assert_eq!(snapshot.lookup_owner_pid(&established), Some(42));
}

#[test]
fn a_protocol_snapshot_reads_only_that_protocols_tables() {
    let root = socket_tables();
    let inode_pids = HashMap::from([(100, 41), (200, 42), (300, 43)]);
    let tcp = read_socket_owners(&root, &inode_pids, Some(Protocol::Tcp)).expect("tcp owners");
    let udp = read_socket_owners(&root, &inode_pids, Some(Protocol::Udp)).expect("udp owners");
    fs::remove_dir_all(&root).expect("remove table directory");

    let resolver = LocalEndpoint {
        address: IpAddr::V4(Ipv4Addr::LOCALHOST),
        port: 53,
    };
    let listener = LocalEndpoint {
        address: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        port: 443,
    };
    assert_eq!(
        udp.local_endpoint_owner(Protocol::Udp, resolver),
        netmetrics_core::Ownership::Resolved(43)
    );
    assert_eq!(
        tcp.local_endpoint_owner(Protocol::Udp, resolver),
        netmetrics_core::Ownership::NotFound,
        "a TCP scan reads no UDP table"
    );
    assert_eq!(
        tcp.local_endpoint_owner(Protocol::Tcp, listener),
        netmetrics_core::Ownership::Resolved(41)
    );
    assert_eq!(
        udp.local_endpoint_owner(Protocol::Tcp, listener),
        netmetrics_core::Ownership::NotFound,
        "a UDP scan reads no TCP table"
    );
}

/// `tcp6` and `udp6` rows of `AF_INET6` sockets that carry IPv4, as the kernel prints them:
/// each address is four 32-bit words of `sk_v6_rcv_saddr` / `sk_v6_daddr` in host byte
/// order (`get_tcp6_sock` in `net/ipv6/tcp_ipv6.c`, `__ip6_dgram_sock_seq_show` in
/// `net/ipv6/datagram.c`), and the IPv4 connection of such a socket holds the IPv4-mapped
/// form there (`ipv6(7)`). Row 2 of `tcp6` is a time-wait socket left by an earlier such
/// connection (`get_timewait6_sock`). Written beside [`socket_tables`]' IPv4 tables.
fn add_dual_stack_tables(root: &Path) {
    let header = "  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n";
    fs::write(
        root.join("tcp6"),
        format!(
            "{header}\
             0: 0000000000000000FFFF00000100007F:C351 0000000000000000FFFF00000100007F:1F90 01 00000000:00000000 00:00000000 00000000 0 0 400 1\n\
             1: 00000000000000000000000000000000:1F90 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000 0 0 500 1\n   \
             2: 0000000000000000FFFF00000100007F:C35E 0000000000000000FFFF00000100007F:1F90 06 00000000:00000000 03:00001770 00000000     0        0 0 3 0\n"
        ),
    )
    .expect("write tcp6 table");
    fs::write(
        root.join("udp6"),
        format!(
            "{header}0: 00000000000000000000000000000000:14E9 00000000000000000000000000000000:0000 07 00000000:00000000 00:00000000 00000000 0 0 600 2\n"
        ),
    )
    .expect("write udp6 table");
}

#[test]
fn parses_proc_ipv4_mapped_endpoint() {
    assert_eq!(
        parse_endpoint("0000000000000000FFFF00000100007F:C351", true),
        Some((IpAddr::V6(Ipv4Addr::LOCALHOST.to_ipv6_mapped()), 50_001))
    );
}

/// The rows keep the mapped form; the owners they give are found under plain IPv4, as
/// packets and flow events name them, and a listener or bind on `::` owns IPv4 endpoints.
#[test]
fn dual_stack_rows_own_their_ipv4_endpoints() {
    let root = socket_tables();
    add_dual_stack_tables(&root);
    let inode_pids = HashMap::from([
        (100, 41),
        (200, 42),
        (300, 43),
        (400, 44),
        (500, 45),
        (600, 46),
    ]);
    let snapshot = read_socket_owners(&root, &inode_pids, None).expect("socket owners");
    fs::remove_dir_all(&root).expect("remove table directory");

    let connection = FlowKey {
        protocol: Protocol::Tcp,
        local_addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
        local_port: 50_001,
        remote_addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
        remote_port: 8080,
    };
    assert_eq!(snapshot.lookup_owner_pid(&connection), Some(44));
    let departed = FlowKey {
        local_port: 8080,
        remote_port: 51_000,
        ..connection
    };
    assert_eq!(
        snapshot.lookup_owner_pid(&departed),
        Some(45),
        "the listener on [::]:8080 owns an inbound IPv4 connection"
    );
    let resolver = LocalEndpoint {
        address: IpAddr::V4(Ipv4Addr::LOCALHOST),
        port: 5353,
    };
    assert_eq!(
        snapshot.local_endpoint_owner(Protocol::Udp, resolver),
        netmetrics_core::Ownership::Resolved(46),
        "the bind on [::]:5353 owns an IPv4 sender"
    );
    assert_eq!(
        snapshot.lookup_owner_pid(&FlowKey {
            local_port: 50_000,
            remote_addr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)),
            remote_port: 443,
            ..connection
        }),
        Some(42),
        "IPv4 rows are unchanged"
    );
}

/// What the kernel really lists: an `AF_INET6` socket connected to `::ffff:127.0.0.1`,
/// accepted by a listener on `[::]`.
#[test]
fn a_dual_stack_connection_is_owned_under_its_ipv4_addresses() {
    use std::net::{TcpListener, TcpStream};

    let listener = TcpListener::bind((Ipv6Addr::UNSPECIFIED, 0)).expect("listen on [::]");
    let port = listener.local_addr().expect("listener address").port();
    let client = TcpStream::connect((Ipv4Addr::LOCALHOST.to_ipv6_mapped(), port)).expect("connect");
    let (_accepted, _) = listener.accept().expect("accept");
    let local = client.local_addr().expect("client address");
    assert_eq!(
        local.ip(),
        IpAddr::V6(Ipv4Addr::LOCALHOST.to_ipv6_mapped()),
        "a dual-stack socket keeps the mapped form"
    );

    let pid = Some(std::process::id());
    let snapshot = socket_owner_snapshot_for(Protocol::Tcp);
    let connection = FlowKey {
        protocol: Protocol::Tcp,
        local_addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
        local_port: local.port(),
        remote_addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
        remote_port: port,
    };
    assert_eq!(snapshot.lookup_owner_pid(&connection), pid);
    assert_eq!(
        snapshot.lookup_owner_pid(&connection.reverse()),
        pid,
        "the accepted end"
    );
    let departed = FlowKey {
        remote_port: 9,
        ..connection.reverse()
    };
    assert_eq!(
        snapshot.lookup_owner_pid(&departed),
        pid,
        "the listener on [::] owns an inbound IPv4 connection"
    );
}

/// Of a row in every TCP state, only established connections become flows, so a finished
/// one is never opened. Every connection a file refers to names its owner, whatever its
/// state; a time-wait or request socket, or one its application has closed, names none.
#[test]
fn only_established_connections_become_flows() {
    let root = socket_tables();
    add_dual_stack_tables(&root);
    let inode_pids = HashMap::from([
        (100, 41),
        (200, 42),
        (202, 43),
        (204, 44),
        (206, 45),
        (209, 46),
        (210, 47),
        (300, 48),
        (301, 49),
        (400, 50),
        (500, 51),
        (600, 52),
    ]);
    let flows = read_proc_flows(&root, &inode_pids).expect("flows");
    let owners = read_socket_owners(&root, &inode_pids, None).expect("socket owners");
    fs::remove_dir_all(&root).expect("remove table directory");

    let client = |port| FlowKey {
        protocol: Protocol::Tcp,
        local_addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
        local_port: port,
        remote_addr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)),
        remote_port: 443,
    };
    let server = |port| FlowKey {
        local_port: 443,
        remote_port: port,
        ..client(0)
    };
    let mapped_loopback = IpAddr::V6(Ipv4Addr::LOCALHOST.to_ipv6_mapped());
    let dual_stack = FlowKey {
        protocol: Protocol::Tcp,
        local_addr: mapped_loopback,
        local_port: 50_001,
        remote_addr: mapped_loopback,
        remote_port: 8080,
    };
    let connected_udp = FlowKey {
        protocol: Protocol::Udp,
        local_addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
        local_port: 54_321,
        remote_addr: IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
        remote_port: 53,
    };
    assert_eq!(
        flows,
        HashMap::from([
            (client(50_000), (42, 200)),
            (client(50_010), (47, 210)),
            (server(50_013), (0, 0)),
            (dual_stack, (50, 400)),
            (connected_udp, (49, 301)),
        ]),
        "established, close-wait and not yet accepted connections, and connected UDP"
    );

    for (port, owner) in [
        (50_000, Some(42)),
        (50_002, Some(43)),
        (50_004, Some(44)),
        (50_005, None),
        (50_006, Some(45)),
        (50_007, None),
        (50_008, None),
        (50_009, Some(46)),
        (50_010, Some(47)),
        (50_011, None),
        (50_012, None),
    ] {
        assert_eq!(owners.lookup_owner_pid(&client(port)), owner, "port {port}");
    }
    assert_eq!(
        owners.lookup_owner_pid(&server(50_003)),
        Some(41),
        "a request socket names no process; its listener owns it"
    );
    let finished_dual_stack = FlowKey {
        local_addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
        local_port: 50_014,
        remote_addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
        ..dual_stack
    };
    assert_eq!(owners.lookup_owner_pid(&finished_dual_stack), None);
}

/// The count is the established TCP connections only, in both families: of the fixture's
/// rows, IPv4 `127.0.0.1:50000` (`ESTABLISHED`), `:50010` (`CLOSE_WAIT`) and the
/// connection waiting on `:443`, and the dual-stack connection in `tcp6`. Its listeners
/// and handshakes, the connections this end has sent its FIN on (`:50004` and `:50006`,
/// which their application still holds, among them), its time-wait rows, its UDP binds and
/// its connected UDP socket are not counted.
#[test]
fn the_active_count_is_established_tcp_connections() {
    let root = socket_tables();
    add_dual_stack_tables(&root);
    let count = count_established_tcp_connections(&root).expect("count");
    fs::remove_dir_all(&root).expect("remove table directory");
    assert_eq!(count, 4);
}

#[test]
fn an_unreadable_table_is_no_count() {
    let root = socket_tables();
    fs::remove_file(root.join("tcp")).expect("remove tcp table");
    fs::create_dir(root.join("tcp")).expect("put a directory where the tcp table was");
    let count = count_established_tcp_connections(&root);
    fs::remove_dir_all(&root).expect("remove table directory");
    assert!(count.is_err(), "{count:?}");
}
