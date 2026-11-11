use super::poller::{PendingUdpClose, emit_tcp_table_row, tcp_table_event};
use super::tables::{
    AlignedBuffer, MAX_TCP_TABLE_BYTES, OWNER_PID_BUFFERS, TCP_STATE_CLOSE_WAIT,
    TCP_STATE_ESTABLISHED, TCP_STATE_LISTEN, fetch_into_with, ingest_tcp, ingest_tcp_listeners,
    map_tcp_listeners, map_tcp_rows, table_rows, tcp_socket, tcp_table_size_ok,
};
use super::*;
use arc_swap::ArcSwap;
use netmetrics_core::Protocol;
use netmetrics_sys::{BackendEvent, EventSink};
use std::collections::HashSet;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::sync::mpsc::sync_channel;
use windows::Win32::Foundation::{ERROR_INSUFFICIENT_BUFFER, NO_ERROR};
use windows::Win32::NetworkManagement::IpHelper::{
    MIB_TCPROW_OWNER_MODULE, MIB_TCPTABLE_OWNER_MODULE,
};

#[test]
fn owns_local_endpoint_finds_this_process_tcp_and_udp_sockets() {
    let listener = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("listen");
    let client =
        std::net::TcpStream::connect(listener.local_addr().expect("addr")).expect("connect");
    let _accepted = listener.accept().expect("accept");
    let udp = std::net::UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).expect("bind udp");
    let pid = std::process::id();
    let tcp_port = client.local_addr().expect("tcp addr").port();
    let udp_port = udp.local_addr().expect("udp addr").port();

    let at = |port: u16| move |_: IpAddr, local_port: u16| local_port == port;
    assert_eq!(owns_local_endpoint(true, pid, at(tcp_port)), Ok(true));
    assert_eq!(owns_local_endpoint(false, pid, at(udp_port)), Ok(true));
    // The same ports under another owner, or the wrong protocol, are foreign.
    assert_eq!(owns_local_endpoint(true, pid + 1, at(tcp_port)), Ok(false));
    assert_eq!(owns_local_endpoint(false, pid, at(tcp_port)), Ok(false));
}

fn tcp4_row(state: u32, pid: u32, created: i64) -> MIB_TCPROW_OWNER_MODULE {
    MIB_TCPROW_OWNER_MODULE {
        dwState: state,
        dwLocalAddr: u32::from_ne_bytes([192, 0, 2, 10]),
        dwLocalPort: u32::from(u16::to_be(50_000)),
        dwRemoteAddr: u32::from_ne_bytes([198, 51, 100, 20]),
        dwRemotePort: u32::from(u16::to_be(443)),
        dwOwningPid: pid,
        liCreateTimestamp: created,
        OwningModuleInfo: [0; 16],
    }
}

#[test]
fn first_tcp_poll_opens_a_flow_and_later_polls_only_learn_the_cookie() {
    let key = FlowKey {
        protocol: Protocol::Tcp,
        local_addr: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
        local_port: 50_000,
        remote_addr: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 20)),
        remote_port: 443,
    };
    let cookie = SocketCookie {
        value: 7,
        source: CookieSource::WindowsCreateTimestamp,
    };
    let opened = tcp_table_event(true, key, 42, cookie, 1);
    assert!(matches!(opened, BackendEvent::Opened { pid: 42, .. }));
    let learned = tcp_table_event(false, key, 42, cookie, 2);
    assert!(matches!(
        learned,
        BackendEvent::CookieResolved { pid: 42, .. }
    ));
}

#[test]
fn startup_seed_opens_only_established_and_close_wait() {
    let mut established = HashMap::new();
    ingest_tcp(&[tcp4_row(TCP_STATE_ESTABLISHED, 42, 7)], &mut established);
    assert!(established.values().next().expect("established").seeds_flow);

    let mut close_wait = HashMap::new();
    ingest_tcp(&[tcp4_row(TCP_STATE_CLOSE_WAIT, 42, 7)], &mut close_wait);
    assert!(close_wait.values().next().expect("close-wait").seeds_flow);

    // CLOSED, SYN_SENT, SYN_RCVD, FIN_WAIT1, FIN_WAIT2, CLOSING, LAST_ACK,
    // TIME_WAIT, DELETE_TCB. Listen is not a flow row.
    for state in [1, 3, 4, 6, 7, 9, 10, 11, 12] {
        let mut owners = HashMap::new();
        ingest_tcp(&[tcp4_row(state, 42, 7)], &mut owners);
        let seen = owners
            .values()
            .next()
            .expect("non-listen row stays in the owner map");
        assert!(
            !seen.seeds_flow,
            "state {state} must not open a flow at startup"
        );
        let event = tcp_table_event(
            seen.seeds_flow,
            seen_key(&owners),
            seen.pid,
            seen.cookie(),
            1,
        );
        assert!(matches!(event, BackendEvent::CookieResolved { .. }));
    }
}

fn seen_key(owners: &HashMap<FlowKey, TcpSeen>) -> FlowKey {
    *owners.keys().next().expect("key")
}

#[test]
fn rejected_seed_open_is_retried_as_an_open() {
    let (sender, receiver) = sync_channel(1);
    let sink = EventSink::new(sender, Arc::new(AtomicU64::new(0)));
    let key = FlowKey {
        protocol: Protocol::Tcp,
        local_addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
        local_port: 50_000,
        remote_addr: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 20)),
        remote_port: 443,
    };
    let seen = TcpSeen {
        pid: 42,
        created: 7,
        seeds_flow: true,
    };
    let mut pending = HashSet::new();
    assert!(sink.emit(tcp_table_event(true, key, seen.pid, seen.cookie(), 1)));
    emit_tcp_table_row(&sink, &mut pending, true, key, seen, 2);
    assert!(pending.contains(&key));
    let _ = receiver.try_recv().expect("first event");
    emit_tcp_table_row(&sink, &mut pending, true, key, seen, 3);
    assert!(!pending.contains(&key));
    assert!(matches!(
        receiver.try_recv(),
        Ok(BackendEvent::Opened { .. })
    ));
}

#[test]
fn rejected_udp_closes_are_retried_in_order_until_the_endpoint_is_bound_again() {
    let (sender, receiver) = sync_channel(1);
    let sink = EventSink::new(sender, Arc::new(AtomicU64::new(0)));
    let mut poller = CookiePoller::new(
        Arc::new(ArcSwap::from_pointee(TcpOwnerSnapshot::default())),
        Arc::new(ArcSwap::from_pointee(UdpOwnerSnapshot::default())),
        Duration::from_secs(1),
    );
    let close = |port: u16| PendingUdpClose {
        key: (IpAddr::V4(Ipv4Addr::LOCALHOST), port),
        cookie: None,
        timestamp: u64::from(port),
    };
    let port = |event: BackendEvent| match event {
        BackendEvent::LocalEndpointClosed { local_port, .. } => local_port,
        other => panic!("unexpected {other:?}"),
    };
    poller.pending_udp_closes = vec![close(1), close(2), close(3)];
    poller.emit_udp_closes(&sink);
    assert_eq!(port(receiver.try_recv().expect("first close")), 1);
    assert_eq!(
        poller.pending_udp_closes.len(),
        2,
        "the full channel keeps the rest"
    );

    // Port 2 was bound by a new socket before the retry.
    poller
        .working_udp
        .insert((IpAddr::V4(Ipv4Addr::LOCALHOST), 2), UdpBind::Ambiguous);
    poller.emit_udp_closes(&sink);
    assert_eq!(port(receiver.try_recv().expect("retried close")), 3);
    assert!(poller.pending_udp_closes.is_empty());
    assert!(receiver.try_recv().is_err());
}

#[test]
fn ingest_tcp4_writes_rows_directly_into_the_working_map() {
    let rows = [
        tcp4_row(5, 4242, 133_000_000),
        tcp4_row(TCP_STATE_LISTEN, 1, 1),
    ];
    let mut map = HashMap::new();
    ingest_tcp(&rows, &mut map);
    assert_eq!(map.len(), 1);
    let seen = map.values().next().expect("row");
    assert_eq!(seen.pid, 4242);
    assert_eq!(seen.created, 133_000_000);
}

fn tcp_owner_snapshot(created: i64, valid_through: i64) -> (TcpOwnerSnapshot, FlowKey) {
    let socket = tcp_socket(&tcp4_row(5, 4242, created)).expect("owned TCP socket");
    let mut live = HashMap::new();
    live.insert(
        socket.key,
        TcpSeen {
            pid: socket.pid,
            created: socket.created,
            seeds_flow: false,
        },
    );
    let mut snapshot = TcpOwnerSnapshot::default();
    snapshot.fill_from(&live, valid_through, Duration::ZERO);
    (snapshot, socket.key)
}

#[test]
fn tcp_owner_snapshot_requires_event_within_observed_socket_lifetime() {
    let (snapshot, key) = tcp_owner_snapshot(100, 200);

    assert_eq!(
        snapshot.lookup(&key, 150).map(|owner| owner.pid),
        Some(4242)
    );
    assert!(snapshot.lookup(&key, 99).is_none(), "event predates socket");
    assert!(
        snapshot.lookup(&key, 201).is_none(),
        "event is newer than the table observation"
    );
}

#[test]
fn tcp_owner_snapshot_matches_reverse_ipv4_and_ipv6() {
    let (mut snapshot, key4) = tcp_owner_snapshot(100, 200);
    let mut key6 = key4;
    key6.local_addr = IpAddr::V6(Ipv6Addr::LOCALHOST);
    key6.remote_addr = "2001:db8::1".parse().unwrap();
    snapshot.sockets.insert(
        key6,
        TcpSeen {
            pid: 4242,
            created: 100,
            seeds_flow: false,
        },
    );
    for key in [key4, key6] {
        assert_eq!(snapshot.lookup(&key.reverse(), 150).unwrap().pid, 4242);
    }
    snapshot.fill_from_at(
        &HashMap::new(),
        300,
        Instant::now(),
        CLOSED_OWNER_GRACE,
        Duration::ZERO,
    );
    for key in [key4, key6] {
        assert_eq!(snapshot.lookup(&key.reverse(), 250).unwrap().pid, 4242);
        assert!(snapshot.lookup(&key.reverse(), 301).is_none());
    }
}

#[test]
fn tcp_live_validity_is_bounded_by_one_poll_interval() {
    let (mut snapshot, key) = tcp_owner_snapshot(100, 200);
    let live = snapshot.sockets.clone();
    let interval = Duration::from_nanos(5_000);
    snapshot.fill_from(&live, 200, interval);
    for key in [key, key.reverse()] {
        assert!(snapshot.lookup(&key, 250).is_some());
        assert!(snapshot.lookup(&key, 251).is_none());
        assert!(snapshot.lookup(&key, 99).is_none());
    }
    snapshot.fill_from(&HashMap::new(), 300, interval);
    assert!(snapshot.lookup(&key.reverse(), 300).is_some());
    assert!(snapshot.lookup(&key.reverse(), 301).is_none());
    snapshot.fill_from(&live, i64::MAX - 1, interval);
    assert_eq!(snapshot.valid_until, i64::MAX);
}

#[test]
fn tcp_owner_snapshot_requires_an_exact_full_tuple() {
    let (snapshot, key) = tcp_owner_snapshot(100, 200);
    let mut contradictory = key;
    contradictory.remote_addr = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9));

    assert!(snapshot.lookup(&contradictory, 150).is_none());
}

#[test]
fn disappeared_tcp_owner_still_pins_pid_within_grace() {
    let t0 = Instant::now();
    let (mut snapshot, key) = tcp_owner_snapshot(100, 200);
    snapshot.fill_from_at(&HashMap::new(), 300, t0, CLOSED_OWNER_GRACE, Duration::ZERO);

    assert_eq!(
        snapshot.lookup(&key, 150).map(|owner| owner.pid),
        Some(4242)
    );
    assert_eq!(
        snapshot.lookup(&key, 250).map(|owner| owner.pid),
        Some(4242)
    );
    assert!(
        snapshot.lookup(&key, 301).is_none(),
        "event is newer than close observation"
    );
}

#[test]
fn expired_closed_tcp_owner_does_not_pin() {
    let t0 = Instant::now();
    let (mut snapshot, key) = tcp_owner_snapshot(100, 200);
    snapshot.fill_from_at(&HashMap::new(), 300, t0, CLOSED_OWNER_GRACE, Duration::ZERO);
    snapshot.fill_from_at(
        &HashMap::new(),
        400,
        t0 + CLOSED_OWNER_GRACE + Duration::from_millis(1),
        CLOSED_OWNER_GRACE,
        Duration::ZERO,
    );

    assert!(snapshot.lookup(&key, 150).is_none());
}

#[test]
fn reused_tuple_uses_live_owner_for_new_events_and_closed_owner_for_old() {
    let t0 = Instant::now();
    let (mut snapshot, key) = tcp_owner_snapshot(100, 200);
    let mut live = HashMap::new();
    live.insert(
        key,
        TcpSeen {
            pid: 8484,
            created: 500,
            seeds_flow: false,
        },
    );
    snapshot.fill_from_at(&live, 600, t0, CLOSED_OWNER_GRACE, Duration::ZERO);

    assert_eq!(
        snapshot.lookup(&key, 550).map(|owner| owner.pid),
        Some(8484)
    );
    assert_eq!(
        snapshot.lookup(&key, 150).map(|owner| owner.pid),
        Some(4242)
    );
}

fn owner_pid_buffer_capacities() -> (usize, usize) {
    let buffers = OWNER_PID_BUFFERS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    (buffers.0.capacity_bytes(), buffers.1.capacity_bytes())
}

#[test]
fn counting_sockets_retains_owner_pid_buffers_across_reads() {
    let _ = count_owner_pid_tables();
    let first = owner_pid_buffer_capacities();
    let _ = count_owner_pid_tables();
    assert_eq!(first, owner_pid_buffer_capacities());
}

#[test]
fn established_rows_map_to_keyed_sockets() {
    let mapped = map_tcp_rows(&[tcp4_row(5, 4242, 133_000_000)]);
    assert_eq!(mapped.len(), 1);
    assert_eq!(mapped[0].pid, 4242);
    assert_eq!(mapped[0].key.local_port, 50_000);
    assert_eq!(mapped[0].key.remote_port, 443);
    assert_eq!(
        mapped[0].key.local_addr,
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10))
    );
    assert_eq!(
        mapped[0].cookie().source,
        CookieSource::WindowsCreateTimestamp
    );
}

#[test]
fn listeners_and_unowned_rows_are_skipped() {
    assert!(map_tcp_rows(&[tcp4_row(TCP_STATE_LISTEN, 4242, 1)]).is_empty());
    assert!(map_tcp_rows(&[tcp4_row(5, 0, 1)]).is_empty());
}

#[test]
fn listener_rows_map_to_local_bind_owners() {
    let mapped = map_tcp_listeners(&[tcp4_row(TCP_STATE_LISTEN, 4242, 1)]);
    assert_eq!(mapped.len(), 1);
    assert_eq!(
        mapped[0].0,
        (IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)), 50_000)
    );
    assert_eq!(
        mapped[0].1,
        TcpSeen {
            pid: 4242,
            created: 1,
            seeds_flow: false,
        }
    );
    assert!(map_tcp_listeners(&[tcp4_row(5, 4242, 1)]).is_empty());
    assert!(map_tcp_listeners(&[tcp4_row(TCP_STATE_LISTEN, 0, 1)]).is_empty());
}

#[test]
fn listener_fallback_rejects_events_before_creation_and_after_snapshot_expiry() {
    let row = tcp4_row(TCP_STATE_LISTEN, 4242, 100);
    let key = map_tcp_rows(&[tcp4_row(5, 4242, 100)])[0].key;
    let mut snapshot = TcpOwnerSnapshot {
        valid_through: 200,
        valid_until: 250,
        ..TcpOwnerSnapshot::default()
    };
    ingest_tcp_listeners(&[row], &mut snapshot.listeners);
    assert!(
        snapshot.lookup(&key, 99).is_none(),
        "a replacement listener cannot own older events"
    );
    assert_eq!(snapshot.lookup(&key, 100).unwrap().pid, 4242);
    assert_eq!(snapshot.lookup(&key, 250).unwrap().created, 0);
    assert!(
        snapshot.lookup(&key, 251).is_none(),
        "failed polls cannot extend listener validity"
    );
}

#[test]
fn listener_fallback_rejects_missing_creation_time() {
    let key = map_tcp_rows(&[tcp4_row(5, 4242, 100)])[0].key;
    let mut snapshot = TcpOwnerSnapshot {
        valid_through: 200,
        valid_until: 250,
        ..TcpOwnerSnapshot::default()
    };
    ingest_tcp_listeners(
        &[tcp4_row(TCP_STATE_LISTEN, 4242, 0)],
        &mut snapshot.listeners,
    );
    assert!(snapshot.lookup(&key, 150).is_none());
}

#[test]
fn listener_fallback_attributes_inbound_when_the_tuple_is_absent() {
    let mut snapshot = TcpOwnerSnapshot {
        valid_through: 200,
        valid_until: 250,
        ..TcpOwnerSnapshot::default()
    };
    insert_tcp_listener(
        &mut snapshot.listeners,
        (IpAddr::V4(Ipv4Addr::UNSPECIFIED), 50_000),
        TcpSeen {
            pid: 4242,
            created: 100,
            seeds_flow: false,
        },
    );
    let inbound = FlowKey {
        protocol: Protocol::Tcp,
        local_addr: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
        local_port: 50_000,
        remote_addr: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 20)),
        remote_port: 51_000,
    };
    let owner = snapshot
        .lookup(&inbound, 150)
        .expect("the listener owns the local port");
    assert_eq!(owner.pid, 4242);
    assert_eq!(
        owner.created, 0,
        "a listener must not fabricate a connection cookie"
    );

    let mut outbound = inbound;
    std::mem::swap(&mut outbound.local_addr, &mut outbound.remote_addr);
    std::mem::swap(&mut outbound.local_port, &mut outbound.remote_port);
    assert!(
        snapshot.lookup(&outbound, 150).is_none(),
        "a listener must not claim a flow on the peer's port"
    );
}

#[test]
fn exact_socket_owner_wins_over_a_listener_fallback() {
    let (mut snapshot, key) = tcp_owner_snapshot(100, 200);
    insert_tcp_listener(
        &mut snapshot.listeners,
        (key.local_addr, key.local_port),
        TcpSeen {
            pid: 8484,
            created: 100,
            seeds_flow: false,
        },
    );
    let owner = snapshot.lookup(&key, 150).expect("exact owner");
    assert_eq!(owner.pid, 4242);
    assert!(owner.created > 0, "an exact owner keeps its cookie");
}

#[test]
fn ambiguous_listener_is_not_attributed() {
    let mut snapshot = TcpOwnerSnapshot {
        valid_through: 200,
        valid_until: 250,
        ..TcpOwnerSnapshot::default()
    };
    let endpoint = (IpAddr::V4(Ipv4Addr::UNSPECIFIED), 50_000);
    insert_tcp_listener(
        &mut snapshot.listeners,
        endpoint,
        TcpSeen {
            pid: 4242,
            created: 100,
            seeds_flow: false,
        },
    );
    insert_tcp_listener(
        &mut snapshot.listeners,
        endpoint,
        TcpSeen {
            pid: 8484,
            created: 100,
            seeds_flow: false,
        },
    );
    let inbound = FlowKey {
        protocol: Protocol::Tcp,
        local_addr: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
        local_port: 50_000,
        remote_addr: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 20)),
        remote_port: 51_000,
    };
    assert!(snapshot.lookup(&inbound, 150).is_none());
}

#[test]
fn a_reused_tuple_with_a_later_timestamp_yields_a_contradicting_cookie() {
    let first = map_tcp_rows(&[tcp4_row(5, 4242, 133_000_000)])[0].cookie();
    let second = map_tcp_rows(&[tcp4_row(5, 4243, 133_000_500)])[0].cookie();
    assert!(first.contradicts(second));
}

#[test]
fn an_unchanged_socket_yields_a_stable_cookie() {
    let first = map_tcp_rows(&[tcp4_row(5, 4242, 133_000_000)])[0].cookie();
    let again = map_tcp_rows(&[tcp4_row(5, 4242, 133_000_000)])[0].cookie();
    assert!(!first.contradicts(again));
}

#[test]
#[ignore = "requires Windows; enumerates the live TCP table"]
fn live_table_returns_established_sockets_with_stable_cookies() {
    let first = snapshot().expect("owner-module snapshot");
    assert!(
        !first.is_empty(),
        "an interactive session should hold at least one established TCP socket"
    );
    for socket in &first {
        assert_ne!(socket.pid, 0);
        assert_ne!(socket.key.remote_port, 0);
    }

    eprintln!("established TCP sockets: {}", first.len());
    for socket in first.iter().take(3) {
        eprintln!(
            "  {}:{} -> {}:{} pid={} created={}",
            socket.key.local_addr,
            socket.key.local_port,
            socket.key.remote_addr,
            socket.key.remote_port,
            socket.pid,
            socket.created
        );
    }

    // A socket's creation timestamp is fixed, so re-reading must not look like a change.
    let second = snapshot().expect("second snapshot");
    for socket in &first {
        if let Some(later) = second.iter().find(|other| other.key == socket.key) {
            assert!(
                !socket.cookie().contradicts(later.cookie()),
                "a live socket changed cookie between reads: {:?}",
                socket.key
            );
        }
    }
}

#[test]
fn buffers_satisfy_the_alignment_the_row_structs_require() {
    let mut buffer = AlignedBuffer::new();
    buffer.ensure(1000);
    assert_eq!(
        buffer.as_bytes().as_ptr() as usize % align_of::<MIB_TCPROW_OWNER_MODULE>(),
        0
    );
}

#[test]
fn truncated_tables_yield_no_rows_instead_of_reading_out_of_bounds() {
    let header = std::mem::offset_of!(MIB_TCPTABLE_OWNER_MODULE, table);
    // Claims 100 rows but carries none.
    let mut buffer = AlignedBuffer::new();
    buffer.ensure(header);
    // SAFETY: the buffer owns at least `header` bytes.
    unsafe {
        buffer
            .as_mut_ptr()
            .copy_from(100_u32.to_ne_bytes().as_ptr(), 4);
    }
    // SAFETY: `AlignedBuffer` satisfies the row alignment; the bounds clamp is the
    // behaviour under test.
    let rows: &[MIB_TCPROW_OWNER_MODULE] = unsafe { table_rows(buffer.as_bytes(), header) };
    assert!(rows.is_empty());
}

#[test]
fn oversized_table_requests_are_rejected_before_allocation() {
    assert!(tcp_table_size_ok(0).is_ok());
    assert!(tcp_table_size_ok(MAX_TCP_TABLE_BYTES).is_ok());
    assert!(tcp_table_size_ok(MAX_TCP_TABLE_BYTES + 1).is_err());
    assert!(tcp_table_size_ok(u32::MAX).is_err());
}

#[test]
fn fetch_retry_rejects_an_oversized_report_before_growing() {
    let mut buffer = AlignedBuffer::new();
    buffer.ensure(64);
    let capacity_before = buffer.capacity_bytes();
    let mut calls = 0_u32;
    let result = fetch_into_with(&mut buffer, |_, size| {
        calls += 1;
        *size = MAX_TCP_TABLE_BYTES + 1;
        ERROR_INSUFFICIENT_BUFFER.0
    });
    assert!(result.is_err());
    assert_eq!(calls, 1);
    assert_eq!(buffer.capacity_bytes(), capacity_before);
}

#[test]
fn fetch_retry_grows_only_after_the_cap_check() {
    let mut buffer = AlignedBuffer::new();
    let mut calls = 0_u32;
    let result = fetch_into_with(&mut buffer, |table, size| {
        calls += 1;
        if calls == 1 {
            *size = 256;
            return ERROR_INSUFFICIENT_BUFFER.0;
        }
        assert!(table.is_some());
        NO_ERROR.0
    });
    assert!(result.is_ok());
    assert_eq!(calls, 2);
    assert!(buffer.capacity_bytes() >= 256);
}

fn udp_endpoint(pid: u32, created: i64) -> OwnedUdpEndpoint {
    OwnedUdpEndpoint {
        local_addr: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
        local_port: 53,
        pid,
        created,
    }
}

#[test]
fn conflicting_udp_binds_are_ambiguous_instead_of_last_write() {
    let mut map = HashMap::new();
    insert_udp_bind(&mut map, udp_endpoint(1, 10));
    insert_udp_bind(&mut map, udp_endpoint(2, 11));
    assert_eq!(
        map.get(&(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)), 53)),
        Some(&UdpBind::Ambiguous)
    );
    let mut snapshot = UdpOwnerSnapshot::default();
    snapshot.fill_from(&map, 200, Duration::ZERO);
    assert!(
        snapshot
            .lookup(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)), 53, 150)
            .is_none()
    );
}

#[test]
fn ambiguous_exact_bind_does_not_fall_back_to_a_wildcard_owner() {
    let specific = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10));
    let wildcard = IpAddr::V4(Ipv4Addr::UNSPECIFIED);
    let mut live = HashMap::new();
    live.insert((specific, 53), UdpBind::Ambiguous);
    live.insert(
        (wildcard, 53),
        UdpBind::Unique(OwnedUdpEndpoint {
            local_addr: wildcard,
            local_port: 53,
            pid: 99,
            created: 1,
        }),
    );
    let mut snapshot = UdpOwnerSnapshot::default();
    snapshot.fill_from(&live, 200, Duration::ZERO);
    assert!(
        snapshot.lookup(specific, 53, 150).is_none(),
        "an ambiguous exact bind must not inherit a wildcard owner"
    );
    assert_eq!(
        snapshot
            .lookup(wildcard, 53, 150)
            .map(|endpoint| endpoint.pid),
        Some(99)
    );
    assert_eq!(
        snapshot
            .lookup(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 11)), 53, 150)
            .map(|endpoint| endpoint.pid),
        Some(99),
        "a missing exact bind may still use a unique wildcard"
    );
}

#[test]
fn udp_validity_is_bounded_and_closed_generations_stay_strict() {
    for addr in [
        IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        IpAddr::V6(Ipv6Addr::UNSPECIFIED),
    ] {
        let mut endpoint = udp_endpoint(42, 100);
        endpoint.local_addr = addr;
        let local = if addr.is_ipv4() {
            "192.0.2.10"
        } else {
            "2001:db8::1"
        }
        .parse()
        .unwrap();
        let live = HashMap::from([(endpoint.key(), UdpBind::Unique(endpoint))]);
        let mut snapshot = UdpOwnerSnapshot::default();
        let interval = Duration::from_nanos(5_000);
        snapshot.fill_from(&live, 200, interval);
        for address in [addr, local] {
            assert!(snapshot.lookup(address, endpoint.local_port, 250).is_some());
            assert!(snapshot.lookup(address, endpoint.local_port, 251).is_none());
            assert!(snapshot.lookup(address, endpoint.local_port, 99).is_none());
        }
        let replacement = OwnedUdpEndpoint {
            pid: 99,
            created: 300,
            ..endpoint
        };
        snapshot.fill_from(
            &HashMap::from([(endpoint.key(), UdpBind::Unique(replacement))]),
            350,
            interval,
        );
        assert_eq!(
            snapshot
                .lookup(local, endpoint.local_port, 400)
                .unwrap()
                .pid,
            99
        );
        assert_eq!(
            snapshot
                .lookup(local, endpoint.local_port, 250)
                .unwrap()
                .pid,
            42
        );
        snapshot.fill_from(&HashMap::new(), 450, interval);
        assert!(snapshot.lookup(local, endpoint.local_port, 451).is_none());
        snapshot.fill_from(&live, i64::MAX - 1, interval);
        assert_eq!(snapshot.valid_until, i64::MAX);
    }
}

#[test]
fn udp_rebind_cookie_splits_before_new_bytes_are_charged() {
    let old = udp_endpoint(42, 100);
    let new = udp_endpoint(99, 300);
    let key = FlowKey {
        protocol: Protocol::Udp,
        local_addr: old.local_addr,
        local_port: old.local_port,
        remote_addr: "198.51.100.1".parse().unwrap(),
        remote_port: 9999,
    };
    let mut table = netmetrics_core::FlowTable::new(4);
    table.add_attributed_bytes_ref(
        key,
        old.pid,
        None,
        netmetrics_core::ByteDelta {
            sent: 1,
            received: 0,
        },
        1,
        Some(old.cookie()),
    );
    let outcome = table.add_attributed_bytes_ref(
        key,
        new.pid,
        None,
        netmetrics_core::ByteDelta {
            sent: 2,
            received: 0,
        },
        2,
        Some(new.cookie()),
    );
    assert_eq!(outcome.superseded.unwrap().bytes_sent, 1);
    assert_eq!(table.get(&key).unwrap().meta.pid, 99);
    assert_eq!(table.get(&key).unwrap().bytes_sent, 2);
}

#[test]
fn identical_udp_rows_stay_unique() {
    let mut map = HashMap::new();
    insert_udp_bind(&mut map, udp_endpoint(1, 10));
    insert_udp_bind(&mut map, udp_endpoint(1, 10));
    assert!(matches!(
        map.get(&(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)), 53)),
        Some(UdpBind::Unique(_))
    ));
}

#[test]
fn udp_owner_snapshot_requires_event_within_observed_bind_lifetime() {
    let endpoint = udp_endpoint(4242, 100);
    let mut live = HashMap::new();
    live.insert(endpoint.key(), UdpBind::Unique(endpoint));
    let mut snapshot = UdpOwnerSnapshot::default();
    snapshot.fill_from(&live, 200, Duration::ZERO);

    assert!(
        snapshot
            .lookup(endpoint.local_addr, endpoint.local_port, 150)
            .is_some()
    );
    assert!(
        snapshot
            .lookup(endpoint.local_addr, endpoint.local_port, 99)
            .is_none(),
        "event predates bind"
    );
    assert!(
        snapshot
            .lookup(endpoint.local_addr, endpoint.local_port, 201)
            .is_none(),
        "event is newer than the table observation"
    );
}

#[test]
fn disappeared_udp_owner_still_pins_pid_within_grace() {
    let t0 = Instant::now();
    let endpoint = udp_endpoint(4242, 10);
    let mut live = HashMap::new();
    live.insert(endpoint.key(), UdpBind::Unique(endpoint));
    let mut snapshot = UdpOwnerSnapshot::default();
    snapshot.fill_from_at(&live, 200, t0, CLOSED_OWNER_GRACE, Duration::ZERO);
    snapshot.fill_from_at(&HashMap::new(), 300, t0, CLOSED_OWNER_GRACE, Duration::ZERO);

    assert_eq!(
        snapshot
            .lookup(endpoint.local_addr, endpoint.local_port, 250)
            .map(|owner| owner.pid),
        Some(4242)
    );
}

#[test]
fn closed_udp_owner_does_not_pin_an_event_after_disappearance() {
    let t0 = Instant::now();
    let endpoint = udp_endpoint(4242, 100);
    let mut live = HashMap::new();
    live.insert(endpoint.key(), UdpBind::Unique(endpoint));
    let mut snapshot = UdpOwnerSnapshot::default();
    snapshot.fill_from_at(&live, 200, t0, CLOSED_OWNER_GRACE, Duration::ZERO);
    snapshot.fill_from_at(&HashMap::new(), 300, t0, CLOSED_OWNER_GRACE, Duration::ZERO);

    assert!(
        snapshot
            .lookup(endpoint.local_addr, endpoint.local_port, 301)
            .is_none(),
        "an event newer than the disappearance observation belongs to an unknown or reused bind"
    );
}

#[test]
fn closed_udp_owner_does_not_pin_an_event_before_creation() {
    let t0 = Instant::now();
    let endpoint = udp_endpoint(4242, 100);
    let mut live = HashMap::new();
    live.insert(endpoint.key(), UdpBind::Unique(endpoint));
    let mut snapshot = UdpOwnerSnapshot::default();
    snapshot.fill_from_at(&live, 200, t0, CLOSED_OWNER_GRACE, Duration::ZERO);
    snapshot.fill_from_at(&HashMap::new(), 300, t0, CLOSED_OWNER_GRACE, Duration::ZERO);

    assert!(
        snapshot
            .lookup(endpoint.local_addr, endpoint.local_port, 99)
            .is_none(),
        "an event predating the retained bind cannot belong to it"
    );
}

#[test]
fn reused_udp_bind_uses_live_owner_for_new_events_and_closed_owner_for_old() {
    let t0 = Instant::now();
    let old = udp_endpoint(4242, 100);
    let new = udp_endpoint(8484, 500);
    let mut live = HashMap::new();
    live.insert(old.key(), UdpBind::Unique(old));
    let mut snapshot = UdpOwnerSnapshot::default();
    snapshot.fill_from_at(&live, 200, t0, CLOSED_OWNER_GRACE, Duration::ZERO);
    live.insert(new.key(), UdpBind::Unique(new));
    snapshot.fill_from_at(&live, 600, t0, CLOSED_OWNER_GRACE, Duration::ZERO);

    assert_eq!(
        snapshot
            .lookup(new.local_addr, new.local_port, 550)
            .map(|owner| owner.pid),
        Some(8484)
    );
    assert_eq!(
        snapshot
            .lookup(old.local_addr, old.local_port, 150)
            .map(|owner| owner.pid),
        Some(4242)
    );
}

#[test]
fn newest_closed_udp_generation_replaces_the_older_one() {
    let t0 = Instant::now();
    let old = udp_endpoint(4242, 100);
    let new = udp_endpoint(8484, 500);
    let mut live = HashMap::new();
    live.insert(old.key(), UdpBind::Unique(old));
    let mut snapshot = UdpOwnerSnapshot::default();
    snapshot.fill_from_at(&live, 200, t0, CLOSED_OWNER_GRACE, Duration::ZERO);
    live.insert(new.key(), UdpBind::Unique(new));
    snapshot.fill_from_at(&live, 600, t0, CLOSED_OWNER_GRACE, Duration::ZERO);
    snapshot.fill_from_at(&HashMap::new(), 700, t0, CLOSED_OWNER_GRACE, Duration::ZERO);

    assert_eq!(
        snapshot
            .lookup(new.local_addr, new.local_port, 650)
            .map(|owner| owner.pid),
        Some(8484)
    );
}

#[test]
fn expired_closed_udp_owner_does_not_pin() {
    let t0 = Instant::now();
    let endpoint = udp_endpoint(4242, 10);
    let mut live = HashMap::new();
    live.insert(endpoint.key(), UdpBind::Unique(endpoint));
    let mut snapshot = UdpOwnerSnapshot::default();
    snapshot.fill_from_at(&live, 200, t0, CLOSED_OWNER_GRACE, Duration::ZERO);
    snapshot.fill_from_at(&HashMap::new(), 300, t0, CLOSED_OWNER_GRACE, Duration::ZERO);
    snapshot.fill_from_at(
        &HashMap::new(),
        400,
        t0 + CLOSED_OWNER_GRACE + Duration::from_millis(1),
        CLOSED_OWNER_GRACE,
        Duration::ZERO,
    );

    assert!(
        snapshot
            .lookup(endpoint.local_addr, endpoint.local_port, 250)
            .is_none()
    );
}

fn cached_count(count: u32, sampled_at: Instant) -> CachedTcpCount {
    CachedTcpCount {
        sample: SocketCountSample {
            count,
            sampled_at_ms: 0,
        },
        sampled_at,
    }
}

#[test]
fn fresh_tcp_count_is_returned_without_walking_the_table() {
    let now = Instant::now();
    let (count, refresh) =
        resolve_tcp_socket_count(Some(cached_count(7, now)), now, TCP_COUNT_TTL, || {
            panic!("fresh cache must not walk OWNER_PID")
        });
    assert_eq!(count, SocketCount::fresh(7));
    assert_eq!(refresh, None);
}

#[test]
fn stale_tcp_count_uses_the_independent_table_reader() {
    let now = Instant::now();
    let sampled_at = now
        .checked_sub(TCP_COUNT_TTL + Duration::from_secs(1))
        .expect("ttl");
    let (count, refresh) = resolve_tcp_socket_count(
        Some(cached_count(7, sampled_at)),
        now,
        TCP_COUNT_TTL,
        || Ok(11),
    );
    assert_eq!(count, SocketCount::fresh(11));
    assert_eq!(refresh, Some(11));
}

#[test]
fn stale_tcp_count_keeps_last_known_when_the_reader_fails() {
    let now = Instant::now();
    let sampled_at = now
        .checked_sub(TCP_COUNT_TTL + Duration::from_secs(1))
        .expect("ttl");
    let (count, refresh) = resolve_tcp_socket_count(
        Some(cached_count(7, sampled_at)),
        now,
        TCP_COUNT_TTL,
        || Err("access denied".into()),
    );
    assert_eq!(count, SocketCount::stale(7));
    assert_eq!(refresh, None);
}

#[test]
fn missing_tcp_count_is_none_when_the_reader_fails() {
    let (count, refresh) = resolve_tcp_socket_count(None, Instant::now(), TCP_COUNT_TTL, || {
        Err("access denied".into())
    });
    assert_eq!(count, SocketCount::UNAVAILABLE);
    assert_eq!(refresh, None);
}

#[test]
fn missing_tcp_count_stores_a_successful_walk() {
    let (count, refresh) = resolve_tcp_socket_count(None, Instant::now(), TCP_COUNT_TTL, || Ok(4));
    assert_eq!(count, SocketCount::fresh(4));
    assert_eq!(refresh, Some(4));
}
