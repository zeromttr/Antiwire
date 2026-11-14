use super::*;

/// Writes `address` the way the driver does; see `address_from_words`.
fn put_address(bytes: &mut [u8], address: std::net::IpAddr) {
    let value = u128::from(match address {
        std::net::IpAddr::V4(v4) => v4.to_ipv6_mapped(),
        std::net::IpAddr::V6(v6) => v6,
    });
    for index in 0..4 {
        let word = u32::try_from((value >> (32 * index)) & 0xffff_ffff).expect("word");
        bytes[index * 4..index * 4 + 4].copy_from_slice(&word.to_ne_bytes());
    }
}

fn address(protocol: u8, local_port: u16, remote_port: u16, local: [u8; 4]) -> DivertAddress {
    let mut data = [0u8; 64];
    put_address(&mut data[20..36], std::net::Ipv4Addr::from(local).into());
    put_address(
        &mut data[36..52],
        std::net::Ipv4Addr::new(203, 0, 113, 9).into(),
    );
    data[52..54].copy_from_slice(&local_port.to_ne_bytes());
    data[54..56].copy_from_slice(&remote_port.to_ne_bytes());
    data[56] = protocol;
    data[16..20].copy_from_slice(&77u32.to_ne_bytes());
    DivertAddress {
        timestamp: 0,
        layer_event: EVENT_FLOW_ESTABLISHED << 8,
        reserved2: 0,
        data,
    }
}

#[test]
fn kernel_ticks_convert_to_the_instant_they_name() {
    let now = Instant::now();
    let at = instant_of_ticks(9_000, 10_000, 1_000, now);
    assert_eq!(now.duration_since(at), Duration::from_secs(1));
    assert_eq!(instant_of_ticks(11_000, 10_000, 1_000, now), now, "future");
    assert_eq!(instant_of_ticks(9_000, 10_000, 0, now), now, "no frequency");
}

#[test]
fn only_an_owned_established_flow_feeds_endpoint_owners() {
    let established = address(PROTOCOL_UDP, 50_002, 53, [127, 0, 0, 1]);
    let (key, pid) = established_owner(&established).expect("established");
    assert_eq!(
        (key.local_port, key.protocol, pid),
        (50_002, Protocol::Udp, 77)
    );

    let mut deleted = address(PROTOCOL_UDP, 50_002, 53, [127, 0, 0, 1]);
    deleted.layer_event = EVENT_FLOW_DELETED << 8;
    assert!(established_owner(&deleted).is_none());

    let mut kernel = address(PROTOCOL_UDP, 50_002, 53, [127, 0, 0, 1]);
    kernel.data[16..20].copy_from_slice(&0u32.to_ne_bytes());
    assert!(established_owner(&kernel).is_none());
}

#[test]
fn flow_address_decodes_mapped_ipv4_and_host_ports() {
    let key = flow_key_from_address(&address(PROTOCOL_TCP, 50_000, 443, [198, 51, 100, 8]))
        .expect("tcp flow");
    assert_eq!(key.protocol, Protocol::Tcp);
    assert_eq!(
        key.local_addr,
        std::net::IpAddr::V4(std::net::Ipv4Addr::new(198, 51, 100, 8))
    );
    assert_eq!(key.local_port, 50_000);
    assert_eq!(key.remote_port, 443);
    assert!(flow_key_from_address(&address(1, 1, 1, [1, 1, 1, 1])).is_none());
}

/// Words captured from the driver for a `127.0.0.1` loopback flow, and an
/// IPv6 address laid out the same way.
#[test]
fn flow_address_words_are_least_significant_first() {
    assert_eq!(
        address_from_words(&[0x7f00_0001, 0x0000_ffff, 0, 0]),
        Some(std::net::Ipv4Addr::LOCALHOST.into())
    );
    assert_eq!(
        address_from_words(&[0x0000_0001, 0, 0, 0x2001_0db8]),
        Some(std::net::Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1).into())
    );
    assert_eq!(address_from_words(&[0; 4]), None);

    let mut data = [0u8; 16];
    let v6: std::net::IpAddr = std::net::Ipv6Addr::new(0xfe80, 0, 0, 0, 1, 2, 3, 4).into();
    put_address(&mut data, v6);
    assert_eq!(address_from_words(&read_words(&data)), Some(v6));
}

#[test]
fn tcp_flow_deleted_is_a_close_and_udp_flow_deleted_is_not() {
    let cache = FlowOwnerCache::default();
    let (tx, rx) = std::sync::mpsc::sync_channel(4);
    let sink = netmetrics_sys::EventSink::new(
        tx,
        std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)),
    );
    let mut tcp = address(PROTOCOL_TCP, 50_000, 443, [198, 51, 100, 8]);
    tcp.layer_event = EVENT_FLOW_DELETED << 8;
    let mut udp = address(PROTOCOL_UDP, 50_001, 53, [198, 51, 100, 8]);
    udp.layer_event = EVENT_FLOW_DELETED << 8;
    let mut cache = cache;
    apply_event(&mut cache, &sink, &tcp, Instant::now(), None);
    apply_event(&mut cache, &sink, &udp, Instant::now(), None);
    let closed = rx.try_recv().expect("tcp FLOW_DELETED must close the flow");
    assert!(
        matches!(closed, netmetrics_sys::BackendEvent::Closed { key, .. } if key.protocol == Protocol::Tcp && key.local_port == 50_000)
    );
    assert!(
        rx.try_recv().is_err(),
        "udp FLOW_DELETED must not close a flow"
    );
}

fn established_by(pid: u32, local_port: u16) -> DivertAddress {
    let mut established = address(PROTOCOL_UDP, local_port, 853, [192, 168, 68, 50]);
    established.data[16..20].copy_from_slice(&pid.to_ne_bytes());
    established
}

fn recorded_owners(
    events: &[DivertAddress],
    local_port: u16,
) -> (Option<u32>, endpoint_owner::EndpointOwner) {
    let cache = Mutex::new(FlowOwnerCache::default());
    let feed = EndpointOwnerFeed::new(crate::endpoint_owner::trusted_owner);
    let (tx, _rx) = std::sync::mpsc::sync_channel(4);
    let sink = netmetrics_sys::EventSink::new(
        tx,
        std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)),
    );
    let base = Instant::now();
    let mut at = base;
    for event in events {
        record_event(&cache, &feed, &sink, event, at, at);
        at += Duration::from_millis(1);
    }
    let key = flow_key_from_address(&events[0]).expect("flow key");
    let cached = lock_cache(&cache).lookup(&key, at).map(|owner| owner.pid);
    let endpoint = LocalEndpoint {
        address: key.local_addr,
        port: local_port,
    };
    let recorded = feed.owner_at(Protocol::Udp, endpoint, at, Instant::now());
    (cached, recorded)
}

/// The regression this guards: the `System` flow the kernel reports for a
/// packet the DNS divert reinjected replaced the daemon as its `DoQ`
/// socket's owner, so the divert dropped the daemon's next packet.
#[test]
fn a_reinjected_packets_system_flow_keeps_the_real_owner() {
    let (cached, recorded) = recorded_owners(
        &[
            established_by(77, 50_010),
            established_by(endpoint_owner::SYSTEM_PID, 50_010),
        ],
        50_010,
    );
    assert_eq!(cached, Some(77), "the flow's bytes stay with its owner");
    assert_eq!(recorded, endpoint_owner::EndpointOwner::Resolved(77));
}

#[test]
fn system_flows_nobody_else_holds_and_new_owners_are_still_recorded() {
    let (cached, recorded) = recorded_owners(
        &[established_by(endpoint_owner::SYSTEM_PID, 50_011)],
        50_011,
    );
    assert_eq!(cached, Some(endpoint_owner::SYSTEM_PID));
    assert_eq!(
        recorded,
        endpoint_owner::EndpointOwner::Resolved(endpoint_owner::SYSTEM_PID)
    );

    let (cached, recorded) = recorded_owners(
        &[established_by(77, 50_012), established_by(88, 50_012)],
        50_012,
    );
    assert_eq!(cached, Some(88), "a reused tuple takes its new owner");
    assert_eq!(recorded, endpoint_owner::EndpointOwner::Resolved(88));
}

/// The regression this guards: the echo of a reinjected DNS answer was
/// recorded as `System` owning the resolver's own loopback flow whenever it
/// arrived before the real owner had been recorded, which is the one case
/// [`is_reinjection_echo`] cannot see.
#[test]
fn a_system_flow_on_loopback_is_never_kept_as_the_flows_owner() {
    let on_loopback = |pid: u32, local_port: u16| {
        let mut established = address(PROTOCOL_UDP, local_port, 53, [127, 0, 0, 1]);
        established.data[16..20].copy_from_slice(&pid.to_ne_bytes());
        established
    };
    let (cached, recorded) =
        recorded_owners(&[on_loopback(endpoint_owner::SYSTEM_PID, 50_020)], 50_020);
    assert_eq!(cached, None, "an echo is no owner");
    assert_eq!(recorded, endpoint_owner::EndpointOwner::Untrusted);

    // The real owner, recorded afterwards, is kept as usual.
    let (cached, _) = recorded_owners(
        &[
            on_loopback(endpoint_owner::SYSTEM_PID, 50_021),
            on_loopback(77, 50_021),
        ],
        50_021,
    );
    assert_eq!(cached, Some(77));
}

/// An endpoint's owner at once, after waiting, and how long the wait took.
type OwnerLookup = (
    endpoint_owner::EndpointOwner,
    endpoint_owner::EndpointOwner,
    Duration,
);

fn lookup_pair(
    from: std::net::SocketAddr,
    protocol: Protocol,
    received_at: Instant,
) -> OwnerLookup {
    let endpoint = LocalEndpoint {
        address: from.ip(),
        port: from.port(),
    };
    let now = endpoint_owner::endpoint_owner_at(protocol, endpoint, received_at, Duration::ZERO);
    let started = Instant::now();
    let waited = endpoint_owner::endpoint_owner_at(
        protocol,
        endpoint,
        received_at,
        Duration::from_millis(200),
    );
    (now, waited, started.elapsed())
}

/// Sends one query from `client` and looks up its owner once `server` reads it.
fn udp_lookup(client: &std::net::UdpSocket, server: &std::net::UdpSocket) -> OwnerLookup {
    let server_addr = server.local_addr().expect("udp server addr");
    client.send_to(b"q", server_addr).expect("send");
    let mut buffer = [0u8; 8];
    let (_, from) = server.recv_from(&mut buffer).expect("recv");
    lookup_pair(from, Protocol::Udp, Instant::now())
}

/// One query each from `rounds` new client sockets on `loopback`.
fn fresh_udp_lookups(loopback: std::net::IpAddr, rounds: usize) -> Vec<OwnerLookup> {
    let server = std::net::UdpSocket::bind((loopback, 0)).expect("udp server");
    (0..rounds)
        .map(|_| {
            let client = std::net::UdpSocket::bind((loopback, 0)).expect("udp client");
            udp_lookup(&client, &server)
        })
        .collect()
}

/// Diagnostic for DNS attribution: whether FLOW reports loopback UDP and
/// TCP flows to a local server, as a stub client's query is, and whether
/// the owner is already recorded when the server reads the query.
///
/// Prints how many of the lookups resolved at once, how many only after
/// waiting, and the slowest wait. Read the numbers as well as the result.
#[test]
#[ignore = "downloads WinDivert from reqrypt.org and opens a kernel driver; requires elevation"]
fn live_loopback_flows_record_their_owner_before_the_server_reads() {
    use crate::endpoint_owner::EndpointOwner;
    use std::collections::BTreeMap;
    use std::io::{Read, Write};
    use std::net::{Ipv4Addr, Ipv6Addr, TcpListener, TcpStream, UdpSocket};

    // Clients that sent before the listener started, as a long-lived
    // resolver socket would have.
    let early_server = UdpSocket::bind((Ipv6Addr::LOCALHOST, 0)).expect("early udp server");
    let early_addr = early_server.local_addr().expect("early udp server addr");
    let early_clients: Vec<UdpSocket> = (0..20)
        .map(|_| {
            let client = UdpSocket::bind((Ipv6Addr::LOCALHOST, 0)).expect("early udp client");
            client.send_to(b"q", early_addr).expect("early send");
            let mut buffer = [0u8; 8];
            early_server.recv_from(&mut buffer).expect("early recv");
            client
        })
        .collect();

    let cache = Arc::new(Mutex::new(FlowOwnerCache::default()));
    let (tx, _rx) = std::sync::mpsc::sync_channel(1_024);
    let sink = EventSink::new(tx, Arc::new(std::sync::atomic::AtomicU64::new(0)));
    let listener = start(cache, sink).expect("start flow listener");
    let pid = std::process::id();
    let rounds = 200;
    let owners = |lookups: &[OwnerLookup]| {
        let mut counts = BTreeMap::new();
        for (_, waited, _) in lookups {
            *counts.entry(format!("{waited:?}")).or_insert(0) += 1;
        }
        counts
    };

    let report = |label: &str, lookups: &[OwnerLookup]| {
        let immediate = lookups
            .iter()
            .filter(|(now, _, _)| *now == EndpointOwner::Resolved(pid))
            .count();
        let resolved = lookups
            .iter()
            .filter(|(_, waited, _)| *waited == EndpointOwner::Resolved(pid))
            .count();
        let slowest = lookups
            .iter()
            .map(|(_, _, took)| *took)
            .max()
            .unwrap_or_default();
        eprintln!(
            "{label}: {resolved}/{} resolved to this process, {immediate} without waiting, slowest wait {slowest:?}",
            lookups.len()
        );
        resolved
    };

    let udp = fresh_udp_lookups(Ipv4Addr::LOCALHOST.into(), rounds);
    let udp_over_ipv6 = fresh_udp_lookups(Ipv6Addr::LOCALHOST.into(), rounds);
    let early: Vec<_> = early_clients
        .iter()
        .map(|client| udp_lookup(client, &early_server))
        .collect();

    let tcp_server = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("tcp server");
    let tcp_addr = tcp_server.local_addr().expect("tcp server addr");
    let mut tcp = Vec::new();
    for _ in 0..rounds {
        let mut client = TcpStream::connect(tcp_addr).expect("connect");
        let (mut accepted, from) = tcp_server.accept().expect("accept");
        client.write_all(b"q").expect("write");
        let mut byte = [0u8; 1];
        accepted.read_exact(&mut byte).expect("read");
        let received_at = Instant::now();
        tcp.push(lookup_pair(from, Protocol::Tcp, received_at));
    }
    drop(listener);

    let udp_resolved = report("loopback udp", &udp);
    let tcp_resolved = report("loopback tcp", &tcp);
    let ipv6_resolved = report("loopback udp ::1", &udp_over_ipv6);
    eprintln!("loopback udp ::1 owners: {:?}", owners(&udp_over_ipv6));
    eprintln!(
        "udp ::1 sockets that sent before the listener started: {:?} (this pid {pid})",
        owners(&early)
    );
    assert_eq!(
        ipv6_resolved, rounds,
        "IPv6 loopback UDP flows must be recorded"
    );
    assert!(
        early
            .iter()
            .all(|(_, waited, _)| *waited != EndpointOwner::Resolved(4)),
        "a socket the listener never saw open must not be recorded as System"
    );
    assert_eq!(udp_resolved, rounds, "loopback UDP flows must be recorded");
    assert_eq!(tcp_resolved, rounds, "loopback TCP flows must be recorded");
}

#[test]
#[ignore = "downloads WinDivert from reqrypt.org and opens a kernel driver; requires elevation"]
fn official_package_records_this_process_on_connect() {
    let cache = Arc::new(Mutex::new(FlowOwnerCache::default()));
    let (tx, _rx) = std::sync::mpsc::sync_channel(8);
    let sink = EventSink::new(tx, Arc::new(std::sync::atomic::AtomicU64::new(0)));
    let listener = start(Arc::clone(&cache), sink).expect("start flow listener");
    // A local connection proves the driver path without depending on an
    // external resolver's reachability or silently ignoring connect failures.
    let server =
        std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).expect("bind server");
    let socket = std::net::TcpStream::connect(server.local_addr().expect("server address"))
        .expect("connect");
    let (_accepted, client_address) = server.accept().expect("accept");
    let received_at = Instant::now();
    drop(socket);
    let historical = endpoint_owner::endpoint_owner_at(
        Protocol::Tcp,
        LocalEndpoint {
            address: client_address.ip(),
            port: client_address.port(),
        },
        received_at,
        Duration::from_secs(2),
    );
    let pid = std::process::id();
    let found = (0..50).any(|_| {
        std::thread::sleep(std::time::Duration::from_millis(20));
        let mut cache = lock_cache(&cache);
        cache.contains_pid(pid, Instant::now())
    });
    drop(listener);
    assert!(found, "WinDivert FLOW did not record pid {pid}");
    assert_eq!(historical, endpoint_owner::EndpointOwner::Resolved(pid));
}
