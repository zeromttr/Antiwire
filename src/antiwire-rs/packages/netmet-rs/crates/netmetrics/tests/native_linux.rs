//! Privileged Linux eBPF integration coverage.

#![cfg(target_os = "linux")]

use netmetrics::{
    ByteDelta, Collector, CollectorBuilder, DegradeReason, FlowEvent, FlowKey, LocalEndpoint,
    Protocol, endpoint_owner,
};
use socket2::SockRef;
use std::collections::BTreeSet;
use std::fs;
use std::io::{Read, Write};
use std::mem::MaybeUninit;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

const PAYLOAD_LEN: usize = 64 * 1024;
const WAIT: Duration = Duration::from_secs(8);

fn wait_until(timeout: Duration, mut predicate: impl FnMut() -> bool) {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if predicate() {
            return;
        }
        thread::sleep(Duration::from_millis(25));
    }
}

/// Starts `builder`'s collector with short intervals, so a test sees its own traffic
/// quickly, and returns it with every event it reports but the interface samples, which no
/// test here reads and which would bury the rest of a failure's event list.
fn start(builder: CollectorBuilder) -> (Collector, Arc<Mutex<Vec<FlowEvent>>>) {
    let events = Arc::new(Mutex::new(Vec::new()));
    let captured = Arc::clone(&events);
    let mut collector = builder
        .session_name(format!("netmetrics-linux-test-{}", std::process::id()))
        .coalesce_interval_ms(25)
        .poll_interval_ms(100)
        .build()
        .expect("collector");
    collector
        .start(Box::new(move |event| {
            if !matches!(event, FlowEvent::Interface(_)) {
                captured.lock().expect("events").push(event);
            }
        }))
        .expect("start");
    (collector, events)
}

/// Fails when the collector fell back to procfs or lost a required eBPF source, which
/// would make a test's conclusions about the eBPF path meaningless.
fn assert_ebpf_was_used(events: &[FlowEvent]) {
    assert!(
        !events.iter().any(|event| {
            matches!(
                event,
                FlowEvent::Degraded {
                    reason: DegradeReason::SnapshotOnly { source }
                } if source == "procfs"
            )
        }),
        "collector silently used procfs fallback: {events:#?}"
    );
    assert!(
        !events.iter().any(|event| {
            matches!(
                event,
                FlowEvent::Degraded {
                    reason: DegradeReason::SourceUnavailable { source, .. }
                } if source == "linux-ebpf" || source == "linux-dns-hints"
            )
        }),
        "required eBPF source was unavailable: {events:#?}"
    );
}

/// Loads the accounting and DNS socket-filter objects, then proves that a
/// successful TCP send reaches the public event stream without procfs fallback.
#[test]
#[ignore = "requires Linux BTF plus BPF/PERFMON (or SYS_ADMIN) and NET_RAW capabilities"]
fn elevated_ebpf_observes_successful_tcp_send() {
    let accounting_object = std::env::var_os("NETMETRICS_BPF_OBJECT")
        .expect("NETMETRICS_BPF_OBJECT must name the compiled accounting object");
    let dns_filter_object = std::env::var_os("NETMETRICS_DNS_FILTER_OBJECT")
        .expect("NETMETRICS_DNS_FILTER_OBJECT must name the compiled DNS filter object");
    assert!(std::path::Path::new(&accounting_object).is_file());
    assert!(std::path::Path::new(&dns_filter_object).is_file());

    let (mut collector, events) =
        start(Collector::builder().ignore_loopback(false).dns_hints(true));
    thread::sleep(Duration::from_millis(750));

    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("listener");
    let server_address = listener.local_addr().expect("server address");
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept");
        std::io::copy(&mut stream, &mut std::io::sink()).expect("copy");
    });
    let mut client = TcpStream::connect(server_address).expect("connect");
    let client_address = client.local_addr().expect("client address");
    client
        .write_all(&vec![7_u8; PAYLOAD_LEN])
        .expect("write payload");
    drop(client);
    server.join().expect("server");

    wait_until(WAIT, || {
        events
            .lock()
            .expect("events")
            .iter()
            .filter_map(|event| match event {
                FlowEvent::Bytes(key, delta)
                    if key.protocol == Protocol::Tcp
                        && key.local_port == client_address.port()
                        && key.remote_port == server_address.port() =>
                {
                    Some(delta.sent)
                }
                _ => None,
            })
            .fold(0_u64, u64::saturating_add)
            >= PAYLOAD_LEN as u64
    });

    collector.stop().expect("stop");
    let events = events.lock().expect("events");
    assert_ebpf_was_used(&events);
    let sent = events
        .iter()
        .filter_map(|event| match event {
            FlowEvent::Bytes(key, delta)
                if key.protocol == Protocol::Tcp
                    && key.local_port == client_address.port()
                    && key.remote_port == server_address.port() =>
            {
                Some(delta.sent)
            }
            _ => None,
        })
        .fold(0_u64, u64::saturating_add);
    assert!(
        sent >= PAYLOAD_LEN as u64,
        "expected at least {PAYLOAD_LEN} successful send bytes, observed {sent}: {events:#?}"
    );
}

/// Starts `builder`'s collector and waits for its eBPF source, which is ready once it
/// publishes endpoint ownership.
fn start_ebpf(builder: CollectorBuilder) -> (Collector, Arc<Mutex<Vec<FlowEvent>>>) {
    let (collector, events) = start(builder);
    wait_until(WAIT, endpoint_owner::available);
    assert!(
        endpoint_owner::available(),
        "the eBPF source did not start: {:#?}",
        events.lock().expect("events")
    );
    (collector, events)
}

/// Makes one IPv4 connection between dual-stack sockets: an `AF_INET6` socket connects to
/// `::ffff:127.0.0.1`, a listener on `[::]` accepts it, the client sends [`PAYLOAD_LEN`]
/// bytes and the server reads them all. Linux keeps both sockets' addresses in the
/// IPv4-mapped form (`ipv6(7)`). Returns the connection as the client sees it, under the
/// plain IPv4 addresses the collector must report.
fn dual_stack_exchange() -> FlowKey {
    let mapped_loopback = Ipv4Addr::LOCALHOST.to_ipv6_mapped();
    let listener = TcpListener::bind((Ipv6Addr::UNSPECIFIED, 0)).expect("listen on [::]");
    let port = listener.local_addr().expect("listener address").port();
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept");
        std::io::copy(&mut stream, &mut std::io::sink()).expect("read payload")
    });
    let mut client = TcpStream::connect((mapped_loopback, port)).expect("connect");
    let client_address = client.local_addr().expect("client address");
    assert_eq!(
        client_address.ip(),
        IpAddr::V6(mapped_loopback),
        "the client is a dual-stack socket"
    );
    client
        .write_all(&vec![7_u8; PAYLOAD_LEN])
        .expect("write payload");
    drop(client);
    assert_eq!(
        server.join().expect("server"),
        PAYLOAD_LEN as u64,
        "the server read the payload"
    );
    FlowKey {
        protocol: Protocol::Tcp,
        local_addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
        local_port: client_address.port(),
        remote_addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
        remote_port: port,
    }
}

/// The flow keys `events` report for `connection`'s ports, either way round and in any
/// address form.
fn reported_keys(events: &[FlowEvent], connection: FlowKey) -> BTreeSet<FlowKey> {
    let ports = [connection.local_port, connection.remote_port];
    events
        .iter()
        .filter_map(|event| match event {
            FlowEvent::Opened(key, _) | FlowEvent::Bytes(key, _) | FlowEvent::Closed(key, _) => {
                Some(*key)
            }
            _ => None,
        })
        .filter(|key| {
            key.protocol == connection.protocol
                && ports.contains(&key.local_port)
                && ports.contains(&key.remote_port)
        })
        .collect()
}

fn bytes_reported(events: &[FlowEvent], wanted: FlowKey) -> ByteDelta {
    events
        .iter()
        .filter_map(|event| match event {
            FlowEvent::Bytes(key, delta) if *key == wanted => Some(*delta),
            _ => None,
        })
        .fold(ByteDelta::default(), |mut total, delta| {
            total.saturating_add_assign(delta);
            total
        })
}

/// Waits until the eBPF source has read every record of `connection`, which it has once
/// the endpoint history names the client's owner for a moment after the exchange.
fn assert_owner_recorded(connection: FlowKey) {
    let client = LocalEndpoint {
        address: connection.local_addr,
        port: connection.local_port,
    };
    assert_eq!(
        endpoint_owner::owner_at(Protocol::Tcp, client, Instant::now(), WAIT),
        endpoint_owner::EndpointOwner::Resolved(std::process::id()),
        "the endpoint history does not name this process for {client:?}"
    );
}

/// A connection between dual-stack sockets is reported once per end, under plain
/// `127.0.0.1` addresses, with its owner and its bytes, although Linux holds both
/// sockets' addresses IPv4-mapped.
#[test]
#[ignore = "requires Linux BTF plus BPF/PERFMON (or SYS_ADMIN) capabilities"]
fn elevated_a_dual_stack_connection_is_one_ipv4_flow_per_end() {
    let (mut collector, events) = start_ebpf(Collector::builder().ignore_loopback(false));
    let connection = dual_stack_exchange();
    let accepted = connection.reverse();
    assert_owner_recorded(connection);
    wait_until(WAIT, || {
        let events = events.lock().expect("events");
        bytes_reported(&events, connection).sent >= PAYLOAD_LEN as u64
            && bytes_reported(&events, accepted).received >= PAYLOAD_LEN as u64
    });
    collector.stop().expect("stop");

    let events = events.lock().expect("events");
    assert_ebpf_was_used(&events);
    assert_eq!(
        reported_keys(&events, connection),
        BTreeSet::from([connection, accepted]),
        "each end must be one flow under 127.0.0.1: {events:#?}"
    );
    let pid = std::process::id();
    for end in [connection, accepted] {
        assert!(
            events
                .iter()
                .any(|event| matches!(event, FlowEvent::Opened(key, meta) if *key == end && meta.pid == pid)),
            "{end:?} was not attributed to this process: {events:#?}"
        );
    }
    assert_eq!(
        bytes_reported(&events, connection).sent,
        PAYLOAD_LEN as u64,
        "the client's bytes, counted once: {events:#?}"
    );
    assert_eq!(
        bytes_reported(&events, accepted).received,
        PAYLOAD_LEN as u64,
        "the server's bytes, counted once: {events:#?}"
    );
}

/// With loopback filtering on, as the daemon runs it, a connection between dual-stack
/// sockets on loopback is not reported at all.
#[test]
#[ignore = "requires Linux BTF plus BPF/PERFMON (or SYS_ADMIN) capabilities"]
fn elevated_dual_stack_loopback_is_filtered_by_default() {
    let (mut collector, events) = start_ebpf(Collector::builder());
    let connection = dual_stack_exchange();
    // The eBPF source has emitted every record of the exchange by now; give the
    // collector several of its publication intervals to report any of them.
    assert_owner_recorded(connection);
    thread::sleep(Duration::from_millis(500));
    collector.stop().expect("stop");

    let events = events.lock().expect("events");
    assert_ebpf_was_used(&events);
    assert_eq!(
        reported_keys(&events, connection),
        BTreeSet::new(),
        "loopback on dual-stack sockets was reported: {events:#?}"
    );
}

/// What each of the reads below takes: small enough to arrive in one piece on loopback.
const READ_LEN: usize = 8 * 1024;

/// Makes one loopback connection on which the client sends [`READ_LEN`] bytes in two
/// halves, a pause apart, and the server takes them with `read`. Returns the connection
/// as the server sees it, the end that receives.
fn connection_read_with(read: impl FnOnce(TcpStream) + Send + 'static) -> FlowKey {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("listener");
    let server_address = listener.local_addr().expect("server address");
    let server = thread::spawn(move || {
        let (stream, _) = listener.accept().expect("accept");
        read(stream);
    });
    let mut client = TcpStream::connect(server_address).expect("connect");
    let client_address = client.local_addr().expect("client address");
    let half = vec![7_u8; READ_LEN / 2];
    client.write_all(&half).expect("first half");
    thread::sleep(Duration::from_millis(300));
    client.write_all(&half).expect("second half");
    server.join().expect("server");
    FlowKey {
        protocol: Protocol::Tcp,
        local_addr: server_address.ip(),
        local_port: server_address.port(),
        remote_addr: client_address.ip(),
        remote_port: client_address.port(),
    }
}

/// The bytes `events` report as received on `receiver`'s connection, under its key or the
/// other end's.
///
/// On loopback both ends are local. A TCP connection is opened at each end, so each has a
/// flow. A UDP receiver that never sent has no flow of its own when its first bytes
/// arrive, and the flow table then counts them on the flow the sender opened, as that
/// flow's received bytes (`FlowTable::resolve_existing_key`). In these tests the sending
/// end receives nothing, so the sum is what the receiver read.
fn received_on(events: &[FlowEvent], receiver: FlowKey) -> u64 {
    bytes_reported(events, receiver)
        .received
        .saturating_add(bytes_reported(events, receiver.reverse()).received)
}

/// Stops `collector` once it has reported [`READ_LEN`] bytes received on `receiver`'s
/// connection, and asserts it reported exactly that many. A read counted twice reports
/// more.
fn assert_received_once(
    mut collector: Collector,
    events: &Mutex<Vec<FlowEvent>>,
    receiver: FlowKey,
) {
    wait_until(WAIT, || {
        received_on(&events.lock().expect("events"), receiver) >= READ_LEN as u64
    });
    collector.stop().expect("stop");
    let events = events.lock().expect("events");
    assert_ebpf_was_used(&events);
    assert_eq!(
        received_on(&events, receiver),
        READ_LEN as u64,
        "the bytes {receiver:?} received, counted once: {events:#?}"
    );
}

/// `recv(2)`: `MSG_PEEK` returns data without taking it off the queue, so the next read
/// returns the same data. `tcp_recvmsg_locked()` reports what a peek copied to
/// `tcp_cleanup_rbuf()` like any read, and the bytes must still be counted once.
#[test]
#[ignore = "requires Linux BTF plus BPF/PERFMON (or SYS_ADMIN) capabilities"]
fn elevated_tcp_bytes_peeked_and_then_read_are_counted_once() {
    let (collector, events) = start_ebpf(Collector::builder().ignore_loopback(false));
    let receiver = connection_read_with(|mut stream| {
        let mut buffer = vec![0_u8; READ_LEN];
        while stream.peek(&mut buffer).expect("peek") < READ_LEN {
            thread::sleep(Duration::from_millis(10));
        }
        stream.read_exact(&mut buffer).expect("read");
    });
    assert_received_once(collector, &events, receiver);
}

/// `recv(2)`: `MSG_WAITALL` blocks until the whole request is satisfied. The kernel calls
/// `tcp_cleanup_rbuf()` with the running total before it waits for the second half, and
/// with the whole total at the end, and the bytes must still be counted once.
#[test]
#[ignore = "requires Linux BTF plus BPF/PERFMON (or SYS_ADMIN) capabilities"]
fn elevated_a_tcp_read_that_waits_for_all_its_bytes_is_counted_once() {
    let (collector, events) = start_ebpf(Collector::builder().ignore_loopback(false));
    let receiver = connection_read_with(|stream| {
        let mut buffer = [MaybeUninit::<u8>::uninit(); READ_LEN];
        let read = SockRef::from(&stream)
            .recv_with_flags(&mut buffer, libc::MSG_WAITALL)
            .expect("recv");
        assert_eq!(read, READ_LEN, "one read took both halves");
    });
    assert_received_once(collector, &events, receiver);
}

/// A datagram peeked with `MSG_PEEK` stays queued (`recv(2)`), and the read that takes it
/// is the one that counts.
#[test]
#[ignore = "requires Linux BTF plus BPF/PERFMON (or SYS_ADMIN) capabilities"]
fn elevated_a_udp_datagram_peeked_and_then_read_is_counted_once() {
    let (collector, events) = start_ebpf(Collector::builder().ignore_loopback(false));
    let receiver = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("receiver");
    let sender = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("sender");
    let receiver_address = receiver.local_addr().expect("receiver address");
    let sender_address = sender.local_addr().expect("sender address");
    sender
        .send_to(&[7_u8; READ_LEN], receiver_address)
        .expect("send");
    let mut buffer = vec![0_u8; READ_LEN];
    assert_eq!(
        receiver.peek_from(&mut buffer).expect("peek"),
        (READ_LEN, sender_address)
    );
    assert_eq!(
        receiver.recv_from(&mut buffer).expect("read"),
        (READ_LEN, sender_address)
    );
    assert_received_once(
        collector,
        &events,
        FlowKey {
            protocol: Protocol::Udp,
            local_addr: receiver_address.ip(),
            local_port: receiver_address.port(),
            remote_addr: sender_address.ip(),
            remote_port: sender_address.port(),
        },
    );
}

/// Sends one datagram of [`READ_LEN`] bytes from `sender` to the unconnected `receiver`,
/// which reads it with `recv(2)`. That read asks for no address, so the kernel copies none
/// to the reader, and only the datagram's own headers name its sender. Returns the
/// receiver's end of the exchange, keyed as the collector keys it: an IPv4-mapped address
/// as the IPv4 address it maps.
fn datagram_read_without_asking_its_sender(receiver: &UdpSocket, sender: &UdpSocket) -> FlowKey {
    let receiver_address = receiver.local_addr().expect("receiver address");
    let sender_address = sender.local_addr().expect("sender address");
    let destination = SocketAddr::new(
        receiver_address.ip().to_canonical(),
        receiver_address.port(),
    );
    sender
        .send_to(&[7_u8; READ_LEN], destination)
        .expect("send");
    let mut buffer = vec![0_u8; READ_LEN];
    assert_eq!(receiver.recv(&mut buffer).expect("read"), READ_LEN);
    FlowKey {
        protocol: Protocol::Udp,
        local_addr: receiver_address.ip().to_canonical(),
        local_port: receiver_address.port(),
        remote_addr: sender_address.ip().to_canonical(),
        remote_port: sender_address.port(),
    }
}

#[test]
#[ignore = "requires Linux BTF plus BPF/PERFMON (or SYS_ADMIN) capabilities"]
fn elevated_a_datagram_read_without_asking_its_sender_is_counted_under_the_sender() {
    let (collector, events) = start_ebpf(Collector::builder().ignore_loopback(false));
    let receiver = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("receiver");
    let sender = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("sender");
    let receiving_end = datagram_read_without_asking_its_sender(&receiver, &sender);
    assert_received_once(collector, &events, receiving_end);
}

/// An IPv6 socket receives IPv4 under an IPv4-mapped address (`ipv6(7)`), from a sender it
/// names the same way.
#[test]
#[ignore = "requires Linux BTF plus BPF/PERFMON (or SYS_ADMIN) capabilities"]
fn elevated_a_datagram_an_ipv6_socket_receives_over_ipv4_is_counted_under_the_sender() {
    let (collector, events) = start_ebpf(Collector::builder().ignore_loopback(false));
    let receiver =
        UdpSocket::bind((Ipv4Addr::LOCALHOST.to_ipv6_mapped(), 0)).expect("receiver on IPv6");
    let sender = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("sender on IPv4");
    let receiving_end = datagram_read_without_asking_its_sender(&receiver, &sender);
    assert_received_once(collector, &events, receiving_end);
}

#[test]
#[ignore = "requires Linux BTF plus BPF/PERFMON (or SYS_ADMIN) capabilities"]
fn elevated_a_datagram_received_over_ipv6_is_counted_under_the_sender() {
    let (collector, events) = start_ebpf(Collector::builder().ignore_loopback(false));
    let receiver = UdpSocket::bind((Ipv6Addr::LOCALHOST, 0)).expect("receiver");
    let sender = UdpSocket::bind((Ipv6Addr::LOCALHOST, 0)).expect("sender");
    let receiving_end = datagram_read_without_asking_its_sender(&receiver, &sender);
    assert_received_once(collector, &events, receiving_end);
}

/// The `st` column of the `/proc/net/tcp` row for `127.0.0.1:local_port` to
/// `127.0.0.1:remote_port`, or `None` when there is no such row.
///
/// The kernel prints an address as the network-order word it stores read as a native
/// integer, and a port in host order (`get_tcp4_sock` and `get_timewait4_sock` in
/// `net/ipv4/tcp_ipv4.c`).
fn loopback_tcp_state(local_port: u16, remote_port: u16) -> Option<String> {
    let loopback = u32::from_ne_bytes(Ipv4Addr::LOCALHOST.octets());
    let local = format!("{loopback:08X}:{local_port:04X}");
    let remote = format!("{loopback:08X}:{remote_port:04X}");
    std::fs::read_to_string("/proc/net/tcp")
        .expect("read /proc/net/tcp")
        .lines()
        .skip(1)
        .find_map(|line| {
            let fields: Vec<_> = line.split_ascii_whitespace().collect();
            match fields.as_slice() {
                [_, row_local, row_remote, state, ..]
                    if *row_local == local && *row_remote == remote =>
                {
                    Some((*state).to_owned())
                }
                _ => None,
            }
        })
}

/// `TIME_WAIT` in the `st` column (`include/net/tcp_states.h`).
const TIME_WAIT: &str = "06";

/// Makes a TCP connection on loopback and closes it, the client first, so the kernel
/// keeps the client's end as a time-wait socket for a minute. Returns the connection as
/// the client saw it, once `/proc/net/tcp` lists that time-wait row.
fn finished_connection() -> FlowKey {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("listener");
    let port = listener.local_addr().expect("listener address").port();
    let client = TcpStream::connect((Ipv4Addr::LOCALHOST, port)).expect("connect");
    let client_port = client.local_addr().expect("client address").port();
    let (mut accepted, _) = listener.accept().expect("accept");
    drop(client);
    accepted
        .read_to_end(&mut Vec::new())
        .expect("read up to the client's FIN");
    drop(accepted);
    wait_until(WAIT, || {
        loopback_tcp_state(client_port, port).as_deref() == Some(TIME_WAIT)
    });
    assert_eq!(
        loopback_tcp_state(client_port, port).as_deref(),
        Some(TIME_WAIT),
        "the closed connection left no time-wait row for 127.0.0.1:{client_port}"
    );
    FlowKey {
        protocol: Protocol::Tcp,
        local_addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
        local_port: client_port,
        remote_addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
        remote_port: port,
    }
}

/// The owners `events` report opening `wanted` with, one per open.
fn opened_by(events: &[FlowEvent], wanted: FlowKey) -> Vec<u32> {
    events
        .iter()
        .filter_map(|event| match event {
            FlowEvent::Opened(key, meta) if *key == wanted => Some(meta.pid),
            _ => None,
        })
        .collect()
}

/// A connection that finished before the collector started still has a time-wait row in
/// `/proc/net/tcp`, but no socket left to close, so the start must not open it. A
/// connection still open then is opened once per end, owned by this process.
#[test]
#[ignore = "requires Linux BTF plus BPF/PERFMON (or SYS_ADMIN) capabilities"]
fn elevated_a_connection_finished_before_start_is_not_opened() {
    let finished = finished_connection();
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("listener");
    let port = listener.local_addr().expect("listener address").port();
    let client = TcpStream::connect((Ipv4Addr::LOCALHOST, port)).expect("connect");
    let (accepted, _) = listener.accept().expect("accept");
    let open = FlowKey {
        protocol: Protocol::Tcp,
        local_addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
        local_port: client.local_addr().expect("client address").port(),
        remote_addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
        remote_port: port,
    };

    let (mut collector, events) = start_ebpf(Collector::builder().ignore_loopback(false));
    wait_until(WAIT, || {
        let events = events.lock().expect("events");
        !opened_by(&events, open).is_empty() && !opened_by(&events, open.reverse()).is_empty()
    });
    // The time-wait row was listed before the start and still is, so the start's read of
    // the table, which opened both ends, saw it.
    assert_eq!(
        loopback_tcp_state(finished.local_port, finished.remote_port).as_deref(),
        Some(TIME_WAIT),
        "the time-wait row expired before the collector started"
    );
    // The start reads the table once; give the collector several of its publication
    // intervals to report anything else from that read.
    thread::sleep(Duration::from_millis(500));
    collector.stop().expect("stop");
    drop((client, accepted));

    let events = events.lock().expect("events");
    assert_ebpf_was_used(&events);
    let pid = std::process::id();
    for end in [open, open.reverse()] {
        assert_eq!(
            opened_by(&events, end),
            vec![pid],
            "{end:?} must be opened once, owned by this process: {events:#?}"
        );
    }
    assert_eq!(
        reported_keys(&events, finished),
        BTreeSet::new(),
        "the finished connection was reported: {events:#?}"
    );
}

/// Names the compiled object [`elevated_ebpf_that_cannot_start_falls_back_and_takes_over`]
/// installs at the path `NETMETRICS_BPF_OBJECT` names, once it has seen the fallback.
const OBJECT_TO_INSTALL: &str = "NETMETRICS_BPF_OBJECT_TO_INSTALL";
/// How long the collector polls procfs before it tries eBPF again
/// (`netmetrics_sys::NATIVE_RETRY_INTERVAL`), and room for the start itself.
const RETRY_WAIT: Duration = Duration::from_secs(60 + 30);

/// Removes the object the test installed, even when an assertion fails.
struct RemoveInstalled<'a>(&'a Path);

impl Drop for RemoveInstalled<'_> {
    fn drop(&mut self) {
        let _ = fs::remove_file(self.0);
    }
}

/// When each `Opened` event for `key` says the flow opened, in order.
fn open_times(events: &[FlowEvent], key: FlowKey) -> Vec<u64> {
    events
        .iter()
        .filter_map(|event| match event {
            FlowEvent::Opened(opened, meta) if *opened == key => Some(meta.open_ts),
            _ => None,
        })
        .collect()
}

/// Where in `events` each `Closed` event for `key` is.
fn close_positions(events: &[FlowEvent], key: FlowKey) -> Vec<usize> {
    events
        .iter()
        .enumerate()
        .filter_map(|(position, event)| {
            matches!(event, FlowEvent::Closed(closed, _) if *closed == key).then_some(position)
        })
        .collect()
}

/// A connection is reported closed, once at each end, when it closes. The kernel chose
/// both local ports here, and it gives such a port back before it reports `TCP_CLOSE`
/// (`tcp_set_state` in `net/ipv4/tcp.c`), so a close record that named the port the socket
/// holds by then, which is none, would end no flow.
#[test]
#[ignore = "requires Linux BTF plus BPF/PERFMON (or SYS_ADMIN) capabilities"]
fn elevated_a_closed_connection_is_reported_closed_at_each_end() {
    let (mut collector, events) = start_ebpf(Collector::builder().ignore_loopback(false));
    let connection = dual_stack_exchange();
    let accepted = connection.reverse();
    let closes = |key| close_positions(&events.lock().expect("events"), key).len();
    wait_until(WAIT, || closes(connection) > 0 && closes(accepted) > 0);
    // Counted before the collector stops, so that stopping cannot be what closed them.
    let (connecting_end, accepted_end) = (closes(connection), closes(accepted));
    collector.stop().expect("stop");

    let events = events.lock().expect("events");
    assert_ebpf_was_used(&events);
    assert_eq!(
        connecting_end, 1,
        "the connecting end was not reported closed once: {events:#?}"
    );
    assert_eq!(
        accepted_end, 1,
        "the accepted end was not reported closed once: {events:#?}"
    );
}

/// Fails unless `events` say why eBPF could not start and that procfs stands in for it, and
/// nothing yet says eBPF is back, nor publishes endpoint owners.
fn assert_procfs_fallback(events: &[FlowEvent]) {
    assert!(
        events.iter().any(|event| matches!(
            event,
            FlowEvent::Degraded {
                reason: DegradeReason::SourceUnavailable { source, .. }
            } if source == "linux-ebpf"
        )),
        "why eBPF could not start was not reported: {events:#?}"
    );
    assert!(
        events.iter().any(|event| matches!(
            event,
            FlowEvent::Degraded {
                reason: DegradeReason::SnapshotOnly { source }
            } if source == "procfs"
        )),
        "the fallback was not reported: {events:#?}"
    );
    assert!(
        !events
            .iter()
            .any(|event| matches!(event, FlowEvent::Restored { .. })),
        "eBPF has not started, so nothing was restored: {events:#?}"
    );
    assert!(
        !endpoint_owner::available(),
        "endpoint owners must be unavailable while the collector polls procfs"
    );
}

/// eBPF cannot start while its object is not installed. The collector says why, falls back
/// to procfs and still lists a connection. Once the object is there it starts eBPF at its next
/// retry, says so, publishes endpoint owners and reports a new connection with its bytes. The
/// connection the fallback listed is opened once, and closed once, when it closes.
///
/// `NETMETRICS_BPF_OBJECT` must name a path with nothing there yet, which keeps every other
/// eBPF test in this file from running, so `scripts/ci-elevated-unix.sh` runs this one on its
/// own.
#[test]
#[ignore = "requires Linux BTF plus BPF/PERFMON (or SYS_ADMIN), an object to install and a path to install it at; waits about a minute"]
fn elevated_ebpf_that_cannot_start_falls_back_and_takes_over() {
    let object = PathBuf::from(
        std::env::var_os("NETMETRICS_BPF_OBJECT")
            .expect("NETMETRICS_BPF_OBJECT must name the path the test installs the object at"),
    );
    let compiled = PathBuf::from(
        std::env::var_os(OBJECT_TO_INSTALL)
            .unwrap_or_else(|| panic!("{OBJECT_TO_INSTALL} must name the compiled object")),
    );
    assert!(compiled.is_file(), "{compiled:?} is not a file");
    assert!(
        !object.exists(),
        "{object:?} exists, so eBPF could start and this test would prove nothing"
    );
    let _remove = RemoveInstalled(&object);

    let (mut collector, events) = start(Collector::builder().ignore_loopback(false));
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("listener");
    let server_port = listener.local_addr().expect("server address").port();
    let client = TcpStream::connect((Ipv4Addr::LOCALHOST, server_port)).expect("connect");
    let (accepted, _) = listener.accept().expect("accept");
    let listed = FlowKey {
        protocol: Protocol::Tcp,
        local_addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
        local_port: client.local_addr().expect("client address").port(),
        remote_addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
        remote_port: server_port,
    };
    let pid = std::process::id();
    let listed_by_procfs = |events: &[FlowEvent]| {
        events.iter().any(|event| {
            matches!(event, FlowEvent::Opened(key, meta) if *key == listed && meta.pid == pid)
        })
    };
    wait_until(WAIT, || listed_by_procfs(&events.lock().expect("events")));
    {
        let events = events.lock().expect("events");
        assert!(
            listed_by_procfs(&events),
            "the fallback did not list this process's connection: {events:#?}"
        );
        assert_procfs_fallback(&events);
    }

    fs::copy(&compiled, &object).expect("install the object");
    let restored = |events: &[FlowEvent]| {
        events
            .iter()
            .any(|event| matches!(event, FlowEvent::Restored { source } if source == "procfs"))
    };
    wait_until(RETRY_WAIT, || {
        restored(&events.lock().expect("events")) && endpoint_owner::available()
    });
    assert!(
        restored(&events.lock().expect("events")),
        "eBPF did not start within {RETRY_WAIT:?} of the object being installed"
    );
    assert!(
        endpoint_owner::available(),
        "endpoint owners must be available once eBPF runs"
    );

    let connection = dual_stack_exchange();
    assert_owner_recorded(connection);
    wait_until(WAIT, || {
        bytes_reported(&events.lock().expect("events"), connection).sent >= PAYLOAD_LEN as u64
    });

    let closed_from = events.lock().expect("events").len();
    drop(client);
    drop(accepted);
    wait_until(WAIT, || {
        !close_positions(&events.lock().expect("events"), listed).is_empty()
    });
    let restarts = collector.stats().backend_restarts;
    collector.stop().expect("stop");

    let events = events.lock().expect("events");
    assert_eq!(
        bytes_reported(&events, connection).sent,
        PAYLOAD_LEN as u64,
        "eBPF reports a new connection's bytes: {events:#?}"
    );
    let opened_at = open_times(&events, listed);
    assert!(
        opened_at.windows(2).all(|pair| pair[0] == pair[1]),
        "the connection the fallback listed was opened again: {opened_at:?}"
    );
    let closed_at = close_positions(&events, listed);
    assert_eq!(
        closed_at.len(),
        1,
        "the connection the fallback listed is closed once: {events:#?}"
    );
    assert!(
        closed_at.iter().all(|position| *position >= closed_from),
        "the connection the fallback listed was closed while it was open: {events:#?}"
    );
    assert_eq!(
        restarts, 0,
        "the backend must fall back and recover, not fail and be restarted"
    );
}
