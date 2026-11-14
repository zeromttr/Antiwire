//! Privileged coverage both Unix backends must pass: eBPF on Linux and PKTAP on macOS.
//!
//! Each test starts the real collector as root and checks what it reports about traffic
//! the test itself makes on loopback.

#![cfg(any(target_os = "linux", target_os = "macos"))]

use netmetrics::{
    Collector, CookieSource, DegradeReason, FlowEvent, FlowKey, Protocol, endpoint_owner,
};
use netmetrics_core::test_support::{dns_message, dns_over_tcp};
use std::io::{Read, Write};
use std::net::{Ipv4Addr, Shutdown, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

/// Where a flow's cookie comes from when the kernel supplies it.
#[cfg(target_os = "linux")]
const KERNEL_COOKIE: CookieSource = CookieSource::LinuxSockCookie;
#[cfg(target_os = "macos")]
const KERNEL_COOKIE: CookieSource = CookieSource::MacosFlowId;

/// Names the address a child of this test binary sends one datagram to.
const DATAGRAM_TARGET: &str = "NETMETRICS_TEST_DATAGRAM_TARGET";
const WAIT: Duration = Duration::from_secs(8);
const IO_TIMEOUT: Duration = Duration::from_secs(5);

/// A running collector and every event it has reported, interface counters aside.
struct Session {
    collector: Collector,
    events: Arc<Mutex<Vec<FlowEvent>>>,
}

impl Session {
    /// Starts the collector and waits for its native source, which is ready once it
    /// publishes endpoint ownership.
    fn start(dns_hints: bool) -> Self {
        let events = Arc::new(Mutex::new(Vec::new()));
        let reported = Arc::clone(&events);
        let mut collector = Collector::builder()
            .session_name(format!("netmetrics-unix-test-{}", std::process::id()))
            .ignore_loopback(false)
            .dns_hints(dns_hints)
            .coalesce_interval_ms(25)
            .poll_interval_ms(100)
            .build()
            .expect("collector");
        collector
            .start(Box::new(move |event: FlowEvent| {
                if !matches!(event, FlowEvent::Interface(_)) {
                    reported.lock().expect("events").push(event);
                }
            }))
            .expect("start");
        let session = Self { collector, events };
        let deadline = Instant::now() + IO_TIMEOUT;
        while !endpoint_owner::available() && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(10));
        }
        assert!(
            endpoint_owner::available(),
            "the native source did not start: {:#?}",
            session.degradations()
        );
        session
    }

    /// Polls the events reported so far until `find` returns something.
    fn wait_for<T>(&self, find: impl Fn(&[FlowEvent]) -> Option<T>) -> Option<T> {
        let deadline = Instant::now() + WAIT;
        loop {
            if let Some(found) = find(&self.events.lock().expect("events")) {
                return Some(found);
            }
            if Instant::now() >= deadline {
                return None;
            }
            thread::sleep(Duration::from_millis(25));
        }
    }

    fn degradations(&self) -> Vec<DegradeReason> {
        self.events
            .lock()
            .expect("events")
            .iter()
            .filter_map(|event| match event {
                FlowEvent::Degraded { reason } => Some(reason.clone()),
                _ => None,
            })
            .collect()
    }

    /// Everything reported that is not a byte count, for a failed assertion to show.
    fn account(&self) -> Vec<FlowEvent> {
        self.events
            .lock()
            .expect("events")
            .iter()
            .filter(|event| !matches!(event, FlowEvent::Bytes(..)))
            .cloned()
            .collect()
    }

    /// Fails when a source the test depends on reported that it could not start.
    fn assert_available(&self, source_part: &str) {
        let missing: Vec<_> = self
            .degradations()
            .into_iter()
            .filter(|reason| {
                matches!(
                    reason,
                    DegradeReason::SourceUnavailable { source, .. }
                        | DegradeReason::PermissionDenied { source }
                        if source.contains(source_part)
                )
            })
            .collect();
        assert!(
            missing.is_empty(),
            "{source_part} is unavailable: {missing:#?}"
        );
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        let _ = self.collector.stop();
    }
}

fn loopback(port: u16) -> SocketAddr {
    SocketAddr::from((Ipv4Addr::LOCALHOST, port))
}

/// The collector names who owns a TCP connection, and which socket it is, when the
/// connection is made. Neither end ever sends a byte of data.
#[test]
#[ignore = "requires root with working eBPF on Linux or NETMETRICS_PKTAP_INTERFACE on macOS"]
fn elevated_a_connection_is_owned_and_identified_before_it_carries_data() {
    let session = Session::start(false);
    let listener = TcpListener::bind(loopback(0)).expect("listen");
    let server = listener.local_addr().expect("server address");
    let client = TcpStream::connect(server).expect("connect");
    let (_accepted, _) = listener.accept().expect("accept");
    let client = client.local_addr().expect("client address");
    let pid = std::process::id();

    // The flow as either end sees it: `(local port, remote port)`.
    let owned = |local: u16, remote: u16, cookie: Option<CookieSource>| {
        session.wait_for(|events| {
            events.iter().find_map(|event| match event {
                FlowEvent::Opened(key, meta)
                    if key.protocol == Protocol::Tcp
                        && key.local_port == local
                        && key.remote_port == remote
                        && meta.pid == pid
                        && cookie.is_none_or(|source| {
                            meta.cookie.is_some_and(|cookie| cookie.source == source)
                        }) =>
                {
                    Some(())
                }
                _ => None,
            })
        })
    };
    assert!(
        owned(client.port(), server.port(), Some(KERNEL_COOKIE)).is_some(),
        "the connecting end was not attributed to this process with a kernel cookie: {:#?}",
        session.account()
    );
    assert!(
        owned(server.port(), client.port(), None).is_some(),
        "the accepting end was not attributed to this process: {:#?}",
        session.account()
    );
    session.assert_available("cookie");
    session.assert_available("owner");
}

/// The TCP flow whose local end is `local` and whose remote end is `remote`.
fn tcp_flow(local: SocketAddr, remote: SocketAddr) -> FlowKey {
    FlowKey {
        protocol: Protocol::Tcp,
        local_addr: local.ip(),
        local_port: local.port(),
        remote_addr: remote.ip(),
        remote_port: remote.port(),
    }
}

/// Where in `events` the flow `key` was reported finishing.
fn finishing_positions(events: &[FlowEvent], key: FlowKey) -> Vec<usize> {
    events
        .iter()
        .enumerate()
        .filter(|(_, event)| matches!(event, FlowEvent::Finishing(finishing) if *finishing == key))
        .map(|(position, _)| position)
        .collect()
}

/// Where in `events` the flow `key` was reported closed.
fn closed_positions(events: &[FlowEvent], key: FlowKey) -> Vec<usize> {
    events
        .iter()
        .enumerate()
        .filter(|(_, event)| matches!(event, FlowEvent::Closed(closed, _) if *closed == key))
        .map(|(position, _)| position)
        .collect()
}

/// A connection whose application shut down its sending side is no longer established:
/// that end is reported finishing, once, and stays one flow. What it still receives is
/// counted on that flow, which is closed once, when its socket closes. The other end has
/// only received a FIN and can still send, so it is not finishing until it closes too.
#[test]
#[ignore = "requires root with working eBPF on Linux or NETMETRICS_PKTAP_INTERFACE on macOS"]
fn elevated_a_half_closed_connection_is_finishing_and_keeps_its_bytes() {
    const REPLY_LEN: usize = 64 * 1024;
    let session = Session::start(false);
    let listener = TcpListener::bind(loopback(0)).expect("listen");
    let server = listener.local_addr().expect("server address");
    let mut client = TcpStream::connect(server).expect("connect");
    let (mut accepted, _) = listener.accept().expect("accept");
    for stream in [&client, &accepted] {
        stream
            .set_read_timeout(Some(IO_TIMEOUT))
            .expect("read timeout");
    }
    let client_address = client.local_addr().expect("client address");
    let client_end = tcp_flow(client_address, server);
    let accepted_end = tcp_flow(server, client_address);

    client.write_all(b"request").expect("send the request");
    client.shutdown(Shutdown::Write).expect("shut down sending");
    let mut request = Vec::new();
    accepted
        .read_to_end(&mut request)
        .expect("the request and its end");
    assert!(
        session
            .wait_for(|events| (!finishing_positions(events, client_end).is_empty()).then_some(()))
            .is_some(),
        "the end that shut down sending was not reported finishing: {:#?}",
        session.account()
    );

    accepted
        .write_all(&vec![0x5a; REPLY_LEN])
        .expect("send the reply");
    client
        .read_exact(&mut vec![0; REPLY_LEN])
        .expect("the reply");
    assert!(
        finishing_positions(&session.events.lock().expect("events"), accepted_end).is_empty(),
        "the end that can still send was reported finishing: {:#?}",
        session.account()
    );

    drop(client);
    drop(accepted);
    assert!(
        session
            .wait_for(|events| (!closed_positions(events, client_end).is_empty()).then_some(()))
            .is_some(),
        "the connection was not reported closed: {:#?}",
        session.account()
    );

    let events = session.events.lock().expect("events").clone();
    let finishing = finishing_positions(&events, client_end);
    let closed = closed_positions(&events, client_end);
    assert_eq!(
        (finishing.len(), closed.len()),
        (1, 1),
        "one flow finishes once and closes once: {:#?}",
        session.account()
    );
    assert!(finishing[0] < closed[0], "{:#?}", session.account());
    let received_while_finishing: u64 = events[finishing[0]..closed[0]]
        .iter()
        .filter_map(|event| match event {
            FlowEvent::Bytes(key, delta) if *key == client_end => Some(delta.received),
            _ => None,
        })
        .sum();
    assert!(
        received_while_finishing >= REPLY_LEN as u64,
        "the finishing flow was credited {received_while_finishing} of the {REPLY_LEN} bytes it received: {:#?}",
        session.account()
    );
}

/// Every byte of a transfer is counted at both ends, also when it travels in segments far
/// larger than an Ethernet frame, as it does on loopback. macOS capture once lost every
/// packet longer than its 4096-byte buffer.
///
/// The transfer is small enough for the kernel's capture buffers on macOS to hold both
/// copies of it, one as sent and one as received, even if the collector reads nothing
/// until it is over. A longer burst can outrun the reader, which loses packets and is
/// reported as a buffer overflow; that is not what this test is about.
#[test]
#[ignore = "requires root with working eBPF on Linux or NETMETRICS_PKTAP_INTERFACE on macOS"]
fn elevated_a_transfer_in_large_segments_is_counted_in_full() {
    const TRANSFER_LEN: usize = 256 * 1024;
    let session = Session::start(false);
    let listener = TcpListener::bind(loopback(0)).expect("listen");
    let server = listener.local_addr().expect("server address");
    let mut client = TcpStream::connect(server).expect("connect");
    let (mut accepted, _) = listener.accept().expect("accept");
    client
        .set_read_timeout(Some(IO_TIMEOUT))
        .expect("read timeout");
    let client_address = client.local_addr().expect("client address");
    let sending_end = tcp_flow(server, client_address);
    let receiving_end = tcp_flow(client_address, server);

    let sender = thread::spawn(move || {
        accepted
            .write_all(&vec![0x5a; TRANSFER_LEN])
            .expect("send the transfer");
    });
    client
        .read_exact(&mut vec![0; TRANSFER_LEN])
        .expect("the transfer");
    sender.join().expect("sender");
    drop(client);

    let counted = |events: &[FlowEvent]| {
        let mut sent = 0_u64;
        let mut received = 0_u64;
        for event in events {
            match event {
                FlowEvent::Bytes(key, delta) if *key == sending_end => sent += delta.sent,
                FlowEvent::Bytes(key, delta) if *key == receiving_end => {
                    received += delta.received;
                }
                _ => {}
            }
        }
        (sent, received)
    };
    let wanted = TRANSFER_LEN as u64;
    let in_full = session.wait_for(|events| {
        let (sent, received) = counted(events);
        (sent >= wanted && received >= wanted).then_some(())
    });
    let (sent, received) = counted(&session.events.lock().expect("events"));
    assert!(
        in_full.is_some(),
        "of {wanted} bytes, {sent} were counted as sent and {received} as received: {:#?}",
        session.degradations()
    );
}

/// A connection attempt that is refused never becomes a connection, so it is never a flow:
/// nothing is opened for it and no bytes are reported for it.
#[test]
#[ignore = "requires root with working eBPF on Linux or NETMETRICS_PKTAP_INTERFACE on macOS"]
fn elevated_a_refused_connection_is_never_a_flow() {
    let session = Session::start(false);
    // A port nothing listens on: one the kernel just gave out and took back.
    let refusing = TcpListener::bind(loopback(0))
        .expect("listen")
        .local_addr()
        .expect("address");
    assert!(
        TcpStream::connect(refusing).is_err(),
        "nothing listens on {refusing}, yet it accepted a connection"
    );

    // A connection made afterwards shows the collector has got past the attempt.
    let listener = TcpListener::bind(loopback(0)).expect("listen");
    let server = listener.local_addr().expect("server address");
    let client = TcpStream::connect(server).expect("connect");
    let (_accepted, _) = listener.accept().expect("accept");
    let made = tcp_flow(client.local_addr().expect("client address"), server);
    assert!(
        session
            .wait_for(|events| {
                events
                    .iter()
                    .any(|event| matches!(event, FlowEvent::Opened(key, _) if *key == made))
                    .then_some(())
            })
            .is_some(),
        "the connection made after the attempt was not reported: {:#?}",
        session.account()
    );
    // Long enough for bytes held back for coalescing to be reported.
    thread::sleep(Duration::from_millis(500));

    let events = session.events.lock().expect("events");
    let names_attempt = |key: &FlowKey| {
        key.protocol == Protocol::Tcp
            && (key.local_port == refusing.port() || key.remote_port == refusing.port())
    };
    let reported: Vec<_> = events
        .iter()
        .filter(|event| match event {
            FlowEvent::Opened(key, _)
            | FlowEvent::Closed(key, _)
            | FlowEvent::Bytes(key, _)
            | FlowEvent::Finishing(key) => names_attempt(key),
            _ => false,
        })
        .collect();
    assert!(
        reported.is_empty(),
        "the refused attempt was reported as a flow: {reported:#?}"
    );
}

/// Runs only as the child `elevated_a_process_that_exits_at_once_is_reported_and_stopped`
/// starts: sends one datagram and exits. Otherwise it does nothing.
#[test]
#[ignore = "a helper the short-lived process test runs in a child process"]
fn child_sends_one_datagram_and_exits() {
    let Ok(target) = std::env::var(DATAGRAM_TARGET) else {
        return;
    };
    let socket = UdpSocket::bind(loopback(0)).expect("bind");
    socket
        .send_to(b"datagram", target.parse::<SocketAddr>().expect("target"))
        .expect("send");
}

/// A process that sends one datagram and exits is reported with its name, and its exit is
/// reported when it happens, not when a later poll finds it gone.
#[test]
#[ignore = "requires root with working eBPF on Linux or NETMETRICS_PKTAP_INTERFACE on macOS"]
fn elevated_a_process_that_exits_at_once_is_reported_and_stopped() {
    let session = Session::start(false);
    let receiver = UdpSocket::bind(loopback(0)).expect("bind");
    receiver
        .set_read_timeout(Some(IO_TIMEOUT))
        .expect("read timeout");
    let executable = std::env::current_exe().expect("test executable");
    let mut child = Command::new(&executable)
        .args(["--ignored", "--exact", "child_sends_one_datagram_and_exits"])
        .env(
            DATAGRAM_TARGET,
            receiver.local_addr().expect("receiver address").to_string(),
        )
        .spawn()
        .expect("spawn child");
    let child_pid = child.id();
    receiver
        .recv_from(&mut [0; 32])
        .expect("the child's datagram");
    assert!(child.wait().expect("child exit").success());

    let file_name = executable
        .file_name()
        .expect("executable name")
        .to_string_lossy()
        .into_owned();
    let started = session.wait_for(|events| {
        events.iter().find_map(|event| match event {
            FlowEvent::ProcessStarted(process) if process.pid == child_pid => {
                Some(process.identity.clone())
            }
            _ => None,
        })
    });
    let identity = started.unwrap_or_else(|| {
        panic!(
            "process {child_pid} was not reported: {:#?}",
            session.account()
        )
    });
    // The kernel keeps only the start of a long name.
    assert!(
        !identity.name.is_empty() && file_name.starts_with(&identity.name),
        "process {child_pid} was reported as {identity:?}, not as {file_name}"
    );
    let stopped = session.wait_for(|events| {
        events
            .iter()
            .any(
                |event| matches!(event, FlowEvent::ProcessStopped { pid, .. } if *pid == child_pid),
            )
            .then_some(())
    });
    assert!(
        stopped.is_some(),
        "the exit of process {child_pid} was not reported: {:#?}",
        session.account()
    );
    session.assert_available("process-exit");
}

/// Waits for the lookup of `name` to be reported as refused, asked for by this process.
fn refused_lookup_was_reported(session: &Session, name: &str) -> bool {
    let pid = Some(std::process::id());
    session
        .wait_for(|events| {
            events
                .iter()
                .any(|event| {
                    matches!(
                        event,
                        FlowEvent::DnsQuery(query)
                            if query.name == name
                                && query.status == 3
                                && query.caller.requesting_pid == pid
                    )
                })
                .then_some(())
        })
        .is_some()
}

/// A lookup the resolver refuses is reported with its response code and the process that
/// asked, over UDP and over TCP.
#[test]
#[ignore = "requires root with working eBPF on Linux or NETMETRICS_PKTAP_INTERFACE on macOS; binds 127.0.0.1:53"]
fn elevated_a_refused_lookup_is_reported_with_who_asked() {
    const NXDOMAIN: u8 = 3;
    let session = Session::start(true);
    session.assert_available("dns");

    let over_udp = "missing-udp.netmetrics.test";
    let resolver = UdpSocket::bind(loopback(53)).expect("bind UDP port 53");
    let client = UdpSocket::bind(loopback(0)).expect("bind client");
    for socket in [&resolver, &client] {
        socket
            .set_read_timeout(Some(IO_TIMEOUT))
            .expect("read timeout");
    }
    client
        .send_to(&dns_message(7, over_udp, None, 0), loopback(53))
        .expect("send query");
    let (_, asker) = resolver.recv_from(&mut [0; 512]).expect("the query");
    resolver
        .send_to(&dns_message(7, over_udp, Some(NXDOMAIN), 0), asker)
        .expect("send refusal");
    client.recv_from(&mut [0; 512]).expect("the refusal");
    assert!(
        refused_lookup_was_reported(&session, over_udp),
        "the refused UDP lookup was not reported for this process: {:#?}",
        session.account()
    );

    let over_tcp = "missing-tcp.netmetrics.test";
    let query = dns_over_tcp(&dns_message(9, over_tcp, None, 0));
    let refusal = dns_over_tcp(&dns_message(9, over_tcp, Some(NXDOMAIN), 0));
    let listener = TcpListener::bind(loopback(53)).expect("bind TCP port 53");
    let mut client = TcpStream::connect(loopback(53)).expect("connect");
    let (mut resolver, _) = listener.accept().expect("accept");
    for stream in [&client, &resolver] {
        stream
            .set_read_timeout(Some(IO_TIMEOUT))
            .expect("read timeout");
    }
    client.write_all(&query).expect("send query");
    resolver
        .read_exact(&mut vec![0; query.len()])
        .expect("the query");
    resolver.write_all(&refusal).expect("send refusal");
    client
        .read_exact(&mut vec![0; refusal.len()])
        .expect("the refusal");
    assert!(
        refused_lookup_was_reported(&session, over_tcp),
        "the refused TCP lookup was not reported for this process: {:#?}",
        session.account()
    );
}
