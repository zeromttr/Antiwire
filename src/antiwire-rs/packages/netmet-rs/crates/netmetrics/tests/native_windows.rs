#![allow(missing_docs, unsafe_code)]
#![cfg(windows)]

//! Elevated Windows ETW integration coverage.

use netmetrics::{Collector, DegradeReason, FlowEvent, FlowKey, Protocol};
use std::io::Write;
use std::net::{IpAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

const PAYLOAD_LEN: usize = 64 * 1024;

#[link(name = "shell32")]
unsafe extern "system" {
    fn IsUserAnAdmin() -> i32;
}

fn assert_elevated() {
    assert_ne!(
        // SAFETY: `IsUserAnAdmin` takes no arguments and returns a Boolean value.
        unsafe { IsUserAnAdmin() },
        0,
        "run this ignored test from an elevated Windows shell"
    );
}

fn start_collector(label: &str, dns_hints: bool) -> (Collector, Arc<Mutex<Vec<FlowEvent>>>) {
    let events = Arc::new(Mutex::new(Vec::new()));
    let captured = Arc::clone(&events);
    let mut collector = Collector::builder()
        .session_name(format!("{label}-{}", std::process::id()))
        .ignore_loopback(false)
        .dns_hints(dns_hints)
        .coalesce_interval_ms(25)
        .poll_interval_ms(100)
        .build()
        .expect("collector");
    collector
        .start(Box::new(move |event| {
            captured.lock().expect("events").push(event);
        }))
        .expect("start");
    // Collector startup is asynchronous; allow both ETW sessions to begin
    // processing before producing the events under test.
    thread::sleep(Duration::from_millis(750));
    (collector, events)
}

fn assert_native_etw(events: &[FlowEvent]) {
    assert!(
        !events.iter().any(|event| {
            matches!(
                event,
                FlowEvent::Degraded {
                    reason: DegradeReason::PermissionDenied { .. }
                }
            )
        }),
        "ETW reported PermissionDenied: {events:#?}"
    );
    assert!(
        !events.iter().any(|event| {
            matches!(
                event,
                FlowEvent::Degraded {
                    reason: DegradeReason::SnapshotOnly { source }
                } if source == "windows-ip-helper"
            )
        }),
        "collector silently used the IP Helper fallback: {events:#?}"
    );
}

fn wait_until(timeout: Duration, mut predicate: impl FnMut() -> bool) {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if predicate() {
            return;
        }
        thread::sleep(Duration::from_millis(25));
    }
}

/// Proves that elevated kernel ETW reports a precise TCP tuple, PID, byte
/// deltas, and process lifecycle instead of falling back to IP Helper.
#[test]
#[ignore = "requires Windows sudo or another elevated Windows runner"]
fn elevated_etw_observes_tcp_bytes_pid_and_process_lifecycle() {
    assert_elevated();
    let (mut collector, events) = start_collector("netmetrics-kernel-test", false);

    let mut child = Command::new("cmd.exe")
        .args(["/D", "/C", "ping -n 2 127.0.0.1 >NUL"])
        .spawn()
        .expect("spawn child process");
    let child_pid = child.id();

    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("listener");
    let server_address = listener.local_addr().expect("server address");
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept");
        std::io::copy(&mut stream, &mut std::io::sink()).expect("copy");
    });
    let mut client = TcpStream::connect(server_address).expect("connect");
    let client_address = client.local_addr().expect("client address");
    let expected = FlowKey {
        protocol: Protocol::Tcp,
        local_addr: client_address.ip(),
        local_port: client_address.port(),
        remote_addr: server_address.ip(),
        remote_port: server_address.port(),
    };
    client
        .write_all(&vec![7_u8; PAYLOAD_LEN])
        .expect("write payload");
    drop(client);
    server.join().expect("server");
    assert!(child.wait().expect("wait for child").success());

    wait_until(Duration::from_secs(8), || {
        let events = events.lock().expect("events");
        let sent = events
            .iter()
            .filter_map(|event| match event {
                FlowEvent::Bytes(key, delta) if *key == expected => Some(delta.sent),
                _ => None,
            })
            .fold(0_u64, u64::saturating_add);
        let process_started = events
            .iter()
            .any(|event| matches!(event, FlowEvent::ProcessStarted(info) if info.pid == child_pid));
        let process_stopped = events.iter().any(
            |event| matches!(event, FlowEvent::ProcessStopped { pid, .. } if *pid == child_pid),
        );
        sent >= PAYLOAD_LEN as u64 && process_started && process_stopped
    });

    collector.stop().expect("stop");
    let events = events.lock().expect("events");
    assert_native_etw(&events);
    assert!(
        events.iter().any(
            |event| matches!(event, FlowEvent::Opened(key, meta) if *key == expected && meta.pid == std::process::id())
        ),
        "missing attributed TCP open for {expected:?}: {events:#?}"
    );
    let sent = events
        .iter()
        .filter_map(|event| match event {
            FlowEvent::Bytes(key, delta) if *key == expected => Some(delta.sent),
            _ => None,
        })
        .fold(0_u64, u64::saturating_add);
    assert!(
        sent >= PAYLOAD_LEN as u64,
        "expected at least {PAYLOAD_LEN} sent bytes for {expected:?}, observed {sent}"
    );
    assert!(
        events
            .iter()
            .any(|event| matches!(event, FlowEvent::ProcessStarted(info) if info.pid == child_pid)),
        "missing ProcessStarted for child PID {child_pid}"
    );
    // The start identity remains usable after the child has exited.
    let identity = events
        .iter()
        .find_map(|event| match event {
            FlowEvent::ProcessStarted(info) if info.pid == child_pid => Some(&info.identity),
            _ => None,
        })
        .expect("child start identity");
    assert!(
        identity.executable.contains(['\\', '/']),
        "expected full image path: {identity:?}"
    );
    assert!(std::path::Path::new(&identity.executable).exists());
    assert!(
        events.iter().any(
            |event| matches!(event, FlowEvent::ProcessStopped { pid, .. } if *pid == child_pid)
        ),
        "missing ProcessStopped for child PID {child_pid}"
    );
}

/// Proves that the optional DNS-Client ETW session publishes a successful
/// address-bearing lookup while running elevated.
#[test]
#[ignore = "requires Windows sudo, DNS access, and an elevated Windows runner"]
fn elevated_dns_etw_emits_resolved_answers() {
    assert_elevated();
    let (mut collector, events) = start_collector("netmetrics-dns-test", true);
    let caller_pid = std::process::id();
    let queries = ["example.com", "iana.org", "one.one.one.one"];
    let mut resolved = false;
    for query in queries {
        if (query, 443).to_socket_addrs().is_ok() {
            resolved = true;
        }
    }
    assert!(resolved, "none of the DNS test names resolved");

    wait_until(Duration::from_secs(8), || {
        events.lock().expect("events").iter().any(|event| {
            matches!(
                event,
                FlowEvent::DnsResolvedWithMetadata { query, answers, .. }
                    if queries.contains(&query.as_str()) && !answers.is_empty()
            )
        })
    });
    collector.stop().expect("stop");

    let events = events.lock().expect("events");
    assert_native_etw(&events);
    assert!(
        events.iter().any(|event| {
            matches!(
                event,
                FlowEvent::DnsResolvedWithMetadata { query, answers, .. }
                    if queries.contains(&query.as_str())
                        && answers.iter().any(|answer| answer.parse::<IpAddr>().is_ok())
            )
        }),
        "DNS-Client ETW did not publish an address-bearing result: {events:#?}"
    );
    assert!(
        events.iter().any(|event| {
            matches!(
                event,
                FlowEvent::DnsQuery(query)
                    if query.event_id == Some(3008)
                        && query.event_version == Some(0)
                        && query.name == queries[0]
                        && query.caller.logging_pid == Some(caller_pid)
                        && query.caller.requesting_pid == Some(caller_pid)
                        && query.caller.resolver_pid.is_none()
            )
        }),
        "event 3008 v0 did not retain the known caller/header identity: {events:#?}"
    );
}
