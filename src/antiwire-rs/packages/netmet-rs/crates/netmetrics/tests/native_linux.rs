//! Privileged Linux eBPF integration coverage.

#![cfg(target_os = "linux")]

use netmetrics::{Collector, DegradeReason, FlowEvent, Protocol};
use std::io::Write;
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

const PAYLOAD_LEN: usize = 64 * 1024;

fn wait_until(timeout: Duration, mut predicate: impl FnMut() -> bool) {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if predicate() {
            return;
        }
        thread::sleep(Duration::from_millis(25));
    }
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

    let events = Arc::new(Mutex::new(Vec::new()));
    let captured = Arc::clone(&events);
    let mut collector = Collector::builder()
        .session_name(format!("netmetrics-linux-test-{}", std::process::id()))
        .ignore_loopback(false)
        .dns_hints(true)
        .coalesce_interval_ms(25)
        .poll_interval_ms(100)
        .build()
        .expect("collector");
    collector
        .start(Box::new(move |event| {
            captured.lock().expect("events").push(event);
        }))
        .expect("start");
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

    wait_until(Duration::from_secs(8), || {
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
