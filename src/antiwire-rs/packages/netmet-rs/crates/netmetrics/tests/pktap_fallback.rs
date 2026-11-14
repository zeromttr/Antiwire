//! The macOS collector when PKTAP cannot start: it says why, falls back to the socket table,
//! and still lists connections.
//!
//! `NETMETRICS_PKTAP_INTERFACE` must name an interface that does not exist and that no
//! interface cloner can create, so `ifconfig <name> create` (`ifconfig(8)`) fails and nothing
//! on the host changes: XNU's `if_clone_create` (`bsd/net/if.c`) returns `EINVAL` when no
//! cloner's name matches. `scripts/ci-elevated-unix.sh` sets one.

#![cfg(target_os = "macos")]

use netmetrics::{Collector, CookieSource, DegradeReason, FlowEvent, Protocol, endpoint_owner};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

const WAIT: Duration = Duration::from_secs(8);

/// Whether `ifconfig(8)` knows `interface`.
fn interface_exists(interface: &str) -> bool {
    Command::new("/sbin/ifconfig")
        .arg(interface)
        .output()
        .expect("run ifconfig")
        .status
        .success()
}

/// Destroys the interface, should the collector have created it after all, even when an
/// assertion fails.
struct DestroyIfCreated<'a>(&'a str);

impl Drop for DestroyIfCreated<'_> {
    fn drop(&mut self) {
        if interface_exists(self.0) {
            let _ = Command::new("/sbin/ifconfig")
                .args([self.0, "destroy"])
                .output();
        }
    }
}

#[test]
#[ignore = "runs /sbin/ifconfig; needs NETMETRICS_PKTAP_INTERFACE naming an interface no cloner can create"]
fn a_capture_that_cannot_start_falls_back_and_still_lists_connections() {
    let interface = std::env::var("NETMETRICS_PKTAP_INTERFACE")
        .expect("NETMETRICS_PKTAP_INTERFACE must name an interface that cannot be created");
    assert!(
        !interface_exists(&interface),
        "{interface} exists, so capture could start and this test would prove nothing"
    );
    let _cleanup = DestroyIfCreated(&interface);

    let events = Arc::new(Mutex::new(Vec::new()));
    let reported = Arc::clone(&events);
    let mut collector = Collector::builder()
        .session_name(format!("netmetrics-fallback-test-{}", std::process::id()))
        .ignore_loopback(false)
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

    let listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).expect("listen");
    let client = TcpStream::connect(listener.local_addr().expect("server")).expect("connect");
    let (_accepted, _) = listener.accept().expect("accept");
    let client_port = client.local_addr().expect("client address").port();
    let pid = std::process::id();
    let deadline = Instant::now() + WAIT;
    let listed = loop {
        let listed = events.lock().expect("events").iter().any(|event| {
            matches!(event, FlowEvent::Opened(key, meta)
                if key.protocol == Protocol::Tcp
                    && key.local_port == client_port
                    && meta.pid == pid
                    && meta.cookie.is_some_and(|cookie| cookie.source == CookieSource::Synthetic))
        });
        if listed || Instant::now() >= deadline {
            break listed;
        }
        thread::sleep(Duration::from_millis(25));
    };
    let owners_available = endpoint_owner::available();
    let restarts = collector.stats().backend_restarts;
    collector.stop().expect("stop");

    let events = events.lock().expect("events");
    let degradations: Vec<_> = events
        .iter()
        .filter_map(|event| match event {
            FlowEvent::Degraded { reason } => Some(reason),
            _ => None,
        })
        .collect();
    assert!(
        degradations.iter().any(|reason| matches!(
            reason,
            DegradeReason::SourceUnavailable { source, .. }
                | DegradeReason::PermissionDenied { source }
                if source.starts_with("pktap")
        )),
        "why capture could not start was not reported: {degradations:#?}"
    );
    assert!(
        degradations.iter().any(|reason| matches!(
            reason,
            DegradeReason::SnapshotOnly { source } if source == "macos-socket-table"
        )),
        "the fallback was not reported: {degradations:#?}"
    );
    assert!(
        listed,
        "the fallback did not list this process's connection: {events:#?}"
    );
    assert!(
        !owners_available,
        "endpoint owners must be unavailable while the collector polls the socket table"
    );
    assert_eq!(
        restarts, 0,
        "the backend must fall back, not fail and be restarted"
    );
    assert!(
        !events
            .iter()
            .any(|event| matches!(event, FlowEvent::Restored { .. })),
        "capture never started, so nothing was restored: {events:#?}"
    );
}
