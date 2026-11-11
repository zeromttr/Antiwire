//! All backends feed the same history and the same public lookup API.

use netmetrics::{
    LocalEndpoint, Protocol,
    endpoint_owner::{self, EndpointOwner},
};
use netmetrics_core::FlowKey;
use netmetrics_sys::endpoint_owner::EndpointOwnerSource;
use std::time::{Duration, Instant};

#[test]
fn native_history_survives_socket_closure_and_port_reuse_through_the_public_api() {
    assert!(!endpoint_owner::available());
    let source = EndpointOwnerSource::default();
    assert!(endpoint_owner::available());
    let key = FlowKey {
        protocol: Protocol::Udp,
        local_addr: "127.0.0.1".parse().unwrap(),
        local_port: 50_000,
        remote_addr: "127.0.0.1".parse().unwrap(),
        remote_port: 53,
    };
    let now = Instant::now();
    let old = now.checked_sub(Duration::from_millis(30)).unwrap();
    let query = now.checked_sub(Duration::from_millis(20)).unwrap();
    let reused = now.checked_sub(Duration::from_millis(10)).unwrap();
    // Delivery is delayed; event time, not processing time, selects the owner.
    source.record(key, 111, old);
    source.record(key, 222, reused);
    source.drained();
    let endpoint = LocalEndpoint {
        address: key.local_addr,
        port: key.local_port,
    };
    assert_eq!(
        endpoint_owner::owner_at(Protocol::Udp, endpoint, query, Duration::from_secs(1)),
        EndpointOwner::Resolved(111)
    );
    assert_eq!(
        endpoint_owner::owner_at(Protocol::Udp, endpoint, now, Duration::from_secs(1)),
        EndpointOwner::Resolved(222)
    );
    drop(source);
    assert!(!endpoint_owner::available());
    assert_eq!(
        endpoint_owner::owner_at(Protocol::Udp, endpoint, query, Duration::ZERO),
        EndpointOwner::Unavailable
    );
}

/// Both Unix backends must retain the sender after a short-lived socket closes.
#[cfg(unix)]
#[test]
#[ignore = "requires root with working eBPF on Linux or NETMETRICS_PKTAP_INTERFACE on macOS"]
fn elevated_native_source_retains_a_closed_udp_sender() {
    use netmetrics::Collector;
    use std::net::UdpSocket;
    let mut collector = Collector::builder()
        .ignore_loopback(false)
        .dns_hints(false)
        .build()
        .unwrap();
    collector
        .start(Box::new(|_: netmetrics::FlowEvent| {}))
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    while !endpoint_owner::available() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(
        endpoint_owner::available(),
        "native ownership source did not start"
    );
    let server = UdpSocket::bind("127.0.0.1:0").unwrap();
    server
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let client = UdpSocket::bind("127.0.0.1:0").unwrap();
    client
        .send_to(b"query", server.local_addr().unwrap())
        .unwrap();
    let (_, sender) = server.recv_from(&mut [0; 32]).unwrap();
    let received_at = Instant::now();
    drop(client);
    let owner = endpoint_owner::owner_at(
        Protocol::Udp,
        LocalEndpoint {
            address: sender.ip(),
            port: sender.port(),
        },
        received_at,
        Duration::from_secs(2),
    );
    collector.stop().unwrap();
    assert_eq!(owner, EndpointOwner::Resolved(std::process::id()));
}
