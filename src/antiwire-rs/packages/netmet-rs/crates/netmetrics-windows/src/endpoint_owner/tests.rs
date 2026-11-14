use super::*;
use netmetrics_core::Protocol;
use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, Instant};

fn ms(base: Instant, offset: u64) -> Instant {
    base + Duration::from_millis(offset)
}

pub(crate) static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// The regression this guards: Dnscache's `[::1]` client ports were named
/// `System`, so every stub answer it fetched was recorded for PID 4.
#[test]
fn a_reinjected_loopback_flow_hides_the_owner_instead_of_naming_system() {
    let base = Instant::now();
    let feed = EndpointOwnerFeed::new(crate::endpoint_owner::trusted_owner);
    let loopback6 = LocalEndpoint {
        address: IpAddr::V6(std::net::Ipv6Addr::LOCALHOST),
        port: 62_483,
    };
    let adapter = LocalEndpoint {
        address: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
        port: 445,
    };
    feed.received(ms(base, 10), Some((Protocol::Udp, loopback6, 3032)), base);
    feed.received(
        ms(base, 20),
        Some((Protocol::Udp, loopback6, SYSTEM_PID)),
        base,
    );
    feed.received(
        ms(base, 20),
        Some((Protocol::Tcp, adapter, SYSTEM_PID)),
        base,
    );
    feed.received(ms(base, 40), None, base);
    let lookup = |protocol, endpoint, at| feed.owner_at(protocol, endpoint, at, at);
    assert_eq!(
        lookup(Protocol::Udp, loopback6, ms(base, 15)),
        EndpointOwner::Resolved(3032)
    );
    assert_eq!(
        lookup(Protocol::Udp, loopback6, ms(base, 30)),
        EndpointOwner::Untrusted,
        "the socket table must answer for the reused port"
    );
    assert_eq!(
        lookup(Protocol::Tcp, adapter, ms(base, 30)),
        EndpointOwner::Resolved(SYSTEM_PID),
        "System really owns kernel sockets off loopback"
    );
}
