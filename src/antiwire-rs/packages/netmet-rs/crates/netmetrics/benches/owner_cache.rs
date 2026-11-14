//! Cost of a [`SocketOwnerCache`] lookup the newest snapshot answers, alone and
//! with eight threads at once, and of the scans behind it.
//!
//! Run with `cargo bench -p netmetrics --bench owner_cache`.

use std::hint::black_box;
use std::net::{IpAddr, Ipv4Addr};
use std::thread;
use std::time::{Duration, Instant};

use netmetrics::owner_cache::Wait;
use netmetrics::{LocalEndpoint, Protocol, SocketOwnerCache, SocketOwnerSnapshot};

const LOOKUPS: u32 = 1_000_000;
const THREADS: u32 = 8;

fn main() {
    // A host-sized table: thousands of UDP binds and established TCP rows.
    let snapshot = || {
        let mut owners = SocketOwnerSnapshot::default();
        for port in 10_000..14_000 {
            owners.insert_udp(endpoint(port), u32::from(port));
        }
        for port in 20_000..22_000 {
            owners.insert_tcp(
                netmetrics::FlowKey {
                    protocol: Protocol::Tcp,
                    local_addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
                    local_port: port,
                    remote_addr: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
                    remote_port: 443,
                },
                u32::from(port),
            );
        }
        owners
    };
    let cache = SocketOwnerCache::with_scanner(Duration::from_secs(3_600), |_| snapshot());
    let observed = Instant::now();
    // Prime both protocols' snapshots, taken after `observed`.
    for protocol in [Protocol::Udp, Protocol::Tcp] {
        cache
            .owner(protocol, endpoint(10_000), observed, Wait::Never)
            .expect("first lookup scans");
    }
    for (label, protocol, base) in [
        ("udp", Protocol::Udp, 10_000),
        ("tcp", Protocol::Tcp, 20_000),
    ] {
        let lookup = |i: u32| {
            let port = u16::try_from(base + i % 2_000).expect("port");
            black_box(cache.owner(protocol, endpoint(port), observed, Wait::Never)).expect("hit");
        };
        let started = Instant::now();
        for i in 0..LOOKUPS {
            lookup(i);
        }
        report(
            &format!("hit {label} threads=1"),
            started.elapsed(),
            LOOKUPS,
        );
        let started = Instant::now();
        thread::scope(|scope| {
            for _ in 0..THREADS {
                scope.spawn(|| (0..LOOKUPS).for_each(lookup));
            }
        });
        report(
            &format!("hit {label} threads={THREADS}"),
            started.elapsed(),
            LOOKUPS * THREADS,
        );
    }

    let live = SocketOwnerCache::new(Duration::ZERO);
    for (label, protocol) in [("udp", Protocol::Udp), ("tcp", Protocol::Tcp)] {
        const SCANS: u32 = 25;
        live.snapshot_since(protocol, Instant::now(), Wait::Never)
            .expect("warm-up scan");
        let started = Instant::now();
        for _ in 0..SCANS {
            black_box(live.snapshot_since(protocol, Instant::now(), Wait::Never)).expect("scan");
        }
        report(&format!("live scan {label}"), started.elapsed(), SCANS);
    }
}

fn endpoint(port: u16) -> LocalEndpoint {
    LocalEndpoint {
        address: IpAddr::V4(Ipv4Addr::LOCALHOST),
        port,
    }
}

fn report(label: &str, elapsed: Duration, operations: u32) {
    println!(
        "owner_cache {label}: {:.1} ns/op",
        elapsed.as_secs_f64() * 1e9 / f64::from(operations)
    );
}
