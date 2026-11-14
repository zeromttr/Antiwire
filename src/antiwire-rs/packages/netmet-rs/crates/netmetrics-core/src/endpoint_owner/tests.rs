use super::*;
use std::net::Ipv4Addr;

fn endpoint(port: u16) -> LocalEndpoint {
    LocalEndpoint {
        address: IpAddr::V4(Ipv4Addr::LOCALHOST),
        port,
    }
}

fn key(port: u16) -> EndpointKey {
    EndpointKey::new(Protocol::Udp, endpoint(port))
}

fn ms(base: Instant, offset: u64) -> Instant {
    base + Duration::from_millis(offset)
}

/// The regression this guards: a port reused by another process made the
/// socket-table snapshot name the new owner for the old owner's query.
#[test]
fn a_reused_port_keeps_the_owner_from_when_the_query_arrived() {
    let base = Instant::now();
    let mut owners = Owners::default();
    owners.record(key(50_000), ms(base, 10), 1111, base);
    owners.record(key(50_000), ms(base, 30), 2222, base);
    assert_eq!(owners.owner_at(key(50_000), ms(base, 20), base), Some(1111));
    assert_eq!(owners.owner_at(key(50_000), ms(base, 40), base), Some(2222));
    assert_eq!(owners.owner_at(key(50_000), ms(base, 5), base), None);
    assert_eq!(owners.owner_at(key(50_001), ms(base, 40), base), None);
}

#[test]
fn an_event_without_an_owner_is_never_resolved_to_pid_zero() {
    let base = Instant::now();
    let feed = EndpointOwnerFeed::default();
    let adapter = LocalEndpoint {
        address: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
        port: 50_000,
    };
    feed.received(ms(base, 10), Some((Protocol::Udp, adapter, 0)), base);
    feed.received(ms(base, 20), None, base);
    assert_eq!(
        feed.owner_at(Protocol::Udp, adapter, ms(base, 15), ms(base, 15)),
        EndpointOwner::Untrusted
    );
}

#[test]
fn out_of_order_events_are_sorted_and_history_is_bounded() {
    let base = Instant::now();
    let mut owners = Owners::default();
    for (offset, pid) in [(50, 5), (10, 1), (30, 3), (20, 2), (40, 4)] {
        owners.record(key(1), ms(base, offset), pid, base);
    }
    let history: Vec<u32> = owners
        .entries
        .get(&key(1))
        .expect("history")
        .iter()
        .map(|(_, pid)| *pid)
        .collect();
    assert_eq!(history, vec![2, 3, 4, 5]);
    assert_eq!(owners.owner_at(key(1), ms(base, 35), base), Some(3));
}

#[test]
fn ipv4_mapped_and_plain_addresses_are_one_endpoint() {
    let base = Instant::now();
    let mut owners = Owners::default();
    let mapped = LocalEndpoint {
        address: IpAddr::V6(Ipv4Addr::LOCALHOST.to_ipv6_mapped()),
        port: 7,
    };
    owners.record(EndpointKey::new(Protocol::Udp, mapped), base, 9, base);
    assert_eq!(owners.owner_at(key(7), base, base), Some(9));
    assert_eq!(
        owners.owner_at(EndpointKey::new(Protocol::Tcp, endpoint(7)), base, base),
        None,
        "protocols are separate endpoints"
    );
}

#[test]
fn a_lookup_hit_keeps_a_busy_endpoint_past_its_retention() {
    let base = Instant::now();
    let mut owners = Owners::default();
    owners.record(key(1), base, 42, base);
    let later = (base + RETENTION)
        .checked_sub(Duration::from_secs(1))
        .expect("within retention");
    assert_eq!(owners.owner_at(key(1), base, later), Some(42));
    let after_first_deadline = base + RETENTION + Duration::from_secs(1);
    assert_eq!(
        owners.owner_at(key(1), base, after_first_deadline),
        Some(42)
    );
    let idle = after_first_deadline + RETENTION;
    assert_eq!(owners.owner_at(key(1), base, idle), None);
}

#[test]
fn capacity_evicts_the_endpoint_closest_to_expiry() {
    let base = Instant::now();
    let mut owners = Owners::default();
    for port in 0..u16::try_from(CAPACITY).expect("capacity fits") {
        owners.record(
            key(port + 1),
            base,
            1,
            base + Duration::from_millis(u64::from(port)),
        );
    }
    owners.record(key(60_000), base, 2, base + Duration::from_secs(10));
    assert_eq!(owners.entries.len(), CAPACITY);
    assert!(!owners.entries.contains_key(&key(1)));
    assert!(owners.entries.contains_key(&key(60_000)));
}

#[test]
fn a_later_event_proves_the_feed_caught_up() {
    let feed = EndpointOwnerFeed::default();
    let base = Instant::now();
    feed.received(base, Some((Protocol::Udp, endpoint(53_000), 77)), base);
    let arrived = base + Duration::from_millis(1);
    feed.received(arrived + Duration::from_millis(1), None, base);
    let started = Instant::now();
    assert_eq!(
        feed.owner_at(
            Protocol::Udp,
            endpoint(53_000),
            arrived,
            started + Duration::from_secs(5)
        ),
        EndpointOwner::Resolved(77)
    );
    assert!(started.elapsed() < Duration::from_millis(500));
}

#[test]
fn a_lookup_waits_for_an_event_still_on_its_way() {
    let feed = Arc::new(EndpointOwnerFeed::default());
    let arrived = Instant::now();
    let listener = {
        let feed = Arc::clone(&feed);
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(20));
            // The flow was established before the query arrived, but its
            // event is only processed now.
            feed.received(
                arrived
                    .checked_sub(Duration::from_millis(1))
                    .expect("representable"),
                Some((Protocol::Udp, endpoint(53_001), 88)),
                Instant::now(),
            );
            feed.receiving(Instant::now());
        })
    };
    let owner = feed.owner_at(
        Protocol::Udp,
        endpoint(53_001),
        arrived,
        Instant::now() + Duration::from_secs(5),
    );
    listener.join().expect("listener");
    assert_eq!(owner, EndpointOwner::Resolved(88));
}

#[test]
fn a_current_owner_needs_a_running_listener_that_caught_up() {
    let feed = EndpointOwnerFeed::default();
    let base = Instant::now();
    feed.received(base, Some((Protocol::Udp, endpoint(53_002), 77)), base);
    let arrived = base + Duration::from_millis(1);
    let soon = || Instant::now() + Duration::from_millis(20);
    assert_eq!(
        feed.current_owner_at(Protocol::Udp, endpoint(53_002), arrived, soon()),
        None,
        "a listener that has not caught up may not have seen a newer owner"
    );
    feed.received(arrived + Duration::from_millis(1), None, base);
    assert_eq!(
        feed.current_owner_at(Protocol::Udp, endpoint(53_002), arrived, soon()),
        Some(77)
    );
    feed.close();
    assert_eq!(
        feed.current_owner_at(Protocol::Udp, endpoint(53_002), arrived, soon()),
        None,
        "a stopped listener no longer records new owners"
    );
}

#[test]
fn a_receive_that_returned_is_no_proof_while_its_event_is_handled() {
    let feed = EndpointOwnerFeed::default();
    let base = Instant::now();
    feed.received(base, Some((Protocol::Udp, endpoint(53_003), 1111)), base);
    let arrived = base + Duration::from_millis(1);
    feed.receiving(arrived);
    // The receive returns an event for the port's new owner; resolving its
    // process image takes longer than the idle proof.
    feed.processing();
    std::thread::sleep(IDLE_PROOF * 5);
    let soon = Instant::now() + Duration::from_millis(20);
    assert_eq!(
        feed.current_owner_at(Protocol::Udp, endpoint(53_003), arrived, soon),
        None,
        "the previous owner must not be certified while the new one is recorded"
    );
    feed.received(arrived, Some((Protocol::Udp, endpoint(53_003), 2222)), base);
    feed.receiving(Instant::now());
    let soon = Instant::now() + Duration::from_millis(20);
    assert_eq!(
        feed.current_owner_at(Protocol::Udp, endpoint(53_003), arrived, soon),
        Some(2222)
    );
}

#[test]
fn a_closed_feed_stays_closed() {
    let feed = EndpointOwnerFeed::default();
    let base = Instant::now();
    feed.received(base, Some((Protocol::Udp, endpoint(53_004), 77)), base);
    feed.close();
    feed.receiving(Instant::now());
    feed.processing();
    let arrived = base + Duration::from_millis(1);
    let soon = Instant::now() + Duration::from_millis(20);
    assert_eq!(
        feed.current_owner_at(Protocol::Udp, endpoint(53_004), arrived, soon),
        None
    );
    assert_eq!(
        feed.owner_at(Protocol::Udp, endpoint(53_004), arrived, soon),
        EndpointOwner::Resolved(77),
        "a closed feed still answers from what it recorded"
    );
}

#[test]
fn an_idle_listener_proves_the_feed_caught_up() {
    let feed = EndpointOwnerFeed::default();
    let base = Instant::now();
    feed.receiving(base);
    let started = Instant::now();
    assert_eq!(
        feed.owner_at(
            Protocol::Udp,
            endpoint(1),
            base,
            started + Duration::from_secs(5)
        ),
        EndpointOwner::NotFound
    );
    let waited = started.elapsed();
    assert!(waited < Duration::from_millis(500), "waited {waited:?}");
}

#[test]
fn a_stalled_listener_is_bounded_by_the_deadline() {
    let feed = EndpointOwnerFeed::default();
    let arrived = Instant::now();
    let started = Instant::now();
    let owner = feed.owner_at(
        Protocol::Udp,
        endpoint(1),
        arrived,
        started + Duration::from_millis(30),
    );
    assert_eq!(owner, EndpointOwner::Behind);
    assert!(started.elapsed() >= Duration::from_millis(30));
}

#[test]
fn closing_wakes_waiting_lookups() {
    let feed = Arc::new(EndpointOwnerFeed::default());
    let arrived = Instant::now();
    let closer = {
        let feed = Arc::clone(&feed);
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(20));
            feed.close();
        })
    };
    let started = Instant::now();
    let owner = feed.owner_at(
        Protocol::Udp,
        endpoint(1),
        arrived,
        started + Duration::from_secs(5),
    );
    closer.join().expect("closer");
    assert_eq!(owner, EndpointOwner::NotFound);
    assert!(started.elapsed() < Duration::from_secs(1));
}

#[test]
fn withdraw_leaves_a_newer_feed_published() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    let old = Arc::new(EndpointOwnerFeed::default());
    let new = Arc::new(EndpointOwnerFeed::default());
    publish(&old);
    publish(&new);
    withdraw(&old);
    assert!(endpoint_owners_available());
    withdraw(&new);
    assert!(!endpoint_owners_available());
    assert_eq!(
        endpoint_owner_at(Protocol::Udp, endpoint(1), Instant::now(), Duration::ZERO),
        EndpointOwner::Unavailable
    );
}

/// Tests that publish share the process-wide feed.
pub(crate) static SERIAL: Mutex<()> = Mutex::new(());

#[test]
fn repeated_packet_observations_preserve_previous_owners() {
    let base = Instant::now();
    let mut owners = Owners::default();
    owners.record(key(50_000), base, 11, base);
    for offset in 1..100 {
        owners.record(key(50_000), ms(base, offset), 22, base);
    }
    assert_eq!(owners.entries.get(&key(50_000)).unwrap().len(), 2);
    assert_eq!(owners.owner_at(key(50_000), base, base), Some(11));
    assert_eq!(owners.owner_at(key(50_000), ms(base, 50), base), Some(22));
}

#[test]
fn default_policy_does_not_treat_unix_pid_four_as_windows_system() {
    let base = Instant::now();
    let feed = EndpointOwnerFeed::default();
    feed.received(base, Some((Protocol::Udp, endpoint(53_000), 4)), base);
    assert_eq!(
        feed.owner_at(Protocol::Udp, endpoint(53_000), base, base),
        EndpointOwner::Resolved(4)
    );
}

#[test]
fn wildcard_udp_owners_resolve_but_conflicting_exact_owners_are_untrusted() {
    let base = Instant::now();
    let mut owners = Owners::default();
    let exact = key(50_000);
    let wildcard = EndpointKey {
        address: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        ..exact
    };
    owners.record(wildcard, ms(base, 10), 11, base);
    owners.record(exact, ms(base, 30), 22, base);
    owners.record(wildcard, ms(base, 50), 33, base);
    assert_eq!(owners.owner_at(exact, ms(base, 20), base), Some(11));
    assert_eq!(
        owners.owner_at(exact, ms(base, 40), base),
        Some(UNKNOWN_OWNER)
    );
    assert_eq!(
        owners.owner_at(exact, ms(base, 60), base),
        Some(UNKNOWN_OWNER)
    );
    let ipv6 = EndpointKey {
        address: IpAddr::V6(std::net::Ipv6Addr::LOCALHOST),
        ..exact
    };
    assert_eq!(owners.owner_at(ipv6, ms(base, 60), base), None);
}

/// Linux records a dual-stack UDP socket under `::`, and its query is looked up
/// under the IPv4 address it came from.
#[test]
fn an_ipv6_wildcard_owner_answers_for_ipv4_unless_an_ipv4_wildcard_does() {
    let base = Instant::now();
    let mut owners = Owners::default();
    let exact = key(50_000);
    let any_ipv6 = EndpointKey {
        address: IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED),
        ..exact
    };
    owners.record(any_ipv6, ms(base, 10), 11, base);
    assert_eq!(owners.owner_at(exact, ms(base, 20), base), Some(11));
    let any_ipv4 = EndpointKey {
        address: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        ..exact
    };
    owners.record(any_ipv4, ms(base, 30), 22, base);
    assert_eq!(
        owners.owner_at(exact, ms(base, 40), base),
        Some(22),
        "an IPv4 socket on the port is the likelier owner"
    );
    let ipv6 = EndpointKey {
        address: IpAddr::V6(std::net::Ipv6Addr::LOCALHOST),
        ..exact
    };
    assert_eq!(
        owners.owner_at(ipv6, ms(base, 40), base),
        Some(11),
        "an IPv4 socket never owns an IPv6 endpoint"
    );
}

/// A closed wildcard socket must not keep a live exact owner untrusted for as
/// long as lookups keep asking.
#[test]
fn a_conflicting_wildcard_owner_ages_out_while_the_exact_owner_stays_live() {
    let base = Instant::now();
    let mut owners = Owners::default();
    let exact = key(50_000);
    let wildcard = EndpointKey {
        address: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        ..exact
    };
    owners.record(wildcard, ms(base, 10), 11, base);
    owners.record(exact, ms(base, 30), 22, base);
    let late = base + Duration::from_secs(60);
    for _ in 0..3 {
        assert_eq!(
            owners.owner_at(exact, ms(base, 40), late),
            Some(UNKNOWN_OWNER)
        );
    }
    // The live socket keeps sending; the closed one does not.
    owners.record(exact, late, 22, late);
    let after_retention = base + RETENTION + Duration::from_secs(1);
    assert_eq!(
        owners.owner_at(exact, ms(base, 40), after_retention),
        Some(22)
    );
}

/// Byte records report a send when it returns, after the receiver may have
/// read it, so they must not count as progress past the query.
#[test]
fn an_out_of_order_observation_records_history_without_proving_progress() {
    let base = Instant::now();
    let feed = EndpointOwnerFeed::default();
    feed.observed(ms(base, 10), Protocol::Udp, endpoint(50_000), 7, base);
    feed.observed(ms(base, 50), Protocol::Udp, endpoint(50_001), 8, base);
    assert_eq!(
        feed.owner_at(
            Protocol::Udp,
            endpoint(50_000),
            ms(base, 20),
            Instant::now()
        ),
        EndpointOwner::Resolved(7)
    );
    assert_eq!(
        feed.current_owner_at(
            Protocol::Udp,
            endpoint(50_000),
            ms(base, 20),
            Instant::now()
        ),
        None,
        "the newer observation is no proof the reader caught up"
    );
    feed.received(ms(base, 60), None, base);
    assert_eq!(
        feed.current_owner_at(
            Protocol::Udp,
            endpoint(50_000),
            ms(base, 20),
            Instant::now()
        ),
        Some(7)
    );
}
