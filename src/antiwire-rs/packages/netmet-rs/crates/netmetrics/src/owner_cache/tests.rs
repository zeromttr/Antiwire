use super::*;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Barrier;
use std::sync::atomic::AtomicUsize;
use std::thread;

const REFRESH: Duration = Duration::from_millis(250);
const LONG: Duration = Duration::from_secs(5);

fn local(port: u16) -> LocalEndpoint {
    LocalEndpoint {
        address: IpAddr::V4(Ipv4Addr::LOCALHOST),
        port,
    }
}

/// Localhost UDP binds as `(port, pid)`.
fn udp(binds: &[(u16, u32)]) -> SocketOwnerSnapshot {
    let mut owners = SocketOwnerSnapshot::default();
    for &(port, pid) in binds {
        owners.insert_udp(local(port), pid);
    }
    owners
}

fn ago(age: Duration) -> Instant {
    Instant::now()
        .checked_sub(age)
        .expect("test instant remains representable")
}

fn in_(delay: Duration) -> Instant {
    Instant::now() + delay
}

fn no_scan(_: Protocol) -> SocketOwnerSnapshot {
    panic!("the cached snapshot answers")
}

impl<S> SocketOwnerCache<S>
where
    S: Fn(Protocol) -> SocketOwnerSnapshot,
{
    /// Stores `owners` as if a scan had started at `captured_at`, without
    /// using up a scan slot.
    fn seed(&self, protocol: Protocol, owners: SocketOwnerSnapshot, captured_at: Instant) {
        self.slot(protocol).replace(Arc::new(CachedSnapshot {
            owners,
            captured_at,
        }));
    }

    /// Records a scan that started at `at`, so the refresh interval counts from it.
    fn started_scan_at(&self, protocol: Protocol, at: Instant) {
        self.slot(protocol).lock_state().last_started = Some(at);
    }

    fn latest(&self, protocol: Protocol) -> Arc<CachedSnapshot> {
        self.slot(protocol)
            .latest_if(|_| true)
            .expect("a snapshot was stored")
    }

    fn udp_owner(&self, port: u16, observed_at: Instant, wait: Wait) -> Result<Ownership, Pending> {
        self.owner(Protocol::Udp, local(port), observed_at, wait)
    }
}

/// A scanner that counts its calls and returns `owners`.
fn counting(
    calls: &AtomicUsize,
    owners: impl Fn() -> SocketOwnerSnapshot,
) -> impl Fn(Protocol) -> SocketOwnerSnapshot {
    move |_| {
        calls.fetch_add(1, Ordering::Relaxed);
        owners()
    }
}

/// A scanner that meets `entered` when it starts and `release` before it
/// returns `owners`, so a test can act while it runs.
fn gated<'a>(
    entered: &'a Barrier,
    release: &'a Barrier,
    owners: impl Fn() -> SocketOwnerSnapshot + 'a,
) -> impl Fn(Protocol) -> SocketOwnerSnapshot + 'a {
    move |_| {
        entered.wait();
        release.wait();
        owners()
    }
}

#[test]
fn a_fresh_snapshot_answers_hits_ambiguity_and_misses_without_scanning() {
    let cache = SocketOwnerCache::with_scanner(REFRESH, no_scan);
    let mut owners = udp(&[(50_000, 4242), (50_001, 100)]);
    owners.insert_udp(local(50_001), 200);
    cache.seed(Protocol::Udp, owners, Instant::now());
    // Events that arrived before the snapshot was taken.
    let before = ago(Duration::from_millis(50));
    assert_eq!(
        cache.udp_owner(50_000, before, Wait::Never),
        Ok(Ownership::Resolved(4242))
    );
    assert_eq!(
        cache.udp_owner(50_001, before, Wait::Never),
        Ok(Ownership::Ambiguous)
    );
    assert_eq!(
        cache.udp_owner(50_002, before, Wait::Never),
        Ok(Ownership::NotFound)
    );
    assert_eq!(
        cache.udp_owner(0, Instant::now(), Wait::Never),
        Ok(Ownership::NotFound),
        "port 0 is never bound"
    );
    assert_eq!(cache.scans(), 0);
}

/// The regression this guards: a socket opened just after a scan sent its
/// query within the refresh interval and was recorded as unknown.
#[test]
fn a_miss_on_a_snapshot_older_than_the_event_rescans() {
    let calls = AtomicUsize::new(0);
    let cache =
        SocketOwnerCache::with_scanner(REFRESH, counting(&calls, || udp(&[(50_000, 4242)])));
    cache.seed(
        Protocol::Udp,
        SocketOwnerSnapshot::default(),
        ago(Duration::from_millis(20)),
    );
    assert_eq!(
        cache.udp_owner(50_000, Instant::now(), Wait::Never),
        Ok(Ownership::Resolved(4242))
    );
    assert_eq!(calls.load(Ordering::Relaxed), 1);
}

#[test]
fn a_hit_on_a_snapshot_older_than_the_event_is_trusted_within_the_refresh_interval() {
    let cache = SocketOwnerCache::with_scanner(REFRESH, no_scan);
    cache.seed(
        Protocol::Udp,
        udp(&[(50_000, 4242)]),
        ago(Duration::from_millis(20)),
    );
    assert_eq!(
        cache.udp_owner(50_000, Instant::now(), Wait::Never),
        Ok(Ownership::Resolved(4242))
    );
}

#[test]
fn a_stale_snapshot_is_rescanned_for_hits_and_misses() {
    for previous in [SocketOwnerSnapshot::default(), udp(&[(50_000, 4242)])] {
        let calls = AtomicUsize::new(0);
        let cache =
            SocketOwnerCache::with_scanner(REFRESH, counting(&calls, || udp(&[(50_000, 8484)])));
        cache.seed(Protocol::Udp, previous, ago(REFRESH));
        assert_eq!(
            cache.udp_owner(50_000, Instant::now(), Wait::Never),
            Ok(Ownership::Resolved(8484))
        );
        assert_eq!(calls.load(Ordering::Relaxed), 1);
    }
}

#[test]
fn a_snapshot_taken_after_the_event_answers_whatever_its_age() {
    let cache = SocketOwnerCache::with_scanner(REFRESH, no_scan);
    let observed = ago(Duration::from_secs(2));
    cache.seed(
        Protocol::Udp,
        udp(&[(50_000, 4242)]),
        ago(Duration::from_secs(1)),
    );
    assert_eq!(
        cache.udp_owner(50_000, observed, Wait::Never),
        Ok(Ownership::Resolved(4242))
    );
    assert_eq!(
        cache.udp_owner(50_001, observed, Wait::Never),
        Ok(Ownership::NotFound),
        "the socket had closed by the time of the scan"
    );
}

#[test]
fn missing_ports_share_one_snapshot_during_a_burst() {
    let calls = AtomicUsize::new(0);
    let cache =
        SocketOwnerCache::with_scanner(REFRESH, counting(&calls, SocketOwnerSnapshot::default));
    // The burst arrived together, before the scan its first lookup runs.
    let arrived = ago(Duration::from_millis(50));
    for port in 10_000..11_000 {
        assert_eq!(
            cache.udp_owner(port, arrived, Wait::Never),
            Ok(Ownership::NotFound)
        );
    }
    assert_eq!(
        calls.load(Ordering::Relaxed),
        1,
        "missing ports must not each scan every socket"
    );
}

#[test]
fn a_burst_of_waiting_lookups_shares_one_scan() {
    let calls = AtomicUsize::new(0);
    let cache =
        SocketOwnerCache::with_scanner(REFRESH, counting(&calls, SocketOwnerSnapshot::default));
    cache.started_scan_at(Protocol::Udp, Instant::now());
    let arrived = Instant::now();
    for port in 10_000..11_000 {
        assert_eq!(
            cache.udp_owner(port, arrived, Wait::Until(in_(LONG))),
            Ok(Ownership::NotFound)
        );
    }
    assert_eq!(
        calls.load(Ordering::Relaxed),
        1,
        "one scan covers lookups for events before it"
    );
}

#[test]
fn reply_and_worker_scans_share_the_refresh_limit() {
    let calls = AtomicUsize::new(0);
    let cache =
        SocketOwnerCache::with_scanner(REFRESH, counting(&calls, SocketOwnerSnapshot::default));
    assert_eq!(
        cache.udp_owner(50_000, Instant::now(), Wait::Never),
        Ok(Ownership::NotFound)
    );
    let first = cache.latest(Protocol::Udp).captured_at();
    // A socket opened after that scan needs another. A lookup that may not
    // wait gets none; one that may waits for the next slot.
    assert_eq!(
        cache.udp_owner(50_001, Instant::now(), Wait::Never),
        Err(Pending::Busy)
    );
    assert_eq!(
        cache.udp_owner(50_002, Instant::now(), Wait::Until(in_(LONG))),
        Ok(Ownership::NotFound)
    );
    let second = cache.latest(Protocol::Udp).captured_at();
    assert!(second.duration_since(first) >= REFRESH);
    assert_eq!(
        cache.udp_owner(50_003, Instant::now(), Wait::Until(in_(LONG))),
        Ok(Ownership::NotFound)
    );
    let third = cache.latest(Protocol::Udp).captured_at();
    assert!(third.duration_since(second) >= REFRESH);
    assert_eq!(calls.load(Ordering::Relaxed), 3);
    assert_eq!(cache.scans(), 3);
}

#[test]
fn a_lookup_does_not_wait_for_a_slot_past_its_deadline() {
    let cache = SocketOwnerCache::with_scanner(REFRESH, no_scan);
    cache.started_scan_at(Protocol::Udp, Instant::now());
    let started = Instant::now();
    assert_eq!(
        cache.udp_owner(
            50_000,
            Instant::now(),
            Wait::Until(in_(Duration::from_millis(10)))
        ),
        Err(Pending::DeadlinePassed)
    );
    assert!(
        started.elapsed() < REFRESH,
        "it gives up at once rather than sleep"
    );
}

#[test]
fn a_lookup_past_its_deadline_starts_no_scan() {
    let cache = SocketOwnerCache::with_scanner(REFRESH, no_scan);
    let deadline = Instant::now();
    assert_eq!(
        cache.udp_owner(50_000, Instant::now(), Wait::Until(deadline)),
        Err(Pending::DeadlinePassed)
    );
    assert_eq!(
        cache
            .snapshot_since(Protocol::Udp, Instant::now(), Wait::Until(deadline))
            .map(|_| ()),
        Err(Pending::DeadlinePassed)
    );
}

#[test]
fn a_slow_scan_holds_no_lock_and_turns_other_lookups_away() {
    let (entered, release) = (Barrier::new(2), Barrier::new(2));
    let cache =
        SocketOwnerCache::with_scanner(REFRESH, gated(&entered, &release, || udp(&[(50_000, 42)])));
    let arrived = Instant::now();
    thread::scope(|scope| {
        let scanning = scope.spawn(|| cache.udp_owner(50_000, arrived, Wait::Never));
        entered.wait();
        assert!(cache.slot(Protocol::Udp).latest.try_write().is_ok());
        assert_eq!(
            cache.udp_owner(50_001, arrived, Wait::Never),
            Err(Pending::Busy),
            "a lookup that may not wait hands off rather than queue behind a scan"
        );
        release.wait();
        assert_eq!(scanning.join().unwrap(), Ok(Ownership::Resolved(42)));
    });
    assert_eq!(
        cache.udp_owner(50_000, arrived, Wait::Never),
        Ok(Ownership::Resolved(42)),
        "the scan's snapshot answers later lookups"
    );
}

#[test]
fn a_waiting_lookup_reuses_the_scan_it_waited_for() {
    let (entered, release) = (Barrier::new(2), Barrier::new(2));
    let cache =
        SocketOwnerCache::with_scanner(REFRESH, gated(&entered, &release, || udp(&[(50_001, 77)])));
    let arrived = Instant::now();
    thread::scope(|scope| {
        let scanning = scope.spawn(|| cache.udp_owner(50_000, arrived, Wait::Never));
        entered.wait();
        let waiting = scope.spawn(|| cache.udp_owner(50_001, arrived, Wait::Until(in_(LONG))));
        thread::sleep(Duration::from_millis(50));
        assert!(!waiting.is_finished(), "a waiting lookup must not give up");
        release.wait();
        assert_eq!(scanning.join().unwrap(), Ok(Ownership::NotFound));
        assert_eq!(waiting.join().unwrap(), Ok(Ownership::Resolved(77)));
    });
    assert_eq!(cache.scans(), 1);
}

#[test]
fn a_waiting_lookup_gives_up_at_its_deadline_behind_a_hung_scan() {
    let (entered, release) = (Barrier::new(2), Barrier::new(2));
    let cache = SocketOwnerCache::with_scanner(
        REFRESH,
        gated(&entered, &release, SocketOwnerSnapshot::default),
    );
    thread::scope(|scope| {
        let scanning = scope.spawn(|| cache.udp_owner(50_000, Instant::now(), Wait::Never));
        entered.wait();
        let started = Instant::now();
        assert_eq!(
            cache.udp_owner(
                50_001,
                Instant::now(),
                Wait::Until(in_(Duration::from_millis(50)))
            ),
            Err(Pending::DeadlinePassed)
        );
        assert!(started.elapsed() >= Duration::from_millis(50));
        assert!(started.elapsed() < LONG);
        release.wait();
        scanning.join().unwrap().unwrap();
    });
}

#[test]
fn a_panicking_scan_uses_its_slot_and_wakes_waiters() {
    let (entered, release) = (Barrier::new(2), Barrier::new(2));
    let calls = AtomicUsize::new(0);
    let cache = SocketOwnerCache::with_scanner(REFRESH, |_| {
        if calls.fetch_add(1, Ordering::Relaxed) == 0 {
            entered.wait();
            release.wait();
            panic!("scan failed");
        }
        udp(&[(50_000, 9)])
    });
    let arrived = Instant::now();
    thread::scope(|scope| {
        let panicking = scope.spawn(|| cache.udp_owner(50_000, arrived, Wait::Never));
        entered.wait();
        let waiting = scope.spawn(|| cache.udp_owner(50_000, arrived, Wait::Until(in_(LONG))));
        thread::sleep(Duration::from_millis(20));
        release.wait();
        assert!(panicking.join().is_err());
        assert_eq!(
            cache.udp_owner(50_000, arrived, Wait::Never),
            Err(Pending::Busy),
            "a failed scan must not be retried at once"
        );
        assert_eq!(
            waiting.join().unwrap(),
            Ok(Ownership::Resolved(9)),
            "a waiter is woken and scans in the next slot"
        );
    });
    assert_eq!(calls.load(Ordering::Relaxed), 2);
}

#[test]
fn live_udp_and_tcp_clients_resolve_to_this_process() {
    let udp_socket = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind UDP");
    let listener = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind listener");
    let tcp = std::net::TcpStream::connect(listener.local_addr().expect("listener addr"))
        .expect("connect");
    let _accepted = listener.accept().expect("accept");
    let cache = SocketOwnerCache::new(REFRESH);
    for (protocol, addr) in [
        (Protocol::Udp, udp_socket.local_addr().expect("udp addr")),
        (Protocol::Tcp, tcp.local_addr().expect("tcp addr")),
    ] {
        let endpoint = LocalEndpoint {
            address: addr.ip(),
            port: addr.port(),
        };
        assert_eq!(
            cache.owner(protocol, endpoint, Instant::now(), Wait::Never),
            Ok(Ownership::Resolved(std::process::id())),
            "{protocol:?} client {addr}"
        );
    }
}

/// The host's own cache, with real sockets. Whichever protocol it scanned for
/// last, a lookup for the other must not be answered "not found" from that
/// scan: where the two share a snapshot, the scan has to read both.
#[test]
fn the_host_cache_answers_each_protocol_after_a_scan_for_the_other() {
    let udp = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind UDP socket");
    let tcp = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind TCP listener");
    let endpoint = |address: std::net::SocketAddr| LocalEndpoint {
        address: address.ip(),
        port: address.port(),
    };
    let sockets = [
        (
            Protocol::Udp,
            endpoint(udp.local_addr().expect("UDP address")),
        ),
        (
            Protocol::Tcp,
            endpoint(tcp.local_addr().expect("TCP address")),
        ),
    ];
    let bound = Instant::now();
    for [(scanned, _), (asked, endpoint)] in [sockets, [sockets[1], sockets[0]]] {
        let cache = SocketOwnerCache::new(REFRESH);
        cache
            .snapshot_since(scanned, Instant::now(), Wait::Never)
            .expect("an idle cache scans at once");
        assert_eq!(
            cache.owner(asked, endpoint, bound, Wait::Until(in_(LONG))),
            Ok(Ownership::Resolved(std::process::id())),
            "{asked:?} lookup after a scan for {scanned:?}"
        );
    }
}

#[test]
fn each_protocol_has_its_own_snapshot_where_scans_are_per_protocol() {
    let calls = AtomicUsize::new(0);
    let cache =
        SocketOwnerCache::with_scanner(REFRESH, counting(&calls, SocketOwnerSnapshot::default));
    cache.seed(Protocol::Udp, udp(&[(50_000, 1)]), Instant::now());
    assert_eq!(
        cache.owner(Protocol::Tcp, local(50_000), Instant::now(), Wait::Never),
        Ok(Ownership::NotFound)
    );
    assert_eq!(
        calls.load(Ordering::Relaxed),
        1,
        "a UDP snapshot says nothing about TCP"
    );
}

#[test]
fn one_snapshot_serves_both_protocols_where_a_scan_reads_every_table() {
    let calls = AtomicUsize::new(0);
    let mut cache = SocketOwnerCache::with_scanner(
        REFRESH,
        counting(&calls, || {
            let mut owners = udp(&[(50_000, 1)]);
            owners.insert_tcp_listener(local(50_001), 2);
            owners
        }),
    );
    cache.per_protocol = false;
    let arrived = ago(Duration::from_millis(1));
    assert_eq!(
        cache.owner(Protocol::Udp, local(50_000), arrived, Wait::Never),
        Ok(Ownership::Resolved(1))
    );
    assert_eq!(
        cache.owner(Protocol::Tcp, local(50_001), arrived, Wait::Never),
        Ok(Ownership::Resolved(2))
    );
    assert_eq!(calls.load(Ordering::Relaxed), 1);
}

#[test]
fn snapshot_since_reuses_a_snapshot_taken_after_since() {
    let cache = SocketOwnerCache::with_scanner(REFRESH, no_scan);
    cache.seed(
        Protocol::Tcp,
        SocketOwnerSnapshot::default(),
        Instant::now(),
    );
    let first = cache
        .snapshot_since(Protocol::Tcp, ago(Duration::from_millis(10)), Wait::Never)
        .unwrap();
    assert!(Arc::ptr_eq(&first, &cache.latest(Protocol::Tcp)));
}

#[test]
fn snapshot_since_scans_when_the_newest_is_older_and_ignores_the_refresh_interval() {
    let calls = AtomicUsize::new(0);
    let cache =
        SocketOwnerCache::with_scanner(REFRESH, counting(&calls, SocketOwnerSnapshot::default));
    for _ in 0..3 {
        let since = Instant::now();
        let snapshot = cache
            .snapshot_since(Protocol::Tcp, since, Wait::Never)
            .unwrap();
        assert!(snapshot.captured_at() >= since);
    }
    assert_eq!(calls.load(Ordering::Relaxed), 3);
}

#[test]
fn snapshot_since_clamps_a_future_instant_to_now() {
    let calls = AtomicUsize::new(0);
    let cache =
        SocketOwnerCache::with_scanner(REFRESH, counting(&calls, SocketOwnerSnapshot::default));
    cache
        .snapshot_since(Protocol::Udp, in_(Duration::from_secs(3_600)), Wait::Never)
        .unwrap();
    assert_eq!(calls.load(Ordering::Relaxed), 1);
}

#[test]
fn snapshot_since_joins_a_running_scan_that_started_after_since() {
    let (entered, release) = (Barrier::new(2), Barrier::new(2));
    let cache = SocketOwnerCache::with_scanner(
        REFRESH,
        gated(&entered, &release, SocketOwnerSnapshot::default),
    );
    let since = Instant::now();
    thread::scope(|scope| {
        let scanning = scope.spawn(|| cache.snapshot_since(Protocol::Tcp, since, Wait::Never));
        entered.wait();
        assert_eq!(
            cache
                .snapshot_since(Protocol::Tcp, since, Wait::Never)
                .map(|_| ()),
            Err(Pending::Busy)
        );
        let joining =
            scope.spawn(|| cache.snapshot_since(Protocol::Tcp, since, Wait::Until(in_(LONG))));
        thread::sleep(Duration::from_millis(20));
        release.wait();
        let scanned = scanning.join().unwrap().unwrap();
        let joined = joining.join().unwrap().unwrap();
        assert!(Arc::ptr_eq(&scanned, &joined));
    });
    assert_eq!(cache.scans(), 1);
}

#[test]
fn snapshot_since_waits_out_an_older_running_scan_then_scans() {
    let (entered, release) = (Barrier::new(2), Barrier::new(2));
    let calls = AtomicUsize::new(0);
    let cache = SocketOwnerCache::with_scanner(REFRESH, |_| {
        if calls.fetch_add(1, Ordering::Relaxed) == 0 {
            entered.wait();
            release.wait();
        }
        SocketOwnerSnapshot::default()
    });
    let cache = &cache;
    thread::scope(|scope| {
        let scanning =
            scope.spawn(|| cache.snapshot_since(Protocol::Tcp, Instant::now(), Wait::Never));
        entered.wait();
        let since = Instant::now();
        let later =
            scope.spawn(move || cache.snapshot_since(Protocol::Tcp, since, Wait::Until(in_(LONG))));
        thread::sleep(Duration::from_millis(20));
        release.wait();
        scanning.join().unwrap().unwrap();
        assert!(later.join().unwrap().unwrap().captured_at() >= since);
    });
    assert_eq!(calls.load(Ordering::Relaxed), 2);
}

/// Eight threads hammer one slot, with sockets opening throughout so lookups
/// keep needing new scans.
fn hammer<S>(cache: &SocketOwnerCache<S>, with_snapshots: bool)
where
    S: Fn(Protocol) -> SocketOwnerSnapshot + Sync,
{
    thread::scope(|scope| {
        for worker in 0..8_u16 {
            scope.spawn(move || {
                for round in 0..300_u16 {
                    let wait = if round % 2 == 0 {
                        Wait::Never
                    } else {
                        Wait::Until(in_(Duration::from_millis(20)))
                    };
                    if with_snapshots && round % 5 == 0 {
                        let _ = cache.snapshot_since(Protocol::Udp, Instant::now(), wait);
                    } else {
                        let port = 50_000 + (worker * 7 + round) % 3;
                        let _ = cache.udp_owner(port, Instant::now(), wait);
                    }
                }
            });
        }
    });
}

#[test]
fn concurrent_lookups_stay_within_the_refresh_limit() {
    const REFRESH: Duration = Duration::from_millis(5);
    let cache = SocketOwnerCache::with_scanner(REFRESH, |_| {
        thread::sleep(Duration::from_micros(200));
        SocketOwnerSnapshot::default()
    });
    let started = Instant::now();
    hammer(&cache, false);
    let allowed = started.elapsed().as_millis() / REFRESH.as_millis() + 1;
    assert!(cache.scans() > 0);
    assert!(
        u128::from(cache.scans()) <= allowed,
        "{} scans in {:?}",
        cache.scans(),
        started.elapsed()
    );
}

#[test]
fn concurrent_lookups_and_snapshots_do_not_deadlock() {
    let cache = SocketOwnerCache::with_scanner(Duration::from_millis(5), |_| {
        thread::sleep(Duration::from_micros(200));
        udp(&[(50_000, 1)])
    });
    let started = Instant::now();
    hammer(&cache, true);
    assert!(started.elapsed() < Duration::from_secs(30));
}

#[test]
fn a_lookup_the_snapshot_answers_needs_no_scan() {
    let cache = SocketOwnerCache::with_scanner(REFRESH, no_scan);
    cache.seed(Protocol::Udp, udp(&[(50_000, 4242)]), Instant::now());
    let before = ago(Duration::from_millis(50));
    assert_eq!(
        cache.owner_without_scan(Protocol::Udp, local(50_000), before),
        Some(Ok(Ownership::Resolved(4242)))
    );
    assert_eq!(
        cache.owner_without_scan(Protocol::Udp, local(50_001), before),
        Some(Ok(Ownership::NotFound)),
        "a snapshot taken after the event proves the socket absent"
    );
    assert_eq!(
        cache.owner_without_scan(Protocol::Udp, local(0), Instant::now()),
        Some(Ok(Ownership::NotFound)),
        "port 0 is never bound"
    );
    assert_eq!(cache.scans(), 0);
}

/// `owner_without_scan` says in advance what `owner` then does: scan when a
/// slot is free, and turn the lookup away when one is not.
#[test]
fn a_lookup_that_needs_a_scan_is_told_whether_one_would_start() {
    let calls = AtomicUsize::new(0);
    let cache =
        SocketOwnerCache::with_scanner(REFRESH, counting(&calls, SocketOwnerSnapshot::default));
    let lookup = |port| cache.owner_without_scan(Protocol::Udp, local(port), Instant::now());

    assert_eq!(lookup(50_000), None, "no scan has run, so one would start");
    assert_eq!(calls.load(Ordering::Relaxed), 0, "asking starts nothing");
    assert_eq!(
        cache.udp_owner(50_000, Instant::now(), Wait::Never),
        Ok(Ownership::NotFound)
    );

    // A socket opened after that scan needs another, which is not due yet.
    assert_eq!(lookup(50_001), Some(Err(Pending::Busy)));
    assert_eq!(
        cache.udp_owner(50_001, Instant::now(), Wait::Never),
        Err(Pending::Busy)
    );

    cache.started_scan_at(Protocol::Udp, ago(REFRESH));
    assert_eq!(lookup(50_002), None, "the refresh interval has passed");
    assert_eq!(calls.load(Ordering::Relaxed), 1);
}

#[test]
fn a_lookup_is_turned_away_without_waiting_while_a_scan_runs() {
    let entered = Barrier::new(2);
    let release = Barrier::new(2);
    let cache = SocketOwnerCache::with_scanner(
        Duration::ZERO,
        gated(&entered, &release, SocketOwnerSnapshot::default),
    );
    thread::scope(|scope| {
        let scanning = scope.spawn(|| cache.udp_owner(50_000, Instant::now(), Wait::Never));
        entered.wait();
        assert_eq!(
            cache.owner_without_scan(Protocol::Udp, local(50_001), Instant::now()),
            Some(Err(Pending::Busy)),
            "a refresh interval of zero would otherwise allow a scan at once"
        );
        release.wait();
        assert_eq!(scanning.join().expect("scan"), Ok(Ownership::NotFound));
    });
}
