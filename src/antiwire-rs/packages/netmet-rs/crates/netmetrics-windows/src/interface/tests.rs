use super::*;
use netmetrics_core::Protocol;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::AtomicU64;
use std::sync::mpsc::sync_channel;

#[test]
fn bound_address_beats_the_route_guess_and_loopback_ignores_it() {
    let bound = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10));
    assert_eq!(select_interface(bound, Some(12), Some(4)), Some((12, true)));
    assert_eq!(
        select_interface(IpAddr::V4(Ipv4Addr::LOCALHOST), Some(1), Some(4)),
        Some((1, true))
    );
    assert_eq!(
        select_interface(IpAddr::V4(Ipv4Addr::LOCALHOST), None, Some(4)),
        None
    );
    assert_eq!(
        select_interface(IpAddr::V4(Ipv4Addr::UNSPECIFIED), None, Some(4)),
        Some((4, false))
    );
}

fn key() -> FlowKey {
    FlowKey {
        protocol: Protocol::Tcp,
        local_addr: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
        local_port: 50_000,
        remote_addr: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 20)),
        remote_port: 443,
    }
}

#[test]
fn cache_hit_emits_immediately_and_deduplicates_pending() {
    let (sender, receiver) = sync_channel(8);
    let sink = EventSink::new(sender, Arc::new(AtomicU64::new(0)));
    let route = RouteKey {
        local: key().local_addr,
        remote: key().remote_addr,
    };
    let mut cache = HashMap::new();
    cache.insert(
        route,
        CacheEntry {
            result: Ok(7),
            bound: true,
            expires_at: Instant::now() + Duration::from_secs(30),
            epoch: 1,
        },
    );
    let mut pending = HashMap::new();
    let mut queue = VecDeque::new();
    let mut queued = HashSet::new();
    enqueue_request(
        key(),
        3,
        0,
        &mut cache,
        &mut pending,
        &mut queue,
        &mut queued,
        1,
        Instant::now(),
        &sink,
    );
    assert!(queue.is_empty());
    assert!(pending.is_empty());
    assert!(matches!(
        receiver.try_recv(),
        Ok(BackendEvent::InterfaceHint {
            if_index: 7,
            generation: 3,
            ..
        })
    ));
}

#[test]
fn stale_epoch_and_expiry_miss_the_cache() {
    let (sender, receiver) = sync_channel(8);
    let sink = EventSink::new(sender, Arc::new(AtomicU64::new(0)));
    let route = RouteKey {
        local: key().local_addr,
        remote: key().remote_addr,
    };
    let mut cache = HashMap::new();
    cache.insert(
        route,
        CacheEntry {
            result: Ok(7),
            bound: true,
            expires_at: Instant::now() + Duration::from_secs(30),
            epoch: 1,
        },
    );
    let mut pending = HashMap::new();
    let mut queue = VecDeque::new();
    let mut queued = HashSet::new();
    enqueue_request(
        key(),
        1,
        0,
        &mut cache,
        &mut pending,
        &mut queue,
        &mut queued,
        2,
        Instant::now(),
        &sink,
    );
    assert_eq!(queue.len(), 1);
    assert!(receiver.try_recv().is_err());
}

fn other_key() -> FlowKey {
    FlowKey {
        remote_addr: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 21)),
        ..key()
    }
}

#[test]
fn bound_retries_stop_after_four_attempts_without_retaining_flow_state() {
    let mut retries = VecDeque::new();
    let now = Instant::now();
    for attempts in 0..=u8::try_from(ROUTE_RETRY_LIMIT).expect("small limit") {
        schedule_bound_retry(&mut retries, key(), 1, attempts, now);
        if usize::from(attempts) < ROUTE_RETRY_LIMIT {
            assert_eq!(retries.pop_front().map(|retry| retry.3), Some(attempts + 1));
        }
    }
    assert!(retries.is_empty());
}

#[test]
fn fresh_unbound_cache_keeps_a_due_retry_queued() {
    let (sender, receiver) = sync_channel(8);
    let sink = EventSink::new(sender, Arc::new(AtomicU64::new(0)));
    let now = Instant::now();
    let resume_at = now + FAILURE_TTL;
    let route = RouteKey {
        local: key().local_addr,
        remote: key().remote_addr,
    };
    let mut cache = HashMap::new();
    cache.insert(
        route,
        CacheEntry {
            result: Ok(4),
            bound: false,
            expires_at: resume_at,
            epoch: 1,
        },
    );
    let mut retries = VecDeque::from([(now, key(), 1, 2)]);
    let mut pending = HashMap::new();
    let mut queue = VecDeque::new();
    let mut queued = HashSet::new();
    promote_due_retries(
        &mut retries,
        &mut cache,
        &mut pending,
        &mut queue,
        &mut queued,
        1,
        now,
        &sink,
    );
    assert!(
        receiver.try_recv().is_err(),
        "a route guess must not be delivered again as the retry's answer"
    );
    assert!(queue.is_empty());
    assert_eq!(retries.len(), 1);
    let (due, flow, generation, attempts) = retries[0];
    assert_eq!(flow, key());
    assert_eq!(generation, 1);
    assert_eq!(attempts, 2);
    assert_eq!(due, resume_at);
}

#[test]
fn deferred_retry_stays_ahead_of_a_later_one() {
    let (sender, _receiver) = sync_channel(8);
    let sink = EventSink::new(sender, Arc::new(AtomicU64::new(0)));
    let now = Instant::now();
    let resume_at = now + Duration::from_millis(100);
    let later = now + Duration::from_millis(800);
    let mut cache = HashMap::new();
    cache.insert(
        RouteKey {
            local: key().local_addr,
            remote: key().remote_addr,
        },
        CacheEntry {
            result: Ok(4),
            bound: false,
            expires_at: resume_at,
            epoch: 1,
        },
    );
    let mut retries = VecDeque::from([(now, key(), 1, 1), (later, other_key(), 2, 1)]);
    let mut pending = HashMap::new();
    let mut queue = VecDeque::new();
    let mut queued = HashSet::new();
    promote_due_retries(
        &mut retries,
        &mut cache,
        &mut pending,
        &mut queue,
        &mut queued,
        1,
        now,
        &sink,
    );
    assert_eq!(retries.len(), 2);
    assert_eq!(retries[0].0, resume_at);
    assert_eq!(retries[0].1, key());
    assert_eq!(retries[1].0, later);
    assert_eq!(retries[1].1, other_key());
}

#[test]
fn bound_cache_finishes_a_due_retry() {
    let (sender, receiver) = sync_channel(8);
    let sink = EventSink::new(sender, Arc::new(AtomicU64::new(0)));
    let now = Instant::now();
    let mut cache = HashMap::new();
    cache.insert(
        RouteKey {
            local: key().local_addr,
            remote: key().remote_addr,
        },
        CacheEntry {
            result: Ok(12),
            bound: true,
            expires_at: now + SUCCESS_TTL,
            epoch: 1,
        },
    );
    let mut retries = VecDeque::from([(now, key(), 9, 1)]);
    let mut pending = HashMap::new();
    let mut queue = VecDeque::new();
    let mut queued = HashSet::new();
    promote_due_retries(
        &mut retries,
        &mut cache,
        &mut pending,
        &mut queue,
        &mut queued,
        1,
        now,
        &sink,
    );
    assert!(retries.is_empty());
    assert!(matches!(
        receiver.try_recv(),
        Ok(BackendEvent::InterfaceHint {
            if_index: 12,
            bound: true,
            generation: 9,
            ..
        })
    ));
}

#[test]
fn due_retry_is_promoted_while_other_routes_are_queued() {
    let (sender, _receiver) = sync_channel(8);
    let sink = EventSink::new(sender, Arc::new(AtomicU64::new(0)));
    let now = Instant::now();
    let mut retries = VecDeque::from([(now, key(), 1, 1)]);
    let mut cache = HashMap::new();
    let mut pending = HashMap::new();
    let mut queue = VecDeque::new();
    let mut queued = HashSet::new();
    enqueue_request(
        other_key(),
        1,
        0,
        &mut cache,
        &mut pending,
        &mut queue,
        &mut queued,
        1,
        now,
        &sink,
    );
    promote_due_retries(
        &mut retries,
        &mut cache,
        &mut pending,
        &mut queue,
        &mut queued,
        1,
        now,
        &sink,
    );
    assert!(retries.is_empty());
    assert_eq!(queue.len(), 2);
    assert_eq!(
        pending[&RouteKey {
            local: key().local_addr,
            remote: key().remote_addr
        }]
            .waiters,
        vec![(key(), 1, 1)]
    );
}

#[test]
fn drain_queue_honours_a_lookup_budget() {
    let (sender, _receiver) = sync_channel(8);
    let sink = EventSink::new(sender, Arc::new(AtomicU64::new(0)));
    let stop = StopFlag::new();
    let mut cache = HashMap::new();
    let mut pending = HashMap::new();
    let mut queue = VecDeque::new();
    let mut queued = HashSet::new();
    enqueue_request(
        key(),
        1,
        0,
        &mut cache,
        &mut pending,
        &mut queue,
        &mut queued,
        1,
        Instant::now(),
        &sink,
    );
    enqueue_request(
        other_key(),
        1,
        0,
        &mut cache,
        &mut pending,
        &mut queue,
        &mut queued,
        1,
        Instant::now(),
        &sink,
    );
    assert_eq!(queue.len(), 2);
    let mut retries = VecDeque::new();
    drain_queue(
        &mut cache,
        &mut pending,
        &mut queue,
        &mut queued,
        &mut retries,
        1,
        Instant::now(),
        &sink,
        1,
        &stop,
    );
    assert_eq!(queue.len(), 1);
}

#[test]
fn drain_queue_checks_cancellation_before_each_lookup() {
    let (sender, _receiver) = sync_channel(8);
    let sink = EventSink::new(sender, Arc::new(AtomicU64::new(0)));
    let stop = StopFlag::new();
    let mut cache = HashMap::new();
    let mut pending = HashMap::new();
    let mut queue = VecDeque::new();
    let mut queued = HashSet::new();
    enqueue_request(
        key(),
        1,
        0,
        &mut cache,
        &mut pending,
        &mut queue,
        &mut queued,
        1,
        Instant::now(),
        &sink,
    );
    enqueue_request(
        other_key(),
        1,
        0,
        &mut cache,
        &mut pending,
        &mut queue,
        &mut queued,
        1,
        Instant::now(),
        &sink,
    );
    stop.stop();
    let mut retries = VecDeque::new();
    drain_queue(
        &mut cache,
        &mut pending,
        &mut queue,
        &mut queued,
        &mut retries,
        1,
        Instant::now(),
        &sink,
        8,
        &stop,
    );
    assert_eq!(queue.len(), 2);
}

#[test]
fn dropping_the_estimator_joins_the_worker() {
    let (sender, _receiver) = sync_channel(8);
    let sink = EventSink::new(sender, Arc::new(AtomicU64::new(0)));
    let estimator = InterfaceEstimator::start(sink, StopFlag::new()).expect("spawn");
    drop(estimator);
}

#[test]
fn failed_lookups_are_cached_and_do_not_emit() {
    let (sender, receiver) = sync_channel(8);
    let sink = EventSink::new(sender, Arc::new(AtomicU64::new(0)));
    let route = RouteKey {
        local: key().local_addr,
        remote: key().remote_addr,
    };
    let mut cache = HashMap::new();
    cache.insert(
        route,
        CacheEntry {
            result: Err(()),
            bound: false,
            expires_at: Instant::now() + Duration::from_secs(30),
            epoch: 1,
        },
    );
    let mut pending = HashMap::new();
    let mut queue = VecDeque::new();
    let mut queued = HashSet::new();
    enqueue_request(
        key(),
        1,
        0,
        &mut cache,
        &mut pending,
        &mut queue,
        &mut queued,
        1,
        Instant::now(),
        &sink,
    );
    assert!(queue.is_empty());
    assert!(receiver.try_recv().is_err());
}
