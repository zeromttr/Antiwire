use super::dns_trace::{DNS_CLIENT_EVENT_IDS, classify_dns_caller, split_dns_answers};
use super::fallback::{ETW_RETRY_INTERVAL, FallbackExit, IpHelperFallback, interface_stats};
use super::network::{
    CONNID_CACHE_CAPACITY, CONNID_RETENTION, ConnIdCache, DecodedNetwork, NetworkAttribution,
    NetworkClass, PROCESS_REANNOUNCE, ProcessAnnouncements, TCP_EVENT_IDS, TcpPidMetrics,
    classify_network_opcode, emit_decoded, orient_network_key, prefer_flow_owner,
    tuple_is_reversed,
};
use super::session::{
    ProcessingWorker, SessionOwner, SessionOwners, classify_trace_error, etw_trace_properties,
    failed_start_may_own_session, is_session_collision, stop_stale_session,
};
use super::*;
use crate::owner_module::OwnedSocket;
use ferrisetw::native::EvntraceNativeError;
use ferrisetw::trace::TraceError;
use netmetrics_core::{
    DnsCallerIdentity, FlowKey, ProcessIdentity, ProcessInfo, TcpPidAttributionSample,
};
use netmetrics_sys::BackendErrorKind;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::AtomicU64;
use std::sync::mpsc::{self, Receiver};
use std::thread;

#[test]
fn a_flow_owner_identity_is_announced_once_until_it_changes_or_goes_stale() {
    let (sender, receiver) = mpsc::sync_channel(16);
    let sink = EventSink::new(sender, Arc::new(AtomicU64::new(0)));
    let mut announced = ProcessAnnouncements::default();
    let process = |start_ts| ProcessInfo {
        pid: 42,
        identity: ProcessIdentity {
            executable: r"C:\app.exe".to_owned(),
            name: "app.exe".to_owned(),
            start_ts,
        },
    };
    let packet = |start_ts| DecodedNetwork {
        event: BackendEvent::ProcessStopped {
            pid: 1,
            timestamp: 0,
            identity: None,
        },
        process: Some(process(start_ts)),
    };
    let starts = |receiver: &Receiver<BackendEvent>| {
        receiver
            .try_iter()
            .filter(|event| matches!(event, BackendEvent::ProcessStarted(_)))
            .count()
    };
    for _ in 0..3 {
        emit_decoded(&sink, packet(10), &mut announced);
    }
    assert_eq!(
        starts(&receiver),
        1,
        "repeats of one identity are suppressed"
    );
    emit_decoded(&sink, packet(20), &mut announced);
    assert_eq!(
        starts(&receiver),
        1,
        "a reused PID's new identity is announced"
    );

    let earlier = Instant::now()
        .checked_sub(PROCESS_REANNOUNCE)
        .expect("monotonic clock past the re-announce interval");
    announced.record(process(20), earlier);
    emit_decoded(&sink, packet(20), &mut announced);
    assert_eq!(starts(&receiver), 1, "a stale announcement is repeated");
}

#[test]
fn a_rejected_announcement_is_retried_on_the_next_packet() {
    let (sender, receiver) = mpsc::sync_channel(0);
    let sink = EventSink::new(sender, Arc::new(AtomicU64::new(0)));
    let mut announced = ProcessAnnouncements::default();
    let process = ProcessInfo {
        pid: 42,
        identity: ProcessIdentity {
            executable: r"C:\app.exe".to_owned(),
            name: "app.exe".to_owned(),
            start_ts: 10,
        },
    };
    emit_decoded(
        &sink,
        DecodedNetwork {
            event: BackendEvent::ProcessStopped {
                pid: 1,
                timestamp: 0,
                identity: None,
            },
            process: Some(process.clone()),
        },
        &mut announced,
    );
    drop(receiver);
    assert!(announced.is_due(&process, Instant::now()));
}

#[test]
fn ip_helper_fallback_yields_to_etw_retries_without_reannouncing_sockets() {
    // An established connection of our own, so the owner table has a known row.
    let listener = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("listen");
    let client =
        std::net::TcpStream::connect(listener.local_addr().expect("addr")).expect("connect");
    let _accepted = listener.accept().expect("accept");
    let ours = client.local_addr().expect("client addr");

    let (sender, receiver) = mpsc::sync_channel(65_536);
    let sink = EventSink::new(sender, Arc::new(AtomicU64::new(0)));
    let config = BackendConfig {
        session_name: "test".to_owned(),
        buffer_mb: 1,
        poll_interval_ms: 250,
        dns_hints: false,
    };
    let stop = StopFlag::new();
    let mut fallback = IpHelperFallback::default();
    let opened_ours = |events: &[BackendEvent]| {
        events
            .iter()
            .filter(|event| {
                matches!(event, BackendEvent::Opened { key, .. }
                    if key.local_port == ours.port() && key.local_addr == ours.ip())
            })
            .count()
    };
    let snapshot_only = |events: &[BackendEvent]| {
        events
            .iter()
            .filter(|event| {
                matches!(
                    event,
                    BackendEvent::Degraded(DegradeReason::SnapshotOnly { .. })
                )
            })
            .count()
    };

    let exit = fallback
        .run(&config, &sink, &stop, Duration::ZERO)
        .expect("first cycle");
    assert_eq!(
        exit,
        FallbackExit::RetryEtw,
        "an elapsed interval hands back to ETW"
    );
    let first: Vec<_> = receiver.try_iter().collect();
    assert_eq!(opened_ours(&first), 1);
    assert_eq!(snapshot_only(&first), 1);

    let exit = fallback
        .run(&config, &sink, &stop, Duration::ZERO)
        .expect("second cycle");
    assert_eq!(exit, FallbackExit::RetryEtw);
    let second: Vec<_> = receiver.try_iter().collect();
    assert_eq!(
        opened_ours(&second),
        0,
        "a known socket is not announced again"
    );
    assert_eq!(
        snapshot_only(&second),
        0,
        "snapshot-only mode is announced once"
    );

    stop.stop();
    assert_eq!(
        fallback
            .run(&config, &sink, &stop, ETW_RETRY_INTERVAL)
            .expect("stopped"),
        FallbackExit::Stopped
    );
}

#[test]
fn flow_cache_supplies_image_for_matching_payload_pid() {
    let cache = Mutex::new(crate::flow_owner::FlowOwnerCache::default());
    let key = network_key(443);
    let now = Instant::now();
    cache.lock().expect("cache").insert(
        key,
        crate::flow_owner::FlowOwner {
            pid: 42,
            executable: r"C:\apps\short-lived.exe".to_owned(),
            name: "short-lived.exe".to_owned(),
            start_ts: 9,
        },
        now,
    );
    let snapshot = Some((42, None));
    let (owner, process) = prefer_flow_owner(42, &key, snapshot, &cache, now);
    assert_eq!(owner, snapshot);
    let process = process.expect("captured image must remain usable with a payload PID");
    assert_eq!(process.pid, 42);
    assert_eq!(process.identity.executable, r"C:\apps\short-lived.exe");
    assert_eq!(process.identity.start_ts, 9);
    let (_, conflicting) = prefer_flow_owner(42, &key, Some((7, None)), &cache, now);
    assert!(conflicting.is_none());
    let (_, expired) = prefer_flow_owner(42, &key, snapshot, &cache, now + Duration::from_secs(31));
    assert!(expired.is_none());
}

#[test]
fn flow_cache_supplies_pid_and_process_when_payload_pid_is_missing() {
    let cache = Mutex::new(crate::flow_owner::FlowOwnerCache::default());
    let key = network_key(443);
    cache.lock().expect("cache").insert(
        key,
        crate::flow_owner::FlowOwner {
            pid: 42,
            executable: r"C:\apps\browser.exe".to_owned(),
            name: "browser.exe".to_owned(),
            start_ts: 9,
        },
        Instant::now(),
    );
    let snapshot = Some((7, None));
    let (owner, process) = prefer_flow_owner(0, &key, snapshot, &cache, Instant::now());
    assert_eq!(owner.map(|(pid, _)| pid), Some(42));
    let process = process.expect("process identity");
    assert_eq!(process.pid, 42);
    assert_eq!(process.identity.executable, r"C:\apps\browser.exe");
    let (payload_owner, payload_process) =
        prefer_flow_owner(11, &key, snapshot, &cache, Instant::now());
    assert_eq!(payload_owner.map(|(pid, _)| pid), Some(7));
    assert!(payload_process.is_none());
}

#[test]
fn a_snapshot_cookie_never_attaches_to_a_different_owner() {
    let cookie = |value| {
        Some(netmetrics_core::SocketCookie {
            value,
            source: netmetrics_core::CookieSource::WindowsCreateTimestamp,
        })
    };
    let cache = Mutex::new(crate::flow_owner::FlowOwnerCache::default());
    let key = network_key(443);
    let now = Instant::now();
    cache.lock().expect("cache").insert(
        key,
        crate::flow_owner::FlowOwner {
            pid: 42,
            executable: String::new(),
            name: String::new(),
            start_ts: 0,
        },
        now,
    );
    let (owner, _) = prefer_flow_owner(0, &key, Some((7, cookie(700))), &cache, now);
    assert_eq!(
        owner,
        Some((42, None)),
        "FLOW's owner keeps no foreign cookie"
    );
    let (owner, _) = prefer_flow_owner(0, &key, Some((42, cookie(420))), &cache, now);
    assert_eq!(owner, Some((42, cookie(420))));

    let mut connids = ConnIdCache::default();
    let conflicting = connids.observe(Some(1), &key, 42, Some((7, cookie(700))), now);
    assert_eq!((conflicting.pid, conflicting.cookie), (42, None));
    let agreeing = connids.observe(Some(1), &key, 42, Some((42, cookie(420))), now);
    assert_eq!((agreeing.pid, agreeing.cookie), (42, cookie(420)));
    let remembered = connids.observe(Some(1), &key, 42, Some((7, cookie(700))), now);
    assert_eq!(
        (remembered.pid, remembered.cookie),
        (42, cookie(420)),
        "the connection's own cookie survives a conflicting snapshot"
    );
}

#[test]
fn classifies_every_documented_network_opcode() {
    for opcode in TCP_EVENT_IDS {
        assert!(
            classify_network_opcode(Protocol::Tcp, opcode).is_some(),
            "{opcode}"
        );
    }
    for opcode in [10_u8, 11, 26, 27] {
        let class = classify_network_opcode(Protocol::Udp, opcode);
        assert!(
            matches!(
                class,
                Some(NetworkClass::Bytes {
                    protocol: Protocol::Udp,
                    ..
                })
            ),
            "{opcode}"
        );
    }
    assert!(classify_network_opcode(Protocol::Tcp, 255).is_none());
    assert!(classify_network_opcode(Protocol::Udp, 42).is_none());
}

fn network_key(remote_port: u16) -> FlowKey {
    FlowKey {
        protocol: Protocol::Tcp,
        local_addr: "10.0.0.2".parse().unwrap(),
        local_port: 51_000,
        remote_addr: "203.0.113.7".parse().unwrap(),
        remote_port,
    }
}

fn test_cookie(key: FlowKey, pid: u32, created: i64) -> netmetrics_core::SocketCookie {
    OwnedSocket { key, pid, created }.cookie()
}

#[test]
fn connid_supplies_a_missing_payload_pid_from_the_same_connection() {
    let mut cache = ConnIdCache::default();
    let now = Instant::now();
    let key = network_key(443);
    let cookie = test_cookie(key, 42, 100);

    assert_eq!(
        cache.observe(Some(7), &key, 42, Some((42, Some(cookie))), now),
        NetworkAttribution {
            pid: 42,
            cookie: Some(cookie),
            recovered: false,
        }
    );
    // A later byte event lost its payload PID and missed the owner table;
    // the connection id supplies both the PID and the cookie.
    assert_eq!(
        cache.observe(Some(7), &key, 0, None, now),
        NetworkAttribution {
            pid: 42,
            cookie: Some(cookie),
            recovered: true,
        }
    );
}

#[test]
fn per_event_owner_wins_over_the_cached_connection_owner() {
    let mut cache = ConnIdCache::default();
    let now = Instant::now();
    let key = network_key(443);
    cache.observe(
        Some(7),
        &key,
        42,
        Some((42, Some(test_cookie(key, 42, 100)))),
        now,
    );

    let replacement = test_cookie(key, 99, 500);
    assert_eq!(
        cache.observe(Some(7), &key, 0, Some((99, Some(replacement))), now),
        NetworkAttribution {
            pid: 99,
            cookie: Some(replacement),
            recovered: true,
        }
    );
    assert_eq!(cache.observe(Some(7), &key, 0, None, now).pid, 99);
}

#[test]
fn payload_pid_keeps_the_connections_remembered_cookie() {
    let mut cache = ConnIdCache::default();
    let now = Instant::now();
    let key = network_key(443);
    let cookie = test_cookie(key, 42, 100);
    cache.observe(Some(7), &key, 42, Some((42, Some(cookie))), now);

    assert_eq!(
        cache.observe(Some(7), &key, 42, None, now),
        NetworkAttribution {
            pid: 42,
            cookie: Some(cookie),
            recovered: false,
        }
    );
}

#[test]
fn payload_pid_change_drops_the_previous_sockets_cookie() {
    let mut cache = ConnIdCache::default();
    let now = Instant::now();
    let key = network_key(443);
    let old_cookie = test_cookie(key, 42, 100);
    cache.observe(Some(7), &key, 42, Some((42, Some(old_cookie))), now);

    assert_eq!(
        cache.observe(Some(7), &key, 99, None, now),
        NetworkAttribution {
            pid: 99,
            cookie: None,
            recovered: false,
        }
    );
    assert_eq!(
        cache.observe(Some(7), &key, 0, None, now),
        NetworkAttribution {
            pid: 99,
            cookie: None,
            recovered: true,
        }
    );
}

#[test]
fn connid_refresh_extends_retention_without_growing_the_expiration_queue() {
    let mut cache = ConnIdCache::default();
    let key = network_key(443);
    let start = Instant::now();
    cache.observe(Some(1), &key, 42, None, start);
    for _ in 0..10_000 {
        cache.observe(Some(1), &key, 42, None, start);
    }
    assert_eq!(cache.entries.len(), 1);
    assert_eq!(cache.entries.deadline_count(), 1);

    let refreshed = start + Duration::from_secs(20);
    cache.observe(Some(1), &key, 42, None, refreshed);
    assert_eq!(cache.entries.deadline_count(), 1);

    let still_live_at = start + CONNID_RETENTION + Duration::from_secs(1);
    let still_live = cache.observe(Some(1), &key, 0, None, still_live_at);
    assert_eq!(still_live.pid, 42);
    assert_eq!(cache.entries.deadline_count(), 1);

    let expired = cache.observe(
        Some(1),
        &key,
        0,
        None,
        still_live_at + CONNID_RETENTION + Duration::from_millis(1),
    );
    assert_eq!(expired.pid, 0);
    assert!(cache.entries.is_empty());
}

#[test]
fn connid_mappings_expire() {
    let mut cache = ConnIdCache::default();
    let key = network_key(443);
    let start = Instant::now();
    cache.observe(Some(1), &key, 42, None, start);

    let expired = cache.observe(
        Some(1),
        &key,
        0,
        None,
        start + CONNID_RETENTION + Duration::from_millis(1),
    );
    assert_eq!(
        expired,
        NetworkAttribution {
            pid: 0,
            cookie: None,
            recovered: false,
        }
    );
}

#[test]
fn connid_mappings_are_bounded() {
    let mut cache = ConnIdCache::default();
    let key = network_key(443);
    let now = Instant::now();
    for connid in 1..=u64::try_from(CONNID_CACHE_CAPACITY).unwrap() + 64 {
        cache.observe(Some(connid), &key, 42, None, now);
    }
    assert!(cache.entries.len() <= CONNID_CACHE_CAPACITY);
    assert!(cache.entries.deadline_count() <= CONNID_CACHE_CAPACITY);
}

#[test]
fn connid_refresh_cannot_hide_an_expired_owner_behind_a_later_deadline() {
    let mut cache = ConnIdCache::default();
    let key = network_key(443);
    let start = Instant::now();
    let cookie = test_cookie(network_key(443), 42, 100);
    cache.observe(Some(1), &key, 42, Some((42, Some(cookie))), start);
    cache.observe(Some(2), &key, 43, None, start + Duration::from_secs(1));
    cache.observe(Some(1), &key, 42, None, start + Duration::from_secs(29));
    cache.observe(
        Some(3),
        &key,
        44,
        None,
        start + Duration::from_millis(29_500),
    );
    cache.entries.expire(start + Duration::from_secs(30));
    cache.entries.expire(start + Duration::from_secs(31));

    let owner = cache.observe(
        Some(1),
        &key,
        0,
        None,
        start + Duration::from_millis(59_100),
    );
    assert_eq!(
        owner,
        NetworkAttribution {
            pid: 0,
            cookie: None,
            recovered: false
        }
    );
    assert_eq!(cache.entries.len(), 1, "only the later connection survives");
}

#[test]
fn recycled_connid_does_not_keep_the_previous_flows_pid() {
    let mut cache = ConnIdCache::default();
    let now = Instant::now();
    let first = network_key(443);
    let second = network_key(8443);
    cache.observe(Some(7), &first, 42, None, now);
    assert_eq!(
        cache.observe(Some(7), &second, 0, None, now),
        NetworkAttribution {
            pid: 0,
            cookie: None,
            recovered: false,
        }
    );
    assert_eq!(cache.observe(Some(7), &first, 0, None, now).pid, 42);
}

#[test]
fn udp_connid_follows_the_local_socket_across_remotes() {
    let mut cache = ConnIdCache::default();
    let now = Instant::now();
    let mut first = network_key(53);
    first.protocol = Protocol::Udp;
    let mut second = first;
    second.remote_addr = "203.0.113.8".parse().unwrap();
    let mut other_socket = first;
    other_socket.local_port = 51_001;
    cache.observe(Some(7), &first, 42, None, now);
    assert_eq!(cache.observe(Some(7), &second, 0, None, now).pid, 42);
    assert_eq!(cache.observe(Some(7), &other_socket, 0, None, now).pid, 0);
}

#[test]
fn absent_connid_leaves_attribution_to_owner_evidence() {
    let mut cache = ConnIdCache::default();
    let key = network_key(443);
    let now = Instant::now();
    assert_eq!(
        cache.observe(None, &key, 0, None, now),
        NetworkAttribution {
            pid: 0,
            cookie: None,
            recovered: false,
        }
    );
    assert_eq!(
        cache.observe(None, &key, 0, Some((42, None)), now),
        NetworkAttribution {
            pid: 42,
            cookie: None,
            recovered: true,
        }
    );
}

#[test]
fn reconnect_and_copy_are_attribution_observations() {
    for (opcode, ipv6, reverse) in [
        (16, false, false),
        (32, true, false),
        (18, false, false),
        (34, true, false),
    ] {
        assert_eq!(
            classify_network_opcode(Protocol::Tcp, opcode),
            Some(NetworkClass::Open {
                protocol: Protocol::Tcp,
                ipv6,
                reverse
            })
        );
        let metrics = TcpPidMetrics::new();
        metrics.observe(opcode, 2, 42);
        assert_eq!(metrics.snapshot()[0].event_id, opcode);
    }
}

#[test]
fn udp_receive_first_uses_the_destination_as_local_bind() {
    for (opcode, local, remote) in [
        (11, "192.0.2.1", "198.51.100.1"),
        (27, "2001:db8::1", "2001:db8::2"),
    ] {
        let wire = FlowKey {
            protocol: Protocol::Udp,
            local_addr: remote.parse().unwrap(),
            local_port: 9999,
            remote_addr: local.parse().unwrap(),
            remote_port: 12345,
        };
        let class = classify_network_opcode(Protocol::Udp, opcode).expect("UDP receive");
        let key = orient_network_key(wire, tuple_is_reversed(class));
        let mut owners = netmetrics_core::SocketOwnerSnapshot::default();
        owners.insert_udp(
            netmetrics_core::LocalEndpoint {
                address: key.local_addr,
                port: 12345,
            },
            42,
        );
        assert_eq!(owners.lookup_owner_pid(&key), Some(42));
        assert_eq!(key.local_addr, local.parse::<IpAddr>().unwrap());
        assert_eq!(key.local_port, 12345);
    }
}

#[test]
fn tcp_accept_keeps_saddr_as_the_local_listener() {
    for (opcode, local, remote) in [
        (15, "192.0.2.1", "198.51.100.1"),
        (31, "2001:db8::1", "2001:db8::2"),
    ] {
        let wire = FlowKey {
            protocol: Protocol::Tcp,
            local_addr: local.parse().unwrap(),
            local_port: 53,
            remote_addr: remote.parse().unwrap(),
            remote_port: 51_000,
        };
        let class = classify_network_opcode(Protocol::Tcp, opcode).expect("TCP accept");
        let key = orient_network_key(wire, tuple_is_reversed(class));
        assert_eq!(key.local_addr, local.parse::<IpAddr>().unwrap());
        assert_eq!(key.local_port, 53);
        let mut owners = netmetrics_core::SocketOwnerSnapshot::default();
        owners.insert_tcp_listener(
            netmetrics_core::LocalEndpoint {
                address: key.local_addr,
                port: key.local_port,
            },
            42,
        );
        assert_eq!(owners.lookup_owner_pid(&key), Some(42));
    }
}

#[test]
fn tcp_recv_keeps_saddr_as_local_so_upstream_dns_is_not_inverted() {
    for (opcode, local, remote) in [
        (11, "192.168.68.50", "9.9.9.9"),
        (27, "2001:db8::1", "2001:db8::2"),
    ] {
        let wire = FlowKey {
            protocol: Protocol::Tcp,
            local_addr: local.parse().unwrap(),
            local_port: 52_946,
            remote_addr: remote.parse().unwrap(),
            remote_port: 53,
        };
        let class = classify_network_opcode(Protocol::Tcp, opcode).expect("TCP recv");
        assert!(
            matches!(class, NetworkClass::Bytes { received: true, .. }),
            "{opcode} must still count as received bytes"
        );
        let key = orient_network_key(wire, tuple_is_reversed(class));
        assert_eq!(key.local_addr, local.parse::<IpAddr>().unwrap());
        assert_eq!(key.local_port, 52_946);
        assert_eq!(key.remote_addr, remote.parse::<IpAddr>().unwrap());
        assert_eq!(key.remote_port, 53);

        let mut owners = netmetrics_core::SocketOwnerSnapshot::default();
        owners.insert_tcp(key, 4242);
        owners.insert_tcp_listener(
            netmetrics_core::LocalEndpoint {
                address: IpAddr::V4(Ipv4Addr::LOCALHOST),
                port: 53,
            },
            7,
        );
        assert_eq!(
            owners.lookup_owner_pid(&key),
            Some(4242),
            "a loopback DNS listener must not claim an outbound resolver flow"
        );

        let mut listener_only = netmetrics_core::SocketOwnerSnapshot::default();
        listener_only.insert_tcp_listener(
            netmetrics_core::LocalEndpoint {
                address: IpAddr::V4(Ipv4Addr::LOCALHOST),
                port: 53,
            },
            7,
        );
        assert_eq!(
            listener_only.lookup_owner_pid(&key),
            None,
            "recv-first outbound DNS with no established row stays unknown"
        );
    }
}

#[test]
fn udp_metrics_partition_missing_and_recovered_payloads() {
    let metrics = TcpPidMetrics::new();
    for opcode in [10, 11, 26, 27] {
        metrics.observe(opcode, 2, 42);
        metrics.observe(opcode, 2, 0);
        metrics.observe(opcode, 2, 0);
        metrics.recover(opcode, 2);
    }
    for sample in metrics.snapshot() {
        assert_eq!(
            (sample.observed, sample.missing, sample.recovered),
            (3, 2, 1)
        );
    }
}

#[test]
fn tcp_pid_metrics_are_partitioned_by_event_id_and_version() {
    let metrics = TcpPidMetrics::new();
    metrics.observe(12, 2, 4242);
    metrics.observe(12, 2, 0);
    metrics.observe(12, 2, 0);
    metrics.recover(12, 2);
    metrics.observe(28, 1, 0);

    assert_eq!(
        metrics.snapshot(),
        vec![
            TcpPidAttributionSample {
                event_id: 12,
                event_version: 2,
                observed: 3,
                missing: 2,
                recovered: 1,
            },
            TcpPidAttributionSample {
                event_id: 28,
                event_version: 1,
                observed: 1,
                missing: 1,
                recovered: 0,
            },
        ]
    );
}

#[test]
fn dns_answer_parser_ignores_non_addresses() {
    assert_eq!(
        split_dns_answers("203.0.113.1;not-an-ip,2001:db8::1"),
        vec!["203.0.113.1", "2001:db8::1"]
    );
    assert_eq!(
        split_dns_answers("::ffff:203.0.113.5 TTL: 12"),
        vec!["203.0.113.5"]
    );
}

#[test]
fn dns_3008_v0_uses_header_pid_as_requester() {
    assert_eq!(
        classify_dns_caller(3008, 0, 4242, None),
        DnsCallerIdentity {
            logging_pid: Some(4242),
            requesting_pid: Some(4242),
            resolver_pid: None,
        }
    );
}

#[test]
fn dns_event_with_client_pid_keeps_header_as_logging_process_only() {
    assert_eq!(
        classify_dns_caller(3018, 2, 1000, Some(4242)),
        DnsCallerIdentity {
            logging_pid: Some(1000),
            requesting_pid: Some(4242),
            resolver_pid: None,
        }
    );
}

#[test]
fn dns_event_without_supported_pid_semantics_remains_unattributed() {
    assert_eq!(
        classify_dns_caller(3018, 0, 1000, None),
        DnsCallerIdentity {
            logging_pid: Some(1000),
            requesting_pid: None,
            resolver_pid: None,
        }
    );
}

/// Outcome and error events carry the same explicit `ClientPID` as the
/// completion schemas, so a blocked NXDOMAIN/NODATA/timeout still names the
/// requesting process even when the request/completion pair was missed.
#[test]
fn dns_outcome_events_supply_explicit_caller_evidence() {
    for event_id in [1013, 1015, 1016, 1017, 1018, 1027, 3012, 3023] {
        assert!(
            DNS_CLIENT_EVENT_IDS.contains(&event_id),
            "event {event_id} must be decoded for caller evidence"
        );
        assert_eq!(
            classify_dns_caller(event_id, 0, 1000, Some(4242)),
            DnsCallerIdentity {
                logging_pid: Some(1000),
                requesting_pid: Some(4242),
                resolver_pid: None,
            }
        );
    }
}

#[test]
fn access_errors_are_normalized() {
    let error = classify_trace_error("ETW", "Access is denied");
    assert_eq!(error.kind, BackendErrorKind::PermissionDenied);
}

#[test]
fn stale_recovery_only_handles_already_existing_sessions() {
    assert!(is_session_collision(&TraceError::EtwNativeError(
        EvntraceNativeError::AlreadyExist
    )));
    assert!(!is_session_collision(&TraceError::InvalidTraceName));
    assert!(!failed_start_may_own_session(&TraceError::InvalidTraceName));
    assert!(!failed_start_may_own_session(&TraceError::EtwNativeError(
        EvntraceNativeError::AlreadyExist
    )));
    assert!(failed_start_may_own_session(&TraceError::EtwNativeError(
        EvntraceNativeError::InvalidHandle
    )));
}

#[test]
fn processing_worker_exposes_success_and_failure() {
    for expected in [Ok(()), Err("process trace failed".to_owned())] {
        let returned = expected.clone();
        let worker = ProcessingWorker::spawn_job("netmetrics-worker-test", move || returned)
            .expect("worker starts");
        let deadline = Instant::now() + Duration::from_secs(1);
        let observed = loop {
            if let Some(result) = worker.poll() {
                break result;
            }
            assert!(
                Instant::now() < deadline,
                "worker did not report completion"
            );
            thread::yield_now();
        };
        assert_eq!(observed, expected);
        worker.join().expect("worker joins");
    }
}

#[test]
fn etw_logger_names_stay_inside_the_netmetrics_prefix() {
    let names = SessionNames::new("Antiwire-Net", true).unwrap();
    assert_eq!(names.kernel(), "netmetrics-Antiwire-Net");
    assert_eq!(names.dns(), Some("netmetrics-Antiwire-Net-dns"));
    let default_names = SessionNames::new("netmetrics", true).unwrap();
    assert_eq!(default_names.kernel(), "netmetrics");
    assert_eq!(default_names.dns(), Some("netmetrics-dns"));
    let owners = SessionOwners::acquire(&names).unwrap();
    assert_eq!(stop_stale_session(&owners, "NT Kernel Logger"), 4201);
}

#[test]
fn derived_aliases_contend_for_the_same_live_owner() {
    let first = SessionNames::new("owner-alias", true).unwrap();
    let kernel_alias = SessionNames::new("NETMETRICS-OWNER-ALIAS", false).unwrap();
    let dns_alias = SessionNames::new("owner-alias-dns", false).unwrap();
    let (ready_sender, ready_receiver) = std::sync::mpsc::channel();
    let (release_sender, release_receiver) = std::sync::mpsc::channel();
    let worker = thread::spawn(move || {
        let _owners = SessionOwners::acquire(&first).expect("first owner");
        ready_sender.send(()).unwrap();
        release_receiver.recv().unwrap();
    });
    ready_receiver.recv().unwrap();
    assert!(SessionOwners::acquire(&kernel_alias).is_err());
    assert!(SessionOwners::acquire(&dns_alias).is_err());
    release_sender.send(()).unwrap();
    worker.join().unwrap();
}

#[test]
fn live_session_owner_cannot_be_displaced() {
    let session_name = format!(
        "netmetrics-owner-test-{}-{}",
        std::process::id(),
        unix_now_ms()
    );
    let worker_name = session_name.clone();
    let (ready_sender, ready_receiver) = std::sync::mpsc::channel();
    let (release_sender, release_receiver) = std::sync::mpsc::channel();
    let worker = thread::spawn(move || {
        let _owner = SessionOwner::acquire(&worker_name).expect("first owner");
        ready_sender.send(()).expect("ready signal");
        release_receiver.recv().expect("release signal");
    });
    ready_receiver.recv().expect("owner ready");
    assert!(SessionOwner::acquire(&session_name).is_err());
    release_sender.send(()).expect("release owner");
    worker.join().expect("owner worker");
    assert!(SessionOwner::acquire(&session_name).is_ok());
}

#[test]
fn session_lock_failure_uses_ip_helper_instead_of_exiting() {
    let session_name = format!(
        "netmetrics-fallback-{}-{}",
        std::process::id(),
        unix_now_ms()
    );
    let _owner = SessionOwner::acquire(&session_name).expect("live owner");
    let (sender, receiver) = std::sync::mpsc::sync_channel(256);
    let sink = EventSink::new(sender, Arc::new(AtomicU64::new(0)));
    let stop = StopFlag::new();
    let config = BackendConfig {
        session_name,
        buffer_mb: 8,
        poll_interval_ms: 250,
        dns_hints: false,
    };
    let worker_stop = stop.clone();
    let worker = thread::spawn(move || WindowsBackend.run(&config, sink, worker_stop));

    let deadline = Instant::now() + Duration::from_secs(3);
    let mut saw_lock_failure = false;
    let mut saw_fallback = false;
    while Instant::now() < deadline && !(saw_lock_failure && saw_fallback) {
        let Ok(event) = receiver.recv_timeout(Duration::from_millis(50)) else {
            continue;
        };
        match event {
            BackendEvent::Degraded(DegradeReason::SourceUnavailable { source, .. })
                if source == "windows-etw-session" =>
            {
                saw_lock_failure = true;
            }
            BackendEvent::Degraded(DegradeReason::SnapshotOnly { source })
                if source == "windows-ip-helper" =>
            {
                saw_fallback = true;
            }
            _ => {}
        }
    }
    stop.stop();
    worker
        .join()
        .expect("backend thread")
        .expect("fallback run");
    assert!(saw_lock_failure, "mutex failure should be reported");
    assert!(saw_fallback, "IP Helper fallback should run");
}

#[test]
fn etw_total_buffer_hint_is_bounded() {
    let properties = etw_trace_properties(32);
    assert_eq!(properties.buffer_size, 64);
    assert_eq!(properties.min_buffer, 512);
    assert_eq!(etw_trace_properties(u32::MAX).max_buffer, 1024);
}

#[test]
fn ip_helper_interface_query_is_well_formed() {
    let samples = interface_stats(7).expect("GetIfTable2 should be available");
    assert!(!samples.is_empty());
    assert!(samples.iter().all(|sample| sample.timestamp == 7));
}

/// A flow whose kernel event names another process than the one recorded at
/// establishment is kept with both, once however many events repeat it, so
/// the cause can be told from the log.
#[test]
fn a_flow_whose_owner_sources_disagree_is_noted_once_with_both_processes() {
    let key = FlowKey {
        protocol: Protocol::Tcp,
        local_addr: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 77)),
        local_port: 51_777,
        remote_addr: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 77)),
        remote_port: 443,
    };
    let cache = Mutex::new(crate::flow_owner::FlowOwnerCache::default());
    let recorded = Instant::now();
    cache.lock().expect("cache").insert(
        key.reverse(),
        crate::flow_owner::FlowOwner {
            pid: 4_242,
            executable: r"C:\apps\other-end.exe".to_owned(),
            name: "other-end.exe".to_owned(),
            start_ts: 9,
        },
        recorded,
    );
    let later = recorded + Duration::from_millis(1_500);
    for _ in 0..3 {
        let (owner, _) = prefer_flow_owner(7_777, &key, None, &cache, later);
        assert_eq!(owner, None, "the event's own PID still stands");
    }
    // An event that agrees with the record is not a disagreement.
    let _ = prefer_flow_owner(4_242, &key, None, &cache, later);

    // Other tests share the list; this flow's addresses are its own.
    let noted: Vec<_> = super::network::take_owner_disagreements()
        .into_iter()
        .filter(|noted| noted.key == key)
        .collect();
    assert_eq!(noted.len(), 1, "{noted:?}");
    let noted = &noted[0];
    assert_eq!((noted.event_pid, noted.recorded_pid), (7_777, 4_242));
    assert_eq!(noted.recorded_executable, r"C:\apps\other-end.exe");
    assert!(noted.reversed, "the record is the other end's");
    assert_eq!(noted.record_age_ms, 1_500);
    assert_eq!(noted.events, 3);
}

/// The regression this guards: the owner lookup falls back to the flow's
/// addresses swapped. Between two endpoints on this host that record is the
/// process at the other end, and an event that carried no PID of its own was
/// given it, so a resolver's side of a loopback query could be attributed to
/// the client that sent it. With a PID on the event the pair was counted as
/// a disagreement, though each was right about its own end.
#[test]
fn the_other_ends_record_is_not_this_ends_owner_between_local_endpoints() {
    let loopback = IpAddr::V6(std::net::Ipv6Addr::LOCALHOST);
    let server_side = FlowKey {
        protocol: Protocol::Udp,
        local_addr: loopback,
        local_port: 53,
        remote_addr: loopback,
        remote_port: 59_702,
    };
    let cache = Mutex::new(crate::flow_owner::FlowOwnerCache::default());
    let now = Instant::now();
    // Only the client's flow was recorded.
    cache.lock().expect("cache").insert(
        server_side.reverse(),
        crate::flow_owner::FlowOwner {
            pid: 3_128,
            executable: r"C:\apps\client.exe".to_owned(),
            name: "client.exe".to_owned(),
            start_ts: 9,
        },
        now,
    );

    let (owner, process) = prefer_flow_owner(0, &server_side, None, &cache, now);
    assert_eq!(owner, None, "the client does not own the server's end");
    assert!(process.is_none());
    let table = Some((21_612, None));
    let (owner, _) = prefer_flow_owner(0, &server_side, table, &cache, now);
    assert_eq!(owner, table, "the socket table still answers for this end");

    let _ = prefer_flow_owner(21_612, &server_side, None, &cache, now);
    assert!(
        super::network::take_owner_disagreements()
            .iter()
            .all(|noted| noted.key != server_side),
        "two ends with two owners do not disagree"
    );

    // The client's own events still find the client's record.
    let (owner, process) = prefer_flow_owner(0, &server_side.reverse(), None, &cache, now);
    assert_eq!(owner, Some((3_128, None)));
    assert!(process.is_some());

    // The same address at each end is local too, loopback or not.
    let lan = IpAddr::V4(Ipv4Addr::new(192, 168, 68, 50));
    let same_host = FlowKey {
        local_addr: lan,
        remote_addr: lan,
        ..server_side
    };
    cache.lock().expect("cache").insert(
        same_host.reverse(),
        crate::flow_owner::FlowOwner {
            pid: 3_128,
            executable: r"C:\apps\client.exe".to_owned(),
            name: "client.exe".to_owned(),
            start_ts: 9,
        },
        now,
    );
    assert_eq!(prefer_flow_owner(0, &same_host, None, &cache, now).0, None);
}
