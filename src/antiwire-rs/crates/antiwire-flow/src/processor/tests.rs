use super::*;
use crate::domain_stats::executable_key;
use crate::system_services;
use antiwire_events::NotificationHub;
use antiwire_platform::{SiemConfig, SiemExporter};
use antiwire_secrets::UnixSecureFileKeyProvider;
use antiwire_store::{ConnectionDomainUpgrade, Store};
use netmetrics_core::{FlowMeta, ProcessIdentity, Protocol};
use std::net::{IpAddr, Ipv4Addr};
use tempfile::tempdir;

/// The opening of the connection `log` describes, by a process whose start
/// time is unknown.
fn opening_of(log: &NewConnectionLog) -> Opening {
    Opening::at(u64::try_from(log.timestamp.unix_timestamp_nanos() / 1_000_000).unwrap_or(0))
}

/// What a lookup made as the connection `log` describes closed says of a
/// name it could not confirm.
fn unconfirmed(log: &NewConnectionLog) -> Naming {
    Naming {
        complete_at_ms: opening_of(log).at_ms + domain_names::HINTS_ARRIVE_WITHIN_MS,
        lasting: false,
    }
}

/// What the tracker's flush tick does for closed connections: those to an
/// address evidence has arrived for are looked up again, and the names that
/// changed are written.
fn settle_closed(processor: &FlowProcessor) {
    processor.settle_closed_names(&processor.take_newly_named());
}

fn sample_key() -> FlowKey {
    FlowKey {
        protocol: Protocol::Tcp,
        local_addr: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)),
        local_port: 50_000,
        remote_addr: IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
        remote_port: 443,
    }
}

fn test_processor(store: Arc<Store>, traffic_hub: TrafficStreamingHub) -> FlowProcessor {
    let alerts = AlertPublisher::unsaved(NotificationHub::with_capacity(4), None);
    let rule_engine = Arc::new(RwLock::new(RuleEngine::new()));
    let siem = SiemExporter::new(SiemConfig::default());
    FlowProcessor::new(
        Arc::new(AppIdResolver::new(
            Arc::clone(&store),
            alerts.clone(),
            SiemExporter::new(SiemConfig::default()),
        )),
        None,
        rule_engine,
        store,
        traffic_hub,
        alerts,
        siem,
    )
}

#[tokio::test]
async fn publishes_update_event_on_byte_delta() {
    let dir = tempdir().expect("tempdir");
    let keystore = UnixSecureFileKeyProvider::new(dir.path().join("key"));
    let store =
        Arc::new(Store::open_with_keystore(dir.path().join("db.sqlite"), &keystore).expect("open"));

    let traffic_hub = TrafficStreamingHub::with_capacity(4);
    let mut subscription = traffic_hub.subscribe();
    let processor = test_processor(store, traffic_hub.clone());
    let key = sample_key();

    processor.publish_byte_update(
        &key,
        &ByteDelta {
            sent: 512,
            received: 256,
        },
        "test.exe",
        r"C:\apps\test.exe",
        OffsetDateTime::now_utc(),
    );

    let event = subscription.recv().await.expect("traffic event");
    assert_eq!(event.action, "UPDATE");
    assert_eq!(event.app_name, "test.exe");
    assert_eq!(event.app_path, r"C:\apps\test.exe");
    assert_eq!(event.bytes_sent, 512);
    assert_eq!(event.bytes_received, 256);
    assert_eq!(traffic_hub.total_bytes_sent(), 512);
    assert_eq!(traffic_hub.total_bytes_received(), 256);
}

/// Totals must advance even when no gRPC stream is attached; only the event
/// allocation is skipped.
#[test]
fn byte_totals_advance_without_a_traffic_subscriber() {
    let dir = tempdir().expect("tempdir");
    let keystore = UnixSecureFileKeyProvider::new(dir.path().join("key"));
    let store =
        Arc::new(Store::open_with_keystore(dir.path().join("db.sqlite"), &keystore).expect("open"));
    let traffic_hub = TrafficStreamingHub::with_capacity(4);
    let processor = test_processor(store, traffic_hub.clone());

    processor.publish_byte_update(
        &sample_key(),
        &ByteDelta {
            sent: 512,
            received: 256,
        },
        "test.exe",
        r"C:\apps\test.exe",
        OffsetDateTime::now_utc(),
    );

    assert_eq!(traffic_hub.total_bytes_sent(), 512);
    assert_eq!(traffic_hub.total_bytes_received(), 256);
}

/// DNS answers are coalesced in memory and only reach SQLite on flush.
#[test]
fn dns_answers_are_buffered_until_the_flush() {
    let dir = tempdir().expect("tempdir");
    let keystore = UnixSecureFileKeyProvider::new(dir.path().join("key"));
    let store =
        Arc::new(Store::open_with_keystore(dir.path().join("db.sqlite"), &keystore).expect("open"));
    let processor = test_processor(Arc::clone(&store), TrafficStreamingHub::with_capacity(4));
    let ip = sample_key().remote_addr;
    let id = ip.to_string();

    processor.handle_event(&FlowEvent::DnsResolved {
        pid: 0,
        query: "buffered.example".to_owned(),
        answers: vec![id.clone()],
    });

    assert!(
        store.get_dns_cache(&id).expect("cache read").is_none(),
        "the answer must not be written before the flush"
    );
    // Lookups still see it immediately through the pending buffer.
    assert_eq!(
        processor.lookup_domain(9999, &ip),
        "buffered.example (inferred)"
    );

    processor.flush_dns_cache();

    assert_eq!(
        store
            .get_dns_cache(&id)
            .expect("cache read")
            .expect("row")
            .domain,
        "buffered.example"
    );
}

#[tokio::test]
async fn publishes_traffic_event_on_closed_flow() {
    let dir = tempdir().expect("tempdir");
    let keystore = UnixSecureFileKeyProvider::new(dir.path().join("key"));
    let store =
        Arc::new(Store::open_with_keystore(dir.path().join("db.sqlite"), &keystore).expect("open"));

    let traffic_hub = TrafficStreamingHub::with_capacity(4);
    let mut subscription = traffic_hub.subscribe();
    let processor = test_processor(store, traffic_hub.clone());

    let key = sample_key();
    let mut log = NewConnectionLog {
        replace_domain: false,
        is_close: true,
        conn_pid: 0,
        conn_id: 0,
        timestamp: OffsetDateTime::now_utc(),
        app_id: 1,
        app_path: String::new(),
        protocol: "TCP".to_owned(),
        src_ip: key.local_addr.to_string(),
        src_port: i32::from(key.local_port),
        dst_ip: key.remote_addr.to_string(),
        dst_port: i32::from(key.remote_port),
        dst_domain: "example.com".to_owned(),
        bytes_sent: 128,
        bytes_received: 64,
        action_taken: "ALLOWED".to_owned(),
        last_seen: OffsetDateTime::now_utc(),
        country_code: String::new(),
        isp: String::new(),
        blocklist_names: String::new(),
    };

    processor.enrich_connection_log(
        &key,
        0,
        r"C:\apps\test.exe",
        "test.exe",
        NameRequest::adding(opening_of(&log)),
        &mut log,
    );
    processor.publish_closed_flow(r"C:\apps\test.exe", "test.exe", &log);

    let event = subscription.recv().await.expect("traffic event");
    assert_eq!(event.app_name, "test.exe");
    assert_eq!(event.dst_domain, "example.com");
    assert_eq!(event.bytes_sent, 128);
    assert_eq!(event.bytes_received, 64);
    assert_eq!(event.closed_at, unix_secs(log.last_seen));
    log.is_close = false;
    assert_eq!(traffic_event_from_log("test.exe", "", &log).closed_at, 0);
}

#[test]
fn dns_resolution_updates_cache_for_enrichment() {
    let dir = tempdir().expect("tempdir");
    let keystore = UnixSecureFileKeyProvider::new(dir.path().join("key"));
    let store =
        Arc::new(Store::open_with_keystore(dir.path().join("db.sqlite"), &keystore).expect("open"));

    let traffic_hub = TrafficStreamingHub::with_capacity(4);
    let processor = test_processor(store, traffic_hub);
    let key = sample_key();

    let observed_at =
        u64::try_from((OffsetDateTime::now_utc().unix_timestamp_nanos() / 1_000_000).max(0))
            .unwrap_or(0);
    processor.handle_event(&FlowEvent::DnsResolvedWithMetadata {
        attribution: DnsResolutionAttribution::Process(1234),
        query: "example.com".to_owned(),
        answers: vec![key.remote_addr.to_string()],
        ttl_ms: 60_000,
        observed_at,
    });

    let mut log = NewConnectionLog {
        replace_domain: false,
        is_close: false,
        conn_pid: 0,
        conn_id: 0,
        timestamp: OffsetDateTime::now_utc(),
        app_id: 1,
        app_path: String::new(),
        protocol: "TCP".to_owned(),
        src_ip: key.local_addr.to_string(),
        src_port: i32::from(key.local_port),
        dst_ip: key.remote_addr.to_string(),
        dst_port: i32::from(key.remote_port),
        dst_domain: String::new(),
        bytes_sent: 0,
        bytes_received: 0,
        action_taken: "ALLOWED".to_owned(),
        last_seen: OffsetDateTime::now_utc(),
        country_code: String::new(),
        isp: String::new(),
        blocklist_names: String::new(),
    };

    // Query with matching PID 1234 gets process-scoped resolution without "(inferred)"
    processor.enrich_connection_log(
        &key,
        1234,
        "app.exe",
        "app.exe",
        NameRequest::adding(opening_of(&log)),
        &mut log,
    );
    assert_eq!(log.dst_domain, "example.com");
}

#[test]
fn shared_dns_hint_is_labeled_as_inferred() {
    let dir = tempdir().expect("tempdir");
    let keystore = UnixSecureFileKeyProvider::new(dir.path().join("key"));
    let store =
        Arc::new(Store::open_with_keystore(dir.path().join("db.sqlite"), &keystore).expect("open"));
    let processor = test_processor(store, TrafficStreamingHub::with_capacity(4));
    let key = sample_key();
    let observed_at =
        u64::try_from((OffsetDateTime::now_utc().unix_timestamp_nanos() / 1_000_000).max(0))
            .unwrap_or(0);

    processor.handle_event(&FlowEvent::DnsResolvedWithMetadata {
        attribution: DnsResolutionAttribution::Shared,
        query: "shared.example".to_owned(),
        answers: vec![key.remote_addr.to_string()],
        ttl_ms: 60_000,
        observed_at,
    });

    assert_eq!(
        processor.lookup_domain(4242, &key.remote_addr),
        "shared.example (inferred)"
    );
}

#[test]
fn ambiguous_dns_candidates_do_not_fall_back_to_a_single_global_name() {
    for attribution in [
        DnsResolutionAttribution::Process(1234),
        DnsResolutionAttribution::Shared,
    ] {
        let dir = tempdir().expect("tempdir");
        let keystore = UnixSecureFileKeyProvider::new(dir.path().join("key"));
        let store = Arc::new(
            Store::open_with_keystore(dir.path().join("db.sqlite"), &keystore).expect("open"),
        );
        let key = sample_key();
        store
            .upsert_dns_cache(&DnsCacheEntry {
                id: key.remote_addr.to_string(),
                domain: "persistent.example".to_owned(),
                last_seen: OffsetDateTime::now_utc(),
            })
            .expect("upsert");
        let processor = test_processor(store, TrafficStreamingHub::with_capacity(4));
        let observed_at =
            u64::try_from((OffsetDateTime::now_utc().unix_timestamp_nanos() / 1_000_000).max(0))
                .unwrap_or(0);
        for query in ["first.example", "second.example"] {
            processor.handle_event(&FlowEvent::DnsResolvedWithMetadata {
                attribution,
                query: query.to_owned(),
                answers: vec![key.remote_addr.to_string()],
                ttl_ms: 60_000,
                observed_at,
            });
        }
        assert_eq!(
            processor.lookup_domain(1234, &key.remote_addr),
            "",
            "ambiguous live candidates must not become one buffered global guess"
        );
        processor.flush_dns_cache();
        assert_eq!(
            processor.lookup_domain(1234, &key.remote_addr),
            "",
            "ambiguity must also prevent the persisted global fallback"
        );
    }
}

#[test]
fn discarded_live_candidates_block_global_fallback_after_retained_names_expire() {
    let dir = tempdir().expect("tempdir");
    let keystore = UnixSecureFileKeyProvider::new(dir.path().join("key"));
    let store =
        Arc::new(Store::open_with_keystore(dir.path().join("db.sqlite"), &keystore).expect("open"));
    let processor = test_processor(store, TrafficStreamingHub::with_capacity(4));
    let key = sample_key();
    let observed_at =
        u64::try_from((OffsetDateTime::now_utc().unix_timestamp_nanos() / 1_000_000).max(0))
            .unwrap_or(0)
            .saturating_sub(100);
    processor.handle_event(&FlowEvent::DnsResolvedWithMetadata {
        attribution: DnsResolutionAttribution::Process(1234),
        query: "discarded.example".to_owned(),
        answers: vec![key.remote_addr.to_string()],
        ttl_ms: 60_000,
        observed_at,
    });
    for index in 0..10 {
        processor.handle_event(&FlowEvent::DnsResolvedWithMetadata {
            attribution: DnsResolutionAttribution::Process(1234),
            query: format!("short-{index}.example"),
            answers: vec![key.remote_addr.to_string()],
            ttl_ms: 1,
            observed_at,
        });
    }
    assert_eq!(processor.lookup_domain(1234, &key.remote_addr), "");
    processor.flush_dns_cache();
    assert_eq!(processor.lookup_domain(1234, &key.remote_addr), "");
    processor.handle_event(&FlowEvent::DnsResolvedWithMetadata {
        attribution: DnsResolutionAttribution::Process(1234),
        query: "retained.example".to_owned(),
        answers: vec![key.remote_addr.to_string()],
        ttl_ms: 60_000,
        observed_at,
    });
    assert_eq!(processor.lookup_domain(1234, &key.remote_addr), "");
}

#[test]
fn process_hint_wins_over_persistent_inference() {
    let dir = tempdir().expect("tempdir");
    let keystore = UnixSecureFileKeyProvider::new(dir.path().join("key"));
    let store =
        Arc::new(Store::open_with_keystore(dir.path().join("db.sqlite"), &keystore).expect("open"));
    let key = sample_key();
    store
        .upsert_dns_cache(&DnsCacheEntry {
            id: key.remote_addr.to_string(),
            domain: "persistent.example".to_owned(),
            last_seen: OffsetDateTime::now_utc(),
        })
        .expect("upsert");
    let processor = test_processor(store, TrafficStreamingHub::with_capacity(4));
    let observed_at =
        u64::try_from((OffsetDateTime::now_utc().unix_timestamp_nanos() / 1_000_000).max(0))
            .unwrap_or(0);

    processor.handle_event(&FlowEvent::DnsResolvedWithMetadata {
        attribution: DnsResolutionAttribution::Process(1234),
        query: "live.example".to_owned(),
        answers: vec![key.remote_addr.to_string()],
        ttl_ms: 60_000,
        observed_at,
    });

    // The live process hint keeps priority and carries no inferred label,
    // even with a persistent mapping for the same address.
    assert_eq!(
        processor.lookup_domain(1234, &key.remote_addr),
        "live.example"
    );
}

#[test]
fn shared_hint_wins_over_persistent_inference() {
    let dir = tempdir().expect("tempdir");
    let keystore = UnixSecureFileKeyProvider::new(dir.path().join("key"));
    let store =
        Arc::new(Store::open_with_keystore(dir.path().join("db.sqlite"), &keystore).expect("open"));
    let key = sample_key();
    store
        .upsert_dns_cache(&DnsCacheEntry {
            id: key.remote_addr.to_string(),
            domain: "persistent.example".to_owned(),
            last_seen: OffsetDateTime::now_utc(),
        })
        .expect("upsert");
    let processor = test_processor(store, TrafficStreamingHub::with_capacity(4));
    let observed_at =
        u64::try_from((OffsetDateTime::now_utc().unix_timestamp_nanos() / 1_000_000).max(0))
            .unwrap_or(0);

    processor.handle_event(&FlowEvent::DnsResolvedWithMetadata {
        attribution: DnsResolutionAttribution::Shared,
        query: "shared.example".to_owned(),
        answers: vec![key.remote_addr.to_string()],
        ttl_ms: 60_000,
        observed_at,
    });

    assert_eq!(
        processor.lookup_domain(4242, &key.remote_addr),
        "shared.example (inferred)"
    );
}

#[test]
fn record_dns_resolution_batches_canonical_deduped_answers() {
    let dir = tempdir().expect("tempdir");
    let keystore = UnixSecureFileKeyProvider::new(dir.path().join("key"));
    let store =
        Arc::new(Store::open_with_keystore(dir.path().join("db.sqlite"), &keystore).expect("open"));
    let processor = test_processor(store, TrafficStreamingHub::with_capacity(4));

    processor.handle_event(&FlowEvent::DnsResolved {
        pid: 0,
        query: "batch.example".to_owned(),
        answers: vec![
            "93.184.216.34".to_owned(),
            "93.184.216.34".to_owned(),
            "not-an-ip".to_owned(),
            "2001:DB8::2".to_owned(),
        ],
    });

    let v4: IpAddr = "93.184.216.34".parse().expect("v4");
    let v6: IpAddr = "2001:db8::2".parse().expect("v6");
    assert_eq!(
        processor.lookup_domain(9999, &v4),
        "batch.example (inferred)"
    );
    assert_eq!(
        processor.lookup_domain(9999, &v6),
        "batch.example (inferred)"
    );
}

#[test]
fn persistent_inference_rejects_mappings_past_the_maximum_age() {
    let dir = tempdir().expect("tempdir");
    let keystore = UnixSecureFileKeyProvider::new(dir.path().join("key"));
    let store =
        Arc::new(Store::open_with_keystore(dir.path().join("db.sqlite"), &keystore).expect("open"));
    // Prime the retention gate so the old rows below persist until their
    // own assertions run instead of being purged by the first write.
    store
        .upsert_dns_cache(&DnsCacheEntry {
            id: "192.0.2.240".to_owned(),
            domain: "prime.example".to_owned(),
            last_seen: OffsetDateTime::now_utc(),
        })
        .expect("prime");
    let processor = test_processor(Arc::clone(&store), TrafficStreamingHub::with_capacity(4));
    let now = OffsetDateTime::now_utc();

    // 24h30m: the old whole-hours comparison admitted this (24 <= 24).
    let stale_ip: IpAddr = "192.0.2.241".parse().expect("ip");
    store
        .upsert_dns_cache(&DnsCacheEntry {
            id: stale_ip.to_string(),
            domain: "stale.example".to_owned(),
            last_seen: now - time::Duration::hours(24) - time::Duration::minutes(30),
        })
        .expect("upsert stale");
    assert_eq!(processor.lookup_domain(9999, &stale_ip), "");

    // Safely inside the window: still inferred.
    let fresh_ip: IpAddr = "192.0.2.242".parse().expect("ip");
    store
        .upsert_dns_cache(&DnsCacheEntry {
            id: fresh_ip.to_string(),
            domain: "fresh.example".to_owned(),
            last_seen: now - time::Duration::hours(23) - time::Duration::minutes(59),
        })
        .expect("upsert fresh");
    assert_eq!(
        processor.lookup_domain(9999, &fresh_ip),
        "fresh.example (inferred)"
    );
}

#[test]
fn persistent_inference_rejects_far_future_timestamps() {
    let dir = tempdir().expect("tempdir");
    let keystore = UnixSecureFileKeyProvider::new(dir.path().join("key"));
    let store =
        Arc::new(Store::open_with_keystore(dir.path().join("db.sqlite"), &keystore).expect("open"));
    store
        .upsert_dns_cache(&DnsCacheEntry {
            id: "192.0.2.240".to_owned(),
            domain: "prime.example".to_owned(),
            last_seen: OffsetDateTime::now_utc(),
        })
        .expect("prime");
    let processor = test_processor(Arc::clone(&store), TrafficStreamingHub::with_capacity(4));
    let now = OffsetDateTime::now_utc();

    // A minute of drift is tolerated...
    let drift_ip: IpAddr = "192.0.2.243".parse().expect("ip");
    store
        .upsert_dns_cache(&DnsCacheEntry {
            id: drift_ip.to_string(),
            domain: "drift.example".to_owned(),
            last_seen: now + time::Duration::minutes(1),
        })
        .expect("upsert drift");
    assert_eq!(
        processor.lookup_domain(9999, &drift_ip),
        "drift.example (inferred)"
    );

    // ...an hour is clock skew, not data.
    let skew_ip: IpAddr = "192.0.2.244".parse().expect("ip");
    store
        .upsert_dns_cache(&DnsCacheEntry {
            id: skew_ip.to_string(),
            domain: "skew.example".to_owned(),
            last_seen: now + time::Duration::hours(1),
        })
        .expect("upsert skew");
    assert_eq!(processor.lookup_domain(9999, &skew_ip), "");
}

#[test]
fn recorded_answer_is_visible_to_the_next_lookup() {
    let dir = tempdir().expect("tempdir");
    let keystore = UnixSecureFileKeyProvider::new(dir.path().join("key"));
    let store =
        Arc::new(Store::open_with_keystore(dir.path().join("db.sqlite"), &keystore).expect("open"));
    let processor = test_processor(store, TrafficStreamingHub::with_capacity(4));
    let key = sample_key();

    // Unresolved first: no hint, no persistent mapping.
    assert_eq!(processor.lookup_domain(9999, &key.remote_addr), "");
    processor.handle_event(&FlowEvent::DnsResolved {
        pid: 0,
        query: "recorded.example".to_owned(),
        answers: vec![key.remote_addr.to_string()],
    });
    // The single-write path must be visible immediately, labeled inferred.
    assert_eq!(
        processor.lookup_domain(9999, &key.remote_addr),
        "recorded.example (inferred)"
    );
}

#[test]
fn dns_hint_uses_native_ttl_and_observation_time() {
    let dir = tempdir().expect("tempdir");
    let keystore = UnixSecureFileKeyProvider::new(dir.path().join("key"));
    let store =
        Arc::new(Store::open_with_keystore(dir.path().join("db.sqlite"), &keystore).expect("open"));
    let processor = test_processor(store, TrafficStreamingHub::with_capacity(4));
    let key = sample_key();

    processor.handle_event(&FlowEvent::DnsResolvedWithMetadata {
        attribution: DnsResolutionAttribution::Process(1234),
        query: "short.example".to_owned(),
        answers: vec![key.remote_addr.to_string()],
        ttl_ms: 50,
        observed_at: 1_000,
    });

    let hints = processor.dns_hints.read();
    let hints = hints.processes();
    assert_eq!(
        hints.resolve(1234, key.remote_addr, 1_050),
        Some("short.example")
    );
    assert_eq!(hints.resolve(1234, key.remote_addr, 1_051), None);
}

#[test]
fn stub_hint_names_the_querying_process_without_an_inferred_suffix() {
    let dir = tempdir().expect("tempdir");
    let keystore = UnixSecureFileKeyProvider::new(dir.path().join("key"));
    let store =
        Arc::new(Store::open_with_keystore(dir.path().join("db.sqlite"), &keystore).expect("open"));
    let processor = test_processor(store, TrafficStreamingHub::with_capacity(4));
    let key = sample_key();

    processor.record_stub_hint(
        1234,
        "app.example",
        &[key.remote_addr],
        60_000,
        netmetrics_core::unix_now_ms(),
    );

    assert_eq!(
        processor.lookup_domain(1234, &key.remote_addr),
        "app.example"
    );
}

#[test]
fn global_dns_cache_fallback_labels_as_inferred() {
    let dir = tempdir().expect("tempdir");
    let keystore = UnixSecureFileKeyProvider::new(dir.path().join("key"));
    let store =
        Arc::new(Store::open_with_keystore(dir.path().join("db.sqlite"), &keystore).expect("open"));

    let key = sample_key();
    store
        .upsert_dns_cache(&DnsCacheEntry {
            id: key.remote_addr.to_string(),
            domain: "inferred.example".to_owned(),
            last_seen: OffsetDateTime::now_utc(),
        })
        .expect("upsert");

    let traffic_hub = TrafficStreamingHub::with_capacity(4);
    let processor = test_processor(store, traffic_hub);

    let mut log = NewConnectionLog {
        replace_domain: false,
        is_close: false,
        conn_pid: 0,
        conn_id: 0,
        timestamp: OffsetDateTime::now_utc(),
        app_id: 1,
        app_path: String::new(),
        protocol: "TCP".to_owned(),
        src_ip: key.local_addr.to_string(),
        src_port: i32::from(key.local_port),
        dst_ip: key.remote_addr.to_string(),
        dst_port: i32::from(key.remote_port),
        dst_domain: String::new(),
        bytes_sent: 0,
        bytes_received: 0,
        action_taken: "ALLOWED".to_owned(),
        last_seen: OffsetDateTime::now_utc(),
        country_code: String::new(),
        isp: String::new(),
        blocklist_names: String::new(),
    };

    // Enrich with no in-memory hint hit; falls back to SQLite cache labeled as inferred
    processor.enrich_connection_log(
        &key,
        9999,
        "app.exe",
        "app.exe",
        NameRequest::adding(opening_of(&log)),
        &mut log,
    );
    assert_eq!(log.dst_domain, "inferred.example (inferred)");
}

/// A connection named from another process's lookup is counted once when its
/// name turns inferred and once when it closes unconfirmed, both times under
/// the process that hinted its address.
#[test]
fn an_inferred_connection_is_counted_once_by_the_process_that_hinted_its_address() {
    let dir = tempdir().expect("tempdir");
    let keystore = UnixSecureFileKeyProvider::new(dir.path().join("key"));
    let store =
        Arc::new(Store::open_with_keystore(dir.path().join("db.sqlite"), &keystore).expect("open"));
    let processor = test_processor(store, TrafficStreamingHub::with_capacity(4));
    let key = sample_key();

    processor.record_stub_hint(
        4321,
        "other.example",
        &[key.remote_addr],
        60_000,
        netmetrics_core::unix_now_ms(),
    );
    let now = OffsetDateTime::now_utc();
    let mut log = NewConnectionLog {
        replace_domain: false,
        is_close: true,
        conn_pid: 1234,
        conn_id: 7,
        timestamp: now,
        app_id: 1,
        app_path: "app.exe".to_owned(),
        protocol: "TCP".to_owned(),
        src_ip: key.local_addr.to_string(),
        src_port: i32::from(key.local_port),
        dst_ip: key.remote_addr.to_string(),
        dst_port: i32::from(key.remote_port),
        dst_domain: String::new(),
        bytes_sent: 0,
        bytes_received: 0,
        action_taken: "ALLOWED".to_owned(),
        last_seen: now,
        country_code: String::new(),
        isp: String::new(),
        blocklist_names: String::new(),
    };

    processor.enrich_connection_log(
        &key,
        1234,
        "app.exe",
        "app.exe",
        NameRequest::adding(opening_of(&log)),
        &mut log,
    );
    assert_eq!(log.dst_domain, "other.example (inferred)");
    // A retry finds the name already inferred and does not count it again.
    processor.enrich_connection_log(
        &key,
        1234,
        "app.exe",
        "app.exe",
        NameRequest::adding(opening_of(&log)),
        &mut log,
    );
    processor.await_final_name(
        1234,
        key.remote_addr,
        "app.exe",
        opening_of(&log),
        Some(unconfirmed(&log)),
        &log,
    );

    let stats = processor.domain_lookup_stats();
    assert_eq!(stats.first_inferred_never_hinted, 0);
    assert_eq!(
        stats.first_inferred,
        [[0, 0], [0, 0], [0, 0], [0, 1]],
        "another process held a live hint when the name turned inferred"
    );
    assert_eq!(stats.closed_rows, [0, 1, 0]);
    assert_eq!(
        stats.closed_unconfirmed,
        [[0, 0, 0], [0, 0, 0], [0, 0, 0], [0, 1, 0]],
        "and that hint covered the connection's opening"
    );
}
#[test]
fn flow_with_bytes_transferred_remains_allowed_even_if_policy_blocks() {
    let dir = tempdir().expect("tempdir");
    let keystore = UnixSecureFileKeyProvider::new(dir.path().join("key"));
    let store =
        Arc::new(Store::open_with_keystore(dir.path().join("db.sqlite"), &keystore).expect("open"));

    let traffic_hub = TrafficStreamingHub::with_capacity(4);
    let alerts = AlertPublisher::unsaved(NotificationHub::with_capacity(4), None);
    let mut engine = RuleEngine::new();
    let mut builder = antiwire_policy::BlocklistBuilder::new(10);
    builder.add_from_list("test_list", "evil.example");
    let prepared = builder.prepare().expect("prepare");
    engine.publish_blocklist(prepared);
    let rule_engine = Arc::new(RwLock::new(engine));
    let siem = SiemExporter::new(SiemConfig::default());
    let processor = FlowProcessor::new(
        Arc::new(AppIdResolver::new(
            Arc::clone(&store),
            alerts.clone(),
            SiemExporter::new(SiemConfig::default()),
        )),
        None,
        rule_engine,
        store,
        traffic_hub,
        alerts,
        siem,
    );

    let key = sample_key();
    let mut log = NewConnectionLog {
        replace_domain: false,
        is_close: false,
        conn_pid: 0,
        conn_id: 0,
        timestamp: OffsetDateTime::now_utc(),
        app_id: 1,
        app_path: String::new(),
        protocol: "TCP".to_owned(),
        src_ip: key.local_addr.to_string(),
        src_port: i32::from(key.local_port),
        dst_ip: key.remote_addr.to_string(),
        dst_port: i32::from(key.remote_port),
        dst_domain: "evil.example".to_owned(),
        bytes_sent: 1024,
        bytes_received: 2048,
        action_taken: "ALLOWED".to_owned(),
        last_seen: OffsetDateTime::now_utc(),
        country_code: String::new(),
        isp: String::new(),
        blocklist_names: String::new(),
    };

    processor.enrich_connection_log(
        &key,
        1234,
        "app.exe",
        "app.exe",
        NameRequest::adding(opening_of(&log)),
        &mut log,
    );

    // Bytes flowed, so observed action is ALLOWED, but blocklist_names records the rule match
    assert_eq!(log.action_taken, "ALLOWED");
    assert_eq!(log.blocklist_names, "test_list");

    // When 0 bytes were transferred, action_taken is BLOCKED
    let mut zero_bytes_log = NewConnectionLog {
        is_close: false,
        conn_pid: 0,
        conn_id: 0,
        bytes_sent: 0,
        bytes_received: 0,
        ..log.clone()
    };
    processor.enrich_connection_log(
        &key,
        1234,
        "app.exe",
        "app.exe",
        NameRequest::adding(opening_of(&zero_bytes_log)),
        &mut zero_bytes_log,
    );
    assert_eq!(zero_bytes_log.action_taken, "BLOCKED");
    assert_eq!(zero_bytes_log.blocklist_names, "test_list");
}

#[test]
fn dns_resolved_names_are_sanitized_before_they_are_cached() {
    let dir = tempdir().expect("tempdir");
    let keystore = UnixSecureFileKeyProvider::new(dir.path().join("key"));
    let store =
        Arc::new(Store::open_with_keystore(dir.path().join("db.sqlite"), &keystore).expect("open"));
    let processor = test_processor(Arc::clone(&store), TrafficStreamingHub::with_capacity(4));
    let ip = sample_key().remote_addr;

    processor.handle_event(&FlowEvent::DnsResolved {
        pid: 0,
        query: "evil\nexample.com".to_owned(),
        answers: vec![ip.to_string()],
    });

    assert_eq!(
        processor.lookup_domain(9999, &ip),
        "evilexample.com (inferred)"
    );

    processor.flush_dns_cache();
    let row = store
        .get_dns_cache(&ip.to_string())
        .expect("cache read")
        .expect("row");
    assert_eq!(row.domain, "evilexample.com");
}

#[test]
fn dns_metadata_hints_are_sanitized_before_they_are_cached() {
    let dir = tempdir().expect("tempdir");
    let keystore = UnixSecureFileKeyProvider::new(dir.path().join("key"));
    let store =
        Arc::new(Store::open_with_keystore(dir.path().join("db.sqlite"), &keystore).expect("open"));
    let processor = test_processor(store, TrafficStreamingHub::with_capacity(4));
    let ip = sample_key().remote_addr;
    let observed_at =
        u64::try_from((OffsetDateTime::now_utc().unix_timestamp_nanos() / 1_000_000).max(0))
            .unwrap_or(0);

    processor.handle_event(&FlowEvent::DnsResolvedWithMetadata {
        attribution: DnsResolutionAttribution::Process(1234),
        query: "hint\nforged.example".to_owned(),
        answers: vec![ip.to_string()],
        ttl_ms: 60_000,
        observed_at,
    });

    assert_eq!(processor.lookup_domain(1234, &ip), "hintforged.example");
}

fn system_test_fixture() -> (
    tempfile::TempDir,
    Arc<Store>,
    TrafficStreamingHub,
    AlertPublisher,
    FlowProcessor,
) {
    let dir = tempdir().expect("tempdir");
    let keystore = UnixSecureFileKeyProvider::new(dir.path().join("key"));
    let store =
        Arc::new(Store::open_with_keystore(dir.path().join("db.sqlite"), &keystore).expect("open"));
    let traffic_hub = TrafficStreamingHub::with_capacity(4);
    let alerts = AlertPublisher::unsaved(NotificationHub::with_capacity(8), None);
    let rule_engine = Arc::new(RwLock::new(RuleEngine::new()));
    let siem = SiemExporter::new(SiemConfig::default());
    let processor = FlowProcessor::new(
        Arc::new(AppIdResolver::new(
            Arc::clone(&store),
            alerts.clone(),
            SiemExporter::new(SiemConfig::default()),
        )),
        None,
        rule_engine,
        Arc::clone(&store),
        traffic_hub.clone(),
        alerts.clone(),
        siem,
    );
    (dir, store, traffic_hub, alerts, processor)
}

fn dhcp_key() -> FlowKey {
    FlowKey {
        protocol: Protocol::Udp,
        local_addr: IpAddr::V4(Ipv4Addr::new(192, 168, 68, 50)),
        local_port: 68,
        remote_addr: IpAddr::V4(Ipv4Addr::new(192, 168, 68, 1)),
        remote_port: 67,
    }
}

fn dhcp_server_key() -> FlowKey {
    FlowKey {
        protocol: Protocol::Udp,
        local_addr: IpAddr::V4(Ipv4Addr::new(192, 168, 68, 1)),
        local_port: 67,
        remote_addr: IpAddr::V4(Ipv4Addr::new(192, 168, 68, 60)),
        remote_port: 68,
    }
}

fn ownerless_meta() -> FlowMeta {
    FlowMeta {
        pid: 0,
        process: None,
        open_ts: 0,
        cookie: None,
        if_index: None,
    }
}

fn app_meta(pid: u32, executable: &str, name: &str) -> FlowMeta {
    FlowMeta {
        pid,
        process: Some(ProcessIdentity {
            executable: executable.to_owned(),
            name: name.to_owned(),
            start_ts: 0,
        }),
        open_ts: 0,
        cookie: None,
        if_index: None,
    }
}

fn verified_dhcp_meta(pid: u32, start_ts: u64) -> FlowMeta {
    FlowMeta {
        pid,
        process: Some(ProcessIdentity {
            // The SCM-derived `::Dhcp` identity is deliberately supplied
            // by the seeded cache below. An explicit decorated metadata
            // path would be normalized as a plain svchost identity before
            // the system allowlist sees it.
            executable: String::new(),
            name: String::new(),
            start_ts,
        }),
        open_ts: 0,
        cookie: None,
        if_index: None,
    }
}

/// A user-mode application path that is trusted on every host, so
/// attribution tests behave identically on Windows, Linux, and macOS.
#[cfg(windows)]
fn user_app() -> (&'static str, &'static str) {
    (r"C:\apps\vpn.exe", "vpn.exe")
}

/// A user-mode application path that is trusted on every host, so
/// attribution tests behave identically on Windows, Linux, and macOS.
#[cfg(not(windows))]
fn user_app() -> (&'static str, &'static str) {
    ("/tmp/vpn.exe", "vpn.exe")
}

/// Base directory for building overlong test paths on any host.
#[cfg(windows)]
fn long_base() -> &'static str {
    r"C:\"
}

/// Base directory for building overlong test paths on any host.
#[cfg(not(windows))]
fn long_base() -> &'static str {
    "/tmp/"
}

/// Drains published alerts until one of the wanted type arrives or the budget is spent.
/// New-application sightings publish first, so the impersonation alert is
/// never assumed to be the head of the queue.
macro_rules! recv_until_type {
    ($events:expr, $want:expr) => {{
        let mut found = None;
        for _ in 0..8 {
            match tokio::time::timeout(std::time::Duration::from_millis(50), $events.recv()).await {
                Ok(Some(event)) if event.kind.as_str() == $want => {
                    found = Some(event);
                    break;
                }
                Ok(_) => {}
                Err(_) => break,
            }
        }
        found
    }};
}

#[test]
fn system_fold_ownerless_dhcp_skips_resolution() {
    let (_dir, store, _, _, processor) = system_test_fixture();
    let before = processor.system_attribution_stats();

    let (app_id, app_path, app_name) = processor.resolve_flow_app_inner(
        true,
        system_services::windows(),
        &dhcp_key(),
        &ownerless_meta(),
    );

    assert!(app_id > 0);
    assert_eq!(app_path, "System");
    assert_eq!(app_name, "system");
    let app = store
        .find_application_by_name("system")
        .expect("application lookup")
        .expect("system row exists");
    assert_eq!(app.id, app_id);
    assert_eq!(app.app_path, "System");

    let after = processor.system_attribution_stats();
    assert!(after.matched > before.matched);
    assert!(after.folded_ownerless > before.folded_ownerless);
}

#[tokio::test]
async fn system_fold_verified_dhcp_service() {
    let (_dir, store, _, publisher, processor) = system_test_fixture();
    let mut events = publisher.subscribe();
    let before = processor.system_attribution_stats();

    // Production obtains this identity through SCM disambiguation of the live
    // svchost instance (covered by the ignored live test). The cache seed
    // carries the SCM-derived path/name, while the flow carries its known
    // creation timestamp so the resolver can validate that generation
    // without querying the fake PID.
    let pid = 459_105;
    processor.processes().seed_cache(
        pid,
        r"C:\Windows\System32\svchost.exe::Dhcp",
        "Dhcp (svchost.exe)",
        111_000,
    );
    let meta = verified_dhcp_meta(pid, 111_000);
    let resolved = processor.resolve_flow_app_identity_inner(
        true,
        system_services::windows(),
        &dhcp_key(),
        &meta,
    );
    assert_eq!(resolved.start_ts, 111_000);
    let (app_id, app_path, app_name) = resolved.into_parts();

    assert!(app_id > 0);
    assert_eq!(app_path, "System");
    assert_eq!(app_name, "system");
    // The fold must not mint the service's row or alert on the way through.
    assert!(
        store
            .find_application_by_name("Dhcp (svchost.exe)")
            .expect("application lookup")
            .is_none(),
        "verified folds leave no service row behind"
    );
    assert!(
        recv_until_type!(events, "NEW_APP").is_none()
            && recv_until_type!(events, "SYSTEM_SERVICE_IMPERSONATION").is_none(),
        "verified folds publish nothing"
    );
    let after = processor.system_attribution_stats();
    assert!(after.folded_verified > before.folded_verified);
}

#[test]
fn system_rejects_forged_service_labels_from_metadata() {
    let (_dir, _, _, _, processor) = system_test_fixture();
    // A `::` label smuggled through flow metadata: resolution passes it
    // through as trusted, but verification still fails because the host
    // image is not the canonical service host.
    #[cfg(windows)]
    let forged = r"C:\Temp\evil.exe::Dnscache";
    #[cfg(not(windows))]
    let forged = "/tmp/evil::Dnscache";
    let meta = app_meta(459_107, forged, "Dnscache (svchost.exe)");
    let dns = FlowKey {
        protocol: Protocol::Udp,
        local_addr: IpAddr::V4(Ipv4Addr::new(192, 168, 68, 50)),
        local_port: 51_234,
        remote_addr: IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9)),
        remote_port: 53,
    };
    let (app_id, _, app_name) =
        processor.resolve_flow_app_inner(true, system_services::windows(), &dns, &meta);
    assert_ne!(app_name, "system", "a forged label must never fold");
    assert_ne!(app_id, 0, "the flow keeps its (unverified) attribution");
}

#[tokio::test]
async fn system_keeps_user_owner_on_client_shape() {
    let (_dir, _, _, publisher, processor) = system_test_fixture();
    let mut events = publisher.subscribe();
    let before = processor.system_attribution_stats();

    let (app_path, app_name) = user_app();
    let meta = app_meta(459_102, app_path, app_name);
    let (app_id, resolved_path, resolved_name) =
        processor.resolve_flow_app_inner(true, system_services::windows(), &dhcp_key(), &meta);

    assert!(app_id > 0);
    assert_eq!(resolved_path, app_path);
    assert_eq!(resolved_name, app_name);
    let after = processor.system_attribution_stats();
    assert!(after.matched > before.matched);
    assert!(after.no_rule > before.no_rule);
    assert!(
        recv_until_type!(events, "SYSTEM_SERVICE_IMPERSONATION").is_none(),
        "a client-shaped flow with a real owner must not alert"
    );
}

#[tokio::test]
async fn system_alerts_once_for_rogue_dhcp_server() {
    let (_dir, _, _, publisher, processor) = system_test_fixture();
    let mut events = publisher.subscribe();
    let before = processor.system_attribution_stats();

    let (evil_path, evil_name) = {
        #[cfg(windows)]
        {
            (r"C:\apps\evil.exe", "evil.exe")
        }
        #[cfg(not(windows))]
        {
            ("/tmp/evil.exe", "evil.exe")
        }
    };
    let meta = app_meta(459_103, evil_path, evil_name);
    let (app_id, app_path, app_name) = processor.resolve_flow_app_inner(
        true,
        system_services::windows(),
        &dhcp_server_key(),
        &meta,
    );

    // The record keeps its real attribution.
    assert!(app_id > 0);
    assert_eq!(app_path, evil_path);
    assert_eq!(app_name, evil_name);
    let event =
        recv_until_type!(events, "SYSTEM_SERVICE_IMPERSONATION").expect("impersonation alert");
    assert_eq!(event.severity, Severity::High);
    assert!(event.message.contains("evil.exe"));
    assert!(event.message.contains("DHCPv4 server"));

    // A repeat sighting stays silent.
    let _ = processor.resolve_flow_app_inner(
        true,
        system_services::windows(),
        &dhcp_server_key(),
        &meta,
    );
    assert!(
        recv_until_type!(events, "SYSTEM_SERVICE_IMPERSONATION").is_none(),
        "repeat sightings stay suppressed"
    );
    let after = processor.system_attribution_stats();
    assert!(after.impersonation_alert > before.impersonation_alert);
}

#[tokio::test]
async fn system_alert_keeps_evidence_despite_long_paths() {
    let (_dir, _, _, publisher, processor) = system_test_fixture();
    let mut events = publisher.subscribe();

    // A maximal path must not amputate the service and endpoint tail,
    // and IPv6 endpoints must stay unambiguous. The name runs at the full
    // display width too, so the message budget is proven, not assumed.
    let long_path = format!("{}{}", long_base(), "A".repeat(2000));
    let long_name = "€".repeat(256);
    let meta = app_meta(459_108, &long_path, &long_name);
    let key = FlowKey {
        protocol: Protocol::Udp,
        local_addr: "fe80::1".parse().unwrap(),
        local_port: 53,
        remote_addr: "fe80::2".parse().unwrap(),
        remote_port: 51_234,
    };
    let (_, app_path, _) =
        processor.resolve_flow_app_inner(true, system_services::windows(), &key, &meta);
    assert_eq!(app_path, long_path);

    let event =
        recv_until_type!(events, "SYSTEM_SERVICE_IMPERSONATION").expect("impersonation alert");
    assert!(
        event.message.contains("system DNS")
            && event.message.contains("[fe80::1]:53")
            && event
                .message
                .ends_with("the connection keeps its real attribution."),
        "tail must survive path truncation: {}",
        event.message
    );
    // Caps are character-based throughout (see `sanitize::text`); the
    // endpoint tail above proves the security content is within budget.
    assert!(
        event.message.chars().count() <= sanitize::MAX_MESSAGE_CHARS,
        "message respects the cap"
    );
}

#[test]
fn system_disabled_mode_counts_without_folding() {
    let (_dir, _, _, _, processor) = system_test_fixture();
    let before = processor.system_attribution_stats();

    let (app_id, app_path, app_name) = processor.resolve_flow_app_inner(
        false,
        system_services::windows(),
        &dhcp_key(),
        &ownerless_meta(),
    );
    assert_eq!((app_id, app_path.as_str(), app_name.as_str()), (0, "", ""));

    let pid = 459_106;
    processor.processes().seed_cache(
        pid,
        r"C:\Windows\System32\svchost.exe::Dhcp",
        "Dhcp (svchost.exe)",
        111_000,
    );
    let meta = verified_dhcp_meta(pid, 111_000);
    let (_, _, name) =
        processor.resolve_flow_app_inner(false, system_services::windows(), &dhcp_key(), &meta);
    assert!(
        name.contains("svchost.exe"),
        "audit mode must keep the resolved owner, got '{name}'"
    );

    let after = processor.system_attribution_stats();
    assert!(after.matched > before.matched);
    assert!(after.no_rule > before.no_rule);
}

#[test]
fn system_never_folds_daemon_pid() {
    let (_dir, _, _, _, processor) = system_test_fixture();
    let meta = FlowMeta {
        pid: std::process::id(),
        process: None,
        open_ts: 0,
        cookie: None,
        if_index: None,
    };
    let (app_id, app_path, app_name) =
        processor.resolve_flow_app_inner(true, system_services::windows(), &dhcp_key(), &meta);
    assert!(app_id > 0, "the daemon resolves to its real identity");
    assert_ne!(app_path, "");
    assert_ne!(app_name, "system");
}

#[test]
fn system_pid_four_returns_system_without_further_rule() {
    let (_dir, _, _, _, processor) = system_test_fixture();
    let before = processor.system_attribution_stats();

    let meta = FlowMeta {
        pid: 4,
        process: None,
        open_ts: 0,
        cookie: None,
        if_index: None,
    };
    let (app_id, app_path, app_name) =
        processor.resolve_flow_app_inner(true, system_services::windows(), &dhcp_key(), &meta);

    assert!(app_id > 0);
    assert_eq!(app_path, "System");
    assert_eq!(app_name, "system");
    let after = processor.system_attribution_stats();
    assert!(after.matched > before.matched);
    assert!(after.no_rule > before.no_rule);
}

#[test]
fn system_pid_zero_with_process_evidence_resolves_by_path() {
    let (_dir, _, _, _, processor) = system_test_fixture();
    let (app_path, app_name) = user_app();
    let meta = app_meta(0, app_path, app_name);
    let (app_id, resolved_path, resolved_name) =
        processor.resolve_flow_app_inner(true, system_services::windows(), &dhcp_key(), &meta);
    assert!(app_id > 0);
    assert_eq!(resolved_path, app_path);
    assert_eq!(resolved_name, app_name);
}

/// How [`FlakyDomainStore`] answers the writes it can break.
#[derive(Clone, Copy, PartialEq)]
enum StoreMode {
    Working,
    Failing,
    /// Answers a domain upgrade with fewer results than it was given.
    ShortAnswer,
}

/// A real store whose DNS cache and domain-upgrade writes can be made to fail.
struct FlakyDomainStore {
    inner: Arc<Store>,
    mode: Mutex<StoreMode>,
    dns_writes: AtomicU64,
}

impl FlakyDomainStore {
    fn set_mode(&self, mode: StoreMode) {
        *self.mode.lock() = mode;
    }
}

fn injected_failure() -> antiwire_store::StoreError {
    antiwire_store::StoreError::Database("injected failure".to_owned())
}

impl DomainStore for FlakyDomainStore {
    fn get_dns_cache(&self, id: &str) -> antiwire_store::Result<Option<DnsCacheEntry>> {
        self.inner.get_dns_cache(id)
    }

    fn upsert_dns_cache_batch(&self, entries: &[DnsCacheEntry]) -> antiwire_store::Result<()> {
        self.dns_writes.fetch_add(1, Ordering::Relaxed);
        match *self.mode.lock() {
            StoreMode::Failing => Err(injected_failure()),
            _ => self.inner.upsert_dns_cache_batch(entries),
        }
    }

    fn record_domain_sighting(
        &self,
        domain: &str,
        seen_at: OffsetDateTime,
    ) -> antiwire_store::Result<bool> {
        self.inner.record_domain_sighting(domain, seen_at)
    }

    fn upgrade_connection_domains(
        &self,
        upgrades: &[ConnectionDomainUpgrade],
    ) -> antiwire_store::Result<Vec<bool>> {
        match *self.mode.lock() {
            StoreMode::Working => self.inner.upgrade_connection_domains(upgrades),
            StoreMode::Failing => Err(injected_failure()),
            StoreMode::ShortAnswer => Ok(Vec::new()),
        }
    }
}

fn flaky_processor() -> (tempfile::TempDir, Arc<FlakyDomainStore>, FlowProcessor) {
    let dir = tempdir().expect("tempdir");
    let keystore = UnixSecureFileKeyProvider::new(dir.path().join("key"));
    let inner =
        Arc::new(Store::open_with_keystore(dir.path().join("db.sqlite"), &keystore).expect("open"));
    let flaky = Arc::new(FlakyDomainStore {
        inner: Arc::clone(&inner),
        mode: Mutex::new(StoreMode::Working),
        dns_writes: AtomicU64::new(0),
    });
    let alerts = AlertPublisher::unsaved(NotificationHub::with_capacity(4), None);
    let processor = FlowProcessor::new(
        Arc::new(AppIdResolver::new(
            inner,
            alerts.clone(),
            SiemExporter::new(SiemConfig::default()),
        )),
        None,
        Arc::new(RwLock::new(RuleEngine::new())),
        Arc::clone(&flaky),
        TrafficStreamingHub::with_capacity(4),
        alerts,
        SiemExporter::new(SiemConfig::default()),
    );
    (dir, flaky, processor)
}

fn distinct_answers(count: usize, offset: u32) -> Vec<String> {
    (0..count)
        .map(|index| {
            let index = u32::try_from(index).expect("small index") + offset;
            Ipv4Addr::from(0x0A00_0000 + index).to_string()
        })
        .collect()
}

/// While the store is failing, a full DNS buffer used to be rewritten inline
/// on every answer. It now waits for the flush tick and drops answers that
/// do not fit, counting them.
#[test]
fn a_failing_dns_cache_write_waits_for_the_flush_tick() {
    let (_dir, store, processor) = flaky_processor();
    let cap = domain_names::DNS_CACHE_PENDING_CAP;
    store.set_mode(StoreMode::Failing);

    processor.record_dns_resolution("full.example", &distinct_answers(cap, 0));
    assert_eq!(store.dns_writes.load(Ordering::Relaxed), 1);
    assert_eq!(
        processor.pending_dns.lock().len(),
        cap,
        "the batch is requeued"
    );

    for offset in 0..3 {
        processor.record_dns_resolution("more.example", &distinct_answers(1, 100_000 + offset));
    }
    assert_eq!(
        store.dns_writes.load(Ordering::Relaxed),
        1,
        "no write is retried inline while the store is failing"
    );
    assert_eq!(processor.pending_dns.lock().len(), cap);
    assert_eq!(processor.domain_lookup_stats().dns_answers_shed, 3);

    store.set_mode(StoreMode::Working);
    processor.flush_dns_cache();
    assert_eq!(store.dns_writes.load(Ordering::Relaxed), 2);
    assert!(processor.pending_dns.lock().is_empty());

    processor.record_dns_resolution("again.example", &distinct_answers(1, 200_000));
    assert_eq!(
        processor.pending_dns.lock().len(),
        1,
        "a recovered store buffers answers again"
    );
}

fn ready_upgrade(processor: &FlowProcessor, attempts: u8) {
    processor.ready_domain_upgrades.lock().push(ReadyUpgrade {
        upgrade: ConnectionDomainUpgrade {
            replace: false,
            conn_id: 1,
            conn_pid: 1,
            conn_start: OffsetDateTime::now_utc(),
            dst_domain: "late.example".to_owned(),
        },
        attempts,
        record: TrafficEvent::default(),
    });
}

fn upgrade_attempts_left(processor: &FlowProcessor) -> Vec<u8> {
    processor
        .ready_domain_upgrades
        .lock()
        .iter()
        .map(|ready| ready.attempts)
        .collect()
}

const BROWSER: &str = r"C:\apps\browser\browser.exe";

/// Records a hint for `pid` as a process running `executable` would. A PID
/// the host does not have cannot be resolved to its image, so the tests name
/// the executable themselves.
fn hint_from(processor: &FlowProcessor, pid: u32, executable: &str, query: &str, ip: IpAddr) {
    let now_ms = netmetrics_core::unix_now_ms();
    processor.record_dns_resolution(query, &[ip.to_string()]);
    processor.dns_hints.write().insert(
        pid,
        executable_key(executable),
        query,
        &[ip],
        now_ms,
        60_000,
    );
    processor.note_named([ip]);
}

fn closed_log(key: &FlowKey, pid: i32, app_path: &str, dst_domain: &str) -> NewConnectionLog {
    let now = OffsetDateTime::now_utc();
    NewConnectionLog {
        replace_domain: false,
        is_close: true,
        conn_pid: pid,
        conn_id: 7,
        timestamp: now,
        app_id: 1,
        app_path: app_path.to_owned(),
        protocol: "TCP".to_owned(),
        src_ip: key.local_addr.to_string(),
        src_port: i32::from(key.local_port),
        dst_ip: key.remote_addr.to_string(),
        dst_port: i32::from(key.remote_port),
        dst_domain: dst_domain.to_owned(),
        bytes_sent: 10,
        bytes_received: 20,
        action_taken: "ALLOWED".to_owned(),
        last_seen: now,
        country_code: String::new(),
        isp: String::new(),
        blocklist_names: String::new(),
    }
}

/// The regression this guards: an application that asks for a name in one
/// process and connects from another had its connections named as inferred,
/// because the hint was held under a different PID.
#[test]
fn a_name_another_process_of_the_same_executable_asked_for_is_confirmed() {
    let dir = tempdir().expect("tempdir");
    let keystore = UnixSecureFileKeyProvider::new(dir.path().join("key"));
    let store =
        Arc::new(Store::open_with_keystore(dir.path().join("db.sqlite"), &keystore).expect("open"));
    let processor = test_processor(store, TrafficStreamingHub::with_capacity(4));
    let key = sample_key();
    hint_from(&processor, 4321, BROWSER, "site.example", key.remote_addr);

    let mut sibling = closed_log(&key, 1234, BROWSER, "");
    processor.enrich_connection_log(
        &key,
        1234,
        BROWSER,
        "browser.exe",
        NameRequest::adding(opening_of(&sibling)),
        &mut sibling,
    );
    assert_eq!(sibling.dst_domain, "site.example");

    let mut stranger = closed_log(&key, 1235, r"C:\apps\other.exe", "");
    processor.enrich_connection_log(
        &key,
        1235,
        r"C:\apps\other.exe",
        "other.exe",
        NameRequest::adding(opening_of(&stranger)),
        &mut stranger,
    );
    assert_eq!(
        stranger.dst_domain, "site.example (inferred)",
        "another application's lookup stays an inference"
    );

    let stats = processor.domain_lookup_stats();
    assert_eq!((stats.application_hint, stats.process_hint), (1, 0));
}

/// A sibling's hint that arrives after the connection closed confirms its row,
/// as a late hint from the connection's own process does.
#[test]
fn a_late_hint_from_a_sibling_process_confirms_a_closed_row() {
    let dir = tempdir().expect("tempdir");
    let keystore = UnixSecureFileKeyProvider::new(dir.path().join("key"));
    let store =
        Arc::new(Store::open_with_keystore(dir.path().join("db.sqlite"), &keystore).expect("open"));
    let processor = test_processor(Arc::clone(&store), TrafficStreamingHub::with_capacity(4));
    let key = sample_key();
    let log = closed_log(&key, 1234, BROWSER, "site.example (inferred)");
    store
        .insert_connection_logs(std::slice::from_ref(&log))
        .expect("write the closed row");
    processor.await_final_name(
        1234,
        key.remote_addr,
        "browser.exe",
        opening_of(&log),
        Some(unconfirmed(&log)),
        &log,
    );

    hint_from(
        &processor,
        4322,
        r"C:\apps\other.exe",
        "site.example",
        key.remote_addr,
    );
    settle_closed(&processor);
    assert_eq!(
        processor.domain_lookup_stats().late_upgrades,
        0,
        "another application's hint must not confirm the row"
    );

    hint_from(&processor, 4321, BROWSER, "site.example", key.remote_addr);
    settle_closed(&processor);
    assert_eq!(processor.domain_lookup_stats().late_upgrades, 1);
}

/// The regression this guards: the bound on closed connections held for a
/// later name counted the addresses they went to. Connections to one address
/// were held without limit, each with a copy of its record.
#[test]
fn closed_connections_held_for_a_name_are_bounded_however_few_addresses_they_share() {
    let dir = tempdir().expect("tempdir");
    let keystore = UnixSecureFileKeyProvider::new(dir.path().join("key"));
    let store =
        Arc::new(Store::open_with_keystore(dir.path().join("db.sqlite"), &keystore).expect("open"));
    let processor = test_processor(store, TrafficStreamingHub::with_capacity(4));
    let key = sample_key();
    let cap = closed_names::CLOSED_NAMES_CAP;
    let extra = 25;
    for index in 0..cap + extra {
        let mut log = closed_log(&key, 1234, BROWSER, "site.example (inferred)");
        log.conn_id = i64::try_from(index + 1).expect("a small count");
        processor.await_final_name(
            1234,
            key.remote_addr,
            "browser.exe",
            opening_of(&log),
            Some(unconfirmed(&log)),
            &log,
        );
    }
    assert_eq!(processor.closed_names.lock().len(), cap);
    assert_eq!(
        processor.domain_lookup_stats().closed_names_shed,
        u64::try_from(extra).expect("a small count")
    );
}

/// A hint is shared with the executable its process runs, which has to be the
/// same key a connection from that executable is looked up under.
#[test]
fn a_hinting_process_is_keyed_by_the_executable_its_connections_carry() {
    let dir = tempdir().expect("tempdir");
    let keystore = UnixSecureFileKeyProvider::new(dir.path().join("key"));
    let store =
        Arc::new(Store::open_with_keystore(dir.path().join("db.sqlite"), &keystore).expect("open"));
    let processor = test_processor(store, TrafficStreamingHub::with_capacity(4));
    let pid = std::process::id();
    let meta = FlowMeta {
        pid,
        process: None,
        open_ts: 0,
        cookie: None,
        if_index: None,
    };

    let connection = processor.resolve_app(pid, &meta);
    let now_ms = netmetrics_core::unix_now_ms();
    let image = processor.hint_image(pid, now_ms);

    assert_ne!(image.executable, 0, "a running process has an image");
    assert_eq!(image.executable, executable_key(&connection.app_path));
    assert_eq!(
        processor.hint_image(u32::MAX - 7, now_ms).executable,
        0,
        "a process that cannot be found shares its hints with no application"
    );
}

/// The regression this guards: a hint was dropped the moment its answer's TTL
/// ran out, so a connection the same process then opened from its own cache
/// was named from the global address table, as inferred.
#[test]
fn a_connection_opened_after_its_process_hint_expired_is_still_confirmed() {
    let dir = tempdir().expect("tempdir");
    let keystore = UnixSecureFileKeyProvider::new(dir.path().join("key"));
    let store =
        Arc::new(Store::open_with_keystore(dir.path().join("db.sqlite"), &keystore).expect("open"));
    let processor = test_processor(store, TrafficStreamingHub::with_capacity(4));
    let key = sample_key();
    let now_ms = netmetrics_core::unix_now_ms();
    // Asked two minutes ago, with an answer good for one second.
    processor.handle_event(&FlowEvent::DnsResolvedWithMetadata {
        attribution: DnsResolutionAttribution::Process(1234),
        query: "cached.example".to_owned(),
        answers: vec![key.remote_addr.to_string()],
        ttl_ms: 1_000,
        observed_at: now_ms - 120_000,
    });

    let mut log = closed_log(&key, 1234, "app.exe", "");
    processor.enrich_connection_log(
        &key,
        1234,
        "app.exe",
        "app.exe",
        NameRequest::adding(opening_of(&log)),
        &mut log,
    );
    assert_eq!(log.dst_domain, "cached.example");
    assert_eq!(processor.domain_lookup_stats().retained_process_hint, 1);

    // The same address for a process that started after the hint was
    // recorded: an earlier process had its PID, and the hint is not its own.
    let mut reused = closed_log(&key, 1234, "app.exe", "");
    let opening = Opening {
        process_started_ms: now_ms - 60_000,
        ..opening_of(&reused)
    };
    processor.enrich_connection_log(
        &key,
        1234,
        "app.exe",
        "app.exe",
        NameRequest::adding(opening),
        &mut reused,
    );
    assert_eq!(reused.dst_domain, "cached.example (inferred)");
}

/// The regression this guards: a process holding two names for one address,
/// as on a shared CDN address, had its connections left unnamed even when it
/// had asked for one of them an instant before connecting.
#[test]
fn of_two_names_for_an_address_the_one_just_asked_for_names_the_connection() {
    let dir = tempdir().expect("tempdir");
    let keystore = UnixSecureFileKeyProvider::new(dir.path().join("key"));
    let store =
        Arc::new(Store::open_with_keystore(dir.path().join("db.sqlite"), &keystore).expect("open"));
    let processor = test_processor(store, TrafficStreamingHub::with_capacity(4));
    let key = sample_key();
    let now_ms = netmetrics_core::unix_now_ms();
    let hint = |pid: u32, query: &str, observed_at| {
        processor.handle_event(&FlowEvent::DnsResolvedWithMetadata {
            attribution: DnsResolutionAttribution::Process(pid),
            query: query.to_owned(),
            answers: vec![key.remote_addr.to_string()],
            ttl_ms: 300_000,
            observed_at,
        });
    };
    hint(1234, "earlier.example", now_ms - 60_000);
    hint(1234, "just-asked.example", now_ms - 100);

    let mut log = closed_log(&key, 1234, "app.exe", "");
    processor.enrich_connection_log(
        &key,
        1234,
        "app.exe",
        "app.exe",
        NameRequest::adding(Opening::at(now_ms)),
        &mut log,
    );
    assert_eq!(
        log.dst_domain, "just-asked.example (inferred)",
        "a likely guess is shown as one"
    );
    assert_eq!(processor.domain_lookup_stats().nearest_hint, 1);

    // A process that asked for neither name recently may be reusing either.
    hint(1235, "earlier.example", now_ms - 60_000);
    hint(1235, "later.example", now_ms - 50_000);
    let mut reused = closed_log(&key, 1235, "app.exe", "");
    processor.enrich_connection_log(
        &key,
        1235,
        "app.exe",
        "app.exe",
        NameRequest::adding(Opening::at(now_ms)),
        &mut reused,
    );
    assert_eq!(reused.dst_domain, "");
}

/// The names a process held when a connection opened cannot change later,
/// but a hint from then can arrive late. Until it has had time to, the answer
/// stays open, a confirmed name included: that was the regression. A lookup
/// just after the opening confirmed a name for good, and a hint stamped
/// before the opening that arrived a second later could not correct it.
///
/// Once every such hint is in, a confirmed name is final, and so are names
/// that competed. Looking those up again is wasted, and after one of the
/// competing hints has been dropped from memory it would find the other alone
/// and confirm it.
#[test]
fn a_name_is_final_only_once_every_hint_from_the_opening_has_had_time_to_arrive() {
    let dir = tempdir().expect("tempdir");
    let keystore = UnixSecureFileKeyProvider::new(dir.path().join("key"));
    let store =
        Arc::new(Store::open_with_keystore(dir.path().join("db.sqlite"), &keystore).expect("open"));
    let processor = test_processor(store, TrafficStreamingHub::with_capacity(4));
    let key = sample_key();
    let now_ms = netmetrics_core::unix_now_ms();
    let hint = |attribution, query: &str, observed_at| {
        processor.handle_event(&FlowEvent::DnsResolvedWithMetadata {
            attribution,
            query: query.to_owned(),
            answers: vec![key.remote_addr.to_string()],
            ttl_ms: 300_000,
            observed_at,
        });
    };
    let own = DnsResolutionAttribution::Process(1234);
    hint(own, "first.example", now_ms - 120_000);
    hint(own, "second.example", now_ms - 110_000);
    // The name, and whether evidence arriving now could still change it.
    let name = |pid: u32, opened_at| {
        let mut log = closed_log(&key, 1234, "app.exe", "");
        let naming = processor
            .enrich_connection_log(
                &key,
                pid,
                "app.exe",
                "app.exe",
                NameRequest::adding(Opening::at(opened_at)),
                &mut log,
            )
            .expect("a lookup was made");
        assert_eq!(
            naming.complete_at_ms,
            opened_at + domain_names::HINTS_ARRIVE_WITHIN_MS
        );
        (log.dst_domain, naming.open_at(now_ms))
    };

    assert_eq!(
        name(1234, now_ms - 60_000),
        (String::new(), false),
        "opened a minute ago: every hint from then has arrived"
    );
    assert_eq!(
        name(1234, now_ms),
        (String::new(), true),
        "opened just now: a hint stamped before it may still be on its way"
    );

    // A name asked for just before the opening is a guess, final the same way.
    hint(own, "just-asked.example", now_ms - 60_100);
    assert_eq!(
        name(1234, now_ms - 60_000),
        ("just-asked.example (inferred)".to_owned(), false)
    );

    // Competing hints no process is known for are not the last word: the
    // connection's own process may yet be heard from.
    hint(
        DnsResolutionAttribution::Shared,
        "shared.example",
        now_ms - 120_000,
    );
    hint(
        DnsResolutionAttribution::Shared,
        "shared-too.example",
        now_ms - 110_000,
    );
    assert_eq!(name(4321, now_ms - 60_000), (String::new(), true));

    // A confirmed name is final, once every hint from its opening is in.
    hint(
        DnsResolutionAttribution::Process(4321),
        "own.example",
        now_ms - 60_100,
    );
    assert_eq!(
        name(4321, now_ms - 60_000),
        ("own.example".to_owned(), false)
    );
    assert_eq!(
        name(4321, now_ms),
        ("own.example".to_owned(), true),
        "opened just now: another name its process asked for may yet arrive"
    );
}

/// A name judged again stands in place of the one written only as far as the
/// new judgment knows better. What the hints say replaces anything. The
/// address-only tables say nothing of the moment the connection opened: they
/// displace a confirmed name, whose hint is gone, but not an inference they
/// made before, or a later answer for the address would rename the row.
#[test]
fn a_replacing_judgment_displaces_only_what_it_knows_better_than() {
    let dir = tempdir().expect("tempdir");
    let keystore = UnixSecureFileKeyProvider::new(dir.path().join("key"));
    let store =
        Arc::new(Store::open_with_keystore(dir.path().join("db.sqlite"), &keystore).expect("open"));
    let processor = test_processor(store, TrafficStreamingHub::with_capacity(4));
    let key = sample_key();
    let now_ms = netmetrics_core::unix_now_ms();
    let judge = |pid: u32, written: &str, request: fn(Opening) -> NameRequest| {
        let mut log = closed_log(&key, 1234, "app.exe", written);
        processor.enrich_connection_log(
            &key,
            pid,
            "app.exe",
            "app.exe",
            request(Opening::at(now_ms)),
            &mut log,
        );
        (log.dst_domain, log.replace_domain)
    };

    // Only the address-only tables name the address.
    processor.record_dns_resolution("table.example", &[key.remote_addr.to_string()]);
    assert_eq!(
        judge(1234, "", NameRequest::replacing),
        ("table.example (inferred)".to_owned(), false),
        "the store takes a first name without being told to"
    );
    assert_eq!(
        judge(1234, "earlier.example (inferred)", NameRequest::replacing),
        ("earlier.example (inferred)".to_owned(), false)
    );
    assert_eq!(
        judge(1234, "withdrawn.example", NameRequest::replacing),
        ("table.example (inferred)".to_owned(), true),
        "no hint stands behind the confirmed name any more"
    );
    assert_eq!(
        judge(1234, "withdrawn.example", NameRequest::adding),
        ("withdrawn.example".to_owned(), false),
        "a judgment that only adds leaves a confirmed name alone"
    );

    // The process's own hint names it.
    processor.record_stub_hint(1234, "own.example", &[key.remote_addr], 60_000, now_ms - 50);
    assert_eq!(
        judge(1234, "earlier.example", NameRequest::replacing),
        ("own.example".to_owned(), true)
    );
    assert_eq!(
        judge(1234, "earlier.example (inferred)", NameRequest::replacing),
        ("own.example".to_owned(), false),
        "confirmed over inferred is the store's own preference"
    );

    // Its own names compete, which leaves no name at all.
    processor.record_stub_hint(
        1234,
        "own-too.example",
        &[key.remote_addr],
        60_000,
        now_ms - 40,
    );
    assert_eq!(
        judge(1234, "own.example", NameRequest::replacing),
        (String::new(), true)
    );
    assert_eq!(
        judge(1234, "table.example (inferred)", NameRequest::replacing),
        (String::new(), true)
    );
    assert_eq!(
        judge(1234, "table.example (inferred)", NameRequest::adding),
        ("table.example (inferred)".to_owned(), false)
    );
}

/// The closed half of the same regression: a connection that closed with a
/// name confirmed from the hints that had arrived by then kept it, whatever
/// arrived a moment later.
#[test]
fn a_hint_from_before_the_opening_that_arrives_after_the_close_corrects_the_row() {
    let dir = tempdir().expect("tempdir");
    let keystore = UnixSecureFileKeyProvider::new(dir.path().join("key"));
    let store =
        Arc::new(Store::open_with_keystore(dir.path().join("db.sqlite"), &keystore).expect("open"));
    let processor = test_processor(Arc::clone(&store), TrafficStreamingHub::with_capacity(4));
    let key = sample_key();
    let mut log = closed_log(&key, 1234, "app.exe", "");
    let opening = opening_of(&log);
    let hint = |query: &str, answered_at_ms| {
        processor.record_stub_hint(1234, query, &[key.remote_addr], 300_000, answered_at_ms);
    };
    hint("earlier.example", opening.at_ms - 60_000);

    let naming = processor.enrich_connection_log(
        &key,
        1234,
        "app.exe",
        "app.exe",
        NameRequest::replacing(opening),
        &mut log,
    );
    assert_eq!(log.dst_domain, "earlier.example");
    store
        .insert_connection_logs(std::slice::from_ref(&log))
        .expect("write the closed row");
    processor.await_final_name(1234, key.remote_addr, "app.exe", opening, naming, &log);
    assert_eq!(
        processor.closed_names.lock().len(),
        1,
        "a confirmed name is held while it is provisional"
    );
    // Evidence the tick before the hint arrives is not about this address.
    settle_closed(&processor);

    hint("just-asked.example", opening.at_ms - 100);
    settle_closed(&processor);
    let rows = store
        .query_connection_logs(&antiwire_store::ConnectionLogQuery::default())
        .expect("query logs")
        .logs;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].dst_domain, "just-asked.example (inferred)");
    assert_eq!(
        processor.closed_names.lock().len(),
        1,
        "and is held until every hint from the opening has had time to arrive"
    );
}

/// A closed connection whose name is final is not held at all, and one whose
/// name is complete but unconfirmed takes only a confirmation.
#[test]
fn a_closed_connection_past_its_provisional_time_only_takes_a_confirmation() {
    let dir = tempdir().expect("tempdir");
    let keystore = UnixSecureFileKeyProvider::new(dir.path().join("key"));
    let store =
        Arc::new(Store::open_with_keystore(dir.path().join("db.sqlite"), &keystore).expect("open"));
    let processor = test_processor(Arc::clone(&store), TrafficStreamingHub::with_capacity(4));
    let key = sample_key();
    let now_ms = netmetrics_core::unix_now_ms();
    // Opened a minute ago: nothing from before then is still on its way.
    let opening = Opening::at(now_ms - 60_000);
    let complete = |lasting| {
        Some(Naming {
            complete_at_ms: opening.at_ms + domain_names::HINTS_ARRIVE_WITHIN_MS,
            lasting,
        })
    };

    let confirmed = closed_log(&key, 1234, "app.exe", "final.example");
    processor.await_final_name(
        1234,
        key.remote_addr,
        "app.exe",
        opening,
        complete(true),
        &confirmed,
    );
    processor.await_final_name(1234, key.remote_addr, "app.exe", opening, None, &confirmed);
    assert_eq!(processor.closed_names.lock().len(), 0);

    let mut inferred = closed_log(&key, 1234, "app.exe", "guess.example (inferred)");
    inferred.conn_id = 8;
    store
        .insert_connection_logs(std::slice::from_ref(&inferred))
        .expect("write the closed row");
    processor.await_final_name(
        1234,
        key.remote_addr,
        "app.exe",
        opening,
        complete(false),
        &inferred,
    );
    assert_eq!(processor.closed_names.lock().len(), 1);
    let domain = || {
        store
            .query_connection_logs(&antiwire_store::ConnectionLogQuery::default())
            .expect("query logs")
            .logs
            .remove(0)
            .dst_domain
    };

    // Another process's answer, after the close, is no reason to rename it.
    processor.record_stub_hint(4321, "other.example", &[key.remote_addr], 60_000, now_ms);
    settle_closed(&processor);
    assert_eq!(domain(), "guess.example (inferred)");
    assert_eq!(processor.closed_names.lock().len(), 1);

    // Its own process's is, and then nothing is left to wait for.
    processor.record_stub_hint(1234, "own.example", &[key.remote_addr], 60_000, now_ms);
    settle_closed(&processor);
    assert_eq!(domain(), "own.example");
    assert_eq!(processor.closed_names.lock().len(), 0);
}

/// The regression this guards: a stub hint was stamped when it was recorded,
/// after the client's owner had been found, which can be later than the
/// client takes to connect. Judged at the connection's opening, the hint then
/// looked as if it had come afterwards, and another name asked for since
/// left the connection unconfirmed.
#[test]
fn a_stub_hint_is_valid_from_when_its_answer_was_served() {
    let dir = tempdir().expect("tempdir");
    let keystore = UnixSecureFileKeyProvider::new(dir.path().join("key"));
    let store =
        Arc::new(Store::open_with_keystore(dir.path().join("db.sqlite"), &keystore).expect("open"));
    let processor = test_processor(store, TrafficStreamingHub::with_capacity(4));
    let key = sample_key();
    let now_ms = netmetrics_core::unix_now_ms();
    let opened_at = now_ms - 2_000;
    // Answered 300 ms before the connection opened, recorded only now.
    processor.record_stub_hint(
        1234,
        "opened-with.example",
        &[key.remote_addr],
        60_000,
        opened_at - 300,
    );
    // The process has since asked for another name at the same address.
    processor.record_stub_hint(
        1234,
        "asked-since.example",
        &[key.remote_addr],
        60_000,
        now_ms - 100,
    );

    let mut log = closed_log(&key, 1234, "app.exe", "");
    processor.enrich_connection_log(
        &key,
        1234,
        "app.exe",
        "app.exe",
        NameRequest::adding(Opening::at(opened_at)),
        &mut log,
    );
    assert_eq!(log.dst_domain, "opened-with.example");
    assert_eq!(processor.domain_lookup_stats().process_hint, 1);
}

/// A DNS answer's event can be delivered after the process that asked has
/// exited. The hint still belongs to that process's executable, which is how
/// a sibling's connection is matched to it.
#[test]
fn a_hint_from_a_process_that_has_exited_is_still_keyed_by_its_executable() {
    let dir = tempdir().expect("tempdir");
    let keystore = UnixSecureFileKeyProvider::new(dir.path().join("key"));
    let store =
        Arc::new(Store::open_with_keystore(dir.path().join("db.sqlite"), &keystore).expect("open"));
    let processor = test_processor(store, TrafficStreamingHub::with_capacity(4));
    let pid = 919_001;
    let started_at = netmetrics_core::unix_now_ms() - 10_000;
    processor.handle_event(&FlowEvent::ProcessStarted(netmetrics_core::ProcessInfo {
        pid,
        identity: ProcessIdentity {
            executable: BROWSER.to_owned(),
            name: "browser.exe".to_owned(),
            start_ts: started_at,
        },
    }));
    assert_eq!(
        processor.hint_image(pid, started_at + 500).executable,
        0,
        "gone, and not yet known to have been running then"
    );

    processor.handle_event(&FlowEvent::ProcessStopped {
        pid,
        stop_ts: started_at + 1_000,
    });
    assert_eq!(
        processor.hint_image(pid, started_at + 500).executable,
        executable_key(BROWSER)
    );
    assert_eq!(
        processor.processes().resolution_stats().attempts,
        0,
        "identifying a hint's process is not a connection attribution"
    );
}

/// A long-lived connection is looked up again long after it opened. The name
/// it opened with must not be lost because the hint has since expired.
#[test]
fn a_connection_is_named_by_the_hints_that_stood_when_it_opened() {
    let dir = tempdir().expect("tempdir");
    let keystore = UnixSecureFileKeyProvider::new(dir.path().join("key"));
    let store =
        Arc::new(Store::open_with_keystore(dir.path().join("db.sqlite"), &keystore).expect("open"));
    let processor = test_processor(store, TrafficStreamingHub::with_capacity(4));
    let key = sample_key();
    let now_ms = netmetrics_core::unix_now_ms();
    let hint = |query: &str, observed_at| {
        processor.handle_event(&FlowEvent::DnsResolvedWithMetadata {
            attribution: DnsResolutionAttribution::Process(1234),
            query: query.to_owned(),
            answers: vec![key.remote_addr.to_string()],
            ttl_ms: 5_000,
            observed_at,
        });
    };
    hint("opened-with.example", now_ms - 600_000);
    hint("asked-later.example", now_ms - 1_000);

    // Opened ten minutes ago, one second after the first answer.
    let mut log = closed_log(&key, 1234, "app.exe", "");
    let opening = Opening::at(now_ms - 599_000);
    processor.enrich_connection_log(
        &key,
        1234,
        "app.exe",
        "app.exe",
        NameRequest::adding(opening),
        &mut log,
    );
    assert_eq!(log.dst_domain, "opened-with.example");
}

/// A row confirmed after it closed was last published unconfirmed, and on a
/// quiet machine nothing else told a subscriber to read it again.
#[tokio::test]
async fn a_late_confirmed_row_is_published_again_with_its_name() {
    let dir = tempdir().expect("tempdir");
    let keystore = UnixSecureFileKeyProvider::new(dir.path().join("key"));
    let store =
        Arc::new(Store::open_with_keystore(dir.path().join("db.sqlite"), &keystore).expect("open"));
    let hub = TrafficStreamingHub::with_capacity(4);
    let mut subscription = hub.subscribe();
    let processor = test_processor(Arc::clone(&store), hub);
    let key = sample_key();
    let now = OffsetDateTime::now_utc();
    let log = NewConnectionLog {
        replace_domain: false,
        is_close: true,
        conn_pid: 1234,
        conn_id: 7,
        timestamp: now,
        app_id: 1,
        app_path: "app.exe".to_owned(),
        protocol: "TCP".to_owned(),
        src_ip: key.local_addr.to_string(),
        src_port: i32::from(key.local_port),
        dst_ip: key.remote_addr.to_string(),
        dst_port: i32::from(key.remote_port),
        dst_domain: "late.example (inferred)".to_owned(),
        bytes_sent: 10,
        bytes_received: 20,
        action_taken: "ALLOWED".to_owned(),
        last_seen: now,
        country_code: String::new(),
        isp: String::new(),
        blocklist_names: String::new(),
    };
    store
        .insert_connection_logs(std::slice::from_ref(&log))
        .expect("write the closed row");

    processor.await_final_name(
        1234,
        key.remote_addr,
        "app.exe",
        opening_of(&log),
        Some(unconfirmed(&log)),
        &log,
    );

    settle_closed(&processor);
    processor.record_stub_hint(
        1234,
        "late.example",
        &[key.remote_addr],
        60_000,
        netmetrics_core::unix_now_ms(),
    );
    settle_closed(&processor);

    let published = tokio::time::timeout(std::time::Duration::from_secs(5), subscription.recv())
        .await
        .expect("the confirmed row is published")
        .expect("the hub is open");
    assert_eq!(published.dst_domain, "late.example");
    assert_eq!(published.app_name, "app.exe");
    assert_eq!((published.bytes_sent, published.bytes_received), (10, 20));
    assert!(published.closed_at > 0 && !published.is_active);
    assert_eq!(processor.domain_lookup_stats().late_upgrades, 1);
}

/// A store error used to discard every ready upgrade.
#[test]
fn a_failed_domain_upgrade_is_retried() {
    let (_dir, store, processor) = flaky_processor();
    ready_upgrade(&processor, 3);
    store.set_mode(StoreMode::Failing);

    settle_closed(&processor);
    assert_eq!(upgrade_attempts_left(&processor), [2]);
    settle_closed(&processor);
    settle_closed(&processor);
    assert!(
        upgrade_attempts_left(&processor).is_empty(),
        "an upgrade gives up once its attempts run out"
    );
}

/// `zip` used to drop upgrades the store returned no result for.
#[test]
fn a_short_domain_upgrade_answer_retries_the_rest() {
    let (_dir, store, processor) = flaky_processor();
    ready_upgrade(&processor, 3);
    store.set_mode(StoreMode::ShortAnswer);

    settle_closed(&processor);
    assert_eq!(upgrade_attempts_left(&processor), [2]);
}

#[tokio::test]
async fn a_process_created_after_the_flow_opened_is_not_its_owner() {
    let dir = tempdir().expect("tempdir");
    let keystore = UnixSecureFileKeyProvider::new(dir.path().join("key"));
    let store =
        Arc::new(Store::open_with_keystore(dir.path().join("db.sqlite"), &keystore).expect("open"));
    let processor = test_processor(Arc::clone(&store), TrafficStreamingHub::with_capacity(4));
    // This test process is the PID's live holder. A flow that opened long
    // before it started belonged to whichever process held the PID then.
    let pid = std::process::id();
    let meta = |open_ts| FlowMeta {
        pid,
        process: None,
        open_ts,
        cookie: None,
        if_index: None,
    };
    let now_ms = u64::try_from(OffsetDateTime::now_utc().unix_timestamp_nanos() / 1_000_000)
        .expect("after the epoch");

    let current = processor.resolve_app(pid, &meta(now_ms));
    assert!(current.app_id > 0, "the live holder owns a flow opened now");
    assert!(current.start_ts > 0 && current.start_ts <= now_ms);
    let unknown_open = processor.resolve_app(pid, &meta(0));
    assert_eq!(
        unknown_open.app_id, current.app_id,
        "no open time, no check"
    );

    let earlier = processor.resolve_app(pid, &meta(current.start_ts - 60_000));
    assert_eq!(earlier.app_id, 0);
    assert_eq!(earlier.app_path, "");
    // Within the one second of clock skew creation-time checks allow, the
    // live holder is still accepted.
    let skewed = processor.resolve_app(pid, &meta(current.start_ts - 500));
    assert_eq!(skewed.app_id, current.app_id);
}

/// The regression this guards: a PID's image was remembered without the time
/// it held from. Once a new process had been given an answer, a delayed
/// answer to the process that had the PID before it was credited to the new
/// one's executable, and confirmed that name for its other processes.
#[test]
fn a_delayed_answer_to_an_earlier_holder_of_the_pid_is_not_its_successors() {
    const EDITOR: &str = r"C:\apps\editor\editor.exe";
    let dir = tempdir().expect("tempdir");
    let keystore = UnixSecureFileKeyProvider::new(dir.path().join("key"));
    let store =
        Arc::new(Store::open_with_keystore(dir.path().join("db.sqlite"), &keystore).expect("open"));
    let processor = test_processor(store, TrafficStreamingHub::with_capacity(4));
    let key = sample_key();
    let pid = 919_101;
    let now_ms = netmetrics_core::unix_now_ms();
    let ran = |executable: &str, name: &str, started_at: u64, stopped_at: u64| {
        processor.handle_event(&FlowEvent::ProcessStarted(netmetrics_core::ProcessInfo {
            pid,
            identity: ProcessIdentity {
                executable: executable.to_owned(),
                name: name.to_owned(),
                start_ts: started_at,
            },
        }));
        processor.handle_event(&FlowEvent::ProcessStopped {
            pid,
            stop_ts: stopped_at,
        });
    };
    // An editor had the PID, then a browser, whose own answer is recorded
    // first and has its image remembered.
    ran(EDITOR, "editor.exe", now_ms - 20_000, now_ms - 15_000);
    ran(BROWSER, "browser.exe", now_ms - 10_000, now_ms - 5_000);
    let elsewhere = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7));
    processor.record_stub_hint(
        pid,
        "browser.example",
        &[elsewhere],
        300_000,
        now_ms - 9_000,
    );
    assert_eq!(
        processor.hint_image(pid, now_ms - 9_000).executable,
        executable_key(BROWSER)
    );

    // An answer the editor was given arrives late.
    processor.record_stub_hint(
        pid,
        "editor.example",
        &[key.remote_addr],
        300_000,
        now_ms - 18_000,
    );
    assert_eq!(
        processor.hint_image(pid, now_ms - 18_000).executable,
        0,
        "the browser had not started when that answer was given"
    );
    assert_eq!(
        processor.hint_image(pid, now_ms - 9_000).executable,
        executable_key(BROWSER),
        "and the browser is still the process remembered"
    );

    // Another browser process connects to the address the editor asked for.
    let mut log = closed_log(&key, 4321, BROWSER, "");
    processor.enrich_connection_log(
        &key,
        4321,
        BROWSER,
        "browser.exe",
        NameRequest::adding(Opening::at(now_ms - 8_000)),
        &mut log,
    );
    assert_eq!(
        log.dst_domain, "editor.example (inferred)",
        "no browser process asked for the name"
    );
}

/// The closed half of judging evidence by when it arrived. A closed
/// connection whose name is complete takes only a confirmation from evidence
/// that arrives now. Evidence that arrived while the name was provisional
/// replaces it, however late the flush that asks about it.
#[test]
fn evidence_that_arrived_in_time_corrects_a_closed_row_however_late_the_flush() {
    // The row's name after evidence that arrived `arrived_after_opening_ms`
    // after the connection opened, or only now when `None`.
    let name_after = |arrived_after_opening_ms: Option<u64>| {
        let dir = tempdir().expect("tempdir");
        let keystore = UnixSecureFileKeyProvider::new(dir.path().join("key"));
        let store = Arc::new(
            Store::open_with_keystore(dir.path().join("db.sqlite"), &keystore).expect("open"),
        );
        let processor = test_processor(Arc::clone(&store), TrafficStreamingHub::with_capacity(4));
        let key = sample_key();
        // Opened a minute ago: nothing from before then is still on its way.
        let opening = Opening::at(netmetrics_core::unix_now_ms() - 60_000);
        let log = closed_log(&key, 1234, "app.exe", "guess.example (inferred)");
        store
            .insert_connection_logs(std::slice::from_ref(&log))
            .expect("write the closed row");
        processor.await_final_name(
            1234,
            key.remote_addr,
            "app.exe",
            opening,
            Some(Naming {
                complete_at_ms: opening.at_ms + domain_names::HINTS_ARRIVE_WITHIN_MS,
                lasting: false,
            }),
            &log,
        );
        settle_closed(&processor);

        // Two names its process held when it opened, one asked for just
        // before: a likely guess, and not a confirmation.
        let hint = |query: &str, answered_at_ms| {
            processor.record_stub_hint(1234, query, &[key.remote_addr], 300_000, answered_at_ms);
        };
        hint("earlier.example", opening.at_ms - 60_000);
        hint("just-asked.example", opening.at_ms - 100);
        if let Some(after_ms) = arrived_after_opening_ms {
            processor.note_named_at([key.remote_addr], opening.at_ms + after_ms);
        }
        settle_closed(&processor);
        store
            .query_connection_logs(&antiwire_store::ConnectionLogQuery::default())
            .expect("query logs")
            .logs
            .remove(0)
            .dst_domain
    };

    assert_eq!(
        name_after(None),
        "guess.example (inferred)",
        "arriving now, long after the opening, only a confirmation would do"
    );
    assert_eq!(name_after(Some(3_000)), "just-asked.example (inferred)");
}
