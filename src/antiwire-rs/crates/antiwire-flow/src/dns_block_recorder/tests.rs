use super::attribution::{attributed_requesting_pid, started_after};
use super::*;
use crate::correlator::DnsAttributionStatus;
use antiwire_events::{AlertKind, NotificationHub};

/// Dropping the last reference must not wait for a worker stuck in a write:
/// that reference can be released on an async runtime thread.
#[test]
fn dropping_the_recorder_stops_its_worker_without_waiting() {
    let (release, blocked) = mpsc::channel::<()>();
    let worker = std::thread::spawn(move || {
        let _ = blocked.recv();
    });
    let (tx, _rx) = mpsc::sync_channel(1);
    let worker_stop = Arc::new(AtomicBool::new(false));
    let recorder = DnsBlockRecorder {
        tx: Arc::new(Mutex::new(Some(tx))),
        settings: Arc::new(RuntimeSettings {
            log_daemon_connections: AtomicBool::new(false),
            notify_threat_detected: AtomicBool::new(true),
        }),
        worker_stop: Arc::clone(&worker_stop),
        worker: Mutex::new(Some(worker)),
        dropped: AtomicU64::new(0),
        pending_reconciliations: Arc::new(AtomicU64::new(0)),
        shed: Arc::new(ShedReporter::default()),
    };

    let started = Instant::now();
    drop(recorder);
    assert!(started.elapsed() < Duration::from_secs(1));
    assert!(
        worker_stop.load(Ordering::Acquire),
        "the worker is told to stop"
    );
    release.send(()).unwrap();
}

/// The regression this guards: the owner was resolved seconds after the
/// query, and a PID reused in between was credited with the block.
#[test]
fn a_process_started_after_the_query_is_not_its_owner() {
    let event = OffsetDateTime::from_unix_timestamp(1_700_000_000).expect("time");
    let event_ms = 1_700_000_000_000_u64;
    assert!(!started_after(event_ms - 60_000, event), "started earlier");
    assert!(!started_after(event_ms + 500, event), "within the skew");
    assert!(started_after(event_ms + 5_000, event), "started later");
    assert!(!started_after(0, event), "unknown start time");
}
use antiwire_platform::{SiemConfig, SiemExporter};
use antiwire_secrets::UnixSecureFileKeyProvider;
use antiwire_store::ConnectionLogQuery;
use netmetrics_core::{DnsCallerIdentity, DnsCorrelationId, DnsQueryEvent};
use serde_json::Value;
use tempfile::tempdir;

#[derive(Clone, Copy)]
enum DeliveryOrder {
    QueryFirst,
    BlockFirst,
}

fn assert_reconciles_delivery_order(order: DeliveryOrder, caller_pid: u32) {
    let dir = tempdir().expect("tempdir");
    let keystore = UnixSecureFileKeyProvider::new(dir.path().join("key"));
    let store =
        Arc::new(Store::open_with_keystore(dir.path().join("db.sqlite"), &keystore).expect("open"));
    let alerts = AlertPublisher::unsaved(NotificationHub::with_capacity(4), None);
    let app_resolver = Arc::new(AppIdResolver::new(
        Arc::clone(&store),
        alerts.clone(),
        SiemExporter::new(SiemConfig::default()),
    ));
    let correlator = Arc::new(DnsQueryCorrelator::default());
    let recorder = DnsBlockRecorder::with_correlator_and_delay(
        Arc::clone(&app_resolver),
        Arc::clone(&store),
        alerts,
        SiemExporter::new(SiemConfig::default()),
        Arc::clone(&correlator),
        Duration::from_millis(100),
    );
    let now = OffsetDateTime::now_utc();
    let query = DnsQueryEvent {
        event_id: None,
        event_version: None,
        name: "race.test".to_owned(),
        query_type: 1,
        status: 0,
        caller: DnsCallerIdentity {
            logging_pid: None,
            requesting_pid: Some(caller_pid),
            resolver_pid: Some(1000),
        },
        correlation: DnsCorrelationId::default(),
        timestamp: u64::try_from(now.unix_timestamp_nanos() / 1_000_000)
            .expect("current timestamp is non-negative and fits in milliseconds"),
    };
    app_resolver.processes().process_started(
        caller_pid,
        &format!(r"C:\apps\caller-{caller_pid}.exe"),
        &format!("caller-{caller_pid}.exe"),
        0,
    );

    if matches!(order, DeliveryOrder::QueryFirst) {
        correlator.record_query(&query);
    }
    recorder.record_blocked_query_with_ownership(
        "race.test",
        Ownership::Resolved(1000),
        &[],
        Some(now),
    );
    if matches!(order, DeliveryOrder::BlockFirst) {
        let deadline = Instant::now() + Duration::from_secs(1);
        while recorder.pending_reconciliation_count() == 0 {
            assert!(
                Instant::now() < deadline,
                "block never entered reconciliation"
            );
            std::thread::yield_now();
        }
        correlator.record_query(&query);
    }

    let deadline = Instant::now() + Duration::from_secs(1);
    loop {
        let page = store
            .query_connection_logs(&ConnectionLogQuery::default())
            .expect("query logs");
        if let Some(log) = page.logs.first() {
            let app = store
                .list_applications()
                .expect("apps")
                .into_iter()
                .find(|app| app.id == log.app_id)
                .expect("persisted app");
            assert_eq!(app.app_name, format!("caller-{caller_pid}.exe"));
            break;
        }
        assert!(Instant::now() < deadline, "block was not persisted");
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn wait_for_persisted_app(store: &Store) -> (String, String) {
    let deadline = Instant::now() + Duration::from_secs(1);
    loop {
        let page = store
            .query_connection_logs(&ConnectionLogQuery::default())
            .expect("query logs");
        if let Some(log) = page.logs.first() {
            let app = store
                .list_applications()
                .expect("apps")
                .into_iter()
                .find(|app| app.id == log.app_id)
                .expect("persisted app");
            return (app.app_name, app.app_path);
        }
        assert!(Instant::now() < deadline, "block was not persisted");
        std::thread::sleep(Duration::from_millis(10));
    }
}

/// A recorder and the resolver it attributes blocks with.
fn block_recorder_fixture(
    store: &Arc<Store>,
    correlator: &Arc<DnsQueryCorrelator>,
) -> (Arc<DnsBlockRecorder>, Arc<AppIdResolver>) {
    let alerts = AlertPublisher::unsaved(NotificationHub::with_capacity(4), None);
    let app_resolver = Arc::new(AppIdResolver::new(
        Arc::clone(store),
        alerts.clone(),
        SiemExporter::new(SiemConfig::default()),
    ));
    let recorder = DnsBlockRecorder::with_correlator_and_delay(
        Arc::clone(&app_resolver),
        Arc::clone(store),
        alerts,
        SiemExporter::new(SiemConfig::default()),
        Arc::clone(correlator),
        Duration::from_millis(100),
    );
    (recorder, app_resolver)
}

fn query_event(
    domain: &str,
    logging_pid: Option<u32>,
    requesting_pid: u32,
    timestamp_ms: u64,
) -> DnsQueryEvent {
    DnsQueryEvent {
        event_id: None,
        event_version: None,
        name: domain.to_owned(),
        query_type: 1,
        status: 0,
        caller: DnsCallerIdentity {
            logging_pid,
            requesting_pid: Some(requesting_pid),
            resolver_pid: None,
        },
        correlation: DnsCorrelationId::default(),
        timestamp: timestamp_ms,
    }
}

fn now_ms() -> u64 {
    u64::try_from(OffsetDateTime::now_utc().unix_timestamp_nanos() / 1_000_000).unwrap_or_default()
}

/// The resolved socket owner is frequently the system resolver, whose
/// identity need not appear in the recorded query. A unique recorded caller
/// must still attribute the block.
#[test]
fn resolver_owned_block_falls_back_to_the_recorded_caller() {
    let dir = tempdir().expect("tempdir");
    let keystore = UnixSecureFileKeyProvider::new(dir.path().join("key"));
    let store =
        Arc::new(Store::open_with_keystore(dir.path().join("db.sqlite"), &keystore).expect("open"));
    let correlator = Arc::new(DnsQueryCorrelator::default());
    let (recorder, app_resolver) = block_recorder_fixture(&store, &correlator);
    let caller = 71_701;
    app_resolver
        .processes()
        .process_started(caller, r"C:\apps\caller.exe", "caller.exe", 0);

    let now = OffsetDateTime::now_utc();
    correlator.record_query(&query_event("github.com", Some(7000), caller, now_ms()));
    recorder.record_blocked_query_with_ownership(
        "github.com",
        Ownership::Resolved(9000),
        &[],
        Some(now),
    );

    assert_eq!(wait_for_persisted_app(&store).0, "caller.exe");
}

/// Multiple callers whose requests are clearly separated in time are
/// resolved to the nearest one, which is the request that caused the block.
#[test]
fn scoped_ambiguity_falls_back_to_the_nearest_caller() {
    let dir = tempdir().expect("tempdir");
    let keystore = UnixSecureFileKeyProvider::new(dir.path().join("key"));
    let store =
        Arc::new(Store::open_with_keystore(dir.path().join("db.sqlite"), &keystore).expect("open"));
    let correlator = Arc::new(DnsQueryCorrelator::default());
    let (recorder, app_resolver) = block_recorder_fixture(&store, &correlator);
    let nearest = 71_702;
    let older = 71_703;
    app_resolver
        .processes()
        .process_started(nearest, r"C:\apps\nearest.exe", "nearest.exe", 0);
    app_resolver
        .processes()
        .process_started(older, r"C:\apps\older.exe", "older.exe", 0);

    let now = OffsetDateTime::now_utc();
    let target = now_ms();
    correlator.record_query(&query_event("github.com", Some(9000), nearest, target - 40));
    correlator.record_query(&query_event(
        "github.com",
        Some(9000),
        older,
        target - 3_000,
    ));
    recorder.record_blocked_query_with_ownership(
        "github.com",
        Ownership::Resolved(9000),
        &[],
        Some(now),
    );

    assert_eq!(wait_for_persisted_app(&store).0, "nearest.exe");
}

/// Near-simultaneous callers cannot be told apart, so the block falls back
/// to the process that owns the query's socket. Naming the resolver is
/// truthful: it is the process that actually sent the query.
#[test]
fn near_simultaneous_callers_fall_back_to_the_socket_owner() {
    let dir = tempdir().expect("tempdir");
    let keystore = UnixSecureFileKeyProvider::new(dir.path().join("key"));
    let store =
        Arc::new(Store::open_with_keystore(dir.path().join("db.sqlite"), &keystore).expect("open"));
    let correlator = Arc::new(DnsQueryCorrelator::default());
    let (recorder, app_resolver) = block_recorder_fixture(&store, &correlator);
    let first = 71_704;
    let second = 71_705;
    let resolver = 71_706;
    app_resolver
        .processes()
        .process_started(first, r"C:\apps\first.exe", "first.exe", 0);
    app_resolver
        .processes()
        .process_started(second, r"C:\apps\second.exe", "second.exe", 0);
    app_resolver
        .processes()
        .process_started(resolver, r"C:\apps\resolver.exe", "resolver.exe", 0);

    let now = OffsetDateTime::now_utc();
    let target = now_ms();
    correlator.record_query(&query_event("github.com", Some(9000), first, target - 100));
    correlator.record_query(&query_event("github.com", Some(9000), second, target - 200));
    recorder.record_blocked_query_with_ownership(
        "github.com",
        Ownership::Resolved(resolver),
        &[],
        Some(now),
    );

    assert_eq!(wait_for_persisted_app(&store).0, "resolver.exe");
}

/// A direct query whose caller never reached ETW is still owned by the
/// process that sent it; the socket owner is the record's identity.
#[test]
fn socket_owner_attributes_a_block_without_any_caller_evidence() {
    let dir = tempdir().expect("tempdir");
    let keystore = UnixSecureFileKeyProvider::new(dir.path().join("key"));
    let store =
        Arc::new(Store::open_with_keystore(dir.path().join("db.sqlite"), &keystore).expect("open"));
    let correlator = Arc::new(DnsQueryCorrelator::default());
    let (recorder, app_resolver) = block_recorder_fixture(&store, &correlator);
    let direct = 71_707;
    app_resolver
        .processes()
        .process_started(direct, r"C:\apps\direct.exe", "direct.exe", 0);

    recorder.record_blocked_query_with_ownership(
        "github.com",
        Ownership::Resolved(direct),
        &[],
        Some(OffsetDateTime::now_utc()),
    );

    assert_eq!(wait_for_persisted_app(&store).0, "direct.exe");
}

/// With neither caller nor socket-owner evidence the record must stay
/// honestly unattributed.
#[test]
fn block_without_any_owner_stays_unknown_no_owner() {
    let dir = tempdir().expect("tempdir");
    let keystore = UnixSecureFileKeyProvider::new(dir.path().join("key"));
    let store =
        Arc::new(Store::open_with_keystore(dir.path().join("db.sqlite"), &keystore).expect("open"));
    let correlator = Arc::new(DnsQueryCorrelator::default());
    let (recorder, _app_resolver) = block_recorder_fixture(&store, &correlator);

    recorder.record_blocked_query_with_ownership(
        "github.com",
        Ownership::NotFound,
        &[],
        Some(OffsetDateTime::now_utc()),
    );

    let (name, path) = wait_for_persisted_app(&store);
    assert_eq!(name, "unknown.exe");
    assert_eq!(path, "Unknown (No Owner)");
}

fn block_key(domain: &str) -> DnsBlockKey {
    DnsBlockKey {
        pid: 42,
        domain: domain.to_owned(),
    }
}

#[test]
fn repeated_dns_blocks_are_deduplicated_within_the_window() {
    let mut recent = RecentLru::new(2);
    let start = Instant::now();
    let dedup_window = Duration::from_secs(30);

    for step in 0..100_u64 {
        let now = start
            .checked_add(Duration::from_secs(step * 31))
            .expect("test instant remains representable");
        assert!(recent.should_admit(block_key("repeat.example"), now, dedup_window));
    }

    let within_window = start
        .checked_add(Duration::from_secs(99 * 31 + 1))
        .expect("test instant remains representable");
    assert!(!recent.should_admit(block_key("repeat.example"), within_window, dedup_window));
}

#[test]
fn recent_dns_block_eviction_preserves_current_entries() {
    let mut recent = RecentLru::new(2);
    let now = Instant::now();
    let dedup_window = Duration::from_secs(30);

    assert!(recent.should_admit(block_key("one.example"), now, dedup_window));
    assert!(recent.should_admit(block_key("two.example"), now, dedup_window));
    assert!(recent.should_admit(block_key("three.example"), now, dedup_window));

    let within_window = now + Duration::from_secs(1);
    assert!(!recent.should_admit(block_key("two.example"), within_window, dedup_window));
    assert!(!recent.should_admit(block_key("three.example"), within_window, dedup_window));
    assert!(recent.should_admit(block_key("one.example"), within_window, dedup_window));
}

#[test]
fn shutdown_sheds_many_unresolved_records_without_delaying_known_record() {
    let dir = tempdir().expect("tempdir");
    let (store, publisher, mut worker, shed, _siem_path) = retry_worker_fixture(dir.path());
    worker.reconciliation_delay = Duration::from_secs(60);
    let bad_pid = 5_300_020;
    let bad_path = r"C:\apps\dns-shutdown-budget-bad.exe";
    let bad_name = "dns-shutdown-budget-bad.exe";
    let known_pid = 5_300_021;
    let known_path = r"C:\apps\dns-shutdown-budget-known.exe";
    let known_name = "dns-shutdown-budget-known.exe";
    let processes = worker.app_resolver.processes();
    processes.process_started(bad_pid, bad_path, bad_name, 6_000);
    processes.process_started(known_pid, known_path, known_name, 6_001);
    processes.process_stopped(bad_pid);
    processes.process_stopped(known_pid);
    assert!(
        worker
            .app_resolver
            .get_or_create_app_id(known_path, known_name)
            > 0
    );

    let fault = rusqlite::Connection::open(store.path()).expect("fault-injection connection");
    fault
        .execute_batch(
            r"CREATE TRIGGER fail_dns_application_insert_shutdown_budget
             BEFORE INSERT ON applications
             WHEN NEW.app_path = 'C:\apps\dns-shutdown-budget-bad.exe'
             BEGIN SELECT RAISE(ABORT, 'injected shutdown application write failure'); END;",
        )
        .expect("install shutdown application fault");

    let (tx, rx) = mpsc::sync_channel(WRITE_QUEUE_CAPACITY);
    let start = OffsetDateTime::now_utc();
    for index in 0..200_u32 {
        let mut item = pending_test_block_for_pid(
            &format!("shutdown-budget-bad-{index}.example"),
            bad_pid,
            start + time::Duration::milliseconds(i64::from(index)),
        );
        item.ownership = PendingOwnership::Socket(Ownership::Resolved(bad_pid));
        tx.send(item).expect("queue unresolved block");
    }
    let mut known = pending_test_block_for_pid(
        "shutdown-budget-known.example",
        known_pid,
        start + time::Duration::milliseconds(200),
    );
    known.ownership = PendingOwnership::Socket(Ownership::Resolved(known_pid));
    tx.send(known)
        .expect("queue known block after unresolved records");
    drop(tx);
    // Socket owners without caller evidence enter reconciliation. Start
    // with admission closed so shutdown must process twenty small pending
    // batches, rather than one large directly attributed batch.
    let (done_tx, done_rx) = mpsc::channel();
    let thread = std::thread::spawn(move || {
        worker.run(&rx, &AtomicBool::new(true));
        let _ = done_tx.send(());
    });
    wait_for_shed(&shed);
    done_rx
        .recv_timeout(WORKER_JOIN_TIMEOUT)
        .expect("worker must finish bounded unresolved shutdown");
    thread.join().expect("worker shutdown");
    drop(fault);

    let page = store
        .query_connection_logs(&ConnectionLogQuery::default())
        .expect("query logs");
    assert_eq!(page.total_count, 1, "only the known record should persist");
    assert_eq!(page.logs[0].dst_domain, "shutdown-budget-known.example");
    assert!(page
        .logs
        .iter()
        .all(|log| { !log.dst_domain.starts_with("shutdown-budget-bad-") }));
    assert!(shed.reported.load(Ordering::Relaxed));
    drop(publisher);
}

/// A re-admission after the dedup window must count as a fresh use, so a later
/// insertion evicts an actually-colder entry rather than the just-re-admitted one.
#[test]
fn readmitted_dns_block_refreshes_its_queue_position() {
    let mut recent = RecentLru::new(2);
    let start = Instant::now();
    let window = Duration::from_secs(30);
    let after_window = start + Duration::from_secs(31);

    assert!(recent.should_admit(block_key("one.example"), start, window));
    assert!(recent.should_admit(block_key("two.example"), start, window));
    // `one` is re-admitted after its window, so it is now fresher than `two`.
    assert!(recent.should_admit(block_key("one.example"), after_window, window));
    // A new key must evict the coldest entry (`two`), leaving the fresh `one`.
    assert!(recent.should_admit(block_key("three.example"), after_window, window));

    assert!(
        !recent.should_admit(block_key("one.example"), after_window, window),
        "the re-admitted entry must not be evicted while its window is still open"
    );
}

#[test]
fn update_settings_stores_both_flags() {
    let dir = tempdir().expect("tempdir");
    let (_store, _hub, recorder, _resolver) = recorder_fixture(dir.path());

    recorder.update_settings(true, false);

    assert!(recorder
        .settings
        .log_daemon_connections
        .load(Ordering::Relaxed));
    assert!(!recorder
        .settings
        .notify_threat_detected
        .load(Ordering::Relaxed));
}

#[test]
fn shed_reporter_surfaces_and_recovers() {
    let health = Arc::new(CollectorHealth::default());
    let shed = ShedReporter::default();
    shed.set_health(Arc::clone(&health));

    shed.report();
    assert!(
        !health.byte_accounting_available(),
        "a dropped blocked-DNS record must degrade collector health"
    );
    assert!(health.detail().contains("blocked DNS"));

    shed.recovered();
    assert!(health.byte_accounting_available());
    assert_eq!(health.detail(), "");
}

#[test]
fn shed_reporter_serializes_recovery_with_health_updates() {
    let health = Arc::new(CollectorHealth::default());
    let shed = Arc::new(ShedReporter::default());
    shed.set_health(Arc::clone(&health));
    shed.report();

    // Hold the same gate used by `recovered` while a producer attempts to
    // clear the report. The producer cannot observe the state transition
    // between `reported.swap(false)` and `clear_records_shed()` because
    // both operations are serialized under this gate.
    let gate = shed.gate.lock();
    let (done_tx, done_rx) = mpsc::channel();
    let recovering = Arc::clone(&shed);
    let recovery = std::thread::spawn(move || {
        recovering.recovered();
        done_tx.send(()).expect("recovery completion");
    });
    assert!(
        done_rx.try_recv().is_err(),
        "recovery must wait for the state/health gate"
    );
    drop(gate);
    done_rx.recv().expect("recovery completed");
    recovery.join().expect("recovery thread");

    shed.report();
    assert!(shed.reported.load(Ordering::Relaxed));
    assert!(
        !health.byte_accounting_available(),
        "a report after recovery must remain visible in collector health"
    );
}

fn retry_worker_fixture(
    dir: &Path,
) -> (
    Arc<Store>,
    AlertPublisher,
    DnsBlockWorker,
    Arc<ShedReporter>,
    PathBuf,
) {
    let keystore = UnixSecureFileKeyProvider::new(dir.join("key"));
    let store =
        Arc::new(Store::open_with_keystore(dir.join("db.sqlite"), &keystore).expect("open"));
    let publisher = AlertPublisher::saved(NotificationHub::new(), Arc::clone(&store), None);
    let siem_path = dir.join("events.json");
    let siem = SiemExporter::new(SiemConfig {
        enabled: true,
        file_enabled: true,
        file_path: siem_path.clone(),
        ..SiemConfig::default()
    });
    let resolver = Arc::new(AppIdResolver::new(
        Arc::clone(&store),
        publisher.clone(),
        SiemExporter::new(SiemConfig::default()),
    ));
    let settings = Arc::new(RuntimeSettings {
        log_daemon_connections: AtomicBool::new(true),
        notify_threat_detected: AtomicBool::new(true),
    });
    let pending_reconciliations = Arc::new(AtomicU64::new(0));
    let shed = Arc::new(ShedReporter::default());
    let worker = DnsBlockWorker {
        app_resolver: resolver,
        store: Arc::clone(&store),
        alerts: publisher.clone(),
        siem,
        settings,
        correlator: Arc::new(DnsQueryCorrelator::default()),
        reconciliation_delay: Duration::ZERO,
        pending_reconciliations,
        daemon_path: None,
        shed: Arc::clone(&shed),
        early_reconciliations: AtomicU64::new(0),
    };
    (store, publisher, worker, shed, siem_path)
}

fn flush_test_siem(siem: &SiemExporter, path: &Path) {
    siem.update_config(SiemConfig {
        enabled: true,
        file_enabled: true,
        file_path: path.to_owned(),
        ..SiemConfig::default()
    })
    .expect("flush SIEM worker");
}

fn siem_app_paths(path: &Path) -> Vec<String> {
    std::fs::read_to_string(path)
        .expect("SIEM output")
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).expect("SIEM JSON event"))
        .filter_map(|event| {
            event
                .get("details")
                .and_then(|details| details.get("app_path"))
                .and_then(Value::as_str)
                .map(str::to_owned)
        })
        .collect()
}

fn pending_test_block(domain: &str, timestamp: OffsetDateTime) -> PendingBlock {
    PendingBlock {
        domain: domain.to_owned(),
        ownership: PendingOwnership::Caller(0),
        blocklist_names: Vec::new(),
        timestamp,
    }
}

fn pending_test_block_for_pid(domain: &str, pid: u32, timestamp: OffsetDateTime) -> PendingBlock {
    PendingBlock {
        domain: domain.to_owned(),
        ownership: PendingOwnership::Caller(pid),
        blocklist_names: Vec::new(),
        timestamp,
    }
}

fn wait_for_shed(shed: &ShedReporter) {
    let deadline = Instant::now() + Duration::from_secs(2);
    while !shed.reported.load(Ordering::Relaxed) {
        assert!(Instant::now() < deadline, "write fault was never observed");
        std::thread::sleep(Duration::from_millis(5));
    }
}

fn wait_for_log_count(store: &Store, expected: u64) {
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        let page = store
            .query_connection_logs(&ConnectionLogQuery::default())
            .expect("query logs");
        if page.total_count >= expected {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "expected DNS blocks were not persisted"
        );
        std::thread::sleep(Duration::from_millis(5));
    }
}

#[test]
fn failed_dns_batch_retries_in_order_and_fans_out_once_after_recovery() {
    let dir = tempdir().expect("tempdir");
    let (store, publisher, worker, shed, siem_path) = retry_worker_fixture(dir.path());
    let fault = rusqlite::Connection::open(store.path()).expect("fault-injection connection");
    fault
        .execute_batch(
            "CREATE TRIGGER fail_dns_connection_insert
             BEFORE INSERT ON connection_logs
             BEGIN SELECT RAISE(ABORT, 'injected DNS write failure'); END;",
        )
        .expect("install DNS write fault");

    let (tx, rx) = mpsc::sync_channel(WRITE_QUEUE_CAPACITY);
    let stop = Arc::new(AtomicBool::new(false));
    let thread_stop = Arc::clone(&stop);
    let thread = std::thread::spawn(move || worker.run(&rx, &thread_stop));
    let start = OffsetDateTime::now_utc();
    tx.send(pending_test_block("retry-first.example", start))
        .expect("queue first block");
    tx.send(pending_test_block(
        "retry-second.example",
        // SQLite stores these timestamps at millisecond precision. Keep
        // the fixture's intended order observable after persistence
        // instead of relying on a sub-millisecond tie-break.
        start + time::Duration::milliseconds(1),
    ))
    .expect("queue second block");

    wait_for_shed(&shed);
    fault
        .execute_batch("DROP TRIGGER fail_dns_connection_insert")
        .expect("remove DNS write fault");
    wait_for_log_count(&store, 2);

    stop.store(true, Ordering::Release);
    drop(tx);
    thread.join().expect("worker shutdown");

    let page = store
        .query_connection_logs(&ConnectionLogQuery {
            order_by: Some("timestamp".to_owned()),
            sort_descending: false,
            ..ConnectionLogQuery::default()
        })
        .expect("query logs");
    assert_eq!(
        page.logs
            .iter()
            .map(|log| log.dst_domain.as_str())
            .collect::<Vec<_>>(),
        ["retry-first.example", "retry-second.example"]
    );
    publisher.flush();
    let alerts = store.list_alerts().expect("alerts");
    for domain in ["retry-first.example", "retry-second.example"] {
        assert_eq!(
            alerts
                .iter()
                .filter(|alert| alert.message.contains(domain))
                .count(),
            1,
            "notification fan-out must happen once for {domain}"
        );
    }
    let siem = std::fs::read_to_string(siem_path).expect("SIEM output");
    for domain in ["retry-first.example", "retry-second.example"] {
        assert_eq!(
            siem.matches(domain).count(),
            2,
            "one connection and one new-domain SIEM event expected for {domain}"
        );
    }
    assert!(!shed.reported.load(Ordering::Relaxed));
    drop(publisher);
}

#[test]
fn failed_application_write_retries_before_dedup_and_fans_out_once_after_recovery() {
    let dir = tempdir().expect("tempdir");
    let (store, publisher, worker, shed, siem_path) = retry_worker_fixture(dir.path());
    let fault = rusqlite::Connection::open(store.path()).expect("fault-injection connection");
    fault
        .execute_batch(
            "CREATE TRIGGER fail_dns_application_insert
             BEFORE INSERT ON applications
             BEGIN SELECT RAISE(ABORT, 'injected application write failure'); END;",
        )
        .expect("install application write fault");

    let pid = 5_200_001;
    let processes = worker.app_resolver.processes();
    processes.process_started(
        pid,
        &format!(r"C:\apps\dns-retry-{pid}.exe"),
        &format!("dns-retry-{pid}.exe"),
        1_000,
    );
    processes.process_stopped(pid);

    let (tx, rx) = mpsc::sync_channel(WRITE_QUEUE_CAPACITY);
    let stop = Arc::new(AtomicBool::new(false));
    let thread_stop = Arc::clone(&stop);
    let thread = std::thread::spawn(move || worker.run(&rx, &thread_stop));
    let domain = "retry-after-application-failure.example";
    tx.send(pending_test_block_for_pid(
        domain,
        pid,
        OffsetDateTime::now_utc(),
    ))
    .expect("queue block");

    wait_for_shed(&shed);
    fault
        .execute_batch("DROP TRIGGER fail_dns_application_insert")
        .expect("remove application write fault");
    wait_for_log_count(&store, 1);

    stop.store(true, Ordering::Release);
    drop(tx);
    thread.join().expect("worker shutdown");

    let page = store
        .query_connection_logs(&ConnectionLogQuery::default())
        .expect("query logs");
    assert_eq!(
        page.logs
            .iter()
            .filter(|log| log.dst_domain == domain)
            .count(),
        1,
        "the recovered application write must produce one DNS row"
    );
    publisher.flush();
    let alerts = store.list_alerts().expect("alerts");
    assert_eq!(
        alerts
            .iter()
            .filter(|alert| alert.message.contains(domain))
            .count(),
        1,
        "notification fan-out must happen once after application recovery"
    );
    let siem = std::fs::read_to_string(siem_path).expect("SIEM output");
    assert_eq!(
        siem.matches(domain).count(),
        2,
        "one connection and one new-domain SIEM event expected after recovery"
    );
    drop(publisher);
}

#[test]
fn failed_application_write_keeps_captured_identity_after_pid_reuse() {
    let dir = tempdir().expect("tempdir");
    let (store, publisher, worker, shed, siem_path) = retry_worker_fixture(dir.path());
    let fault = rusqlite::Connection::open(store.path()).expect("fault-injection connection");
    fault
        .execute_batch(
            "CREATE TRIGGER fail_dns_application_insert_reuse
             BEFORE INSERT ON applications
             BEGIN SELECT RAISE(ABORT, 'injected application write failure'); END;",
        )
        .expect("install application write fault");

    let pid = 5_200_002;
    let old_path = format!(r"C:\apps\dns-old-{pid}.exe");
    let old_name = format!("dns-old-{pid}.exe");
    let new_path = format!(r"C:\apps\dns-new-{pid}.exe");
    let new_name = format!("dns-new-{pid}.exe");
    let app_resolver = Arc::clone(&worker.app_resolver);
    app_resolver
        .processes()
        .process_started(pid, &old_path, &old_name, 2_000);
    app_resolver.processes().process_stopped(pid);

    let (tx, rx) = mpsc::sync_channel(WRITE_QUEUE_CAPACITY);
    let stop = Arc::new(AtomicBool::new(false));
    let thread_stop = Arc::clone(&stop);
    let siem_barrier = worker.siem.clone();
    let thread = std::thread::spawn(move || worker.run(&rx, &thread_stop));
    let domain = "retry-after-pid-reuse.example";
    tx.send(pending_test_block_for_pid(
        domain,
        pid,
        OffsetDateTime::now_utc(),
    ))
    .expect("queue block");

    wait_for_shed(&shed);
    // Keep the application trigger active while replacing the lifecycle
    // evidence. The batch must already contain the old path/name before
    // this PID is reused, and must never resolve the new occupant.
    app_resolver
        .processes()
        .process_started(pid, &new_path, &new_name, 3_000);
    fault
        .execute_batch("DROP TRIGGER fail_dns_application_insert_reuse")
        .expect("remove application write fault");
    wait_for_log_count(&store, 1);

    stop.store(true, Ordering::Release);
    drop(tx);
    thread.join().expect("worker shutdown");
    flush_test_siem(&siem_barrier, &siem_path);

    let page = store
        .query_connection_logs(&ConnectionLogQuery::default())
        .expect("query logs");
    let log = page
        .logs
        .iter()
        .find(|log| log.dst_domain == domain)
        .expect("recovered DNS row");
    let app = store
        .list_applications()
        .expect("apps")
        .into_iter()
        .find(|app| app.id == log.app_id)
        .expect("persisted app");
    assert_eq!(app.app_path, old_path);
    assert_eq!(app.app_name, old_name);
    assert_ne!(app.app_path, new_path);
    assert_ne!(app.app_name, new_name);

    publisher.flush();
    let alerts = store.list_alerts().expect("alerts");
    let alert = alerts
        .iter()
        .find(|alert| alert.message.contains(domain))
        .expect("DNS notification");
    assert!(alert.message.contains(&old_name));
    assert!(!alert.message.contains(&new_name));
    let siem_paths = siem_app_paths(&siem_path);
    assert!(siem_paths.iter().any(|path| path == &old_path));
    assert!(!siem_paths.iter().any(|path| path == &new_path));
    drop(publisher);
}

fn mixed_shutdown_identities(worker: &DnsBlockWorker) -> (Vec<(u32, String, String)>, u32) {
    let processes = worker.app_resolver.processes();
    let mut known = Vec::new();
    for index in 0..10_u32 {
        let pid = 5_300_001 + index;
        let path = format!(r"C:\apps\dns-mixed-known-{index}.exe");
        let name = format!("dns-mixed-known-{index}.exe");
        processes.process_started(pid, &path, &name, 4_000 + u64::from(index));
        processes.process_stopped(pid);
        let app_id = worker.app_resolver.get_or_create_app_id(&path, &name);
        assert!(app_id > 0, "known application must be cached");
        known.push((pid, path, name));
    }

    let unresolved_pid = 5_300_011;
    let unresolved_path = r"C:\apps\dns-mixed-unresolved.exe".to_owned();
    let unresolved_name = "dns-mixed-unresolved.exe".to_owned();
    processes.process_started(unresolved_pid, &unresolved_path, &unresolved_name, 5_000);
    processes.process_stopped(unresolved_pid);
    (known, unresolved_pid)
}

fn assert_mixed_shutdown_results(store: &Store, siem_path: &Path, shed: &ShedReporter) {
    let page = store
        .query_connection_logs(&ConnectionLogQuery {
            order_by: Some("timestamp".to_owned()),
            sort_descending: false,
            ..ConnectionLogQuery::default()
        })
        .expect("query logs");
    assert_eq!(
        page.total_count, 10,
        "only the unresolved app should be shed"
    );
    let expected_domains = (0..10)
        .map(|index| format!("mixed-known-{index}.example"))
        .collect::<Vec<_>>();
    assert_eq!(
        page.logs
            .iter()
            .map(|log| log.dst_domain.clone())
            .collect::<Vec<_>>(),
        expected_domains
    );
    assert!(page
        .logs
        .iter()
        .all(|log| log.dst_domain != "mixed-unresolved.example"));

    let alerts = store.list_alerts().expect("alerts");
    for index in 0..10 {
        let domain = format!("mixed-known-{index}.example");
        assert_eq!(
            alerts
                .iter()
                .filter(|alert| alert.message.contains(&domain))
                .count(),
            1,
            "notification fan-out must happen once for {domain}"
        );
    }
    assert!(!alerts
        .iter()
        .any(|alert| alert.message.contains("mixed-unresolved.example")));
    let siem = std::fs::read_to_string(siem_path).expect("SIEM output");
    for index in 0..10 {
        let domain = format!("mixed-known-{index}.example");
        assert_eq!(
            siem.matches(&domain).count(),
            2,
            "one connection and one new-domain SIEM event expected for {domain}"
        );
    }
    assert!(!siem.contains("mixed-unresolved.example"));
    assert!(shed.reported.load(Ordering::Relaxed));
}

#[test]
fn shutdown_persists_resolved_subset_when_one_application_stays_unresolved() {
    let dir = tempdir().expect("tempdir");
    let (store, publisher, worker, shed, siem_path) = retry_worker_fixture(dir.path());
    let (known, unresolved_pid) = mixed_shutdown_identities(&worker);

    let fault = rusqlite::Connection::open(store.path()).expect("fault-injection connection");
    fault
        .execute_batch(
            r"CREATE TRIGGER fail_dns_application_insert_mixed
             BEFORE INSERT ON applications
             WHEN NEW.app_path = 'C:\apps\dns-mixed-unresolved.exe'
             BEGIN SELECT RAISE(ABORT, 'injected mixed application write failure'); END;",
        )
        .expect("install mixed application write fault");

    let (tx, rx) = mpsc::sync_channel(WRITE_QUEUE_CAPACITY);
    let stop = Arc::new(AtomicBool::new(false));
    let thread_stop = Arc::clone(&stop);
    let thread = std::thread::spawn(move || worker.run(&rx, &thread_stop));
    let start = OffsetDateTime::now_utc();
    for (index, (pid, _, _)) in known.iter().take(9).enumerate() {
        tx.send(pending_test_block_for_pid(
            &format!("mixed-known-{index}.example"),
            *pid,
            start + time::Duration::milliseconds(i64::try_from(index).unwrap_or(0)),
        ))
        .expect("queue known block");
    }
    tx.send(pending_test_block_for_pid(
        "mixed-unresolved.example",
        unresolved_pid,
        start + time::Duration::milliseconds(9),
    ))
    .expect("queue unresolved block");
    let (queued_pid, _, _) = &known[9];
    tx.send(pending_test_block_for_pid(
        "mixed-known-9.example",
        *queued_pid,
        start + time::Duration::milliseconds(10),
    ))
    .expect("queue known block after unresolved head");

    wait_for_shed(&shed);
    stop.store(true, Ordering::Release);
    drop(tx);
    thread.join().expect("worker shutdown");
    drop(fault);
    publisher.flush();
    assert_mixed_shutdown_results(&store, &siem_path, &shed);
    drop(publisher);
}

#[test]
fn unrecoverable_dns_write_is_explicitly_shed_on_shutdown() {
    let dir = tempdir().expect("tempdir");
    let (store, _hub, worker, shed, _siem_path) = retry_worker_fixture(dir.path());
    let fault = rusqlite::Connection::open(store.path()).expect("fault-injection connection");
    fault
        .execute_batch(
            "CREATE TRIGGER fail_dns_connection_insert_shutdown
             BEFORE INSERT ON connection_logs
             BEGIN SELECT RAISE(ABORT, 'injected DNS shutdown write failure'); END;",
        )
        .expect("install DNS write fault");

    let (tx, rx) = mpsc::sync_channel(WRITE_QUEUE_CAPACITY);
    let stop = Arc::new(AtomicBool::new(false));
    let thread_stop = Arc::clone(&stop);
    let thread = std::thread::spawn(move || worker.run(&rx, &thread_stop));
    tx.send(pending_test_block(
        "shed-on-shutdown.example",
        OffsetDateTime::now_utc(),
    ))
    .expect("queue block");

    wait_for_shed(&shed);
    stop.store(true, Ordering::Release);
    drop(tx);
    thread.join().expect("worker must shed and stop");
    assert!(shed.reported.load(Ordering::Relaxed));
    assert_eq!(
        store
            .query_connection_logs(&ConnectionLogQuery::default())
            .expect("query logs")
            .total_count,
        0
    );
}

#[test]
fn saturated_queue_drains_and_sustained_load_preserves_every_admitted_event() {
    let dir = tempdir().expect("tempdir");
    let store = Arc::new(Store::open(dir.path().join("load.sqlite")).unwrap());
    let publisher = AlertPublisher::unsaved(NotificationHub::with_capacity(4), None);
    let resolver = Arc::new(AppIdResolver::new(
        Arc::clone(&store),
        publisher.clone(),
        SiemExporter::new(SiemConfig::default()),
    ));
    let pending = Arc::new(AtomicU64::new(0));
    let worker = DnsBlockWorker {
        app_resolver: resolver,
        store: Arc::clone(&store),
        alerts: publisher,
        siem: SiemExporter::new(SiemConfig::default()),
        settings: Arc::new(RuntimeSettings {
            log_daemon_connections: AtomicBool::new(false),
            notify_threat_detected: AtomicBool::new(false),
        }),
        correlator: Arc::new(DnsQueryCorrelator::default()),
        reconciliation_delay: Duration::ZERO,
        pending_reconciliations: Arc::clone(&pending),
        daemon_path: None,
        shed: Arc::new(ShedReporter::default()),
        early_reconciliations: AtomicU64::new(0),
    };
    let (tx, rx) = mpsc::sync_channel(WRITE_QUEUE_CAPACITY);
    let now = OffsetDateTime::now_utc();
    let item = PendingBlock {
        domain: "flood.example".to_owned(),
        ownership: PendingOwnership::Caller(0),
        blocklist_names: vec![],
        timestamp: now,
    };
    for _ in 0..WRITE_QUEUE_CAPACITY {
        tx.try_send(item.clone()).unwrap();
    }
    assert!(matches!(
        tx.try_send(item.clone()),
        Err(TrySendError::Full(_))
    ));
    let thread = std::thread::spawn(move || worker.run(&rx, &AtomicBool::new(false)));
    // Keep feeding while the initially saturated queue drains.
    for _ in 0..WRITE_QUEUE_CAPACITY {
        tx.send(item.clone()).unwrap();
    }
    drop(tx);
    thread.join().unwrap();
    let page = store
        .query_connection_logs(&ConnectionLogQuery::default())
        .unwrap();
    assert_eq!(page.total_count, (WRITE_QUEUE_CAPACITY * 2) as u64);
    assert!(page
        .logs
        .iter()
        .all(|log| log.closed_at == Some(log.last_seen)
            && log.last_seen.unix_timestamp() == now.unix_timestamp()));
    let buckets = store
        .query_activity_buckets(
            now - time::Duration::hours(1),
            now + time::Duration::hours(1),
        )
        .unwrap();
    assert_eq!(
        buckets.iter().map(|bucket| bucket.event_count).sum::<u64>(),
        page.total_count
    );
    assert_eq!(
        buckets
            .iter()
            .map(|bucket| bucket.blocked_count)
            .sum::<u64>(),
        page.total_count
    );
    assert_eq!(pending.load(Ordering::Relaxed), 0);
}

#[tokio::test]
async fn records_blocked_dns_query_in_connection_logs() {
    let dir = tempdir().expect("tempdir");
    let keystore = UnixSecureFileKeyProvider::new(dir.path().join("key"));
    let store =
        Arc::new(Store::open_with_keystore(dir.path().join("db.sqlite"), &keystore).expect("open"));

    let alerts = AlertPublisher::unsaved(NotificationHub::with_capacity(4), None);
    let app_resolver = Arc::new(AppIdResolver::new(
        Arc::clone(&store),
        alerts.clone(),
        SiemExporter::new(SiemConfig::default()),
    ));
    let app_id = app_resolver.get_or_create_app_id(r"C:\apps\browser.exe", "browser.exe");
    assert!(app_id > 0);

    let siem = SiemExporter::new(SiemConfig::default());
    let recorder = DnsBlockRecorder::new(app_resolver, Arc::clone(&store), alerts, siem);

    store
        .insert_dns_block_log(
            app_id,
            r"C:\Apps\browser.exe",
            "blocked.ads",
            OffsetDateTime::now_utc(),
            "hagezi_light",
        )
        .expect("upsert");

    let page = store
        .query_connection_logs(&ConnectionLogQuery::default())
        .expect("query");
    assert_eq!(page.total_count, 1);
    assert_eq!(page.logs[0].protocol, "DNS");
    assert_eq!(page.logs[0].dst_domain, "blocked.ads");
    assert_eq!(page.logs[0].action_taken, "BLOCKED");
    assert_eq!(page.logs[0].blocklist_names, "hagezi_light");

    let weak = Arc::downgrade(&recorder);
    drop(recorder);
    assert!(
        weak.upgrade().is_none(),
        "persistence worker must not retain the recorder"
    );
}

#[test]
fn correlates_blocked_dns_to_etw_caller() {
    let correlator = Arc::new(DnsQueryCorrelator::default());

    let now = OffsetDateTime::now_utc();
    let now_ms = u64::try_from(now.unix_timestamp_nanos() / 1_000_000)
        .expect("current timestamp is non-negative and fits in milliseconds");

    // ETW event: ClientPID = 5555, Dnscache PID = 1000
    correlator.record_query(&DnsQueryEvent {
        event_id: None,
        event_version: None,
        name: "malware.test".to_owned(),
        query_type: 1,
        status: 0,
        caller: DnsCallerIdentity {
            logging_pid: None,
            requesting_pid: Some(5555),
            resolver_pid: Some(1000),
        },
        correlation: DnsCorrelationId::default(),
        timestamp: now_ms,
    });

    let correlation = correlator.correlate("malware.test", 1000, Some(now));
    assert_eq!(correlation.requesting_pid, Some(5555));
    assert_eq!(correlation.resolver_pid, Some(1000));
    assert!(!correlation.ambiguous);
}

#[test]
fn distinct_callers_for_same_domain_dedup_separately() {
    let correlator = DnsQueryCorrelator::new(100, 1000);
    let now = OffsetDateTime::now_utc();
    let now_ms = u64::try_from(now.unix_timestamp_nanos() / 1_000_000)
        .expect("current timestamp is non-negative and fits in milliseconds");

    correlator.record_query(&DnsQueryEvent {
        event_id: None,
        event_version: None,
        name: "blocked.test".to_owned(),
        query_type: 1,
        status: 0,
        caller: DnsCallerIdentity {
            logging_pid: None,
            requesting_pid: Some(1111),
            resolver_pid: Some(1000),
        },
        correlation: DnsCorrelationId::default(),
        timestamp: now_ms,
    });

    correlator.record_query(&DnsQueryEvent {
        event_id: None,
        event_version: None,
        name: "blocked.test".to_owned(),
        query_type: 1,
        status: 0,
        caller: DnsCallerIdentity {
            logging_pid: None,
            requesting_pid: Some(2222),
            resolver_pid: Some(1000),
        },
        correlation: DnsCorrelationId::default(),
        timestamp: now_ms + 2500,
    });

    let corr1 = correlator.correlate("blocked.test", 1000, Some(now));
    let corr2 = correlator.correlate(
        "blocked.test",
        1000,
        Some(now + Duration::from_millis(2500)),
    );

    let pid1 = corr1.requesting_pid.unwrap_or(1000);
    let pid2 = corr2.requesting_pid.unwrap_or(1000);
    assert_eq!(pid1, 1111);
    assert_eq!(pid2, 2222);

    let mut recent = RecentLru::new(10);
    let inst = Instant::now();
    let window = Duration::from_secs(30);

    let key1 = DnsBlockKey {
        pid: pid1,
        domain: "blocked.test".to_owned(),
    };
    let key2 = DnsBlockKey {
        pid: pid2,
        domain: "blocked.test".to_owned(),
    };

    assert!(recent.should_admit(key1.clone(), inst, window));
    assert!(
        recent.should_admit(key2.clone(), inst, window),
        "distinct callers requesting same domain must not suppress each other"
    );
    assert!(
        !recent.should_admit(key1, inst, window),
        "same caller must be deduplicated"
    );
}

#[test]
fn ambiguous_or_unattributed_results_never_use_the_resolver_as_caller() {
    for status in [
        crate::correlator::DnsAttributionStatus::Ambiguous,
        crate::correlator::DnsAttributionStatus::Unattributed,
    ] {
        let correlation = DnsCorrelationResult {
            requesting_pid: None,
            resolver_pid: Some(1000),
            ambiguous: status == crate::correlator::DnsAttributionStatus::Ambiguous,
            status,
        };

        assert_eq!(attributed_requesting_pid(correlation), None);
    }
}

#[test]
fn persists_caller_when_etw_query_arrives_before_block() {
    assert_reconciles_delivery_order(DeliveryOrder::QueryFirst, 51_001);
}

#[test]
fn reconciles_caller_when_block_arrives_before_etw_query() {
    assert_reconciles_delivery_order(DeliveryOrder::BlockFirst, 51_002);
}

#[test]
fn daemon_identity_uses_the_install_path_not_the_file_name() {
    let daemon = std::env::current_exe().expect("current executable");
    let daemon = std::fs::canonicalize(&daemon).unwrap_or(daemon);
    let spoof = if cfg!(windows) {
        r"C:\Users\me\AppData\Local\Temp\antiwire-daemon.exe"
    } else {
        "/tmp/antiwire-daemon"
    };

    assert!(is_daemon_executable(
        Some(&daemon),
        &daemon.to_string_lossy()
    ));
    assert!(!is_daemon_executable(Some(&daemon), spoof));
    assert!(!is_daemon_executable(None, &daemon.to_string_lossy()));
}

fn recorder_fixture(
    dir: &Path,
) -> (
    Arc<Store>,
    AlertPublisher,
    Arc<DnsBlockRecorder>,
    Arc<AppIdResolver>,
) {
    let keystore = UnixSecureFileKeyProvider::new(dir.join("key"));
    let store =
        Arc::new(Store::open_with_keystore(dir.join("db.sqlite"), &keystore).expect("open"));
    let alerts = AlertPublisher::unsaved(NotificationHub::with_capacity(8), None);
    let app_resolver = Arc::new(AppIdResolver::new(
        Arc::clone(&store),
        alerts.clone(),
        SiemExporter::new(SiemConfig::default()),
    ));
    let recorder = DnsBlockRecorder::new(
        Arc::clone(&app_resolver),
        Arc::clone(&store),
        alerts.clone(),
        SiemExporter::new(SiemConfig::default()),
    );
    (store, alerts, recorder, app_resolver)
}

fn wait_for_domain_log(store: &Store, domain: &str) {
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        let page = store
            .query_connection_logs(&ConnectionLogQuery::default())
            .expect("query logs");
        if page.logs.iter().any(|log| log.dst_domain == domain) {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "dns block for {domain} was never persisted"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
}

/// Shutdown drains queued blocks before joining, and repeating it is a no-op.
#[tokio::test]
async fn shutdown_flushes_queued_blocks_and_is_idempotent() {
    let dir = tempdir().expect("tempdir");
    let (store, _alerts, recorder, _resolver) = recorder_fixture(dir.path());

    recorder.record_blocked_query("shutdown-flush.example", 0, &[]);
    recorder.shutdown().await;
    recorder.shutdown().await;

    let page = store
        .query_connection_logs(&ConnectionLogQuery::default())
        .expect("query logs");
    assert!(
        page.logs
            .iter()
            .any(|log| log.dst_domain == "shutdown-flush.example"),
        "shutdown must flush queued blocks before stopping"
    );
    assert!(
        recorder.tx.lock().is_none(),
        "shutdown must close admission before the worker exits"
    );
    let dropped = recorder.dropped.load(Ordering::Relaxed);
    recorder.record_blocked_query("after-shutdown.example", 0, &[]);
    assert_eq!(
        recorder.dropped.load(Ordering::Relaxed),
        dropped + 1,
        "events arriving after shutdown must be explicitly shed"
    );
}

#[tokio::test]
async fn daemon_blocks_persist_without_notifying_by_default() {
    let dir = tempdir().expect("tempdir");
    let (store, alerts, recorder, _resolver) = recorder_fixture(dir.path());
    let mut notifications = alerts.subscribe();

    // Use the real test process so the resolver can verify the current
    // PID/path pair after the active-identity freshness check. The worker
    // compares the canonical executable path, so the test name is not
    // part of daemon suppression.
    let pid = std::process::id();

    recorder.record_blocked_query("daemon-blocked.example", pid, &[]);

    wait_for_domain_log(&store, "daemon-blocked.example");

    let deadline = Instant::now() + Duration::from_millis(300);
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break;
        }
        match tokio::time::timeout(remaining, notifications.recv()).await {
            Ok(Some(event)) => assert_ne!(
                event.kind,
                AlertKind::MaliciousFlow,
                "daemon notification was not suppressed: {}",
                event.message
            ),
            Ok(None) | Err(_) => break,
        }
    }
}

#[tokio::test]
async fn a_spoofed_daemon_name_does_not_suppress_the_audit_trail() {
    let dir = tempdir().expect("tempdir");
    let (store, alerts, recorder, app_resolver) = recorder_fixture(dir.path());
    let mut notifications = alerts.subscribe();

    let pid = 52_111;
    let spoof = if cfg!(windows) {
        r"C:\Users\me\AppData\Local\Temp\spoof\antiwire-daemon.exe"
    } else {
        "/tmp/spoof/antiwire-daemon"
    };
    app_resolver
        .processes()
        .process_started(pid, spoof, "antiwire-daemon.exe", 0);

    recorder.record_blocked_query("spoofed-blocked.example", pid, &[]);

    wait_for_domain_log(&store, "spoofed-blocked.example");

    let deadline = Instant::now() + Duration::from_secs(2);
    let mut notified = false;
    while !notified && Instant::now() < deadline {
        let remaining = deadline.saturating_duration_since(Instant::now());
        match tokio::time::timeout(remaining, notifications.recv()).await {
            Ok(Some(event)) if event.kind == AlertKind::MaliciousFlow => notified = true,
            Ok(Some(_)) => {}
            Ok(None) | Err(_) => break,
        }
    }
    assert!(
        notified,
        "a forged daemon file name must not suppress the block notification"
    );
}

#[tokio::test]
async fn blocked_dns_names_and_labels_are_sanitized() {
    let dir = tempdir().expect("tempdir");
    let (store, alerts, recorder, app_resolver) = recorder_fixture(dir.path());
    let mut notifications = alerts.subscribe();

    let pid = 52_112;
    app_resolver
        .processes()
        .process_started(pid, r"C:\apps\evil.exe", "evil.exe", 0);

    recorder.record_blocked_query("evil\nexample.com", pid, &["list\ninjected".to_owned()]);

    wait_for_domain_log(&store, "evilexample.com");

    let page = store
        .query_connection_logs(&ConnectionLogQuery::default())
        .expect("query logs");
    let log = page.logs.first().expect("log");
    assert_eq!(log.dst_domain, "evilexample.com");
    assert_eq!(log.blocklist_names, "listinjected");

    let event = loop {
        let event = notifications.recv().await.expect("notification");
        if event.kind == AlertKind::MaliciousFlow {
            break event;
        }
    };
    assert!(!event.message.contains('\n'));
}

/// The "(via X)" resolver label used to resolve the PID with no creation-time
/// check, so a resolver PID recycled after the query named the new process and
/// registered it as an application.
#[test]
fn a_resolver_started_after_the_query_is_not_named() {
    let dir = tempdir().expect("tempdir");
    let (store, _publisher, worker, _shed, _siem_path) = retry_worker_fixture(dir.path());
    let timestamp = OffsetDateTime::now_utc();
    let event_ms = u64::try_from(timestamp.unix_timestamp_nanos() / 1_000_000)
        .expect("current timestamp fits in milliseconds");
    let (caller, early_resolver, late_resolver) = (5_007_101, 5_007_102, 5_007_103);
    let processes = worker.app_resolver.processes();
    processes.process_started(
        caller,
        r"C:\apps\caller.exe",
        "caller.exe",
        event_ms - 60_000,
    );
    processes.process_started(
        early_resolver,
        r"C:\apps\early-resolver.exe",
        "early-resolver.exe",
        event_ms - 60_000,
    );
    processes.process_started(
        late_resolver,
        r"C:\apps\late-resolver.exe",
        "late-resolver.exe",
        event_ms + 60_000,
    );
    let block = pending_test_block("resolver.example", timestamp);
    let correlation = |resolver| DnsCorrelationResult {
        requesting_pid: Some(caller),
        resolver_pid: Some(resolver),
        ambiguous: false,
        status: DnsAttributionStatus::Correlated,
    };

    let named = worker.prepare_dns_block(&block, correlation(early_resolver));
    assert_eq!(named.resolver_desc.as_deref(), Some("early-resolver.exe"));

    let recycled = worker.prepare_dns_block(&block, correlation(late_resolver));
    assert_eq!(recycled.resolver_desc, None);
    let apps = store.list_applications().expect("list applications");
    assert!(
        apps.iter().all(|app| !app.app_path.contains("resolver")),
        "a resolver label must not register the resolver as an application"
    );
}

/// A full reconciliation queue writes its oldest block before late evidence
/// can attribute it. That used to happen without a trace; it is now counted.
#[test]
fn an_early_reconciliation_is_counted() {
    let dir = tempdir().expect("tempdir");
    let (_store, _publisher, mut worker, _shed, _siem_path) = retry_worker_fixture(dir.path());
    worker.reconciliation_delay = Duration::from_secs(3_600);
    let mut pending = std::collections::VecDeque::new();
    let mut recent = RecentLru::new(WRITE_QUEUE_CAPACITY * 2);
    let mut batch = DnsWriteBatch::with_capacity(WRITE_BATCH_SIZE);
    let now = OffsetDateTime::now_utc();
    for index in 0..=WRITE_QUEUE_CAPACITY {
        worker.enqueue_pending(
            pending_test_block(&format!("early-{index}.example"), now),
            &mut pending,
            &mut recent,
            dns_dedup_window(),
            &mut batch,
        );
    }
    assert_eq!(pending.len(), WRITE_QUEUE_CAPACITY);
    assert_eq!(worker.early_reconciliations.load(Ordering::Relaxed), 1);
}
