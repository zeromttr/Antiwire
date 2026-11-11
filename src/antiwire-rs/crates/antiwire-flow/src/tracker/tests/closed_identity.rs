use super::*;

const LATE_PATH: &str = if cfg!(windows) {
    r"C:\apps\late-image.exe"
} else {
    "/opt/antiwire-tests/late-image.exe"
};
const AMBIGUOUS_PATH: &str = if cfg!(windows) {
    r"C:\apps\ambiguous-image.exe"
} else {
    "/opt/antiwire-tests/ambiguous-image.exe"
};

#[test]
fn ownerless_close_can_recover_the_original_verified_process_instance() {
    let dir = tempdir().expect("tempdir");
    let keystore = UnixSecureFileKeyProvider::new(dir.path().join("key"));
    let store = Arc::new(
        Store::open_with_keystore(dir.path().join("db.sqlite"), &keystore).expect("store"),
    );
    let processor = Arc::new(test_processor(
        Arc::clone(&store),
        TrafficStreamingHub::with_capacity(4),
    ));
    let tracker =
        FlowTracker::with_processor(StoreFlowAdapter::new(Arc::clone(&store)), Some(processor));
    let pid = 916_001;
    let key = sample_key();
    open_placeholder_flow(&tracker, key, pid, "late-image.exe", 77_000);
    tracker.flush_active_flows().expect("persist original");
    tracker
        .processes_for_test()
        .seed_cache(pid, LATE_PATH, "late-image.exe", 77_000);
    tracker.handle_event(&FlowEvent::Closed(
        key,
        FlowMeta {
            pid: 0,
            process: None,
            open_ts: 0,
            cookie: None,
            if_index: None,
        },
    ));
    tracker.flush().expect("flush close");
    let logs = store
        .query_connection_logs(&ConnectionLogQuery::default())
        .expect("logs")
        .logs;
    assert_eq!(logs.len(), 1);
    assert_eq!(logs[0].app_path, LATE_PATH);
    assert!(logs[0].closed_at.is_some());
}

#[test]
fn closed_placeholder_recovers_exact_record_without_recounting_bytes() {
    for (persist_before_evidence, real_app_already_known) in
        [(false, false), (true, false), (true, true)]
    {
        let dir = tempdir().expect("tempdir");
        let keystore = UnixSecureFileKeyProvider::new(dir.path().join("key"));
        let store = Arc::new(
            Store::open_with_keystore(dir.path().join("db.sqlite"), &keystore).expect("store"),
        );
        let processor = Arc::new(test_processor(
            Arc::clone(&store),
            TrafficStreamingHub::with_capacity(4),
        ));
        let tracker = FlowTracker::with_processor(
            StoreFlowAdapter::new(Arc::clone(&store)),
            Some(Arc::clone(&processor)),
        );
        let pid = 912_001 + u32::from(persist_before_evidence) + u32::from(real_app_already_known);
        let known_app = real_app_already_known.then(|| {
            store
                .record_application_sighting(
                    "late-image.exe",
                    LATE_PATH,
                    true,
                    OffsetDateTime::now_utc(),
                )
                .expect("known app")
                .app_id
        });
        let key = sample_key();
        insert_dns_metadata(&processor, &key, pid, "late.example");
        open_placeholder_flow(&tracker, key, pid, "late-image.exe", 77_000);
        tracker.handle_event(&FlowEvent::Bytes(
            key,
            ByteDelta {
                sent: 150,
                received: 230,
            },
        ));
        tracker.handle_event(&FlowEvent::Closed(
            key,
            FlowMeta {
                pid,
                process: None,
                open_ts: 0,
                cookie: None,
                if_index: None,
            },
        ));
        if persist_before_evidence {
            tracker.flush().expect("initial flush");
        }
        let event = process_started_event(pid, LATE_PATH, "late-image.exe", 77_000);
        tracker.handle_event(&event);
        tracker.handle_event(&event);
        tracker.flush().expect("recovery flush");
        let logs = store
            .query_connection_logs(&ConnectionLogQuery::default())
            .expect("logs")
            .logs;
        assert_eq!(logs.len(), 1, "late evidence must update the original row");
        assert_eq!(logs[0].app_path, LATE_PATH);
        assert_eq!(logs[0].dst_domain, "late.example");
        if let Some(app_id) = known_app {
            assert_eq!(logs[0].app_id, app_id);
        }
        assert_eq!((logs[0].bytes_sent, logs[0].bytes_received), (150, 230));
        assert!(logs[0].closed_at.is_some());
        let totals = tracker.closed_app_bytes.lock();
        let identity = application_identity(LATE_PATH, "late-image.exe").expect("identity");
        assert_eq!(totals.get(&identity), Some(&(150, 230)));
    }
}

#[test]
fn closed_placeholder_never_recovers_from_a_different_process_instance() {
    for (index, original_ts, evidence_pid_offset, evidence_ts) in [
        (0, 77_000, 1, 77_000),
        (1, 77_000, 0, 77_001),
        (2, 0, 0, 77_000),
    ] {
        let dir = tempdir().expect("tempdir");
        let keystore = UnixSecureFileKeyProvider::new(dir.path().join("key"));
        let store = Arc::new(
            Store::open_with_keystore(dir.path().join("db.sqlite"), &keystore).expect("store"),
        );
        let processor = Arc::new(test_processor(
            Arc::clone(&store),
            TrafficStreamingHub::with_capacity(4),
        ));
        let tracker =
            FlowTracker::with_processor(StoreFlowAdapter::new(Arc::clone(&store)), Some(processor));
        let pid = 913_000 + index * 10;
        let key = sample_key();
        open_placeholder_flow(&tracker, key, pid, "ambiguous-image.exe", original_ts);
        tracker.handle_event(&FlowEvent::Closed(
            key,
            FlowMeta {
                pid,
                process: None,
                open_ts: 0,
                cookie: None,
                if_index: None,
            },
        ));
        tracker.handle_event(&process_started_event(
            pid + evidence_pid_offset,
            AMBIGUOUS_PATH,
            "ambiguous-image.exe",
            evidence_ts,
        ));
        tracker.flush().expect("flush");
        let logs = store
            .query_connection_logs(&ConnectionLogQuery::default())
            .expect("logs")
            .logs;
        assert_eq!(logs.len(), 1);
        assert_eq!(logs[0].app_path, "Path unavailable");
    }
}

#[test]
fn closed_identity_queue_expires_candidates_and_evicts_oldest_at_capacity() {
    let writes = Arc::new(std::sync::Mutex::new(Vec::new()));
    let capture = Arc::clone(&writes);
    let tracker = FlowTracker::new(move |batch: &[NewConnectionLog]| {
        capture.lock().expect("writes").extend_from_slice(batch);
        Ok(())
    });
    let key = sample_key();
    tracker.handle_event(&FlowEvent::Opened(
        key,
        FlowMeta {
            pid: 914_001,
            process: None,
            open_ts: 0,
            cookie: None,
            if_index: None,
        },
    ));
    let mut flow = tracker.active.lock().get(&key).expect("flow").clone();
    flow.pid = 914_001;
    flow.process_start_ts = Some(11_000);
    let now = Instant::now();
    let mut queue = ClosedIdentityQueue::new(2, Duration::from_secs(5));
    for pid in [914_001, 914_002, 914_003] {
        flow.pid = pid;
        queue.remember(key, flow.clone(), now);
    }
    assert_eq!(queue.len(), 2);
    assert!(queue.take_for(914_001, 11_000, now).is_empty());
    assert!(queue.take_for(914_002, 11_001, now).is_empty());
    assert_eq!(queue.take_for(914_002, 11_000, now).len(), 1);
    assert!(queue
        .take_for(914_003, 11_000, now + Duration::from_secs(5))
        .is_empty());
    assert_eq!(queue.len(), 0);
}

/// A process's candidates are taken whole; one it closes afterwards must not
/// be mistaken for the taken ones when the oldest is evicted.
#[test]
fn a_process_closing_again_after_recovery_keeps_its_new_candidate() {
    let tracker = FlowTracker::new(|_: &[NewConnectionLog]| Ok(()));
    let key = sample_key();
    tracker.handle_event(&FlowEvent::Opened(
        key,
        FlowMeta {
            pid: 915_001,
            process: None,
            open_ts: 0,
            cookie: None,
            if_index: None,
        },
    ));
    let mut flow = tracker.active.lock().get(&key).expect("flow").clone();
    flow.process_start_ts = Some(12_000);
    let now = Instant::now();
    let mut queue = ClosedIdentityQueue::new(2, Duration::from_secs(5));

    flow.pid = 915_001;
    queue.remember(key, flow.clone(), now);
    assert_eq!(queue.take_for(915_001, 12_000, now).len(), 1);
    queue.remember(key, flow.clone(), now);
    flow.pid = 915_002;
    queue.remember(key, flow.clone(), now);
    // Full: the next one evicts the oldest still held, 915_001's new one.
    flow.pid = 915_003;
    queue.remember(key, flow.clone(), now);

    assert_eq!(queue.len(), 2);
    assert!(queue.take_for(915_001, 12_000, now).is_empty());
    assert_eq!(queue.take_for(915_002, 12_000, now).len(), 1);
    assert_eq!(queue.take_for(915_003, 12_000, now).len(), 1);
    assert_eq!(queue.len(), 0);
}

/// A tracker with one closed, flushed connection of `pid`, opened at
/// `opened_at` with nothing known of the process that had the PID.
fn closed_connection_of_an_unknown_process(
    pid: u32,
    opened_at: u64,
) -> (
    tempfile::TempDir,
    Arc<Store>,
    Arc<FlowProcessor>,
    FlowTracker<StoreFlowAdapter>,
) {
    let dir = tempdir().expect("tempdir");
    let keystore = UnixSecureFileKeyProvider::new(dir.path().join("key"));
    let store = Arc::new(
        Store::open_with_keystore(dir.path().join("db.sqlite"), &keystore).expect("store"),
    );
    let processor = Arc::new(test_processor(
        Arc::clone(&store),
        TrafficStreamingHub::with_capacity(4),
    ));
    let tracker = FlowTracker::with_processor(
        StoreFlowAdapter::new(Arc::clone(&store)),
        Some(Arc::clone(&processor)),
    );
    let key = sample_key();
    let meta = |open_ts| FlowMeta {
        pid,
        process: None,
        open_ts,
        cookie: None,
        if_index: None,
    };
    tracker.handle_event(&FlowEvent::Opened(key, meta(opened_at)));
    tracker.handle_event(&FlowEvent::Bytes(
        key,
        ByteDelta {
            sent: 150,
            received: 230,
        },
    ));
    tracker.handle_event(&FlowEvent::Closed(key, meta(0)));
    tracker.flush().expect("flush the closed connection");
    (dir, store, processor, tracker)
}

/// Delivers a lifecycle event as the tracker's event loop does: to the
/// processor, which records it, and then to the tracker.
fn deliver(processor: &FlowProcessor, tracker: &FlowTracker<StoreFlowAdapter>, event: &FlowEvent) {
    processor.handle_event(event);
    tracker.handle_event(event);
    tracker.flush().expect("flush");
}

fn only_log(store: &Store) -> antiwire_store::ConnectionLog {
    let mut logs = store
        .query_connection_logs(&ConnectionLogQuery::default())
        .expect("logs")
        .logs;
    assert_eq!(logs.len(), 1, "late evidence must update the original row");
    logs.remove(0)
}

/// The regression this guards: a process that connected and exited before
/// its start event was delivered had its connection looked at with nothing
/// known of the PID and no process left to ask. The connection closed as
/// unknown, and the lifecycle events that followed could not repair it,
/// because a closed connection was only found again by a creation time it
/// never had.
#[test]
fn a_connection_closed_before_its_process_was_known_is_attributed_when_its_lifecycle_arrives() {
    let pid = 917_001;
    let opened_at = netmetrics_core::unix_now_ms() - 5_000;
    let (_dir, store, processor, tracker) = closed_connection_of_an_unknown_process(pid, opened_at);
    assert!(
        only_log(&store).app_path.starts_with("Unknown"),
        "nothing is known of the process yet"
    );

    let started = process_started_event(pid, LATE_PATH, "late-image.exe", opened_at - 1_000);
    deliver(&processor, &tracker, &started);
    assert!(
        only_log(&store).app_path.starts_with("Unknown"),
        "started in time, but it may have exited before the connection opened"
    );

    let stopped = FlowEvent::ProcessStopped {
        pid,
        stop_ts: opened_at + 500,
    };
    deliver(&processor, &tracker, &stopped);
    let log = only_log(&store);
    assert_eq!(log.app_path, LATE_PATH);
    assert_eq!((log.bytes_sent, log.bytes_received), (150, 230));
    assert!(log.closed_at.is_some());
}

/// A PID is reused. Of two processes that had it, only the one running when
/// the connection opened may be given the connection.
#[test]
fn a_process_that_exited_before_the_connection_opened_is_not_given_it() {
    let pid = 917_002;
    let opened_at = netmetrics_core::unix_now_ms() - 5_000;
    let (_dir, store, processor, tracker) = closed_connection_of_an_unknown_process(pid, opened_at);

    // An earlier process with the PID: started and gone well before.
    let earlier = process_started_event(
        pid,
        AMBIGUOUS_PATH,
        "ambiguous-image.exe",
        opened_at - 60_000,
    );
    deliver(&processor, &tracker, &earlier);
    deliver(
        &processor,
        &tracker,
        &FlowEvent::ProcessStopped {
            pid,
            stop_ts: opened_at - 30_000,
        },
    );
    assert!(only_log(&store).app_path.starts_with("Unknown"));

    // The one that opened the connection.
    let owner = process_started_event(pid, LATE_PATH, "late-image.exe", opened_at - 200);
    deliver(&processor, &tracker, &owner);
    deliver(
        &processor,
        &tracker,
        &FlowEvent::ProcessStopped {
            pid,
            stop_ts: opened_at + 300,
        },
    );
    assert_eq!(only_log(&store).app_path, LATE_PATH);

    // A later process with the PID changes nothing.
    let later = process_started_event(
        pid,
        AMBIGUOUS_PATH,
        "ambiguous-image.exe",
        opened_at + 2_000,
    );
    deliver(&processor, &tracker, &later);
    assert_eq!(only_log(&store).app_path, LATE_PATH);
}
