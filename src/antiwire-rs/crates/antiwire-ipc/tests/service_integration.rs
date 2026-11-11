//! The gRPC service end to end, over a temporary store.

use std::sync::Arc;

use antiwire_events::{ActiveApplicationSample, ActiveConnectionCounter, ActiveConnectionSample};
use antiwire_ipc::TestService;
use antiwire_proto::antiwire_service_server::AntiwireService;
use parking_lot::Mutex;
use tonic::Request;

#[tokio::test]
async fn add_rule_round_trip_via_service() {
    let harness = TestService::new();
    let store = Arc::clone(&harness.store);
    let service = &harness;

    let request = Request::new(antiwire_proto::Rule {
        id: 0,
        target_type: "DNS".to_owned(),
        target_value: "blocked.example".to_owned(),
        action: "BLOCK".to_owned(),
        direction: "BOTH".to_owned(),
    });

    let response = service.add_rule(request).await.expect("add rule");
    assert!(response.into_inner().success);

    // A client that predates the direction field must still get outbound rules.
    let legacy_request = Request::new(antiwire_proto::Rule {
        id: 0,
        target_type: "DNS".to_owned(),
        target_value: "legacy.example".to_owned(),
        action: "BLOCK".to_owned(),
        direction: String::new(),
    });
    let legacy_response = service.add_rule(legacy_request).await.expect("add rule");
    assert!(legacy_response.into_inner().success);

    let rules = store.list_rules().expect("list");
    assert_eq!(rules.len(), 2);
    assert_eq!(rules[0].target_value, "blocked.example");
    assert_eq!(rules[0].direction, antiwire_policy::RuleDirection::Both);
    assert_eq!(rules[1].direction, antiwire_policy::RuleDirection::Outbound);
}

#[tokio::test]
async fn get_stats_reports_active_connection_counter() {
    use std::sync::atomic::{AtomicU32, Ordering};

    struct TestActiveConnectionCounter {
        count: Arc<AtomicU32>,
        thread: Arc<Mutex<Option<std::thread::ThreadId>>>,
    }

    impl ActiveConnectionCounter for TestActiveConnectionCounter {
        fn active_connections_count(&self) -> ActiveConnectionSample {
            *self.thread.lock() = Some(std::thread::current().id());
            ActiveConnectionSample::fresh(self.count.load(Ordering::Relaxed))
        }
    }

    let active_connections = Arc::new(AtomicU32::new(3));
    let active_connection_thread = Arc::new(Mutex::new(None));
    let harness = TestService::with_active_connections(Arc::new(TestActiveConnectionCounter {
        count: Arc::clone(&active_connections),
        thread: Arc::clone(&active_connection_thread),
    }));

    let runtime_thread = std::thread::current().id();
    let response = harness
        .get_stats(Request::new(antiwire_proto::Empty {}))
        .await
        .expect("get stats");
    let stats = response.into_inner();
    assert_eq!(stats.active_connections_count, 3);
    assert_eq!(stats.active_connections_available, Some(true));
    assert!(!stats.active_connections_stale);
    assert_ne!(
        *active_connection_thread.lock(),
        Some(runtime_thread),
        "stats queries must not run on the async worker"
    );

    active_connections.store(1, Ordering::Relaxed);
    let response = harness
        .get_stats(Request::new(antiwire_proto::Empty {}))
        .await
        .expect("get stats");
    let stats = response.into_inner();
    assert_eq!(stats.active_connections_count, 1);
    assert_eq!(stats.active_connections_available, Some(true));
    assert!(!stats.active_connections_stale);
}

#[tokio::test]
async fn get_active_applications_sorts_busiest_first() {
    struct TwoApps;

    impl ActiveConnectionCounter for TwoApps {
        fn active_connections_count(&self) -> ActiveConnectionSample {
            ActiveConnectionSample::fresh(3)
        }

        fn active_applications(&self) -> Option<Vec<ActiveApplicationSample>> {
            Some(vec![
                ActiveApplicationSample {
                    app_name: "Quiet.exe".to_owned(),
                    connection_count: 2,
                    download_rate: 10,
                    ..ActiveApplicationSample::default()
                },
                ActiveApplicationSample {
                    app_name: "Busy.exe".to_owned(),
                    connection_count: 1,
                    download_rate: 5_000,
                    upload_rate: 700,
                    top_destinations: vec!["cdn.example".to_owned()],
                    destination_count: 1,
                    newest_opened_at: 1_700_000_000,
                    ..ActiveApplicationSample::default()
                },
            ])
        }
    }

    let harness = TestService::with_active_connections(Arc::new(TwoApps));
    let response = harness
        .get_active_applications(Request::new(antiwire_proto::Empty {}))
        .await
        .expect("get active applications")
        .into_inner();
    assert!(response.available);
    let names: Vec<&str> = response
        .applications
        .iter()
        .map(|app| app.app_name.as_str())
        .collect();
    assert_eq!(names, ["Busy.exe", "Quiet.exe"]);
    let busy = &response.applications[0];
    assert_eq!((busy.download_rate, busy.upload_rate), (5_000, 700));
    assert_eq!(busy.top_destinations, ["cdn.example"]);
    assert_eq!(busy.newest_opened_at, 1_700_000_000);
}

#[tokio::test]
async fn get_active_applications_is_unavailable_without_attribution() {
    let harness = TestService::new();
    let response = harness
        .get_active_applications(Request::new(antiwire_proto::Empty {}))
        .await
        .expect("get active applications")
        .into_inner();
    assert!(
        !response.available,
        "a counter that cannot attribute must not look like an empty list"
    );
    assert!(response.applications.is_empty());
}

#[tokio::test]
async fn get_stats_preserves_unavailable_socket_counts() {
    struct UnavailableActiveConnectionCounter;

    impl ActiveConnectionCounter for UnavailableActiveConnectionCounter {
        fn active_connections_count(&self) -> ActiveConnectionSample {
            ActiveConnectionSample::default()
        }
    }

    let harness =
        TestService::with_active_connections(Arc::new(UnavailableActiveConnectionCounter));
    let response = harness
        .get_stats(Request::new(antiwire_proto::Empty {}))
        .await
        .expect("get stats");
    let stats = response.into_inner();
    assert_eq!(stats.active_connections_count, 0);
    assert_eq!(
        stats.active_connections_available,
        Some(false),
        "acquisition failure must not look like a valid zero"
    );
    assert!(!stats.active_connections_stale);
}

#[tokio::test]
async fn get_stats_reports_stale_last_known_socket_counts() {
    struct StaleActiveConnectionCounter;

    impl ActiveConnectionCounter for StaleActiveConnectionCounter {
        fn active_connections_count(&self) -> ActiveConnectionSample {
            ActiveConnectionSample::stale(7)
        }
    }

    let harness = TestService::with_active_connections(Arc::new(StaleActiveConnectionCounter));
    let response = harness
        .get_stats(Request::new(antiwire_proto::Empty {}))
        .await
        .expect("get stats");
    let stats = response.into_inner();
    assert_eq!(stats.active_connections_count, 7);
    assert_eq!(stats.active_connections_available, Some(true));
    assert!(
        stats.active_connections_stale,
        "last-known after a failed refresh must be marked stale"
    );
}

#[tokio::test]
async fn network_watch_validates_interval_and_round_trips_ip() {
    let service = TestService::new();
    let request = |interval_minutes| {
        Request::new(antiwire_proto::NetworkDeviceWatch {
            id: 0,
            ip_address: "192.168.1.7".to_owned(),
            mac_address: "00-1b-63-00-00-07".to_owned(),
            adapter_id: String::new(),
            cidr: String::new(),
            interval_minutes,
            enabled: true,
            present: false,
            last_checked: String::new(),
        })
    };

    let invalid = service
        .save_network_device_watch(request(2))
        .await
        .expect("an action reply")
        .into_inner();
    assert!(!invalid.success, "an unsupported interval is refused");

    let saved = service
        .save_network_device_watch(request(5))
        .await
        .expect("save watch")
        .into_inner();
    assert!(saved.success, "{}", saved.message);
    let state = service
        .get_network_mapping_state(Request::new(antiwire_proto::Empty {}))
        .await
        .expect("mapping state")
        .into_inner();
    assert_eq!(state.device_watches.len(), 1);
    assert_eq!(state.device_watches[0].ip_address, "192.168.1.7");
    assert_eq!(state.device_watches[0].mac_address, "00:1B:63:00:00:07");

    let duplicate = service
        .save_network_device_watch(request(10))
        .await
        .expect("an action reply")
        .into_inner();
    assert!(!duplicate.success);
    assert!(
        duplicate.message.contains("already watched"),
        "{}",
        duplicate.message
    );
}

#[tokio::test]
async fn network_scan_rejects_invalid_range_before_starting_worker() {
    let service = TestService::new();
    let error = service
        .scan_network(Request::new(antiwire_proto::NetworkMapRequest {
            cidr_ranges: vec!["not-a-cidr".to_owned()],
        }))
        .await
        .expect_err("invalid range");
    assert_eq!(error.code(), tonic::Code::InvalidArgument);
}

#[tokio::test]
async fn application_capture_needs_connection_attribution() {
    let harness = TestService::new();
    let error = harness
        .start_capture(Request::new(antiwire_proto::StartCaptureRequest {
            app_path: r"C:\apps\vpn.exe".to_owned(),
            ..Default::default()
        }))
        .await
        .expect_err("attribution is unavailable without a tracker");
    assert_eq!(error.code(), tonic::Code::FailedPrecondition);
}
