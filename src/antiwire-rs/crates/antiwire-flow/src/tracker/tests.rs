//! Unit tests for the flow tracker.

use super::attribution::{
    application_identity, identity_upgrade_acceptable, needs_socket_attribution,
    should_retry_socket_lookup, SocketTables,
};
use super::degradation::degradation_key;
use super::persistence::should_defer_unknown_persist;

mod closed_identity;
use super::*;
use crate::processor::FlowProcessor;
use crate::store::StoreFlowAdapter;
use antiwire_events::TrafficStreamingHub;
use antiwire_platform::{SiemConfig, SiemExporter};
use antiwire_policy::RuleEngine;
use antiwire_secrets::UnixSecureFileKeyProvider;
use antiwire_store::ConnectionLogQuery;
use antiwire_store::Store;
use netmetrics_core::{
    CookieSource, DnsCallerIdentity, DnsCallerObservation, DnsCallerRecovery, DnsCorrelationId,
    DnsEventKind, DnsResolutionAttribution, FlowMeta, ProcessIdentity, ProcessInfo,
};
use parking_lot::RwLock;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use tempfile::tempdir;

use crate::app_resolver::AppIdResolver;
use antiwire_events::{AlertKind, AlertPublisher, NotificationHub};

const UPGRADE_PATH: &str = if cfg!(windows) {
    r"C:\apps\upgrade.exe"
} else {
    "/opt/antiwire-tests/apps/upgrade.exe"
};
const BROWSER_PATH: &str = if cfg!(windows) {
    r"C:\apps\browser.exe"
} else {
    "/opt/antiwire-tests/apps/browser.exe"
};
const CLOSE_HEAL_PATH: &str = if cfg!(windows) {
    r"C:\apps\close-heal.exe"
} else {
    "/opt/antiwire-tests/apps/close-heal.exe"
};

fn sample_key() -> FlowKey {
    FlowKey {
        protocol: Protocol::Tcp,
        local_addr: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)),
        local_port: 50_000,
        remote_addr: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5)),
        remote_port: 443,
    }
}

fn store_error(message: &str) -> crate::FlowError {
    crate::FlowError::Store(antiwire_store::StoreError::Database(message.to_owned()))
}

#[test]
fn defers_unknown_persist_until_socket_lookup_window() {
    let flow = ActiveFlow {
        conn_id: 1,
        open_pid: 0,
        app_id: 0,
        app_path: "Unknown (Exited)".to_owned(),
        app_name: crate::process_resolver::UNKNOWN_APP_NAME.to_owned(),
        pid: 0,
        protocol: "TCP".to_owned(),
        src_ip: "10.0.0.2".to_owned(),
        src_port: 50_000,
        dst_ip: "93.184.216.34".to_owned(),
        dst_port: 443,
        bytes_sent: 100,
        bytes_received: 0,
        persisted_sent: 0,
        persisted_received: 0,
        db_row_created: false,
        cookie: None,
        persisted_app_id: 0,
        persisted_domain: String::new(),
        name_lookup: NameLookup::default(),
        traffic_template: None,
        unknown_since: Some(Instant::now()),
        unknown_socket_lookup_done: false,
        socket_lookup_attempts: 0,
        next_socket_lookup: None,
        identity_lookup_attempts: 0,
        attribution_lookup: AttributionLookup::Idle,
        next_identity_retry: None,
        process_start_ts: None,
        open_ts: 0,
        finishing: false,
        opened_at: OffsetDateTime::now_utc(),
        last_seen: OffsetDateTime::now_utc(),
    };
    assert!(should_defer_unknown_persist(&flow));

    let expired = ActiveFlow {
        unknown_since: Some(
            Instant::now()
                .checked_sub(UNKNOWN_SOCKET_ATTRIBUTION_DELAY + Duration::from_millis(1))
                .unwrap_or_else(Instant::now),
        ),
        ..flow
    };
    assert!(!should_defer_unknown_persist(&expired));
}

/// The periodic flush defers a young unattributed flow so the socket table can
/// name it; the shutdown flush has no later tick, so it must write the bytes.
#[test]
fn the_final_flush_writes_a_deferred_unknown_flow() {
    let written = Arc::new(Mutex::new(Vec::<NewConnectionLog>::new()));
    let sink = Arc::clone(&written);
    let tracker = FlowTracker::new(move |logs: &[NewConnectionLog]| {
        sink.lock().extend_from_slice(logs);
        Ok(())
    });
    let key = sample_key();
    tracker.handle_event(&FlowEvent::Bytes(
        key,
        ByteDelta {
            sent: 100,
            received: 0,
        },
    ));
    let deferred = tracker
        .active
        .lock()
        .get(&key)
        .is_some_and(should_defer_unknown_persist);
    assert!(deferred, "a fresh unattributed flow starts deferred");

    tracker.flush_active_flows().expect("periodic flush");
    assert!(written.lock().is_empty(), "the periodic flush waits");

    tracker.flush_active_flows_final().expect("final flush");
    let written = written.lock();
    assert_eq!(written.len(), 1);
    assert_eq!(written[0].bytes_sent, 100);
}

#[test]
fn port_cache_assigns_pid_to_inferred_flow() {
    let tracker = FlowTracker::new(|_: &[NewConnectionLog]| Ok(()));
    let key = sample_key();
    tracker.remember_port_pid_for_test(&key, 12_345);

    tracker.handle_event(&FlowEvent::Bytes(
        key,
        ByteDelta {
            sent: 64,
            received: 128,
        },
    ));
    tracker.flush_active_flows().expect("flush active");

    assert_eq!(tracker.flow_pid_for_test(&key), Some(12_345));
}

#[test]
fn closing_attributed_flow_skips_socket_table_capture() {
    let tracker = FlowTracker::new(|_: &[NewConnectionLog]| Ok(()));
    let key = sample_key();
    let meta = FlowMeta {
        pid: 12_345,
        process: None,
        open_ts: 1,
        cookie: None,
        if_index: None,
    };
    tracker.handle_event(&FlowEvent::Opened(key, meta.clone()));
    let before = tracker.socket_snapshot_calls_for_test();

    tracker.handle_event(&FlowEvent::Closed(key, meta));

    assert_eq!(
        tracker.socket_snapshot_calls_for_test(),
        before,
        "an attributed flow must not enumerate the OS socket table on close"
    );
}

#[test]
fn closing_unknown_flow_still_captures_socket_table() {
    let tracker = FlowTracker::new(|_: &[NewConnectionLog]| Ok(()));
    let key = sample_key();
    tracker.handle_event(&FlowEvent::Bytes(
        key,
        ByteDelta {
            sent: 1,
            received: 0,
        },
    ));
    let before = tracker.socket_snapshot_calls_for_test();

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

    assert_eq!(
        tracker.socket_snapshot_calls_for_test(),
        before + 1,
        "an unattributed flow must still consult the socket table on close"
    );
}

#[test]
fn a_pass_reads_each_protocols_socket_table_once_and_only_when_used() {
    let tracker = FlowTracker::new(|_: &[NewConnectionLog]| Ok(()));
    let tables = SocketTables::since(Instant::now());
    let before = tracker.socket_snapshot_calls_for_test();
    assert_eq!(
        tracker.socket_snapshot_calls_for_test(),
        before,
        "creating the tables reads nothing"
    );
    for _ in 0..3 {
        tracker.socket_table(&tables, Protocol::Udp);
    }
    assert_eq!(tracker.socket_snapshot_calls_for_test(), before + 1);
    tracker.socket_table(&tables, Protocol::Tcp);
    tracker.socket_table(&tables, Protocol::Tcp);
    assert_eq!(tracker.socket_snapshot_calls_for_test(), before + 2);
}

#[test]
fn a_new_unknown_flow_is_attributed_from_the_shared_socket_table() {
    let socket = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind UDP");
    let local = socket.local_addr().expect("local");
    let tracker = FlowTracker::new(|_: &[NewConnectionLog]| Ok(()));
    let key = FlowKey {
        protocol: Protocol::Udp,
        local_addr: local.ip(),
        local_port: local.port(),
        remote_addr: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 53)),
        remote_port: 53,
    };
    tracker.handle_event(&FlowEvent::Opened(
        key,
        FlowMeta {
            pid: 0,
            process: None,
            open_ts: 0,
            cookie: None,
            if_index: None,
        },
    ));
    assert_eq!(
        tracker.flow_pid_for_test(&key),
        Some(std::process::id()),
        "a scan after the flow was seen names the socket's owner"
    );
}

#[test]
fn idle_eviction_reuses_one_socket_capture_for_unknown_flows() {
    let tracker = FlowTracker::new(|_: &[NewConnectionLog]| Ok(()));
    let stale = OffsetDateTime::now_utc() - Duration::from_secs(31 * 60);
    let old_unknown = || ActiveFlow {
        conn_id: 1,
        open_pid: 0,
        app_id: 0,
        app_path: "Unknown (Exited)".to_owned(),
        app_name: crate::process_resolver::UNKNOWN_APP_NAME.to_owned(),
        pid: 0,
        protocol: "TCP".to_owned(),
        src_ip: "10.0.0.2".to_owned(),
        src_port: 50_000,
        dst_ip: "93.184.216.34".to_owned(),
        dst_port: 443,
        bytes_sent: 1,
        bytes_received: 0,
        persisted_sent: 0,
        persisted_received: 0,
        db_row_created: false,
        cookie: None,
        persisted_app_id: 0,
        persisted_domain: String::new(),
        name_lookup: NameLookup::default(),
        traffic_template: None,
        unknown_since: Some(
            Instant::now()
                .checked_sub(UNKNOWN_SOCKET_ATTRIBUTION_DELAY + Duration::from_millis(1))
                .unwrap_or_else(Instant::now),
        ),
        unknown_socket_lookup_done: false,
        socket_lookup_attempts: 0,
        next_socket_lookup: None,
        identity_lookup_attempts: 0,
        attribution_lookup: AttributionLookup::Idle,
        next_identity_retry: None,
        process_start_ts: None,
        open_ts: 0,
        finishing: false,
        opened_at: stale,
        last_seen: stale,
    };
    let mut second_key = sample_key();
    second_key.local_port = 50_001;
    tracker.active.lock().insert(sample_key(), old_unknown());
    tracker.active.lock().insert(second_key, old_unknown());
    let before = tracker.socket_snapshot_calls_for_test();

    tracker.evict_idle();

    assert_eq!(
        tracker.socket_snapshot_calls_for_test(),
        before + 1,
        "one capture must serve every unknown flow in the eviction batch"
    );
}

#[test]
fn zero_pid_open_never_downgrades_known_flow() {
    let tracker = FlowTracker::new(|_: &[NewConnectionLog]| Ok(()));
    let key = sample_key();
    tracker.handle_event(&FlowEvent::Opened(
        key,
        FlowMeta {
            pid: 12_345,
            process: None,
            open_ts: 1,
            cookie: None,
            if_index: None,
        },
    ));

    tracker.handle_event(&FlowEvent::Opened(
        key,
        FlowMeta {
            pid: 0,
            process: None,
            open_ts: 2,
            cookie: None,
            if_index: None,
        },
    ));

    assert_eq!(tracker.flow_pid_for_test(&key), Some(12_345));
}

#[test]
fn duplicate_ownerless_open_never_displaces_a_real_owner() {
    let (_dir, store) = system_test_store();
    let tracker = system_tracker(&store);
    let key = dhcp_key();
    let pid = 459_301;
    let (vpn_path, vpn_name) = user_app();
    tracker.handle_event(&FlowEvent::Opened(
        key,
        FlowMeta {
            pid,
            process: Some(ProcessIdentity {
                executable: vpn_path.to_owned(),
                name: vpn_name.to_owned(),
                start_ts: 0,
            }),
            open_ts: 0,
            cookie: None,
            if_index: None,
        },
    ));
    let (app_id, app_path, app_name) = tracker.flow_identity_for_test(&key).expect("flow");
    assert_eq!(app_path, vpn_path);
    assert_eq!(app_name, vpn_name);

    // A stale duplicate open without owner evidence (e.g. re-emitted after
    // a backend restart) resolves to System but must not rewind the owner.
    tracker.handle_event(&FlowEvent::Opened(key, ownerless_meta()));
    let (still_id, still_path, still_name) = tracker.flow_identity_for_test(&key).expect("flow");
    assert_eq!(
        (still_id, still_path.as_str(), still_name.as_str()),
        (app_id, app_path.as_str(), app_name.as_str())
    );
    assert_eq!(tracker.flow_pid_for_test(&key), Some(pid));

    tracker.handle_event(&FlowEvent::Bytes(
        key,
        ByteDelta {
            sent: 64,
            received: 0,
        },
    ));
    tracker.flush_active_flows().expect("flush active");
    tracker.flush().expect("flush");
    let page = store
        .query_connection_logs(&antiwire_store::ConnectionLogQuery::default())
        .expect("query logs");
    assert_eq!(page.logs.len(), 1);
    assert_eq!(page.logs[0].app_id, app_id);
}

#[test]
fn ownerless_timestamps_never_poison_instance_tracking() {
    let (_dir, store) = system_test_store();
    let tracker = system_tracker(&store);
    let key = dhcp_key();
    // Ownerless evidence carrying a timestamp it cannot vouch for: the
    // fold still applies, but the timestamp must not stick to the flow.
    tracker.handle_event(&FlowEvent::Opened(
        key,
        FlowMeta {
            pid: 0,
            process: Some(ProcessIdentity {
                executable: String::new(),
                name: String::new(),
                start_ts: 9_999,
            }),
            open_ts: 0,
            cookie: None,
            if_index: None,
        },
    ));
    let (_, path, _) = tracker.flow_identity_for_test(&key).expect("flow");
    assert_eq!(path, "System");

    // A later real owner with an unrelated timestamp must still adopt: the
    // ownerless timestamp proved nothing and blocks nothing.
    let pid = 459_401;
    let (vpn_path, vpn_name) = user_app();
    tracker.handle_event(&FlowEvent::Opened(
        key,
        FlowMeta {
            pid,
            process: Some(ProcessIdentity {
                executable: vpn_path.to_owned(),
                name: vpn_name.to_owned(),
                start_ts: 1_000,
            }),
            open_ts: 0,
            cookie: None,
            if_index: None,
        },
    ));
    let (app_id, app_path, app_name) = tracker.flow_identity_for_test(&key).expect("flow");
    assert!(app_id > 0);
    assert_eq!(app_path, vpn_path);
    assert_eq!(app_name, vpn_name);
    assert_eq!(tracker.flow_pid_for_test(&key), Some(pid));
}

#[test]
fn system_identity_without_store_id_skips_socket_lookup() {
    // A folded System identity whose store id is still pending (the
    // sighting write failed transiently) already has its owner: the id is
    // retried at flush time, so no socket work is needed.
    let folded = ActiveFlow {
        conn_id: 1,
        open_pid: 0,
        app_id: 0,
        app_path: "System".to_owned(),
        app_name: "system".to_owned(),
        pid: 0,
        protocol: "UDP".to_owned(),
        src_ip: "192.168.68.50".to_owned(),
        src_port: 68,
        dst_ip: "192.168.68.1".to_owned(),
        dst_port: 67,
        bytes_sent: 100,
        bytes_received: 0,
        persisted_sent: 0,
        persisted_received: 0,
        db_row_created: false,
        cookie: None,
        persisted_app_id: 0,
        persisted_domain: String::new(),
        name_lookup: NameLookup::default(),
        traffic_template: None,
        unknown_since: None,
        unknown_socket_lookup_done: false,
        socket_lookup_attempts: 0,
        next_socket_lookup: None,
        identity_lookup_attempts: 0,
        attribution_lookup: AttributionLookup::Idle,
        next_identity_retry: None,
        process_start_ts: None,
        open_ts: 0,
        finishing: false,
        opened_at: OffsetDateTime::now_utc(),
        last_seen: OffsetDateTime::now_utc(),
    };
    assert!(!needs_socket_attribution(&folded));

    let empty = ActiveFlow {
        app_id: 0,
        app_path: String::new(),
        app_name: String::new(),
        ..folded
    };
    assert!(needs_socket_attribution(&empty));
}

#[test]
fn coalescing_flush_does_not_scan_or_persist_active_flows() {
    let writes = Arc::new(StdMutex::new(Vec::new()));
    let writes_clone = Arc::clone(&writes);
    let tracker = FlowTracker::new(move |logs: &[NewConnectionLog]| {
        writes_clone.lock().expect("lock").extend_from_slice(logs);
        Ok(())
    });
    let key = sample_key();
    tracker.handle_event(&FlowEvent::Opened(
        key,
        FlowMeta {
            pid: 100,
            process: None,
            open_ts: 0,
            cookie: None,
            if_index: None,
        },
    ));
    tracker.handle_event(&FlowEvent::Bytes(
        key,
        ByteDelta {
            sent: 100,
            received: 200,
        },
    ));

    tracker.flush().expect("flush closed queue");

    assert!(writes.lock().expect("lock").is_empty());
    assert_eq!(tracker.tracked_flow_count(), 1);
}

#[test]
fn failed_store_write_remains_queued_for_retry() {
    let attempts = Arc::new(AtomicUsize::new(0));
    let writes = Arc::new(StdMutex::new(Vec::new()));
    let attempts_clone = Arc::clone(&attempts);
    let writes_clone = Arc::clone(&writes);
    let tracker = FlowTracker::new(move |logs: &[NewConnectionLog]| {
        if attempts_clone.fetch_add(1, Ordering::SeqCst) == 0 {
            return Err(store_error("injected failure"));
        }
        writes_clone.lock().expect("lock").extend_from_slice(logs);
        Ok(())
    });
    let key = sample_key();
    let meta = FlowMeta {
        pid: 100,
        process: None,
        open_ts: 0,
        cookie: None,
        if_index: None,
    };
    tracker.handle_event(&FlowEvent::Opened(key, meta.clone()));
    tracker.handle_event(&FlowEvent::Bytes(
        key,
        ByteDelta {
            sent: 100,
            received: 200,
        },
    ));
    tracker.handle_event(&FlowEvent::Closed(key, meta));

    assert!(tracker.flush().is_err());
    tracker.flush().expect("retry succeeds");

    let writes = writes.lock().expect("lock");
    assert_eq!(writes.len(), 1);
    assert_eq!(writes[0].bytes_sent, 100);
    assert_eq!(writes[0].bytes_received, 200);
}

#[test]
fn socket_lookup_retry_stays_pending_during_the_grace_window() {
    let tracker = FlowTracker::new(|_: &[NewConnectionLog]| Ok(()));
    let key = sample_key();
    tracker.handle_event(&FlowEvent::Bytes(
        key,
        ByteDelta {
            sent: 32,
            received: 0,
        },
    ));

    tracker.flush_active_flows().expect("first flush");
    tracker.flush_active_flows().expect("second flush");

    assert_eq!(tracker.flow_pid_for_test(&key), Some(0));
    assert!(tracker.flow_lookup_retry_pending_for_test(&key));
}

/// An unknown flow the socket table can never resolve must not force a full
/// socket-table capture on every flush. Retries back off and stop at a cap; the
/// close path still gets its own forced attempt.
#[test]
fn unresolvable_unknown_flow_retries_with_backoff_and_a_cap() {
    let tracker = FlowTracker::new(|_: &[NewConnectionLog]| Ok(()));
    let key = sample_key();
    tracker.handle_event(&FlowEvent::Bytes(
        key,
        ByteDelta {
            sent: 32,
            received: 0,
        },
    ));
    tracker.expire_unknown_grace_for_test(&key);

    tracker.flush_active_flows().expect("first flush");
    let after_first = tracker.socket_snapshot_calls_for_test();
    assert!(
        tracker.flow_lookup_retry_pending_for_test(&key),
        "a miss must retain a bounded retry"
    );

    tracker.flush_active_flows().expect("second flush");
    assert_eq!(
        tracker.socket_snapshot_calls_for_test(),
        after_first,
        "a later flush must not re-enumerate the socket table"
    );
    assert_eq!(tracker.flow_pid_for_test(&key), Some(0));
    for _ in 1..MAX_SOCKET_LOOKUP_ATTEMPTS {
        tracker
            .active
            .lock()
            .get_mut(&key)
            .unwrap()
            .next_socket_lookup = Some(Instant::now());
        tracker.flush_active_flows().unwrap();
    }
    assert!(!tracker.flow_lookup_retry_pending_for_test(&key));
    let exhausted = tracker.socket_snapshot_calls_for_test();
    assert_eq!(
        exhausted,
        after_first + u64::from(MAX_SOCKET_LOOKUP_ATTEMPTS - 1)
    );
    tracker.flush_active_flows().unwrap();
    assert_eq!(tracker.socket_snapshot_calls_for_test(), exhausted);
}

#[test]
fn udp_owner_can_resolve_on_a_later_retry() {
    let tracker = FlowTracker::new(|_: &[NewConnectionLog]| Ok(()));
    let mut key = sample_key();
    key.protocol = Protocol::Udp;
    tracker.handle_event(&FlowEvent::Bytes(
        key,
        ByteDelta {
            sent: 0,
            received: 32,
        },
    ));
    tracker.expire_unknown_grace_for_test(&key);
    let mut active = tracker.active.lock();
    let flow = active.get_mut(&key).unwrap();
    tracker.maybe_attempt_socket_attribution(flow, &key, &SocketOwnerSnapshot::default(), false);
    assert_eq!(flow.socket_lookup_attempts, 1);
    let mut snapshot = SocketOwnerSnapshot::default();
    snapshot.insert_udp(
        netmetrics_core::LocalEndpoint {
            address: key.local_addr,
            port: key.local_port,
        },
        4242,
    );
    // Another flow's snapshot must not bypass this flow's backoff.
    tracker.maybe_attempt_socket_attribution(flow, &key, &snapshot, false);
    assert_eq!(flow.pid, 0);
    flow.next_socket_lookup = Some(Instant::now());
    tracker.maybe_attempt_socket_attribution(flow, &key, &snapshot, false);
    assert_eq!(flow.pid, 4242);
    assert_eq!(
        flow.socket_lookup_attempts, 0,
        "successful resolution resets retry state"
    );
    assert!(!should_retry_socket_lookup(flow));
}

/// A socket-table owner discovered while the identity backoff is armed
/// must still resolve: the new pid is fresh evidence, not another blind
/// retry. Covers hourly UDP renews (e.g. DHCP) stranding as unknown after
/// one slow lookup armed the backoff.
#[test]
fn newly_discovered_socket_pid_forces_identity_refresh_past_backoff() {
    let dir = tempdir().expect("tempdir");
    let keystore = UnixSecureFileKeyProvider::new(dir.path().join("key"));
    let store =
        Arc::new(Store::open_with_keystore(dir.path().join("db.sqlite"), &keystore).expect("open"));
    let traffic_hub = TrafficStreamingHub::with_capacity(4);
    let processor = Arc::new(test_processor(Arc::clone(&store), traffic_hub.clone()));
    let tracker =
        FlowTracker::with_processor(StoreFlowAdapter::new(Arc::clone(&store)), Some(processor));

    // Unknown UDP flow, as produced by a first packet with no owner.
    let mut key = sample_key();
    key.protocol = Protocol::Udp;
    tracker.handle_event(&FlowEvent::Bytes(
        key,
        ByteDelta {
            sent: 32,
            received: 0,
        },
    ));
    tracker.expire_unknown_grace_for_test(&key);

    // An earlier failed identity attempt armed the backoff.
    let pid = 452_101;
    tracker
        .processes_for_test()
        .process_started(pid, r"C:\Apps\late.exe", "late.exe", 0);
    {
        let mut active = tracker.active.lock();
        let flow = active.get_mut(&key).expect("flow");
        flow.identity_lookup_attempts = 1;
        flow.next_identity_retry = Some(Instant::now() + std::time::Duration::from_secs(60));
    }

    // The socket table now names the owner: resolution must run anyway.
    let mut snapshot = SocketOwnerSnapshot::default();
    snapshot.insert_udp(
        netmetrics_core::LocalEndpoint {
            address: key.local_addr,
            port: key.local_port,
        },
        pid,
    );
    {
        let mut active = tracker.active.lock();
        let flow = active.get_mut(&key).expect("flow");
        tracker.maybe_attempt_socket_attribution(flow, &key, &snapshot, false);
        assert_eq!(flow.pid, pid);
    }

    let (_, _, name) = tracker.flow_identity_for_test(&key).expect("flow");
    assert_eq!(name, "late.exe");
    assert_eq!(
        tracker.identity_attempts_for_test(&key),
        Some(0),
        "a successful recovery resets the budget"
    );
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

/// A verified responder (pid, path, name) for the late-fold test, per host
/// OS: the mechanics are identical, only the service differs. The key stays
/// `dhcp_server_key` everywhere: the DHCP server role never folds ownerless
/// on any profile, so the unknown pre-state holds on every host.
#[cfg(windows)]
fn verified_server_case() -> (u32, &'static str, &'static str) {
    (
        459_201,
        r"C:\Windows\System32\svchost.exe::SharedAccess",
        "SharedAccess (svchost.exe)",
    )
}

/// A verified responder (pid, path, name) for the late-fold test, per host
/// OS: the mechanics are identical, only the service differs. The key stays
/// `dhcp_server_key` everywhere: the DHCP server role never folds ownerless
/// on any profile, so the unknown pre-state holds on every host.
#[cfg(target_os = "linux")]
fn verified_server_case() -> (u32, &'static str, &'static str) {
    (459_201, "/usr/sbin/dhcpd", "dhcpd")
}

/// A verified responder (pid, path, name) for the late-fold test, per host
/// OS: the mechanics are identical, only the service differs. The key stays
/// `dhcp_server_key` everywhere: the DHCP server role never folds ownerless
/// on any profile, so the unknown pre-state holds on every host.
#[cfg(target_os = "macos")]
fn verified_server_case() -> (u32, &'static str, &'static str) {
    (459_201, "/usr/libexec/bootpd", "bootpd")
}

fn test_processor_and_hub(
    store: Arc<Store>,
    traffic_hub: TrafficStreamingHub,
) -> (FlowProcessor, AlertPublisher) {
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
        store,
        traffic_hub,
        alerts.clone(),
        siem,
    );
    (processor, alerts)
}

fn system_test_store() -> (tempfile::TempDir, Arc<Store>) {
    let dir = tempdir().expect("tempdir");
    let keystore = UnixSecureFileKeyProvider::new(dir.path().join("key"));
    let store =
        Arc::new(Store::open_with_keystore(dir.path().join("db.sqlite"), &keystore).expect("open"));
    (dir, store)
}

fn system_tracker(store: &Arc<Store>) -> FlowTracker<StoreFlowAdapter> {
    let traffic_hub = TrafficStreamingHub::with_capacity(4);
    let processor = Arc::new(test_processor(Arc::clone(store), traffic_hub.clone()));
    FlowTracker::with_processor(StoreFlowAdapter::new(Arc::clone(store)), Some(processor))
}

fn system_app_id(store: &Arc<Store>) -> i32 {
    store
        .find_application_by_name("system")
        .expect("application lookup")
        .expect("system row exists")
        .id
}

#[test]
fn ownerless_dhcp_flow_folds_to_system_without_socket_lookup() {
    let (_dir, store) = system_test_store();
    let tracker = system_tracker(&store);
    let key = dhcp_key();

    tracker.handle_event(&FlowEvent::Bytes(
        key,
        ByteDelta {
            sent: 317,
            received: 0,
        },
    ));

    let (app_id, app_path, app_name) = tracker.flow_identity_for_test(&key).expect("flow");
    assert!(app_id > 0);
    assert_eq!(app_path, "System");
    assert_eq!(app_name, "system");
    assert_eq!(tracker.socket_snapshot_calls_for_test(), 0);
    assert_eq!(tracker.identity_attempts_for_test(&key), Some(0));

    // The grace window and periodic flushes must not consult the socket
    // table for a folded flow either.
    tracker.expire_unknown_grace_for_test(&key);
    tracker.flush_active_flows().expect("flush active");
    assert_eq!(tracker.socket_snapshot_calls_for_test(), 0);

    // The reply arrives on the same key, then the flow closes: one System row.
    tracker.handle_event(&FlowEvent::Bytes(
        key,
        ByteDelta {
            sent: 0,
            received: 300,
        },
    ));
    tracker.handle_event(&FlowEvent::Closed(key, ownerless_meta()));
    tracker.flush().expect("flush");

    let page = store
        .query_connection_logs(&antiwire_store::ConnectionLogQuery::default())
        .expect("query logs");
    assert_eq!(page.logs.len(), 1);
    assert_eq!(page.logs[0].bytes_sent, 317);
    assert_eq!(page.logs[0].bytes_received, 300);
    assert!(page.logs[0].closed_at.is_some());
    assert_eq!(page.logs[0].app_id, system_app_id(&store));
}

#[test]
fn ownerless_dns_request_folds_to_system() {
    let (_dir, store) = system_test_store();
    let tracker = system_tracker(&store);
    let key = FlowKey {
        protocol: Protocol::Udp,
        local_addr: IpAddr::V4(Ipv4Addr::new(192, 168, 68, 50)),
        local_port: 51_234,
        remote_addr: IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9)),
        remote_port: 53,
    };

    tracker.handle_event(&FlowEvent::Bytes(
        key,
        ByteDelta {
            sent: 80,
            received: 240,
        },
    ));
    tracker.handle_event(&FlowEvent::Closed(key, ownerless_meta()));
    tracker.flush().expect("flush");

    let page = store
        .query_connection_logs(&antiwire_store::ConnectionLogQuery::default())
        .expect("query logs");
    assert_eq!(page.logs.len(), 1);
    assert_eq!(page.logs[0].app_id, system_app_id(&store));
}

#[cfg(any(target_os = "windows", target_os = "linux", target_os = "macos"))]
#[test]
fn verified_service_folds_on_late_socket_attribution() {
    let (_dir, store) = system_test_store();
    let tracker = system_tracker(&store);
    // The server role stays unattributed until verified identity evidence
    // arrives for the flow's observed process generation.
    let key = dhcp_server_key();
    let (pid, path, name) = verified_server_case();
    tracker.handle_event(&FlowEvent::Opened(
        key,
        FlowMeta {
            pid,
            process: Some(ProcessIdentity {
                executable: String::new(),
                name: String::new(),
                start_ts: 10_000,
            }),
            open_ts: 0,
            cookie: None,
            if_index: None,
        },
    ));
    tracker.handle_event(&FlowEvent::Bytes(
        key,
        ByteDelta {
            sent: 100,
            received: 0,
        },
    ));
    let (_, _, before) = tracker.flow_identity_for_test(&key).expect("flow");
    assert_eq!(before, crate::process_resolver::UNKNOWN_APP_NAME);

    tracker
        .processes_for_test()
        .seed_cache(pid, path, name, 10_000);
    let mut snapshot = SocketOwnerSnapshot::default();
    snapshot.insert_udp(
        netmetrics_core::LocalEndpoint {
            address: key.local_addr,
            port: key.local_port,
        },
        pid,
    );
    {
        let mut active = tracker.active.lock();
        let flow = active.get_mut(&key).expect("flow");
        // Make the bounded retry due after the new same-generation
        // identity evidence arrives.
        flow.next_identity_retry = None;
        tracker.maybe_attempt_socket_attribution(flow, &key, &snapshot, true);
        assert_eq!(flow.pid, pid);
    }
    tracker.processes_for_test().process_stopped(pid);

    let (app_id, app_path, app_name) = tracker.flow_identity_for_test(&key).expect("flow");
    assert!(app_id > 0);
    assert_eq!(app_path, "System");
    assert_eq!(app_name, "system");
}

#[tokio::test]
async fn rogue_dhcp_server_keeps_app_and_alerts() {
    let (_dir, store) = system_test_store();
    let traffic_hub = TrafficStreamingHub::with_capacity(4);
    let (processor, publisher) = test_processor_and_hub(Arc::clone(&store), traffic_hub.clone());
    let mut events = publisher.subscribe();
    let tracker = FlowTracker::with_processor(
        StoreFlowAdapter::new(Arc::clone(&store)),
        Some(Arc::new(processor)),
    );

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
    let key = dhcp_server_key();
    let meta = FlowMeta {
        pid: 459_202,
        process: Some(ProcessIdentity {
            executable: evil_path.to_owned(),
            name: evil_name.to_owned(),
            start_ts: 0,
        }),
        open_ts: 0,
        cookie: None,
        if_index: None,
    };
    tracker.handle_event(&FlowEvent::Opened(key, meta.clone()));

    let (app_id, app_path, app_name) = tracker.flow_identity_for_test(&key).expect("flow");
    assert!(app_id > 0);
    assert_eq!(app_path, evil_path);
    assert_eq!(app_name, evil_name);

    let mut alert = None;
    for _ in 0..8 {
        match tokio::time::timeout(std::time::Duration::from_millis(50), events.recv()).await {
            Ok(Some(event)) if event.kind == AlertKind::SystemServiceImpersonation => {
                alert = Some(event);
                break;
            }
            Ok(_) => {}
            Err(_) => break,
        }
    }
    let alert = alert.expect("impersonation alert");
    assert!(alert.message.contains("evil.exe"));
    assert!(alert.message.contains("DHCPv4 server"));

    // The persisted record keeps the real application, not System.
    tracker.handle_event(&FlowEvent::Bytes(
        key,
        ByteDelta {
            sent: 300,
            received: 0,
        },
    ));
    tracker.handle_event(&FlowEvent::Closed(key, meta));
    tracker.flush().expect("flush");
    let page = store
        .query_connection_logs(&antiwire_store::ConnectionLogQuery::default())
        .expect("query logs");
    assert_eq!(page.logs.len(), 1);
    assert_eq!(page.logs[0].app_id, app_id);
}

#[test]
fn tcp_listener_snapshot_resolves_an_inbound_flow_on_a_retry() {
    let tracker = FlowTracker::new(|_: &[NewConnectionLog]| Ok(()));
    let key = sample_key();
    tracker.handle_event(&FlowEvent::Bytes(
        key,
        ByteDelta {
            sent: 0,
            received: 64,
        },
    ));
    tracker.expire_unknown_grace_for_test(&key);
    let mut active = tracker.active.lock();
    let flow = active.get_mut(&key).unwrap();
    // The transient established tuple is already gone from the table.
    tracker.maybe_attempt_socket_attribution(flow, &key, &SocketOwnerSnapshot::default(), false);
    assert_eq!(flow.pid, 0);

    // The durable listener still names the process that accepts on this port.
    let mut snapshot = SocketOwnerSnapshot::default();
    snapshot.insert_tcp_listener(
        netmetrics_core::LocalEndpoint {
            address: key.local_addr,
            port: key.local_port,
        },
        4242,
    );
    flow.next_socket_lookup = Some(Instant::now());
    tracker.maybe_attempt_socket_attribution(flow, &key, &snapshot, false);
    assert_eq!(flow.pid, 4242);
    assert!(!needs_socket_attribution(flow));
    assert!(!should_retry_socket_lookup(flow));
}

#[test]
fn periodic_flush_on_empty_tracker_is_noop() {
    let tracker = FlowTracker::new(|_: &[NewConnectionLog]| Ok(()));
    tracker.flush_active_flows().expect("flush active");
}

#[test]
fn periodic_flush_persists_active_flow_bytes() {
    let writes = Arc::new(StdMutex::new(Vec::new()));
    let writes_clone = Arc::clone(&writes);
    let tracker = FlowTracker::new(move |logs: &[NewConnectionLog]| {
        writes_clone.lock().expect("lock").extend_from_slice(logs);
        Ok(())
    });

    let key = sample_key();
    let meta = FlowMeta {
        pid: 100,
        process: None,
        open_ts: 0,
        cookie: None,
        if_index: None,
    };

    tracker.handle_event(&FlowEvent::Opened(key, meta));
    tracker.handle_event(&FlowEvent::Bytes(
        key,
        ByteDelta {
            sent: 100,
            received: 5_000_000,
        },
    ));
    tracker.flush_active_flows().expect("flush active");

    let batch = writes.lock().expect("lock");
    assert_eq!(batch.len(), 1);
    assert_eq!(batch[0].bytes_sent, 100);
    assert_eq!(batch[0].bytes_received, 5_000_000);
    assert_eq!(tracker.tracked_flow_count(), 1);
    drop(batch);

    tracker.handle_event(&FlowEvent::Bytes(
        key,
        ByteDelta {
            sent: 50,
            received: 3_000_000,
        },
    ));
    tracker.flush_active_flows().expect("flush active again");

    let batch = writes.lock().expect("lock");
    assert_eq!(batch.len(), 2);
    assert_eq!(batch[1].bytes_sent, 50);
    assert_eq!(batch[1].bytes_received, 3_000_000);
}

/// The skip-before-enrich filter must not strand a flow that is persisted
/// before its DNS answer arrives: a later zero-byte tick still backfills it.
#[test]
fn late_domain_still_backfills_an_already_persisted_active_flow() {
    let dir = tempdir().expect("tempdir");
    let keystore = UnixSecureFileKeyProvider::new(dir.path().join("key"));
    let store =
        Arc::new(Store::open_with_keystore(dir.path().join("db.sqlite"), &keystore).expect("open"));
    let traffic_hub = TrafficStreamingHub::with_capacity(4);
    let processor = Arc::new(test_processor(Arc::clone(&store), traffic_hub));
    let tracker =
        FlowTracker::with_processor(StoreFlowAdapter::new(Arc::clone(&store)), Some(processor));
    let key = sample_key();
    tracker.handle_event(&FlowEvent::Opened(
        key,
        FlowMeta {
            pid: 71_004,
            process: None,
            open_ts: 1,
            cookie: None,
            if_index: None,
        },
    ));
    tracker.handle_event(&FlowEvent::Bytes(
        key,
        ByteDelta {
            sent: 64,
            received: 128,
        },
    ));
    // No resolver cache entry is relied on: expire the unknown-flow
    // grace window so the provisional row is written on the first flush.
    tracker.expire_unknown_grace_for_test(&key);
    tracker
        .flush_active_flows()
        .expect("persist before the domain is known");

    // The answer arrives the way every answer does. It is what prompts the
    // flow to be looked up again: an idle flow is not retried on a timer.
    let processor = tracker.processor.as_ref().expect("processor");
    processor.handle_event(&FlowEvent::DnsResolved {
        pid: 0,
        query: "late.example".to_owned(),
        answers: vec![key.remote_addr.to_string()],
    });

    tracker
        .flush_active_flows()
        .expect("backfill domain on a zero-byte tick");

    let page = store
        .query_connection_logs(&antiwire_store::ConnectionLogQuery::default())
        .expect("query logs");
    assert_eq!(page.logs.len(), 1);
    assert_eq!(page.logs[0].dst_domain, "late.example (inferred)");
}

/// Builds a tracker with one attributed, already-persisted active flow.
fn enriched_flow_setup(
    pid: u32,
) -> (
    tempfile::TempDir,
    Arc<Store>,
    Arc<FlowProcessor>,
    FlowTracker<StoreFlowAdapter>,
    FlowKey,
) {
    enriched_flow_setup_with_policy(
        pid,
        RuleEngine::new(),
        TrafficStreamingHub::with_capacity(4),
    )
}

fn enriched_flow_setup_with_policy(
    pid: u32,
    engine: RuleEngine,
    traffic_hub: TrafficStreamingHub,
) -> (
    tempfile::TempDir,
    Arc<Store>,
    Arc<FlowProcessor>,
    FlowTracker<StoreFlowAdapter>,
    FlowKey,
) {
    let dir = tempdir().expect("tempdir");
    let keystore = UnixSecureFileKeyProvider::new(dir.path().join("key"));
    let store =
        Arc::new(Store::open_with_keystore(dir.path().join("db.sqlite"), &keystore).expect("open"));
    let processor = Arc::new(test_processor_with_policy(
        Arc::clone(&store),
        traffic_hub,
        engine,
    ));
    let tracker = FlowTracker::with_processor(
        StoreFlowAdapter::new(Arc::clone(&store)),
        Some(Arc::clone(&processor)),
    );
    let key = sample_key();
    tracker.handle_event(&FlowEvent::Opened(
        key,
        FlowMeta {
            pid,
            process: Some(ProcessIdentity {
                executable: UPGRADE_PATH.to_owned(),
                name: "upgrade.exe".to_owned(),
                start_ts: 1,
            }),
            open_ts: 1,
            cookie: None,
            if_index: None,
        },
    ));
    tracker.handle_event(&FlowEvent::Bytes(
        key,
        ByteDelta {
            sent: 64,
            received: 128,
        },
    ));
    tracker.expire_unknown_grace_for_test(&key);
    tracker.flush_active_flows().expect("persist initial bytes");
    (dir, store, processor, tracker, key)
}

fn insert_dns_metadata(processor: &FlowProcessor, key: &FlowKey, pid: u32, domain: &str) {
    let observed_at =
        u64::try_from((OffsetDateTime::now_utc().unix_timestamp_nanos() / 1_000_000).max(0))
            .unwrap_or(0);
    processor.handle_event(&FlowEvent::DnsResolvedWithMetadata {
        attribution: if pid == 0 {
            DnsResolutionAttribution::Shared
        } else {
            DnsResolutionAttribution::Process(pid)
        },
        query: domain.to_owned(),
        answers: vec![key.remote_addr.to_string()],
        ttl_ms: 60_000,
        observed_at,
    });
}

fn single_persisted_domain(store: &Store) -> String {
    let page = store
        .query_connection_logs(&antiwire_store::ConnectionLogQuery::default())
        .expect("query logs");
    assert_eq!(page.logs.len(), 1, "one connection must map to one row");
    page.logs[0].dst_domain.clone()
}

#[test]
fn persisted_inferred_domain_upgrades_without_new_bytes() {
    let (_dir, store, processor, tracker, key) = enriched_flow_setup(71_010);
    insert_dns_metadata(&processor, &key, 0, "inferred.example");
    tracker.flush_active_flows().expect("persist inferred");
    assert_eq!(
        single_persisted_domain(&store),
        "inferred.example (inferred)"
    );

    insert_dns_metadata(&processor, &key, 71_010, "inferred.example");
    tracker
        .flush_active_flows()
        .expect("upgrade on a zero-byte tick");

    assert_eq!(
        single_persisted_domain(&store),
        "inferred.example",
        "process-scoped evidence must drop the (inferred) suffix"
    );
    assert_eq!(processor.domain_upgrade_count(), 1);
}

/// The regression this guards: every active flow without a confirmed name
/// was looked up again on each flush that carried bytes, and at least every
/// five seconds otherwise, for as long as it lived. In a 15-minute capture
/// 90% of 8,004 lookups found nothing, most of them repeats.
#[test]
fn an_unconfirmed_flow_is_looked_up_again_only_when_evidence_arrives_for_its_address() {
    let (_dir, store, processor, tracker, key) = enriched_flow_setup(71_040);
    let lookups = || {
        let stats = processor.domain_lookup_stats();
        stats.process_hint
            + stats.application_hint
            + stats.retained_process_hint
            + stats.retained_application_hint
            + stats.shared_hint
            + stats.pending
            + stats.store
            + stats.ambiguous
            + stats.unresolved
    };
    let baseline = lookups();
    assert!(
        baseline >= 1,
        "the flow is looked up when it is first written"
    );
    assert_eq!(single_persisted_domain(&store), "");

    // Time passing and bytes moving say nothing new about the address.
    for _ in 0..5 {
        tracker.handle_event(&FlowEvent::Bytes(
            key,
            ByteDelta {
                sent: 10,
                received: 10,
            },
        ));
        tracker.flush_active_flows().expect("persist bytes");
    }
    assert_eq!(lookups(), baseline, "no lookup without new evidence");

    // Nor does an answer for some other address.
    let mut elsewhere = key;
    elsewhere.remote_addr = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 77));
    insert_dns_metadata(&processor, &elsewhere, 71_040, "elsewhere.example");
    tracker.flush_active_flows().expect("flush");
    assert_eq!(lookups(), baseline);

    // An answer for its address, from another process, names it by inference.
    insert_dns_metadata(&processor, &key, 71_041, "site.example");
    tracker.flush_active_flows().expect("flush");
    assert_eq!(lookups(), baseline + 1);
    assert_eq!(single_persisted_domain(&store), "site.example (inferred)");
    tracker.flush_active_flows().expect("flush");
    assert_eq!(
        lookups(),
        baseline + 1,
        "and that settles it until more arrives"
    );

    // One from its own process confirms it, after which it is never looked up.
    insert_dns_metadata(&processor, &key, 71_040, "site.example");
    tracker.flush_active_flows().expect("flush");
    assert_eq!(lookups(), baseline + 2);
    assert_eq!(single_persisted_domain(&store), "site.example");
    insert_dns_metadata(&processor, &key, 71_041, "other.example");
    tracker.flush_active_flows().expect("flush");
    assert_eq!(lookups(), baseline + 2);
}

/// A flow whose own names competed when it opened is named once those names
/// are all in, and is then left alone however much more arrives for its address.
#[test]
fn a_flow_whose_names_competed_is_not_looked_up_again_once_settled() {
    let pid = 71_050;
    let (_dir, store, processor, tracker, first) = enriched_flow_setup(pid);
    let lookups = || {
        let stats = processor.domain_lookup_stats();
        (
            stats.nearest_hint,
            stats.ambiguous + stats.unresolved + stats.store,
        )
    };
    let now_ms = netmetrics_core::unix_now_ms();
    let opened_at = now_ms - 10_000;
    let mut key = first;
    key.remote_addr = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 50));
    key.local_port = first.local_port + 1;
    let hint = |from: u32, query: &str, observed_at| {
        processor.handle_event(&FlowEvent::DnsResolvedWithMetadata {
            attribution: DnsResolutionAttribution::Process(from),
            query: query.to_owned(),
            answers: vec![key.remote_addr.to_string()],
            ttl_ms: 300_000,
            observed_at,
        });
    };
    hint(pid, "earlier.example", opened_at - 60_000);
    hint(pid, "just-asked.example", opened_at - 100);

    tracker.handle_event(&FlowEvent::Opened(
        key,
        FlowMeta {
            pid,
            process: Some(ProcessIdentity {
                executable: UPGRADE_PATH.to_owned(),
                name: "upgrade.exe".to_owned(),
                start_ts: 1,
            }),
            open_ts: opened_at,
            cookie: None,
            if_index: None,
        },
    ));
    tracker.handle_event(&FlowEvent::Bytes(
        key,
        ByteDelta {
            sent: 64,
            received: 128,
        },
    ));
    tracker.expire_unknown_grace_for_test(&key);
    let before = lookups();
    tracker.flush_active_flows().expect("persist the flow");
    assert_eq!(
        lookups().0,
        before.0 + 1,
        "named by the name just asked for"
    );
    let domains: Vec<String> = store
        .query_connection_logs(&antiwire_store::ConnectionLogQuery::default())
        .expect("query logs")
        .logs
        .into_iter()
        .map(|log| log.dst_domain)
        .collect();
    assert!(
        domains.contains(&"just-asked.example (inferred)".to_owned()),
        "{domains:?}"
    );

    // More evidence for the address, from its own process and from another.
    let settled = lookups();
    hint(pid, "asked-much-later.example", now_ms);
    hint(pid + 1, "someone-else.example", now_ms);
    for _ in 0..3 {
        tracker.flush_active_flows().expect("flush");
    }
    assert_eq!(lookups(), settled, "a settled name is not looked up again");
}

/// A second flow of `pid` to an address of its own, opened `ago_ms` ago, with
/// its first row written. `hint` records a name `pid` was given for the
/// address at a time in Unix epoch milliseconds.
fn flow_opened_ago(
    tracker: &FlowTracker<StoreFlowAdapter>,
    first: FlowKey,
    pid: u32,
    opened_at: u64,
) -> FlowKey {
    let mut key = first;
    key.remote_addr = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 90));
    key.local_port = first.local_port + 1;
    tracker.handle_event(&FlowEvent::Opened(
        key,
        FlowMeta {
            pid,
            process: Some(ProcessIdentity {
                executable: UPGRADE_PATH.to_owned(),
                name: "upgrade.exe".to_owned(),
                start_ts: 1,
            }),
            open_ts: opened_at,
            cookie: None,
            if_index: None,
        },
    ));
    tracker.handle_event(&FlowEvent::Bytes(
        key,
        ByteDelta {
            sent: 64,
            received: 128,
        },
    ));
    tracker.expire_unknown_grace_for_test(&key);
    tracker.flush_active_flows().expect("first write");
    key
}

fn hint_at(processor: &FlowProcessor, key: &FlowKey, pid: u32, query: &str, observed_at: u64) {
    processor.handle_event(&FlowEvent::DnsResolvedWithMetadata {
        attribution: DnsResolutionAttribution::Process(pid),
        query: query.to_owned(),
        answers: vec![key.remote_addr.to_string()],
        ttl_ms: 300_000,
        observed_at,
    });
}

fn domain_of(store: &Store, key: &FlowKey) -> String {
    let mut rows: Vec<_> = store
        .query_connection_logs(&antiwire_store::ConnectionLogQuery::default())
        .expect("query logs")
        .logs
        .into_iter()
        .filter(|log| log.dst_ip == key.remote_addr.to_string())
        .collect();
    assert_eq!(rows.len(), 1, "one connection must map to one row");
    rows.remove(0).dst_domain
}

/// The regression this guards: a flow is looked up within a tenth of a second
/// of opening, and a confirmed answer was final. A DNS-Client event can be
/// delivered a second after it was stamped, so a flow whose process already
/// held another name for the address kept that name, though the hint for the
/// name it had just asked for was stamped before it opened.
#[test]
fn a_hint_from_before_the_opening_that_arrives_late_corrects_a_confirmed_name() {
    let pid = 71_090;
    let (_dir, store, processor, tracker, first) = enriched_flow_setup(pid);
    let opened_at = netmetrics_core::unix_now_ms() - 300;
    let mut address = first;
    address.remote_addr = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 90));
    hint_at(
        &processor,
        &address,
        pid,
        "earlier.example",
        opened_at - 60_000,
    );
    let key = flow_opened_ago(&tracker, first, pid, opened_at);
    assert_eq!(
        domain_of(&store, &key),
        "earlier.example",
        "the only name known when the flow is first written"
    );

    hint_at(&processor, &key, pid, "just-asked.example", opened_at - 100);
    tracker.flush_active_flows().expect("flush");
    assert_eq!(domain_of(&store, &key), "just-asked.example (inferred)");
    let stats = processor.domain_lookup_stats();
    assert_eq!(
        (stats.corrected_open, stats.corrected_closed),
        ([0, 1, 0], [0, 0, 0])
    );

    // A name asked for after the flow opened says nothing about it.
    let lookups = processor.domain_lookup_stats().nearest_hint;
    hint_at(
        &processor,
        &key,
        pid,
        "asked-later.example",
        netmetrics_core::unix_now_ms(),
    );
    tracker.flush_active_flows().expect("flush");
    assert_eq!(domain_of(&store, &key), "just-asked.example (inferred)");
    assert_eq!(
        processor.domain_lookup_stats().nearest_hint,
        lookups + 1,
        "though while the name is provisional it is looked at"
    );
}

/// The same for a flow that closed before the hint arrived: no log follows
/// the one that closes a row, so the correction is written to the row itself.
#[test]
fn a_hint_from_before_the_opening_that_arrives_after_the_close_corrects_the_row() {
    let pid = 71_091;
    let (_dir, store, processor, tracker, first) = enriched_flow_setup(pid);
    let opened_at = netmetrics_core::unix_now_ms() - 300;
    let mut address = first;
    address.remote_addr = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 90));
    hint_at(
        &processor,
        &address,
        pid,
        "earlier.example",
        opened_at - 60_000,
    );
    let key = flow_opened_ago(&tracker, first, pid, opened_at);
    tracker.handle_event(&FlowEvent::Closed(
        key,
        FlowMeta {
            pid,
            process: None,
            open_ts: opened_at,
            cookie: None,
            if_index: None,
        },
    ));
    // The hint arrives before the log that closes the row has been written.
    // That log carries the name the flow closed with, so the correction has
    // to wait for it, or the log would put the old name back.
    hint_at(&processor, &key, pid, "just-asked.example", opened_at - 100);
    tracker.flush_active_flows().expect("flush");
    assert_eq!(domain_of(&store, &key), "earlier.example");
    tracker.flush().expect("flush the closed flow");
    assert_eq!(domain_of(&store, &key), "earlier.example");

    tracker.flush_active_flows().expect("flush");
    assert_eq!(domain_of(&store, &key), "just-asked.example (inferred)");
    let stats = processor.domain_lookup_stats();
    assert_eq!(stats.late_upgrades, 1);
    assert_eq!(
        (stats.corrected_open, stats.corrected_closed),
        ([0, 0, 0], [0, 1, 0])
    );
}

/// A flow opened ten seconds ago whose only name, `opened-with.example`, is
/// confirmed and past correcting, and a hint for `just-asked.example` stamped
/// before the opening. Recording that hint now dates it far too late; the
/// caller says when it really arrived. Returns the flow and when it opened.
fn settled_flow_and_a_hint_from_before_it_opened(
    pid: u32,
) -> (
    tempfile::TempDir,
    Arc<Store>,
    Arc<FlowProcessor>,
    FlowTracker<StoreFlowAdapter>,
    FlowKey,
    u64,
) {
    let (dir, store, processor, tracker, first) = enriched_flow_setup(pid);
    let opened_at = netmetrics_core::unix_now_ms() - 10_000;
    let mut address = first;
    address.remote_addr = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 90));
    hint_at(
        &processor,
        &address,
        pid,
        "opened-with.example",
        opened_at - 60_000,
    );
    let key = flow_opened_ago(&tracker, first, pid, opened_at);
    assert_eq!(domain_of(&store, &key), "opened-with.example");
    hint_at(&processor, &key, pid, "just-asked.example", opened_at - 100);
    (dir, store, processor, tracker, key, opened_at)
}

/// The regression this guards: evidence was dated when a flush noticed it,
/// not when it arrived. A hint that arrived just inside the time a name can
/// be corrected in, with the next flush just outside it, found the name
/// already final.
#[test]
fn evidence_that_arrived_in_time_corrects_a_name_however_late_the_flush() {
    let (_dir, store, processor, tracker, key, opened_at) =
        settled_flow_and_a_hint_from_before_it_opened(71_093);
    // The hint arrived three seconds after the opening, and no flush has
    // run since.
    processor.note_named_at([key.remote_addr], opened_at + 3_000);

    tracker.flush_active_flows().expect("flush");
    assert_eq!(domain_of(&store, &key), "just-asked.example (inferred)");
}

/// The same for a flow that closes before the next flush: nothing has told
/// it of the evidence yet, and no later flush will find it to tell.
#[test]
fn evidence_that_arrived_in_time_corrects_a_flow_that_closes_before_the_flush() {
    let pid = 71_094;
    let (_dir, store, processor, tracker, key, opened_at) =
        settled_flow_and_a_hint_from_before_it_opened(pid);
    processor.note_named_at([key.remote_addr], opened_at + 3_000);

    tracker.handle_event(&FlowEvent::Closed(
        key,
        FlowMeta {
            pid,
            process: None,
            open_ts: opened_at,
            cookie: None,
            if_index: None,
        },
    ));
    tracker.flush().expect("flush the closed flow");
    assert_eq!(domain_of(&store, &key), "just-asked.example (inferred)");
}

/// A confirmed name that every hint from the opening has had time to
/// contradict is final: what arrives later is not even looked at.
#[test]
fn a_confirmed_name_is_final_once_every_hint_from_the_opening_is_in() {
    let pid = 71_092;
    let (_dir, store, processor, tracker, first) = enriched_flow_setup(pid);
    let now_ms = netmetrics_core::unix_now_ms();
    let opened_at = now_ms - 10_000;
    let mut address = first;
    address.remote_addr = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 90));
    hint_at(
        &processor,
        &address,
        pid,
        "opened-with.example",
        opened_at - 1_000,
    );
    let key = flow_opened_ago(&tracker, first, pid, opened_at);
    assert_eq!(domain_of(&store, &key), "opened-with.example");

    let lookups = processor.domain_lookup_stats().process_hint;
    // Stamped before the opening, but far too late to be believed in time.
    hint_at(
        &processor,
        &key,
        pid,
        "stale-arrival.example",
        opened_at - 100,
    );
    hint_at(&processor, &key, pid, "asked-later.example", now_ms);
    for _ in 0..3 {
        tracker.flush_active_flows().expect("flush");
    }
    assert_eq!(domain_of(&store, &key), "opened-with.example");
    let stats = processor.domain_lookup_stats();
    assert_eq!(
        (stats.process_hint, stats.nearest_hint, stats.ambiguous),
        (lookups, 0, 0),
        "a final name is not looked up again"
    );
}

/// The regression this guards: a short connection closed before the ETW
/// hint naming it for its own process arrived, about a second later, so its
/// closed row kept an inferred name for good.
#[test]
fn a_late_hint_for_the_process_confirms_a_closed_row() {
    let (_dir, store, processor, tracker, key) = enriched_flow_setup(71_030);
    insert_dns_metadata(&processor, &key, 0, "late.example");
    tracker.handle_event(&FlowEvent::Closed(
        key,
        FlowMeta {
            pid: 71_030,
            process: None,
            open_ts: 1,
            cookie: None,
            if_index: None,
        },
    ));
    tracker.flush().expect("flush closed flow");
    assert_eq!(single_persisted_domain(&store), "late.example (inferred)");

    insert_dns_metadata(&processor, &key, 71_031, "other-process.example");
    tracker.flush_active_flows().expect("flush");
    assert_eq!(
        single_persisted_domain(&store),
        "late.example (inferred)",
        "another process's hint must not confirm the row"
    );

    insert_dns_metadata(&processor, &key, 71_030, "late.example");
    tracker.flush_active_flows().expect("flush");
    assert_eq!(single_persisted_domain(&store), "late.example");
    assert_eq!(processor.domain_lookup_stats().late_upgrades, 1);
}

fn domain_upgrade_blocking_engine() -> RuleEngine {
    let mut builder = antiwire_policy::BlocklistBuilder::new(10);
    builder.add_from_list("upgrade_test", "upgrade-blocked.example");
    let mut engine = RuleEngine::new();
    engine.publish_blocklist(builder.prepare().expect("prepare blocklist"));
    engine
}

#[test]
fn domain_upgrade_without_new_bytes_preserves_observed_allowed_action() {
    let (_dir, store, processor, tracker, key) = enriched_flow_setup_with_policy(
        71_017,
        domain_upgrade_blocking_engine(),
        TrafficStreamingHub::with_capacity(4),
    );
    insert_dns_metadata(&processor, &key, 0, "before-upgrade.example");
    tracker
        .flush_active_flows()
        .expect("persist inferred domain");

    insert_dns_metadata(&processor, &key, 71_017, "upgrade-blocked.example");
    tracker
        .flush_active_flows()
        .expect("upgrade without new bytes");

    let page = store
        .query_connection_logs(&antiwire_store::ConnectionLogQuery::default())
        .expect("query logs");
    assert_eq!(page.logs.len(), 1);
    let log = &page.logs[0];
    assert_eq!(log.dst_domain, "upgrade-blocked.example");
    assert_eq!(log.blocklist_names, "upgrade_test");
    assert_eq!((log.bytes_sent, log.bytes_received), (64, 128));
    assert_eq!(
        log.action_taken, "ALLOWED",
        "observed transferred bytes survive metadata-only updates"
    );
}

#[tokio::test]
async fn close_after_flushed_bytes_publishes_observed_allowed_action() {
    let traffic_hub = TrafficStreamingHub::with_capacity(4);
    let (_dir, _store, processor, tracker, key) = enriched_flow_setup_with_policy(
        71_018,
        domain_upgrade_blocking_engine(),
        traffic_hub.clone(),
    );
    insert_dns_metadata(&processor, &key, 71_018, "upgrade-blocked.example");
    let mut subscription = traffic_hub.subscribe();
    tracker.handle_event(&FlowEvent::Closed(
        key,
        FlowMeta {
            pid: 71_018,
            process: None,
            open_ts: 1,
            cookie: None,
            if_index: None,
        },
    ));
    tracker.flush().expect("flush closed flow");

    let event = tokio::time::timeout(Duration::from_secs(1), subscription.recv())
        .await
        .expect("close publication timeout")
        .expect("close event");
    assert_eq!(
        event.action, "ALLOWED",
        "closing after a byte flush must not imply blocking"
    );
    assert_eq!((event.bytes_sent, event.bytes_received), (64, 128));
}

#[test]
fn inferred_domain_is_replaced_by_a_different_confirmed_domain() {
    let (_dir, store, processor, tracker, key) = enriched_flow_setup(71_011);
    insert_dns_metadata(&processor, &key, 0, "first.example");
    tracker.flush_active_flows().expect("persist inferred");

    insert_dns_metadata(&processor, &key, 71_011, "second.example");
    tracker.flush_active_flows().expect("replace inferred");

    assert_eq!(single_persisted_domain(&store), "second.example");
    assert_eq!(processor.domain_upgrade_count(), 1);
}

#[test]
fn shared_evidence_never_upgrades_an_inferred_domain() {
    let (_dir, store, processor, tracker, key) = enriched_flow_setup(71_012);
    insert_dns_metadata(&processor, &key, 0, "shared.example");
    tracker.flush_active_flows().expect("persist inferred");

    // Another shared answer, even for a different name, is the same tier.
    insert_dns_metadata(&processor, &key, 0, "other.example");
    tracker.flush_active_flows().expect("zero-byte tick");

    assert_eq!(single_persisted_domain(&store), "shared.example (inferred)");
    assert_eq!(processor.domain_upgrade_count(), 0);
}

#[test]
fn evidence_for_another_pid_never_upgrades_an_inferred_domain() {
    let (_dir, store, processor, tracker, key) = enriched_flow_setup(71_013);
    insert_dns_metadata(&processor, &key, 0, "shared.example");
    tracker.flush_active_flows().expect("persist inferred");

    insert_dns_metadata(&processor, &key, 999_999, "process.example");
    tracker.flush_active_flows().expect("zero-byte tick");

    assert_eq!(single_persisted_domain(&store), "shared.example (inferred)");
    assert_eq!(processor.domain_upgrade_count(), 0);
}

#[test]
fn an_existing_confirmed_domain_remains_stable() {
    let (_dir, store, processor, tracker, key) = enriched_flow_setup(71_014);
    insert_dns_metadata(&processor, &key, 71_014, "stable.example");
    tracker.flush_active_flows().expect("persist confirmed");
    assert_eq!(single_persisted_domain(&store), "stable.example");

    insert_dns_metadata(&processor, &key, 0, "later.example");
    tracker.flush_active_flows().expect("zero-byte tick");

    assert_eq!(single_persisted_domain(&store), "stable.example");
    assert_eq!(processor.domain_upgrade_count(), 0);
}

#[test]
fn repeated_identical_evidence_produces_no_extra_write() {
    let dir = tempdir().expect("tempdir");
    let keystore = UnixSecureFileKeyProvider::new(dir.path().join("key"));
    let store =
        Arc::new(Store::open_with_keystore(dir.path().join("db.sqlite"), &keystore).expect("open"));
    let processor = Arc::new(test_processor(
        Arc::clone(&store),
        TrafficStreamingHub::with_capacity(4),
    ));
    let writes = Arc::new(AtomicUsize::new(0));
    let real = Arc::clone(&store);
    let counter = Arc::clone(&writes);
    let tracker = FlowTracker::with_processor(
        move |logs: &[NewConnectionLog]| {
            counter.fetch_add(1, Ordering::SeqCst);
            real.insert_connection_logs(logs).map_err(Into::into)
        },
        Some(Arc::clone(&processor)),
    );
    let key = sample_key();
    tracker.handle_event(&FlowEvent::Opened(
        key,
        FlowMeta {
            pid: 71_015,
            process: Some(ProcessIdentity {
                executable: UPGRADE_PATH.to_owned(),
                name: "upgrade.exe".to_owned(),
                start_ts: 1,
            }),
            open_ts: 1,
            cookie: None,
            if_index: None,
        },
    ));
    tracker.handle_event(&FlowEvent::Bytes(
        key,
        ByteDelta {
            sent: 64,
            received: 128,
        },
    ));
    insert_dns_metadata(&processor, &key, 0, "repeat.example");
    tracker.flush_active_flows().expect("persist inferred");
    assert_eq!(writes.load(Ordering::SeqCst), 1);
    assert_eq!(single_persisted_domain(&store), "repeat.example (inferred)");

    insert_dns_metadata(&processor, &key, 0, "repeat.example");
    tracker.flush_active_flows().expect("zero-byte tick");

    assert_eq!(
        writes.load(Ordering::SeqCst),
        1,
        "identical evidence must not rewrite the row"
    );
    assert_eq!(processor.domain_upgrade_count(), 0);
}

/// A completion that arrived before its request is upgraded once the
/// matching request supplies the caller, and that recovered caller must be
/// able to correct an already-persisted inferred domain.
#[test]
fn recovered_process_caller_triggers_persisted_domain_upgrade() {
    let (_dir, store, processor, tracker, key) = enriched_flow_setup(71_016);
    insert_dns_metadata(&processor, &key, 0, "recovered.example");
    tracker.flush_active_flows().expect("persist inferred");
    assert_eq!(
        single_persisted_domain(&store),
        "recovered.example (inferred)"
    );

    let now_ms =
        u64::try_from((OffsetDateTime::now_utc().unix_timestamp_nanos() / 1_000_000).max(0))
            .unwrap_or(0);
    let activity = Some([9_u8; 16]);
    let mut recovery = DnsCallerRecovery::default();
    let shared = recovery.observe(DnsCallerObservation {
        kind: DnsEventKind::Completion,
        event_id: 3018,
        event_version: 2,
        name: "recovered.example".to_owned(),
        query_type: 1,
        status: 0,
        caller: DnsCallerIdentity {
            logging_pid: Some(1000),
            requesting_pid: None,
            resolver_pid: None,
        },
        correlation: DnsCorrelationId {
            activity_id: activity,
            query_blob: None,
        },
        answers: vec![key.remote_addr],
        ttl_ms: Some(60_000),
        timestamp: now_ms,
    });
    assert_eq!(shared.len(), 1, "the response is published as shared first");

    let recovered = recovery
        .observe(DnsCallerObservation {
            kind: DnsEventKind::Request,
            event_id: 3006,
            event_version: 0,
            name: "recovered.example".to_owned(),
            query_type: 1,
            status: 0,
            caller: DnsCallerIdentity {
                logging_pid: Some(1000),
                requesting_pid: Some(71_016),
                resolver_pid: None,
            },
            correlation: DnsCorrelationId {
                activity_id: activity,
                query_blob: None,
            },
            answers: Vec::new(),
            ttl_ms: None,
            timestamp: now_ms.saturating_add(1),
        })
        .into_iter()
        .find(|resolution| resolution.pid == 71_016)
        .expect("the request recovers the caller");

    processor.handle_event(&FlowEvent::DnsResolvedWithMetadata {
        attribution: DnsResolutionAttribution::Process(recovered.pid),
        query: recovered.query.clone(),
        answers: recovered.answers.iter().map(ToString::to_string).collect(),
        ttl_ms: recovered.ttl_ms,
        observed_at: recovered.observed_at,
    });
    tracker
        .flush_active_flows()
        .expect("upgrade the persisted domain");

    assert_eq!(single_persisted_domain(&store), "recovered.example");
    assert_eq!(processor.domain_upgrade_count(), 1);
}

#[test]
fn batches_closed_flow_writes() {
    let writes = Arc::new(StdMutex::new(Vec::new()));
    let writes_clone = Arc::clone(&writes);
    let store = move |logs: &[NewConnectionLog]| {
        writes_clone.lock().expect("lock").extend_from_slice(logs);
        Ok(())
    };

    let tracker = FlowTracker::new(store);
    let key = sample_key();
    let meta = FlowMeta {
        pid: 100,
        process: None,
        open_ts: 0,
        cookie: None,
        if_index: None,
    };

    tracker.handle_event(&FlowEvent::Opened(key, meta.clone()));
    tracker.handle_event(&FlowEvent::Bytes(
        key,
        ByteDelta {
            sent: 200,
            received: 50,
        },
    ));
    tracker.handle_event(&FlowEvent::Closed(key, meta));
    tracker.flush().expect("flush");

    let batch = writes.lock().expect("lock");
    assert_eq!(batch.len(), 1);
    assert_eq!(batch[0].bytes_sent, 200);
    assert_eq!(batch[0].bytes_received, 50);
    assert_eq!(batch[0].dst_port, 443);
}

#[test]
fn active_count_tracks_open_and_closed_flows() {
    let tracker = FlowTracker::new(|_: &[NewConnectionLog]| Ok(()));
    let key_a = sample_key();
    let key_b = FlowKey {
        local_port: 50_001,
        ..sample_key()
    };
    let meta = FlowMeta {
        pid: 100,
        process: None,
        open_ts: 0,
        cookie: None,
        if_index: None,
    };

    assert_eq!(tracker.tracked_flow_count(), 0);

    tracker.handle_event(&FlowEvent::Opened(key_a, meta.clone()));
    tracker.handle_event(&FlowEvent::Opened(key_b, meta.clone()));
    assert_eq!(tracker.tracked_flow_count(), 2);

    tracker.handle_event(&FlowEvent::Closed(key_a, meta.clone()));
    assert_eq!(tracker.tracked_flow_count(), 1);

    tracker.handle_event(&FlowEvent::Closed(key_b, meta));
    assert_eq!(tracker.tracked_flow_count(), 0);
}

#[test]
fn active_application_count_counts_distinct_owned_apps() {
    let (_dir, store) = system_test_store();
    let tracker = system_tracker(&store);
    let (vpn_path, vpn_name) = user_app();
    let owned = |pid: u32| FlowMeta {
        pid,
        process: Some(ProcessIdentity {
            executable: vpn_path.to_owned(),
            name: vpn_name.to_owned(),
            start_ts: 0,
        }),
        open_ts: 0,
        cookie: None,
        if_index: None,
    };
    let key = |port: u16| FlowKey {
        local_port: port,
        ..sample_key()
    };

    assert_eq!(tracker.active_application_count(), 0);

    // Two connections from one application count once.
    tracker.handle_event(&FlowEvent::Opened(key(50_010), owned(459_401)));
    tracker.handle_event(&FlowEvent::Opened(key(50_011), owned(459_401)));
    assert_eq!(tracker.tracked_flow_count(), 2);
    assert_eq!(tracker.active_application_count(), 1);

    // A flow with no owner evidence is not an application.
    tracker.handle_event(&FlowEvent::Opened(key(50_012), ownerless_meta()));
    assert_eq!(tracker.active_application_count(), 1);

    tracker.handle_event(&FlowEvent::Closed(key(50_010), owned(459_401)));
    assert_eq!(tracker.active_application_count(), 1);
    tracker.handle_event(&FlowEvent::Closed(key(50_011), owned(459_401)));
    assert_eq!(tracker.active_application_count(), 0);
}

#[test]
fn active_applications_group_live_flows_and_keep_closed_bytes() {
    let (_dir, store) = system_test_store();
    let tracker = system_tracker(&store);
    let (vpn_path, vpn_name) = user_app();
    let owned = |pid: u32| FlowMeta {
        pid,
        process: Some(ProcessIdentity {
            executable: vpn_path.to_owned(),
            name: vpn_name.to_owned(),
            start_ts: 0,
        }),
        open_ts: 0,
        cookie: None,
        if_index: None,
    };
    let key = |port: u16| FlowKey {
        local_port: port,
        ..sample_key()
    };
    let bytes = |sent: u64, received: u64| ByteDelta { sent, received };

    assert_eq!(tracker.active_applications(), []);

    tracker.handle_event(&FlowEvent::Opened(key(50_020), owned(459_402)));
    tracker.handle_event(&FlowEvent::Opened(key(50_021), owned(459_402)));
    tracker.handle_event(&FlowEvent::Opened(key(50_022), ownerless_meta()));
    tracker.handle_event(&FlowEvent::Bytes(key(50_020), bytes(100, 1_000)));
    tracker.handle_event(&FlowEvent::Bytes(key(50_021), bytes(10, 20)));

    let apps = tracker.active_applications();
    assert_eq!(apps.len(), 1, "the ownerless flow is not an application");
    let app = &apps[0];
    assert_eq!(app.connection_count, 2);
    assert_eq!((app.total_sent, app.total_received), (110, 1_020));
    // Both flows share one destination IP until a domain is known.
    assert_eq!(app.destination_count, 1);
    assert_eq!(
        app.top_destinations,
        vec![sample_key().remote_addr.to_string()]
    );

    // Closing a connection keeps its bytes in the running total.
    tracker.handle_event(&FlowEvent::Closed(key(50_020), owned(459_402)));
    let apps = tracker.active_applications();
    assert_eq!(apps[0].connection_count, 1);
    assert_eq!((apps[0].total_sent, apps[0].total_received), (110, 1_020));

    tracker.handle_event(&FlowEvent::Closed(key(50_021), owned(459_402)));
    assert_eq!(tracker.active_applications(), []);
}

/// A connection that is no longer established is not one of its application's
/// connections any more, but stays the application's until it closes: what it
/// still receives is the application's, and its row is written once.
#[test]
fn a_finishing_flow_is_not_counted_and_keeps_its_bytes() {
    let (_dir, store) = system_test_store();
    let tracker = system_tracker(&store);
    let (vpn_path, vpn_name) = user_app();
    let owned = FlowMeta {
        pid: 459_403,
        process: Some(ProcessIdentity {
            executable: vpn_path.to_owned(),
            name: vpn_name.to_owned(),
            start_ts: 0,
        }),
        open_ts: 0,
        cookie: None,
        if_index: None,
    };
    let key = |port: u16| FlowKey {
        local_port: port,
        ..sample_key()
    };
    let received = |received: u64| ByteDelta { sent: 0, received };

    tracker.handle_event(&FlowEvent::Opened(key(50_030), owned.clone()));
    tracker.handle_event(&FlowEvent::Opened(key(50_031), owned.clone()));
    tracker.handle_event(&FlowEvent::Bytes(key(50_030), received(100)));
    assert_eq!(tracker.active_applications()[0].connection_count, 2);

    tracker.handle_event(&FlowEvent::Finishing(key(50_030)));
    tracker.handle_event(&FlowEvent::Bytes(key(50_030), received(900)));
    let apps = tracker.active_applications();
    assert_eq!(apps[0].connection_count, 1);
    assert_eq!(apps[0].total_received, 1_000);
    assert_eq!(
        tracker.active.lock().len(),
        2,
        "no flow was opened for the bytes"
    );

    // A later update of the flow's owner does not make it a connection again.
    tracker.handle_event(&FlowEvent::Opened(key(50_030), owned.clone()));
    assert_eq!(tracker.active_applications()[0].connection_count, 1);

    tracker.handle_event(&FlowEvent::Closed(key(50_031), owned.clone()));
    let apps = tracker.active_applications();
    assert_eq!(apps.len(), 1, "the application is still receiving");
    assert_eq!(apps[0].connection_count, 0);

    tracker.handle_event(&FlowEvent::Closed(key(50_030), owned));
    assert_eq!(tracker.active_applications(), []);
}

#[test]
fn application_identity_skips_unattributed_owners() {
    let (vpn_path, vpn_name) = user_app();
    assert!(application_identity(vpn_path, vpn_name).is_some());
    assert_eq!(application_identity("", "vpn.exe"), None);
    assert_eq!(application_identity("  ", "vpn.exe"), None);
    assert_eq!(
        application_identity(
            vpn_path,
            &crate::process_resolver::UNKNOWN_APP_NAME.to_uppercase()
        ),
        None
    );
}

#[test]
fn application_flows_return_only_the_named_application() {
    let (_dir, store) = system_test_store();
    let tracker = system_tracker(&store);
    let (vpn_path, vpn_name) = user_app();
    let owned = |path: &str, name: &str, pid: u32| FlowMeta {
        pid,
        process: Some(ProcessIdentity {
            executable: path.to_owned(),
            name: name.to_owned(),
            start_ts: 0,
        }),
        open_ts: 0,
        cookie: None,
        if_index: None,
    };
    let key = |port: u16| FlowKey {
        local_port: port,
        ..sample_key()
    };

    assert_eq!(tracker.application_flows(vpn_path), []);

    tracker.handle_event(&FlowEvent::Opened(
        key(50_030),
        owned(vpn_path, vpn_name, 459_403),
    ));
    tracker.handle_event(&FlowEvent::Opened(
        key(50_031),
        owned(vpn_path, vpn_name, 459_403),
    ));
    tracker.handle_event(&FlowEvent::Opened(
        key(50_032),
        owned("/opt/antiwire-tests/apps/other.exe", "other.exe", 459_404),
    ));
    tracker.handle_event(&FlowEvent::Opened(key(50_033), ownerless_meta()));

    let mut ports: Vec<u16> = tracker
        .application_flows(vpn_path)
        .iter()
        .map(|flow| flow.local_port)
        .collect();
    ports.sort_unstable();
    assert_eq!(ports, vec![50_030, 50_031]);

    let other_case = vpn_path.to_ascii_uppercase();
    assert_eq!(
        tracker.application_flows(&other_case).len() == 2,
        cfg!(windows),
        "paths compare case-insensitively on Windows only"
    );
    assert_eq!(tracker.application_flows(""), [] as [FlowKey; 0]);
    assert_eq!(tracker.application_flows("  "), [] as [FlowKey; 0]);
}

#[test]
fn inferred_flow_persists_as_unknown_no_owner_not_app_id_zero() {
    let writes = Arc::new(StdMutex::new(Vec::new()));
    let writes_clone = Arc::clone(&writes);
    let dir = tempdir().expect("tempdir");
    let keystore = UnixSecureFileKeyProvider::new(dir.path().join("key"));
    let store =
        Arc::new(Store::open_with_keystore(dir.path().join("db.sqlite"), &keystore).expect("open"));

    let traffic_hub = TrafficStreamingHub::with_capacity(4);
    let processor = Arc::new(test_processor(store.clone(), traffic_hub));
    let unknown_app_id = processor.unknown_no_owner().0;
    assert!(unknown_app_id > 0);

    let tracker = FlowTracker::with_processor(
        move |logs: &[NewConnectionLog]| {
            writes_clone.lock().expect("lock").extend_from_slice(logs);
            Ok(())
        },
        Some(processor),
    );

    let key = sample_key();
    tracker.handle_event(&FlowEvent::Bytes(
        key,
        ByteDelta {
            sent: 400,
            received: 800,
        },
    ));
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
    tracker.flush().expect("flush");

    let batch = writes.lock().expect("lock");
    assert_eq!(batch.len(), 1);
    assert_eq!(batch[0].app_id, unknown_app_id);
    assert_eq!(batch[0].bytes_sent, 400);
    assert_eq!(batch[0].bytes_received, 800);
    assert_eq!(batch[0].src_ip, key.local_addr.to_string());
    assert_eq!(batch[0].src_port, i32::from(key.local_port));
    assert_eq!(batch[0].dst_ip, key.remote_addr.to_string());
    assert_eq!(batch[0].dst_port, i32::from(key.remote_port));
    assert_eq!(batch[0].protocol, "TCP");
    assert_eq!(batch[0].action_taken, "ALLOWED");
}

#[test]
fn unattributed_flow_still_surfaces_as_unknown_in_persisted_logs() {
    let dir = tempdir().expect("tempdir");
    let keystore = UnixSecureFileKeyProvider::new(dir.path().join("key"));
    let store =
        Arc::new(Store::open_with_keystore(dir.path().join("db.sqlite"), &keystore).expect("open"));
    let traffic_hub = TrafficStreamingHub::with_capacity(4);
    let processor = Arc::new(test_processor(Arc::clone(&store), traffic_hub));
    let unknown = processor.unknown_no_owner();
    let tracker =
        FlowTracker::with_processor(StoreFlowAdapter::new(Arc::clone(&store)), Some(processor));

    // Port 443: no system signature matches, so this stays the unknown path.
    // (An ownerless port-53 flow now folds to System; see the system tests below.)
    let key = FlowKey {
        protocol: Protocol::Tcp,
        local_addr: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
        local_port: 52_946,
        remote_addr: IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9)),
        remote_port: 443,
    };
    tracker.handle_event(&FlowEvent::Bytes(
        key,
        ByteDelta {
            sent: 80,
            received: 240,
        },
    ));
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
    tracker.flush().expect("flush");

    let page = store
        .query_connection_logs(&antiwire_store::ConnectionLogQuery::default())
        .expect("query logs");
    assert_eq!(page.logs.len(), 1, "the flow must still be persisted");
    assert_eq!(page.logs[0].app_id, unknown.0);
    assert_eq!(page.logs[0].src_ip, "192.0.2.10");
    assert_eq!(page.logs[0].src_port, 52_946);
    assert_eq!(page.logs[0].dst_ip, "9.9.9.9");
    assert_eq!(page.logs[0].dst_port, 443);
    assert_eq!(page.logs[0].bytes_sent, 80);
    assert_eq!(page.logs[0].bytes_received, 240);

    let summaries = store
        .query_application_log_summaries(&antiwire_store::ApplicationLogSummaryQuery::default())
        .expect("query summaries");
    assert!(
        summaries.iter().any(|row| {
            row.app_id == unknown.0
                && row.app_name.eq_ignore_ascii_case(crate::process_resolver::UNKNOWN_APP_NAME)
                && row.app_path == "Unknown (No Owner)"
                && row.connection_count == 1
        }),
        "the unknown application / Unknown (No Owner) must remain a visible application row: {summaries:?}"
    );
}

#[test]
fn outbound_resolver_flow_does_not_take_a_loopback_dns_listener() {
    let tracker = FlowTracker::new(|_: &[NewConnectionLog]| Ok(()));
    let key = FlowKey {
        protocol: Protocol::Tcp,
        local_addr: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
        local_port: 52_946,
        remote_addr: IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9)),
        remote_port: 53,
    };
    tracker.handle_event(&FlowEvent::Bytes(
        key,
        ByteDelta {
            sent: 80,
            received: 240,
        },
    ));
    tracker.expire_unknown_grace_for_test(&key);
    let mut snapshot = SocketOwnerSnapshot::default();
    snapshot.insert_tcp_listener(
        netmetrics_core::LocalEndpoint {
            address: IpAddr::V4(Ipv4Addr::LOCALHOST),
            port: 53,
        },
        7,
    );
    let mut active = tracker.active.lock();
    let flow = active.get_mut(&key).unwrap();
    tracker.maybe_attempt_socket_attribution(flow, &key, &snapshot, true);
    assert_eq!(
        flow.pid, 0,
        "a loopback DNS listener must not claim outbound resolver traffic"
    );
    assert_eq!(flow.src_ip, "192.0.2.10");
    assert_eq!(flow.dst_ip, "9.9.9.9");
    assert_eq!(flow.dst_port, 53);
}

#[test]
fn late_pid_attribution_moves_already_persisted_unknown_row() {
    let dir = tempdir().expect("tempdir");
    let keystore = UnixSecureFileKeyProvider::new(dir.path().join("key"));
    let store =
        Arc::new(Store::open_with_keystore(dir.path().join("db.sqlite"), &keystore).expect("open"));
    let traffic_hub = TrafficStreamingHub::with_capacity(4);
    let processor = Arc::new(test_processor(Arc::clone(&store), traffic_hub.clone()));
    let unknown_app_id = processor.unknown_no_owner().0;
    let tracker = FlowTracker::with_processor(
        StoreFlowAdapter::new(Arc::clone(&store)),
        Some(Arc::clone(&processor)),
    );
    let key = sample_key();
    tracker.handle_event(&FlowEvent::Bytes(
        key,
        ByteDelta {
            sent: 400,
            received: 800,
        },
    ));
    tracker.expire_unknown_grace_for_test(&key);
    tracker
        .flush_active_flows()
        .expect("persist provisional row");

    let provisional = store
        .query_connection_logs(&antiwire_store::ConnectionLogQuery::default())
        .expect("query provisional");
    assert_eq!(provisional.logs.len(), 1);
    assert_eq!(provisional.logs[0].app_id, unknown_app_id);

    tracker.handle_event(&FlowEvent::Opened(
        key,
        FlowMeta {
            pid: 71_001,
            process: Some(ProcessIdentity {
                executable: BROWSER_PATH.to_owned(),
                name: "browser.exe".to_owned(),
                start_ts: 1,
            }),
            open_ts: 1,
            cookie: None,
            if_index: None,
        },
    ));
    tracker
        .flush_active_flows()
        .expect("apply late attribution");

    let resolved_app_id = store
        .find_application_by_name("browser.exe")
        .expect("find application")
        .expect("resolved application")
        .id;
    let resolved = store
        .query_connection_logs(&antiwire_store::ConnectionLogQuery::default())
        .expect("query resolved");
    assert_eq!(resolved.logs.len(), 1);
    assert_eq!(resolved.logs[0].app_id, resolved_app_id);
    assert_eq!(resolved.logs[0].bytes_sent, 400);
    assert_eq!(resolved.logs[0].bytes_received, 800);
    assert_ne!(resolved.logs[0].app_id, unknown_app_id);
}

/// A reopened tuple is a new connection even though every flow-tuple field
/// matches: the second session must start its own row rather than
/// accumulating onto the first connection's totals.
#[test]
fn reopened_tuple_starts_a_new_connection_row() {
    let dir = tempdir().expect("tempdir");
    let keystore = UnixSecureFileKeyProvider::new(dir.path().join("key"));
    let store =
        Arc::new(Store::open_with_keystore(dir.path().join("db.sqlite"), &keystore).expect("open"));
    let tracker = FlowTracker::new(StoreFlowAdapter::new(Arc::clone(&store)));
    let key = sample_key();
    let meta = FlowMeta {
        pid: 100,
        process: None,
        open_ts: 0,
        cookie: None,
        if_index: None,
    };

    tracker.handle_event(&FlowEvent::Opened(key, meta.clone()));
    tracker.handle_event(&FlowEvent::Bytes(
        key,
        ByteDelta {
            sent: 10,
            received: 20,
        },
    ));
    tracker.handle_event(&FlowEvent::Closed(key, meta.clone()));
    tracker.flush().expect("flush first connection");

    tracker.handle_event(&FlowEvent::Opened(key, meta.clone()));
    tracker.handle_event(&FlowEvent::Bytes(
        key,
        ByteDelta {
            sent: 30,
            received: 40,
        },
    ));
    tracker.handle_event(&FlowEvent::Closed(key, meta));
    tracker.flush().expect("flush second connection");

    let page = store
        .query_connection_logs(&antiwire_store::ConnectionLogQuery::default())
        .expect("query logs");
    assert_eq!(page.logs.len(), 2);
    let mut by_conn: Vec<(i64, i64, i64)> = page
        .logs
        .iter()
        .map(|log| (log.conn_id, log.bytes_sent, log.bytes_received))
        .collect();
    by_conn.sort_unstable();
    assert_ne!(by_conn[0].0, by_conn[1].0, "sessions must differ");
    assert_ne!(by_conn[0].0, 0, "sessions are never unattributed");
    assert_eq!((by_conn[0].1, by_conn[0].2), (10, 20));
    assert_eq!((by_conn[1].1, by_conn[1].2), (30, 40));
}

/// Closing a fully flushed flow still records its end in the store: one
/// row, lifetime totals, and a close time.
#[test]
fn close_of_fully_flushed_flow_records_close_in_store() {
    let dir = tempdir().expect("tempdir");
    let keystore = UnixSecureFileKeyProvider::new(dir.path().join("key"));
    let store =
        Arc::new(Store::open_with_keystore(dir.path().join("db.sqlite"), &keystore).expect("open"));
    let tracker = FlowTracker::new(StoreFlowAdapter::new(Arc::clone(&store)));
    let key = sample_key();
    let meta = FlowMeta {
        pid: 100,
        process: None,
        open_ts: 0,
        cookie: None,
        if_index: None,
    };

    tracker.handle_event(&FlowEvent::Opened(key, meta.clone()));
    tracker.handle_event(&FlowEvent::Bytes(
        key,
        ByteDelta {
            sent: 100,
            received: 200,
        },
    ));
    tracker.flush_active_flows().expect("flush bytes");
    tracker.handle_event(&FlowEvent::Closed(key, meta));
    tracker.flush().expect("flush close");

    let page = store
        .query_connection_logs(&antiwire_store::ConnectionLogQuery::default())
        .expect("query logs");
    assert_eq!(page.logs.len(), 1);
    assert_eq!(page.logs[0].bytes_sent, 100);
    assert_eq!(page.logs[0].bytes_received, 200);
    assert!(
        page.logs[0].closed_at.is_some(),
        "the close must be recorded even with an empty final delta"
    );
}

#[test]
fn reresolves_unknown_app_at_flow_close() {
    let writes = Arc::new(StdMutex::new(Vec::new()));
    let writes_clone = Arc::clone(&writes);
    let dir = tempdir().expect("tempdir");
    let keystore = UnixSecureFileKeyProvider::new(dir.path().join("key"));
    let store =
        Arc::new(Store::open_with_keystore(dir.path().join("db.sqlite"), &keystore).expect("open"));

    let traffic_hub = TrafficStreamingHub::with_capacity(4);
    let processor = Arc::new(test_processor(store, traffic_hub));
    let tracker = FlowTracker::with_processor(
        move |logs: &[NewConnectionLog]| {
            writes_clone.lock().expect("lock").extend_from_slice(logs);
            Ok(())
        },
        Some(processor),
    );

    let key = sample_key();
    let open_meta = FlowMeta {
        pid: 71_002,
        process: None,
        open_ts: 0,
        cookie: None,
        if_index: None,
    };
    let close_meta = FlowMeta {
        pid: 71_002,
        process: Some(ProcessIdentity {
            executable: r"C:\Windows\System32\curl.exe".to_owned(),
            name: "curl.exe".to_owned(),
            start_ts: 0,
        }),
        open_ts: 0,
        cookie: None,
        if_index: None,
    };

    tracker.handle_event(&FlowEvent::Opened(key, open_meta));
    tracker.handle_event(&FlowEvent::Closed(key, close_meta));
    tracker.flush().expect("flush");

    let batch = writes.lock().expect("lock");
    assert_eq!(batch.len(), 1);
    assert!(batch[0].app_id > 0);
}

/// Opens a flow whose backend supplied only a bare executable name: the
/// Elevated-process placeholder, with `start_ts` as its creation evidence
/// (zero for none).
fn open_placeholder_flow(
    tracker: &FlowTracker<impl crate::store::FlowStore>,
    key: FlowKey,
    pid: u32,
    name: &str,
    start_ts: u64,
) {
    tracker.handle_event(&FlowEvent::Opened(
        key,
        FlowMeta {
            pid,
            process: Some(ProcessIdentity {
                executable: name.to_owned(),
                name: name.to_owned(),
                start_ts,
            }),
            open_ts: 0,
            cookie: None,
            if_index: None,
        },
    ));
}

fn process_started_event(pid: u32, executable: &str, name: &str, start_ts: u64) -> FlowEvent {
    FlowEvent::ProcessStarted(ProcessInfo {
        pid,
        identity: ProcessIdentity {
            executable: executable.to_owned(),
            name: name.to_owned(),
            start_ts,
        },
    })
}

#[test]
fn placeholder_flow_upgrades_on_same_instance_process_start() {
    let dir = tempdir().expect("tempdir");
    let keystore = UnixSecureFileKeyProvider::new(dir.path().join("key"));
    let store =
        Arc::new(Store::open_with_keystore(dir.path().join("db.sqlite"), &keystore).expect("open"));
    let traffic_hub = TrafficStreamingHub::with_capacity(4);
    let processor = Arc::new(test_processor(Arc::clone(&store), traffic_hub.clone()));
    let tracker =
        FlowTracker::with_processor(StoreFlowAdapter::new(Arc::clone(&store)), Some(processor));

    let pid = 451_001;
    let key = sample_key();
    open_placeholder_flow(&tracker, key, pid, "same-instance.exe", 777_000);
    let (_, path, _) = tracker.flow_identity_for_test(&key).expect("flow");
    assert_eq!(path, "Path unavailable");
    let before = tracker.identity_recovery_stats();

    // The same instance later resolves with a real path: PID plus
    // creation time match, so the flow is reattributed.
    tracker.processes_for_test().process_started(
        pid,
        r"C:\apps\same-instance.exe",
        "same-instance.exe",
        777_000,
    );
    tracker.handle_event(&process_started_event(
        pid,
        r"C:\apps\same-instance.exe",
        "same-instance.exe",
        777_000,
    ));

    let (_, path, name) = tracker.flow_identity_for_test(&key).expect("flow");
    assert_eq!(path, r"C:\apps\same-instance.exe");
    assert_eq!(name, "same-instance.exe");
    let after = tracker.identity_recovery_stats();
    assert_eq!(after.recoveries - before.recoveries, 1);
    assert!(after.attempts > before.attempts);
}

#[test]
fn placeholder_flow_without_creation_time_never_upgrades_on_name_alone() {
    let dir = tempdir().expect("tempdir");
    let keystore = UnixSecureFileKeyProvider::new(dir.path().join("key"));
    let store =
        Arc::new(Store::open_with_keystore(dir.path().join("db.sqlite"), &keystore).expect("open"));
    let traffic_hub = TrafficStreamingHub::with_capacity(4);
    let processor = Arc::new(test_processor(Arc::clone(&store), traffic_hub.clone()));
    let tracker =
        FlowTracker::with_processor(StoreFlowAdapter::new(Arc::clone(&store)), Some(processor));

    let pid = 451_002;
    let key = sample_key();
    open_placeholder_flow(&tracker, key, pid, "nameless-proof.exe", 0);
    let before = tracker.identity_recovery_stats();

    // A real path is known for this PID, but nothing ties it to the
    // flow's instance: no creation time on either side.
    tracker.processes_for_test().process_started(
        pid,
        r"C:\apps\nameless-proof.exe",
        "nameless-proof.exe",
        0,
    );
    tracker.handle_event(&process_started_event(
        pid,
        r"C:\apps\nameless-proof.exe",
        "nameless-proof.exe",
        0,
    ));

    let (_, path, _) = tracker.flow_identity_for_test(&key).expect("flow");
    assert_eq!(path, "Path unavailable");
    let after = tracker.identity_recovery_stats();
    assert_eq!(after.recoveries - before.recoveries, 0);
}

#[test]
fn recycled_pid_process_start_never_upgrades_placeholder_flow() {
    let dir = tempdir().expect("tempdir");
    let keystore = UnixSecureFileKeyProvider::new(dir.path().join("key"));
    let store =
        Arc::new(Store::open_with_keystore(dir.path().join("db.sqlite"), &keystore).expect("open"));
    let traffic_hub = TrafficStreamingHub::with_capacity(4);
    let processor = Arc::new(test_processor(Arc::clone(&store), traffic_hub.clone()));
    let tracker =
        FlowTracker::with_processor(StoreFlowAdapter::new(Arc::clone(&store)), Some(processor));

    let pid = 451_003;
    let key = sample_key();
    open_placeholder_flow(&tracker, key, pid, "recycled.exe", 111_000);
    let before = tracker.identity_recovery_stats();

    // A lifecycle event for the same PID but a different creation time
    // proves recycling: the new occupant must not rename the old flow.
    tracker.processes_for_test().process_started(
        pid,
        r"C:\apps\impostor.exe",
        "impostor.exe",
        222_000,
    );
    tracker.handle_event(&process_started_event(
        pid,
        r"C:\apps\impostor.exe",
        "impostor.exe",
        222_000,
    ));

    let (_, path, name) = tracker.flow_identity_for_test(&key).expect("flow");
    assert_eq!(path, "Path unavailable");
    assert_eq!(name, "recycled.exe");
    let after = tracker.identity_recovery_stats();
    assert_eq!(after.recoveries - before.recoveries, 0);
}

#[test]
fn identity_recovery_retries_are_bounded() {
    let dir = tempdir().expect("tempdir");
    let keystore = UnixSecureFileKeyProvider::new(dir.path().join("key"));
    let store =
        Arc::new(Store::open_with_keystore(dir.path().join("db.sqlite"), &keystore).expect("open"));
    let traffic_hub = TrafficStreamingHub::with_capacity(4);
    let processor = Arc::new(test_processor(Arc::clone(&store), traffic_hub.clone()));
    let tracker =
        FlowTracker::with_processor(StoreFlowAdapter::new(Arc::clone(&store)), Some(processor));

    let key = sample_key();
    tracker.handle_event(&FlowEvent::Opened(
        key,
        FlowMeta {
            pid: 451_004,
            process: None,
            open_ts: 0,
            cookie: None,
            if_index: None,
        },
    ));
    assert!(tracker.flow_identity_for_test(&key).is_some());

    // A burst of flushes must not re-run failing lookups without bound:
    // the first attempt arms the backoff, the rest wait for it.
    for _ in 0..4 {
        tracker.flush_active_flows().expect("flush");
    }
    assert_eq!(tracker.identity_attempts_for_test(&key), Some(1));
    let attempts_after_burst = tracker.identity_recovery_stats().attempts;

    // Even with expired backoffs the per-flow budget caps the retries.
    for _ in 0..10 {
        tracker.expire_identity_retry_for_test(&key);
        tracker.flush_active_flows().expect("flush");
    }
    assert_eq!(
        tracker.identity_attempts_for_test(&key),
        Some(MAX_IDENTITY_LOOKUP_ATTEMPTS)
    );
    let capped = tracker.identity_recovery_stats().attempts;
    assert_eq!(
        capped - attempts_after_burst,
        u64::from(MAX_IDENTITY_LOOKUP_ATTEMPTS) - 1
    );

    // At the cap, further flushes attempt nothing more.
    tracker.expire_identity_retry_for_test(&key);
    tracker.flush_active_flows().expect("flush");
    assert_eq!(tracker.identity_recovery_stats().attempts, capped);
}

#[test]
fn placeholder_flow_upgrades_at_close_with_creation_time_evidence() {
    let dir = tempdir().expect("tempdir");
    let keystore = UnixSecureFileKeyProvider::new(dir.path().join("key"));
    let store =
        Arc::new(Store::open_with_keystore(dir.path().join("db.sqlite"), &keystore).expect("open"));
    let traffic_hub = TrafficStreamingHub::with_capacity(4);
    let processor = Arc::new(test_processor(Arc::clone(&store), traffic_hub.clone()));
    let tracker =
        FlowTracker::with_processor(StoreFlowAdapter::new(Arc::clone(&store)), Some(processor));

    let pid = 451_005;
    let key = sample_key();
    open_placeholder_flow(&tracker, key, pid, "close-heal.exe", 555_000);
    tracker.handle_event(&FlowEvent::Closed(
        key,
        FlowMeta {
            pid,
            process: Some(ProcessIdentity {
                executable: CLOSE_HEAL_PATH.to_owned(),
                name: "close-heal.exe".to_owned(),
                start_ts: 555_000,
            }),
            open_ts: 0,
            cookie: None,
            if_index: None,
        },
    ));
    tracker.flush().expect("flush");

    let apps = store.list_applications().expect("apps");
    let real = apps
        .iter()
        .find(|app| app.app_path == CLOSE_HEAL_PATH)
        .expect("real application row");
    let logs = store
        .query_connection_logs(&ConnectionLogQuery {
            app_name: Some("close-heal.exe".to_owned()),
            ..ConnectionLogQuery::default()
        })
        .expect("logs");
    assert_ne!(logs.logs, []);
    assert!(
        logs.logs.iter().all(|log| log.app_id == real.id),
        "every persisted row must carry the upgraded identity"
    );
}

#[test]
fn placeholder_flow_recovers_creation_time_from_earlier_lifecycle_event() {
    let dir = tempdir().expect("tempdir");
    let keystore = UnixSecureFileKeyProvider::new(dir.path().join("key"));
    let store =
        Arc::new(Store::open_with_keystore(dir.path().join("db.sqlite"), &keystore).expect("open"));
    let traffic_hub = TrafficStreamingHub::with_capacity(4);
    let processor = Arc::new(test_processor(Arc::clone(&store), traffic_hub));
    let tracker =
        FlowTracker::with_processor(StoreFlowAdapter::new(Arc::clone(&store)), Some(processor));
    let pid = 451_006;
    let key = sample_key();
    let meta = FlowMeta {
        pid,
        process: None,
        open_ts: 0,
        cookie: None,
        if_index: None,
    };
    tracker
        .processes_for_test()
        .process_started(pid, "early-heal.exe", "early-heal.exe", 666_000);
    tracker.handle_event(&process_started_event(
        pid,
        "early-heal.exe",
        "early-heal.exe",
        666_000,
    ));
    tracker.handle_event(&FlowEvent::Opened(key, meta.clone()));
    tracker.flush_active_flows().expect("persist fallback");
    assert_eq!(
        tracker.flow_identity_for_test(&key).expect("flow").1,
        "Path unavailable"
    );

    // A later successful image lookup carries the same creation time, but
    // no second lifecycle event or process metadata arrives on this flow.
    let real_path = r"C:\apps\early-heal.exe";
    tracker
        .processes_for_test()
        .seed_cache(pid, real_path, "early-heal.exe", 666_000);
    tracker.handle_event(&FlowEvent::Closed(key, meta));
    tracker.flush().expect("flush");
    tracker.processes_for_test().process_stopped(pid);

    let logs = store
        .query_connection_logs(&ConnectionLogQuery::default())
        .expect("logs");
    assert_eq!(logs.logs.len(), 1);
    assert_eq!(logs.logs[0].app_path, real_path);
    assert_eq!(tracker.identity_recovery_stats().recoveries, 1);
}

#[test]
fn earlier_lifecycle_creation_time_rejects_unverified_pid_identity() {
    for (pid, lookup_start_ts, duplicate_open, system_fold) in [
        (451_007, 888_000, false, false),
        (451_008, 0, false, false),
        (451_009, 0, true, false),
        (451_010, 0, false, true),
    ] {
        let dir = tempdir().expect("tempdir");
        let keystore = UnixSecureFileKeyProvider::new(dir.path().join("key"));
        let store = Arc::new(
            Store::open_with_keystore(dir.path().join("db.sqlite"), &keystore).expect("open"),
        );
        let traffic_hub = TrafficStreamingHub::with_capacity(4);
        let processor = Arc::new(test_processor(Arc::clone(&store), traffic_hub));
        let tracker =
            FlowTracker::with_processor(StoreFlowAdapter::new(Arc::clone(&store)), Some(processor));
        let mut key = sample_key();
        if system_fold {
            key.protocol = Protocol::Udp;
            key.local_port = 68;
            key.remote_port = 67;
            key.remote_addr = "255.255.255.255".parse().expect("broadcast");
        }
        let meta = FlowMeta {
            pid,
            process: None,
            open_ts: 0,
            cookie: None,
            if_index: None,
        };
        tracker
            .processes_for_test()
            .process_started(pid, "previous.exe", "previous.exe", 777_000);
        tracker.handle_event(&FlowEvent::Opened(key, meta.clone()));
        tracker.processes_for_test().seed_cache(
            pid,
            if system_fold {
                r"C:\Windows\System32\svchost.exe::Dhcp"
            } else {
                r"C:\apps\new-occupant.exe"
            },
            if system_fold {
                "Dhcp (svchost.exe)"
            } else {
                "new-occupant.exe"
            },
            lookup_start_ts,
        );
        if duplicate_open {
            tracker.handle_event(&FlowEvent::Opened(key, meta.clone()));
        }
        tracker.handle_event(&FlowEvent::Closed(key, meta));
        tracker.flush().expect("flush");
        tracker.processes_for_test().process_stopped(pid);

        let logs = store
            .query_connection_logs(&ConnectionLogQuery::default())
            .expect("logs");
        assert_eq!(logs.logs.len(), 1);
        assert_eq!(logs.logs[0].app_path, "Path unavailable");
        assert_eq!(tracker.identity_recovery_stats().recoveries, 0);
    }
}

#[test]
fn identity_upgrade_acceptance_rules() {
    assert!(identity_upgrade_acceptable(false, r"C:\a.exe", "a.exe"));
    assert!(!identity_upgrade_acceptable(false, "", "a.exe"));
    assert!(!identity_upgrade_acceptable(
        false,
        r"C:\a.exe",
        crate::process_resolver::UNKNOWN_APP_NAME
    ));
    // A placeholder already names the application: only a real path
    // counts as an upgrade, never another stand-in.
    assert!(identity_upgrade_acceptable(true, r"C:\a.exe", "a.exe"));
    assert!(!identity_upgrade_acceptable(
        true,
        "Path unavailable",
        "a.exe"
    ));
    assert!(!identity_upgrade_acceptable(
        true,
        "Unknown (Exited)",
        crate::process_resolver::UNKNOWN_APP_NAME
    ));
    assert!(!identity_upgrade_acceptable(true, "", "a.exe"));
}

#[test]
fn close_recovery_rejects_another_process_instance() {
    let dir = tempdir().expect("tempdir");
    let store = Arc::new(Store::open(dir.path().join("db.sqlite")).expect("store"));
    let processor = Arc::new(test_processor(
        Arc::clone(&store),
        TrafficStreamingHub::with_capacity(4),
    ));
    let tracker = FlowTracker::with_processor(StoreFlowAdapter::new(store), Some(processor));
    for (offset, close_pid, close_ts) in [
        (0, 452_001, 222_000),
        (1, 452_002, 0),
        (2, 452_999, 111_000),
    ] {
        let pid = 452_001 + offset;
        let key = sample_key();
        open_placeholder_flow(&tracker, key, pid, "original.exe", 111_000);
        let flow = tracker.active.lock().remove(&key).expect("flow");
        tracker.processes_for_test().process_started(
            pid,
            r"C:\apps\replacement.exe",
            "replacement.exe",
            222_000,
        );
        let recovered = tracker.maybe_reresolve_flow(
            flow,
            &key,
            &FlowMeta {
                pid: close_pid,
                process: Some(ProcessIdentity {
                    executable: r"C:\apps\replacement.exe".to_owned(),
                    name: "replacement.exe".to_owned(),
                    start_ts: close_ts,
                }),
                open_ts: 0,
                cookie: None,
                if_index: None,
            },
        );
        tracker.processes_for_test().process_stopped(pid);
        assert_eq!(recovered.app_path, "Path unavailable");
        assert_eq!(recovered.app_name, "original.exe");
    }
}

#[test]
fn recovery_preserves_ids_held_by_unflushed_flows_and_cache() {
    let dir = tempdir().expect("tempdir");
    let store = Arc::new(Store::open(dir.path().join("db.sqlite")).expect("store"));
    let processor = Arc::new(test_processor(
        Arc::clone(&store),
        TrafficStreamingHub::with_capacity(4),
    ));
    let tracker = FlowTracker::with_processor(
        StoreFlowAdapter::new(Arc::clone(&store)),
        Some(Arc::clone(&processor)),
    );
    let key = sample_key();
    open_placeholder_flow(&tracker, key, 453_001, "shared.exe", 111_000);
    let old_id = tracker.flow_identity_for_test(&key).expect("flow").0;
    tracker.flush_active_flows().expect("first persistence");
    let mut other = key;
    other.local_port += 1;
    open_placeholder_flow(&tracker, other, 453_002, "shared.exe", 0);
    tracker.processes_for_test().process_started(
        453_001,
        r"C:\apps\shared.exe",
        "shared.exe",
        111_000,
    );
    tracker.handle_event(&process_started_event(
        453_001,
        r"C:\apps\shared.exe",
        "shared.exe",
        111_000,
    ));
    tracker
        .flush_active_flows()
        .expect("recovery and pending persistence");
    tracker.processes_for_test().process_stopped(453_001);
    assert!(
        store
            .list_applications()
            .expect("apps")
            .iter()
            .any(|app| app.id == old_id),
        "an unflushed flow still owns this ID"
    );
    let cached = processor
        .resolve_app(
            453_003,
            &FlowMeta {
                pid: 453_003,
                process: Some(ProcessIdentity {
                    executable: "shared.exe".to_owned(),
                    name: "shared.exe".to_owned(),
                    start_ts: 0,
                }),
                open_ts: 0,
                cookie: None,
                if_index: None,
            },
        )
        .app_id;
    assert!(
        store
            .list_applications()
            .expect("apps")
            .iter()
            .any(|app| app.id == cached),
        "cached IDs must still exist"
    );
}

#[test]
fn merges_bytes_when_etw_tuple_orientation_differs() {
    let writes = Arc::new(StdMutex::new(Vec::new()));
    let writes_clone = Arc::clone(&writes);
    let tracker = FlowTracker::new(move |logs: &[NewConnectionLog]| {
        writes_clone.lock().expect("lock").extend_from_slice(logs);
        Ok(())
    });

    let key = sample_key();
    let meta = FlowMeta {
        pid: 100,
        process: None,
        open_ts: 0,
        cookie: None,
        if_index: None,
    };

    tracker.handle_event(&FlowEvent::Opened(key, meta.clone()));
    tracker.handle_event(&FlowEvent::Bytes(
        key,
        ByteDelta {
            sent: 512,
            received: 0,
        },
    ));
    tracker.handle_event(&FlowEvent::Bytes(
        key.reverse(),
        ByteDelta {
            sent: 0,
            received: 9_216,
        },
    ));
    tracker.handle_event(&FlowEvent::Closed(key, meta));
    tracker.flush().expect("flush");

    let batch = writes.lock().expect("lock");
    assert_eq!(batch.len(), 1);
    assert_eq!(batch[0].bytes_sent, 512);
    assert_eq!(batch[0].bytes_received, 9_216);
}

fn test_processor(store: Arc<Store>, traffic_hub: TrafficStreamingHub) -> FlowProcessor {
    test_processor_with_policy(store, traffic_hub, RuleEngine::new())
}

fn test_processor_with_policy(
    store: Arc<Store>,
    traffic_hub: TrafficStreamingHub,
    engine: RuleEngine,
) -> FlowProcessor {
    let alerts = AlertPublisher::unsaved(NotificationHub::with_capacity(4), None);
    let rule_engine = Arc::new(RwLock::new(engine));
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
async fn publishes_attributed_update_after_opened_and_bytes() {
    let dir = tempdir().expect("tempdir");
    let keystore = UnixSecureFileKeyProvider::new(dir.path().join("key"));
    let store =
        Arc::new(Store::open_with_keystore(dir.path().join("db.sqlite"), &keystore).expect("open"));

    let traffic_hub = TrafficStreamingHub::with_capacity(4);
    let mut subscription = traffic_hub.subscribe();
    let processor = Arc::new(test_processor(store, traffic_hub.clone()));
    let tracker = FlowTracker::with_processor(
        |_logs: &[NewConnectionLog]| Ok(()),
        Some(Arc::clone(&processor)),
    );

    let key = sample_key();
    let meta = FlowMeta {
        pid: 71_003,
        process: Some(ProcessIdentity {
            executable: BROWSER_PATH.to_owned(),
            name: "browser.exe".to_owned(),
            start_ts: 0,
        }),
        open_ts: 0,
        cookie: None,
        if_index: None,
    };

    tracker.handle_event(&FlowEvent::Opened(key, meta));
    tracker.handle_event(&FlowEvent::Bytes(
        key,
        ByteDelta {
            sent: 100,
            received: 900,
        },
    ));

    let event = subscription.recv().await.expect("traffic event");
    assert_eq!(event.action, "UPDATE");
    assert_eq!(event.bytes_sent, 100);
    assert_eq!(event.bytes_received, 900);
    assert_eq!(event.app_name, "browser.exe");
    assert_eq!(event.app_path, BROWSER_PATH);
}

/// The naming tests above call the flush themselves. This one leaves it to
/// the tracker's own loop, which is what decides when the connections a hint
/// may name are looked up: a hint that arrives after a flow closed has to
/// reach its row, and one from before a flow opened has to correct the name
/// the flow was first given, with nothing but the loop's ticks to prompt it.
#[tokio::test]
async fn the_event_loop_names_closed_and_open_flows_from_hints_that_arrive_late() {
    let dir = tempdir().expect("tempdir");
    let keystore = UnixSecureFileKeyProvider::new(dir.path().join("key"));
    let store =
        Arc::new(Store::open_with_keystore(dir.path().join("db.sqlite"), &keystore).expect("open"));
    let processor = Arc::new(test_processor(
        Arc::clone(&store),
        TrafficStreamingHub::with_capacity(4),
    ));
    let tracker = Arc::new(FlowTracker::with_processor(
        StoreFlowAdapter::new(Arc::clone(&store)),
        Some(Arc::clone(&processor)),
    ));
    let (tx, rx) = mpsc::channel(32);
    let running = tokio::spawn({
        let tracker = Arc::clone(&tracker);
        async move { tracker.run(rx).await }
    });

    let pid = 98_771;
    // The open flow's name is corrected only while it is provisional, which
    // is counted from here. The steps below take a few of the loop's ticks.
    let opened_at = netmetrics_core::unix_now_ms();
    let meta = FlowMeta {
        pid,
        process: Some(ProcessIdentity {
            executable: UPGRADE_PATH.to_owned(),
            name: "upgrade.exe".to_owned(),
            start_ts: 1,
        }),
        open_ts: opened_at,
        cookie: None,
        if_index: None,
    };
    let closed = sample_key();
    let mut open = closed;
    open.remote_addr = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 91));
    open.local_port = closed.local_port + 1;
    let bytes = ByteDelta {
        sent: 10,
        received: 20,
    };
    let hint = |key: &FlowKey, query: &str, observed_at| FlowEvent::DnsResolvedWithMetadata {
        attribution: DnsResolutionAttribution::Process(pid),
        query: query.to_owned(),
        answers: vec![key.remote_addr.to_string()],
        ttl_ms: 300_000,
        observed_at,
    };
    let send = |event| {
        let tx = tx.clone();
        async move { tx.send(event).await.expect("the loop is running") }
    };
    let domain_soon = |key: FlowKey, wanted: &'static str| {
        let store = Arc::clone(&store);
        let tracker = Arc::clone(&tracker);
        async move {
            let deadline = Instant::now() + Duration::from_secs(10);
            loop {
                // A flow whose process cannot be identified, as this made-up
                // one cannot on every platform, is not written until it has
                // had five seconds to be. That would outlast the time the
                // open flow's name stays provisional.
                tracker.expire_unknown_grace_for_test(&key);
                let found: Vec<String> = store
                    .query_connection_logs(&antiwire_store::ConnectionLogQuery::default())
                    .expect("query logs")
                    .logs
                    .into_iter()
                    .filter(|log| log.dst_ip == key.remote_addr.to_string())
                    .map(|log| log.dst_domain)
                    .collect();
                if found == [wanted] {
                    return;
                }
                assert!(
                    Instant::now() < deadline,
                    "wanted {wanted:?}, the row has {found:?}"
                );
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        }
    };

    // A flow that closes with no name, and one that stays open under the only
    // name its process is known to hold.
    send(hint(&open, "earlier.example", opened_at - 60_000)).await;
    send(FlowEvent::Opened(closed, meta.clone())).await;
    send(FlowEvent::Bytes(closed, bytes)).await;
    send(FlowEvent::Closed(closed, meta.clone())).await;
    send(FlowEvent::Opened(open, meta.clone())).await;
    send(FlowEvent::Bytes(open, bytes)).await;
    domain_soon(closed, "").await;
    domain_soon(open, "earlier.example").await;

    // The hints for both arrive now, stamped before the flows opened.
    send(hint(&closed, "late.example", opened_at - 100)).await;
    send(hint(&open, "just-asked.example", opened_at - 100)).await;
    domain_soon(closed, "late.example").await;
    domain_soon(open, "just-asked.example (inferred)").await;
    let stats = processor.domain_lookup_stats();
    assert_eq!(stats.late_upgrades, 1);
    assert_eq!(
        (stats.corrected_open, stats.corrected_closed),
        ([0, 1, 0], [0, 0, 0])
    );

    drop(tx);
    running.await.expect("join").expect("tracker run");
}

#[tokio::test]
async fn process_start_is_applied_before_following_flow_resolution() {
    let dir = tempdir().expect("tempdir");
    let keystore = UnixSecureFileKeyProvider::new(dir.path().join("key"));
    let store =
        Arc::new(Store::open_with_keystore(dir.path().join("db.sqlite"), &keystore).expect("open"));
    let traffic_hub = TrafficStreamingHub::with_capacity(4);
    let processor = Arc::new(test_processor(Arc::clone(&store), traffic_hub.clone()));
    let tracker = Arc::new(FlowTracker::with_processor(
        StoreFlowAdapter::new(Arc::clone(&store)),
        Some(processor),
    ));
    let key = sample_key();
    let pid = 98_765;
    let (tx, rx) = mpsc::channel(8);
    tx.send(FlowEvent::ProcessStarted(ProcessInfo {
        pid,
        identity: ProcessIdentity {
            executable: r"C:\apps\ordered.exe".to_owned(),
            name: "ordered.exe".to_owned(),
            start_ts: 1,
        },
    }))
    .await
    .expect("process start");
    let meta = FlowMeta {
        pid,
        process: Some(ProcessIdentity {
            executable: String::new(),
            name: String::new(),
            start_ts: 1,
        }),
        open_ts: 2,
        cookie: None,
        if_index: None,
    };
    tx.send(FlowEvent::Opened(key, meta.clone()))
        .await
        .expect("open");
    tx.send(FlowEvent::Bytes(
        key,
        ByteDelta {
            sent: 10,
            received: 20,
        },
    ))
    .await
    .expect("bytes");
    tx.send(FlowEvent::Closed(key, meta)).await.expect("close");
    drop(tx);

    tracker.run(rx).await.expect("tracker run");

    let app = store
        .find_application_by_name("ordered.exe")
        .expect("find app")
        .expect("app exists");
    let page = store
        .query_connection_logs(&antiwire_store::ConnectionLogQuery::default())
        .expect("query logs");
    assert_eq!(page.logs.len(), 1);
    assert_eq!(page.logs[0].app_id, app.id);
}

#[test]
fn losing_byte_accounting_is_reported_to_the_ipc_layer() {
    let health = Arc::new(CollectorHealth::default());
    let tracker = FlowTracker::new(|_: &[NewConnectionLog]| Ok(()))
        .with_collector_health(Arc::clone(&health));

    assert!(health.byte_accounting_available());

    // The Windows backend reports the cause first, then the fallback it dropped into.
    tracker.handle_event(&FlowEvent::Degraded {
        reason: DegradeReason::PermissionDenied {
            source: "kernel ETW".to_owned(),
        },
    });
    tracker.handle_event(&FlowEvent::Degraded {
        reason: DegradeReason::SnapshotOnly {
            source: "windows-ip-helper".to_owned(),
        },
    });

    assert!(!health.byte_accounting_available());
    assert!(
        health.detail().contains("Administrator"),
        "the actionable cause must survive the later fallback report, got {:?}",
        health.detail()
    );
}

fn snapshot_only() -> FlowEvent {
    FlowEvent::Degraded {
        reason: DegradeReason::SnapshotOnly {
            source: "macos-socket-table".to_owned(),
        },
    }
}

fn restored() -> FlowEvent {
    FlowEvent::Restored {
        source: "macos-socket-table".to_owned(),
    }
}

/// The collector's native source can come back after a fallback, and fail again later.
/// The dashboard has to follow it both ways.
#[test]
fn a_fallback_is_retracted_when_the_native_source_is_back_and_reported_again_later() {
    let health = Arc::new(CollectorHealth::default());
    let tracker = FlowTracker::new(|_: &[NewConnectionLog]| Ok(()))
        .with_collector_health(Arc::clone(&health));

    tracker.handle_event(&snapshot_only());
    assert!(!health.byte_accounting_available());

    tracker.handle_event(&restored());
    assert!(
        health.byte_accounting_available(),
        "still claiming {:?}",
        health.detail()
    );

    tracker.handle_event(&snapshot_only());
    assert!(
        !health.byte_accounting_available(),
        "a second loss must be reported despite the de-duplication of the first"
    );
}

/// A source coming back does not grant the daemon the privilege it lacked.
#[test]
fn a_restored_source_leaves_a_missing_privilege_reported() {
    let health = Arc::new(CollectorHealth::default());
    let tracker = FlowTracker::new(|_: &[NewConnectionLog]| Ok(()))
        .with_collector_health(Arc::clone(&health));

    tracker.handle_event(&FlowEvent::Degraded {
        reason: DegradeReason::PermissionDenied {
            source: "pktap-bpf".to_owned(),
        },
    });
    tracker.handle_event(&snapshot_only());
    tracker.handle_event(&restored());

    assert!(!health.byte_accounting_available());
    assert!(health.detail().contains("Administrator"));
}

/// Byte counts the bridge dropped stay missing from the totals, whatever the source does.
#[test]
fn a_restored_source_leaves_dropped_byte_counts_reported() {
    let health = Arc::new(CollectorHealth::default());
    let tracker = FlowTracker::new(|_: &[NewConnectionLog]| Ok(()))
        .with_collector_health(Arc::clone(&health));

    health.mark_bytes_dropped("some sent and received bytes were not counted");
    tracker.handle_event(&snapshot_only());
    tracker.handle_event(&restored());

    assert!(!health.byte_accounting_available());
    assert!(health.detail().contains("not counted"));
}

#[test]
fn unrelated_degradation_leaves_byte_accounting_alone() {
    let health = Arc::new(CollectorHealth::default());
    let tracker = FlowTracker::new(|_: &[NewConnectionLog]| Ok(()))
        .with_collector_health(Arc::clone(&health));

    tracker.handle_event(&FlowEvent::Degraded {
        reason: DegradeReason::BufferOverflow { dropped: 3 },
    });

    assert!(health.byte_accounting_available());
}

#[test]
fn degradation_deduplication_ignores_changing_overflow_counts() {
    assert_eq!(
        degradation_key(&DegradeReason::BufferOverflow { dropped: 1 }),
        degradation_key(&DegradeReason::BufferOverflow { dropped: 65_536 }),
        "overflow deltas belong to one stable warning category"
    );
    assert_ne!(
        degradation_key(&DegradeReason::BufferOverflow { dropped: 1 }),
        degradation_key(&DegradeReason::CapacityExceeded { evicted: 1 })
    );
}

fn meta_with_cookie(pid: u32, cookie: u64) -> FlowMeta {
    FlowMeta {
        pid,
        process: None,
        open_ts: 0,
        cookie: Some(SocketCookie {
            value: cookie,
            source: CookieSource::LinuxSockCookie,
        }),
        if_index: None,
    }
}

#[test]
fn recycled_tuple_with_a_new_cookie_splits_into_separate_logs() {
    let writes = Arc::new(StdMutex::new(Vec::new()));
    let writes_clone = Arc::clone(&writes);
    let tracker = FlowTracker::new(move |logs: &[NewConnectionLog]| {
        writes_clone.lock().expect("lock").extend_from_slice(logs);
        Ok(())
    });
    let key = sample_key();

    tracker.handle_event(&FlowEvent::Opened(key, meta_with_cookie(100, 1)));
    tracker.handle_event(&FlowEvent::Bytes(
        key,
        ByteDelta {
            sent: 100,
            received: 200,
        },
    ));

    // The ephemeral port is recycled onto a different socket, with no close observed.
    let second = meta_with_cookie(101, 2);
    tracker.handle_event(&FlowEvent::Opened(key, second.clone()));
    tracker.handle_event(&FlowEvent::Bytes(
        key,
        ByteDelta {
            sent: 7,
            received: 9,
        },
    ));
    tracker.handle_event(&FlowEvent::Closed(key, second));
    tracker.flush().expect("flush");

    let writes = writes.lock().expect("lock");
    assert_eq!(writes.len(), 2, "each socket must produce its own log row");
    assert_eq!(writes[0].bytes_sent, 100);
    assert_eq!(writes[0].bytes_received, 200);
    assert_eq!(
        writes[1].bytes_sent, 7,
        "the replacement must not inherit the previous socket's bytes"
    );
    assert_eq!(writes[1].bytes_received, 9);
}

#[test]
fn repeated_open_with_the_same_cookie_stays_one_flow() {
    let writes = Arc::new(StdMutex::new(Vec::new()));
    let writes_clone = Arc::clone(&writes);
    let tracker = FlowTracker::new(move |logs: &[NewConnectionLog]| {
        writes_clone.lock().expect("lock").extend_from_slice(logs);
        Ok(())
    });
    let key = sample_key();

    tracker.handle_event(&FlowEvent::Opened(key, meta_with_cookie(100, 1)));
    tracker.handle_event(&FlowEvent::Bytes(
        key,
        ByteDelta {
            sent: 50,
            received: 0,
        },
    ));
    tracker.handle_event(&FlowEvent::Opened(key, meta_with_cookie(100, 1)));
    tracker.handle_event(&FlowEvent::Closed(key, meta_with_cookie(100, 1)));
    tracker.flush().expect("flush");

    let writes = writes.lock().expect("lock");
    assert_eq!(writes.len(), 1);
    assert_eq!(writes[0].bytes_sent, 50);
}

#[test]
fn open_without_a_cookie_never_splits_an_existing_flow() {
    let writes = Arc::new(StdMutex::new(Vec::new()));
    let writes_clone = Arc::clone(&writes);
    let tracker = FlowTracker::new(move |logs: &[NewConnectionLog]| {
        writes_clone.lock().expect("lock").extend_from_slice(logs);
        Ok(())
    });
    let key = sample_key();

    tracker.handle_event(&FlowEvent::Opened(key, meta_with_cookie(100, 1)));
    tracker.handle_event(&FlowEvent::Bytes(
        key,
        ByteDelta {
            sent: 50,
            received: 0,
        },
    ));

    // Backends that cannot resolve a cookie must never look like a socket change.
    let no_cookie = FlowMeta {
        pid: 100,
        process: None,
        open_ts: 0,
        cookie: None,
        if_index: None,
    };
    tracker.handle_event(&FlowEvent::Opened(key, no_cookie.clone()));
    tracker.handle_event(&FlowEvent::Closed(key, no_cookie));
    tracker.flush().expect("flush");

    let writes = writes.lock().expect("lock");
    assert_eq!(writes.len(), 1);
    assert_eq!(writes[0].bytes_sent, 50);
}

#[test]
fn a_late_cookie_is_adopted_without_splitting() {
    let writes = Arc::new(StdMutex::new(Vec::new()));
    let writes_clone = Arc::clone(&writes);
    let tracker = FlowTracker::new(move |logs: &[NewConnectionLog]| {
        writes_clone.lock().expect("lock").extend_from_slice(logs);
        Ok(())
    });
    let key = sample_key();

    // Mirrors Windows: ETW opens the flow, and the IP Helper poller supplies the cookie
    // one interval later.
    tracker.handle_event(&FlowEvent::Opened(
        key,
        FlowMeta {
            pid: 100,
            process: None,
            open_ts: 0,
            cookie: None,
            if_index: None,
        },
    ));
    tracker.handle_event(&FlowEvent::Bytes(
        key,
        ByteDelta {
            sent: 20,
            received: 0,
        },
    ));
    tracker.handle_event(&FlowEvent::Opened(key, meta_with_cookie(100, 42)));
    tracker.handle_event(&FlowEvent::Bytes(
        key,
        ByteDelta {
            sent: 5,
            received: 0,
        },
    ));
    tracker.handle_event(&FlowEvent::Closed(key, meta_with_cookie(100, 42)));
    tracker.flush().expect("flush");

    let writes = writes.lock().expect("lock");
    assert_eq!(writes.len(), 1, "adopting a cookie is not a socket change");
    assert_eq!(writes[0].bytes_sent, 25);
}

/// Builds `count` distinct flows and drives them open-then-closed through `run`.
async fn drive_open_close_flows<S: crate::store::FlowStore + 'static>(
    tracker: &Arc<FlowTracker<S>>,
    count: u16,
) {
    let (tx, rx) = tokio::sync::mpsc::channel(usize::from(count) * 2 + 8);
    for index in 0..count {
        let key = FlowKey {
            protocol: Protocol::Tcp,
            local_addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            local_port: 40_000 + index,
            remote_addr: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5)),
            remote_port: 443,
        };
        let meta = FlowMeta {
            pid: 71_100,
            process: None,
            open_ts: 0,
            cookie: None,
            if_index: None,
        };
        tx.send(FlowEvent::Opened(key, meta.clone()))
            .await
            .expect("send open");
        tx.send(FlowEvent::Closed(key, meta))
            .await
            .expect("send close");
    }
    drop(tx);
    let _ = tracker.run(rx).await;
}

/// The regression this guards: one panicking flush ended `run`, and
/// connection logging stayed off until the daemon restarted.
#[tokio::test]
async fn a_panicking_flush_does_not_end_the_event_loop() {
    let calls = Arc::new(AtomicUsize::new(0));
    let written = Arc::new(AtomicUsize::new(0));
    let (calls_clone, written_clone) = (Arc::clone(&calls), Arc::clone(&written));
    let tracker = Arc::new(FlowTracker::new(move |rows: &[NewConnectionLog]| {
        assert!(
            calls_clone.fetch_add(1, Ordering::SeqCst) > 0,
            "first flush panics"
        );
        written_clone.fetch_add(rows.len(), Ordering::SeqCst);
        Ok(())
    }));

    let flows = u16::try_from(FLOW_WRITE_BATCH_SIZE).expect("batch size") * 3;
    drive_open_close_flows(&tracker, flows).await;

    assert!(calls.load(Ordering::SeqCst) > 1);
    assert!(written.load(Ordering::SeqCst) > 0);
}

/// A store that keeps failing must not end the event loop.
///
/// `run` used to `?` the flush error straight out, so the task logged one line
/// and exited: every later connection went unrecorded, the UI showed zeros, and
/// nothing said why. The loop now has to drain every event and report the
/// outage through `CollectorHealth` instead.
#[tokio::test]
async fn a_failing_store_does_not_end_the_event_loop() {
    let attempts = Arc::new(AtomicUsize::new(0));
    let attempts_clone = Arc::clone(&attempts);

    let tracker = Arc::new(FlowTracker::new(move |_: &[NewConnectionLog]| {
        attempts_clone.fetch_add(1, Ordering::SeqCst);
        Err(store_error("disk is on fire"))
    }));

    // Enough flows to cross the batch threshold several times over, so the
    // pre-fix code would have bailed out around the first quarter of them.
    let flows = u16::try_from(FLOW_WRITE_BATCH_SIZE).expect("batch size") * 3;
    drive_open_close_flows(&tracker, flows).await;

    assert!(
        attempts.load(Ordering::SeqCst) > 1,
        "the loop must keep flushing after the first failure, got {} attempt(s)",
        attempts.load(Ordering::SeqCst)
    );
    assert_eq!(
        tracker.pending.lock().len(),
        usize::from(flows),
        "every event must still have been handled once the store started failing"
    );
}

/// A tracker that dies while the daemon is running has to say so, because the
/// dashboard would otherwise keep claiming byte accounting is available.
#[tokio::test]
async fn a_panicking_tracker_is_reported_through_collector_health() {
    let health = Arc::new(CollectorHealth::default());
    let tracker = Arc::new(FlowTracker::new(|_: &[NewConnectionLog]| -> Result<()> {
        panic!("store exploded")
    }));
    let (tx, rx) = mpsc::channel(8);
    let key = sample_key();
    let meta = FlowMeta {
        pid: 4242,
        process: None,
        open_ts: 1,
        cookie: None,
        if_index: None,
    };
    tx.send(FlowEvent::Opened(key, meta.clone()))
        .await
        .expect("open");
    tx.send(FlowEvent::Closed(key, meta)).await.expect("close");
    drop(tx);
    let shutdown = tokio_util::sync::CancellationToken::new();

    tracker
        .spawn_supervised(rx, Arc::clone(&health), shutdown)
        .await
        .expect("supervisor task");

    assert!(!health.byte_accounting_available());
    assert!(
        health.detail().contains("restart the daemon"),
        "unexpected detail: {:?}",
        health.detail()
    );
}

/// A tracker that ends during shutdown must not be reported as a failure.
#[tokio::test]
async fn a_tracker_that_stops_with_shutdown_reports_healthy() {
    let health = Arc::new(CollectorHealth::default());
    let tracker = Arc::new(FlowTracker::new(|_: &[NewConnectionLog]| Ok(())));
    let (tx, rx) = mpsc::channel(1);
    drop(tx);
    let shutdown = tokio_util::sync::CancellationToken::new();
    shutdown.cancel();

    tracker
        .spawn_supervised(rx, Arc::clone(&health), shutdown)
        .await
        .expect("supervisor task");

    assert!(health.byte_accounting_available());
    assert_eq!(health.detail(), "");
}

/// An exit while the daemon is still running is a fault even without a panic:
/// the bridge closed its channel, so nothing else can reach the store.
#[tokio::test]
async fn an_early_tracker_exit_is_reported_without_a_panic() {
    let health = Arc::new(CollectorHealth::default());
    let tracker = Arc::new(FlowTracker::new(|_: &[NewConnectionLog]| Ok(())));
    let (tx, rx) = mpsc::channel(1);
    drop(tx);
    let shutdown = tokio_util::sync::CancellationToken::new();

    tracker
        .spawn_supervised(rx, Arc::clone(&health), shutdown)
        .await
        .expect("supervisor task");

    assert!(!health.byte_accounting_available());
}

/// Aborting the supervisor must stop the tracker itself, not just detach it, and
/// must not report a fault: abort is the teardown path after a drain timeout.
#[tokio::test]
async fn an_aborted_supervisor_stops_the_tracker_without_a_fault() {
    let health = Arc::new(CollectorHealth::default());
    let tracker = Arc::new(FlowTracker::new(|_: &[NewConnectionLog]| Ok(())));
    // Holding the sender keeps the tracker running until it is aborted.
    let (_tx, rx) = mpsc::channel(1);
    let shutdown = tokio_util::sync::CancellationToken::new();

    let task = tracker.spawn_supervised(rx, Arc::clone(&health), shutdown);
    task.abort();

    let join_error = task
        .await
        .expect_err("an aborted supervisor cannot complete");
    assert!(join_error.is_cancelled());
    assert!(
        health.byte_accounting_available(),
        "teardown abort is not a tracker fault"
    );
}

/// A tracker wedged in a store call is reported once the stall threshold passes,
/// and retracted as soon as it makes progress again.
#[tokio::test]
async fn a_wedged_tracker_is_reported_and_clears_when_progress_resumes() {
    let health = Arc::new(CollectorHealth::default());
    let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
    let blocked = Arc::new(std::sync::Mutex::new(Some(release_rx)));
    let mut tracker = FlowTracker::new(move |_: &[NewConnectionLog]| -> Result<()> {
        if let Some(rx) = blocked.lock().expect("unpoisoned").take() {
            let _ = rx.recv();
        }
        Ok(())
    });
    // Flush as soon as the batch is handled, so the wedge is deterministic rather
    // than waiting out the coalescing deadline.
    tracker.batch_size = 1;
    // Sample fast enough to see the stall without sleeping out the production
    // cadence; the stall rule itself is the production one.
    tracker.watchdog = WatchdogTiming {
        interval: Duration::from_millis(50),
        ..WatchdogTiming::default()
    };
    let tracker = Arc::new(tracker);

    let (tx, rx) = mpsc::channel(8);
    let key = sample_key();
    let meta = FlowMeta {
        pid: 4242,
        process: None,
        open_ts: 1,
        cookie: None,
        if_index: None,
    };
    tx.send(FlowEvent::Opened(key, meta.clone()))
        .await
        .expect("open");
    tx.send(FlowEvent::Closed(key, meta)).await.expect("close");
    let shutdown = tokio_util::sync::CancellationToken::new();
    let task = Arc::clone(&tracker).spawn_supervised(rx, Arc::clone(&health), shutdown);

    // The first batch flush blocks in the store, so progress stops; the watchdog
    // reports the stall once the threshold passes.
    wait_until(Duration::from_secs(5), || {
        !health.byte_accounting_available()
    })
    .await;
    assert!(health.detail().contains("not making progress"));

    release_tx.send(()).expect("release the store");
    wait_until(Duration::from_secs(5), || {
        health.byte_accounting_available()
    })
    .await;

    drop(tx);
    task.await.expect("supervisor task");
}

/// Waits for a condition, bounded by real time.
async fn wait_until(timeout: Duration, mut condition: impl FnMut() -> bool) {
    let deadline = Instant::now() + timeout;
    while !condition() {
        assert!(Instant::now() < deadline, "condition never became true");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

/// A sustained outage reaches the UI, a blip does not, and recovery retracts it.
///
/// Driven directly rather than through `run`, because the retry cadence is
/// deliberately slow once the store starts failing — reaching the threshold in a
/// live loop takes seconds of wall time that a unit test should not spend.
#[test]
fn a_sustained_outage_is_reported_and_retracted_when_writes_recover() {
    let health = Arc::new(antiwire_events::CollectorHealth::default());
    let tracker = FlowTracker::new(|_: &[NewConnectionLog]| Ok(()))
        .with_collector_health(Arc::clone(&health));

    for _ in 0..FLOW_FLUSH_FAILURES_BEFORE_DEGRADED - 1 {
        tracker.note_flush_outcome("test", Err(store_error("busy")));
    }
    assert!(
        health.byte_accounting_available(),
        "a couple of transient failures are not an outage"
    );

    tracker.note_flush_outcome("test", Err(store_error("busy")));
    assert!(!health.byte_accounting_available());
    assert!(
        health.detail().contains("local database"),
        "the reported detail must name the cause: {:?}",
        health.detail()
    );

    // Recovery has to retract the report, or a few seconds of disk trouble leaves
    // the UI wrong for the rest of the daemon's life.
    tracker.note_flush_outcome("test", Ok(true));
    assert_eq!(tracker.queue_flush_failures.load(Ordering::Relaxed), 0);
    assert!(
        health.byte_accounting_available(),
        "the outage report must clear once writes succeed again"
    );
    assert_eq!(health.detail(), "");
}

/// A store outage must never mask, or be cleared alongside, a collector fault —
/// "run as Administrator" is still true after the database comes back.
#[test]
fn a_store_recovery_does_not_clear_a_collector_fault() {
    let health = Arc::new(antiwire_events::CollectorHealth::default());
    let tracker = FlowTracker::new(|_: &[NewConnectionLog]| Ok(()))
        .with_collector_health(Arc::clone(&health));

    tracker.on_degraded(&DegradeReason::PermissionDenied {
        source: "kernel-etw".to_owned(),
    });
    for _ in 0..FLOW_FLUSH_FAILURES_BEFORE_DEGRADED {
        tracker.note_flush_outcome("test", Err(store_error("busy")));
    }

    tracker.note_flush_outcome("test", Ok(true));

    assert!(
        !health.byte_accounting_available(),
        "the collector still needs elevation"
    );
    assert!(
        health.detail().contains("Administrator"),
        "the actionable cause must survive: {:?}",
        health.detail()
    );
}

/// Every flow still reaches the store when it is healthy, and health stays clean.
#[tokio::test]
async fn a_healthy_store_receives_every_flow_and_stays_healthy() {
    let seen = Arc::new(AtomicUsize::new(0));
    let seen_clone = Arc::clone(&seen);
    let health = Arc::new(antiwire_events::CollectorHealth::default());
    let tracker = Arc::new(
        FlowTracker::new(move |logs: &[NewConnectionLog]| {
            seen_clone.fetch_add(logs.len(), Ordering::SeqCst);
            Ok(())
        })
        .with_collector_health(Arc::clone(&health)),
    );

    let flows = 64_u16;
    drive_open_close_flows(&tracker, flows).await;

    assert_eq!(seen.load(Ordering::SeqCst), usize::from(flows));
    assert!(health.byte_accounting_available());
    assert_eq!(health.detail(), "");
}

/// The backlog is bounded, so an unwritable store cannot grow it without limit.
#[test]
fn the_pending_backlog_is_capped() {
    let tracker = FlowTracker::new(|_: &[NewConnectionLog]| Err(store_error("unavailable")));

    let overflow = tracker.pending_cap + 128;
    for index in 0..overflow {
        tracker.push_pending_log(NewConnectionLog {
            replace_domain: false,
            is_close: false,
            conn_pid: 0,
            conn_id: 0,
            timestamp: OffsetDateTime::now_utc(),
            app_id: 1,
            app_path: String::new(),
            protocol: "TCP".to_owned(),
            src_ip: "10.0.0.2".to_owned(),
            src_port: 40_000,
            dst_ip: format!("203.0.113.{}", index % 250),
            dst_port: 443,
            dst_domain: String::new(),
            bytes_sent: 1,
            bytes_received: 1,
            action_taken: "ALLOWED".to_owned(),
            last_seen: OffsetDateTime::now_utc(),
            country_code: String::new(),
            isp: String::new(),
            blocklist_names: String::new(),
        });
    }

    assert_eq!(tracker.pending.lock().len(), tracker.pending_cap);
    assert_eq!(tracker.shed_records.load(Ordering::Relaxed), 128);
}

fn meta_with_inode_cookie(pid: u32, cookie: u64) -> FlowMeta {
    FlowMeta {
        cookie: Some(SocketCookie {
            value: cookie,
            source: CookieSource::LinuxInode,
        }),
        ..meta_with_cookie(pid, cookie)
    }
}

/// A later, more trustworthy cookie source must replace the stored one so a recycled
/// tuple is still detectable.
#[test]
fn a_sock_cookie_upgrades_a_stored_inode_cookie() {
    let writes = Arc::new(StdMutex::new(Vec::new()));
    let writes_clone = Arc::clone(&writes);
    let tracker = FlowTracker::new(move |logs: &[NewConnectionLog]| {
        writes_clone.lock().expect("lock").extend_from_slice(logs);
        Ok(())
    });
    let key = sample_key();

    tracker.handle_event(&FlowEvent::Opened(key, meta_with_inode_cookie(100, 1)));
    tracker.handle_event(&FlowEvent::Bytes(
        key,
        ByteDelta {
            sent: 11,
            received: 0,
        },
    ));
    // The side channel resolves the boot-unique cookie; it must be adopted.
    tracker.handle_event(&FlowEvent::Opened(key, meta_with_cookie(100, 2)));
    // A third socket on the same tuple now contradicts the adopted cookie and splits.
    tracker.handle_event(&FlowEvent::Opened(key, meta_with_cookie(100, 3)));
    tracker.handle_event(&FlowEvent::Bytes(
        key,
        ByteDelta {
            sent: 7,
            received: 0,
        },
    ));
    tracker.handle_event(&FlowEvent::Closed(key, meta_with_cookie(100, 3)));
    tracker.flush().expect("flush");

    let writes = writes.lock().expect("lock");
    assert_eq!(
        writes.len(),
        2,
        "the upgrade must make the split observable"
    );
    assert_eq!(writes[0].bytes_sent, 11);
    assert_eq!(writes[1].bytes_sent, 7);
}

/// A known non-zero PID is sticky, mirroring `FlowTable`: a later open carrying a
/// different PID must not overwrite it.
#[test]
fn a_different_nonzero_pid_does_not_overwrite_a_known_pid() {
    let tracker = FlowTracker::new(|_: &[NewConnectionLog]| Ok(()));
    let key = sample_key();
    tracker.handle_event(&FlowEvent::Opened(
        key,
        FlowMeta {
            pid: 111,
            process: None,
            open_ts: 1,
            cookie: None,
            if_index: None,
        },
    ));
    tracker.handle_event(&FlowEvent::Opened(
        key,
        FlowMeta {
            pid: 222,
            process: None,
            open_ts: 2,
            cookie: None,
            if_index: None,
        },
    ));

    assert_eq!(tracker.flow_pid_for_test(&key), Some(111));
}

/// A flush that never touched the store must not be mistaken for recovery.
#[test]
fn an_empty_flush_does_not_clear_a_lasting_outage() {
    let health = Arc::new(antiwire_events::CollectorHealth::default());
    let tracker = FlowTracker::new(|_: &[NewConnectionLog]| Ok(()))
        .with_collector_health(Arc::clone(&health));

    for _ in 0..FLOW_FLUSH_FAILURES_BEFORE_DEGRADED {
        tracker.note_flush_outcome("test", Err(store_error("busy")));
    }
    assert!(!health.byte_accounting_available());

    tracker.note_active_flush_outcome(Ok(false));
    tracker.note_flush_outcome("retry", Ok(false));

    assert_eq!(
        tracker.queue_flush_failures.load(Ordering::Relaxed),
        FLOW_FLUSH_FAILURES_BEFORE_DEGRADED,
        "a no-op flush must not reset the failure streak"
    );
    assert!(
        !health.byte_accounting_available(),
        "the outage report must survive an empty flush"
    );
}

/// A rejected re-attribution must not abort the byte persistence behind it.
struct ReattributeFailingStore {
    writes: Arc<StdMutex<Vec<NewConnectionLog>>>,
}

impl crate::store::FlowStore for ReattributeFailingStore {
    fn insert_batch(&self, logs: &[NewConnectionLog]) -> crate::Result<()> {
        self.writes.lock().expect("lock").extend_from_slice(logs);
        Ok(())
    }

    fn reattribute(&self, _attribution: &ConnectionLogAttribution) -> crate::Result<()> {
        Err(store_error("reattribute rejected"))
    }
}

#[test]
fn a_rejected_reattribution_does_not_block_byte_persistence() {
    let writes = Arc::new(StdMutex::new(Vec::new()));
    let tracker = FlowTracker::new(ReattributeFailingStore {
        writes: Arc::clone(&writes),
    });
    let key = sample_key();
    tracker.active.lock().insert(
        key,
        ActiveFlow {
            conn_id: 1,
            open_pid: 100,
            app_id: 2,
            app_path: r"C:\apps\browser.exe".to_owned(),
            app_name: "browser.exe".to_owned(),
            pid: 100,
            protocol: "TCP".to_owned(),
            src_ip: "192.168.1.10".to_owned(),
            src_port: 50_000,
            dst_ip: "203.0.113.5".to_owned(),
            dst_port: 443,
            bytes_sent: 100,
            bytes_received: 200,
            persisted_sent: 0,
            persisted_received: 0,
            db_row_created: true,
            persisted_app_id: 1,
            persisted_domain: String::new(),
            name_lookup: NameLookup::default(),
            traffic_template: None,
            unknown_since: None,
            unknown_socket_lookup_done: false,
            socket_lookup_attempts: 0,
            next_socket_lookup: None,
            identity_lookup_attempts: 0,
            attribution_lookup: AttributionLookup::Idle,
            next_identity_retry: None,
            cookie: None,
            process_start_ts: None,
            open_ts: 0,
            finishing: false,
            opened_at: OffsetDateTime::now_utc(),
            last_seen: OffsetDateTime::now_utc(),
        },
    );

    assert!(
        tracker.flush_active_flows().is_err(),
        "the rejected re-attribution must still be reported"
    );

    {
        let writes = writes.lock().expect("lock");
        assert_eq!(writes.len(), 1, "byte persistence must proceed regardless");
        assert_eq!(writes[0].bytes_sent, 100);
        assert_eq!(writes[0].bytes_received, 200);
    }

    // The byte write advanced the row and left its owner alone, so the
    // correction is still owed and the next flush tries it again.
    assert_eq!(
        tracker
            .active
            .lock()
            .get(&key)
            .expect("flow")
            .persisted_app_id,
        1,
        "a byte write must not record a rejected correction as made"
    );
    assert!(
        tracker.flush_active_flows().is_err(),
        "the rejected re-attribution must be retried"
    );
}

/// Closing a flow that was just flushed must not re-queue the same bytes,
/// but it must still record the end of the connection.
#[test]
fn failed_chunk_retries_do_not_repeat_successful_byte_writes() {
    let writes = Arc::new(StdMutex::new(Vec::new()));
    let saved = Arc::clone(&writes);
    let calls = Arc::new(AtomicUsize::new(0));
    let attempts = Arc::clone(&calls);
    let tracker = FlowTracker::new(move |logs: &[NewConnectionLog]| {
        assert!(logs.len() <= 128);
        if attempts.fetch_add(1, Ordering::Relaxed) == 1 {
            return Err(store_error("second chunk rejected"));
        }
        saved.lock().unwrap().extend_from_slice(logs);
        Ok(())
    });
    let key = sample_key();
    tracker.on_opened(
        key,
        &FlowMeta {
            pid: 42,
            process: None,
            open_ts: 0,
            cookie: None,
            if_index: None,
        },
    );
    let log = FlowTracker::<StoreFlowAdapter>::build_connection_log(
        tracker.active.lock().get(&key).unwrap(),
    );
    for id in 1..=300 {
        let mut log = log.clone();
        log.conn_id = id;
        tracker.push_pending_log(log);
    }
    assert!(tracker.flush().is_err());
    assert_eq!(writes.lock().unwrap().len(), 128);
    assert_eq!(tracker.pending.lock().len(), 172);
    tracker.flush().unwrap();
    let writes = writes.lock().unwrap();
    assert_eq!(writes.len(), 300);
    assert_eq!(
        writes
            .iter()
            .map(|log| log.conn_id)
            .collect::<HashSet<_>>()
            .len(),
        300
    );
}

#[test]
fn closing_after_an_active_flush_does_not_double_count() {
    let writes = Arc::new(StdMutex::new(Vec::new()));
    let writes_clone = Arc::clone(&writes);
    let tracker = FlowTracker::new(move |logs: &[NewConnectionLog]| {
        writes_clone.lock().expect("lock").extend_from_slice(logs);
        Ok(())
    });
    let key = sample_key();
    let meta = FlowMeta {
        pid: 100,
        process: None,
        open_ts: 0,
        cookie: None,
        if_index: None,
    };
    tracker.handle_event(&FlowEvent::Opened(key, meta.clone()));
    tracker.handle_event(&FlowEvent::Bytes(
        key,
        ByteDelta {
            sent: 100,
            received: 200,
        },
    ));
    tracker.flush_active_flows().expect("active flush");
    tracker.handle_event(&FlowEvent::Closed(key, meta));
    tracker.flush().expect("close flush");

    let writes = writes.lock().expect("lock");
    assert_eq!(writes.len(), 2, "bytes plus the close marker");
    assert_eq!(writes[0].bytes_sent, 100);
    assert_eq!(writes[0].bytes_received, 200);
    assert!(!writes[0].is_close);
    assert_eq!(
        writes[1].bytes_sent, 0,
        "the close must not repeat flushed bytes"
    );
    assert_eq!(writes[1].bytes_received, 0);
    assert!(writes[1].is_close);
    assert_eq!(writes[1].conn_id, writes[0].conn_id);
}

#[test]
fn prefer_dst_domain_keeps_strength_ordering() {
    assert_eq!(
        antiwire_store::prefer_dst_domain("a.example", "b.example"),
        "a.example"
    );
    assert_eq!(
        antiwire_store::prefer_dst_domain("203.0.113.5", "b.example"),
        "b.example",
        "a resolved name replaces an IP placeholder"
    );
    assert_eq!(
        antiwire_store::prefer_dst_domain("a.example", ""),
        "a.example"
    );
    assert_eq!(
        antiwire_store::prefer_dst_domain("", "a.example"),
        "a.example"
    );
    assert_eq!(
        antiwire_store::prefer_dst_domain("a.example (inferred)", "a.example"),
        "a.example",
        "confirmed evidence upgrades an inferred name"
    );
    assert_eq!(
        antiwire_store::prefer_dst_domain("a.example", "a.example (inferred)"),
        "a.example",
        "inferred evidence never downgrades a confirmed name"
    );
    assert_eq!(
        antiwire_store::prefer_dst_domain("a.example (inferred)", "b.example (inferred)"),
        "a.example (inferred)",
        "an inferred name does not replace another inferred name"
    );
}

#[test]
fn evict_idle_finalizes_stale_flows_and_keeps_fresh_ones() {
    let writes = Arc::new(StdMutex::new(Vec::new()));
    let writes_clone = Arc::clone(&writes);
    let tracker = FlowTracker::new(move |logs: &[NewConnectionLog]| {
        writes_clone.lock().expect("lock").extend_from_slice(logs);
        Ok(())
    });
    let meta = |pid| FlowMeta {
        pid,
        process: None,
        open_ts: 0,
        cookie: None,
        if_index: None,
    };
    let stale_key = sample_key();
    let fresh_key = FlowKey {
        local_port: 50_001,
        ..sample_key()
    };

    tracker.handle_event(&FlowEvent::Opened(stale_key, meta(100)));
    tracker.handle_event(&FlowEvent::Bytes(
        stale_key,
        ByteDelta {
            sent: 11,
            received: 22,
        },
    ));
    tracker.handle_event(&FlowEvent::Opened(fresh_key, meta(100)));
    tracker.handle_event(&FlowEvent::Bytes(
        fresh_key,
        ByteDelta {
            sent: 1,
            received: 2,
        },
    ));

    // Age only the first flow beyond the idle timeout.
    let stale = OffsetDateTime::now_utc() - Duration::from_secs(31 * 60);
    tracker
        .active
        .lock()
        .get_mut(&stale_key)
        .expect("stale flow")
        .last_seen = stale;

    tracker.evict_idle();
    tracker.flush().expect("flush evicted flow");

    assert!(tracker.active.lock().contains_key(&fresh_key));
    assert!(!tracker.active.lock().contains_key(&stale_key));
    let writes = writes.lock().expect("lock");
    assert_eq!(writes.len(), 1, "only the idle flow must be finalized");
    assert_eq!(writes[0].bytes_sent, 11);
    assert_eq!(writes[0].bytes_received, 22);
}

#[test]
fn evict_idle_keeps_a_quiet_tcp_connection_that_is_still_established() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let client =
        std::net::TcpStream::connect(listener.local_addr().expect("addr")).expect("connect");
    let accepted = listener.accept().expect("accept");
    let local = client.local_addr().expect("local");
    let remote = client.peer_addr().expect("peer");
    let tracker = FlowTracker::new(|_: &[NewConnectionLog]| Ok(()));
    let key = FlowKey {
        protocol: Protocol::Tcp,
        local_addr: local.ip(),
        local_port: local.port(),
        remote_addr: remote.ip(),
        remote_port: remote.port(),
    };
    tracker.handle_event(&FlowEvent::Opened(
        key,
        FlowMeta {
            pid: 100,
            process: None,
            open_ts: 0,
            cookie: None,
            if_index: None,
        },
    ));
    tracker
        .active
        .lock()
        .get_mut(&key)
        .expect("live flow")
        .last_seen = OffsetDateTime::now_utc() - Duration::from_secs(31 * 60);

    tracker.evict_idle();

    assert!(
        tracker.active.lock().contains_key(&key),
        "a TCP tuple still in the socket table must survive the idle sweep"
    );
    let _hold = (listener, client, accepted);
}

#[test]
fn evict_idle_still_finalizes_a_quiet_udp_flow() {
    let tracker = FlowTracker::new(|_: &[NewConnectionLog]| Ok(()));
    let key = FlowKey {
        protocol: Protocol::Udp,
        ..sample_key()
    };
    tracker.handle_event(&FlowEvent::Opened(
        key,
        FlowMeta {
            pid: 100,
            process: None,
            open_ts: 0,
            cookie: None,
            if_index: None,
        },
    ));
    tracker
        .active
        .lock()
        .get_mut(&key)
        .expect("udp flow")
        .last_seen = OffsetDateTime::now_utc() - Duration::from_secs(31 * 60);

    tracker.evict_idle();

    assert!(
        !tracker.active.lock().contains_key(&key),
        "UDP keeps the idle sweep even when no TCP socket matches"
    );
}

/// Once the active-flow map reaches its hard cap, opening another flow must
/// evict the oldest one and persist it rather than growing without bound.
#[test]
fn active_flow_cap_evicts_and_persists_the_oldest_flow() {
    let writes = Arc::new(StdMutex::new(Vec::new()));
    let writes_clone = Arc::clone(&writes);
    let tracker = FlowTracker::new(move |logs: &[NewConnectionLog]| {
        writes_clone.lock().expect("lock").extend_from_slice(logs);
        Ok(())
    });
    let cap = FLOW_ACTIVE_FLOWS_HARD_CAP;

    for index in 0..=cap {
        let key = FlowKey {
            protocol: Protocol::Tcp,
            local_addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            local_port: u16::try_from(index).expect("distinct port within the cap"),
            remote_addr: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5)),
            remote_port: 443,
        };
        tracker.handle_event(&FlowEvent::Opened(
            key,
            FlowMeta {
                pid: 100,
                process: None,
                open_ts: 0,
                cookie: None,
                if_index: None,
            },
        ));
    }

    assert_eq!(
        tracker.tracked_flow_count(),
        u32::try_from(cap).expect("cap")
    );
    tracker.flush().expect("flush evicted flow");
    assert_eq!(
        writes.lock().expect("lock").len(),
        1,
        "the evicted flow must be queued for persistence"
    );
}

#[test]
fn attribution_backlog_is_capped() {
    let mut tracker = FlowTracker::new(|_: &[NewConnectionLog]| Ok(()));
    tracker.attribution_cap = 1;
    let attribution = |to_app_id| ConnectionLogAttribution {
        conn_pid: 0,
        from_app_id: 1,
        to_app_id,
        protocol: "TCP".to_owned(),
        src_ip: "10.0.0.2".to_owned(),
        dst_ip: "203.0.113.5".to_owned(),
        dst_port: 443,
        conn_id: 7,
        conn_start: OffsetDateTime::UNIX_EPOCH,
    };

    tracker.queue_attribution(attribution(2));
    tracker.queue_attribution(attribution(3));

    assert_eq!(tracker.pending_attributions.lock().len(), 1);
    assert_eq!(tracker.shed_records.load(Ordering::Relaxed), 1);
}

/// An opening a second after the epoch, and what a lookup says of its
/// answer: complete five seconds later, and final then or not.
const NAMED_OPENING: Opening = Opening {
    at_ms: 1_000,
    process_started_ms: 0,
};

fn naming(lasting: bool) -> Naming {
    Naming {
        complete_at_ms: 6_000,
        lasting,
    }
}

#[test]
fn a_name_lookup_is_due_only_for_new_evidence_or_a_new_owner() {
    let mut lookup = NameLookup::default();
    assert!(lookup.due(7, 3), "a flow that was never looked up is due");
    assert_eq!(
        lookup.request(7, 3, NAMED_OPENING),
        NameRequest::replacing(NAMED_OPENING)
    );
    lookup.made(7, 3, naming(false));
    assert!(!lookup.due(7, 3));
    assert_eq!(lookup.request(7, 3, NAMED_OPENING), NameRequest::Keep);
    assert!(
        lookup.due(8, 3),
        "another process may have hints of its own"
    );
    assert!(lookup.due(7, 4), "so may another application");
    assert_eq!(
        lookup.request(8, 3, NAMED_OPENING),
        NameRequest::replacing(NAMED_OPENING),
        "the name was judged for another owner"
    );

    lookup.note_evidence(9_000);
    assert!(lookup.due(7, 3));
    assert_eq!(
        lookup.request(7, 3, NAMED_OPENING),
        NameRequest::adding(NAMED_OPENING),
        "evidence from after the answer was complete can only strengthen it"
    );
    lookup.made(7, 3, naming(false));
    assert!(!lookup.due(7, 3));
}

/// The regression this guards: a confirmed name was final from the lookup
/// that found it, so a hint from before the flow opened that arrived a
/// moment later could not correct it.
#[test]
fn evidence_noticed_while_a_name_is_provisional_replaces_it() {
    let mut lookup = NameLookup::default();
    lookup.made(7, 3, naming(true));
    lookup.note_evidence(5_999);
    assert!(lookup.due(7, 3), "a confirmed name is not final yet");
    assert_eq!(
        lookup.request(7, 3, NAMED_OPENING),
        NameRequest::replacing(NAMED_OPENING)
    );
    // What was noticed first decides, however late the lookup is made.
    lookup.note_evidence(60_000);
    assert_eq!(
        lookup.request(7, 3, NAMED_OPENING),
        NameRequest::replacing(NAMED_OPENING)
    );
}

#[test]
fn a_final_name_is_not_looked_up_again_for_new_evidence() {
    let mut lookup = NameLookup::default();
    lookup.made(7, 3, naming(true));
    lookup.note_evidence(6_000);
    assert!(!lookup.due(7, 3), "more evidence cannot change it");
    assert_eq!(lookup.request(7, 3, NAMED_OPENING), NameRequest::Keep);
    assert!(
        lookup.due(8, 3),
        "but it was final for that process, and another has its own hints"
    );
    lookup.made(8, 3, naming(false));
    lookup.note_evidence(6_000);
    assert!(lookup.due(8, 3), "a new owner's name is open again");
}

#[test]
fn a_closing_flow_is_looked_up_once_more_unless_its_name_is_final() {
    let request = |lookup: &NameLookup, now_ms| lookup.closing_request(7, 3, NAMED_OPENING, now_ms);
    let mut lookup = NameLookup::default();
    assert_eq!(
        request(&lookup, 9_000),
        NameRequest::replacing(NAMED_OPENING),
        "never looked up"
    );

    lookup.made(7, 3, naming(false));
    assert_eq!(
        request(&lookup, 9_000),
        NameRequest::adding(NAMED_OPENING),
        "an unconfirmed name may yet be confirmed"
    );
    assert_eq!(
        request(&lookup, 5_000),
        NameRequest::replacing(NAMED_OPENING),
        "closed while its name was provisional"
    );

    lookup.made(7, 3, naming(true));
    assert_eq!(request(&lookup, 9_000), NameRequest::Keep);
    assert_eq!(
        request(&lookup, 5_000),
        NameRequest::replacing(NAMED_OPENING)
    );
    lookup.note_evidence(5_000);
    assert_eq!(
        request(&lookup, 9_000),
        NameRequest::replacing(NAMED_OPENING),
        "evidence noticed while it was provisional is still to be looked at"
    );
}

fn queued_log(conn_id: i64) -> NewConnectionLog {
    NewConnectionLog {
        replace_domain: false,
        is_close: true,
        conn_pid: 7,
        conn_id,
        timestamp: OffsetDateTime::now_utc(),
        app_id: 1,
        app_path: String::new(),
        protocol: "TCP".to_owned(),
        src_ip: "10.0.0.2".to_owned(),
        src_port: 40_000,
        dst_ip: "203.0.113.9".to_owned(),
        dst_port: 443,
        dst_domain: String::new(),
        bytes_sent: 1,
        bytes_received: 1,
        action_taken: "ALLOWED".to_owned(),
        last_seen: OffsetDateTime::now_utc(),
        country_code: String::new(),
        isp: String::new(),
        blocklist_names: String::new(),
    }
}

/// Active-flow writes succeeding must not reset an outage the queued writes are in.
#[test]
fn a_working_active_flush_does_not_hide_a_failing_queue_flush() {
    let health = Arc::new(antiwire_events::CollectorHealth::default());
    let tracker = FlowTracker::new(|_: &[NewConnectionLog]| Ok(()))
        .with_collector_health(Arc::clone(&health));

    for _ in 0..FLOW_FLUSH_FAILURES_BEFORE_DEGRADED {
        tracker.note_active_flush_outcome(Ok(true));
        tracker.note_flush_outcome("retry", Err(store_error("rejected")));
    }
    assert!(!health.byte_accounting_available());
    assert!(!tracker.store_is_healthy());

    tracker.note_active_flush_outcome(Ok(true));
    assert!(
        !health.byte_accounting_available(),
        "only the failing path's own success may retract the outage"
    );

    tracker.note_flush_outcome("retry", Ok(true));
    assert!(health.byte_accounting_available());
    assert!(tracker.store_is_healthy());
}

/// One row the store always rejects must not hold back the rows queued behind it.
#[test]
fn a_row_the_store_keeps_rejecting_is_dropped_once_failures_persist() {
    const POISON: i64 = 666;
    let writes = Arc::new(StdMutex::new(Vec::<i64>::new()));
    let sink = Arc::clone(&writes);
    let tracker = FlowTracker::new(move |logs: &[NewConnectionLog]| {
        if logs.iter().any(|log| log.conn_id == POISON) {
            return Err(store_error("constraint failed"));
        }
        sink.lock()
            .expect("lock")
            .extend(logs.iter().map(|log| log.conn_id));
        Ok(())
    });
    for conn_id in [1, POISON, 2, 3] {
        tracker.push_pending_log(queued_log(conn_id));
    }

    for _ in 0..FLOW_FLUSH_FAILURES_BEFORE_DEGRADED - 1 {
        let result = tracker.flush();
        assert!(
            result.is_err(),
            "the whole chunk fails until isolation starts"
        );
        tracker.note_flush_outcome("retry", result);
    }
    assert!(writes.lock().expect("lock").is_empty());

    let result = tracker.flush();
    assert!(
        result.is_ok(),
        "isolation drops the rejected row: {result:?}"
    );
    assert_eq!(*writes.lock().expect("lock"), vec![1, 2, 3]);
    assert!(tracker.pending.lock().is_empty());
}

/// The regression this guards: two rejected rows side by side read as an
/// outage. Both went back to the front of the queue on every flush, nothing
/// behind them was ever written, and once the queue filled new records were
/// shed.
#[test]
fn rows_the_store_keeps_rejecting_side_by_side_are_dropped_together() {
    let writes = Arc::new(StdMutex::new(Vec::<i64>::new()));
    let sink = Arc::clone(&writes);
    let tracker = FlowTracker::new(move |logs: &[NewConnectionLog]| {
        if logs.iter().any(|log| log.conn_id >= 666) {
            return Err(store_error("constraint failed"));
        }
        sink.lock()
            .expect("lock")
            .extend(logs.iter().map(|log| log.conn_id));
        Ok(())
    });
    for conn_id in [1, 666, 667, 668, 2, 3] {
        tracker.push_pending_log(queued_log(conn_id));
    }

    for _ in 0..FLOW_FLUSH_FAILURES_BEFORE_DEGRADED - 1 {
        let result = tracker.flush();
        assert!(
            result.is_err(),
            "the whole chunk fails until isolation starts"
        );
        tracker.note_flush_outcome("retry", result);
    }
    assert!(writes.lock().expect("lock").is_empty());

    let result = tracker.flush();
    assert!(
        result.is_ok(),
        "isolation drops the rejected rows: {result:?}"
    );
    assert_eq!(*writes.lock().expect("lock"), vec![1, 2, 3]);
    assert!(tracker.pending.lock().is_empty());
}

/// Rows rejected with none accepted after them may be an outage that began
/// part way through, so they are kept, in order, for the next flush.
#[test]
fn rows_rejected_with_none_accepted_after_them_stay_queued() {
    let writes = Arc::new(StdMutex::new(Vec::<i64>::new()));
    let sink = Arc::clone(&writes);
    let tracker = FlowTracker::new(move |logs: &[NewConnectionLog]| {
        if logs.iter().any(|log| log.conn_id >= 666) {
            return Err(store_error("constraint failed"));
        }
        sink.lock()
            .expect("lock")
            .extend(logs.iter().map(|log| log.conn_id));
        Ok(())
    });
    for conn_id in [1, 666, 2, 667, 668] {
        tracker.push_pending_log(queued_log(conn_id));
    }
    for _ in 0..FLOW_FLUSH_FAILURES_BEFORE_DEGRADED {
        let result = tracker.flush();
        assert!(result.is_err());
        tracker.note_flush_outcome("retry", result);
    }
    assert_eq!(*writes.lock().expect("lock"), vec![1, 2]);
    let pending: Vec<i64> = tracker
        .pending
        .lock()
        .iter()
        .map(|log| log.conn_id)
        .collect();
    assert_eq!(pending, vec![667, 668]);
}

/// A store that takes its time to say no, as a busy database does, is not
/// asked about every queued row in turn: that would hold up every other
/// write for as long.
#[test]
fn slow_rejections_end_an_isolating_flush_early() {
    let single_row_writes = Arc::new(AtomicUsize::new(0));
    let attempts = Arc::clone(&single_row_writes);
    let tracker = FlowTracker::new(move |logs: &[NewConnectionLog]| {
        if logs.len() == 1 {
            attempts.fetch_add(1, Ordering::Relaxed);
            std::thread::sleep(antiwire_tuning::FLOW_ISOLATION_BUDGET);
        }
        Err(store_error("database is locked"))
    });
    for conn_id in 1..=4 {
        tracker.push_pending_log(queued_log(conn_id));
    }
    for _ in 0..FLOW_FLUSH_FAILURES_BEFORE_DEGRADED - 1 {
        let result = tracker.flush();
        tracker.note_flush_outcome("retry", result);
    }
    assert_eq!(single_row_writes.load(Ordering::Relaxed), 0);

    assert!(tracker.flush().is_err());
    assert_eq!(
        single_row_writes.load(Ordering::Relaxed),
        1,
        "one slow rejection uses up the time a flush has for them"
    );
    let pending: Vec<i64> = tracker
        .pending
        .lock()
        .iter()
        .map(|log| log.conn_id)
        .collect();
    assert_eq!(pending, vec![1, 2, 3, 4]);
}

/// When every row is rejected, isolation keeps them all: that is an outage.
#[test]
fn isolation_keeps_every_row_when_the_store_rejects_them_all() {
    let tracker = FlowTracker::new(|_: &[NewConnectionLog]| Err(store_error("disk full")));
    for conn_id in 1..=4 {
        tracker.push_pending_log(queued_log(conn_id));
    }
    for _ in 0..=FLOW_FLUSH_FAILURES_BEFORE_DEGRADED {
        let result = tracker.flush();
        tracker.note_flush_outcome("retry", result);
    }
    let pending: Vec<i64> = tracker
        .pending
        .lock()
        .iter()
        .map(|log| log.conn_id)
        .collect();
    assert_eq!(pending, vec![1, 2, 3, 4]);
}

/// Rejects re-attributions for one connection and records the rest.
struct PoisonedAttributionStore {
    applied: Arc<StdMutex<Vec<i64>>>,
}

impl crate::store::FlowStore for PoisonedAttributionStore {
    fn insert_batch(&self, _logs: &[NewConnectionLog]) -> crate::Result<()> {
        Ok(())
    }

    fn reattribute(&self, attribution: &ConnectionLogAttribution) -> crate::Result<()> {
        if attribution.conn_id == 666 {
            return Err(store_error("constraint failed"));
        }
        self.applied.lock().expect("lock").push(attribution.conn_id);
        Ok(())
    }
}

/// A queued move of connection `conn_id` to application `to_app_id`.
fn queued_attribution(conn_id: i64, to_app_id: i32) -> ConnectionLogAttribution {
    ConnectionLogAttribution {
        from_app_id: 1,
        to_app_id,
        protocol: "TCP".to_owned(),
        src_ip: "10.0.0.2".to_owned(),
        dst_ip: "203.0.113.9".to_owned(),
        dst_port: 443,
        conn_id,
        conn_pid: 7,
        conn_start: OffsetDateTime::now_utc(),
    }
}

/// One re-attribution the store always rejects must not hold back the queue.
#[test]
fn a_reattribution_the_store_keeps_rejecting_is_dropped_once_failures_persist() {
    let applied = Arc::new(StdMutex::new(Vec::new()));
    let tracker = FlowTracker::new(PoisonedAttributionStore {
        applied: Arc::clone(&applied),
    });
    for conn_id in [666, 1, 2] {
        tracker.queue_attribution(queued_attribution(conn_id, 2));
    }

    for _ in 0..FLOW_FLUSH_FAILURES_BEFORE_DEGRADED - 1 {
        let result = tracker.flush();
        assert!(
            result.is_err(),
            "the head entry blocks until isolation starts"
        );
        tracker.note_flush_outcome("retry", result);
    }
    assert!(applied.lock().expect("lock").is_empty());

    let result = tracker.flush();
    assert!(
        result.is_ok(),
        "isolation drops the rejected entry: {result:?}"
    );
    assert_eq!(*applied.lock().expect("lock"), vec![1, 2]);
    assert!(tracker.pending_attributions.lock().is_empty());
}

/// The regression this guards: as with connection logs, two rejected entries
/// side by side stopped the pass, so neither was ever dropped and nothing
/// behind them was applied.
#[test]
fn reattributions_the_store_keeps_rejecting_side_by_side_are_dropped_together() {
    let applied = Arc::new(StdMutex::new(Vec::new()));
    let tracker = FlowTracker::new(PoisonedAttributionStore {
        applied: Arc::clone(&applied),
    });
    // Two moves of the rejected connection, then two the store takes, then
    // one more it rejects with nothing after it.
    for (conn_id, to_app_id) in [(666, 2), (666, 3), (1, 2), (2, 2), (666, 4)] {
        tracker.queue_attribution(queued_attribution(conn_id, to_app_id));
    }

    for _ in 0..FLOW_FLUSH_FAILURES_BEFORE_DEGRADED - 1 {
        let result = tracker.flush();
        assert!(
            result.is_err(),
            "the head entry blocks until isolation starts"
        );
        tracker.note_flush_outcome("retry", result);
    }
    assert!(applied.lock().expect("lock").is_empty());

    assert!(
        tracker.flush().is_err(),
        "the entry rejected last is still owed"
    );
    assert_eq!(*applied.lock().expect("lock"), vec![1, 2]);
    let pending: Vec<i32> = tracker
        .pending_attributions
        .lock()
        .iter()
        .map(|attribution| attribution.to_app_id)
        .collect();
    assert_eq!(
        pending,
        vec![4],
        "an entry rejected with none accepted after it may be an outage"
    );
}
