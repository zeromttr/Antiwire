//! Network mapping tests, over a scanner that never touches the network.

use std::sync::Arc;
use std::time::Duration;

use antiwire_events::{
    AlertKind, AlertPublisher, NotificationHub, NotificationSubscription, Severity,
};
use antiwire_netmap::{NetworkDeviceSnapshot, NetworkInterfaceRange, ScanError};
use antiwire_platform::DataPaths;
use antiwire_store::{NetworkDeviceWatch, NetworkScanRange, Store};
use parking_lot::Mutex;
use time::macros::datetime;
use tokio_util::sync::CancellationToken;

use super::{
    valid_watch_interval, watch_is_due, watch_matches, DeviceWatchRequest, NetworkMappingWorker,
    NetworkMappingWorkerError, NetworkScanner,
};
use crate::context::ServiceContext;
use crate::settings_feed::SettingsFeed;

/// Answers every scan with `devices`, or waits until cancelled when `hold`.
#[derive(Default)]
struct FakeScanner {
    devices: Mutex<Vec<NetworkDeviceSnapshot>>,
    hold: bool,
}

#[async_trait::async_trait]
impl NetworkScanner for FakeScanner {
    async fn scan(
        &self,
        _ranges: &[String],
        cancellation: &CancellationToken,
    ) -> Result<Vec<NetworkDeviceSnapshot>, ScanError> {
        if self.hold {
            cancellation.cancelled().await;
            return Err(ScanError::Cancelled);
        }
        Ok(self.devices.lock().clone())
    }

    async fn local_ranges(&self) -> Result<Vec<NetworkInterfaceRange>, ScanError> {
        Ok(vec![NetworkInterfaceRange {
            adapter_id: "eth0".to_owned(),
            cidr: "192.168.1.0/24".to_owned(),
        }])
    }
}

struct Harness {
    _dir: tempfile::TempDir,
    store: Arc<Store>,
    shutdown: CancellationToken,
    alerts: NotificationSubscription,
    worker: NetworkMappingWorker,
}

fn harness(scanner: FakeScanner) -> Harness {
    let dir = tempfile::tempdir().expect("temp dir");
    let data_paths = DataPaths::new(dir.path());
    let store = Arc::new(Store::open(data_paths.database()).expect("open store"));
    let publisher = AlertPublisher::unsaved(NotificationHub::with_capacity(8), None);
    let alerts = publisher.subscribe();
    let shutdown = CancellationToken::new();
    let context = ServiceContext {
        store: Arc::clone(&store),
        settings: SettingsFeed::load(Arc::clone(&store)).expect("feed"),
        alerts: publisher,
        data_paths,
        shutdown: shutdown.clone(),
    };
    let worker = NetworkMappingWorker::with_scanner(&context, None, Arc::new(scanner));
    Harness {
        _dir: dir,
        store,
        shutdown,
        alerts,
        worker,
    }
}

fn watch() -> NetworkDeviceWatch {
    NetworkDeviceWatch {
        id: 1,
        ip_address: "192.168.1.7".to_owned(),
        mac_address: "00:1B:63:00:00:01".to_owned(),
        adapter_id: String::new(),
        cidr: String::new(),
        interval_minutes: 5,
        enabled: true,
        present: true,
        baseline_established: true,
        last_checked: datetime!(2026-08-03 12:00:00 UTC),
    }
}

fn device(ip: &str, mac: &str) -> NetworkDeviceSnapshot {
    NetworkDeviceSnapshot {
        ip_address: ip.to_owned(),
        mac_address: mac.to_owned(),
        vendor: String::new(),
        hostname: String::new(),
        is_online: true,
    }
}

async fn wait_until_idle(worker: &NetworkMappingWorker) {
    for _ in 0..200 {
        if !worker.snapshot().scan_in_progress && worker.inner.scan.lock().await.is_none() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    panic!("the scan did not finish");
}

#[test]
fn only_supported_presence_intervals_are_accepted() {
    for interval in [1, 5, 10, 30, 60] {
        assert!(valid_watch_interval(interval));
    }
    for interval in [0, 2, 15, 61] {
        assert!(!valid_watch_interval(interval));
    }
}

#[test]
fn presence_check_is_due_at_the_configured_interval() {
    let watch = watch();
    assert!(!watch_is_due(&watch, datetime!(2026-08-03 12:04:59 UTC)));
    assert!(watch_is_due(&watch, datetime!(2026-08-03 12:05:00 UTC)));
}

#[test]
fn a_watch_matches_either_ip_or_mac() {
    assert!(watch_matches(
        &watch(),
        &device("192.168.1.99", "00:1b:63:00:00:01")
    ));
}

#[tokio::test]
async fn a_scan_saves_the_inventory_and_reports_it() {
    let scanner = FakeScanner::default();
    scanner
        .devices
        .lock()
        .push(device("192.168.1.20", "00:1B:63:00:00:02"));
    let h = harness(scanner);

    h.worker.start_scan(Vec::new()).await.expect("start");
    wait_until_idle(&h.worker).await;

    assert_eq!(h.worker.snapshot().devices.len(), 1);
    let overview = h.worker.overview().await.expect("overview");
    assert_eq!(overview.devices.len(), 1);
    assert_eq!(overview.scan_ranges[0].cidr, "192.168.1.0/24");
    assert!(
        overview.scan_ranges[0].id < 0,
        "a detected range is not saved"
    );
}

#[tokio::test]
async fn clearing_waits_for_no_scan_and_shutdown_cancels_one() {
    let h = harness(FakeScanner {
        hold: true,
        ..FakeScanner::default()
    });
    h.worker.start_scan(Vec::new()).await.expect("start");

    assert!(!h.worker.clear_devices().await.expect("refused"));
    assert!(matches!(
        h.worker.start_scan(Vec::new()).await,
        Err(NetworkMappingWorkerError::Busy)
    ));

    h.shutdown.cancel();
    tokio::time::timeout(Duration::from_secs(1), h.worker.shutdown())
        .await
        .expect("shutdown cancels the running scan");
    assert!(matches!(
        h.worker.start_scan(Vec::new()).await,
        Err(NetworkMappingWorkerError::ShuttingDown)
    ));
}

#[tokio::test]
async fn watches_are_validated_before_they_are_saved() {
    let h = harness(FakeScanner::default());
    let request = |ip: &str, mac: &str, interval| DeviceWatchRequest {
        ip_address: ip.to_owned(),
        mac_address: mac.to_owned(),
        interval_minutes: interval,
        enabled: true,
        ..DeviceWatchRequest::default()
    };

    for invalid in [
        request("", "", 5),
        request("not-an-ip", "", 5),
        request("", "zz:zz", 5),
        request("192.168.1.7", "", 7),
    ] {
        assert!(matches!(
            h.worker.save_device_watch(invalid).await,
            Err(NetworkMappingWorkerError::Invalid(_))
        ));
    }
    let id = h
        .worker
        .save_device_watch(request("192.168.1.7", "00-1b-63-00-00-01", 5))
        .await
        .expect("valid");
    assert!(matches!(
        h.worker
            .save_device_watch(request("192.168.1.7", "", 5))
            .await,
        Err(NetworkMappingWorkerError::AlreadyWatched)
    ));

    let saved = h.store.list_device_watches().expect("watches");
    assert_eq!(saved.len(), 1);
    assert_eq!(saved[0].id, id);
    assert_eq!(saved[0].mac_address, "00:1B:63:00:00:01");
    assert_eq!(
        h.worker.inner.watches.read().len(),
        1,
        "the cache follows the store"
    );
    h.worker.remove_device_watch(id).await.expect("remove");
    assert!(h.worker.inner.watches.read().is_empty());
}

#[tokio::test]
async fn scan_ranges_are_validated_and_ids_required() {
    let h = harness(FakeScanner::default());

    assert!(h
        .worker
        .save_scan_range(NetworkScanRange {
            id: 0,
            adapter_id: String::new(),
            cidr: "0.0.0.0/0".to_owned(),
        })
        .await
        .is_err());
    assert!(matches!(
        h.worker.remove_scan_range(0).await,
        Err(NetworkMappingWorkerError::Invalid(_))
    ));
}

#[tokio::test]
async fn an_established_watch_that_disappears_raises_an_alert() {
    let mut h = harness(FakeScanner::default());
    let mut watched = watch();
    watched.id = h.store.insert_device_watch(&watched).expect("insert watch");

    h.worker
        .apply_watch_results(&[watched], &[], datetime!(2026-08-03 12:05:00 UTC))
        .await
        .expect("apply disconnected result");

    let alert = h.alerts.recv().await.expect("presence alert");
    assert_eq!(alert.kind, AlertKind::NetworkDeviceDisconnected);
    assert_eq!(alert.severity, Severity::Warning);
    assert!(alert.message.contains("192.168.1.7"));
}
