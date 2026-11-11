//! `GeoIP` service tests, over a source that never touches the network.

use std::path::Path;
use std::sync::Arc;

use antiwire_events::{AlertKind, AlertPublisher, NotificationHub, NotificationSubscription};
use antiwire_geo::GeoIpLookup;
use antiwire_platform::DataPaths;
use antiwire_store::{DaemonSetting, Store};
use arc_swap::ArcSwap;
use parking_lot::Mutex;
use time::OffsetDateTime;
use tokio_util::sync::CancellationToken;

use super::{refresh_due, GeoDatabaseService, GeoDatabaseSource, CITY_MMDB_FILENAME};
use crate::context::ServiceContext;
use crate::settings_feed::SettingsFeed;

/// Writes `body` as the download, or fails with `error`.
struct FakeSource {
    body: Vec<u8>,
    error: Mutex<Option<String>>,
}

#[async_trait::async_trait]
impl GeoDatabaseSource for FakeSource {
    async fn download_latest(&self, dest: &Path) -> Result<String, String> {
        if let Some(error) = self.error.lock().clone() {
            return Err(error);
        }
        std::fs::write(dest, &self.body).map_err(|error| error.to_string())?;
        Ok("1.0.0".to_owned())
    }
}

fn gzip(bytes: &[u8]) -> Vec<u8> {
    use std::io::Write;
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    encoder.write_all(bytes).expect("compress");
    encoder.finish().expect("finish")
}

struct Harness {
    _dir: tempfile::TempDir,
    feed: SettingsFeed,
    geo: Arc<ArcSwap<GeoIpLookup>>,
    source: Arc<FakeSource>,
    alerts: NotificationSubscription,
    service: GeoDatabaseService,
}

impl Harness {
    fn set_enabled(&self, enabled: bool) -> (DaemonSetting, DaemonSetting) {
        self.feed
            .modify(|saved| {
                Ok(DaemonSetting {
                    geoip_enabled: enabled,
                    ..saved.clone()
                })
            })
            .expect("save settings")
    }
}

fn harness() -> Harness {
    let dir = tempfile::tempdir().expect("temp dir");
    let data_paths = DataPaths::new(dir.path());
    let store = Arc::new(Store::open(data_paths.database()).expect("open store"));
    let feed = SettingsFeed::load(Arc::clone(&store)).expect("feed");
    let publisher = AlertPublisher::unsaved(NotificationHub::with_capacity(8), None);
    let alerts = publisher.subscribe();
    let context = ServiceContext {
        store,
        settings: feed.clone(),
        alerts: publisher,
        data_paths,
        shutdown: CancellationToken::new(),
    };
    let geo = Arc::new(ArcSwap::from_pointee(GeoIpLookup::new()));
    let source = Arc::new(FakeSource {
        // A valid archive of something that is not an MMDB, so the install
        // decompresses it and then refuses it.
        body: gzip(b"not a database"),
        error: Mutex::new(None),
    });
    let service = GeoDatabaseService::with_source(
        &context,
        Arc::clone(&geo),
        Arc::clone(&source) as Arc<dyn GeoDatabaseSource>,
    );
    Harness {
        _dir: dir,
        feed,
        geo,
        source,
        alerts,
        service,
    }
}

#[test]
fn disabling_swaps_in_an_empty_lookup() {
    let h = harness();
    h.set_enabled(true);
    let before = h.geo.load_full();

    let (previous, updated) = h.set_enabled(false);
    h.service.on_settings_changed(&previous, &updated);

    let after = h.geo.load_full();
    assert!(!Arc::ptr_eq(&before, &after), "lookup was not replaced");
    assert!(!after.is_loaded());
}

#[test]
fn a_load_that_finishes_after_a_disable_is_not_published() {
    let h = harness();
    let (previous, updated) = h.set_enabled(false);
    h.service.on_settings_changed(&previous, &updated);
    let cleared = h.geo.load_full();

    // Stands in for a load an enable started before the disable.
    assert!(!h.service.inner.publish_if_enabled(GeoIpLookup::new()));
    assert!(Arc::ptr_eq(&cleared, &h.geo.load_full()));

    h.set_enabled(true);
    assert!(h.service.inner.publish_if_enabled(GeoIpLookup::new()));
    assert!(!Arc::ptr_eq(&cleared, &h.geo.load_full()));
}

#[test]
fn refresh_is_due_when_missing_unloadable_or_old() {
    let dir = tempfile::tempdir().expect("temp dir");
    let path = dir.path().join(CITY_MMDB_FILENAME);
    let now = OffsetDateTime::now_utc();
    let fresh = DaemonSetting {
        geoip_database_last_updated: now,
        ..DaemonSetting::default()
    };

    assert!(refresh_due(&path, true, &fresh, now), "missing");
    std::fs::write(&path, b"placeholder").expect("write placeholder");
    assert!(!refresh_due(&path, true, &fresh, now), "fresh and loaded");
    // A truncated or corrupt file with a recent sync used to disable
    // enrichment until the quarterly refresh.
    assert!(
        refresh_due(&path, false, &fresh, now),
        "on disk but not loaded"
    );
    let refresh_age =
        time::Duration::seconds_f64(antiwire_tuning::GEOIP_DATABASE_REFRESH_INTERVAL.as_secs_f64());
    assert!(refresh_due(&path, true, &fresh, now + refresh_age), "old");
}

#[tokio::test]
async fn a_download_that_does_not_open_is_reported_and_never_installed() {
    let mut h = harness();
    h.set_enabled(true);

    let error = h.service.sync_now().await.expect_err("install refuses it");

    assert!(error.contains("failed to open"), "{error}");
    assert!(!h.geo.load().is_loaded());
    let alert = h.alerts.recv().await.expect("alert");
    assert_eq!(alert.kind, AlertKind::GeoIpSyncFailed);
}

#[tokio::test]
async fn a_failed_download_backs_off_automatic_syncs() {
    let h = harness();
    h.set_enabled(true);
    *h.source.error.lock() = Some("mirror down".to_owned());

    h.service.sync_now().await.expect_err("download fails");

    assert!(h.service.inner.syncs.deferred(OffsetDateTime::now_utc()));
}

#[tokio::test]
async fn nothing_is_downloaded_while_enrichment_is_off() {
    let h = harness();
    h.set_enabled(false);
    *h.source.error.lock() = Some("must not be called".to_owned());

    h.service.sync_now().await.expect("nothing to do");
}
