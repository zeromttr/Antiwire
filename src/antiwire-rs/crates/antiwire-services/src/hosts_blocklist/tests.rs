//! Hosts blocklist service tests, over a fake fetcher and a real engine.

use std::sync::Arc;

use antiwire_downloader::{DownloadError, HostsDownloadItem, HostsDownloadOutcome};
use antiwire_events::{AlertKind, AlertPublisher, NotificationHub, NotificationSubscription};
use antiwire_platform::DataPaths;
use antiwire_policy::{RuleEngine, Verdict};
use antiwire_store::{DaemonSetting, Store};
use parking_lot::{Mutex, RwLock};
use tokio_util::sync::CancellationToken;

use super::{HostsBlocklistService, HostsFetcher};
use crate::blocklist_target::BlocklistTarget;
use crate::context::ServiceContext;
use crate::settings_feed::SettingsFeed;
use crate::sync_runner::Trigger;

/// Writes `blocked-<name>.test` into each requested cache, or fails the
/// lists a test names.
#[derive(Default)]
struct FakeFetcher {
    failing: Mutex<Vec<String>>,
    requested: Mutex<Vec<String>>,
}

#[async_trait::async_trait]
impl HostsFetcher for FakeFetcher {
    async fn fetch(&self, items: &[HostsDownloadItem]) -> Vec<HostsDownloadOutcome> {
        items
            .iter()
            .map(|item| {
                self.requested.lock().push(item.name.clone());
                let result = if self.failing.lock().contains(&item.name) {
                    Err(DownloadError::Refused("scripted failure".to_owned()))
                } else {
                    std::fs::write(&item.dest_path, format!("blocked-{}.test\n", item.name))
                        .map(|()| true)
                        .map_err(DownloadError::Io)
                };
                HostsDownloadOutcome {
                    name: item.name.clone(),
                    result,
                }
            })
            .collect()
    }
}

struct Harness {
    dir: tempfile::TempDir,
    store: Arc<Store>,
    feed: SettingsFeed,
    engine: Arc<RwLock<RuleEngine>>,
    fetcher: Arc<FakeFetcher>,
    alerts: NotificationSubscription,
    service: HostsBlocklistService,
}

impl Harness {
    fn gate_armed(&self) -> bool {
        self.engine.boot_gate_armed()
    }

    fn blocks(&self, domain: &str) -> bool {
        self.engine.read().evaluate_domain(domain) == Some(Verdict::Block)
    }

    fn cache(&self, name: &str) -> std::path::PathBuf {
        DataPaths::new(self.dir.path())
            .blocklists_dir()
            .join(format!("{name}.txt"))
    }

    fn select(&self, enabled: bool, lists: &str) -> (DaemonSetting, DaemonSetting) {
        self.feed
            .modify(|saved| {
                Ok(DaemonSetting {
                    hosts_blocklist_enabled: enabled,
                    hosts_blocklist_selected_lists: lists.to_owned(),
                    hosts_blocklist_custom_urls: String::new(),
                    ..saved.clone()
                })
            })
            .expect("save settings")
    }
}

/// A service selecting `lists`, with the boot gate armed for them.
fn harness(lists: &str) -> Harness {
    let dir = tempfile::tempdir().expect("tempdir");
    let data_paths = DataPaths::new(dir.path());
    data_paths.ensure_blocklists_dir().expect("blocklists dir");
    let store = Arc::new(Store::open(data_paths.database()).expect("open"));
    let feed = SettingsFeed::load(Arc::clone(&store)).expect("feed");
    let publisher = AlertPublisher::unsaved(NotificationHub::with_capacity(16), None);
    let alerts = publisher.subscribe();
    let context = ServiceContext {
        store: Arc::clone(&store),
        settings: feed.clone(),
        alerts: publisher,
        data_paths,
        shutdown: CancellationToken::new(),
    };
    let engine = Arc::new(RwLock::new(RuleEngine::new()));
    let fetcher = Arc::new(FakeFetcher::default());
    let service = HostsBlocklistService::with_fetcher(
        &context,
        Arc::clone(&engine) as Arc<dyn BlocklistTarget>,
        Arc::clone(&fetcher) as Arc<dyn HostsFetcher>,
    );
    let harness = Harness {
        dir,
        store,
        feed,
        engine,
        fetcher,
        alerts,
        service,
    };
    harness.select(true, lists);
    harness.service.inner.arm_boot_gate(&harness.feed.current());
    harness
}

#[tokio::test]
async fn a_cached_list_is_published_and_lifts_the_boot_gate() {
    let h = harness("hagezi_light");
    std::fs::write(h.cache("hagezi_light"), "blocked-cache.test\n").expect("cache");
    assert!(h.gate_armed());

    let needs_sync = h
        .service
        .inner
        .reload_from_cache(false)
        .await
        .expect("reload");

    assert!(!needs_sync);
    assert!(h.blocks("blocked-cache.test"));
    assert_eq!(
        h.engine.read().matching_blocklists("blocked-cache.test"),
        vec!["hagezi_light".to_owned()]
    );
    assert!(!h.gate_armed(), "a complete load lifts the boot gate");
}

#[tokio::test]
async fn a_missing_cache_keeps_dns_fail_closed() {
    let h = harness("hagezi_light");

    let needs_sync = h
        .service
        .inner
        .reload_from_cache(false)
        .await
        .expect("reload");

    assert!(needs_sync);
    assert!(
        h.gate_armed(),
        "missing caches keep the gate until they sync"
    );
}

#[tokio::test]
async fn an_unreadable_cache_is_queued_for_repair() {
    // An existing but invalid cache used to be skipped by every repair sync,
    // which only fetched files that did not exist.
    let h = harness("hagezi_light");
    let cache = h.cache("hagezi_light");
    std::fs::write(&cache, [0xff, 0xfe, b'\n']).expect("invalid cache");
    let sidecar = cache.with_extension("sha256");
    std::fs::write(&sidecar, "abc  hagezi_light.txt\n").expect("sidecar");

    assert!(h
        .service
        .inner
        .reload_from_cache(false)
        .await
        .expect("reload"));

    assert!(h.gate_armed());
    assert!(h.service.inner.cache_needs_repair(&cache));
    assert!(
        !sidecar.exists(),
        "a stale hash sidecar would let the repair skip the download"
    );
    Arc::clone(&h.service.inner)
        .sync(Trigger::Automatic, true)
        .await
        .expect("repair sync");
    assert_eq!(*h.fetcher.requested.lock(), vec!["hagezi_light".to_owned()]);
    assert!(h.blocks("blocked-hagezi_light.test"));
    assert!(!h.service.inner.cache_needs_repair(&cache));
}

#[tokio::test]
async fn a_sync_downloads_publishes_records_and_lifts_the_gate() {
    let mut h = harness("hagezi_light");

    h.service.sync_now().await.expect("sync");

    assert!(h.blocks("blocked-hagezi_light.test"));
    assert!(!h.gate_armed());
    let saved = h.store.get_settings().expect("settings");
    assert_eq!(
        saved.hosts_blocklist_last_updated,
        h.feed.current().hosts_blocklist_last_updated,
        "the sync time is saved and published together"
    );
    assert_eq!(
        h.alerts.recv().await.expect("alert").kind,
        AlertKind::HostsSync
    );
}

#[tokio::test]
async fn a_failed_list_is_reported_and_backs_off_automatic_syncs() {
    let mut h = harness("hagezi_light");
    h.fetcher.failing.lock().push("hagezi_light".to_owned());

    let error = h.service.sync_now().await.expect_err("download fails");

    assert!(error.contains("hagezi_light"), "{error}");
    let alert = h.alerts.recv().await.expect("alert");
    assert_eq!(alert.kind, AlertKind::HostsSyncFailed);
    assert!(
        !h.gate_armed(),
        "a failed sync must not leave DNS fail-closed"
    );

    h.service.inner.arm_boot_gate(&h.feed.current());
    h.fetcher.requested.lock().clear();
    Arc::clone(&h.service.inner)
        .sync(Trigger::Automatic, false)
        .await
        .expect("deferred");
    assert!(h.fetcher.requested.lock().is_empty(), "deferred, not run");
    assert!(
        !h.gate_armed(),
        "a deferred sync must not leave DNS fail-closed until restart"
    );
}

#[tokio::test]
async fn a_rebuild_publishes_the_saved_lists_not_the_ones_it_started_with() {
    // A refresh holds the settings from before its download; a disable saved
    // meanwhile must win when it rebuilds.
    let h = harness("hagezi_light");
    std::fs::write(h.cache("hagezi_light"), "blocked-cache.test\n").expect("cache");
    h.service
        .inner
        .reload_from_cache(false)
        .await
        .expect("reload");
    assert!(h.blocks("blocked-cache.test"));

    h.select(false, "hagezi_light");
    h.service
        .inner
        .reload_from_cache(false)
        .await
        .expect("reload");

    assert!(!h.blocks("blocked-cache.test"));
}

#[tokio::test]
async fn settings_changes_arm_and_lift_the_gate() {
    let h = harness("hagezi_light");
    h.service.inner.blocklist.clear_boot_gate();

    let (previous, updated) = h.select(false, "hagezi_light");
    h.service
        .on_settings_changed(&previous, &updated)
        .await
        .expect("disable");
    assert!(!h.gate_armed());

    let (previous, updated) = h.select(true, "hagezi_light");
    h.service
        .on_settings_changed(&previous, &updated)
        .await
        .expect("enable");
    assert!(
        h.gate_armed(),
        "switching the lists on holds DNS until they load"
    );

    let (previous, updated) = h.select(true, "hagezi_light");
    h.service
        .on_settings_changed(&previous, &updated)
        .await
        .expect("unchanged");
    assert!(h.gate_armed(), "an unrelated save does not touch the gate");
}

#[tokio::test]
async fn a_sync_with_no_lists_does_not_record_a_sync() {
    let h = harness("");
    let before = h.feed.current().hosts_blocklist_last_updated;

    h.service.sync_now().await.expect("sync with no lists");

    assert_eq!(h.feed.current().hosts_blocklist_last_updated, before);
    assert!(h.fetcher.requested.lock().is_empty());
}

#[test]
fn the_selection_changes_only_with_its_own_settings() {
    let previous = DaemonSetting::default();
    let mut next = previous.clone();
    next.geoip_enabled = !next.geoip_enabled;
    assert!(!super::blocklist_selection_changed(&previous, &next));
    next.hosts_blocklist_selected_lists = "hagezi_multi".to_owned();
    assert!(super::blocklist_selection_changed(&previous, &next));
}
