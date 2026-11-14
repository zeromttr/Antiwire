//! Community hosts blocklists: downloaded to a disk cache and published to
//! the policy engine, with DNS held fail-closed until the selected lists load.

mod cache;
mod fetcher;
#[cfg(test)]
mod tests;

use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use antiwire_downloader::{hashed_cache_needs_revalidation, HostsDownloadItem};
use antiwire_events::{Alert, AlertKind, AlertPublisher, Severity};
use antiwire_platform::DataPaths;
use antiwire_policy::{
    blocklist_sync_allow_hosts, blocklist_sync_interval_hours, estimate_blocklist_size,
    is_builtin_list_id, resolve_sync_targets, BlocklistBuilder, SyncTarget,
};
use antiwire_store::DaemonSetting;
use time::OffsetDateTime;
use tokio::sync::Mutex;
use tracing::{info, warn};

use crate::background::BackgroundTasks;
use crate::blocklist_target::BlocklistTarget;
use crate::context::ServiceContext;
use crate::settings_feed::SettingsFeed;
use crate::sync_runner::{FailurePolicy, SyncOutcome, SyncRunner, Trigger};

use cache::{
    cache_path, load_cache_into_builder, parse_system_hosts, prune_orphan_cache_files,
    remove_cache_sidecars, CacheLoad,
};
pub use fetcher::{HostsFetcher, HttpHostsFetcher};

/// Keeps the published hosts blocklist matching the selected lists.
///
/// It is the one owner of the blocklist and of the boot gate that holds DNS
/// fail-closed while selected lists are still loading.
pub struct HostsBlocklistService {
    inner: Arc<Inner>,
}

struct Inner {
    settings: SettingsFeed,
    alerts: AlertPublisher,
    data_paths: DataPaths,
    blocklist: Arc<dyn BlocklistTarget>,
    fetcher: Arc<dyn HostsFetcher>,
    /// Orders rebuilds, so the last one published reflects the last settings.
    rebuild_gate: Mutex<()>,
    syncs: SyncRunner,
    tasks: BackgroundTasks,
    initial_load_done: AtomicBool,
    /// Selected caches that exist but could not be read on the last rebuild.
    /// Repair syncs treat them as missing.
    unusable_caches: parking_lot::Mutex<HashSet<PathBuf>>,
}

/// Which syncs a scheduler tick should start, worked out off the runtime
/// because it reads cache files.
struct Due {
    full_sync: bool,
    hashed_refresh: bool,
    repair: bool,
}

impl HostsBlocklistService {
    /// A service that downloads over HTTP.
    #[must_use]
    pub fn new(context: &ServiceContext, blocklist: Arc<dyn BlocklistTarget>) -> Self {
        Self::with_fetcher(context, blocklist, Arc::new(HttpHostsFetcher::new()))
    }

    #[must_use]
    pub fn with_fetcher(
        context: &ServiceContext,
        blocklist: Arc<dyn BlocklistTarget>,
        fetcher: Arc<dyn HostsFetcher>,
    ) -> Self {
        Self {
            inner: Arc::new(Inner {
                settings: context.settings.clone(),
                alerts: context.alerts.clone(),
                data_paths: context.data_paths.clone(),
                blocklist,
                fetcher,
                rebuild_gate: Mutex::new(()),
                syncs: SyncRunner::new(
                    FailurePolicy {
                        kind: AlertKind::HostsSyncFailed,
                        title: "Hosts Sync Failed",
                        summary: "Failed to sync some blocklists",
                        backoff_base_minutes: antiwire_tuning::HOSTS_SYNC_BACKOFF_BASE_MINUTES,
                        backoff_cap_minutes: antiwire_tuning::HOSTS_SYNC_BACKOFF_CAP_MINUTES,
                    },
                    context.alerts.clone(),
                    context.shutdown.clone(),
                ),
                tasks: BackgroundTasks::new(context.shutdown.clone()),
                initial_load_done: AtomicBool::new(false),
                unusable_caches: parking_lot::Mutex::new(HashSet::new()),
            }),
        }
    }

    /// Holds DNS fail-closed for the saved settings, then loads the cached
    /// lists and keeps them current on a schedule.
    pub fn start(&self) {
        self.inner.arm_boot_gate(&self.inner.settings.current());
        let inner = Arc::clone(&self.inner);
        self.inner
            .tasks
            .every(antiwire_tuning::HOSTS_SCHEDULER_INTERVAL, move || {
                let inner = Arc::clone(&inner);
                async move { inner.tick().await }
            });
    }

    /// Waits for every task to stop once the daemon's shutdown has begun.
    pub async fn shutdown(&self) {
        self.inner.tasks.join().await;
    }

    /// Applies saved settings that changed from `previous` to `updated`:
    /// holds DNS fail-closed when the lists are switched on, lifts that when
    /// they are switched off, and rebuilds from the new selection.
    ///
    /// # Errors
    ///
    /// Why the blocklist could not be rebuilt. The boot gate is lifted, so
    /// DNS does not stay fail-closed.
    pub async fn on_settings_changed(
        &self,
        previous: &DaemonSetting,
        updated: &DaemonSetting,
    ) -> Result<(), String> {
        if !blocklist_selection_changed(previous, updated) {
            return Ok(());
        }
        if previous.hosts_blocklist_enabled != updated.hosts_blocklist_enabled {
            self.inner.arm_boot_gate(updated);
        }
        Arc::clone(&self.inner)
            .reload_or_trigger_sync()
            .await
            .map(|_| ())
    }

    /// Downloads every selected list now, ignoring any backoff.
    ///
    /// # Errors
    ///
    /// Names the lists that could not be downloaded, or why the sync could
    /// not run.
    pub async fn sync_now(&self) -> Result<(), String> {
        Arc::clone(&self.inner).sync(Trigger::Manual, false).await
    }
}

impl Inner {
    fn arm_boot_gate(&self, settings: &DaemonSetting) {
        if settings.hosts_blocklist_enabled {
            let hosts = blocklist_sync_allow_hosts(true, &settings.hosts_blocklist_custom_urls);
            self.blocklist.arm_boot_gate(hosts.into_iter().collect());
        } else {
            self.blocklist.clear_boot_gate();
        }
    }

    async fn tick(self: Arc<Self>) {
        if !self.initial_load_done.load(Ordering::SeqCst) {
            match Arc::clone(&self).reload_or_trigger_sync().await {
                Ok(needs_sync) => {
                    self.initial_load_done.store(true, Ordering::SeqCst);
                    if needs_sync {
                        return;
                    }
                }
                Err(error) => {
                    warn!(%error, "hosts blocklist load failed");
                    return;
                }
            }
        }

        let settings = self.settings.current();
        if !settings.hosts_blocklist_enabled {
            return;
        }
        let now = OffsetDateTime::now_utc();
        let backed_off = self.syncs.deferred(now);
        let inspector = Arc::clone(&self);
        let checked = Arc::clone(&settings);
        let due =
            tokio::task::spawn_blocking(move || inspector.due(&checked, now, backed_off)).await;
        let due = match due {
            Ok(due) => due,
            Err(error) => {
                warn!(%error, "hosts blocklist schedule check did not finish");
                return;
            }
        };

        if due.full_sync {
            info!("hosts blocklist update threshold exceeded; syncing lists");
            self.spawn_sync(false);
        } else if due.repair {
            self.spawn_sync(true);
        }
        if due.hashed_refresh {
            let inner = Arc::clone(&self);
            self.tasks
                .spawn(async move { inner.refresh_hashed_lists().await });
        }
    }

    /// Which syncs are due for `settings` at `now`. Blocking: inspects the
    /// cache files.
    fn due(&self, settings: &DaemonSetting, now: OffsetDateTime, backed_off: bool) -> Due {
        let scheduled = !settings
            .hosts_blocklist_update_frequency
            .eq_ignore_ascii_case("manual");
        let interval_hours =
            blocklist_sync_interval_hours(&settings.hosts_blocklist_update_frequency)
                .unwrap_or(24.0 * 7.0);
        let full_sync = scheduled
            && !backed_off
            && now - settings.hosts_blocklist_last_updated
                >= time::Duration::seconds_f64(interval_hours * 3600.0);
        let targets = targets(settings, false);
        let hashed_refresh = scheduled
            && targets.iter().any(|target| {
                !target.hash_urls().is_empty()
                    && hashed_cache_needs_revalidation(&self.cache_path(target), target.hash_urls())
            });
        let repair = !backed_off
            && targets
                .iter()
                .any(|target| self.cache_needs_repair(&self.cache_path(target)));
        Due {
            full_sync,
            hashed_refresh,
            repair,
        }
    }

    fn spawn_sync(self: &Arc<Self>, only_missing: bool) {
        let inner = Arc::clone(self);
        self.tasks.spawn(async move {
            if let Err(error) = inner.sync(Trigger::Automatic, only_missing).await {
                warn!(%error, "blocklist sync failed");
            }
        });
    }

    /// Rebuilds from the cache, and downloads what is missing in the
    /// background. Returns whether a download was needed.
    async fn reload_or_trigger_sync(self: Arc<Self>) -> Result<bool, String> {
        let needs_sync = match self.reload_from_cache(true).await {
            Ok(needs_sync) => needs_sync,
            Err(error) => {
                self.blocklist.clear_boot_gate();
                return Err(error);
            }
        };
        if needs_sync {
            self.spawn_sync(true);
        }
        Ok(needs_sync)
    }

    /// Downloads the selected lists, or only those whose cache is missing or
    /// unreadable, then rebuilds.
    async fn sync(self: Arc<Self>, trigger: Trigger, only_missing: bool) -> Result<(), String> {
        let inner = Arc::clone(&self);
        let outcome = self
            .syncs
            .run(trigger, || inner.download_and_rebuild(only_missing))
            .await;
        match &outcome {
            // The sync holding the gate lifts the boot gate when it ends.
            Ok(SyncOutcome::Coalesced) => {}
            Ok(SyncOutcome::Deferred(resume)) => {
                info!(%resume, "automatic blocklist sync deferred due to failure backoff");
                self.blocklist.clear_boot_gate();
            }
            // Every other end lifts it: success, failure, or shutdown. An
            // armed gate must never outlive the last attempt and leave DNS
            // fail-closed until restart.
            Ok(SyncOutcome::Ran | SyncOutcome::Cancelled) | Err(_) => {
                self.blocklist.clear_boot_gate();
            }
        }
        outcome.map(|_| ())
    }

    async fn download_and_rebuild(self: Arc<Self>, only_missing: bool) -> Result<(), String> {
        self.data_paths
            .ensure_blocklists_dir()
            .map_err(|error| error.to_string())?;
        let settings = self.settings.current();
        if !settings.hosts_blocklist_enabled {
            return Ok(());
        }
        let mut targets = targets(&settings, false);
        if only_missing {
            targets.retain(|target| self.cache_needs_repair(&self.cache_path(target)));
        }
        if targets.is_empty() {
            return Ok(());
        }

        let items: Vec<HostsDownloadItem> = targets
            .iter()
            .map(|target| self.download_item(target))
            .collect();
        for item in &items {
            info!(
                name = %item.name,
                mirror_count = item.urls.len(),
                primary_url = %item.urls[0],
                "downloading blocklist"
            );
        }
        let mut failures = Vec::new();
        for outcome in self.fetcher.fetch(&items).await {
            match outcome.result {
                Ok(_) => info!(name = %outcome.name, "blocklist synced"),
                Err(error) => {
                    warn!(name = %outcome.name, %error, "blocklist download failed");
                    failures.push(format!("{} ({error})", outcome.name));
                }
            }
        }

        self.reload_from_cache(true).await?;
        if failures.len() < targets.len() {
            let settings = self.settings.clone();
            tokio::task::spawn_blocking(move || {
                settings.record_hosts_blocklist_sync(OffsetDateTime::now_utc())
            })
            .await
            .map_err(|error| format!("settings save did not finish: {error}"))?
            .map_err(|error| error.to_string())?;
        }
        if !failures.is_empty() {
            return Err(failures.join("; "));
        }
        self.alerts.publish(Alert::new(
            AlertKind::HostsSync,
            Severity::Info,
            "Hosts Sync Success",
            "Successfully synced hosts blocklists.",
        ));
        Ok(())
    }

    /// Downloads hashed lists whose published hash changed, then rebuilds.
    /// A list that fails is logged; the next full sync reports it.
    async fn refresh_hashed_lists(self: Arc<Self>) {
        let inner = Arc::clone(&self);
        let outcome = self
            .syncs
            .run(Trigger::Automatic, || async move {
                let settings = inner.settings.current();
                if !settings.hosts_blocklist_enabled {
                    return Ok(());
                }
                let items: Vec<HostsDownloadItem> = targets(&settings, false)
                    .into_iter()
                    .filter(|target| {
                        !target.hash_urls().is_empty()
                            && hashed_cache_needs_revalidation(
                                &inner.cache_path(target),
                                target.hash_urls(),
                            )
                    })
                    .map(|target| inner.download_item(&target))
                    .collect();
                if items.is_empty() {
                    return Ok(());
                }
                let mut downloaded = false;
                for outcome in inner.fetcher.fetch(&items).await {
                    match outcome.result {
                        Ok(true) => {
                            info!(name = %outcome.name, "hashed blocklist updated");
                            downloaded = true;
                        }
                        Ok(false) => {}
                        Err(error) => {
                            warn!(name = %outcome.name, %error, "hashed blocklist refresh failed");
                        }
                    }
                }
                if downloaded {
                    inner.reload_from_cache(false).await?;
                }
                Ok(())
            })
            .await;
        if !matches!(outcome, Ok(SyncOutcome::Coalesced)) {
            self.blocklist.clear_boot_gate();
        }
        if let Err(error) = outcome {
            warn!(%error, "hashed blocklist refresh failed");
        }
    }

    /// Rebuilds the blocklist from the caches the current settings select,
    /// and returns whether any selected cache is missing or unreadable.
    ///
    /// The settings are read under `rebuild_gate`, never taken from the
    /// caller: a refresh that started before the user disabled or changed
    /// the lists must not republish the lists it started with.
    async fn reload_from_cache(&self, prune_orphans: bool) -> Result<bool, String> {
        let _rebuild = self.rebuild_gate.lock().await;
        let settings = self.settings.current();
        let enabled = settings.hosts_blocklist_enabled;
        let targets = if enabled {
            targets(&settings, prune_orphans)
        } else {
            self.blocklist.clear_boot_gate();
            Vec::new()
        };
        let prune_orphans = prune_orphans && enabled;
        let blocklists_dir = self.data_paths.blocklists_dir();
        let estimate = estimate_blocklist_size(&targets);
        let caches: Vec<(SyncTarget, PathBuf)> = targets
            .into_iter()
            .map(|target| {
                let path = self.cache_path(&target);
                (target, path)
            })
            .collect();

        let (prepared, needs_sync, unusable) = tokio::task::spawn_blocking(move || {
            if prune_orphans {
                let keep: Vec<PathBuf> = caches.iter().map(|(_, path)| path.clone()).collect();
                prune_orphan_cache_files(&blocklists_dir, &keep);
            }
            let mut builder = BlocklistBuilder::new(estimate);
            parse_system_hosts(&mut builder);
            let mut needs_sync = false;
            let mut unusable = HashSet::new();
            for (target, path) in caches {
                match load_cache_into_builder(&path, &target, &mut builder) {
                    CacheLoad::Loaded(count) => {
                        info!(name = %target.name(), count, "loaded blocklist into engine");
                    }
                    CacheLoad::Missing => needs_sync = true,
                    CacheLoad::Unusable => {
                        // The hash sidecars would let a hashed download skip a
                        // list whose remote hash still matches; without them
                        // the repair fetches it again.
                        remove_cache_sidecars(&path);
                        unusable.insert(path);
                        needs_sync = true;
                    }
                }
            }
            builder
                .prepare()
                .map(|prepared| (prepared, needs_sync, unusable))
                .map_err(str::to_owned)
        })
        .await
        .map_err(|error| format!("blocklist build did not finish: {error}"))??;

        *self.unusable_caches.lock() = unusable;
        self.blocklist.publish(prepared);
        info!(
            total_domains = self.blocklist.domain_count(),
            "blocklist engine updated"
        );
        // Selected caches still missing keep DNS fail-closed, so the sync that
        // fetches them finishes before anything resolves unfiltered.
        if !needs_sync {
            self.blocklist.clear_boot_gate();
        }
        Ok(needs_sync)
    }

    fn cache_needs_repair(&self, path: &std::path::Path) -> bool {
        !path.exists() || self.unusable_caches.lock().contains(path)
    }

    fn cache_path(&self, target: &SyncTarget) -> PathBuf {
        cache_path(&self.data_paths.blocklists_dir(), target)
    }

    fn download_item(&self, target: &SyncTarget) -> HostsDownloadItem {
        HostsDownloadItem {
            name: target.name().to_owned(),
            urls: target.urls().to_vec(),
            hash_urls: target.hash_urls().to_vec(),
            dest_path: self.cache_path(target),
            parser_mode: target.parser_mode(),
        }
    }
}

/// The lists `settings` select.
fn targets(settings: &DaemonSetting, warn_unknown: bool) -> Vec<SyncTarget> {
    if warn_unknown {
        for list in settings
            .hosts_blocklist_selected_lists
            .split(',')
            .map(str::trim)
            .filter(|list| !list.is_empty() && !is_builtin_list_id(list))
        {
            warn!(%list, "ignoring unknown blocklist name");
        }
    }
    resolve_sync_targets(
        settings.hosts_blocklist_enabled,
        &settings.hosts_blocklist_selected_lists,
        &settings.hosts_blocklist_custom_urls,
    )
}

/// Whether the change from `previous` to `next` changes which lists apply.
fn blocklist_selection_changed(previous: &DaemonSetting, next: &DaemonSetting) -> bool {
    previous.hosts_blocklist_enabled != next.hosts_blocklist_enabled
        || previous.hosts_blocklist_selected_lists != next.hosts_blocklist_selected_lists
        || previous.hosts_blocklist_custom_urls != next.hosts_blocklist_custom_urls
}
