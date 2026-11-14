//! The GeoLite2-City database: loaded at start, refreshed quarterly, and
//! swapped into the shared lookup that enriches flows.

mod source;
#[cfg(test)]
mod tests;

use std::path::{Path, PathBuf};
use std::sync::Arc;

use antiwire_downloader::gunzip_file;
use antiwire_events::{Alert, AlertKind, AlertPublisher, Severity};
use antiwire_geo::GeoIpLookup;
use antiwire_platform::DataPaths;
use antiwire_store::DaemonSetting;
use arc_swap::ArcSwap;
use time::OffsetDateTime;
use tracing::{info, warn};

use crate::background::BackgroundTasks;
use crate::context::ServiceContext;
use crate::settings_feed::SettingsFeed;
use crate::sync_runner::{FailurePolicy, SyncOutcome, SyncRunner, Trigger};

use source::CITY_GZ_FILENAME;
pub use source::{GeoDatabaseSource, JsDelivrGeoSource};

const CITY_MMDB_FILENAME: &str = "GeoLite2-City.mmdb";
/// A decompressed download waiting to be opened. `GeoIpLookup` only opens
/// [`CITY_MMDB_FILENAME`], so a leftover staged file is never loaded.
const CITY_STAGED_FILENAME: &str = "GeoLite2-City.mmdb.staged";

/// Keeps the shared `GeoIP` lookup loaded while enrichment is on, and empty
/// while it is off.
pub struct GeoDatabaseService {
    inner: Arc<Inner>,
}

struct Inner {
    settings: SettingsFeed,
    alerts: AlertPublisher,
    data_paths: DataPaths,
    geo: Arc<ArcSwap<GeoIpLookup>>,
    source: Arc<dyn GeoDatabaseSource>,
    syncs: SyncRunner,
    tasks: BackgroundTasks,
    /// Orders installing a loaded database against disabling enrichment. A
    /// publisher re-reads `geoip_enabled` while holding it, and a disable
    /// clears the lookup while holding it, so a load that started before the
    /// user turned `GeoIP` off cannot land after the clear.
    publish_gate: parking_lot::Mutex<()>,
}

impl GeoDatabaseService {
    /// A service that downloads from jsDelivr into `geo`, the lookup flows
    /// are enriched from.
    #[must_use]
    pub fn new(context: &ServiceContext, geo: Arc<ArcSwap<GeoIpLookup>>) -> Self {
        Self::with_source(context, geo, Arc::new(JsDelivrGeoSource::new()))
    }

    #[must_use]
    pub fn with_source(
        context: &ServiceContext,
        geo: Arc<ArcSwap<GeoIpLookup>>,
        source: Arc<dyn GeoDatabaseSource>,
    ) -> Self {
        Self {
            inner: Arc::new(Inner {
                settings: context.settings.clone(),
                alerts: context.alerts.clone(),
                data_paths: context.data_paths.clone(),
                geo,
                source,
                syncs: SyncRunner::new(
                    FailurePolicy {
                        kind: AlertKind::GeoIpSyncFailed,
                        title: "GeoIP Database Update Failed",
                        summary: "Failed to update the GeoIP database",
                        backoff_base_minutes: antiwire_tuning::GEOIP_SYNC_BACKOFF_BASE_MINUTES,
                        backoff_cap_minutes: antiwire_tuning::GEOIP_SYNC_BACKOFF_CAP_MINUTES,
                    },
                    context.alerts.clone(),
                    context.shutdown.clone(),
                ),
                tasks: BackgroundTasks::new(context.shutdown.clone()),
                publish_gate: parking_lot::Mutex::new(()),
            }),
        }
    }

    /// Loads the database on disk when enrichment is on, then checks for a
    /// newer one on a schedule. Await it before flows start, so the first
    /// flows are enriched.
    pub async fn start(&self) {
        if self.inner.settings.current().geoip_enabled {
            Arc::clone(&self.inner).load_from_disk().await;
        }
        let inner = Arc::clone(&self.inner);
        self.inner
            .tasks
            .every(antiwire_tuning::GEOIP_SCHEDULER_INTERVAL, move || {
                let inner = Arc::clone(&inner);
                async move { inner.tick().await }
            });
    }

    /// Waits for every task to stop once the daemon's shutdown has begun.
    pub async fn shutdown(&self) {
        self.inner.tasks.join().await;
    }

    /// Applies saved settings that changed from `previous` to `updated`.
    ///
    /// Turning enrichment on loads the database on disk at once, and
    /// downloads one when it is missing, unloadable, or stale. Turning it off
    /// empties the lookup at once.
    pub fn on_settings_changed(&self, previous: &DaemonSetting, updated: &DaemonSetting) {
        if previous.geoip_enabled == updated.geoip_enabled {
            return;
        }
        if !updated.geoip_enabled {
            let _publish = self.inner.publish_gate.lock();
            self.inner.geo.store(Arc::new(GeoIpLookup::new()));
            info!("geoip enrichment disabled; cleared the in-memory database");
            return;
        }
        let inner = Arc::clone(&self.inner);
        self.inner.tasks.spawn(async move {
            Arc::clone(&inner).load_from_disk().await;
            inner.sync_if_due().await;
        });
    }

    /// Downloads and installs the latest database now, ignoring any backoff.
    ///
    /// # Errors
    ///
    /// Why the download or install failed.
    pub async fn sync_now(&self) -> Result<(), String> {
        let inner = Arc::clone(&self.inner);
        self.inner
            .syncs
            .run(Trigger::Manual, || inner.download_and_install())
            .await
            .map(|_| ())
    }
}

impl Inner {
    async fn tick(self: Arc<Self>) {
        if self.settings.current().geoip_enabled {
            self.sync_if_due().await;
        }
    }

    /// Downloads a database when the one on disk is missing, unloadable, or
    /// past the refresh age.
    async fn sync_if_due(self: Arc<Self>) {
        let now = OffsetDateTime::now_utc();
        if self.syncs.deferred(now) {
            return;
        }
        let path = self.city_database();
        let loaded = self.geo.load().is_loaded();
        let settings = self.settings.current();
        let due = tokio::task::spawn_blocking(move || refresh_due(&path, loaded, &settings, now))
            .await
            .unwrap_or(false);
        if !due {
            return;
        }
        info!("geoip database refresh is due; downloading GeoLite2-City");
        let inner = Arc::clone(&self);
        match self
            .syncs
            .run(Trigger::Automatic, || inner.download_and_install())
            .await
        {
            Ok(SyncOutcome::Deferred(resume)) => {
                info!(%resume, "geoip database sync deferred due to failure backoff");
            }
            Ok(_) => {}
            Err(error) => warn!(%error, "geoip database sync failed"),
        }
    }

    /// Installs the database on disk into the lookup, if it loads and
    /// enrichment is still on.
    async fn load_from_disk(self: Arc<Self>) {
        let geoip_dir = self.data_paths.geoip_dir();
        let inner = Arc::clone(&self);
        let published = tokio::task::spawn_blocking(move || {
            let geo = GeoIpLookup::with_data_dir(geoip_dir);
            if geo.is_loaded() {
                inner.publish_if_enabled(geo)
            } else {
                warn!("geoip enabled but no loadable GeoLite2 database is on disk");
                false
            }
        })
        .await;
        match published {
            Ok(true) => info!("loaded the on-disk GeoLite2 database into flow enrichment"),
            Ok(false) => {}
            Err(error) => warn!(%error, "geoip database load did not finish"),
        }
    }

    /// Installs `geo` unless enrichment is now off; returns whether it did.
    fn publish_if_enabled(&self, geo: GeoIpLookup) -> bool {
        let _publish = self.publish_gate.lock();
        if !self.settings.current().geoip_enabled {
            return false;
        }
        self.geo.store(Arc::new(geo));
        true
    }

    async fn download_and_install(self: Arc<Self>) -> Result<(), String> {
        let dir = self.data_paths.geoip_dir();
        self.data_paths
            .ensure_geoip_dir()
            .map_err(|error| error.to_string())?;
        if !self.settings.current().geoip_enabled {
            return Ok(());
        }

        let gz_path = dir.join(CITY_GZ_FILENAME);
        let version = self.source.download_latest(&gz_path).await?;

        let inner = Arc::clone(&self);
        let installed = tokio::task::spawn_blocking(move || inner.install(&gz_path, &dir))
            .await
            .map_err(|error| format!("database install did not finish: {error}"))??;
        if !installed {
            info!("geoip disabled during download; keeping the file but not enriching");
        }

        let settings = self.settings.clone();
        tokio::task::spawn_blocking(move || settings.record_geoip_sync(OffsetDateTime::now_utc()))
            .await
            .map_err(|error| format!("settings save did not finish: {error}"))?
            .map_err(|error| error.to_string())?;
        info!(%version, "installed the GeoLite2-City database");
        self.alerts.publish(Alert::new(
            AlertKind::GeoIpSync,
            Severity::Info,
            "GeoIP Database Updated",
            "Successfully downloaded the latest GeoLite2-City database.",
        ));
        Ok(())
    }

    /// Decompresses the download beside the live database, opens it there,
    /// and only then replaces the live one, so a file that fails to open
    /// never replaces a working one. Returns whether enrichment now uses it.
    /// Blocking.
    fn install(&self, gz_path: &Path, dir: &Path) -> Result<bool, String> {
        let staged_path = dir.join(CITY_STAGED_FILENAME);
        let staged = gunzip_file(
            gz_path,
            &staged_path,
            antiwire_tuning::GEOIP_MAX_DECOMPRESSED_BYTES,
        );
        remove_intermediate(gz_path);
        staged.map_err(|error| error.to_string())?;

        let geo = GeoIpLookup::from_paths(None, None, Some(staged_path.clone()));
        if !geo.is_loaded() {
            remove_intermediate(&staged_path);
            return Err("downloaded GeoLite2-City database failed to open".to_owned());
        }
        // The lookup reads the whole file into memory, so the staged file is
        // not held open and can be renamed over the live one.
        if let Err(error) = std::fs::rename(&staged_path, dir.join(CITY_MMDB_FILENAME)) {
            remove_intermediate(&staged_path);
            return Err(format!("could not install GeoLite2-City database: {error}"));
        }
        // A multi-minute download can outlive the setting that started it.
        // The file is kept, and the recorded sync stops the next enable from
        // downloading it again, but enrichment the user turned off stays off.
        Ok(self.publish_if_enabled(geo))
    }

    fn city_database(&self) -> PathBuf {
        self.data_paths.geoip_dir().join(CITY_MMDB_FILENAME)
    }
}

/// Whether the database at `path` needs downloading at `now`: it is missing,
/// it is on disk but did not load, or it is past the refresh age. Blocking.
fn refresh_due(path: &Path, loaded: bool, settings: &DaemonSetting, now: OffsetDateTime) -> bool {
    if !path.is_file() || !loaded {
        return true;
    }
    let refresh_interval =
        time::Duration::seconds_f64(antiwire_tuning::GEOIP_DATABASE_REFRESH_INTERVAL.as_secs_f64());
    now - settings.geoip_database_last_updated >= refresh_interval
}

fn remove_intermediate(path: &Path) {
    if let Err(error) = std::fs::remove_file(path) {
        if error.kind() != std::io::ErrorKind::NotFound {
            warn!(path = ?path, %error, "failed to remove intermediate geoip file");
        }
    }
}
