//! The local network: device inventory scans, scan ranges, and device
//! presence watches.

mod scanner;
#[cfg(test)]
mod tests;

use std::collections::BTreeSet;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use antiwire_events::{Alert, AlertKind, AlertPublisher, Severity};
use antiwire_geo::OuiResolver;
use antiwire_netmap::{
    canonical_mac, validate_scan_ranges, NetworkDeviceSnapshot, NetworkMappingState, ScanError,
};
use antiwire_store::{NetworkDevice, NetworkDeviceWatch, NetworkScanRange, Store, StoreError};
use parking_lot::RwLock;
use thiserror::Error;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;

use crate::background::BackgroundTasks;
use crate::context::ServiceContext;
use crate::settings_feed::SettingsFeed;

pub use scanner::{NetworkScanner, SystemScanner};

/// How often scheduled scans and due presence checks are looked for.
const MONITOR_TICK: Duration = Duration::from_secs(5);
const ALLOWED_WATCH_INTERVALS: &[i32] = &[1, 5, 10, 30, 60];

#[derive(Debug, Error)]
pub enum NetworkMappingWorkerError {
    /// The request is not valid. Nothing was changed.
    #[error("{0}")]
    Invalid(String),
    #[error("this device is already watched")]
    AlreadyWatched,
    #[error(transparent)]
    Scan(#[from] ScanError),
    #[error("a network scan or presence check is already running")]
    Busy,
    #[error("the daemon is shutting down")]
    ShuttingDown,
    #[error("network mapping store error: {0}")]
    Store(String),
}

impl From<StoreError> for NetworkMappingWorkerError {
    fn from(error: StoreError) -> Self {
        match error {
            StoreError::WatchAlreadyExists => Self::AlreadyWatched,
            other => Self::Store(other.to_string()),
        }
    }
}

type Result<T> = std::result::Result<T, NetworkMappingWorkerError>;

/// A device watch to save. A positive `id` replaces that watch.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DeviceWatchRequest {
    pub id: i32,
    pub ip_address: String,
    pub mac_address: String,
    pub adapter_id: String,
    pub cidr: String,
    pub interval_minutes: u32,
    pub enabled: bool,
}

/// Everything the network mapping view shows, read at one moment.
#[derive(Debug, Clone, Default)]
pub struct NetworkOverview {
    pub state: NetworkMappingState,
    pub devices: Vec<NetworkDevice>,
    /// Saved ranges, then the host's own ranges not already saved, with
    /// negative ids since they are not saved rows.
    pub scan_ranges: Vec<NetworkScanRange>,
    pub watches: Vec<NetworkDeviceWatch>,
}

#[derive(Debug)]
struct ActiveScan {
    generation: u64,
    cancellation: CancellationToken,
}

/// Runs inventory scans and presence checks, and owns the mapping state and
/// the saved scan ranges and device watches.
#[derive(Clone)]
pub struct NetworkMappingWorker {
    inner: Arc<Inner>,
}

struct Inner {
    store: Arc<Store>,
    settings: SettingsFeed,
    alerts: AlertPublisher,
    oui: Option<OuiResolver>,
    scanner: Arc<dyn NetworkScanner>,
    state: RwLock<NetworkMappingState>,
    /// The saved watches, refreshed on every change, so the monitor does not
    /// read the store on each tick.
    watches: RwLock<Vec<NetworkDeviceWatch>>,
    /// The scan or presence check that is running. Reserving one and
    /// clearing the inventory both hold this, so neither can slip between
    /// the other's check and its work.
    scan: Mutex<Option<ActiveScan>>,
    next_generation: AtomicU64,
    tasks: BackgroundTasks,
}

impl NetworkMappingWorker {
    /// A worker that scans through the operating system.
    #[must_use]
    pub fn new(context: &ServiceContext, oui: Option<OuiResolver>) -> Self {
        Self::with_scanner(context, oui, Arc::new(SystemScanner))
    }

    #[must_use]
    pub fn with_scanner(
        context: &ServiceContext,
        oui: Option<OuiResolver>,
        scanner: Arc<dyn NetworkScanner>,
    ) -> Self {
        Self {
            inner: Arc::new(Inner {
                store: Arc::clone(&context.store),
                settings: context.settings.clone(),
                alerts: context.alerts.clone(),
                oui,
                scanner,
                state: RwLock::new(NetworkMappingState::default()),
                watches: RwLock::new(Vec::new()),
                scan: Mutex::new(None),
                next_generation: AtomicU64::new(1),
                tasks: BackgroundTasks::new(context.shutdown.clone()),
            }),
        }
    }

    /// Loads the saved watches, then runs scheduled scans and due presence
    /// checks until shutdown.
    ///
    /// # Errors
    ///
    /// A store failure reading the watches.
    pub async fn start(&self) -> Result<()> {
        self.reload_watches().await?;
        let worker = self.clone();
        self.inner.tasks.every(MONITOR_TICK, move || {
            let worker = worker.clone();
            async move { worker.tick().await }
        });
        Ok(())
    }

    /// Waits for every task to stop once the daemon's shutdown has begun. A
    /// running scan is cancelled by the same shutdown.
    pub async fn shutdown(&self) {
        self.inner.tasks.join().await;
    }

    /// The mapping state as it is now.
    #[must_use]
    pub fn snapshot(&self) -> NetworkMappingState {
        self.inner.state.read().clone()
    }

    /// Everything the network mapping view shows.
    ///
    /// # Errors
    ///
    /// A store failure.
    pub async fn overview(&self) -> Result<NetworkOverview> {
        let detected = self.inner.scanner.local_ranges().await.unwrap_or_default();
        let store = Arc::clone(&self.inner.store);
        let (devices, mut scan_ranges, watches) = blocking(move || {
            Ok((
                store.list_network_devices()?,
                store.list_scan_ranges()?,
                store.list_device_watches()?,
            ))
        })
        .await?;
        for (index, interface) in detected.into_iter().enumerate() {
            if let Some(saved) = scan_ranges
                .iter_mut()
                .find(|saved| saved.cidr == interface.cidr)
            {
                if saved.adapter_id.trim().is_empty() {
                    saved.adapter_id = interface.adapter_id;
                }
            } else {
                scan_ranges.push(NetworkScanRange {
                    id: -i32::try_from(index + 1).unwrap_or(i32::MAX),
                    adapter_id: interface.adapter_id,
                    cidr: interface.cidr,
                });
            }
        }
        Ok(NetworkOverview {
            state: self.snapshot(),
            devices,
            scan_ranges,
            watches,
        })
    }

    /// Starts a full inventory scan and returns as soon as it is accepted.
    /// With no `ranges`, scans the saved ranges, or the host's own.
    ///
    /// # Errors
    ///
    /// [`NetworkMappingWorkerError::Busy`] while another scan runs,
    /// [`NetworkMappingWorkerError::ShuttingDown`] during shutdown, or an
    /// error for ranges that cannot be resolved or are not valid to scan.
    pub async fn start_scan(&self, ranges: Vec<String>) -> Result<()> {
        let ranges = self.resolve_ranges(ranges).await?;
        validate_scan_ranges(&ranges)?;
        let (generation, cancellation) = self.reserve_scan("Scanning local network…").await?;
        let worker = self.clone();
        self.inner.tasks.spawn(async move {
            worker.run_full_scan(ranges, generation, cancellation).await;
        });
        Ok(())
    }

    /// Cancels the running scan or presence check. Returns whether one ran.
    pub async fn stop_scan(&self) -> bool {
        let scan = self.inner.scan.lock().await;
        scan.as_ref()
            .inspect(|active| active.cancellation.cancel())
            .is_some()
    }

    /// Deletes the device inventory unless a scan is running. Returns
    /// `false` when one is.
    ///
    /// # Errors
    ///
    /// A store failure.
    pub async fn clear_devices(&self) -> Result<bool> {
        let active = self.inner.scan.lock().await;
        if active.is_some() {
            return Ok(false);
        }
        let store = Arc::clone(&self.inner.store);
        blocking(move || store.clear_network_devices().map_err(Into::into)).await?;
        self.inner.state.write().devices.clear();
        Ok(true)
    }

    /// Saves a scan range, replacing the one with its id when that is
    /// positive. Returns the saved id.
    ///
    /// # Errors
    ///
    /// [`NetworkMappingWorkerError::Scan`] for a range that is not valid to
    /// scan, or a store failure.
    pub async fn save_scan_range(&self, range: NetworkScanRange) -> Result<i32> {
        validate_scan_ranges(std::slice::from_ref(&range.cidr))?;
        let store = Arc::clone(&self.inner.store);
        blocking(move || store.save_scan_range(&range).map_err(Into::into)).await
    }

    /// Removes the scan range with `id`.
    ///
    /// # Errors
    ///
    /// [`NetworkMappingWorkerError::Invalid`] for an id that names no saved
    /// range, or a store failure.
    pub async fn remove_scan_range(&self, id: i32) -> Result<()> {
        require_saved_id(id, "scan range")?;
        let store = Arc::clone(&self.inner.store);
        blocking(move || store.delete_scan_range(id).map_err(Into::into)).await
    }

    /// Saves a device watch, replacing the one with its id when that is
    /// positive. Returns the saved id. A saved watch starts a new baseline,
    /// so its first check raises no presence alert.
    ///
    /// # Errors
    ///
    /// [`NetworkMappingWorkerError::Invalid`] for an invalid address,
    /// interval, or range, [`NetworkMappingWorkerError::AlreadyWatched`]
    /// for a device another watch covers, or a store failure.
    pub async fn save_device_watch(&self, request: DeviceWatchRequest) -> Result<i32> {
        let watch = validated_watch(request)?;
        let store = Arc::clone(&self.inner.store);
        let id = blocking(move || store.save_device_watch(&watch).map_err(Into::into)).await?;
        self.reload_watches().await?;
        Ok(id)
    }

    /// Removes the device watch with `id`.
    ///
    /// # Errors
    ///
    /// [`NetworkMappingWorkerError::Invalid`] for an id that names no saved
    /// watch, or a store failure.
    pub async fn remove_device_watch(&self, id: i32) -> Result<()> {
        require_saved_id(id, "device watch")?;
        let store = Arc::clone(&self.inner.store);
        blocking(move || store.delete_device_watch(id).map_err(Into::into)).await?;
        self.reload_watches().await
    }

    async fn tick(&self) {
        if let Err(error) = self.check_due_watches().await {
            if !matches!(
                error,
                NetworkMappingWorkerError::Busy | NetworkMappingWorkerError::ShuttingDown
            ) {
                tracing::warn!(%error, "network presence check could not start");
            }
        }
        if let Err(error) = self.start_automatic_scan_if_due().await {
            if !matches!(
                error,
                NetworkMappingWorkerError::Busy | NetworkMappingWorkerError::ShuttingDown
            ) {
                tracing::warn!(%error, "automatic network scan could not start");
            }
        }
    }

    async fn start_automatic_scan_if_due(&self) -> Result<()> {
        let settings = self.inner.settings.current();
        if !settings.network_mapping_auto_enabled {
            return Ok(());
        }
        let interval =
            time::Duration::minutes(i64::from(settings.network_mapping_interval_minutes.max(5)));
        let last_scan = self.inner.state.read().last_scan.clone();
        let due = OffsetDateTime::parse(&last_scan, &Rfc3339)
            .map_or(true, |last| last + interval <= OffsetDateTime::now_utc());
        if due {
            self.start_scan(Vec::new()).await?;
        }
        Ok(())
    }

    async fn check_due_watches(&self) -> Result<()> {
        let now = OffsetDateTime::now_utc();
        let watches: Vec<_> = self
            .inner
            .watches
            .read()
            .iter()
            .filter(|watch| watch.enabled && watch_is_due(watch, now))
            .cloned()
            .collect();
        if watches.is_empty() {
            return Ok(());
        }
        let ranges = self.watch_ranges(&watches).await?;
        validate_scan_ranges(&ranges)?;
        let (generation, cancellation) = self
            .reserve_scan("Checking watched network devices…")
            .await?;
        let worker = self.clone();
        self.inner.tasks.spawn(async move {
            if let Err(error) = worker
                .run_watch_scan(watches, ranges, generation, cancellation)
                .await
            {
                tracing::warn!(%error, "network presence check failed");
            }
        });
        Ok(())
    }

    async fn run_full_scan(
        &self,
        ranges: Vec<String>,
        generation: u64,
        cancellation: CancellationToken,
    ) {
        match self.inner.scanner.scan(&ranges, &cancellation).await {
            Ok(mut devices) => {
                self.resolve_vendors(&mut devices);
                let scanned_at = OffsetDateTime::now_utc();
                let rows: Vec<_> = devices
                    .iter()
                    .map(|device| snapshot_to_store(device, scanned_at))
                    .collect();
                let store = Arc::clone(&self.inner.store);
                let saved =
                    blocking(move || store.apply_network_scan(&rows).map_err(Into::into)).await;
                let mut state = self.inner.state.write();
                match saved {
                    Ok(()) => {
                        let scanned_at = scanned_at
                            .format(&Rfc3339)
                            .unwrap_or_else(|_| scanned_at.unix_timestamp().to_string());
                        state.finish_scan(devices, scanned_at);
                    }
                    Err(error) => state.fail_scan(format!("Scan could not be saved: {error}")),
                }
            }
            Err(ScanError::Cancelled) => self.inner.state.write().fail_scan("Network scan stopped"),
            Err(error) => self
                .inner
                .state
                .write()
                .fail_scan(format!("Network scan failed: {error}")),
        }
        self.release_scan(generation).await;
    }

    async fn run_watch_scan(
        &self,
        watches: Vec<NetworkDeviceWatch>,
        ranges: Vec<String>,
        generation: u64,
        cancellation: CancellationToken,
    ) -> Result<()> {
        let outcome = self.check_presence(&watches, &ranges, &cancellation).await;
        if let Err(error) = &outcome {
            let message = match error {
                NetworkMappingWorkerError::Scan(ScanError::Cancelled) => {
                    "Presence check stopped".to_owned()
                }
                error => format!("Presence check failed: {error}"),
            };
            self.inner.state.write().fail_scan(message);
        }
        self.release_scan(generation).await;
        match outcome {
            Err(NetworkMappingWorkerError::Scan(ScanError::Cancelled)) => Ok(()),
            other => other,
        }
    }

    async fn check_presence(
        &self,
        watches: &[NetworkDeviceWatch],
        ranges: &[String],
        cancellation: &CancellationToken,
    ) -> Result<()> {
        let mut devices = self.inner.scanner.scan(ranges, cancellation).await?;
        self.resolve_vendors(&mut devices);
        let presence = self
            .apply_watch_results(watches, &devices, OffsetDateTime::now_utc())
            .await?;
        self.reload_watches().await?;

        let mut state = self.inner.state.write();
        state.merge_devices(devices);
        for (watch, present) in watches.iter().zip(presence) {
            if let Some(device) = state
                .devices
                .iter_mut()
                .find(|device| watch_matches(watch, device))
            {
                device.is_online = present;
            }
        }
        state.scan_in_progress = false;
        state.message = format!("Checked {} watched device(s)", watches.len());
        Ok(())
    }

    /// Saves a presence check: the devices seen, each watch's state, and an
    /// alert for each watched device that came or went.
    async fn apply_watch_results(
        &self,
        watches: &[NetworkDeviceWatch],
        devices: &[NetworkDeviceSnapshot],
        checked_at: OffsetDateTime,
    ) -> Result<Vec<bool>> {
        let store = Arc::clone(&self.inner.store);
        let alerts = self.inner.alerts.clone();
        let watches = watches.to_vec();
        let devices = devices.to_vec();
        blocking(move || persist_watch_results(&store, &alerts, &watches, &devices, checked_at))
            .await
    }

    async fn reload_watches(&self) -> Result<()> {
        let store = Arc::clone(&self.inner.store);
        let watches = blocking(move || store.list_device_watches().map_err(Into::into)).await?;
        *self.inner.watches.write() = watches;
        Ok(())
    }

    fn resolve_vendors(&self, devices: &mut [NetworkDeviceSnapshot]) {
        let Some(resolver) = self.inner.oui.as_ref() else {
            return;
        };
        for device in devices {
            device.vendor = resolver
                .vendor(&device.mac_address)
                .unwrap_or_default()
                .to_owned();
        }
    }

    async fn resolve_ranges(&self, requested: Vec<String>) -> Result<Vec<String>> {
        if !requested.is_empty() {
            return Ok(requested);
        }
        let store = Arc::clone(&self.inner.store);
        let saved: Vec<String> = blocking(move || store.list_scan_ranges().map_err(Into::into))
            .await?
            .into_iter()
            .map(|range| range.cidr)
            .filter(|range| !range.is_empty())
            .collect();
        if !saved.is_empty() {
            return Ok(saved);
        }
        Ok(self
            .inner
            .scanner
            .local_ranges()
            .await?
            .into_iter()
            .map(|range| range.cidr)
            .collect())
    }

    async fn watch_ranges(&self, watches: &[NetworkDeviceWatch]) -> Result<Vec<String>> {
        let mut ranges = BTreeSet::new();
        for watch in watches {
            let range = if watch.ip_address.parse::<Ipv4Addr>().is_ok() {
                format!("{}/32", watch.ip_address)
            } else if !watch.cidr.is_empty() {
                watch.cidr.clone()
            } else {
                continue;
            };
            // A watch saved before ranges were validated must not stop the
            // presence check for every other watch.
            match validate_scan_ranges(std::slice::from_ref(&range)) {
                Ok(()) => {
                    ranges.insert(range);
                }
                Err(error) => {
                    tracing::warn!(watch = watch.id, %error, "skipping a device watch with an unusable range");
                }
            }
        }
        if ranges.is_empty() {
            ranges.extend(self.resolve_ranges(Vec::new()).await?);
        }
        Ok(ranges.into_iter().collect())
    }

    /// Marks a scan as running, unless one is or shutdown has begun. Its
    /// cancellation also fires at shutdown.
    async fn reserve_scan(&self, message: &str) -> Result<(u64, CancellationToken)> {
        let mut active = self.inner.scan.lock().await;
        let shutdown = self.inner.tasks.shutdown();
        if shutdown.is_cancelled() {
            return Err(NetworkMappingWorkerError::ShuttingDown);
        }
        if active.is_some() {
            return Err(NetworkMappingWorkerError::Busy);
        }
        let generation = self.inner.next_generation.fetch_add(1, Ordering::Relaxed);
        let cancellation = shutdown.child_token();
        *active = Some(ActiveScan {
            generation,
            cancellation: cancellation.clone(),
        });
        let mut state = self.inner.state.write();
        state.begin_scan();
        message.clone_into(&mut state.message);
        Ok((generation, cancellation))
    }

    async fn release_scan(&self, generation: u64) {
        let mut active = self.inner.scan.lock().await;
        if active
            .as_ref()
            .is_some_and(|scan| scan.generation == generation)
        {
            *active = None;
        }
    }
}

/// Whether `interval_minutes` is an interval a presence watch may use.
#[must_use]
pub fn valid_watch_interval(interval_minutes: i32) -> bool {
    ALLOWED_WATCH_INTERVALS.contains(&interval_minutes)
}

/// Whether `watch` covers the device at `ip_address` or `mac_address`.
#[must_use]
pub fn watch_matches_addr(watch: &NetworkDeviceWatch, ip_address: &str, mac_address: &str) -> bool {
    (!watch.ip_address.is_empty() && watch.ip_address == ip_address)
        || (!watch.mac_address.is_empty() && watch.mac_address.eq_ignore_ascii_case(mac_address))
}

fn validated_watch(request: DeviceWatchRequest) -> Result<NetworkDeviceWatch> {
    let invalid = |message: &str| NetworkMappingWorkerError::Invalid(message.to_owned());
    let ip_address = request.ip_address.trim().to_owned();
    let mac_address = request.mac_address.trim();
    if ip_address.is_empty() && mac_address.is_empty() {
        return Err(invalid("an IPv4 address or MAC address is required"));
    }
    if !ip_address.is_empty() && ip_address.parse::<Ipv4Addr>().is_err() {
        return Err(invalid("watch IP address is invalid"));
    }
    let mac_address = if mac_address.is_empty() {
        String::new()
    } else {
        canonical_mac(mac_address).ok_or_else(|| invalid("watch MAC address is invalid"))?
    };
    let interval_minutes = i32::try_from(request.interval_minutes).unwrap_or(i32::MAX);
    if !valid_watch_interval(interval_minutes) {
        return Err(invalid(
            "watch interval must be 1, 5, 10, 30, or 60 minutes",
        ));
    }
    let cidr = request.cidr.trim().to_owned();
    if !cidr.is_empty() {
        validate_scan_ranges(std::slice::from_ref(&cidr))?;
    }
    Ok(NetworkDeviceWatch {
        id: request.id,
        ip_address,
        mac_address,
        adapter_id: request.adapter_id,
        cidr,
        interval_minutes,
        enabled: request.enabled,
        present: false,
        baseline_established: false,
        last_checked: OffsetDateTime::UNIX_EPOCH,
    })
}

fn require_saved_id(id: i32, what: &str) -> Result<()> {
    if id > 0 {
        Ok(())
    } else {
        Err(NetworkMappingWorkerError::Invalid(format!(
            "{what} id is required"
        )))
    }
}

fn watch_is_due(watch: &NetworkDeviceWatch, now: OffsetDateTime) -> bool {
    !watch.baseline_established
        || watch.last_checked + time::Duration::minutes(i64::from(watch.interval_minutes)) <= now
}

/// Saves a presence check's results; see [`NetworkMappingWorker::apply_watch_results`].
/// Blocking.
fn persist_watch_results(
    store: &Store,
    alerts: &AlertPublisher,
    watches: &[NetworkDeviceWatch],
    devices: &[NetworkDeviceSnapshot],
    checked_at: OffsetDateTime,
) -> Result<Vec<bool>> {
    for device in devices {
        store.upsert_network_device(&snapshot_to_store(device, checked_at))?;
    }
    let mut presence = Vec::with_capacity(watches.len());
    for watch in watches {
        let present = devices.iter().any(|device| watch_matches(watch, device));
        store.update_device_watch_state(watch.id, present, true, checked_at)?;
        store.set_network_device_presence(
            &watch.mac_address,
            &watch.ip_address,
            present,
            checked_at,
        )?;
        if watch.baseline_established && watch.present != present {
            publish_presence_change(alerts, watch, present, checked_at);
        }
        presence.push(present);
    }
    Ok(presence)
}

fn publish_presence_change(
    alerts: &AlertPublisher,
    watch: &NetworkDeviceWatch,
    present: bool,
    checked_at: OffsetDateTime,
) {
    let target = watch_target(watch);
    let status = if present { "connected" } else { "disconnected" };
    let (kind, severity) = if present {
        (AlertKind::NetworkDeviceConnected, Severity::Info)
    } else {
        (AlertKind::NetworkDeviceDisconnected, Severity::Warning)
    };
    alerts.publish(
        Alert::new(
            kind,
            severity,
            format!("Network device {status}"),
            format!("{target} is now {status}."),
        )
        .at(u64::try_from(checked_at.unix_timestamp()).unwrap_or(0)),
    );
}

fn watch_matches(watch: &NetworkDeviceWatch, device: &NetworkDeviceSnapshot) -> bool {
    watch_matches_addr(watch, &device.ip_address, &device.mac_address)
}

fn watch_target(watch: &NetworkDeviceWatch) -> String {
    match (watch.ip_address.is_empty(), watch.mac_address.is_empty()) {
        (false, false) => format!("{} ({})", watch.ip_address, watch.mac_address),
        (false, true) => watch.ip_address.clone(),
        (true, false) => watch.mac_address.clone(),
        (true, true) => "Unknown device".to_owned(),
    }
}

fn snapshot_to_store(device: &NetworkDeviceSnapshot, seen_at: OffsetDateTime) -> NetworkDevice {
    NetworkDevice {
        mac_address: canonical_mac(&device.mac_address)
            .unwrap_or_else(|| device.mac_address.clone()),
        ip_address: device.ip_address.clone(),
        manufacturer: device.vendor.clone(),
        mdns_name: device.hostname.clone(),
        adapter_id: String::new(),
        first_seen: seen_at,
        last_seen: seen_at,
        present: device.is_online,
    }
}

/// Runs blocking store `work` off the async runtime.
async fn blocking<T, F>(work: F) -> Result<T>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T> + Send + 'static,
{
    tokio::task::spawn_blocking(work).await.map_err(|error| {
        NetworkMappingWorkerError::Store(format!("store work did not finish: {error}"))
    })?
}
