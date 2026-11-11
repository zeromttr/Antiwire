//! Asynchronously persists blocked DNS queries into `connection_logs` and SIEM.
//!
//! Attribution prefers the ETW DNS-Client caller. When that evidence is
//! exhausted, the query's socket owner becomes the record's identity — the
//! requesting application for direct DNS and the system resolver (e.g.
//! Dnscache) for mediated queries — so a block is labelled unattributed only
//! when the platform offered no owner at all.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{self, SyncSender, TrySendError};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use antiwire_dns::DnsBlockSink;
use antiwire_events::{AlertPublisher, CollectorHealth};
use antiwire_platform::SiemExporter;
use antiwire_store::Store;
use antiwire_tuning::{Backoff, DNS_BLOCK_DEDUP_MS, DNS_BLOCK_RECONCILIATION_MS};
use arc_swap::ArcSwapOption;
use netmetrics::Ownership;
use parking_lot::Mutex;
use time::OffsetDateTime;
use tracing::warn;

use crate::app_resolver::AppIdResolver;
use crate::correlator::{DnsCorrelationResult, DnsQueryCorrelator};
use crate::sanitize;

mod attribution;
mod worker;

const WRITE_QUEUE_CAPACITY: usize = 8192;
const WRITE_BATCH_SIZE: usize = 10;
const WRITE_RETRY_BACKOFF: Backoff =
    Backoff::new(Duration::from_millis(50), Duration::from_secs(1));
const SHUTDOWN_WRITE_RETRY_ATTEMPTS: u32 = 4;
/// How long the worker may block on the queue before re-checking its stop flag.
const WORKER_STOP_POLL: Duration = Duration::from_millis(250);
/// How long [`DnsBlockRecorder::shutdown`] waits for the worker's final flush.
const WORKER_JOIN_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Clone)]
struct PreparedBlock {
    app_id: i32,
    app_path: String,
    app_name: String,
    domain: String,
    blocklist_names: Vec<String>,
    encoded_names: String,
    timestamp: OffsetDateTime,
    correlation: DnsCorrelationResult,
    attributed: bool,
    resolver_desc: Option<String>,
    suppress_notification: bool,
}

type DnsWriteBatch = Vec<PreparedBlock>;

enum BatchRetry {
    Ready,
    Wait,
    Stop,
}

enum ReceiveResult {
    Item,
    Timeout,
    Retry,
    Stop,
    Disconnected,
}

#[derive(Default)]
struct RetryState {
    at: Option<Instant>,
    attempt: u32,
}

#[derive(Default)]
struct ShutdownState {
    records_shed: bool,
    connection_logs_failed: bool,
    application_retry_exhausted: bool,
}

fn dns_dedup_window() -> Duration {
    Duration::from_millis(DNS_BLOCK_DEDUP_MS)
}

#[derive(Debug, Clone)]
struct PendingBlock {
    domain: String,
    ownership: PendingOwnership,
    blocklist_names: Vec<String>,
    timestamp: OffsetDateTime,
}

#[derive(Debug, Clone, Copy)]
enum PendingOwnership {
    Caller(u32),
    Socket(Ownership),
}

impl PendingOwnership {
    /// The process the query's socket belonged to, when one was resolved.
    ///
    /// This is the requesting application for a direct query and the system
    /// resolver (e.g. Dnscache) for a mediated one. Once caller evidence is
    /// exhausted it is the sender of record, so a block is never labelled
    /// "unknown" when the platform told us who owned the socket.
    fn socket_owner_pid(self) -> u32 {
        match self {
            Self::Caller(pid) | Self::Socket(Ownership::Resolved(pid)) => pid,
            Self::Socket(Ownership::Ambiguous | Ownership::NotFound) => 0,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct DnsBlockKey {
    pid: u32,
    domain: String,
}

/// Records blocked DNS queries into `connection_logs`, with SIEM and notification fan-out.
pub struct DnsBlockRecorder {
    tx: Arc<Mutex<Option<SyncSender<PendingBlock>>>>,
    settings: Arc<RuntimeSettings>,
    worker_stop: Arc<AtomicBool>,
    worker: Mutex<Option<JoinHandle<()>>>,
    dropped: AtomicU64,
    #[cfg(test)]
    pending_reconciliations: Arc<AtomicU64>,
    /// Shared with the worker so both the enqueue side and the persistence side can
    /// report shed records and recovery to the same capability status.
    shed: Arc<ShedReporter>,
}

/// Reports shed blocked-DNS records to the shared collector health, and clears the report
/// only when this producer is the one that raised it.
#[derive(Default)]
struct ShedReporter {
    health: ArcSwapOption<CollectorHealth>,
    reported: AtomicBool,
    gate: Mutex<()>,
}

impl ShedReporter {
    fn set_health(&self, health: Arc<CollectorHealth>) {
        let _gate = self.gate.lock();
        if self.reported.load(Ordering::Relaxed) {
            health.mark_records_shed(
                "Some blocked DNS queries could not be recorded. Blocked-DNS history will be \
                 incomplete until local persistence recovers.",
            );
        }
        self.health.store(Some(health));
    }

    fn report(&self) {
        let _gate = self.gate.lock();
        self.reported.store(true, Ordering::Relaxed);
        if let Some(health) = self.health.load_full() {
            health.mark_records_shed(
                "Some blocked DNS queries could not be recorded. Blocked-DNS history will be \
                 incomplete until local persistence recovers.",
            );
        }
    }

    fn recovered(&self) {
        let _gate = self.gate.lock();
        if self.reported.swap(false, Ordering::Relaxed) {
            if let Some(health) = self.health.load_full() {
                health.clear_records_shed();
            }
        }
    }
}

struct RuntimeSettings {
    log_daemon_connections: AtomicBool,
    notify_threat_detected: AtomicBool,
}

struct DnsBlockWorker {
    app_resolver: Arc<AppIdResolver>,
    store: Arc<Store>,
    alerts: AlertPublisher,
    siem: SiemExporter,
    settings: Arc<RuntimeSettings>,
    correlator: Arc<DnsQueryCorrelator>,
    reconciliation_delay: Duration,
    pending_reconciliations: Arc<AtomicU64>,
    /// Canonical path of the running daemon, so its own blocks are identified by
    /// where it is installed rather than by a file name any process can adopt.
    daemon_path: Option<PathBuf>,
    shed: Arc<ShedReporter>,
    /// Blocks written before their reconciliation delay ran out because the
    /// pending queue was full, so late ETW evidence could not attribute them.
    early_reconciliations: AtomicU64,
}

impl DnsBlockRecorder {
    #[must_use]
    pub fn new(
        app_resolver: Arc<AppIdResolver>,
        store: Arc<Store>,
        alerts: AlertPublisher,
        siem: SiemExporter,
    ) -> Arc<Self> {
        Self::with_correlator(
            app_resolver,
            store,
            alerts,
            siem,
            Arc::new(DnsQueryCorrelator::default()),
        )
    }

    #[must_use]
    pub fn with_correlator(
        app_resolver: Arc<AppIdResolver>,
        store: Arc<Store>,
        alerts: AlertPublisher,
        siem: SiemExporter,
        correlator: Arc<DnsQueryCorrelator>,
    ) -> Arc<Self> {
        Self::with_correlator_and_delay(
            app_resolver,
            store,
            alerts,
            siem,
            correlator,
            Duration::from_millis(DNS_BLOCK_RECONCILIATION_MS),
        )
    }

    fn with_correlator_and_delay(
        app_resolver: Arc<AppIdResolver>,
        store: Arc<Store>,
        alerts: AlertPublisher,
        siem: SiemExporter,
        correlator: Arc<DnsQueryCorrelator>,
        reconciliation_delay: Duration,
    ) -> Arc<Self> {
        let settings = Arc::new(RuntimeSettings {
            log_daemon_connections: AtomicBool::new(false),
            notify_threat_detected: AtomicBool::new(true),
        });
        let worker_stop = Arc::new(AtomicBool::new(false));
        let pending_reconciliations = Arc::new(AtomicU64::new(0));
        let shed = Arc::new(ShedReporter::default());
        let (tx, rx) = mpsc::sync_channel(WRITE_QUEUE_CAPACITY);
        let worker_state = DnsBlockWorker {
            app_resolver,
            store,
            alerts,
            siem,
            settings: Arc::clone(&settings),
            correlator,
            reconciliation_delay,
            pending_reconciliations: Arc::clone(&pending_reconciliations),
            daemon_path: daemon_executable_path(),
            shed: Arc::clone(&shed),
            early_reconciliations: AtomicU64::new(0),
        };
        let thread_stop = Arc::clone(&worker_stop);
        let worker = std::thread::Builder::new()
            .name("antiwire-dns-block-recorder".to_owned())
            .spawn(move || worker_state.run(&rx, &thread_stop));
        let (tx, worker) = match worker {
            Ok(worker) => (Some(tx), Some(worker)),
            Err(error) => {
                warn!(%error, "failed to start dns block persistence worker");
                (None, None)
            }
        };

        Arc::new(Self {
            tx: Arc::new(Mutex::new(tx)),
            settings,
            worker_stop,
            worker: Mutex::new(worker),
            dropped: AtomicU64::new(0),
            #[cfg(test)]
            pending_reconciliations,
            shed,
        })
    }

    /// Shares collector capability status so shed blocked-DNS records surface to the UI.
    pub fn set_collector_health(&self, collector_health: Arc<CollectorHealth>) {
        self.shed.set_health(collector_health);
    }

    /// Number of block events currently waiting for late correlation evidence.
    #[cfg(test)]
    #[must_use]
    pub fn pending_reconciliation_count(&self) -> u64 {
        self.pending_reconciliations.load(Ordering::Relaxed)
    }

    pub fn update_settings(&self, log_daemon_connections: bool, notify_threat_detected: bool) {
        self.settings
            .log_daemon_connections
            .store(log_daemon_connections, Ordering::Relaxed);
        self.settings
            .notify_threat_detected
            .store(notify_threat_detected, Ordering::Relaxed);
    }

    /// Signals the persistence worker to finish and waits a bounded time for its
    /// final flush.
    ///
    /// Idempotent. The worker re-checks its stop flag at least every
    /// [`WORKER_STOP_POLL`], so this resolves promptly unless an in-flight `SQLite`
    /// write is stuck; a timeout is logged rather than failing the caller, and the
    /// worker is left to finish or die with the process.
    pub async fn shutdown(&self) {
        // Close admission before asking the worker to stop. `enqueue` holds the
        // same mutex through `try_send`, so an event is either queued before
        // this point or explicitly shed after it; no producer can race a
        // worker that has already decided the channel is empty.
        self.tx.lock().take();
        self.worker_stop.store(true, Ordering::Release);
        let Some(worker) = self.worker.lock().take() else {
            return;
        };
        // A timed-out spawn_blocking(join) still holds up Tokio runtime teardown.
        // Poll the native handle and join only after the worker has actually exited.
        let deadline = Instant::now() + WORKER_JOIN_TIMEOUT;
        while !worker.is_finished() && Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        finish_worker(worker);
    }
}

/// Dropping the recorder stops its worker but never waits for it. The last
/// reference can be released on an async runtime thread, which must not park
/// behind a `SQLite` write; the worker drains what was queued and exits on its
/// own. [`DnsBlockRecorder::shutdown`] is the path that waits for the flush.
impl Drop for DnsBlockRecorder {
    fn drop(&mut self) {
        self.tx.lock().take();
        self.worker_stop.store(true, Ordering::Release);
    }
}

fn finish_worker(worker: JoinHandle<()>) {
    if !worker.is_finished() {
        warn!("dns block persistence worker did not stop in time; it may still be writing");
    } else if worker.join().is_err() {
        warn!("dns block persistence worker panicked");
    }
}

impl DnsBlockSink for DnsBlockRecorder {
    fn record_blocked_query(&self, domain: &str, pid: u32, blocklist_names: &[String]) {
        self.enqueue(domain, PendingOwnership::Caller(pid), blocklist_names, None);
    }

    fn record_blocked_query_with_ownership(
        &self,
        domain: &str,
        ownership: Ownership,
        blocklist_names: &[String],
        timestamp: Option<time::OffsetDateTime>,
    ) {
        self.enqueue(
            domain,
            PendingOwnership::Socket(ownership),
            blocklist_names,
            timestamp,
        );
    }

    fn update_runtime_settings(&self, log_daemon_connections: bool, notify_threat_detected: bool) {
        self.update_settings(log_daemon_connections, notify_threat_detected);
    }
}

impl DnsBlockRecorder {
    fn enqueue(
        &self,
        domain: &str,
        ownership: PendingOwnership,
        blocklist_names: &[String],
        timestamp: Option<OffsetDateTime>,
    ) {
        // A blocked name may be attacker-crafted, and it is written to `SQLite`,
        // SIEM, notifications, and tracing: sanitize once at the boundary.
        let domain = sanitize::trimmed(domain, sanitize::MAX_DOMAIN_CHARS);
        if domain.is_empty() {
            return;
        }
        let blocklist_names = sanitize_labels(blocklist_names);
        let ts = timestamp.unwrap_or_else(OffsetDateTime::now_utc);
        let block = PendingBlock {
            domain,
            ownership,
            blocklist_names,
            timestamp: ts,
        };
        let send_result = {
            let tx = self.tx.lock();
            match tx.as_ref() {
                Some(tx) => tx.try_send(block),
                None => Err(TrySendError::Disconnected(block)),
            }
        };
        match send_result {
            Ok(()) => {}
            Err(TrySendError::Full(block)) => {
                let dropped = self.dropped.fetch_add(1, Ordering::Relaxed) + 1;
                if dropped.is_power_of_two() {
                    warn!(
                        domain = %block.domain,
                        dropped, "dns block write queue full; dropping events"
                    );
                }
                self.shed.report();
            }
            Err(TrySendError::Disconnected(block)) => {
                let dropped = self.dropped.fetch_add(1, Ordering::Relaxed) + 1;
                if dropped.is_power_of_two() {
                    warn!(
                        domain = %block.domain,
                        dropped, "dns block persistence worker stopped; dropping events"
                    );
                }
                self.shed.report();
            }
        }
    }
}

/// Canonical path of the running daemon executable, or `None` when unavailable.
///
/// `None` disables daemon suppression rather than falling back to a name match,
/// which a local process could forge.
fn daemon_executable_path() -> Option<PathBuf> {
    let path = std::env::current_exe().ok()?;
    Some(std::fs::canonicalize(&path).unwrap_or(path))
}

/// Returns true when `app_path` is the running daemon's own executable.
///
/// Identity comes from the canonical install path, never the file name: an
/// unprivileged process can copy itself to `%TEMP%\antiwire-daemon.exe` and must
/// not be able to suppress its own blocked-DNS audit trail by doing so.
fn is_daemon_executable(daemon_path: Option<&Path>, app_path: &str) -> bool {
    let Some(daemon_path) = daemon_path else {
        return false;
    };
    if app_path.is_empty() {
        return false;
    }
    let candidate = Path::new(app_path);
    let candidate = std::fs::canonicalize(candidate).unwrap_or_else(|_| candidate.to_path_buf());
    #[cfg(windows)]
    {
        candidate
            .as_os_str()
            .eq_ignore_ascii_case(daemon_path.as_os_str())
    }
    #[cfg(not(windows))]
    {
        candidate == daemon_path
    }
}

struct RecentLru {
    map: lru::LruCache<DnsBlockKey, Instant>,
}

impl RecentLru {
    fn new(capacity: usize) -> Self {
        Self {
            map: lru::LruCache::new(
                std::num::NonZeroUsize::new(capacity.max(1)).expect("positive capacity"),
            ),
        }
    }

    fn should_admit(&mut self, key: DnsBlockKey, now: Instant, window: Duration) -> bool {
        // A suppressed duplicate must not refresh the admission window or recency.
        if let Some(&seen) = self.map.peek(&key) {
            if now.saturating_duration_since(seen) < window {
                return false;
            }
        }
        self.insert(key, now);
        true
    }

    fn insert(&mut self, key: DnsBlockKey, now: Instant) {
        self.map.put(key, now);
    }
}

/// Sanitizes blocklist labels before they are persisted or interpolated.
///
/// Labels cannot be trusted to be control-free: they are joined with `,` into
/// notification text and with a newline by [`antiwire_store::encode_blocklist_names`],
/// so a label containing either must not be able to forge records.
fn sanitize_labels(names: &[String]) -> Vec<String> {
    names
        .iter()
        .map(|name| sanitize::trimmed(name, sanitize::MAX_LABEL_CHARS))
        .filter(|name| !name.is_empty())
        .collect()
}

#[cfg(test)]
mod tests;
