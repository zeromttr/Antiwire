use crate::port_pid_cache::PortPidCache;
use crate::process_resolver::BootstrapStats;
use crate::processor::{FlowProcessor, NameRequest, Naming, Opening};
use crate::store::FlowStore;
#[cfg(test)]
use crate::Result;
use antiwire_events::CollectorHealth;
use antiwire_store::{ConnectionLogAttribution, NewConnectionLog};
use antiwire_tuning::{
    Backoff, FLOW_CLOSED_IDENTITY_CAPACITY, FLOW_CLOSED_IDENTITY_RETENTION, FLOW_IDLE_TIMEOUT_MS,
    FLOW_PENDING_ATTRIBUTION_HARD_CAP, FLOW_PENDING_WRITE_HARD_CAP, FLOW_WRITE_BATCH_SIZE,
    FLOW_WRITE_COALESCE_WINDOW,
};
#[cfg(test)]
use antiwire_tuning::{
    FLOW_ACTIVE_FLOWS_HARD_CAP, FLOW_FLUSH_FAILURES_BEFORE_DEGRADED,
    UNKNOWN_SOCKET_ATTRIBUTION_DELAY,
};
#[cfg(test)]
use netmetrics_core::FlowEvent;
#[cfg(test)]
use netmetrics_core::SocketOwnerSnapshot;
#[cfg(test)]
use netmetrics_core::{ByteDelta, DegradeReason, FlowMeta, ProcessIdentity, Protocol};
use netmetrics_core::{FlowKey, SocketCookie};
use parking_lot::Mutex;
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use time::OffsetDateTime;
#[cfg(test)]
use tokio::sync::mpsc;

mod closed_identity;
use closed_identity::ClosedIdentityQueue;

mod attribution;
mod degradation;
mod lifecycle;
mod persistence;
#[cfg(test)]
mod test_hooks;
use attribution::application_identity;

#[cfg(test)]
#[path = "tracker/attribution_tests.rs"]
mod attribution_tests;

const RECEIVE_BATCH_LIMIT: usize = 256;

/// When the supervisor decides the tracker has stalled.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct WatchdogTiming {
    /// How often the supervisor samples the tracker's progress counter.
    interval: Duration,
    /// Consecutive samples without progress before a stall is reported.
    stall_ticks: u32,
}

impl Default for WatchdogTiming {
    fn default() -> Self {
        Self {
            interval: Duration::from_secs(30),
            stall_ticks: 4,
        }
    }
}

/// Cumulative process-identity recovery counters (see
/// [`FlowTracker::identity_recovery_stats`]).
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct IdentityRecoveryStats {
    /// Identity refresh resolutions attempted for recoverable flows.
    pub attempts: u64,
    /// Flows upgraded from a placeholder/unknown identity to a real one.
    pub recoveries: u64,
    /// Mean open-to-upgrade latency in milliseconds, over recovered flows.
    pub mean_recovery_latency_ms: u64,
}

/// Distinct applications whose finished-flow bytes are remembered for rates.
/// Beyond this, new applications simply start from their live flows.
const CLOSED_APP_BYTES_CAP: usize = 4_096;
/// Destinations reported per application.
const TOP_DESTINATIONS: usize = 3;

/// One application owning live flows (see [`FlowTracker::active_applications`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ActiveApplication {
    /// Stable identity (see `application_identity`), for pairing snapshots.
    pub key: String,
    pub app_name: String,
    pub app_path: String,
    /// Its tracked flows, leaving out those whose connection is no longer
    /// established and has not closed yet.
    pub connection_count: u32,
    /// Bytes moved since the daemon started, finished flows included, so two
    /// snapshots give a rate. Only a flow re-attributed away can lower it.
    pub total_sent: u64,
    pub total_received: u64,
    /// Busiest destinations first (domain once known, else the IP).
    pub top_destinations: Vec<String>,
    pub destination_count: u32,
    /// When its newest live flow opened.
    pub newest_opened_at: OffsetDateTime,
}

#[derive(Debug, Clone)]
struct ActiveFlow {
    /// Tracker-assigned session id. One `ActiveFlow` owns exactly one value,
    /// so the store can tell repeats from the same connection apart from a new
    /// connection reusing the tuple. Superseded and reopened flows get fresh ids.
    conn_id: u64,
    /// Pid observed when the flow opened, pinned as the store identity's pid
    /// component. The live `pid` may resolve afterwards (unknown flows) or be
    /// re-attributed, so it must not feed the identity: every flush of one
    /// connection has to carry the same triple.
    open_pid: u32,
    app_id: i32,
    app_path: String,
    app_name: String,
    pid: u32,
    protocol: String,
    src_ip: String,
    src_port: i32,
    dst_ip: String,
    dst_port: i32,
    bytes_sent: u64,
    bytes_received: u64,
    /// Byte totals already persisted for this active session (upsert deltas).
    persisted_sent: u64,
    persisted_received: u64,
    /// Whether a `connection_logs` row exists for this flow key.
    db_row_created: bool,
    /// Application identity used by the row already in `connection_logs`.
    persisted_app_id: i32,
    /// Last `dst_domain` written for this active session.
    persisted_domain: String,
    name_lookup: NameLookup,
    traffic_template: Option<Arc<antiwire_events::TrafficEvent>>,
    /// When this flow was first classified as unknown (socket-table grace window).
    unknown_since: Option<Instant>,
    /// Set when port-cache or socket-table lookup fully resolved attribution.
    unknown_socket_lookup_done: bool,
    /// Bounded scheduled retries; forced close lookup is independent.
    socket_lookup_attempts: u8,
    next_socket_lookup: Option<Instant>,
    /// Bounded retries for process-identity recovery while the flow is alive.
    /// Unthrottled retries would re-run a failing `OpenProcess` on every
    /// packet of a long-lived unknown flow.
    identity_lookup_attempts: u8,
    next_identity_retry: Option<Instant>,
    /// Only one off-lock lookup may update this flow at a time.
    attribution_lookup: AttributionLookup,
    /// Per-socket identity, when a backend resolved one for this flow.
    cookie: Option<SocketCookie>,
    /// Creation timestamp of `pid` from flow metadata or the selected cached,
    /// tracked, or live process identity.
    ///
    /// Retained so a later re-attribution can validate a cached identity
    /// against the process it actually belongs to, instead of inheriting a
    /// recycled PID's cache entry after a lost lifecycle event.
    process_start_ts: Option<u64>,
    /// When the backend saw the flow open, Unix milliseconds, zero when it did
    /// not say. A process created after it is a later holder of the PID.
    open_ts: u64,
    /// Set once the backend reports the flow's connection no longer established
    /// (`FlowEvent::Finishing`). The flow is then no longer one of its
    /// application's connections, and still takes bytes until it closes.
    finishing: bool,
    opened_at: OffsetDateTime,
    last_seen: OffsetDateTime,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AttributionLookup {
    Idle,
    Running,
    RefreshPending,
}

/// When an active flow's name should be looked up again, and what the
/// answer may then do to the name already written.
///
/// A lookup is judged at the time the flow opened, so its answer changes only
/// when DNS evidence arrives for the flow's address or the flow turns out to
/// belong to another process or application. Until one of those happens the
/// flow is left alone.
///
/// The last lookup's [`Naming`] says what arriving evidence means. While the
/// answer is provisional the evidence may be from before the flow opened, and
/// the next answer replaces the name. After that it can only confirm a name
/// that is not final, and a final name is left alone whatever arrives.
#[derive(Debug, Clone, Default)]
struct NameLookup {
    /// The PID and application the last lookup was made for; `None` before
    /// the first.
    made_for: Option<(u32, i32)>,
    /// What that lookup said of its answer.
    naming: Naming,
    /// When the first DNS evidence that could change the answer arrived, of
    /// what has been noticed since that lookup, in Unix epoch milliseconds.
    evidence_at_ms: Option<u64>,
}

impl NameLookup {
    /// DNS evidence for the flow's address arrived at `arrived_ms`. It is
    /// noticed a flush tick later or more, and what it may do to the name
    /// goes by when it arrived.
    fn note_evidence(&mut self, arrived_ms: u64) {
        if self.made_for.is_some() && self.naming.open_at(arrived_ms) {
            self.evidence_at_ms.get_or_insert(arrived_ms);
        }
    }

    /// Whether a lookup for a flow of `pid` and `app_id` could find more than
    /// the last one did.
    fn due(&self, pid: u32, app_id: i32) -> bool {
        self.made_for != Some((pid, app_id)) || self.evidence_at_ms.is_some()
    }

    /// What to ask of the name of a flow of `pid` and `app_id`, opened at
    /// `opening`, as its row is written.
    fn request(&self, pid: u32, app_id: i32, opening: Opening) -> NameRequest {
        if self.made_for != Some((pid, app_id)) {
            // The name, if there is one, was judged for another owner.
            return NameRequest::replacing(opening);
        }
        match self.evidence_at_ms {
            Some(noticed) => NameRequest::Judge {
                opening,
                replaces: self.naming.provisional_at(noticed),
            },
            None => NameRequest::Keep,
        }
    }

    /// [`Self::request`] for a flow that closes at `now_ms`. Its row is not
    /// written again, so the name is looked up once more whether or not
    /// evidence has been noticed, unless it is final.
    fn closing_request(&self, pid: u32, app_id: i32, opening: Opening, now_ms: u64) -> NameRequest {
        if self.made_for != Some((pid, app_id)) {
            return NameRequest::replacing(opening);
        }
        let noticed = self.evidence_at_ms.unwrap_or(now_ms);
        if !self.naming.open_at(noticed) {
            return NameRequest::Keep;
        }
        NameRequest::Judge {
            opening,
            replaces: self.naming.provisional_at(noticed),
        }
    }

    /// A lookup for a flow of `pid` and `app_id` was made, said `naming` of
    /// its answer, and the answer was kept.
    fn made(&mut self, pid: u32, app_id: i32, naming: Naming) {
        self.made_for = Some((pid, app_id));
        self.naming = naming;
        self.evidence_at_ms = None;
    }
}

struct AttributionVersion {
    conn_id: u64,
    pid: u32,
    start_ts: Option<u64>,
    cookie: Option<SocketCookie>,
    app_id: i32,
    app_path: String,
    app_name: String,
}

impl AttributionVersion {
    fn capture(flow: &ActiveFlow) -> Self {
        Self {
            conn_id: flow.conn_id,
            pid: flow.pid,
            start_ts: flow.process_start_ts,
            cookie: flow.cookie,
            app_id: flow.app_id,
            app_path: flow.app_path.clone(),
            app_name: flow.app_name.clone(),
        }
    }

    fn matches(&self, flow: &ActiveFlow) -> bool {
        self.conn_id == flow.conn_id
            && self.pid == flow.pid
            && self.start_ts == flow.process_start_ts
            && self.cookie == flow.cookie
            && self.app_id == flow.app_id
            && self.app_path == flow.app_path
            && self.app_name == flow.app_name
    }
}

/// Aggregates [`FlowEvent`]s and writes connection logs in batches.
pub struct FlowTracker<S: FlowStore> {
    store: S,
    processor: Option<Arc<FlowProcessor>>,
    active: Mutex<HashMap<FlowKey, ActiveFlow>>,
    /// Bytes of finished flows per application identity, so an application's
    /// running total survives its connections closing.
    closed_app_bytes: Mutex<HashMap<String, (u64, u64)>>,
    closed_identities: Mutex<ClosedIdentityQueue>,
    port_pid_cache: Mutex<PortPidCache>,
    pending_attributions: Mutex<Vec<ConnectionLogAttribution>>,
    pending: Mutex<Vec<NewConnectionLog>>,
    /// Degradation reasons already reported, so a backend restart loop cannot spam the log.
    reported_degradations: Mutex<HashSet<String>>,
    /// Capability status shared with the IPC layer, when the daemon wired one in.
    collector_health: Option<Arc<CollectorHealth>>,
    /// Excludes lifecycle changes only while a bounded active-flow write commits.
    flush_gate: Mutex<()>,
    /// Serializes persistence passes without blocking lifecycle callbacks.
    persistence_gate: Mutex<()>,
    /// Consecutive failures of the queued-write flush (closed logs and
    /// re-attributions), for degradation reporting.
    queue_flush_failures: AtomicU32,
    /// Consecutive failures of the active-flow byte flush. Kept apart from the
    /// queued-write streak so one path succeeding cannot hide the other failing.
    active_flush_failures: AtomicU32,
    /// Records shed because the backlog was already at its cap.
    shed_records: AtomicU64,
    /// Source for per-connection session ids handed to the store.
    next_conn_id: AtomicU64,
    /// Monotonic event-loop iteration counter, sampled by the stall watchdog.
    progress: AtomicU64,
    watchdog: WatchdogTiming,
    /// Identity-recovery telemetry: attempts, same-instance upgrades, and
    /// total open-to-upgrade latency (see [`IdentityRecoveryStats`]).
    identity_recovery_attempts: AtomicU64,
    identity_recoveries: AtomicU64,
    identity_recovery_latency_ms: AtomicU64,
    /// Closed connections by the kind of owner they ended with.
    closed_owners: [AtomicU64; 6],
    /// Test-only count of OS socket-table captures, so lookup gates stay observable.
    #[cfg(test)]
    socket_snapshot_calls: AtomicU64,
    batch_size: usize,
    pending_cap: usize,
    attribution_cap: usize,
    coalesce: Duration,
    idle_timeout: Duration,
}

impl<S: FlowStore + Send + Sync + 'static> antiwire_dns::DnsHintSink for FlowTracker<S> {
    fn record_hint(
        &self,
        pid: u32,
        query: &str,
        answers: &[std::net::IpAddr],
        ttl_ms: u64,
        answered_at_ms: u64,
    ) {
        self.record_dns_hint(pid, query, answers, ttl_ms, answered_at_ms);
    }

    fn record_resolution(&self, query: &str, answers: &[std::net::IpAddr]) {
        if let Some(processor) = &self.processor {
            processor.record_stub_resolution(query, answers);
        }
    }
}

impl<S: FlowStore> FlowTracker<S> {
    /// Forwards a stub answer, served at `answered_at_ms` in Unix epoch
    /// milliseconds, into the process-scoped DNS hint map.
    pub fn record_dns_hint(
        &self,
        pid: u32,
        query: &str,
        answers: &[std::net::IpAddr],
        ttl_ms: u64,
        answered_at_ms: u64,
    ) {
        if let Some(processor) = &self.processor {
            processor.record_stub_hint(pid, query, answers, ttl_ms, answered_at_ms);
        }
    }

    #[must_use]
    pub fn new(store: S) -> Self {
        Self::with_processor(store, None)
    }

    #[must_use]
    pub fn with_processor(store: S, processor: Option<Arc<FlowProcessor>>) -> Self {
        Self {
            store,
            processor,
            active: Mutex::new(HashMap::new()),
            closed_app_bytes: Mutex::new(HashMap::new()),
            closed_identities: Mutex::new(ClosedIdentityQueue::new(
                FLOW_CLOSED_IDENTITY_CAPACITY,
                FLOW_CLOSED_IDENTITY_RETENTION,
            )),
            port_pid_cache: Mutex::new(PortPidCache::default()),
            pending_attributions: Mutex::new(Vec::new()),
            pending: Mutex::new(Vec::new()),
            reported_degradations: Mutex::new(HashSet::new()),
            collector_health: None,
            flush_gate: Mutex::new(()),
            persistence_gate: Mutex::new(()),
            queue_flush_failures: AtomicU32::new(0),
            active_flush_failures: AtomicU32::new(0),
            shed_records: AtomicU64::new(0),
            // Zero is reserved for legacy/unattributed rows that must never
            // match another row, so session ids start at one.
            next_conn_id: AtomicU64::new(1),
            progress: AtomicU64::new(0),
            watchdog: WatchdogTiming::default(),
            identity_recovery_attempts: AtomicU64::new(0),
            identity_recoveries: AtomicU64::new(0),
            identity_recovery_latency_ms: AtomicU64::new(0),
            closed_owners: Default::default(),
            #[cfg(test)]
            socket_snapshot_calls: AtomicU64::new(0),
            batch_size: FLOW_WRITE_BATCH_SIZE as usize,
            pending_cap: FLOW_PENDING_WRITE_HARD_CAP,
            attribution_cap: usize::try_from(FLOW_PENDING_ATTRIBUTION_HARD_CAP)
                .unwrap_or(usize::MAX),
            coalesce: FLOW_WRITE_COALESCE_WINDOW,
            idle_timeout: Duration::from_millis(FLOW_IDLE_TIMEOUT_MS as u64),
        }
    }

    /// Shares collector capability status with the IPC layer so the UI can explain a
    /// degraded collector instead of silently showing zeros.
    #[must_use]
    pub fn with_collector_health(mut self, collector_health: Arc<CollectorHealth>) -> Self {
        self.collector_health = Some(collector_health);
        self
    }

    /// Cumulative identity-recovery telemetry.
    ///
    /// `mean_recovery_latency_ms` is the mean open-to-upgrade time over
    /// recovered flows only; it stays zero until the first recovery.
    #[must_use]
    pub(crate) fn identity_recovery_stats(&self) -> IdentityRecoveryStats {
        let recoveries = self.identity_recoveries.load(Ordering::Relaxed);
        let total_latency_ms = self.identity_recovery_latency_ms.load(Ordering::Relaxed);
        IdentityRecoveryStats {
            attempts: self.identity_recovery_attempts.load(Ordering::Relaxed),
            recoveries,
            mean_recovery_latency_ms: total_latency_ms.checked_div(recoveries).unwrap_or(0),
        }
    }

    /// Closed connections by the kind of owner they ended with: an
    /// application with a real executable path, `System`, a process known by
    /// name only, no owner, a process that had exited, and any other unknown.
    #[must_use]
    pub(crate) fn closed_owner_stats(&self) -> [u64; 6] {
        self.closed_owners
            .each_ref()
            .map(|count| count.load(Ordering::Relaxed))
    }

    /// Seeds process evidence from processes already running at daemon start
    /// (parity with ETW `ProcessDCStart` rundown), so their first flows resolve
    /// before any lifecycle event arrives. A tracker without a processor
    /// resolves no identities, so it seeds nothing.
    pub fn bootstrap_running_processes(&self) -> BootstrapStats {
        self.processor
            .as_ref()
            .map(|processor| processor.processes().bootstrap_running_processes())
            .unwrap_or_default()
    }

    /// Returns the number of flows currently tracked for connection logging.
    #[must_use]
    pub fn tracked_flow_count(&self) -> u32 {
        u32::try_from(self.active.lock().len()).unwrap_or(u32::MAX)
    }

    /// Returns how many distinct applications own at least one tracked flow.
    ///
    /// Flows still waiting on attribution (no path, a synthetic placeholder,
    /// or the unknown application) are left out rather than counted as one "unknown"
    /// application.
    #[must_use]
    pub fn active_application_count(&self) -> u32 {
        let active = self.active.lock();
        let apps: HashSet<String> = active
            .values()
            .filter_map(|flow| application_identity(&flow.app_path, &flow.app_name))
            .collect();
        u32::try_from(apps.len()).unwrap_or(u32::MAX)
    }

    /// Applications owning at least one tracked flow, with running byte totals
    /// and their busiest destinations. Unattributed flows are left out, as in
    /// [`Self::active_application_count`].
    #[must_use]
    pub fn active_applications(&self) -> Vec<ActiveApplication> {
        struct Acc {
            app_name: String,
            app_path: String,
            count: u32,
            sent: u64,
            received: u64,
            destinations: HashMap<String, u64>,
            newest: OffsetDateTime,
        }

        let mut apps: HashMap<String, Acc> = HashMap::new();
        {
            let active = self.active.lock();
            for flow in active.values() {
                let Some(key) = application_identity(&flow.app_path, &flow.app_name) else {
                    continue;
                };
                let acc = apps.entry(key).or_insert_with(|| Acc {
                    app_name: flow.app_name.clone(),
                    app_path: flow.app_path.clone(),
                    count: 0,
                    sent: 0,
                    received: 0,
                    destinations: HashMap::new(),
                    newest: flow.opened_at,
                });
                if !flow.finishing {
                    acc.count = acc.count.saturating_add(1);
                }
                acc.sent = acc.sent.saturating_add(flow.bytes_sent);
                acc.received = acc.received.saturating_add(flow.bytes_received);
                let destination = if flow.persisted_domain.is_empty() {
                    flow.dst_ip.clone()
                } else {
                    flow.persisted_domain.clone()
                };
                let bytes = flow.bytes_sent.saturating_add(flow.bytes_received);
                let slot = acc.destinations.entry(destination).or_default();
                *slot = slot.saturating_add(bytes);
                if flow.opened_at > acc.newest {
                    acc.newest = flow.opened_at;
                }
            }
        }

        let closed = self.closed_app_bytes.lock();
        apps.into_iter()
            .map(|(key, acc)| {
                let (closed_sent, closed_received) = closed.get(&key).copied().unwrap_or((0, 0));
                let mut destinations: Vec<(String, u64)> = acc.destinations.into_iter().collect();
                destinations.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
                ActiveApplication {
                    key,
                    app_name: acc.app_name,
                    app_path: acc.app_path,
                    connection_count: acc.count,
                    total_sent: closed_sent.saturating_add(acc.sent),
                    total_received: closed_received.saturating_add(acc.received),
                    destination_count: u32::try_from(destinations.len()).unwrap_or(u32::MAX),
                    top_destinations: destinations
                        .into_iter()
                        .take(TOP_DESTINATIONS)
                        .map(|(destination, _)| destination)
                        .collect(),
                    newest_opened_at: acc.newest,
                }
            })
            .collect()
    }

    /// Keys of the live flows owned by the application at `app_path`. Empty
    /// when the path does not identify an application (see `application_identity`).
    #[must_use]
    pub fn application_flows(&self, app_path: &str) -> Vec<FlowKey> {
        let Some(wanted) = application_identity(app_path, "") else {
            return Vec::new();
        };
        let active = self.active.lock();
        active
            .iter()
            .filter(|(_, flow)| {
                application_identity(&flow.app_path, &flow.app_name).as_deref()
                    == Some(wanted.as_str())
            })
            .map(|(key, _)| *key)
            .collect()
    }
}

const MAX_SOCKET_LOOKUP_ATTEMPTS: u8 = 4;
/// Wait between socket-owner lookups for a flow: 2, 4, 8, then 16 s.
const SOCKET_LOOKUP_BACKOFF: Backoff =
    Backoff::new(Duration::from_secs(2), Duration::from_secs(16));

/// Bounded identity-recovery retries per flow; lifecycle events and the
/// close-time reresolve bypass this budget with forced refreshes.
const MAX_IDENTITY_LOOKUP_ATTEMPTS: u8 = 6;
/// Wait between identity retries: `2^attempts` seconds, at most a minute.
const IDENTITY_RETRY_BACKOFF: Backoff =
    Backoff::new(Duration::from_secs(2), Duration::from_secs(60));

#[cfg(test)]
mod tests;
