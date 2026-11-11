use crate::config::{CollectorBuilder, CollectorConfig};
mod publication;
mod reconcile;
mod supervisor;
#[cfg(test)]
use netmetrics_core::DnsResolutionAttribution;
use netmetrics_core::unix_now_ms;
use netmetrics_core::{
    DegradeReason, FlowEvent, FlowKey, FlowSnapshot, FlowTable, IngressCoalescer, MetricsError,
    ProcessTable,
};
#[cfg(test)]
use netmetrics_sys::BackendEvent;
use netmetrics_sys::{
    Backend, BackendConfig, BackendError, EventSink, OrderedIngress, StopFlag, WakeState,
};
use publication::{SnapshotPublisher, flush_batch, flush_full_batches, publish_snapshot};
#[cfg(test)]
use reconcile::effective_dns_ttl;
use reconcile::process_backend_event;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, TryRecvError};
use std::sync::{Arc, RwLock};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};
use supervisor::{BackendRun, spawn_backend};

/// Longest wait between backend restarts, however often a backend keeps failing.
const MAX_BACKEND_BACKOFF: Duration = Duration::from_secs(30);
/// A backend that ran this long before failing is not in a crash loop, so the
/// next restart waits only the configured base delay.
const BACKEND_STABLE_UPTIME: Duration = Duration::from_secs(60);

pub(crate) type BackendFactory = Arc<dyn Fn() -> Box<dyn Backend> + Send + Sync>;

/// Consumer of normalized flow events.
pub trait FlowConsumer: Send + 'static {
    /// Handles one event. The default batch implementation calls this method.
    fn on_event(&mut self, event: FlowEvent);

    /// Handles a bounded event batch. Override to reduce downstream lock traffic.
    fn on_batch(&mut self, events: &[FlowEvent]) {
        for event in events {
            self.on_event(event.clone());
        }
    }

    /// Consumes events from a reusable collector-owned buffer.
    ///
    /// The default preserves custom [`FlowConsumer::on_batch`] implementations. Consumers
    /// that can take ownership may override this to avoid event clones.
    fn on_batch_buffer(&mut self, events: &mut Vec<FlowEvent>) {
        self.on_batch(events);
        events.clear();
    }
}

impl<F> FlowConsumer for F
where
    F: FnMut(FlowEvent) + Send + 'static,
{
    fn on_event(&mut self, event: FlowEvent) {
        self(event);
    }

    fn on_batch_buffer(&mut self, events: &mut Vec<FlowEvent>) {
        for event in events.drain(..) {
            self(event);
        }
    }
}

#[derive(Debug, Default)]
struct SharedStats {
    ingress_dropped: AtomicU64,
    flow_evicted: AtomicU64,
    backend_restarts: AtomicU64,
    events_published: AtomicU64,
}

#[derive(Debug, Default)]
struct SnapshotState {
    generation: u64,
    snapshot: FlowSnapshot,
}

/// Point-in-time collector operational counters.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CollectorStats {
    /// Native events discarded by the bounded ingress queue.
    pub ingress_dropped: u64,
    /// Flow rows evicted at the configured cap.
    pub flow_evicted: u64,
    /// Native session restarts initiated by the watchdog.
    pub backend_restarts: u64,
    /// Normalized events delivered to the consumer.
    pub events_published: u64,
}

/// Owns one native backend, accounting state, watchdog, and consumer worker.
pub struct Collector {
    config: CollectorConfig,
    backend_factory: BackendFactory,
    stop: StopFlag,
    snapshot: Arc<RwLock<SnapshotState>>,
    stats: Arc<SharedStats>,
    worker: Option<JoinHandle<()>>,
}

impl std::fmt::Debug for Collector {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Collector")
            .field("config", &self.config)
            .field("running", &self.is_running())
            .field("stats", &self.stats())
            .finish_non_exhaustive()
    }
}

impl Collector {
    /// Begins fluent collector configuration.
    pub fn builder() -> CollectorBuilder {
        CollectorBuilder::new()
    }

    pub(crate) fn new(config: CollectorConfig, backend_factory: Option<BackendFactory>) -> Self {
        Self {
            config,
            backend_factory: backend_factory.unwrap_or_else(default_backend_factory),
            stop: StopFlag::new(),
            snapshot: Arc::new(RwLock::new(SnapshotState::default())),
            stats: Arc::new(SharedStats::default()),
            worker: None,
        }
    }

    /// Starts collection. Native callbacks never execute consumer code.
    ///
    /// # Errors
    ///
    /// Returns [`MetricsError::AlreadyRunning`] if already started or
    /// [`MetricsError::Backend`] if the worker thread cannot be created. Returns
    /// [`MetricsError::ThreadPanic`] when reaping a previously failed worker.
    pub fn start(&mut self, consumer: Box<dyn FlowConsumer>) -> Result<(), MetricsError> {
        if self.is_running() {
            return Err(MetricsError::AlreadyRunning);
        }
        if let Some(worker) = self.worker.take() {
            worker.join().map_err(|_| MetricsError::ThreadPanic)?;
        }
        let snapshot_generation = {
            let mut state = write_lock(&self.snapshot);
            state.generation = state.generation.wrapping_add(1);
            state.generation
        };
        self.stop.reset();
        let config = self.config.clone();
        let factory = Arc::clone(&self.backend_factory);
        let stop = self.stop.clone();
        let snapshot = Arc::clone(&self.snapshot);
        let stats = Arc::clone(&self.stats);
        let thread_name = format!("{}-collector", config.session_name);
        let worker = thread::Builder::new()
            .name(thread_name)
            .spawn(move || {
                let _stop_guard = StopOnDrop(stop.clone());
                collector_loop(
                    &config,
                    &factory,
                    &stop,
                    &snapshot,
                    snapshot_generation,
                    &stats,
                    consumer,
                );
            })
            .map_err(|error| MetricsError::Backend(error.to_string()))?;
        self.worker = Some(worker);
        Ok(())
    }

    /// Signals all workers, waits for shutdown, and flushes pending byte events.
    ///
    /// # Errors
    ///
    /// Returns [`MetricsError::NotRunning`] if stopped and
    /// [`MetricsError::ThreadPanic`] if the collector or consumer panicked.
    pub fn stop(&mut self) -> Result<(), MetricsError> {
        let Some(worker) = self.worker.take() else {
            return Err(MetricsError::NotRunning);
        };
        self.stop.stop();
        worker.join().map_err(|_| MetricsError::ThreadPanic)
    }

    /// Returns whether collection is active and its worker has not terminated.
    pub fn is_running(&self) -> bool {
        !self.stop.is_stop_requested()
            && self
                .worker
                .as_ref()
                .is_some_and(|worker| !worker.is_finished())
    }

    /// Copies the latest lock-short flow snapshot.
    pub fn snapshot_flows(&self) -> FlowSnapshot {
        read_lock(&self.snapshot).snapshot.clone()
    }

    /// Reads operational counters without stopping collection.
    pub fn stats(&self) -> CollectorStats {
        CollectorStats {
            ingress_dropped: self.stats.ingress_dropped.load(Ordering::Relaxed),
            flow_evicted: self.stats.flow_evicted.load(Ordering::Relaxed),
            backend_restarts: self.stats.backend_restarts.load(Ordering::Relaxed),
            events_published: self.stats.events_published.load(Ordering::Relaxed),
        }
    }
}

impl Drop for Collector {
    fn drop(&mut self) {
        if self.worker.is_some() {
            let _ = self.stop();
        }
    }
}

struct StopOnDrop(StopFlag);

impl Drop for StopOnDrop {
    fn drop(&mut self) {
        self.0.stop();
    }
}

/// Marks collection as failed as soon as a consumer panic begins unwinding.
///
/// The collector thread can still have auxiliary resources to tear down at this point. Keeping
/// this signal separate from `JoinHandle::is_finished` lets callers observe the failure promptly;
/// `Collector::start` still joins and reaps the old worker before allowing a restart.
struct StopOnPanicConsumer {
    inner: Box<dyn FlowConsumer>,
    stop: StopFlag,
}

impl FlowConsumer for StopOnPanicConsumer {
    fn on_event(&mut self, event: FlowEvent) {
        let _guard = StopOnPanic(&self.stop);
        self.inner.on_event(event);
    }

    fn on_batch(&mut self, events: &[FlowEvent]) {
        let _guard = StopOnPanic(&self.stop);
        self.inner.on_batch(events);
    }

    fn on_batch_buffer(&mut self, events: &mut Vec<FlowEvent>) {
        let _guard = StopOnPanic(&self.stop);
        self.inner.on_batch_buffer(events);
    }
}

struct StopOnPanic<'a>(&'a StopFlag);

impl Drop for StopOnPanic<'_> {
    fn drop(&mut self) {
        if thread::panicking() {
            self.0.stop();
        }
    }
}

#[allow(clippy::too_many_arguments)]
#[allow(clippy::too_many_lines)]
fn collector_loop(
    config: &CollectorConfig,
    factory: &BackendFactory,
    stop: &StopFlag,
    snapshot: &Arc<RwLock<SnapshotState>>,
    snapshot_generation: u64,
    stats: &Arc<SharedStats>,
    consumer: Box<dyn FlowConsumer>,
) {
    let mut consumer = StopOnPanicConsumer {
        inner: consumer,
        stop: stop.clone(),
    };
    let (data_capacity, control_capacity) = ingress_capacities(config.ingress_capacity);
    let (wake_sender, wake_receiver) = mpsc::sync_channel(1);
    let wake_state = WakeState::new();
    let ingress_dropped = Arc::new(AtomicU64::new(0));
    let (sink, mut ingress) = EventSink::ordered(
        data_capacity,
        control_capacity,
        wake_sender,
        wake_state.clone(),
        Arc::clone(&ingress_dropped),
    );
    let sink = sink.with_native_capacity(config.max_flows);
    let backend_config = BackendConfig {
        session_name: config.session_name.clone(),
        buffer_mb: config.buffer_mb,
        poll_interval_ms: config.poll_interval_ms,
        dns_hints: config.dns_hints,
    };
    let mut backend = spawn_backend(factory, &backend_config, &sink, stop.clone()).ok();
    let interface_lookup = spawn_interface_lookup(sink.clone(), stop.clone());
    let mut restart_at = None;
    let mut consecutive_failures = 0_u32;
    let mut backend_terminal = false;
    let mut flow_table = FlowTable::new(config.max_flows);
    let process_capacity = config.max_flows.clamp(1024, 262_144);
    let mut process_table = ProcessTable::new(config.process_grace_ms, process_capacity);
    let mut coalescer =
        IngressCoalescer::new(config.coalesce_interval_ms, config.coalesce_byte_threshold);
    let mut batch = Vec::with_capacity(config.batch_size);
    let mut batch_output = Vec::with_capacity(config.batch_size);
    let mut last_dropped = 0;
    let mut last_evicted = 0;
    let mut last_snapshot = Instant::now();
    let mut last_batch_flush = Instant::now();
    let receive_timeout = Duration::from_millis(config.coalesce_interval_ms.clamp(1, 25));
    let maintenance_interval = Duration::from_millis(config.maintenance_interval_ms);
    let mut next_maintenance = next_deadline(Instant::now(), maintenance_interval);
    let drain_budget = config.ingress_drain_batch_size.max(1);
    let snapshot_publisher = SnapshotPublisher::new(
        &config.session_name,
        Arc::clone(snapshot),
        snapshot_generation,
    );

    while !stop.is_stop_requested() {
        let drained = drain_ingress(
            &mut ingress,
            drain_budget,
            config,
            &mut flow_table,
            &mut process_table,
            &mut coalescer,
            stats,
            &mut batch,
            interface_lookup.as_ref(),
        );
        let ingress_backlogged = drained == drain_budget;

        let timestamp = unix_now_ms();
        for (key, delta) in coalescer.drain_due(Instant::now()) {
            batch.push(FlowEvent::Bytes(key, delta));
        }

        let now = Instant::now();
        if now >= next_maintenance {
            process_table.sweep(timestamp);
            publish_ingress_drop_report(&ingress_dropped, &mut last_dropped, stats, &mut batch);
            publish_eviction_report(&flow_table, &mut last_evicted, stats, &mut batch);
            next_maintenance = next_deadline(now, maintenance_interval);
        }

        // Keep the cumulative counter current even between reports. The
        // degradation event itself is intentionally cadence-limited below.
        stats
            .ingress_dropped
            .store(ingress_dropped.load(Ordering::Relaxed), Ordering::Relaxed);

        if !ingress_backlogged
            && last_snapshot.elapsed() >= Duration::from_millis(config.snapshot_interval_ms)
        {
            let accepted = snapshot_publisher.as_ref().map_or_else(
                || {
                    publish_snapshot(
                        snapshot,
                        snapshot_generation,
                        flow_table.snapshot(timestamp),
                    );
                    true
                },
                |publisher| publisher.try_publish(&flow_table, timestamp),
            );
            if accepted {
                last_snapshot = Instant::now();
            }
        }

        let completed = backend
            .as_ref()
            .and_then(|run| match run.status.try_recv() {
                Ok(result) => Some(result),
                Err(TryRecvError::Disconnected) => Some(Err(BackendError::new(
                    netmetrics_sys::BackendErrorKind::SessionLost,
                    run.name,
                    "backend thread exited without reporting status",
                ))),
                Err(TryRecvError::Empty) => None,
            });
        if let Some(result) = completed {
            if let Some(run) = backend.as_ref() {
                let name = run.name;
                let run = backend.take().expect("backend was present");
                if run.started.elapsed() >= BACKEND_STABLE_UPTIME {
                    consecutive_failures = 0;
                }
                run.gate.revoke();
                let _ = run.handle.join();
                loop {
                    let drained = drain_ingress(
                        &mut ingress,
                        usize::MAX,
                        config,
                        &mut flow_table,
                        &mut process_table,
                        &mut coalescer,
                        stats,
                        &mut batch,
                        interface_lookup.as_ref(),
                    );
                    if drained == 0 {
                        break;
                    }
                }
                for (key, delta) in coalescer.drain_all() {
                    batch.push(FlowEvent::Bytes(key, delta));
                }
                for record in flow_table.close_all(unix_now_ms()) {
                    batch.push(FlowEvent::Closed(record.key, record.meta));
                }
                process_table = ProcessTable::new(config.process_grace_ms, process_capacity);
                if !stop.is_stop_requested() {
                    let retryable = match &result {
                        Ok(()) => true,
                        Err(error) => error.kind != netmetrics_sys::BackendErrorKind::Unsupported,
                    };
                    let reason = result.as_ref().map_or_else(
                        |error| error.degrade_reason(name),
                        |()| DegradeReason::SessionLost {
                            backend: name.to_owned(),
                            detail: "backend exited unexpectedly".to_owned(),
                        },
                    );
                    batch.push(FlowEvent::Degraded { reason });
                    if retryable {
                        stats.backend_restarts.fetch_add(1, Ordering::Relaxed);
                        consecutive_failures = consecutive_failures.saturating_add(1);
                        restart_at = Some(next_deadline(
                            Instant::now(),
                            restart_backoff(config.watchdog_backoff_ms, consecutive_failures),
                        ));
                    } else {
                        backend_terminal = true;
                        restart_at = None;
                    }
                }
            }
        } else if backend.is_none()
            && !backend_terminal
            && restart_at.is_none_or(|deadline| Instant::now() >= deadline)
        {
            match spawn_backend(factory, &backend_config, &sink, stop.clone()) {
                Ok(run) => {
                    backend = Some(run);
                    restart_at = None;
                }
                Err(error) => {
                    batch.push(FlowEvent::Degraded {
                        reason: DegradeReason::SessionLost {
                            backend: "backend-thread".to_owned(),
                            detail: error.to_string(),
                        },
                    });
                    consecutive_failures = consecutive_failures.saturating_add(1);
                    restart_at = Some(next_deadline(
                        Instant::now(),
                        restart_backoff(config.watchdog_backoff_ms, consecutive_failures),
                    ));
                }
            }
        }
        if drained > 0 {
            flush_full_batches(
                &mut batch,
                &mut batch_output,
                &mut consumer,
                config.batch_size,
                stats,
            );
        }
        if last_batch_flush.elapsed() >= receive_timeout {
            flush_batch(&mut batch, &mut consumer, stats);
            last_batch_flush = Instant::now();
        }

        if ingress_backlogged {
            continue;
        }
        if !recheck_or_park(&mut ingress, &wake_state, &wake_receiver, receive_timeout) {
            break;
        }
    }

    stop.stop();
    if let Some(run) = backend {
        let BackendRun { handle, gate, .. } = run;
        let _ = handle.join();
        gate.revoke();
    }
    loop {
        let drained = drain_ingress(
            &mut ingress,
            usize::MAX,
            config,
            &mut flow_table,
            &mut process_table,
            &mut coalescer,
            stats,
            &mut batch,
            interface_lookup.as_ref(),
        );
        if drained == 0 {
            break;
        }
    }
    for (key, delta) in coalescer.drain_all() {
        batch.push(FlowEvent::Bytes(key, delta));
    }
    let timestamp = unix_now_ms();
    process_table.sweep(timestamp);
    publish_ingress_drop_report(&ingress_dropped, &mut last_dropped, stats, &mut batch);
    publish_eviction_report(&flow_table, &mut last_evicted, stats, &mut batch);
    let timestamp = unix_now_ms();
    if let Some(publisher) = snapshot_publisher {
        publisher.finish(&flow_table, timestamp, snapshot);
    } else {
        publish_snapshot(
            snapshot,
            snapshot_generation,
            flow_table.snapshot(timestamp),
        );
    }
    flush_batch(&mut batch, &mut consumer, stats);
}

/// Delay before restarting a backend after its `failures`-th consecutive failure:
/// the configured base, doubled for each failure after the first, capped at
/// [`MAX_BACKEND_BACKOFF`] (or the base, if that is larger).
fn restart_backoff(base_ms: u64, failures: u32) -> Duration {
    let base = Duration::from_millis(base_ms);
    let doublings = failures.saturating_sub(1).min(16);
    base.saturating_mul(1 << doublings)
        .min(MAX_BACKEND_BACKOFF.max(base))
}

fn next_deadline(now: Instant, interval: Duration) -> Instant {
    now.checked_add(interval).unwrap_or(now)
}

fn ingress_capacities(total: usize) -> (usize, usize) {
    let control = (total / 8).clamp(64, 1_024).min(total.max(1));
    (total.max(1), control)
}

/// Clears the wake flag, rechecks both ingress queues and any locally buffered
/// event, then parks on the wake channel only when nothing is pending.
///
/// Returns `false` when the wake channel disconnects.
fn recheck_or_park(
    ingress: &mut OrderedIngress,
    wake_state: &WakeState,
    wake_receiver: &Receiver<()>,
    timeout: Duration,
) -> bool {
    wake_state.clear();
    if ingress.has_pending() {
        return true;
    }
    match wake_receiver.recv_timeout(timeout) {
        Ok(()) | Err(RecvTimeoutError::Timeout) => true,
        Err(RecvTimeoutError::Disconnected) => false,
    }
}

#[allow(clippy::too_many_arguments)]
fn drain_ingress(
    ingress: &mut OrderedIngress,
    budget: usize,
    config: &CollectorConfig,
    flow_table: &mut FlowTable,
    process_table: &mut ProcessTable,
    coalescer: &mut IngressCoalescer,
    stats: &SharedStats,
    batch: &mut Vec<FlowEvent>,
    interface_lookup: Option<&InterfaceLookup>,
) -> usize {
    let mut drained = 0;
    while drained < budget {
        let Some(event) = ingress.try_recv() else {
            break;
        };
        process_backend_event(
            event,
            config,
            flow_table,
            process_table,
            coalescer,
            stats,
            batch,
            interface_lookup,
        );
        drained += 1;
    }
    drained
}

fn publish_ingress_drop_report(
    ingress_dropped: &AtomicU64,
    last_dropped: &mut u64,
    stats: &SharedStats,
    batch: &mut Vec<FlowEvent>,
) {
    let dropped = ingress_dropped.load(Ordering::Relaxed);
    stats.ingress_dropped.store(dropped, Ordering::Relaxed);
    if dropped > *last_dropped {
        let delta = dropped - *last_dropped;
        *last_dropped = dropped;
        batch.push(FlowEvent::Degraded {
            reason: DegradeReason::BufferOverflow { dropped: delta },
        });
    }
}

fn publish_eviction_report(
    flow_table: &FlowTable,
    last_evicted: &mut u64,
    stats: &SharedStats,
    batch: &mut Vec<FlowEvent>,
) {
    let evicted = flow_table.stats().evicted;
    stats.flow_evicted.store(evicted, Ordering::Relaxed);
    if evicted > *last_evicted {
        let delta = evicted - *last_evicted;
        *last_evicted = evicted;
        batch.push(FlowEvent::Degraded {
            reason: DegradeReason::CapacityExceeded { evicted: delta },
        });
    }
}

fn request_interface(lookup: Option<&InterfaceLookup>, key: FlowKey, generation: u64) {
    if let Some(lookup) = lookup {
        lookup.request(key, generation);
    }
}

/// Interface lookups a test recorder has seen requested.
type RecordedRequests = std::sync::Arc<std::sync::Mutex<Vec<(FlowKey, u64)>>>;

struct InterfaceLookup {
    #[cfg(all(windows, feature = "windows"))]
    inner: Option<netmetrics_windows::InterfaceEstimator>,
    recorded: Option<RecordedRequests>,
}

impl InterfaceLookup {
    fn request(&self, key: FlowKey, generation: u64) {
        if let Some(recorded) = &self.recorded
            && let Ok(mut requests) = recorded.lock()
        {
            requests.push((key, generation));
        }
        #[cfg(all(windows, feature = "windows"))]
        if let Some(inner) = &self.inner {
            inner.request(key, generation);
        }
    }

    #[cfg(test)]
    fn recorder() -> (Self, RecordedRequests) {
        let recorded = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        (
            Self {
                #[cfg(all(windows, feature = "windows"))]
                inner: None,
                recorded: Some(std::sync::Arc::clone(&recorded)),
            },
            recorded,
        )
    }
}

fn spawn_interface_lookup(sink: EventSink, stop: StopFlag) -> Option<InterfaceLookup> {
    #[cfg(all(windows, feature = "windows"))]
    {
        netmetrics_windows::InterfaceEstimator::start(sink, stop).map(|inner| InterfaceLookup {
            inner: Some(inner),
            recorded: None,
        })
    }
    #[cfg(not(all(windows, feature = "windows")))]
    {
        let _ = (sink, stop);
        None
    }
}

fn read_lock<T>(lock: &RwLock<T>) -> std::sync::RwLockReadGuard<'_, T> {
    lock.read()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn write_lock<T>(lock: &RwLock<T>) -> std::sync::RwLockWriteGuard<'_, T> {
    lock.write()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

#[cfg(all(windows, feature = "windows"))]
fn default_backend_factory() -> BackendFactory {
    Arc::new(|| Box::new(netmetrics_windows::WindowsBackend))
}

#[cfg(all(target_os = "linux", feature = "linux"))]
fn default_backend_factory() -> BackendFactory {
    Arc::new(|| Box::new(netmetrics_linux::LinuxBackend))
}

#[cfg(all(target_os = "macos", feature = "macos"))]
fn default_backend_factory() -> BackendFactory {
    Arc::new(|| Box::new(netmetrics_macos::MacosBackend))
}

#[cfg(not(any(
    all(windows, feature = "windows"),
    all(target_os = "linux", feature = "linux"),
    all(target_os = "macos", feature = "macos")
)))]
fn default_backend_factory() -> BackendFactory {
    #[derive(Debug)]
    struct Unsupported;
    impl Backend for Unsupported {
        fn name(&self) -> &'static str {
            "unsupported"
        }

        fn run(
            &mut self,
            _config: &BackendConfig,
            _sink: EventSink,
            _stop: StopFlag,
        ) -> Result<(), BackendError> {
            Err(BackendError::new(
                netmetrics_sys::BackendErrorKind::Unsupported,
                "unsupported",
                "no native backend for this target",
            ))
        }
    }
    Arc::new(|| Box::new(Unsupported))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::CollectorConfig;

    #[test]
    fn restart_backoff_doubles_to_a_cap() {
        let delays: Vec<_> = (1..=9)
            .map(|failures| restart_backoff(500, failures))
            .collect();
        assert_eq!(
            delays[0],
            Duration::from_millis(500),
            "the first retry waits the base"
        );
        assert_eq!(delays[1], Duration::from_secs(1));
        assert_eq!(delays[2], Duration::from_secs(2));
        assert_eq!(delays[6], Duration::from_secs(30), "capped");
        assert_eq!(delays[8], MAX_BACKEND_BACKOFF);
        // A base above the cap is honoured rather than shortened.
        assert_eq!(restart_backoff(45_000, 5), Duration::from_secs(45));
        // Extreme failure counts cannot overflow.
        assert_eq!(restart_backoff(500, u32::MAX), MAX_BACKEND_BACKOFF);
    }
    use netmetrics_core::{ByteDelta, FlowKey, ProcessIdentity, ProcessInfo, Protocol};
    use netmetrics_sys::BackendErrorKind;
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::mpsc::sync_channel;
    use std::sync::{Barrier, Mutex};

    fn test_key(loopback: bool, port: u16) -> FlowKey {
        FlowKey {
            protocol: Protocol::Tcp,
            local_addr: IpAddr::V4(if loopback {
                Ipv4Addr::LOCALHOST
            } else {
                Ipv4Addr::new(192, 0, 2, 10)
            }),
            local_port: port,
            remote_addr: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 20)),
            remote_port: 443,
        }
    }

    fn handshake_bytes() -> BackendEvent {
        BackendEvent::Bytes {
            key: test_key(false, 50_000),
            pid: 1,
            delta: ByteDelta {
                sent: 1,
                received: 0,
            },
            timestamp: 1,
            if_index: None,
            cookie: None,
        }
    }

    fn handshake_closed() -> BackendEvent {
        BackendEvent::Closed {
            pid: 0,
            key: test_key(false, 50_000),
            timestamp: 2,
        }
    }

    fn handshake_fixture() -> (EventSink, OrderedIngress, WakeState, Receiver<()>) {
        let (wake_sender, wake_receiver) = sync_channel(1);
        let wake_state = WakeState::new();
        let (sink, ingress) = EventSink::ordered(
            16,
            16,
            wake_sender,
            wake_state.clone(),
            Arc::new(AtomicU64::new(0)),
        );
        (sink, ingress, wake_state, wake_receiver)
    }

    fn racing_enqueue(sink: EventSink, event: BackendEvent) -> std::thread::JoinHandle<()> {
        let start = Arc::new(Barrier::new(2));
        let ready = Arc::clone(&start);
        let producer = thread::spawn(move || {
            ready.wait();
            assert!(sink.emit(event));
        });
        start.wait();
        producer
    }

    #[test]
    fn handshake_sees_a_racing_data_enqueue_without_joining_first() {
        let (sink, mut ingress, wake_state, wake_receiver) = handshake_fixture();
        let producer = racing_enqueue(sink, handshake_bytes());
        assert!(recheck_or_park(
            &mut ingress,
            &wake_state,
            &wake_receiver,
            Duration::from_millis(200),
        ));
        assert!(
            ingress.has_pending(),
            "data enqueue must be visible after clear/recheck/park"
        );
        producer.join().expect("producer");
    }

    #[test]
    fn handshake_sees_a_racing_control_enqueue_without_joining_first() {
        let (sink, mut ingress, wake_state, wake_receiver) = handshake_fixture();
        let producer = racing_enqueue(sink, handshake_closed());
        assert!(recheck_or_park(
            &mut ingress,
            &wake_state,
            &wake_receiver,
            Duration::from_millis(200),
        ));
        assert!(
            ingress.has_pending(),
            "control enqueue must be visible after clear/recheck/park"
        );
        producer.join().expect("producer");
    }

    #[test]
    fn handshake_does_not_sleep_on_a_locally_buffered_event() {
        let (sink, mut ingress, wake_state, wake_receiver) = handshake_fixture();
        assert!(sink.emit(handshake_bytes()));
        assert!(ingress.has_pending(), "event should park in next_data");
        let started = Instant::now();
        assert!(recheck_or_park(
            &mut ingress,
            &wake_state,
            &wake_receiver,
            Duration::from_secs(5),
        ));
        assert!(
            started.elapsed() < Duration::from_millis(200),
            "a locally buffered event must skip the wake wait"
        );
        assert!(ingress.has_pending());
    }

    #[test]
    fn handshake_does_not_sleep_on_a_locally_buffered_control_event() {
        let (sink, mut ingress, wake_state, wake_receiver) = handshake_fixture();
        assert!(sink.emit(handshake_closed()));
        assert!(ingress.has_pending(), "event should park in next_control");
        let started = Instant::now();
        assert!(recheck_or_park(
            &mut ingress,
            &wake_state,
            &wake_receiver,
            Duration::from_secs(5),
        ));
        assert!(
            started.elapsed() < Duration::from_millis(200),
            "a locally buffered control event must skip the wake wait"
        );
        assert!(ingress.has_pending());
    }

    #[test]
    fn overflow_reports_are_cadenced_and_keep_cumulative_counts() {
        let ingress_dropped = AtomicU64::new(35);
        let stats = SharedStats::default();
        let mut last_dropped = 0;
        let mut batch = Vec::new();

        publish_ingress_drop_report(&ingress_dropped, &mut last_dropped, &stats, &mut batch);
        assert_eq!(last_dropped, 35);
        assert_eq!(stats.ingress_dropped.load(Ordering::Relaxed), 35);
        assert_eq!(
            batch,
            vec![FlowEvent::Degraded {
                reason: DegradeReason::BufferOverflow { dropped: 35 }
            }]
        );

        // Re-reporting on every collector iteration would amplify overload;
        // unchanged cumulative counts must produce no second event.
        publish_ingress_drop_report(&ingress_dropped, &mut last_dropped, &stats, &mut batch);
        assert_eq!(batch.len(), 1);

        ingress_dropped.store(100, Ordering::Relaxed);
        publish_ingress_drop_report(&ingress_dropped, &mut last_dropped, &stats, &mut batch);
        assert_eq!(last_dropped, 100);
        assert!(matches!(
            batch.last(),
            Some(FlowEvent::Degraded {
                reason: DegradeReason::BufferOverflow { dropped: 65 }
            })
        ));
    }

    #[test]
    fn lifecycle_reserve_does_not_reduce_configured_data_capacity() {
        assert_eq!(ingress_capacities(8_192), (8_192, 1_024));
        assert_eq!(ingress_capacities(1), (1, 1));
    }

    #[test]
    fn closure_consumers_drain_owned_events_and_preserve_publish_stats() {
        let mut batch = vec![FlowEvent::ProcessStopped {
            pid: 7,
            stop_ts: 11,
        }];
        let stats = SharedStats::default();
        let received = Arc::new(AtomicU64::new(0));
        let captured = Arc::clone(&received);
        let mut consumer = move |_event: FlowEvent| {
            captured.fetch_add(1, Ordering::Relaxed);
        };
        flush_batch(&mut batch, &mut consumer, &stats);
        assert!(batch.is_empty());
        assert_eq!(received.load(Ordering::Relaxed), 1);
        assert_eq!(stats.events_published.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn burst_overload_drops_are_bounded_and_exactly_reported() {
        let attempted = 20_000_u64;
        let script = (0..attempted)
            .map(|_| BackendEvent::ProcessStopped {
                pid: 42,
                timestamp: unix_now_ms(),
                identity: None,
            })
            .collect();
        let events = Arc::new(Mutex::new(Vec::new()));
        let captured = Arc::clone(&events);
        let mut builder = CollectorBuilder::new()
            .ingress_capacity(8_192)
            .ingress_drain_batch_size(1_024)
            .maintenance_interval_ms(25)
            .coalesce_interval_ms(25);
        builder.backend_factory = Some(scripted_factory(script));

        let mut collector = builder.build().expect("collector");
        collector
            .start(Box::new(move |event| {
                // Deliberately create downstream pressure. The native source
                // must remain non-blocking and the drop accounting must stay
                // exact while the bounded queue recovers.
                thread::sleep(Duration::from_micros(50));
                captured.lock().expect("event lock").push(event);
            }))
            .expect("start");
        thread::sleep(Duration::from_millis(100));
        collector.stop().expect("stop");

        let stats = collector.stats();
        let events = events.lock().expect("events");
        let accepted = events
            .iter()
            .filter(|event| matches!(event, FlowEvent::ProcessStopped { .. }))
            .count() as u64;
        let reported = events
            .iter()
            .filter_map(|event| match event {
                FlowEvent::Degraded {
                    reason: DegradeReason::BufferOverflow { dropped },
                } => Some(*dropped),
                _ => None,
            })
            .sum::<u64>();

        assert!(
            stats.ingress_dropped > 0,
            "slow consumer must exercise overflow"
        );
        assert_eq!(accepted + stats.ingress_dropped, attempted);
        assert_eq!(reported, stats.ingress_dropped);
        assert!(
            events.len() < usize::try_from(attempted).expect("test count fits usize"),
            "the bounded test must have exercised shedding"
        );
    }

    struct ScriptedBackend {
        script: Vec<BackendEvent>,
    }

    impl Backend for ScriptedBackend {
        fn name(&self) -> &'static str {
            "scripted"
        }

        fn run(
            &mut self,
            _config: &BackendConfig,
            sink: EventSink,
            stop: StopFlag,
        ) -> Result<(), BackendError> {
            for event in self.script.drain(..) {
                sink.emit(event);
            }
            while !stop.is_stop_requested() {
                stop.wait_timeout(Duration::from_millis(1));
            }
            Ok(())
        }
    }

    fn scripted_factory(script: Vec<BackendEvent>) -> BackendFactory {
        let script = Arc::new(Mutex::new(Some(script)));
        Arc::new(move || {
            let events = script
                .lock()
                .expect("script lock")
                .take()
                .unwrap_or_default();
            Box::new(ScriptedBackend { script: events })
        })
    }

    fn wait_for_backend_restarts(collector: &Collector, minimum: u64) {
        let deadline = Instant::now() + Duration::from_secs(5);
        while collector.stats().backend_restarts < minimum && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(5));
        }
    }

    #[test]
    fn lifecycle_attributes_coalesces_and_flushes_exact_totals() {
        let key = test_key(false, 50_000);
        let base = unix_now_ms();
        let process = ProcessInfo {
            pid: 42,
            identity: ProcessIdentity {
                executable: "example".to_owned(),
                name: "example".to_owned(),
                start_ts: base,
            },
        };
        let script = vec![
            BackendEvent::ProcessStarted(process.clone()),
            BackendEvent::Opened {
                key,
                pid: 42,
                cookie: None,
                timestamp: base + 1,
                if_index: None,
            },
            BackendEvent::Bytes {
                key,
                pid: 42,
                delta: ByteDelta {
                    sent: 10,
                    received: 0,
                },
                timestamp: base + 2,
                if_index: None,
                cookie: None,
            },
            BackendEvent::Bytes {
                key,
                pid: 42,
                delta: ByteDelta {
                    sent: 5,
                    received: 7,
                },
                timestamp: base + 3,
                if_index: None,
                cookie: None,
            },
            BackendEvent::Closed {
                pid: 0,
                key,
                timestamp: base + 4,
            },
        ];
        let events = Arc::new(Mutex::new(Vec::new()));
        let captured = Arc::clone(&events);
        let mut builder = CollectorBuilder::new()
            .ignore_loopback(false)
            .coalesce_interval_ms(10_000)
            .snapshot_interval_ms(1);
        builder.backend_factory = Some(scripted_factory(script));
        let mut collector = builder.build().expect("collector");
        collector
            .start(Box::new(move |event| {
                captured.lock().expect("event lock").push(event);
            }))
            .expect("start");
        thread::sleep(Duration::from_millis(50));
        collector.stop().expect("stop");

        let events = events.lock().expect("events");
        assert!(events.contains(&FlowEvent::ProcessStarted(process.clone())));
        assert!(events.contains(&FlowEvent::Opened(
            key,
            netmetrics_core::FlowMeta {
                pid: 42,
                process: Some(process.identity),
                open_ts: base + 1,
                cookie: None,
                if_index: None,
            }
        )));
        let deltas: Vec<_> = events
            .iter()
            .filter_map(|event| match event {
                FlowEvent::Bytes(event_key, delta) if *event_key == key => Some(*delta),
                _ => None,
            })
            .collect();
        assert_eq!(
            deltas,
            vec![ByteDelta {
                sent: 15,
                received: 7
            }]
        );
        assert!(
            events
                .iter()
                .any(|event| matches!(event, FlowEvent::Closed(event_key, _) if *event_key == key))
        );
    }

    #[test]
    fn reversed_close_drains_canonical_bytes_before_closing() {
        let key = test_key(false, 50_004);
        let reversed = key.reverse();
        let script = vec![
            BackendEvent::Opened {
                key,
                pid: 42,
                cookie: None,
                timestamp: 1,
                if_index: None,
            },
            BackendEvent::Bytes {
                key: reversed,
                pid: 42,
                delta: ByteDelta {
                    sent: 3,
                    received: 4,
                },
                timestamp: 2,
                if_index: None,
                cookie: None,
            },
            BackendEvent::Bytes {
                key: reversed,
                pid: 42,
                delta: ByteDelta {
                    sent: 5,
                    received: 6,
                },
                timestamp: 3,
                if_index: None,
                cookie: None,
            },
            BackendEvent::Closed {
                pid: 0,
                key: reversed,
                timestamp: 4,
            },
        ];
        let events = Arc::new(Mutex::new(Vec::new()));
        let captured = Arc::clone(&events);
        let mut builder = CollectorBuilder::new()
            .ignore_loopback(false)
            .coalesce_interval_ms(10_000);
        builder.backend_factory = Some(scripted_factory(script));
        let mut collector = builder.build().expect("collector");
        collector
            .start(Box::new(move |event| {
                captured.lock().expect("event lock").push(event);
            }))
            .expect("start");
        thread::sleep(Duration::from_millis(30));
        collector.stop().expect("stop");

        let events = events.lock().expect("events");
        let bytes = events
            .iter()
            .position(|event| {
                matches!(
                    event,
                    FlowEvent::Bytes(
                        event_key,
                        ByteDelta {
                            sent: 8,
                            received: 10
                        }
                    ) if *event_key == key
                )
            })
            .unwrap_or_else(|| panic!("canonical byte flush; events={events:?}"));
        let closed = events
            .iter()
            .position(|event| matches!(event, FlowEvent::Closed(event_key, _) if *event_key == key))
            .unwrap_or_else(|| panic!("canonical close; events={events:?}"));
        assert!(bytes < closed, "final bytes must precede close");
        assert!(
            !events[closed + 1..]
                .iter()
                .any(|event| matches!(event, FlowEvent::Bytes(event_key, _) if *event_key == key))
        );
    }

    #[test]
    fn lagged_event_timestamps_do_not_flush_before_reversed_close() {
        let key = test_key(false, 50_005);
        let reversed = key.reverse();
        let config = CollectorConfig {
            ignore_loopback: false,
            ..CollectorConfig::default()
        };
        let mut flow_table = FlowTable::new(16);
        let mut process_table = ProcessTable::new(config.process_grace_ms, 1_024);
        let mut coalescer =
            IngressCoalescer::new(config.coalesce_interval_ms, config.coalesce_byte_threshold);
        let stats = SharedStats::default();
        let mut batch = Vec::new();

        for event in [
            BackendEvent::Opened {
                key,
                pid: 42,
                cookie: None,
                timestamp: 1,
                if_index: None,
            },
            BackendEvent::Bytes {
                key: reversed,
                pid: 42,
                delta: ByteDelta {
                    sent: 3,
                    received: 4,
                },
                timestamp: 2,
                if_index: None,
                cookie: None,
            },
        ] {
            process_backend_event(
                event,
                &config,
                &mut flow_table,
                &mut process_table,
                &mut coalescer,
                &stats,
                &mut batch,
                None,
            );
        }
        assert!(
            coalescer.drain_due(Instant::now()).is_empty(),
            "receive-time coalescing must ignore lagged event timestamps"
        );

        for event in [
            BackendEvent::Bytes {
                key: reversed,
                pid: 42,
                delta: ByteDelta {
                    sent: 5,
                    received: 6,
                },
                timestamp: 3,
                if_index: None,
                cookie: None,
            },
            BackendEvent::Closed {
                pid: 0,
                key: reversed,
                timestamp: 4,
            },
        ] {
            process_backend_event(
                event,
                &config,
                &mut flow_table,
                &mut process_table,
                &mut coalescer,
                &stats,
                &mut batch,
                None,
            );
        }

        let bytes = batch
            .iter()
            .position(|event| {
                matches!(
                    event,
                    FlowEvent::Bytes(
                        event_key,
                        ByteDelta {
                            sent: 8,
                            received: 10
                        }
                    ) if *event_key == key
                )
            })
            .unwrap_or_else(|| panic!("canonical byte flush; events={batch:?}"));
        let closed = batch
            .iter()
            .position(|event| matches!(event, FlowEvent::Closed(event_key, _) if *event_key == key))
            .unwrap_or_else(|| panic!("canonical close; events={batch:?}"));
        assert!(bytes < closed, "final bytes must precede close");
    }

    /// Mirrors the Windows sequence exactly: ETW opens the flow with no identity, the
    /// owner-module poller supplies the cookie one interval later, and traffic spans both.
    #[test]
    fn cookie_enrichment_preserves_byte_totals() {
        let key = test_key(false, 50_010);
        let base = unix_now_ms();
        let cookie = netmetrics_core::SocketCookie {
            value: 777,
            source: netmetrics_core::CookieSource::WindowsCreateTimestamp,
        };
        let script = vec![
            BackendEvent::Opened {
                key,
                pid: 42,
                cookie: None,
                timestamp: base + 1,
                if_index: None,
            },
            BackendEvent::Bytes {
                key,
                pid: 42,
                delta: ByteDelta {
                    sent: 10,
                    received: 20,
                },
                timestamp: base + 2,
                if_index: None,
                cookie: None,
            },
            BackendEvent::CookieResolved {
                key,
                pid: 42,
                cookie,
                timestamp: base + 3,
            },
            BackendEvent::Bytes {
                key,
                pid: 42,
                delta: ByteDelta {
                    sent: 5,
                    received: 7,
                },
                timestamp: base + 4,
                if_index: None,
                cookie: None,
            },
            BackendEvent::Closed {
                pid: 0,
                key,
                timestamp: base + 5,
            },
        ];
        let events = Arc::new(Mutex::new(Vec::new()));
        let captured = Arc::clone(&events);
        let mut builder = CollectorBuilder::new()
            .ignore_loopback(false)
            .coalesce_interval_ms(10_000)
            .snapshot_interval_ms(1);
        builder.backend_factory = Some(scripted_factory(script));
        let mut collector = builder.build().expect("collector");
        collector
            .start(Box::new(move |event| {
                captured.lock().expect("event lock").push(event);
            }))
            .expect("start");
        thread::sleep(Duration::from_millis(50));
        collector.stop().expect("stop");

        let events = events.lock().expect("events");
        let mut total = ByteDelta::default();
        for event in events.iter() {
            match event {
                FlowEvent::Bytes(event_key, delta) if *event_key == key => {
                    total.saturating_add_assign(*delta);
                }
                _ => {}
            }
        }
        assert_eq!(
            total,
            ByteDelta {
                sent: 15,
                received: 27
            },
            "learning a cookie mid-flow must not drop or double-count bytes"
        );
    }

    #[test]
    fn pid_carried_by_udp_bytes_attributes_inferred_open() {
        let mut key = test_key(false, 50_002);
        key.protocol = netmetrics_core::Protocol::Udp;
        let base = unix_now_ms();
        let process = ProcessInfo {
            pid: 42,
            identity: ProcessIdentity {
                executable: "udp-client".to_owned(),
                name: "udp-client".to_owned(),
                start_ts: base,
            },
        };
        let script = vec![
            BackendEvent::ProcessStarted(process.clone()),
            BackendEvent::Bytes {
                key,
                pid: process.pid,
                delta: ByteDelta {
                    sent: 128,
                    received: 0,
                },
                timestamp: base + 1,
                if_index: None,
                cookie: None,
            },
        ];
        let events = Arc::new(Mutex::new(Vec::new()));
        let captured = Arc::clone(&events);
        let mut builder = CollectorBuilder::new()
            .ignore_loopback(false)
            .coalesce_interval_ms(5);
        builder.backend_factory = Some(scripted_factory(script));
        let mut collector = builder.build().expect("collector");
        collector
            .start(Box::new(move |event| {
                captured.lock().expect("event lock").push(event);
            }))
            .expect("start");
        thread::sleep(Duration::from_millis(30));
        collector.stop().expect("stop");

        let events = events.lock().expect("events");
        assert!(events.iter().any(|event| {
            matches!(
                event,
                FlowEvent::Opened(event_key, meta)
                    if *event_key == key
                        && meta.pid == process.pid
                        && meta.process.as_ref() == Some(&process.identity)
            )
        }));
    }

    #[test]
    fn process_stop_identity_attributes_later_flow_without_a_start_event() {
        let key = test_key(false, 50_030);
        let identity = ProcessIdentity {
            executable: r"C:\Apps\gone.exe".to_owned(),
            name: "gone.exe".to_owned(),
            start_ts: 10,
        };
        let script = vec![
            BackendEvent::ProcessStopped {
                pid: 42,
                timestamp: 20,
                identity: Some(identity.clone()),
            },
            BackendEvent::Opened {
                key,
                pid: 42,
                cookie: None,
                timestamp: 25,
                if_index: None,
            },
        ];
        let events = Arc::new(Mutex::new(Vec::new()));
        let captured = Arc::clone(&events);
        let mut builder = CollectorBuilder::new()
            .ignore_loopback(false)
            .process_grace_ms(100)
            .coalesce_interval_ms(5);
        builder.backend_factory = Some(scripted_factory(script));
        let mut collector = builder.build().expect("collector");
        collector
            .start(Box::new(move |event| {
                captured.lock().expect("event lock").push(event);
            }))
            .expect("start");
        thread::sleep(Duration::from_millis(30));
        collector.stop().expect("stop");

        let events = events.lock().expect("events");
        assert!(events.iter().any(|event| {
            matches!(
                event,
                FlowEvent::Opened(event_key, meta)
                    if *event_key == key
                        && meta.pid == 42
                        && meta.process.as_ref() == Some(&identity)
            )
        }));
    }

    #[test]
    fn late_open_republishes_pid_upgrade_for_inferred_flow() {
        let key = test_key(false, 50_003);
        let script = vec![
            BackendEvent::Bytes {
                key,
                pid: 0,
                delta: ByteDelta {
                    sent: 1,
                    received: 0,
                },
                timestamp: 1,
                if_index: None,
                cookie: None,
            },
            BackendEvent::Opened {
                key,
                pid: 99,
                cookie: None,
                timestamp: 2,
                if_index: None,
            },
        ];
        let events = Arc::new(Mutex::new(Vec::new()));
        let captured = Arc::clone(&events);
        let mut builder = CollectorBuilder::new()
            .ignore_loopback(false)
            .coalesce_interval_ms(5);
        builder.backend_factory = Some(scripted_factory(script));
        let mut collector = builder.build().expect("collector");
        collector
            .start(Box::new(move |event| {
                captured.lock().expect("event lock").push(event);
            }))
            .expect("start");
        thread::sleep(Duration::from_millis(30));
        collector.stop().expect("stop");

        let events = events.lock().expect("events");
        let opened_pids: Vec<_> = events
            .iter()
            .filter_map(|event| match event {
                FlowEvent::Opened(event_key, meta) if *event_key == key => Some(meta.pid),
                _ => None,
            })
            .collect();
        assert_eq!(opened_pids, vec![0, 99]);
    }

    #[test]
    fn loopback_events_are_filtered() {
        let key = test_key(true, 1);
        let script = vec![
            BackendEvent::Opened {
                key,
                pid: 1,
                cookie: None,
                timestamp: 1,
                if_index: None,
            },
            BackendEvent::Bytes {
                key,
                pid: 1,
                delta: ByteDelta {
                    sent: 1,
                    received: 2,
                },
                timestamp: 2,
                if_index: None,
                cookie: None,
            },
        ];
        let events = Arc::new(Mutex::new(Vec::new()));
        let captured = Arc::clone(&events);
        let mut builder = CollectorBuilder::new();
        builder.backend_factory = Some(scripted_factory(script));
        let mut collector = builder.build().expect("collector");
        collector
            .start(Box::new(move |event| {
                captured.lock().expect("event lock").push(event);
            }))
            .expect("start");
        thread::sleep(Duration::from_millis(30));
        collector.stop().expect("stop");
        assert!(events.lock().expect("events").is_empty());
    }

    struct FailingBackend;

    impl Backend for FailingBackend {
        fn name(&self) -> &'static str {
            "failing"
        }

        fn run(
            &mut self,
            _config: &BackendConfig,
            _sink: EventSink,
            _stop: StopFlag,
        ) -> Result<(), BackendError> {
            Err(BackendError::new(
                BackendErrorKind::SessionLost,
                "test",
                "synthetic failure",
            ))
        }
    }

    #[test]
    fn watchdog_reports_and_restarts_failed_backend() {
        let mut builder = CollectorBuilder::new()
            .watchdog_backoff_ms(5)
            .coalesce_interval_ms(5);
        builder.backend_factory = Some(Arc::new(|| Box::new(FailingBackend)));
        let mut collector = builder.build().expect("collector");
        let events = Arc::new(Mutex::new(Vec::new()));
        let captured = Arc::clone(&events);
        collector
            .start(Box::new(move |event| {
                captured.lock().expect("event lock").push(event);
            }))
            .expect("start");
        wait_for_backend_restarts(&collector, 2);
        collector.stop().expect("stop");
        assert!(collector.stats().backend_restarts >= 2);
        assert!(
            events
                .lock()
                .expect("events")
                .iter()
                .any(|event| matches!(event, FlowEvent::Degraded { .. }))
        );
    }

    #[test]
    fn a_crash_looping_backend_is_restarted_with_growing_delays() {
        let mut builder = CollectorBuilder::new()
            .watchdog_backoff_ms(20)
            .coalesce_interval_ms(5);
        builder.backend_factory = Some(Arc::new(|| Box::new(FailingBackend)));
        let mut collector = builder.build().expect("collector");
        collector.start(Box::new(|_event| {})).expect("start");
        std::thread::sleep(Duration::from_millis(500));
        collector.stop().expect("stop");
        // A fixed 20 ms delay allows about 25 restarts in this window; doubling
        // delays (20, 40, 80, 160, 320 ms) allow about five.
        let restarts = collector.stats().backend_restarts;
        assert!((2..=8).contains(&restarts), "{restarts} restarts in 500 ms");
    }

    struct TrafficThenFailure;

    impl Backend for TrafficThenFailure {
        fn name(&self) -> &'static str {
            "traffic-then-failure"
        }

        fn run(
            &mut self,
            _config: &BackendConfig,
            sink: EventSink,
            _stop: StopFlag,
        ) -> Result<(), BackendError> {
            let key = test_key(false, 51_000);
            assert!(sink.emit(BackendEvent::Opened {
                key,
                pid: 42,
                cookie: None,
                timestamp: 1,
                if_index: None,
            }));
            assert!(sink.emit(BackendEvent::Bytes {
                key,
                pid: 42,
                delta: ByteDelta {
                    sent: 7,
                    received: 3,
                },
                timestamp: 2,
                if_index: None,
                cookie: None,
            }));
            Err(BackendError::new(
                BackendErrorKind::SessionLost,
                "test",
                "synthetic crash",
            ))
        }
    }

    #[test]
    fn failed_backend_flushes_bytes_and_closes_generation_flows() {
        let mut builder = CollectorBuilder::new()
            .watchdog_backoff_ms(1_000)
            .coalesce_interval_ms(100);
        builder.backend_factory = Some(Arc::new(|| Box::new(TrafficThenFailure)));
        let mut collector = builder.build().expect("collector");
        let events = Arc::new(Mutex::new(Vec::new()));
        let captured = Arc::clone(&events);
        collector
            .start(Box::new(move |event| captured.lock().unwrap().push(event)))
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(1);
        while !events
            .lock()
            .unwrap()
            .iter()
            .any(|event| matches!(event, FlowEvent::Closed(_, _)))
            && Instant::now() < deadline
        {
            thread::sleep(Duration::from_millis(1));
        }
        collector.stop().unwrap();
        let events = events.lock().unwrap();
        let bytes = events
            .iter()
            .position(|event| matches!(event, FlowEvent::Bytes(_, delta) if delta.sent == 7 && delta.received == 3))
            .expect("exact final bytes");
        let closed = events
            .iter()
            .position(|event| matches!(event, FlowEvent::Closed(_, _)))
            .expect("generation close");
        assert!(bytes < closed);
    }

    struct UnsupportedBackend {
        runs: Arc<AtomicU64>,
    }

    impl Backend for UnsupportedBackend {
        fn name(&self) -> &'static str {
            "unsupported-test"
        }

        fn run(
            &mut self,
            _config: &BackendConfig,
            _sink: EventSink,
            _stop: StopFlag,
        ) -> Result<(), BackendError> {
            self.runs.fetch_add(1, Ordering::Relaxed);
            Err(BackendError::new(
                BackendErrorKind::Unsupported,
                "test",
                "unsupported",
            ))
        }
    }

    #[test]
    fn unsupported_backend_is_terminal_instead_of_retrying_forever() {
        let runs = Arc::new(AtomicU64::new(0));
        let factory_runs = Arc::clone(&runs);
        let mut builder = CollectorBuilder::new()
            .watchdog_backoff_ms(1)
            .coalesce_interval_ms(1);
        builder.backend_factory = Some(Arc::new(move || {
            Box::new(UnsupportedBackend {
                runs: Arc::clone(&factory_runs),
            })
        }));
        let mut collector = builder.build().expect("collector");
        collector
            .start(Box::new(|_event| {}))
            .expect("collector start");
        thread::sleep(Duration::from_millis(30));
        collector.stop().expect("collector stop");
        assert_eq!(runs.load(Ordering::Relaxed), 1);
        assert_eq!(collector.stats().backend_restarts, 0);
    }

    #[test]
    fn finished_panicked_worker_is_reaped_and_can_be_restarted() {
        let script = vec![BackendEvent::ProcessStopped {
            pid: 1,
            timestamp: 1,
            identity: None,
        }];
        let mut builder = CollectorBuilder::new().coalesce_interval_ms(1);
        builder.backend_factory = Some(scripted_factory(script));
        let mut collector = builder.build().expect("collector");
        collector
            .start(Box::new(|_event| panic!("synthetic consumer panic")))
            .expect("first start");
        let deadline = Instant::now() + Duration::from_secs(1);
        while collector.is_running() && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(1));
        }
        assert!(!collector.is_running());
        assert!(matches!(
            collector.start(Box::new(|_event| {})),
            Err(MetricsError::ThreadPanic)
        ));
        collector
            .start(Box::new(|_event| {}))
            .expect("restart after reaping panic");
        collector.stop().expect("stop restarted collector");
    }

    struct PanickingBatchConsumer;

    impl FlowConsumer for PanickingBatchConsumer {
        fn on_event(&mut self, _event: FlowEvent) {}

        fn on_batch(&mut self, _events: &[FlowEvent]) {
            panic!("synthetic on_batch panic");
        }
    }

    #[test]
    fn panic_guard_covers_direct_batch_dispatch() {
        let stop = StopFlag::new();
        let mut consumer = StopOnPanicConsumer {
            inner: Box::new(PanickingBatchConsumer),
            stop: stop.clone(),
        };
        let unwind = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            consumer.on_batch(&[]);
        }));
        assert!(unwind.is_err());
        assert!(stop.is_stop_requested());
    }

    #[test]
    fn panicked_on_batch_worker_is_reaped_and_can_be_restarted() {
        let script = vec![BackendEvent::ProcessStopped {
            pid: 1,
            timestamp: 1,
            identity: None,
        }];
        let mut builder = CollectorBuilder::new().coalesce_interval_ms(1);
        builder.backend_factory = Some(scripted_factory(script));
        let mut collector = builder.build().expect("collector");
        collector
            .start(Box::new(PanickingBatchConsumer))
            .expect("first start");
        let deadline = Instant::now() + Duration::from_secs(5);
        while collector.is_running() && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(1));
        }
        assert!(
            !collector.is_running(),
            "on_batch panic must mark the collector stopped"
        );
        assert!(matches!(
            collector.start(Box::new(|_event| {})),
            Err(MetricsError::ThreadPanic)
        ));
        collector
            .start(Box::new(|_event| {}))
            .expect("restart after reaping panic");
        collector.stop().expect("stop restarted collector");
    }

    #[test]
    fn detached_snapshot_worker_cannot_overwrite_newer_run() {
        let snapshot = Arc::new(RwLock::new(SnapshotState {
            generation: 1,
            snapshot: FlowSnapshot::default(),
        }));
        let table = FlowTable::new(1);
        let publisher = SnapshotPublisher::new("stale-snapshot-test", Arc::clone(&snapshot), 1)
            .expect("snapshot publisher");
        let idle = Arc::clone(&publisher.idle);
        let mut snapshot_guard = write_lock(&snapshot);
        assert!(publisher.try_publish(&table, 1));

        let unwind = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
            let _publisher = publisher;
            panic!("synthetic collector panic");
        }));
        assert!(unwind.is_err());

        snapshot_guard.generation = 2;
        snapshot_guard.snapshot.captured_at = 2;
        drop(snapshot_guard);
        let deadline = Instant::now() + Duration::from_secs(1);
        while !idle.load(Ordering::Acquire) && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(1));
        }
        assert!(
            idle.load(Ordering::Acquire),
            "snapshot worker did not finish publication"
        );
        assert_eq!(read_lock(&snapshot).snapshot.captured_at, 2);
    }

    #[test]
    fn dns_answers_are_normalized_and_published() {
        let remote = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 20));
        let script = vec![BackendEvent::DnsResolved {
            pid: 42,
            query: "Example.TEST.".to_owned(),
            answers: vec![remote],
            ttl_ms: 10_000,
            timestamp: unix_now_ms(),
        }];
        let mut builder = CollectorBuilder::new()
            .dns_hints(true)
            .coalesce_interval_ms(5);
        builder.backend_factory = Some(scripted_factory(script));
        let mut collector = builder.build().expect("collector");
        let events = Arc::new(Mutex::new(Vec::new()));
        let captured = Arc::clone(&events);
        collector
            .start(Box::new(move |event| {
                captured.lock().expect("events").push(event);
            }))
            .expect("collector start");
        thread::sleep(Duration::from_millis(30));
        collector.stop().expect("collector stop");
        assert!(events.lock().expect("events").iter().any(|event| matches!(
            event,
            FlowEvent::DnsResolvedWithMetadata {
                attribution: DnsResolutionAttribution::Process(42),
                query,
                answers,
                ttl_ms: 10_000,
                ..
            } if query == "example.test" && *answers == [remote.to_string()]
        )));
    }

    #[test]
    fn dns_ttl_policy_defaults_missing_values_and_caps_oversized_values() {
        assert_eq!(effective_dns_ttl(0, 60_000), Some(60_000));
        assert_eq!(effective_dns_ttl(1_000, 60_000), Some(1_000));
        assert_eq!(
            effective_dns_ttl(u64::MAX, 60_000),
            Some(reconcile::MAX_DNS_TTL_MS)
        );
        assert_eq!(effective_dns_ttl(0, 0), None);
    }

    #[test]
    fn snapshots_publish_cumulative_totals() {
        let key = test_key(false, 50_001);
        let script = vec![
            BackendEvent::Opened {
                key,
                pid: 7,
                cookie: None,
                timestamp: unix_now_ms(),
                if_index: None,
            },
            BackendEvent::Bytes {
                key,
                pid: 7,
                delta: ByteDelta {
                    sent: 11,
                    received: 13,
                },
                timestamp: unix_now_ms(),
                if_index: None,
                cookie: None,
            },
        ];
        let mut builder = CollectorBuilder::new()
            .ignore_loopback(false)
            .snapshot_interval_ms(1)
            .coalesce_interval_ms(5);
        builder.backend_factory = Some(scripted_factory(script));
        let mut collector = builder.build().expect("collector");
        collector
            .start(Box::new(|_event| {}))
            .expect("collector start");
        // Wait for the scripted bytes rather than a fixed sleep, which a loaded CI runner can
        // outlast before the worker has drained the script.
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut snapshot = collector.snapshot_flows();
        while snapshot
            .flows
            .first()
            .is_none_or(|flow| flow.bytes_received < 13)
            && Instant::now() < deadline
        {
            thread::sleep(Duration::from_millis(5));
            snapshot = collector.snapshot_flows();
        }
        collector.stop().expect("collector stop");
        assert_eq!(snapshot.flows.len(), 1);
        assert_eq!(snapshot.flows[0].bytes_sent, 11);
        assert_eq!(snapshot.flows[0].bytes_received, 13);
    }

    struct PanickingBackend;

    impl Backend for PanickingBackend {
        fn name(&self) -> &'static str {
            "panicking"
        }

        fn run(
            &mut self,
            _config: &BackendConfig,
            _sink: EventSink,
            _stop: StopFlag,
        ) -> Result<(), BackendError> {
            panic!("synthetic backend panic");
        }
    }

    #[test]
    fn watchdog_restarts_panicked_backend_threads() {
        let mut builder = CollectorBuilder::new()
            .watchdog_backoff_ms(5)
            .coalesce_interval_ms(5);
        builder.backend_factory = Some(Arc::new(|| Box::new(PanickingBackend)));
        let mut collector = builder.build().expect("collector");
        collector
            .start(Box::new(|_event| {}))
            .expect("collector start");
        wait_for_backend_restarts(&collector, 2);
        collector.stop().expect("collector stop");
        assert!(collector.stats().backend_restarts >= 2);
    }

    struct RecordingConsumer(Vec<FlowEvent>);

    impl FlowConsumer for RecordingConsumer {
        fn on_event(&mut self, event: FlowEvent) {
            self.0.push(event);
        }

        fn on_batch_buffer(&mut self, events: &mut Vec<FlowEvent>) {
            self.0.append(events);
        }
    }

    #[test]
    fn flush_full_batches_preserves_order_and_the_final_partial() {
        let stats = SharedStats::default();
        let mut batch = vec![
            FlowEvent::ProcessStopped { pid: 1, stop_ts: 1 },
            FlowEvent::ProcessStopped { pid: 2, stop_ts: 2 },
            FlowEvent::ProcessStopped { pid: 3, stop_ts: 3 },
            FlowEvent::ProcessStopped { pid: 4, stop_ts: 4 },
            FlowEvent::ProcessStopped { pid: 5, stop_ts: 5 },
        ];
        let original_capacity = batch.capacity();
        let mut output = Vec::with_capacity(2);
        let mut consumer = RecordingConsumer(Vec::new());
        flush_full_batches(&mut batch, &mut output, &mut consumer, 2, &stats);
        assert_eq!(
            consumer.0,
            vec![
                FlowEvent::ProcessStopped { pid: 1, stop_ts: 1 },
                FlowEvent::ProcessStopped { pid: 2, stop_ts: 2 },
                FlowEvent::ProcessStopped { pid: 3, stop_ts: 3 },
                FlowEvent::ProcessStopped { pid: 4, stop_ts: 4 },
            ]
        );
        assert_eq!(
            batch,
            vec![FlowEvent::ProcessStopped { pid: 5, stop_ts: 5 }]
        );
        assert!(batch.capacity() >= original_capacity);
        let output_capacity = output.capacity();
        assert!(output_capacity >= 2);
        assert_eq!(stats.events_published.load(Ordering::Relaxed), 4);

        batch.extend([
            FlowEvent::ProcessStopped { pid: 6, stop_ts: 6 },
            FlowEvent::ProcessStopped { pid: 7, stop_ts: 7 },
            FlowEvent::ProcessStopped { pid: 8, stop_ts: 8 },
        ]);
        flush_full_batches(&mut batch, &mut output, &mut consumer, 2, &stats);
        assert_eq!(
            consumer.0[4..],
            [
                FlowEvent::ProcessStopped { pid: 5, stop_ts: 5 },
                FlowEvent::ProcessStopped { pid: 6, stop_ts: 6 },
                FlowEvent::ProcessStopped { pid: 7, stop_ts: 7 },
                FlowEvent::ProcessStopped { pid: 8, stop_ts: 8 },
            ]
        );
        assert!(batch.is_empty());
        assert_eq!(output.capacity(), output_capacity);
        assert_eq!(stats.events_published.load(Ordering::Relaxed), 8);
    }

    fn apply_events(events: Vec<BackendEvent>) -> (Vec<FlowEvent>, FlowTable, ProcessTable) {
        let config = CollectorConfig {
            ignore_loopback: false,
            ..CollectorConfig::default()
        };
        let mut flow_table = FlowTable::new(16);
        let mut process_table = ProcessTable::new(config.process_grace_ms, 1_024);
        let mut coalescer = IngressCoalescer::new(10_000, 0);
        let stats = SharedStats::default();
        let mut batch = Vec::new();
        for event in events {
            process_backend_event(
                event,
                &config,
                &mut flow_table,
                &mut process_table,
                &mut coalescer,
                &stats,
                &mut batch,
                None,
            );
        }
        (batch, flow_table, process_table)
    }

    fn identity(start_ts: u64) -> ProcessIdentity {
        ProcessIdentity {
            executable: format!("C:/process-{start_ts}.exe"),
            name: "test".into(),
            start_ts,
        }
    }

    #[test]
    fn a_stale_stop_for_a_reused_pid_is_not_published() {
        let (batch, _, processes) = apply_events(vec![
            BackendEvent::ProcessStarted(ProcessInfo {
                pid: 42,
                identity: identity(200),
            }),
            BackendEvent::ProcessStopped {
                pid: 42,
                timestamp: 250,
                identity: Some(identity(100)),
            },
        ]);
        assert!(
            !batch
                .iter()
                .any(|event| matches!(event, FlowEvent::ProcessStopped { .. })),
            "the process still running must not be reported stopped"
        );
        assert_eq!(processes.resolve(42, 500_000).unwrap().start_ts, 200);
    }

    #[test]
    fn current_and_untracked_stops_are_published() {
        let (batch, _, _) = apply_events(vec![
            BackendEvent::ProcessStarted(ProcessInfo {
                pid: 42,
                identity: identity(200),
            }),
            BackendEvent::ProcessStopped {
                pid: 42,
                timestamp: 250,
                identity: Some(identity(200)),
            },
            // Another consumer may track a PID this table never saw.
            BackendEvent::ProcessStopped {
                pid: 43,
                timestamp: 250,
                identity: None,
            },
        ]);
        let stopped: Vec<_> = batch
            .iter()
            .filter_map(|event| match event {
                FlowEvent::ProcessStopped { pid, .. } => Some(*pid),
                _ => None,
            })
            .collect();
        assert_eq!(stopped, [42, 43]);
    }

    #[test]
    fn a_delayed_open_does_not_take_the_identity_of_a_later_process() {
        let key = test_key(false, 50_030);
        let (_, flows, _) = apply_events(vec![
            BackendEvent::ProcessStarted(ProcessInfo {
                pid: 42,
                identity: identity(200),
            }),
            BackendEvent::Opened {
                key,
                pid: 42,
                cookie: None,
                timestamp: 100,
                if_index: None,
            },
        ]);
        let meta = flows.get(&key).expect("flow").meta;
        assert_eq!(meta.pid, 42);
        assert_eq!(meta.process, None);
    }

    #[test]
    fn byte_cookie_change_closes_then_charges_new_bytes() {
        let config = CollectorConfig {
            ignore_loopback: false,
            ..CollectorConfig::default()
        };
        let mut flow_table = FlowTable::new(16);
        let mut process_table = ProcessTable::new(config.process_grace_ms, 1_024);
        let mut coalescer = IngressCoalescer::new(10_000, 0);
        let stats = SharedStats::default();
        let mut batch = Vec::new();
        let key = test_key(false, 50_020);
        let first = netmetrics_core::SocketCookie {
            value: 1,
            source: netmetrics_core::CookieSource::WindowsCreateTimestamp,
        };
        let second = netmetrics_core::SocketCookie {
            value: 2,
            source: netmetrics_core::CookieSource::WindowsCreateTimestamp,
        };
        for event in [
            BackendEvent::Opened {
                key,
                pid: 42,
                cookie: Some(first),
                timestamp: 1,
                if_index: None,
            },
            BackendEvent::Bytes {
                key,
                pid: 42,
                delta: ByteDelta {
                    sent: 10,
                    received: 0,
                },
                timestamp: 2,
                if_index: None,
                cookie: Some(first),
            },
            BackendEvent::Bytes {
                key,
                pid: 43,
                delta: ByteDelta {
                    sent: 5,
                    received: 0,
                },
                timestamp: 3,
                if_index: None,
                cookie: Some(second),
            },
            BackendEvent::Closed {
                key,
                pid: 0,
                timestamp: 4,
            },
        ] {
            process_backend_event(
                event,
                &config,
                &mut flow_table,
                &mut process_table,
                &mut coalescer,
                &stats,
                &mut batch,
                None,
            );
        }
        let kinds: Vec<_> = batch
            .iter()
            .filter_map(|event| match event {
                FlowEvent::Opened(_, meta) => {
                    Some(("open", meta.cookie.map(|cookie| cookie.value)))
                }
                FlowEvent::Bytes(_, delta) => Some(("bytes", Some(delta.sent))),
                FlowEvent::Closed(_, meta) => {
                    Some(("close", meta.cookie.map(|cookie| cookie.value)))
                }
                _ => None,
            })
            .collect();
        assert_eq!(
            kinds,
            vec![
                ("open", Some(1)),
                ("bytes", Some(10)),
                ("close", Some(1)),
                ("open", Some(2)),
                ("bytes", Some(5)),
                ("close", Some(2)),
            ]
        );
    }

    #[test]
    fn a_native_interface_learned_later_is_republished() {
        let config = CollectorConfig {
            ignore_loopback: false,
            ..CollectorConfig::default()
        };
        let mut flow_table = FlowTable::new(16);
        let mut process_table = ProcessTable::new(config.process_grace_ms, 1_024);
        let mut coalescer = IngressCoalescer::new(10_000, 0);
        let stats = SharedStats::default();
        let mut batch = Vec::new();
        let key = test_key(false, 50_022);
        let mut apply = |event| {
            process_backend_event(
                event,
                &config,
                &mut flow_table,
                &mut process_table,
                &mut coalescer,
                &stats,
                &mut batch,
                None,
            );
        };
        apply(BackendEvent::Opened {
            key,
            pid: 42,
            cookie: None,
            timestamp: 1,
            if_index: None,
        });
        apply(BackendEvent::Bytes {
            key,
            pid: 42,
            delta: ByteDelta {
                sent: 10,
                received: 0,
            },
            timestamp: 2,
            if_index: Some(7),
            cookie: None,
        });
        apply(BackendEvent::Opened {
            key,
            pid: 42,
            cookie: None,
            timestamp: 3,
            if_index: Some(7),
        });
        let published: Vec<_> = batch
            .iter()
            .filter_map(|event| match event {
                FlowEvent::Opened(opened, meta) if *opened == key => Some(meta.if_index),
                _ => None,
            })
            .collect();
        assert_eq!(
            published,
            vec![None, Some(7)],
            "republished once, when it changed"
        );
    }

    #[test]
    fn interface_hint_republishes_updated_metadata() {
        let config = CollectorConfig {
            ignore_loopback: false,
            ..CollectorConfig::default()
        };
        let mut flow_table = FlowTable::new(16);
        let mut process_table = ProcessTable::new(config.process_grace_ms, 1_024);
        let mut coalescer = IngressCoalescer::new(10_000, 0);
        let stats = SharedStats::default();
        let mut batch = Vec::new();
        let key = test_key(false, 50_021);
        process_backend_event(
            BackendEvent::Opened {
                key,
                pid: 42,
                cookie: None,
                timestamp: 1,
                if_index: None,
            },
            &config,
            &mut flow_table,
            &mut process_table,
            &mut coalescer,
            &stats,
            &mut batch,
            None,
        );
        let generation = flow_table.identity_generation(key).expect("flow");
        process_backend_event(
            BackendEvent::InterfaceHint {
                key,
                if_index: 7,
                bound: true,
                generation,
            },
            &config,
            &mut flow_table,
            &mut process_table,
            &mut coalescer,
            &stats,
            &mut batch,
            None,
        );
        let opened: Vec<_> = batch
            .iter()
            .filter_map(|event| match event {
                FlowEvent::Opened(_, meta) => Some(meta.if_index),
                _ => None,
            })
            .collect();
        assert_eq!(opened, vec![None, Some(7)]);
        assert_eq!(flow_table.get(&key).expect("flow").meta.if_index, Some(7));
    }

    #[test]
    fn cookie_replacement_requests_a_new_interface_estimate() {
        let config = CollectorConfig {
            ignore_loopback: false,
            ..CollectorConfig::default()
        };
        let mut flow_table = FlowTable::new(16);
        let mut process_table = ProcessTable::new(config.process_grace_ms, 1_024);
        let mut coalescer = IngressCoalescer::new(10_000, 0);
        let stats = SharedStats::default();
        let mut batch = Vec::new();
        let key = test_key(false, 50_022);
        let (lookup, recorded) = InterfaceLookup::recorder();
        process_backend_event(
            BackendEvent::Opened {
                key,
                pid: 42,
                cookie: Some(netmetrics_core::SocketCookie {
                    value: 1,
                    source: netmetrics_core::CookieSource::WindowsCreateTimestamp,
                }),
                timestamp: 1,
                if_index: None,
            },
            &config,
            &mut flow_table,
            &mut process_table,
            &mut coalescer,
            &stats,
            &mut batch,
            Some(&lookup),
        );
        let first_generation = flow_table.identity_generation(key).expect("flow");
        process_backend_event(
            BackendEvent::CookieResolved {
                key,
                pid: 43,
                cookie: netmetrics_core::SocketCookie {
                    value: 2,
                    source: netmetrics_core::CookieSource::WindowsCreateTimestamp,
                },
                timestamp: 2,
            },
            &config,
            &mut flow_table,
            &mut process_table,
            &mut coalescer,
            &stats,
            &mut batch,
            Some(&lookup),
        );
        let second_generation = flow_table.identity_generation(key).expect("replacement");
        assert_ne!(first_generation, second_generation);
        let requests = recorded.lock().expect("requests");
        assert_eq!(
            *requests,
            vec![(key, first_generation), (key, second_generation)]
        );
    }
}
