//! Fully wired daemon state and lifecycle.

use std::sync::Arc;

use antiwire_dns::{bootstrap_dns_interceptor, shutdown_dns_interceptor};
use antiwire_enforce::EnforcementClient;
use antiwire_events::ActiveConnectionCounter;
use antiwire_flow::{NetmetBridge, TrackerActiveConnectionCounter};
use antiwire_ipc::ServiceParts;
use antiwire_platform::{DataPaths, RetentionPolicy, RetentionScheduler, SiemConfig};
use antiwire_services::{LookupClients, SettingsFeed};
use antiwire_store::Store;
use antiwire_tuning::{FLOW_EVENT_QUEUE_CAPACITY, SHUTDOWN_DRAIN_TIMEOUT, SHUTDOWN_REVERT_TIMEOUT};
use anyhow::{bail, Context, Result};
use parking_lot::Mutex;
use tracing::{info, warn};

use crate::context::{assemble_daemon_context, build_update_service, DaemonContext};
use crate::host_revert::OrphanedPending;
use crate::keystore::platform_keystore;

/// How a runtime is hosted, which decides how it is built.
enum Host {
    /// Run by a service manager, with the native firewall. Only a service
    /// can install updates.
    Service,
    /// An interactive Windows run, with the native firewall. It registers
    /// the boot DNS heal task, since no service manager stops it on shutdown.
    Interactive,
    /// Embedded with a caller-supplied firewall worker, for tests and embedders.
    Embedded(EnforcementClient),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Lifecycle {
    Idle,
    Starting,
    Started,
    Stopped,
}

/// Fully wired daemon state.
pub struct AntiwireRuntime {
    context: Arc<DaemonContext>,
    bridge: Arc<Mutex<NetmetBridge>>,
    retention_scheduler: Mutex<Option<RetentionScheduler>>,
    flow_task: Mutex<Option<tokio::task::JoinHandle<()>>>,
    /// Abort handle for the supervised flow tracker, so a drain timeout can stop it.
    flow_abort: Mutex<Option<tokio::task::AbortHandle>>,
    lifecycle: Mutex<Lifecycle>,
    /// Whether the DNS redirect arms boot recovery: an interactive daemon,
    /// which nothing stops cleanly at shutdown, does; a service does not.
    arm_boot_recovery: bool,
}

impl AntiwireRuntime {
    /// Builds a runtime using the native firewall backend.
    ///
    /// # Errors
    ///
    /// Returns an error when the data directory, store, or service graph cannot
    /// be initialized.
    pub fn bootstrap(data_dir: impl Into<std::path::PathBuf>) -> Result<Self> {
        Self::bootstrap_inner(data_dir.into(), Host::Service)
    }

    /// Interactive (non-service) Windows entry: the DNS redirect arms boot recovery.
    ///
    /// # Errors
    ///
    /// Returns an error when the data directory, store, or service graph cannot
    /// be initialized.
    pub fn bootstrap_interactive(data_dir: impl Into<std::path::PathBuf>) -> Result<Self> {
        Self::bootstrap_inner(data_dir.into(), Host::Interactive)
    }

    /// Builds a runtime with a caller-supplied firewall worker.
    ///
    /// This keeps lifecycle tests and embedders independent of privileged host
    /// firewall access while [`Self::bootstrap`] continues to use the native backend.
    ///
    /// # Errors
    ///
    /// Returns an error when the data directory, store, or service graph cannot
    /// be initialized.
    pub fn bootstrap_with_enforcement(
        data_dir: impl Into<std::path::PathBuf>,
        enforce: EnforcementClient,
    ) -> Result<Self> {
        Self::bootstrap_inner(data_dir.into(), Host::Embedded(enforce))
    }

    fn bootstrap_inner(data_dir: std::path::PathBuf, host: Host) -> Result<Self> {
        let arm_boot_recovery = matches!(host, Host::Interactive);
        let is_service = matches!(host, Host::Service);
        let data_paths = DataPaths::new(data_dir);
        data_paths.ensure_root().context("data dir")?;
        let keystore = platform_keystore(&data_paths);

        // Once before the store opens, to restrict files left by an earlier run before
        // anything reads them, and once after, to cover the WAL sidecars SQLite creates while
        // entering WAL mode. `secure_database` skips files that do not exist, so on first
        // launch the first call does nothing: a database created by `open_with_keystore`
        // inherits the data directory's ACL until the second call.
        data_paths.secure_database();
        let store = Arc::new(
            Store::open_with_keystore(data_paths.database(), &keystore).context("open store")?,
        );
        data_paths.secure_database();

        let settings = SettingsFeed::load(Arc::clone(&store)).context("load settings")?;
        let enforce = if let Host::Embedded(enforce) = host {
            enforce
        } else {
            EnforcementClient::try_new().context("firewall worker")?
        };
        let updates = build_update_service(&data_paths.root, is_service, settings.clone());
        let lookups = LookupClients::online().context("lookup clients")?;
        let context =
            assemble_daemon_context(data_paths, store, settings, enforce, updates, lookups);
        let bridge =
            NetmetBridge::new().with_collector_health(Arc::clone(&context.collector_health));

        Ok(Self {
            context,
            bridge: Arc::new(Mutex::new(bridge)),
            retention_scheduler: Mutex::new(None),
            flow_task: Mutex::new(None),
            flow_abort: Mutex::new(None),
            lifecycle: Mutex::new(Lifecycle::Idle),
            arm_boot_recovery,
        })
    }

    /// What the IPC server serves for this runtime.
    ///
    /// `shutdown` is a child of the runtime's token: cancelling it stops the
    /// server on its own, and stopping the runtime stops the server too.
    #[must_use]
    pub fn ipc_service_parts(&self) -> ServiceParts {
        ServiceParts {
            services: self.context.services.clone(),
            store: Arc::clone(&self.context.store),
            traffic_hub: self.context.traffic_hub.clone(),
            alerts: self.context.alerts.clone(),
            active_connections: Arc::new(TrackerActiveConnectionCounter::new(Arc::clone(
                &self.context.flow_tracker,
            ))) as Arc<dyn ActiveConnectionCounter>,
            collector_health: Arc::clone(&self.context.collector_health),
            capture: Arc::clone(&self.context.capture),
            updates: Arc::clone(&self.context.updates),
            shutdown: self.context.shutdown.child_token(),
        }
    }

    /// Starts DNS, firewall rules, collectors, and background schedulers.
    ///
    /// The runtime is single-use. A second start, or a start after stop or a
    /// failed start, returns an error. Any failure after this method begins
    /// rolls host state back through the same teardown as [`Self::stop`].
    ///
    /// # Errors
    ///
    /// Returns an error when settings cannot be loaded, firewall rules cannot
    /// be installed, flow collection cannot start, or the runtime is not idle.
    pub async fn start(&self) -> Result<()> {
        {
            let mut lifecycle = self.lifecycle.lock();
            match *lifecycle {
                Lifecycle::Idle => *lifecycle = Lifecycle::Starting,
                Lifecycle::Starting => bail!("antiwire runtime start is already in progress"),
                Lifecycle::Started => bail!("antiwire runtime already started"),
                Lifecycle::Stopped => bail!("antiwire runtime cannot be restarted"),
            }
        }

        match self.start_inner().await {
            Ok(()) => {
                *self.lifecycle.lock() = Lifecycle::Started;
                info!("antiwire runtime started");
                Ok(())
            }
            Err(error) => {
                *self.lifecycle.lock() = Lifecycle::Stopped;
                if let Err(stop_error) = self.stop_inner().await {
                    warn!(
                        error = %stop_error,
                        "rollback after failed start also failed"
                    );
                }
                Err(error)
            }
        }
    }

    async fn start_inner(&self) -> Result<()> {
        let settings = self.context.settings.current();

        // Before DNS starts: ordinary DNS stays fail-closed until the
        // selected hosts blocklists load.
        self.context.services.hosts_blocklist.start();

        bootstrap_dns_interceptor(
            &self.context.dns_interceptor,
            self.context.services.dns.clone(),
            &settings,
            self.arm_boot_recovery,
            self.context.shutdown.clone(),
        )
        .await
        .context("bootstrap dns interceptor")?;

        antiwire_dns::attach_dns_hint_sink(
            &self.context.dns_interceptor,
            Arc::clone(&self.context.flow_tracker) as Arc<dyn antiwire_dns::DnsHintSink>,
        )
        .await;

        let rule_service = Arc::clone(&self.context.services.rules);
        run_blocking("install saved firewall rules", move || {
            rule_service.install_saved_rules()
        })
        .await?
        .context("install saved firewall rules")?;
        // After the rules: installing them clears every managed rule, this
        // block included. A failure leaves the saved rules enforced.
        let doh = Arc::clone(&self.context.services.doh);
        match run_blocking("apply DoH blocking", move || doh.reconcile(&[])).await? {
            Ok(()) => {}
            Err(error) => warn!(%error, "could not apply DoH blocking"),
        }

        // Before the flow tracker starts, so the first flows are enriched.
        self.context.services.geo_database.start().await;
        if let Err(error) = self.context.services.network_mapping.start().await {
            warn!(%error, "network mapping did not start; scans and presence checks are off");
        }
        self.context
            .updates
            .spawn_checker(self.context.shutdown.clone());

        if let Err(error) = self
            .context
            .siem
            .update_config(SiemConfig::from_settings(&settings))
        {
            warn!(error = %error, "failed to update SIEM configuration");
        }

        let scheduler = RetentionScheduler::start(Arc::clone(&self.context.store));
        *self.retention_scheduler.lock() = Some(scheduler);

        let tracker = Arc::clone(&self.context.flow_tracker);
        let process_rundown = run_blocking("bootstrap running processes", move || {
            tracker.bootstrap_running_processes()
        })
        .await?;
        info!(
            enumerated = process_rundown.enumerated,
            seeded = process_rundown.seeded,
            "seeded process identities from startup rundown"
        );
        if process_rundown.enumerated > 0 && process_rundown.seeded == 0 {
            warn!(
                "startup process rundown seeded nothing; early flows will resolve \
                 without lifecycle evidence until their processes re-resolve"
            );
        }

        let rx = self
            .bridge
            .lock()
            .start(FLOW_EVENT_QUEUE_CAPACITY)
            .context("netmet bridge")?;

        let tracker = Arc::clone(&self.context.flow_tracker);
        let task = tracker.spawn_supervised(
            rx,
            Arc::clone(&self.context.collector_health),
            self.context.shutdown.clone(),
        );
        *self.flow_abort.lock() = Some(task.abort_handle());
        *self.flow_task.lock() = Some(task);
        Ok(())
    }

    /// Tears the daemon down: one signal, then everything stops at once.
    ///
    /// Teardown is racing a deadline it does not control — an OS shutdown kills
    /// the process a few seconds in, whether or not this returned — so nothing
    /// waits for anything it does not need. Cancelling the shutdown token
    /// reaches every background service, traffic stream and the IPC server at
    /// the same moment. The host revert (adapter DNS and firewall rules, the
    /// only state that outlives the process) then runs beside the drain of
    /// collectors and buffers, as a task of its own, so a blocklist download
    /// refusing to cancel or a slow final flow flush can neither delay the
    /// DNS restore nor be delayed by it.
    ///
    /// The revert cannot be undone by work still running beside it: the DNS
    /// slot and the firewall worker close for good as they stop, so a request
    /// that is still finishing cannot start a resolver or install a rule
    /// again. Only the blocked-query recorder and the alert flush wait, for
    /// the revert and the drain both feed them.
    ///
    /// Stop is idempotent: calling it before start, or twice, succeeds without
    /// repeating teardown.
    ///
    /// # Errors
    ///
    /// Returns an error when the flow tracker's supervisor task fails to join; a
    /// tracker fault inside it is reported through collector health instead.
    /// Also returns an error, after every drain phase has run, when the host
    /// was not fully reverted: adapter DNS not confirmed restored, or firewall
    /// rules not removed. Recovery state is kept for the reaper or the next
    /// start then, and the error lets a service host report the failed stop.
    pub async fn stop(&self) -> Result<()> {
        {
            let mut lifecycle = self.lifecycle.lock();
            match *lifecycle {
                // Start owns rollback on `Starting`. Idle/Stopped have nothing to tear down.
                // `Stopped` is claimed before `stop_inner` so a second stop is a no-op
                // rather than repeating host revert.
                Lifecycle::Idle | Lifecycle::Starting | Lifecycle::Stopped => return Ok(()),
                Lifecycle::Started => *lifecycle = Lifecycle::Stopped,
            }
        }

        self.stop_inner().await
    }

    async fn stop_inner(&self) -> Result<()> {
        self.context.request_shutdown();
        let deadline = tokio::time::Instant::now() + SHUTDOWN_DRAIN_TIMEOUT;

        let drain = tokio::spawn(drain(self.drain_parts()));
        let pending = revert_host_state(&self.context).await;
        let drained = self.join_drain(drain, deadline).await;
        self.save_final_records(deadline).await;

        if pending.any() {
            if let Err(error) = drained {
                warn!(error = %error, "shutdown drain failed");
            }
            bail!("{}", pending.describe())
        }
        drained
    }

    /// What the drain takes out of the runtime to run as a task of its own.
    fn drain_parts(&self) -> DrainParts {
        DrainParts {
            context: Arc::clone(&self.context),
            bridge: Arc::clone(&self.bridge),
            scheduler: self.retention_scheduler.lock().take(),
            flow_task: self.flow_task.lock().take(),
        }
    }

    /// Waits for the drain until `deadline`, then stops what is left of it.
    async fn join_drain(
        &self,
        mut drain: tokio::task::JoinHandle<Result<()>>,
        deadline: tokio::time::Instant,
    ) -> Result<()> {
        match tokio::time::timeout_at(deadline, &mut drain).await {
            Ok(Ok(result)) => result,
            Ok(Err(error)) => Err(error).context("shutdown drain task failed"),
            Err(_) => {
                warn!(
                    timeout = ?SHUTDOWN_DRAIN_TIMEOUT,
                    "shutdown drain did not finish in time; exiting anyway"
                );
                // Aborting the drain detaches whatever it was awaiting; abort the
                // tracker too, so a wedged task cannot keep polling past `stop`
                // in an embedder that stays alive after this returns.
                drain.abort();
                if let Some(abort) = self.flow_abort.lock().take() {
                    abort.abort();
                }
                Ok(())
            }
        }
    }

    /// Saves the blocked queries and alerts still queued, by `deadline`.
    ///
    /// After the revert and the drain, because both feed these: the resolver
    /// records blocked queries until it stops, and the revert and the final
    /// flow window raise alerts. Both are bounded on their own; the deadline
    /// only keeps a stuck store write from holding the stop past it.
    async fn save_final_records(&self, deadline: tokio::time::Instant) {
        let saved = tokio::time::timeout_at(deadline, async {
            self.context.dns_block_recorder.shutdown().await;
            let alerts = self.context.alerts.clone();
            if let Err(error) = run_blocking("flush alerts", move || alerts.flush()).await {
                warn!(error = %error, "alert flush task failed");
            }
        })
        .await;
        if saved.is_err() {
            warn!(
                timeout = ?SHUTDOWN_DRAIN_TIMEOUT,
                "blocked queries or alerts were still being saved at the shutdown deadline"
            );
        }
    }
}

/// What [`drain`] stops and flushes, owned so it can run as a task.
struct DrainParts {
    context: Arc<DaemonContext>,
    bridge: Arc<Mutex<NetmetBridge>>,
    scheduler: Option<RetentionScheduler>,
    flow_task: Option<tokio::task::JoinHandle<()>>,
}

/// Undoes every change this daemon made to the host, under a hard deadline,
/// and returns what it could not.
///
/// The two reverts run concurrently rather than in sequence: they touch
/// unrelated subsystems (adapter DNS via IP Helper, rules via the firewall
/// backend's own worker thread), and serializing them would let a slow
/// restore spend the entire budget before the rules were even looked at.
///
/// Timing the DNS restore out is not the same as abandoning it: the DNS stop
/// runs as a task of its own, which carries on past the deadline, waiting
/// first for any settings change still holding the resolver. Whatever still
/// does not land is recovered on the next start — the interceptor recovers
/// from the persisted redirect state and `RuleService::install_saved_rules`
/// clears the managed namespace — so the failure mode here is a boot with
/// stale state rather than a permanent one.
///
/// With "persist rules offline" set, firewall rules are left installed, as
/// the reaper leaves them after a crash; only the rules that depend on the
/// resolver are removed.
///
/// Both close for good: the DNS slot takes no new interceptor and the
/// firewall worker installs no rule after this, whatever is still running.
async fn revert_host_state(context: &DaemonContext) -> OrphanedPending {
    let dns = tokio::time::timeout(
        SHUTDOWN_REVERT_TIMEOUT,
        shutdown_dns_interceptor(&context.dns_interceptor),
    );

    // `EnforcementClient::close` blocks on a reply from the firewall worker
    // thread, so it cannot be awaited directly on a runtime worker.
    let enforce = context.enforce.clone();
    let keep_rules = context.settings.current().persist_rules_offline;
    let firewall = tokio::time::timeout(
        SHUTDOWN_REVERT_TIMEOUT,
        tokio::task::spawn_blocking(move || {
            if keep_rules {
                info!("leaving firewall rules installed while the daemon is offline");
            }
            enforce.close(keep_rules)
        }),
    );

    let (dns, firewall) = tokio::join!(dns, firewall);

    // `shutdown_dns_interceptor` logs its own failure.
    let dns_restored = if let Ok(result) = dns {
        result.is_ok()
    } else {
        warn!(
            timeout = ?SHUTDOWN_REVERT_TIMEOUT,
            "adapter DNS restore did not finish in time; it will be retried on next start"
        );
        false
    };

    let firewall_stopped = match firewall {
        Ok(Ok(Ok(()))) => true,
        Ok(Ok(Err(error))) => {
            warn!(error = %error, "failed to stop firewall enforcement");
            false
        }
        Ok(Err(error)) => {
            warn!(error = %error, "firewall teardown task failed");
            false
        }
        Err(_) => {
            warn!(
                timeout = ?SHUTDOWN_REVERT_TIMEOUT,
                "firewall rule removal did not finish in time; rules will be cleared on next start"
            );
            false
        }
    };

    OrphanedPending {
        dns: !dns_restored,
        firewall: !firewall_stopped,
    }
}

/// Stops the collectors and background services and flushes what they
/// buffered. Runs beside the host revert; nothing here outlives the process.
///
/// The flows and the background services drain side by side: the services
/// were cancelled with everything else, and one slow to stop cannot hold up
/// the final flow window. Every failure is logged rather than allowed to skip
/// a later phase.
async fn drain(parts: DrainParts) -> Result<()> {
    let DrainParts {
        context,
        bridge,
        scheduler,
        flow_task,
    } = parts;
    let services = async {
        tokio::join!(
            context.services.hosts_blocklist.shutdown(),
            context.services.geo_database.shutdown(),
            context.services.network_mapping.shutdown(),
        );
    };
    let flows = drain_flows(Arc::clone(&context.store), bridge, scheduler, flow_task);
    let (joined, ()) = tokio::join!(flows, services);
    joined
}

/// Stops the collector, then waits for the flow tracker to persist its final
/// window, then purges expired connection logs.
async fn drain_flows(
    store: Arc<Store>,
    bridge: Arc<Mutex<NetmetBridge>>,
    scheduler: Option<RetentionScheduler>,
    flow_task: Option<tokio::task::JoinHandle<()>>,
) -> Result<()> {
    if let Some(mut scheduler) = scheduler {
        scheduler.stop();
    }

    // Stop the native collector on the blocking pool. Its forwarding worker
    // retains the channel sender until queued events drain; awaiting the flow
    // task below therefore includes the collector's final window.
    match run_blocking("stop netmet bridge", move || bridge.lock().stop()).await {
        Ok(Ok(())) => {}
        Ok(Err(error)) => warn!(error = %error, "failed to stop netmet bridge"),
        Err(error) => warn!(error = %error, "netmet bridge stop task failed"),
    }

    let joined = match flow_task {
        Some(task) => task.await.context("join flow tracker"),
        None => Ok(()),
    };

    purge_connection_logs_best_effort(store).await;
    joined
}

/// Purges connection logs past the retention period; a failure is logged.
async fn purge_connection_logs_best_effort(store: Arc<Store>) {
    let purged: Result<u64> = async {
        let reader = Arc::clone(&store);
        let settings = run_blocking("load retention settings", move || reader.get_settings())
            .await?
            .context("load retention settings")?;
        run_blocking("retention purge", move || {
            let policy = RetentionPolicy::from_settings(&settings);
            antiwire_platform::purge_connection_logs(&store, &policy)
        })
        .await?
        .context("retention purge")
    }
    .await;
    if let Err(error) = purged {
        warn!(error = %format!("{error:#}"), "shutdown retention purge failed");
    }
}

async fn run_blocking<T, F>(label: &'static str, work: F) -> Result<T>
where
    T: Send + 'static,
    F: FnOnce() -> T + Send + 'static,
{
    tokio::task::spawn_blocking(work)
        .await
        .with_context(|| format!("{label} task panicked"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use antiwire_enforce::{EnforceError, FirewallFilter};
    use antiwire_policy::EnforcementOp;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tempfile::tempdir;

    struct FailingStartFirewall {
        starts: Arc<AtomicUsize>,
        stops: Arc<AtomicUsize>,
    }

    impl FirewallFilter for FailingStartFirewall {
        fn start(&mut self) -> antiwire_enforce::Result<()> {
            self.starts.fetch_add(1, Ordering::SeqCst);
            Err(EnforceError::InvalidOp(
                "injected firewall start failure".into(),
            ))
        }

        fn stop(&mut self) -> antiwire_enforce::Result<()> {
            self.stops.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }

        fn is_enforcing(&self) -> bool {
            false
        }

        fn apply(&mut self, _op: EnforcementOp) -> antiwire_enforce::Result<()> {
            Err(EnforceError::NotStarted)
        }
    }

    /// Starts at once; stops only once the test drops `gate`'s sender, as
    /// a backend removing many rules would take its time.
    struct GatedStopFirewall {
        started: bool,
        gate: std::sync::mpsc::Receiver<()>,
    }

    impl FirewallFilter for GatedStopFirewall {
        fn start(&mut self) -> antiwire_enforce::Result<()> {
            self.started = true;
            Ok(())
        }

        fn stop(&mut self) -> antiwire_enforce::Result<()> {
            let _ = self.gate.recv();
            self.started = false;
            Ok(())
        }

        fn is_enforcing(&self) -> bool {
            self.started
        }

        fn apply(&mut self, _op: EnforcementOp) -> antiwire_enforce::Result<()> {
            if self.started {
                Ok(())
            } else {
                Err(EnforceError::NotStarted)
            }
        }
    }

    /// A runtime whose firewall is started and holds its stop until the
    /// returned sender is dropped.
    fn runtime_with_gated_firewall(
        dir: &std::path::Path,
    ) -> (AntiwireRuntime, std::sync::mpsc::Sender<()>) {
        let (release, gate) = std::sync::mpsc::channel();
        let enforce = EnforcementClient::with_filter(GatedStopFirewall {
            started: false,
            gate,
        })
        .expect("firewall worker");
        let runtime = AntiwireRuntime::bootstrap_with_enforcement(dir, enforce).expect("bootstrap");
        runtime.context.enforce.start().expect("firewall start");
        (runtime, release)
    }

    fn expired_connection_log() -> antiwire_store::NewConnectionLog {
        let long_ago = time::OffsetDateTime::UNIX_EPOCH;
        antiwire_store::NewConnectionLog {
            timestamp: long_ago,
            app_id: 1,
            app_path: String::new(),
            protocol: "TCP".to_owned(),
            src_ip: "192.0.2.1".to_owned(),
            src_port: 50000,
            dst_ip: "192.0.2.2".to_owned(),
            dst_port: 443,
            dst_domain: "expired.example.com".to_owned(),
            bytes_sent: 0,
            bytes_received: 0,
            action_taken: "ALLOWED".to_owned(),
            last_seen: long_ago,
            country_code: String::new(),
            isp: String::new(),
            blocklist_names: String::new(),
            conn_id: 0,
            conn_pid: 0,
            is_close: false,
            replace_domain: false,
        }
    }

    fn holds_the_expired_log(runtime: &AntiwireRuntime) -> bool {
        !runtime
            .context
            .store
            .seen_subdomains("example.com", 10)
            .expect("read logs")
            .is_empty()
    }

    /// The regression this guards: each part of shutdown waited for the one
    /// before it, so a slow firewall revert held the flow drain back, and the
    /// whole stop took the sum of their times.
    ///
    /// The drain's last step purges expired connection logs. It must land
    /// while the firewall revert is still held.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_drain_finishes_while_the_revert_is_still_running() {
        let dir = tempdir().expect("tempdir");
        let (runtime, release) = runtime_with_gated_firewall(dir.path());
        let runtime = Arc::new(runtime);
        runtime
            .context
            .store
            .insert_connection_logs(&[expired_connection_log()])
            .expect("seed log");
        assert!(holds_the_expired_log(&runtime));

        let stopping = tokio::spawn({
            let runtime = Arc::clone(&runtime);
            async move { runtime.stop_inner().await }
        });

        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while holds_the_expired_log(&runtime) {
            assert!(
                std::time::Instant::now() < deadline,
                "the drain waited for the firewall revert"
            );
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        assert!(!stopping.is_finished(), "the firewall revert is still held");

        drop(release);
        stopping.await.expect("stop task").expect("stop");
    }

    /// The regression this guards: with every part stopping at once, a
    /// settings change or rule install still running when shutdown began
    /// could start a new resolver or reinstall rules after the revert.
    ///
    /// The settings change turns the resolver off, so that a regression
    /// fails here rather than redirecting this host's DNS.
    #[tokio::test]
    async fn work_still_running_after_the_revert_cannot_reinstall_host_state() {
        let dir = tempdir().expect("tempdir");
        let (runtime, release) = runtime_with_gated_firewall(dir.path());
        drop(release);

        runtime.stop_inner().await.expect("stop");

        let update = runtime
            .context
            .services
            .settings
            .update(|saved| antiwire_store::DaemonSetting {
                dns_resolver_enabled: !saved.dns_resolver_enabled,
                ..saved.clone()
            })
            .await
            .expect("the change is still saved");
        assert!(
            update
                .not_applied
                .iter()
                .any(|part| part.starts_with("DNS:")),
            "the resolver change must be refused: {:?}",
            update.not_applied
        );
        assert!(runtime.context.dns_interceptor.is_closed());
        assert!(!runtime.context.dns_interceptor.is_occupied().await);

        assert!(matches!(
            runtime.context.enforce.start(),
            Err(EnforceError::Closed)
        ));
        assert!(matches!(
            runtime
                .context
                .enforce
                .apply(EnforcementOp::RemoveDohBlocks),
            Err(EnforceError::Closed)
        ));
    }

    #[tokio::test]
    async fn failed_start_rolls_back_dns_and_firewall() {
        let dir = tempdir().expect("tempdir");
        let starts = Arc::new(AtomicUsize::new(0));
        let stops = Arc::new(AtomicUsize::new(0));
        let enforce = EnforcementClient::with_filter(FailingStartFirewall {
            starts: Arc::clone(&starts),
            stops: Arc::clone(&stops),
        })
        .expect("firewall worker");
        let runtime =
            AntiwireRuntime::bootstrap_with_enforcement(dir.path(), enforce).expect("bootstrap");

        let error = runtime.start().await.expect_err("start should fail");
        let message = format!("{error:#}");
        assert!(
            message.contains("injected firewall start failure"),
            "unexpected start error: {message}"
        );
        assert!(
            starts.load(Ordering::SeqCst) >= 1,
            "firewall start should have been attempted"
        );
        assert!(
            stops.load(Ordering::SeqCst) >= 1,
            "failed start must stop the firewall worker during rollback"
        );
        assert!(
            !runtime.context.dns_interceptor.is_occupied().await,
            "failed start must drop the DNS interceptor rather than leave it running"
        );
        assert!(
            !runtime
                .context
                .enforce
                .is_enforcing()
                .expect("enforcing query"),
            "rollback must leave the firewall unenforcing"
        );
    }
}
