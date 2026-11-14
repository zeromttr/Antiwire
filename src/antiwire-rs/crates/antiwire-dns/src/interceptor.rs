//! System DNS redirect lifecycle and local resolver start/stop.

use std::sync::Arc;

use antiwire_events::{Alert, AlertKind, AlertPublisher, Severity};
use antiwire_store::{DaemonSetting, Store};
use futures_util::future::BoxFuture;
use netmetrics::dns_divert::DivertEvent;
use parking_lot::Mutex;
use tracing::{error, info, warn};

use crate::block::DnsHintSink;
use crate::lifecycle::DnsDependencies;
use crate::listener::DnsListener;
use crate::network_watch::{NetworkEvent, NetworkWatcher, TransitionHook};
use crate::policy_adapter::EnginePolicy;
use crate::query_engine::{EngineServices, QueryEngine};
use crate::settings::dns_config_from_settings;
use crate::{DnsError, Result};

use antiwire_dns_redirect::{DnsRedirect, RedirectOutcome};

/// Manages the loopback DNS listener and persisted redirect state.
pub struct DnsInterceptor {
    dependencies: DnsDependencies,
    hint_sink: Option<Arc<dyn DnsHintSink>>,
    stub: Option<Arc<QueryEngine<EnginePolicy>>>,
    listener: Option<DnsListener>,
    network_watcher: Option<NetworkWatcher>,
    /// System DNS pointed at the listener. Its extender goes to the network
    /// watcher, and as it drops it restores whatever is still redirected.
    redirect: DnsRedirect,
    dns_divert: Option<netmetrics::dns_divert::DnsDivert>,
    /// Listener construction, replaceable in lifecycle fault-injection tests.
    bind_listener: fn(Arc<QueryEngine<EnginePolicy>>) -> Result<DnsListener>,
}

impl DnsInterceptor {
    pub(crate) fn new(dependencies: DnsDependencies, arm_boot_recovery: bool) -> Self {
        let redirect = DnsRedirect::new(
            Arc::clone(&dependencies.store),
            &dependencies.data_dir,
            arm_boot_recovery,
        );
        Self {
            dependencies,
            hint_sink: None,
            stub: None,
            listener: None,
            network_watcher: None,
            redirect,
            dns_divert: None,
            bind_listener: DnsListener::start_default,
        }
    }

    /// Tells the user which configured upstreams were skipped and will not be used.
    fn report_skipped_upstreams(&self, warnings: &[String]) {
        if warnings.is_empty() {
            return;
        }
        let detail = warnings.join("; ");
        warn!(%detail, "dns upstream configuration partially invalid");
        if let Some(alerts) = &self.dependencies.alerts {
            alerts.publish(Alert::new(
                AlertKind::DnsUpstreamSkipped,
                Severity::Warning,
                "DNS upstream problem",
                format!(
                    "Some configured DNS upstreams were skipped and will not be used: {detail}"
                ),
            ));
        }
    }

    #[must_use]
    pub(crate) const fn arms_boot_recovery(&self) -> bool {
        self.redirect.arms_boot_recovery()
    }

    /// Keeps the sink for the live stub and for a later start.
    pub(crate) fn set_hint_sink(&mut self, sink: Arc<dyn DnsHintSink>) {
        if let Some(stub) = self.stub.as_ref() {
            stub.set_hint_sink(Arc::clone(&sink));
        }
        self.hint_sink = Some(sink);
    }

    /// Publishes an already-built AI configuration to the running stub, if any.
    ///
    /// Coordinator publication may wait for persistence serialization, so keep
    /// that synchronous lock acquisition off the Tokio runtime workers.
    pub(crate) async fn update_ai_config(
        &self,
        store: &Arc<Store>,
        runtime: crate::ai_support::AiRuntimeConfig,
    ) -> Result<()> {
        if let Some(stub) = self.stub.as_ref() {
            let stub = Arc::clone(stub);
            let store = Arc::clone(store);
            tokio::task::spawn_blocking(move || stub.update_ai_config(&store, runtime))
                .await
                .map_err(|error| {
                    DnsError::Runtime(format!("AI settings publish task failed: {error}"))
                })?;
        }
        Ok(())
    }

    pub(crate) fn is_running(&self) -> bool {
        self.listener.as_ref().is_some_and(DnsListener::is_running)
    }

    pub(crate) async fn start(&mut self, store: &Store) -> Result<()> {
        self.redirect.stop_restoring().await;
        if self.is_running() {
            return Ok(());
        }
        if self.listener.is_some() {
            // The previous stack died. Its redirect stays in place, so adapters
            // keep pointing at loopback for the stack started below, which
            // recovers the persisted snapshot rather than capturing loopback.
            self.disable_dns_divert();
            self.shutdown_stack().await;
        }

        let settings = store.get_settings()?;
        match self.build_engine(&settings) {
            Ok(stub) => self.serve(stub).await,
            Err(error) => {
                self.recover_after_failed_start().await;
                Err(error)
            }
        }
    }

    /// Restores what a start that failed before the resolver could serve
    /// leaves behind: its own redirect, or one an earlier run recorded.
    async fn recover_after_failed_start(&mut self) {
        if let Err(error) = self.redirect.restore_if_dirty().await {
            warn!(%error, "dns redirect restore after start failure failed");
        }
    }

    /// Replaces a running resolver with one built from the current settings.
    ///
    /// The OS redirect stays in place throughout, so a configuration change
    /// never lets queries reach the network unfiltered, and adapter DNS is not
    /// rewritten twice. The new engine is built before the old stack stops: a
    /// configuration it rejects leaves the running resolver serving.
    pub(crate) async fn restart(&mut self, store: &Store) -> Result<()> {
        self.redirect.stop_restoring().await;
        if !self.is_running() {
            return self.start(store).await;
        }
        let settings = store.get_settings()?;
        let stub = self.build_engine(&settings)?;
        self.disable_dns_divert();
        self.shutdown_stack().await;
        self.serve(stub).await
    }

    /// Builds the query engine for `settings`.
    fn build_engine(&self, settings: &DaemonSetting) -> Result<Arc<QueryEngine<EnginePolicy>>> {
        let config = dns_config_from_settings(settings);
        let stub = QueryEngine::try_new(
            EnginePolicy::from_engine_lock(&self.dependencies.engine),
            &config,
            EngineServices {
                store: Some(Arc::clone(&self.dependencies.store)),
                block_sink: self.dependencies.block_sink.clone(),
                registration_dates: self.dependencies.registration_dates.clone(),
            },
        )
        .inspect_err(|error| {
            error!(
                %error,
                protocol = %settings.dns_protocol,
                provider = %settings.doh_provider,
                "dns interceptor: upstream resolver build failed"
            );
        })?;
        self.report_skipped_upstreams(stub.upstream_config_warnings());
        let stub = Arc::new(stub);
        if let Some(sink) = &self.hint_sink {
            stub.set_hint_sink(Arc::clone(sink));
        }
        Ok(stub)
    }

    /// Binds the listener for `stub`, then redirects OS DNS to it and installs
    /// the port 53 divert. Expects no stack to be running.
    async fn serve(&mut self, stub: Arc<QueryEngine<EnginePolicy>>) -> Result<()> {
        let listener = match (self.bind_listener)(Arc::clone(&stub)) {
            Ok(listener) => listener,
            Err(error) => {
                error!(%error, "dns interceptor: failed to bind listener; restoring any existing OS DNS redirect");
                self.recover_after_failed_start().await;
                return Err(error);
            }
        };

        let redirect_v6 = listener.v6_active();
        // Cached answers do not survive a change of network; drop them on one,
        // and extend the redirect to any adapter the change brought.
        let network_watcher =
            NetworkWatcher::start(Arc::clone(&stub), self.redirect_extension(redirect_v6));

        self.stub = Some(stub);
        self.listener = Some(listener);
        self.network_watcher = Some(network_watcher);

        let redirect = match self.redirect.redirect(redirect_v6).await {
            Ok(outcome) => outcome,
            Err(error) => {
                error!(%error, "dns interceptor: OS DNS not redirected");
                RedirectOutcome::Failed
            }
        };

        self.dns_divert = match netmetrics::dns_divert::start(self.divert_report()) {
            Ok(divert) => {
                info!("outbound port 53 that bypasses the stub is diverted to it");
                Some(divert)
            }
            Err(detail) => {
                warn!(%detail, "port 53 bypass divert was not installed");
                None
            }
        };

        self.report_enforcement_gaps(DnsEnforcement {
            redirect,
            ipv6: redirect_v6,
            divert: self.dns_divert.is_some(),
        });
        info!("dns interceptor started");
        Ok(())
    }

    /// Tells the user when the resolver is running but does not filter every
    /// lookup, which the resolver's own state would otherwise hide.
    fn report_enforcement_gaps(&self, enforcement: DnsEnforcement) {
        let gaps = enforcement.gaps();
        if gaps.is_empty() {
            return;
        }
        let detail = gaps.join("; ");
        warn!(%detail, "dns filtering is incomplete");
        if let Some(alerts) = &self.dependencies.alerts {
            alerts.publish(Alert::new(
                AlertKind::DnsEnforcementIncomplete,
                Severity::High,
                "DNS filtering incomplete",
                format!("The DNS resolver is running, but not every lookup is filtered: {detail}."),
            ));
        }
    }

    /// What hears the port 53 divert once it has started: every change is
    /// logged, and the user is told DNS filtering is incomplete once per episode.
    ///
    /// An episode runs from the divert's loss to the restoration that ends it.
    /// A loss repaired at the first attempt is only logged, so a tool that
    /// removes the divert's rules every few seconds raises no alert. A loss
    /// whose repair failed raises one, and further failures in the same
    /// episode raise none.
    fn divert_report(&self) -> impl Fn(DivertEvent) + Send + 'static {
        let alerts = self.dependencies.alerts.clone();
        let loss = Mutex::new(DivertLoss::default());
        move |event| loss.lock().hear(event, alerts.as_ref())
    }

    /// The watcher hook that extends the redirect to adapters a network
    /// transition brings, or makes it if a start could redirect nothing, and
    /// between transitions retries either once it is due. `None` when this
    /// process may not change system DNS.
    fn redirect_extension(&self, redirect_v6: bool) -> Option<TransitionHook> {
        let extender = self.redirect.extender(redirect_v6)?;
        Some(Arc::new(move |event| -> BoxFuture<'static, ()> {
            if event == NetworkEvent::Unchanged && !extender.is_due() {
                return Box::pin(std::future::ready(()));
            }
            Box::pin(extender.extend())
        }))
    }

    fn disable_dns_divert(&mut self) {
        self.dns_divert.take();
        netmetrics::dns_divert::clear_leftover();
    }

    pub(crate) async fn stop(&mut self) -> Result<()> {
        self.redirect.stop_restoring().await;
        // Release the port 53 divert before anything else. A later restore or
        // listener shutdown can fail; the divert must not stay installed.
        self.disable_dns_divert();
        // Join any adapter extension before restoring its snapshot. No new
        // transition may redirect adapters while shutdown is restoring them,
        // even when the restore fails and the listener must keep serving.
        self.stop_network_watcher().await;
        // Host-visible state first. Machine shutdown often kills us mid-teardown;
        // restoring adapter DNS before stopping the loopback listener means a
        // partial stop still leaves the user with working DNS after reboot.
        // Adapters that could not be restored still point at the loopback
        // listener, so it keeps serving them rather than leaving no DNS at all;
        // the caller can retry the stop. A record left behind once DNS is
        // back is restored again, harmlessly, at the next start.
        if let Err(error) = self.redirect.restore().await {
            if !error.dns_restored() {
                if !self.is_running() {
                    self.redirect.keep_restoring();
                    return Err(DnsError::Runtime(
                        "OS DNS restore was not confirmed; no resolver is running, so recovery will retry in the background"
                            .to_owned(),
                    ));
                }
                return Err(DnsError::Runtime(
                    "OS DNS restore was not confirmed; the resolver keeps serving the redirected adapters"
                        .to_owned(),
                ));
            }
        }
        self.shutdown_stack().await;
        info!("dns interceptor stopped");
        Ok(())
    }

    /// Makes the last restore attempt after a [`Self::stop`] that failed, and
    /// returns whether adapter DNS is now restored. On success it also stops
    /// the listener and engine that `stop` left serving the adapters.
    ///
    /// Without this the attempt would come from `Drop`, detached, and the
    /// caller would report the stop as failed even when that restore landed.
    /// Once the restore job has started, `Drop` does not repeat it: the job
    /// finishes and settles even if this future is cancelled.
    pub(crate) async fn finish_failed_stop(&mut self) -> bool {
        let restored = match self.redirect.finish_failed_restore().await {
            Ok(()) => true,
            Err(error) => error.dns_restored(),
        };
        if restored {
            self.shutdown_stack().await;
            info!("dns interceptor stopped after a retried restore");
        }
        restored
    }

    /// Quiesces adapter extensions, retaining the watcher across cancellation
    /// so `Drop` can still abort its task if shutdown exceeds its deadline.
    async fn stop_network_watcher(&mut self) {
        if let Some(watcher) = self.network_watcher.as_mut() {
            watcher.stop().await;
        }
        self.network_watcher = None;
    }

    /// Stops the network watcher, the listener, and the engine, in that order.
    /// Leaves the OS redirect and the port 53 divert to the caller.
    async fn shutdown_stack(&mut self) {
        self.stop_network_watcher().await;
        if let Some(mut listener) = self.listener.take() {
            if let Err(error) = listener.shutdown().await {
                warn!(%error, "dns server stopped with error");
            }
        }

        // Drain the block-signal worker explicitly, then drop the engine. The
        // drain is a blocking wait, so run it on a blocking thread and await
        // it: teardown completes in order without parking a runtime worker.
        // AI background work drains first with its own bounded timeout and
        // never holds DNS admission.
        if let Some(stub) = self.stub.take() {
            stub.shutdown_async().await;
            let teardown = move || {
                stub.shutdown_blocking();
                drop(stub);
            };
            if let Err(error) = tokio::task::spawn_blocking(teardown).await {
                warn!(%error, "dns stub teardown task failed");
            }
        }
    }

    /// Undoes a redirect left behind by an unclean shutdown.
    ///
    /// Async because the restore itself is: it sweeps every adapter and, on the
    /// fallback path, waits on a `powershell.exe` it spawned — the same call
    /// [`Self::stop`] keeps off the runtime, and this runs at daemon startup
    /// alongside every other service coming up.
    pub(crate) async fn restore_if_dirty(&mut self) -> Result<()> {
        Ok(self.redirect.restore_if_dirty().await?)
    }
}

/// Which parts of DNS enforcement a start put in place.
#[derive(Debug, Clone, Copy)]
struct DnsEnforcement {
    redirect: RedirectOutcome,
    /// Whether the redirect includes IPv6. It does not when `[::1]:53` is
    /// not served, and IPv6 DNS is then left alone.
    ipv6: bool,
    /// Port 53 traffic that bypasses adapter DNS is diverted to the listener.
    divert: bool,
}

impl DnsEnforcement {
    /// What is left unfiltered, in words for the user.
    fn gaps(self) -> Vec<&'static str> {
        let redirect = match self.redirect {
            RedirectOutcome::NotPermitted => Some(
                "Antiwire is not running as administrator, so system DNS was not redirected and \
                 other applications' lookups are not filtered",
            ),
            RedirectOutcome::Failed => Some(
                "system DNS could not be redirected to Antiwire, so other applications' lookups \
                 are not filtered",
            ),
            RedirectOutcome::Partial => Some(
                "system DNS could not be redirected to Antiwire on every network adapter, so \
                 lookups through the others are not filtered until a retry reaches them",
            ),
            RedirectOutcome::Complete => None,
        };
        let redirected = matches!(
            self.redirect,
            RedirectOutcome::Partial | RedirectOutcome::Complete
        );
        let ipv6 = (redirected && !self.ipv6)
            .then_some("IPv6 DNS was not redirected, so lookups sent over IPv6 are not filtered");
        let divert = (!self.divert)
            .then_some("applications that send DNS straight to port 53 bypass filtering");
        redirect.into_iter().chain(ipv6).chain(divert).collect()
    }
}

/// The episode in which the port 53 divert is lost, if one is under way.
#[derive(Debug, Default)]
struct DivertLoss {
    /// Why the divert stopped working.
    why: Option<String>,
    /// Whether the user has been told about this episode.
    alerted: bool,
}

impl DivertLoss {
    fn hear(&mut self, event: DivertEvent, alerts: Option<&AlertPublisher>) {
        match event {
            DivertEvent::Lost(why) => {
                warn!(%why, "port 53 bypass divert stopped working; putting it back");
                self.why = Some(why);
            }
            DivertEvent::Restored => {
                info!("port 53 bypass divert works again");
                *self = Self::default();
            }
            DivertEvent::RestoreFailed(error) => {
                warn!(%error, "port 53 bypass divert could not be put back; retrying");
                if std::mem::replace(&mut self.alerted, true) {
                    return;
                }
                let why = self.why.as_deref().unwrap_or("reason unknown");
                if let Some(alerts) = alerts {
                    alerts.publish(Alert::new(
                        AlertKind::DnsEnforcementIncomplete,
                        Severity::High,
                        "DNS filtering incomplete",
                        format!(
                            "The rules that send DNS which bypasses the resolver back to it \
                             stopped working ({why}), and putting them back failed ({error}). \
                             Until Antiwire restores them, which it keeps trying, applications \
                             that send DNS straight to port 53, or over TLS on port 853, bypass \
                             filtering."
                        ),
                    ));
                }
            }
        }
    }
}

/// Releases `value` without running its destructor on a runtime worker.
///
/// For a destructor that only frees memory this would be pointless; it exists
/// for the ones that block. Off a runtime there is nothing to protect, so the
/// drop happens in place.
fn release_off_runtime<T: Send + 'static>(value: T) {
    match tokio::runtime::Handle::try_current() {
        Ok(handle) => {
            // Detached: `Drop` cannot await, and the join has no result anyone
            // is waiting on.
            handle.spawn_blocking(move || drop(value));
        }
        Err(_) => drop(value),
    }
}

impl Drop for DnsInterceptor {
    fn drop(&mut self) {
        self.disable_dns_divert();
        // `self.redirect` restores whatever is still redirected as it drops,
        // after this, off the runtime: see `DnsRedirect`.

        // `DnsListener::drop` cancels the hickory server and aborts its task,
        // and `NetworkWatcher::drop` does the same for the watcher.
        self.network_watcher = None;
        self.listener = None;

        // Dropping the last `QueryEngine` reference joins the block-signal
        // worker thread, which may be mid-event. `stop` already moves that join
        // off the runtime, but this destructor also runs on paths that never
        // reach `stop`: a cancelled gRPC handler dropping the interceptor
        // mid-`stop`, or a shutdown that overran its deadline. Both cancel on a
        // runtime worker, so the join must not happen inline.
        if let Some(stub) = self.stub.take() {
            release_off_runtime(stub);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::mpsc::{self, Sender};
    use std::sync::Arc;
    use std::thread::ThreadId;
    use std::time::Duration;

    use antiwire_policy::RuleEngine;
    use antiwire_store::Store;
    use parking_lot::RwLock;

    use antiwire_dns_redirect::{AppliedRedirect, RedirectBackend};

    use super::{release_off_runtime, DnsEnforcement, DnsInterceptor, RedirectOutcome};
    use crate::lifecycle::DnsDependencies;
    use crate::listener::DnsListener;
    use crate::policy_adapter::EnginePolicy;
    use crate::query_engine::QueryEngine;
    use crate::settings::DnsConfig;
    use antiwire_events::{
        Alert, AlertKind, AlertPublisher, Notification, NotificationHub, Severity,
    };
    use netmetrics::dns_divert::DivertEvent;

    fn dependencies(store: &Arc<Store>, alerts: Option<AlertPublisher>) -> DnsDependencies {
        DnsDependencies {
            engine: Arc::new(RwLock::new(RuleEngine::new())),
            store: Arc::clone(store),
            data_dir: store.path().parent().expect("data dir").to_path_buf(),
            block_sink: None,
            alerts,
            registration_dates: None,
        }
    }

    /// A backend that changes nothing on this host, and restores through
    /// `restore`.
    fn restoring(restore: fn(&str) -> bool) -> RedirectBackend {
        RedirectBackend {
            restore,
            ..RedirectBackend::INERT
        }
    }

    /// An interceptor whose redirect cannot change this host's DNS, even when
    /// the tests run elevated.
    fn interceptor(store: &Arc<Store>) -> DnsInterceptor {
        let mut interceptor = DnsInterceptor::new(dependencies(store, None), false);
        interceptor.redirect.set_backend(RedirectBackend::INERT);
        interceptor
    }

    /// Reports the thread its destructor ran on.
    struct WhereDropped {
        tx: Sender<ThreadId>,
    }

    impl Drop for WhereDropped {
        fn drop(&mut self) {
            let _ = self.tx.send(std::thread::current().id());
        }
    }

    /// Pinned to a single-threaded runtime, where "another thread" and "not the
    /// runtime" are the same statement.
    #[tokio::test(flavor = "current_thread")]
    async fn a_released_value_drops_off_the_runtime_thread() {
        let runtime_thread = std::thread::current().id();
        let (tx, rx) = mpsc::channel();

        release_off_runtime(WhereDropped { tx });

        let dropped_on = rx
            .recv_timeout(Duration::from_secs(10))
            .expect("the destructor ran");
        assert_ne!(dropped_on, runtime_thread);
    }

    #[test]
    fn released_outside_a_runtime_it_drops_in_place() {
        let this_thread = std::thread::current().id();
        let (tx, rx) = mpsc::channel();

        release_off_runtime(WhereDropped { tx });

        let dropped_on = rx.try_recv().expect("the destructor already ran");
        assert_eq!(dropped_on, this_thread);
    }

    #[tokio::test]
    async fn failed_recovery_start_attempts_to_restore_saved_dns_state() {
        let (_dir, store) = crate::test_support::temp_store();
        let saved_dns = "not valid saved DNS state";
        store.set_dns_redirect(saved_dns).expect("dirty record");
        let mut settings = store.get_settings().expect("settings");
        settings.dns_protocol = "doh".to_owned();
        settings.doh_provider = "custom".to_owned();
        settings.doh_custom_url = "not a URL".to_owned();
        store.update_settings(&settings).expect("dirty settings");

        let mut interceptor = interceptor(&store);
        interceptor.redirect.set_backend(restoring(|_| false));

        assert!(interceptor.start(store.as_ref()).await.is_err());
        assert_eq!(
            interceptor.redirect.snapshot().as_deref(),
            Some(saved_dns),
            "recovery must load the saved adapter state before returning the start error"
        );
        assert!(
            interceptor.redirect.is_applied(),
            "a failed restore must remain armed for Drop and the next launch"
        );
        assert_eq!(
            store
                .get_dns_redirect()
                .expect("record after failed restore")
                .as_deref(),
            Some(saved_dns),
            "a failed restore must keep the record for the next attempt"
        );
    }

    /// An interceptor serving on an ephemeral loopback port, with no redirect.
    fn running_interceptor(store: &Arc<Store>) -> DnsInterceptor {
        let dependencies = dependencies(store, None);
        let stub = Arc::new(QueryEngine::new(
            EnginePolicy::from_engine_lock(&dependencies.engine),
            DnsConfig::default(),
        ));
        let listener =
            DnsListener::start_on(Arc::clone(&stub), "127.0.0.1:0".parse().expect("addr"))
                .expect("listener");
        let mut interceptor = DnsInterceptor::new(dependencies, false);
        interceptor.redirect.set_backend(RedirectBackend::INERT);
        interceptor.stub = Some(stub);
        interceptor.listener = Some(listener);
        interceptor
    }

    #[tokio::test]
    async fn shutdown_joins_the_watcher_and_settles_a_single_restore() {
        use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
        static WATCHER_STOPPED: AtomicBool = AtomicBool::new(false);
        static RESTORES: AtomicUsize = AtomicUsize::new(0);
        fn restore(snapshot: &str) -> bool {
            assert!(WATCHER_STOPPED.load(Ordering::SeqCst));
            assert_eq!(snapshot, "adapter snapshot");
            RESTORES.fetch_add(1, Ordering::SeqCst);
            true
        }

        let (dir, store) = crate::test_support::temp_store();
        let mut interceptor = running_interceptor(&store);
        interceptor.redirect.set_backend(RedirectBackend {
            can_redirect: || true,
            plan: |_, _| Some("adapter snapshot".to_owned()),
            apply: |_, plan| Some(AppliedRedirect::complete(plan)),
            restore,
            ..RedirectBackend::INERT
        });
        interceptor
            .redirect
            .redirect(false)
            .await
            .expect("redirect");
        let journal = dir.path().join("dns-redirect-state.json");
        assert!(journal.exists(), "the recovery journal is armed");
        interceptor.network_watcher = Some(
            crate::network_watch::NetworkWatcher::with_pending_transition(async {
                WATCHER_STOPPED.store(true, Ordering::SeqCst);
            }),
        );
        let shared = Arc::new(crate::DnsInterceptorSlot::holding(interceptor));

        crate::shutdown_dns_interceptor(&shared)
            .await
            .expect("stop");
        crate::shutdown_dns_interceptor(&shared)
            .await
            .expect("already stopped");

        assert_eq!(
            RESTORES.load(Ordering::SeqCst),
            1,
            "stop and Drop must not repeat the restore"
        );
        assert_eq!(store.get_dns_redirect().expect("record"), None);
        assert!(!journal.exists(), "the recovery journal is cleared");
    }

    /// The regression this guards: shutdown cancels `stop` at its deadline,
    /// and `Drop` then restored inline on the runtime worker, holding the
    /// deadline up for as long as the restore took, while the cancelled
    /// restore kept running beside it.
    #[tokio::test(flavor = "current_thread")]
    async fn a_cancelled_stop_returns_on_time_and_its_restore_settles_once() {
        static RESTORES: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        fn slow_restore(_: &str) -> bool {
            RESTORES.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            std::thread::sleep(Duration::from_millis(500));
            true
        }

        let (_dir, store) = crate::test_support::temp_store();
        store
            .set_dns_redirect("snapshot")
            .expect("persisted redirect");
        let mut interceptor = running_interceptor(&store);
        interceptor
            .redirect
            .assume_redirected("snapshot".to_owned());
        interceptor.redirect.set_backend(restoring(slow_restore));

        let started = std::time::Instant::now();
        let stop = async move {
            let mut dns = interceptor;
            dns.stop().await
        };
        assert!(
            tokio::time::timeout(Duration::from_millis(50), stop)
                .await
                .is_err(),
            "the restore outlasts the deadline"
        );
        assert!(
            started.elapsed() < Duration::from_millis(400),
            "dropping the cancelled stop must not wait for a restore: {:?}",
            started.elapsed()
        );

        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while store.get_dns_redirect().expect("record").is_some() {
            assert!(
                std::time::Instant::now() < deadline,
                "the cancelled restore never settled"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        // Long enough for a second restore, had `Drop` started one, to be counted.
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!(RESTORES.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn a_rejected_configuration_leaves_the_running_resolver_and_redirect() {
        let (_dir, store) = crate::test_support::temp_store();
        let mut settings = store.get_settings().expect("settings");
        settings.dns_protocol = "doh".to_owned();
        settings.doh_provider = "custom".to_owned();
        settings.doh_custom_url = "not a URL".to_owned();
        store.update_settings(&settings).expect("settings");
        let mut interceptor = running_interceptor(&store);
        interceptor.redirect.assume_redirected("adapter snapshot");
        interceptor
            .redirect
            .set_backend(restoring(|_| panic!("a restart must not restore")));

        assert!(interceptor.restart(store.as_ref()).await.is_err());
        assert!(interceptor.is_running());
        assert!(interceptor.redirect.is_applied());

        interceptor.redirect.set_backend(restoring(|_| true));
        interceptor.stop().await.expect("stop");
    }

    #[tokio::test]
    async fn a_failed_restore_keeps_the_listener_serving_redirected_adapters() {
        use std::sync::atomic::{AtomicBool, Ordering};
        static WATCHER_STOPPED: AtomicBool = AtomicBool::new(false);

        let (_dir, store) = crate::test_support::temp_store();
        let mut interceptor = running_interceptor(&store);
        interceptor
            .redirect
            .assume_redirected("adapter snapshot".to_owned());
        interceptor.network_watcher = Some(
            crate::network_watch::NetworkWatcher::with_pending_transition(async {
                WATCHER_STOPPED.store(true, Ordering::SeqCst);
            }),
        );
        interceptor.redirect.set_backend(restoring(|_| {
            assert!(WATCHER_STOPPED.load(Ordering::SeqCst));
            false
        }));

        assert!(interceptor.stop().await.is_err());
        assert!(
            interceptor.network_watcher.is_none(),
            "failed restore must not allow further extensions"
        );
        assert!(
            interceptor.is_running(),
            "adapters still point at loopback, so the listener must keep serving"
        );
        assert!(interceptor.redirect.is_applied());

        interceptor.redirect.set_backend(restoring(|_| true));
        interceptor.stop().await.expect("stop");
        assert!(!interceptor.is_running());
        assert!(!interceptor.redirect.is_applied());
    }

    #[tokio::test]
    async fn a_failed_stop_retries_the_restore_once_and_awaits_it() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        static RESTORES: AtomicUsize = AtomicUsize::new(0);
        fn fails_once(_: &str) -> bool {
            RESTORES.fetch_add(1, Ordering::SeqCst) > 0
        }

        let (_dir, store) = crate::test_support::temp_store();
        store
            .set_dns_redirect("adapter snapshot")
            .expect("persisted redirect");
        let mut interceptor = running_interceptor(&store);
        interceptor.redirect.assume_redirected("adapter snapshot");
        interceptor.redirect.set_backend(restoring(fails_once));
        let shared = Arc::new(crate::DnsInterceptorSlot::holding(interceptor));

        crate::shutdown_dns_interceptor(&shared)
            .await
            .expect("the retried restore landed, so the stop succeeded");
        assert!(store.get_dns_redirect().expect("record").is_none());
        // Long enough for a detached restore from `Drop`, had one started, to be counted.
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!(RESTORES.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn a_stop_whose_retried_restore_fails_too_leaves_drop_nothing_to_repeat() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        static RESTORES: AtomicUsize = AtomicUsize::new(0);
        fn always_fails(_: &str) -> bool {
            RESTORES.fetch_add(1, Ordering::SeqCst);
            false
        }

        let (_dir, store) = crate::test_support::temp_store();
        store
            .set_dns_redirect("adapter snapshot")
            .expect("persisted redirect");
        let mut interceptor = running_interceptor(&store);
        interceptor.redirect.assume_redirected("adapter snapshot");
        interceptor.redirect.set_backend(restoring(always_fails));
        let shared = Arc::new(crate::DnsInterceptorSlot::holding(interceptor));

        assert!(crate::shutdown_dns_interceptor(&shared).await.is_err());
        assert!(
            store.get_dns_redirect().expect("record").is_some(),
            "recovery state is kept"
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!(RESTORES.load(Ordering::SeqCst), 2);
    }

    /// The regression this guards: a shutdown that timed out waiting behind
    /// a settings change was dropped before it took the interceptor, so
    /// nothing stopped the resolver that change left running or restored the
    /// adapters it had redirected. The stop is no longer the caller's to
    /// finish: it runs once the change lets go of the slot.
    #[tokio::test]
    async fn a_shutdown_that_gives_up_waiting_still_stops_the_resolver() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        static RESTORES: AtomicUsize = AtomicUsize::new(0);
        fn restore(_: &str) -> bool {
            RESTORES.fetch_add(1, Ordering::SeqCst);
            true
        }

        let (_dir, store) = crate::test_support::temp_store();
        store
            .set_dns_redirect("adapter snapshot")
            .expect("persisted redirect");
        let mut interceptor = running_interceptor(&store);
        interceptor
            .redirect
            .assume_redirected("adapter snapshot".to_owned());
        interceptor.redirect.set_backend(restoring(restore));
        let shared = Arc::new(crate::DnsInterceptorSlot::holding(interceptor));
        let change_in_progress = shared.hold().await;

        assert!(
            tokio::time::timeout(
                Duration::from_millis(50),
                crate::shutdown_dns_interceptor(&shared)
            )
            .await
            .is_err(),
            "the shutdown waits behind the change"
        );
        assert!(shared.is_closed());
        assert_eq!(RESTORES.load(Ordering::SeqCst), 0);
        drop(change_in_progress);

        let stopped = tokio::time::timeout(Duration::from_secs(10), async {
            while shared.is_occupied().await || store.get_dns_redirect().expect("record").is_some()
            {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await;
        assert!(
            stopped.is_ok(),
            "the abandoned shutdown never stopped the resolver"
        );
        assert_eq!(RESTORES.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn failed_restart_bind_retries_restore_without_another_settings_change() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        static RESTORES: AtomicUsize = AtomicUsize::new(0);
        fn fails_once(_: &str) -> bool {
            RESTORES.fetch_add(1, Ordering::SeqCst) > 0
        }

        let (_dir, store) = crate::test_support::temp_store();
        store
            .set_dns_redirect("adapter snapshot")
            .expect("dirty state");
        let mut interceptor = running_interceptor(&store);
        interceptor
            .redirect
            .assume_redirected("adapter snapshot".to_owned());
        interceptor.redirect.set_backend(restoring(fails_once));
        interceptor.bind_listener = |stub| {
            let occupied = std::net::UdpSocket::bind("127.0.0.1:0").expect("occupy UDP port");
            DnsListener::start_on(stub, occupied.local_addr().expect("occupied address"))
        };

        assert!(matches!(
            interceptor.restart(&store).await,
            Err(crate::DnsError::Bind(_))
        ));
        assert!(
            !interceptor.is_running(),
            "the old stack has already stopped"
        );
        assert!(
            interceptor.redirect.is_applied(),
            "the first restore failed"
        );
        assert!(store.get_dns_redirect().expect("record").is_some());

        let recovered = tokio::time::timeout(Duration::from_secs(3), async {
            while interceptor.redirect.is_applied()
                || store.get_dns_redirect().expect("record").is_some()
            {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .is_ok();
        let persisted = store.get_dns_redirect().expect("record after recovery");
        // Clean up even when running this regression against the old behavior.
        interceptor.redirect.set_backend(restoring(|_| true));
        interceptor.stop().await.expect("cleanup");
        assert!(recovered, "restore must retry while no listener is running");
        assert_eq!(persisted, None);
        assert_eq!(RESTORES.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn restore_if_dirty_reports_an_unconfirmed_restore() {
        let (_dir, store) = crate::test_support::temp_store();
        store
            .set_dns_redirect("adapter snapshot")
            .expect("dirty state");
        let mut interceptor = interceptor(&store);
        interceptor.redirect.set_backend(restoring(|_| false));

        let result = interceptor.restore_if_dirty().await;
        assert!(interceptor.redirect.is_applied());
        assert_eq!(
            interceptor.redirect.snapshot().as_deref(),
            Some("adapter snapshot")
        );
        assert!(store.get_dns_redirect().expect("record").is_some());
        interceptor.redirect.set_backend(restoring(|_| true));
        interceptor.stop().await.expect("cleanup");
        assert!(result.is_err(), "an unconfirmed restore is not success");
    }

    #[test]
    fn each_missing_enforcement_layer_is_named() {
        let full = DnsEnforcement {
            redirect: RedirectOutcome::Complete,
            ipv6: true,
            divert: true,
        };
        assert_eq!(full.gaps(), [] as [&str; 0]);
        let ipv4_only = DnsEnforcement {
            ipv6: false,
            ..full
        };
        assert!(ipv4_only.gaps()[0].contains("IPv6"));
        let failed = DnsEnforcement {
            redirect: RedirectOutcome::Failed,
            ipv6: false,
            ..full
        };
        assert_eq!(
            failed.gaps().len(),
            1,
            "nothing was redirected over IPv4 either"
        );
        assert!(failed.gaps()[0].contains("could not be redirected"));
        let partial = DnsEnforcement {
            redirect: RedirectOutcome::Partial,
            ipv6: false,
            ..full
        };
        let gaps = partial.gaps();
        assert_eq!(gaps.len(), 2, "{gaps:?}");
        assert!(gaps[0].contains("every network adapter"));
        assert!(gaps[1].contains("IPv6"));
        let unelevated = DnsEnforcement {
            redirect: RedirectOutcome::NotPermitted,
            ipv6: true,
            divert: false,
        };
        let gaps = unelevated.gaps();
        assert_eq!(gaps.len(), 2, "{gaps:?}");
        assert!(gaps[0].contains("administrator"));
        assert!(gaps[1].contains("port 53"));
    }

    #[tokio::test]
    async fn incomplete_enforcement_reaches_the_user_as_an_alert() {
        let (_dir, store) = crate::test_support::temp_store();
        let alerts = AlertPublisher::unsaved(NotificationHub::with_capacity(4), None);
        let mut subscription = alerts.subscribe();
        let interceptor = DnsInterceptor::new(dependencies(&store, Some(alerts)), false);
        let full = DnsEnforcement {
            redirect: RedirectOutcome::Complete,
            ipv6: true,
            divert: true,
        };

        interceptor.report_enforcement_gaps(full);
        interceptor.report_enforcement_gaps(DnsEnforcement {
            divert: false,
            ..full
        });

        let alert = subscription.recv().await.expect("alert");
        assert_eq!(alert.kind, AlertKind::DnsEnforcementIncomplete);
        assert!(alert.message.contains("port 53"), "{}", alert.message);
    }

    /// Feeds `events` to the divert report of an interceptor, and returns the
    /// alerts the user was shown.
    async fn alerts_for_divert_events(events: Vec<DivertEvent>) -> Vec<Notification> {
        let (_dir, store) = crate::test_support::temp_store();
        let alerts = AlertPublisher::unsaved(NotificationHub::with_capacity(64), None);
        let mut subscription = alerts.subscribe();
        let interceptor = DnsInterceptor::new(dependencies(&store, Some(alerts.clone())), false);
        let report = interceptor.divert_report();
        for event in events {
            report(event);
        }
        // Delivery is in order, so every alert the events raised comes before this one.
        alerts.publish(Alert::new(
            AlertKind::AlertsDropped,
            Severity::Info,
            "end",
            "end",
        ));
        let mut shown = Vec::new();
        while let Some(alert) = subscription.recv().await {
            if alert.kind == AlertKind::AlertsDropped {
                return shown;
            }
            shown.push(alert);
        }
        panic!("the alert hub closed");
    }

    fn lost() -> DivertEvent {
        DivertEvent::Lost("the nftables table is gone".to_owned())
    }

    fn failed() -> DivertEvent {
        DivertEvent::RestoreFailed("nft refused the ruleset".to_owned())
    }

    #[tokio::test]
    async fn an_unrepaired_divert_loss_alerts_once_per_episode() {
        let shown = alerts_for_divert_events(vec![
            lost(),
            failed(),
            failed(),
            failed(),
            DivertEvent::Restored,
            lost(),
            failed(),
            failed(),
        ])
        .await;

        assert_eq!(shown.len(), 2, "{shown:?}");
        for alert in &shown {
            assert_eq!(alert.kind, AlertKind::DnsEnforcementIncomplete);
            assert!(
                alert.message.contains("the nftables table is gone")
                    && alert.message.contains("nft refused the ruleset")
                    && alert.message.contains("port 53"),
                "{}",
                alert.message
            );
        }
    }

    /// A tool that removes the divert's rules every few seconds, each time
    /// put back at once, must not raise an alert per removal.
    #[tokio::test]
    async fn a_repaired_divert_loss_raises_no_alert() {
        let flapping = std::iter::repeat_with(|| [lost(), DivertEvent::Restored])
            .take(20)
            .flatten()
            .collect();

        assert_eq!(alerts_for_divert_events(flapping).await, []);
    }

    #[tokio::test]
    async fn skipped_upstreams_reach_the_user_as_an_alert() {
        let (_dir, store) = crate::test_support::temp_store();
        let alerts = AlertPublisher::unsaved(NotificationHub::with_capacity(4), None);
        let mut subscription = alerts.subscribe();
        let interceptor = DnsInterceptor::new(dependencies(&store, Some(alerts)), false);

        interceptor.report_skipped_upstreams(&["bad.example: not a URL".to_owned()]);
        interceptor.report_skipped_upstreams(&[]);

        let alert = subscription.recv().await.expect("alert");
        assert_eq!(alert.kind, AlertKind::DnsUpstreamSkipped);
        assert!(alert.message.contains("bad.example"));
    }
}
