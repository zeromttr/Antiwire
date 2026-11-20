//! Live DNS interceptor start/stop when daemon settings change over gRPC.

use std::future::Future;
use std::path::PathBuf;
use std::sync::Arc;

use antiwire_events::{Alert, AlertKind, AlertPublisher, Severity};
use antiwire_policy::RuleEngine;
use antiwire_store::{DaemonSetting, Store};
use antiwire_tuning::{DNS_START_RETRY_INITIAL_DELAY, DNS_START_RETRY_MAX_DELAY};
use parking_lot::RwLock;
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use crate::block::{DnsBlockSink, DnsHintSink};
use crate::interceptor::DnsInterceptor;
use crate::new_domain::RegistrationDates;
use crate::settings::dns_config_changed;
use crate::Result;

/// Where the daemon keeps its DNS interceptor.
///
/// Shutdown closes the slot for good: from then on nothing can put a new
/// interceptor in it, and the shutdown takes out the one there to stop it.
/// Without that, a settings change still running when shutdown begins would
/// find the slot empty, start a new resolver, and redirect adapter DNS again
/// after shutdown restored it.
///
/// Closing does not wait for the lock. A settings change can hold it for as
/// long as a resolver restart takes, longer than shutdown waits, and a slot
/// closed only once the lock was taken would stay open when shutdown gave up
/// first.
#[derive(Default)]
pub struct DnsInterceptorSlot {
    interceptor: Mutex<Option<DnsInterceptor>>,
    /// Cancelled when [`shutdown_dns_interceptor`] is called, and never
    /// reset. Whoever takes the lock checks it under the lock.
    closed: CancellationToken,
}

impl DnsInterceptorSlot {
    /// An empty, open slot.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// An open slot holding `interceptor`.
    #[cfg(test)]
    pub(crate) fn holding(interceptor: DnsInterceptor) -> Self {
        Self {
            interceptor: Mutex::new(Some(interceptor)),
            closed: CancellationToken::new(),
        }
    }

    /// Takes the lock a settings change holds while it applies, until the
    /// returned guard is dropped.
    #[cfg(test)]
    pub(crate) async fn hold(&self) -> impl Sized + '_ {
        self.interceptor.lock().await
    }

    /// Whether the slot holds an interceptor.
    pub async fn is_occupied(&self) -> bool {
        self.interceptor.lock().await.is_some()
    }

    /// Whether shutdown has closed the slot.
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.closed.is_cancelled()
    }
}

/// What the DNS interceptor needs from the rest of the daemon.
#[derive(Clone)]
pub struct DnsDependencies {
    /// Policy the resolver answers from.
    pub engine: Arc<RwLock<RuleEngine>>,
    /// Settings, the system DNS redirect record, and AI decisions.
    pub store: Arc<Store>,
    /// The daemon's data directory, where the redirect journal is kept and
    /// recovery of a dead daemon looks for it.
    pub data_dir: PathBuf,
    /// Receives every blocked query.
    pub block_sink: Option<Arc<dyn DnsBlockSink>>,
    /// Receives problems the user should see, such as skipped upstreams.
    pub alerts: Option<AlertPublisher>,
    /// Registration dates for blocking newly registered domains. Without
    /// them that setting has no effect.
    pub registration_dates: Option<RegistrationDates>,
}

/// Applies DNS resolver enable/disable and upstream config changes at runtime.
///
/// # Errors
///
/// Returns [`crate::DnsError`] when the resolver fails to build its upstream
/// handle, bind its listeners, or stop the previous instance, and
/// [`crate::DnsError::ShutDown`] once shutdown has closed the slot: the
/// change stays saved, but no resolver is started again.
pub async fn apply_dns_settings_change(
    interceptor: &DnsInterceptorSlot,
    dependencies: &DnsDependencies,
    previous: &DaemonSetting,
    updated: &DaemonSetting,
) -> Result<()> {
    let store = &dependencies.store;
    let enabled_changed = previous.dns_resolver_enabled != updated.dns_resolver_enabled;
    // The port 53 divert is installed or left out as the resolver starts, so a change to
    // whether packet rules are used restarts it like a change to its configuration.
    let stub_changed = dns_config_changed(previous, updated)
        || previous.uses_packet_rules() != updated.uses_packet_rules();
    let ai_changed = crate::ai_support::ai_config_changed(previous, updated);

    if !enabled_changed && !stub_changed && !ai_changed {
        return Ok(());
    }

    // Built off the query path: store reads and HTTP-client construction are
    // synchronous. The policy is what saved verdicts are recomputed against,
    // including when the classifier itself cannot be built.
    let ai_runtime = if ai_changed {
        Some(load_ai_runtime(updated).await)
    } else {
        None
    };

    // AI-only changes apply live without restarting the stub: publish the new
    // policy, endpoint, and credentials to the running coordinator. Mode,
    // threshold, and action changes take effect immediately via the
    // configuration generation; stale jobs cannot enforce old settings.
    if !enabled_changed && !stub_changed {
        let Some(runtime) = ai_runtime else {
            return Ok(());
        };
        let started = std::time::Instant::now();
        if cfg!(debug_assertions) {
            info!(
                enabled = updated.ai_enabled,
                mode = %updated.ai_decision_mode,
                "applying AI settings to the running resolver"
            );
        }
        let slot = interceptor.interceptor.lock().await;
        if let Some(dns) = slot.as_ref() {
            dns.update_ai_config(store, runtime.clone()).await?;
        }
        let resolver_running = slot.is_some();
        drop(slot);
        if cfg!(debug_assertions) {
            info!(
                elapsed_ms = started.elapsed().as_millis(),
                resolver_running, "AI settings applied"
            );
        }
        refresh_saved_verdicts(store, &runtime.policy).await;
        return Ok(());
    }

    let mut slot = interceptor.interceptor.lock().await;
    // A shutdown that began while this change was running takes the resolver
    // it leaves, once the lock is free.
    if interceptor.is_closed() {
        return Err(crate::DnsError::ShutDown);
    }
    let arm_boot_recovery = slot
        .as_ref()
        .is_some_and(DnsInterceptor::arms_boot_recovery);

    if updated.dns_resolver_enabled {
        let dns = slot
            .get_or_insert_with(|| DnsInterceptor::new(dependencies.clone(), arm_boot_recovery));
        dns.restart().await?;
    } else if let Some(dns) = slot.as_mut() {
        dns.stop().await?;
    }
    drop(slot);

    if let Some(runtime) = ai_runtime {
        refresh_saved_verdicts(store, &runtime.policy).await;
    }

    Ok(())
}

/// Builds the AI runtime away from Tokio workers.
///
/// A classifier that cannot be constructed still yields the saved policy, so
/// verdicts can be recomputed and already-classified domains stay enforceable.
async fn load_ai_runtime(settings: &DaemonSetting) -> crate::ai_support::AiRuntimeConfig {
    let owned = settings.clone();
    let fallback = settings.clone();
    match tokio::task::spawn_blocking(move || crate::ai_support::build_runtime_config(&owned)).await
    {
        Ok(Ok(runtime)) => runtime,
        Ok(Err(error)) => {
            warn!(error = %error, "AI classifier configuration unavailable; saved decisions remain active");
            crate::ai_support::unavailable_runtime_config(&fallback)
        }
        Err(error) => {
            warn!(error = %error, "AI settings build task failed; saved decisions remain active");
            crate::ai_support::unavailable_runtime_config(&fallback)
        }
    }
}

/// Persists verdicts for the new thresholds and, on Windows, drops cached
/// sinkhole answers once any verdict actually changed.
async fn refresh_saved_verdicts(store: &Arc<Store>, policy: &crate::ai::AiPolicySnapshot) {
    let store = Arc::clone(store);
    let policy = *policy;
    let changed = match tokio::task::spawn_blocking(move || {
        crate::ai::decision::recompute_saved_verdicts(&store, &policy)
    })
    .await
    {
        Ok(Ok(changed)) => changed,
        Ok(Err(error)) => {
            warn!(error = %error, "could not recompute saved AI verdicts");
            return;
        }
        Err(error) => {
            warn!(error = %error, "AI verdict recompute task failed");
            return;
        }
    };
    if changed == 0 {
        return;
    }
    info!(
        changed,
        "saved AI verdicts updated to match the current thresholds"
    );
    crate::forget_cached_answers();
}

/// Initializes or restores DNS state at daemon startup (no stop when already disabled).
///
/// A resolver that is enabled but fails to start does not fail the daemon,
/// which still enforces firewall rules and serves the client. It is not left
/// silent either: the failure is raised as an alert, and the start is retried
/// with backoff until it succeeds, the resolver is disabled, or `shutdown`
/// is cancelled.
///
/// # Errors
///
/// Currently always returns `Ok(())`; failures are reported as described.
pub async fn bootstrap_dns_interceptor(
    interceptor: &Arc<DnsInterceptorSlot>,
    dependencies: DnsDependencies,
    settings: &DaemonSetting,
    arm_boot_recovery: bool,
    shutdown: CancellationToken,
) -> Result<()> {
    let _ = tokio::task::spawn_blocking(netmetrics::dns_divert::clear_leftover).await;
    let store = Arc::clone(&dependencies.store);
    let alerts = dependencies.alerts.clone();
    let mut slot = interceptor.interceptor.lock().await;
    if interceptor.is_closed() {
        warn!("dns interceptor not started: shutdown has already begun");
        return Ok(());
    }
    let dns = slot.get_or_insert_with(|| DnsInterceptor::new(dependencies, arm_boot_recovery));

    if settings.dns_resolver_enabled {
        if let Err(error) = dns.start().await {
            warn!(error = %error, "dns interceptor start failed; retrying in the background");
            report_start_failure(alerts.as_ref(), &error);
            // Its first attempt waits for this lock, so holding it here is fine.
            retry_failed_start(Arc::clone(interceptor), store, shutdown);
        }
    } else {
        // Heal a redirect left by an unclean shutdown (common for interactive
        // debug daemons that do not auto-start after reboot). Keep the slot so
        // a later enable via gRPC inherits `arm_boot_recovery`.
        if let Err(error) = dns.restore_if_dirty().await {
            warn!(error = %error, "dns redirect restore failed");
        }
    }

    Ok(())
}

/// Attaches process-scoped name hints to the interceptor, including one started earlier.
pub async fn attach_dns_hint_sink(interceptor: &DnsInterceptorSlot, sink: Arc<dyn DnsHintSink>) {
    if let Some(dns) = interceptor.interceptor.lock().await.as_mut() {
        dns.set_hint_sink(sink);
    }
}

/// Tells the user DNS filtering is off although the resolver is enabled.
fn report_start_failure(alerts: Option<&AlertPublisher>, error: &crate::DnsError) {
    if let Some(alerts) = alerts {
        alerts.publish(Alert::new(
            AlertKind::DnsEnforcementIncomplete,
            Severity::High,
            "DNS filtering is not running",
            format!(
                "The DNS resolver is enabled but could not start, so lookups are not \
                 filtered. Antiwire keeps retrying. Cause: {error}"
            ),
        ));
    }
}

/// Retries a resolver start that failed at boot, with doubling delays.
///
/// Stops once a start succeeds, the resolver is already running (a settings
/// change started it), it was disabled, the interceptor was shut down, or
/// `shutdown` is cancelled.
fn retry_failed_start(
    interceptor: Arc<DnsInterceptorSlot>,
    store: Arc<Store>,
    shutdown: CancellationToken,
) {
    tokio::spawn(async move {
        let mut delay = DNS_START_RETRY_INITIAL_DELAY;
        loop {
            tokio::select! {
                () = shutdown.cancelled() => return,
                () = tokio::time::sleep(delay) => {}
            }
            let mut slot = tokio::select! {
                () = shutdown.cancelled() => return,
                slot = interceptor.interceptor.lock() => slot,
            };
            if interceptor.is_closed() {
                return;
            }
            let Some(dns) = slot.as_mut() else {
                return;
            };
            if dns.is_running() {
                return;
            }
            match store.get_settings() {
                Ok(settings) if !settings.dns_resolver_enabled => return,
                Ok(_) => {}
                Err(error) => warn!(%error, "could not read settings before retrying the resolver"),
            }
            match dns.start().await {
                Ok(()) => {
                    info!("dns interceptor started after an earlier failure");
                    return;
                }
                Err(error) => {
                    warn!(%error, retry_in = ?delay, "dns interceptor start retry failed");
                }
            }
            drop(slot);
            delay = delay.saturating_mul(2).min(DNS_START_RETRY_MAX_DELAY);
        }
    });
}

/// Closes the slot, so that no later settings change can start a resolver
/// again, and stops the interceptor, restoring OS DNS if needed.
///
/// The slot is closed by the time this returns, and the stop runs as a task
/// of its own. Neither depends on the returned future, which only reports
/// the outcome: a caller that stops waiting for it, as a shutdown deadline
/// does, has still closed the slot, and the stop still runs. A settings
/// change already under way finishes first, and the stop then takes the
/// resolver it left.
///
/// Must be called from within a Tokio runtime.
///
/// # Errors
///
/// Returns the stop failure, typically an adapter DNS restore that was not
/// confirmed, when one more restore attempt also fails. The persisted
/// redirect state is kept for recovery then.
pub fn shutdown_dns_interceptor(
    interceptor: &Arc<DnsInterceptorSlot>,
) -> impl Future<Output = Result<()>> + Send + 'static {
    interceptor.closed.cancel();
    let stop = tokio::spawn(stop_closed_slot(Arc::clone(interceptor)));
    async move {
        stop.await.unwrap_or_else(|error| {
            Err(crate::DnsError::Runtime(format!(
                "dns interceptor shutdown task failed: {error}"
            )))
        })
    }
}

/// The stop [`shutdown_dns_interceptor`] hands to a task of its own.
async fn stop_closed_slot(slot: Arc<DnsInterceptorSlot>) -> Result<()> {
    // Waits for a settings change still holding the lock. The slot is
    // closed, so whatever it leaves here is the last interceptor there is.
    let taken = slot.interceptor.lock().await.take();
    let stopped = match taken {
        Some(mut dns) => match dns.stop().await {
            Ok(()) => Ok(()),
            // One more restore, awaited so its outcome is what this returns.
            Err(_) if dns.finish_failed_stop().await => Ok(()),
            Err(error) => Err(error),
        },
        None => Ok(()),
    };
    let _ = tokio::task::spawn_blocking(netmetrics::dns_divert::clear_leftover).await;
    if let Err(error) = &stopped {
        warn!(error = %error, "dns interceptor stop failed");
    }
    stopped
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dependencies(store: &Arc<Store>) -> DnsDependencies {
        DnsDependencies {
            engine: Arc::new(RwLock::new(RuleEngine::new())),
            store: Arc::clone(store),
            data_dir: store.path().parent().expect("data dir").to_path_buf(),
            block_sink: None,
            alerts: None,
            registration_dates: None,
        }
    }

    fn resolver(enabled: bool) -> DaemonSetting {
        DaemonSetting {
            dns_resolver_enabled: enabled,
            ..DaemonSetting::default()
        }
    }

    /// The regression this guards: a settings change still running when
    /// shutdown took the interceptor found the slot empty and started a new
    /// resolver, redirecting adapter DNS again after it had been restored.
    ///
    /// Driven with a change that turns the resolver off, so that a
    /// regression fails here rather than redirecting this host's DNS.
    #[tokio::test]
    async fn a_settings_change_after_shutdown_is_refused() {
        let (_dir, store) = crate::test_support::temp_store();
        let slot = Arc::new(DnsInterceptorSlot::new());

        shutdown_dns_interceptor(&slot)
            .await
            .expect("nothing to stop");
        assert!(slot.is_closed());

        let applied = apply_dns_settings_change(
            &slot,
            &dependencies(&store),
            &resolver(true),
            &resolver(false),
        )
        .await;
        assert!(
            matches!(applied, Err(crate::DnsError::ShutDown)),
            "{applied:?}"
        );
        assert!(!slot.is_occupied().await);
    }

    #[tokio::test]
    async fn an_open_slot_takes_settings_changes() {
        let (_dir, store) = crate::test_support::temp_store();
        let slot = DnsInterceptorSlot::new();

        apply_dns_settings_change(
            &slot,
            &dependencies(&store),
            &resolver(true),
            &resolver(false),
        )
        .await
        .expect("an open slot applies the change");
        assert!(!slot.is_closed());
    }

    /// The regression this guards: shutdown closed the slot only once it had
    /// the lock. Behind a settings change that held the lock past the
    /// shutdown deadline, the timed-out shutdown was dropped still waiting,
    /// and left the slot open for the next change to start a resolver.
    #[tokio::test]
    async fn a_shutdown_waiting_behind_a_settings_change_closes_the_slot_at_once() {
        let (_dir, store) = crate::test_support::temp_store();
        let slot = Arc::new(DnsInterceptorSlot::new());
        let change_in_progress = slot.hold().await;

        let gave_up = tokio::time::timeout(
            std::time::Duration::from_millis(50),
            shutdown_dns_interceptor(&slot),
        )
        .await
        .is_err();
        assert!(gave_up, "the shutdown waits behind the change");
        assert!(slot.is_closed(), "closed although it never got the lock");
        drop(change_in_progress);

        let applied = apply_dns_settings_change(
            &slot,
            &dependencies(&store),
            &resolver(true),
            &resolver(false),
        )
        .await;
        assert!(
            matches!(applied, Err(crate::DnsError::ShutDown)),
            "{applied:?}"
        );
    }

    #[tokio::test]
    async fn bootstrap_after_shutdown_installs_no_interceptor() {
        let (_dir, store) = crate::test_support::temp_store();
        let slot = Arc::new(DnsInterceptorSlot::new());
        shutdown_dns_interceptor(&slot)
            .await
            .expect("nothing to stop");

        bootstrap_dns_interceptor(
            &slot,
            dependencies(&store),
            &resolver(false),
            false,
            CancellationToken::new(),
        )
        .await
        .expect("bootstrap");
        assert!(!slot.is_occupied().await);
    }
}
