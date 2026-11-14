//! Rebuilds DNS network state across network transitions and suspend/resume.
//!
//! Cached answers do not survive a change of network. On split-horizon
//! corporate DNS the same name resolves to different addresses inside and
//! outside the perimeter, and behind a captive portal every name briefly
//! resolves to the portal. Serving those from cache after the transition is
//! actively wrong, so the cache and upstream transport pools are retired
//! together when a transition is detected.

use std::sync::Arc;
use std::time::Instant;

use antiwire_tuning::{DNS_NETWORK_WATCH_INTERVAL, DNS_SUSPEND_GAP_THRESHOLD};
use futures_util::future::BoxFuture;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use antiwire_policy::PolicyEngine;

use crate::query_engine::QueryEngine;

/// Reason a flush was triggered, for logging.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FlushReason {
    NetworkChanged,
    ResumedFromSuspend,
}

impl FlushReason {
    const fn as_str(self) -> &'static str {
        match self {
            Self::NetworkChanged => "network_changed",
            Self::ResumedFromSuspend => "resumed_from_suspend",
        }
    }
}

/// What a sample of the host's networks found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NetworkEvent {
    /// The networks changed, or the host resumed from sleep. DNS state has
    /// been rebuilt for it.
    Transition,
    /// The networks are as they were, or could not be sampled.
    Unchanged,
}

/// Work to run after every sample: after DNS state is rebuilt for a
/// transition, such as extending the OS redirect to an adapter the transition
/// brought, and between transitions, so work a transition left unfinished can
/// be retried without waiting for the next one. It runs on the watcher's task,
/// so [`NetworkWatcher::stop`] also waits for it.
pub(crate) type TransitionHook = Arc<dyn Fn(NetworkEvent) -> BoxFuture<'static, ()> + Send + Sync>;

/// Background task that flushes `cache` when the host's networks change.
pub(crate) struct NetworkWatcher {
    cancel: CancellationToken,
    task: Option<tokio::task::JoinHandle<()>>,
}

impl NetworkWatcher {
    /// Starts sampling adapter state and rebuilding DNS state on every
    /// transition, then running `on_transition`.
    pub(crate) fn start<P>(stub: Arc<QueryEngine<P>>, on_transition: Option<TransitionHook>) -> Self
    where
        P: PolicyEngine + Send + Sync + 'static,
    {
        let cancel = CancellationToken::new();
        let task_cancel = cancel.clone();

        let task = tokio::spawn(async move {
            // No fingerprint until one is actually taken. Defaulting a failed
            // first sample to the empty fingerprint would make the first good
            // tick look like a transition and retire the freshly built pool.
            let mut fingerprint = sample_off_runtime().await;
            let mut last_tick = Instant::now();

            loop {
                tokio::select! {
                    () = task_cancel.cancelled() => break,
                    () = tokio::time::sleep(DNS_NETWORK_WATCH_INTERVAL) => {}
                }

                // A tick that took far longer than its interval means the
                // machine was asleep, not that the loop was starved.
                let elapsed = last_tick.elapsed();
                last_tick = Instant::now();
                let resumed =
                    elapsed.saturating_sub(DNS_NETWORK_WATCH_INTERVAL) >= DNS_SUSPEND_GAP_THRESHOLD;

                // A sample that could not be taken is not a transition: keep the
                // last fingerprint so the next tick compares against real state
                // rather than reading the gap as a network change.
                let changed = match sample_off_runtime().await {
                    Some(current) => {
                        // Only compare against a real previous sample. After a
                        // failed sample the stored fingerprint is stale but
                        // valid, and after a failed first sample there is none.
                        let changed = fingerprint_transition(fingerprint.as_deref(), &current);
                        fingerprint = Some(current);
                        changed
                    }
                    None => false,
                };

                let reason = if resumed {
                    Some(FlushReason::ResumedFromSuspend)
                } else if changed {
                    Some(FlushReason::NetworkChanged)
                } else {
                    None
                };

                if let Some(reason) = reason {
                    info!(
                        reason = reason.as_str(),
                        gap_ms = u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX),
                        "rebuilding dns state after network transition"
                    );
                    if let Err(error) = stub.reset_after_network_change().await {
                        warn!(%error, "failed to rebuild dns upstream after network transition");
                    }
                    if let Some(hook) = &on_transition {
                        hook(NetworkEvent::Transition).await;
                    }
                } else if let Some(hook) = &on_transition {
                    hook(NetworkEvent::Unchanged).await;
                }
            }
        });

        Self {
            cancel,
            task: Some(task),
        }
    }

    /// A transition that finishes after stop is requested, for lifecycle tests.
    #[cfg(test)]
    pub(crate) fn with_pending_transition(
        transition: impl std::future::Future<Output = ()> + Send + 'static,
    ) -> Self {
        let cancel = CancellationToken::new();
        let cancelled = cancel.clone();
        let task = tokio::spawn(async move {
            cancelled.cancelled().await;
            transition.await;
        });
        Self {
            cancel,
            task: Some(task),
        }
    }

    /// Stops the watcher and joins any adapter extension already in progress.
    /// Retain the handle across cancellation so a later stop can join it, or
    /// `Drop` can abort the task rather than detach it during shutdown.
    pub(crate) async fn stop(&mut self) {
        self.cancel.cancel();
        if let Some(task) = self.task.as_mut() {
            if let Err(error) = task.await {
                warn!(%error, "dns network watcher task failed");
            }
        }
        self.task = None;
    }
}

impl Drop for NetworkWatcher {
    fn drop(&mut self) {
        self.cancel.cancel();
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

/// Takes a fingerprint without stalling a runtime worker.
///
/// The sample is a synchronous sweep of every adapter the host has — measured at
/// 5–11 ms on a two-interface machine, and it grows with adapter count, which VPN,
/// container, and hypervisor stacks all push up. That is orders of magnitude past
/// what belongs between two polls, and it repeats every
/// [`DNS_NETWORK_WATCH_INTERVAL`], so it runs on a blocking thread instead.
///
/// `None` means the sample could not be taken at all — the runtime is shutting
/// down, or the sweep panicked.
async fn sample_off_runtime() -> Option<Vec<String>> {
    sample_with(network_fingerprint).await
}

/// The dispatch half of [`sample_off_runtime`], over an arbitrary sampler so a
/// test can observe which thread the sample actually lands on.
async fn sample_with<F>(sample: F) -> Option<Vec<String>>
where
    F: FnOnce() -> Vec<String> + Send + 'static,
{
    match tokio::task::spawn_blocking(sample).await {
        Ok(fingerprint) => Some(fingerprint),
        Err(error) => {
            warn!(%error, "network fingerprint sample failed");
            None
        }
    }
}

/// True when `current` differs from a previously recorded fingerprint.
///
/// A missing previous fingerprint is never a transition: it means no successful
/// sample has been taken yet, so the caller should adopt `current` silently
/// rather than tear down state it just built.
fn fingerprint_transition(previous: Option<&[String]>, current: &[String]) -> bool {
    previous.is_some_and(|previous| previous != current)
}

/// Fingerprint of the host's routable networks: each interface that carries at
/// least one non-loopback address, paired with its sorted address list.
///
/// `sysinfo::Networks` has no up/down status of its own, so "has a
/// non-loopback address" stands in for it — a link that drops carries no
/// address, and a link that comes back up on a different network gets a
/// different one, either of which changes the fingerprint. `sysinfo` also
/// exposes no per-adapter DNS server list, so unlike an approach built on a
/// Windows-specific adapter API there is no need to filter those out to avoid
/// the interceptor's own loopback redirect looking like a network change.
fn network_fingerprint() -> Vec<String> {
    let networks = sysinfo::Networks::new_with_refreshed_list();

    let mut entries: Vec<String> = networks
        .iter()
        .filter_map(|(name, data)| {
            let mut addresses: Vec<String> = data
                .ip_networks()
                .iter()
                .map(|network| network.addr)
                .filter(|addr| !addr.is_loopback())
                .map(|addr| addr.to_string())
                .collect();
            if addresses.is_empty() {
                return None;
            }
            addresses.sort_unstable();
            Some(format!("{name}|{}", addresses.join(",")))
        })
        .collect();

    entries.sort_unstable();
    entries
}

#[cfg(test)]
mod tests {
    use super::*;
    use antiwire_policy::DomainDecision;

    use crate::settings::DnsConfig;

    struct AllowAll;

    impl PolicyEngine for AllowAll {
        fn evaluate_domain_with_source(&self, _: &str) -> Option<DomainDecision> {
            None
        }
    }

    #[test]
    fn fingerprint_is_stable_across_calls() {
        assert_eq!(network_fingerprint(), network_fingerprint());
    }

    #[test]
    fn first_successful_sample_is_not_a_transition() {
        let sample = vec!["eth0|10.0.0.1".to_owned()];
        assert!(!fingerprint_transition(None, &sample));
        assert!(!fingerprint_transition(Some(&sample), &sample));
        assert!(fingerprint_transition(
            Some(&sample),
            &["eth0|10.0.0.2".to_owned()]
        ));
    }

    /// Pinned to a single-threaded runtime, where "another thread" and "not the
    /// runtime" are the same statement: an inline sample would report the test's
    /// own thread and stall every other task on it for the sweep's full duration.
    #[tokio::test(flavor = "current_thread")]
    async fn the_sample_never_runs_on_the_runtime_thread() {
        let runtime_thread = std::thread::current().id();

        let sampled_on = Arc::new(std::sync::Mutex::new(None));
        let recorder = Arc::clone(&sampled_on);
        let sample = sample_with(move || {
            *recorder.lock().expect("lock") = Some(std::thread::current().id());
            Vec::new()
        })
        .await;

        assert_eq!(sample, Some(Vec::new()));
        let sampled_on = sampled_on.lock().expect("lock").expect("sampler ran");
        assert_ne!(sampled_on, runtime_thread);
    }

    #[tokio::test]
    async fn watcher_stops_cleanly() {
        let stub = Arc::new(QueryEngine::new(AllowAll, DnsConfig::default()));
        let mut watcher = NetworkWatcher::start(Arc::clone(&stub), None);
        watcher.stop().await;
        assert_eq!(stub.response_cache().current_generation(), 0);
    }

    #[tokio::test]
    async fn a_cancelled_stop_keeps_the_watcher_owned_until_drop() {
        struct OnDrop(Option<tokio::sync::oneshot::Sender<()>>);
        impl Drop for OnDrop {
            fn drop(&mut self) {
                // A disconnected receiver only means the test already failed.
                if let Some(sender) = self.0.take() {
                    let _ = sender.send(());
                }
            }
        }

        let (started_tx, started) = tokio::sync::oneshot::channel();
        let (dropped_tx, dropped) = tokio::sync::oneshot::channel();
        let mut watcher = NetworkWatcher::with_pending_transition(async move {
            let _on_drop = OnDrop(Some(dropped_tx));
            let _ = started_tx.send(());
            std::future::pending::<()>().await;
        });

        // Poll stop once, then cancel it while the transition is still pending.
        tokio::select! {
            biased;
            () = watcher.stop() => panic!("the transition is still pending"),
            () = std::future::ready(()) => {}
        }
        started.await.expect("transition started");
        let retained = watcher.task.is_some();
        drop(watcher);
        let aborted = tokio::time::timeout(std::time::Duration::from_secs(5), dropped).await;

        assert!(retained, "a cancelled stop must retain the join handle");
        aborted
            .expect("Drop must abort the watcher")
            .expect("drop notification");
    }
}
