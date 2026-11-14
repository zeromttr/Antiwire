//! One kind of download sync: one at a time, backed off after failures, and
//! reported to the user when it fails.

use std::future::Future;

use antiwire_events::{Alert, AlertKind, AlertPublisher, Severity};
use time::OffsetDateTime;
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;

use crate::backoff::SyncBackoff;

/// Who asked for a sync.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Trigger {
    /// The user: waits for a running sync, and ignores any backoff.
    Manual,
    /// A schedule or a settings change: skipped while a sync runs or while
    /// failures defer it.
    Automatic,
}

/// What became of a sync that did not fail.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SyncOutcome {
    Ran,
    /// Another sync was running, so this one was dropped.
    Coalesced,
    /// Recent failures defer automatic syncs until then.
    Deferred(OffsetDateTime),
    /// Shutdown began first.
    Cancelled,
}

/// How a failed sync is told to the user and backed off.
pub(crate) struct FailurePolicy {
    pub(crate) kind: AlertKind,
    pub(crate) title: &'static str,
    /// Leads the alert's message, followed by the error.
    pub(crate) summary: &'static str,
    pub(crate) backoff_base_minutes: f64,
    pub(crate) backoff_cap_minutes: f64,
}

/// Runs one kind of sync.
pub(crate) struct SyncRunner {
    gate: Mutex<()>,
    backoff: SyncBackoff,
    policy: FailurePolicy,
    alerts: AlertPublisher,
    shutdown: CancellationToken,
}

impl SyncRunner {
    pub(crate) fn new(
        policy: FailurePolicy,
        alerts: AlertPublisher,
        shutdown: CancellationToken,
    ) -> Self {
        Self {
            gate: Mutex::new(()),
            backoff: SyncBackoff::new(policy.backoff_base_minutes, policy.backoff_cap_minutes),
            policy,
            alerts,
            shutdown,
        }
    }

    /// Runs `sync` as `trigger` asks. A failure defers automatic syncs and
    /// raises an alert; a success clears the deferral.
    ///
    /// # Errors
    ///
    /// What `sync` returned.
    pub(crate) async fn run<Fut>(
        &self,
        trigger: Trigger,
        sync: impl FnOnce() -> Fut,
    ) -> Result<SyncOutcome, String>
    where
        Fut: Future<Output = Result<(), String>>,
    {
        let _gate = match trigger {
            Trigger::Manual => self.gate.lock().await,
            Trigger::Automatic => match self.gate.try_lock() {
                Ok(gate) => gate,
                Err(_) => return Ok(SyncOutcome::Coalesced),
            },
        };
        if trigger == Trigger::Automatic {
            if let Some(resume) = self.backoff.deferred_until(OffsetDateTime::now_utc()) {
                return Ok(SyncOutcome::Deferred(resume));
            }
        }
        match self.shutdown.run_until_cancelled(sync()).await {
            None => Ok(SyncOutcome::Cancelled),
            Some(Ok(())) => {
                self.backoff.reset();
                Ok(SyncOutcome::Ran)
            }
            Some(Err(error)) => {
                let resume = self.backoff.register_failure(OffsetDateTime::now_utc());
                tracing::warn!(%error, %resume, "{}; automatic retry deferred", self.policy.summary);
                self.alerts.publish(Alert::new(
                    self.policy.kind,
                    Severity::Warning,
                    self.policy.title,
                    format!("{}: {error}", self.policy.summary),
                ));
                Err(error)
            }
        }
    }

    /// Whether failures defer automatic syncs at `now`.
    pub(crate) fn deferred(&self, now: OffsetDateTime) -> bool {
        self.backoff.deferred_until(now).is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use antiwire_events::NotificationHub;

    fn runner() -> (
        SyncRunner,
        antiwire_events::NotificationSubscription,
        CancellationToken,
    ) {
        let alerts = AlertPublisher::unsaved(NotificationHub::with_capacity(4), None);
        let subscription = alerts.subscribe();
        let shutdown = CancellationToken::new();
        let runner = SyncRunner::new(
            FailurePolicy {
                kind: AlertKind::HostsSyncFailed,
                title: "Sync Failed",
                summary: "Failed to sync",
                backoff_base_minutes: 10.0,
                backoff_cap_minutes: 60.0,
            },
            alerts,
            shutdown.clone(),
        );
        (runner, subscription, shutdown)
    }

    #[tokio::test]
    async fn a_failure_alerts_and_defers_automatic_syncs_but_not_manual_ones() {
        let (runner, mut alerts, _) = runner();

        let error = runner
            .run(Trigger::Automatic, || async {
                Err("mirror down".to_owned())
            })
            .await
            .expect_err("fails");
        assert_eq!(error, "mirror down");
        let alert = alerts.recv().await.expect("alert");
        assert_eq!(alert.kind, AlertKind::HostsSyncFailed);
        assert_eq!(alert.message, "Failed to sync: mirror down");

        let deferred = runner
            .run(Trigger::Automatic, || async { Ok(()) })
            .await
            .expect("deferred");
        assert!(matches!(deferred, SyncOutcome::Deferred(_)));

        let manual = runner
            .run(Trigger::Manual, || async { Ok(()) })
            .await
            .expect("manual");
        assert_eq!(manual, SyncOutcome::Ran);
        assert!(
            !runner.deferred(OffsetDateTime::now_utc()),
            "a success clears it"
        );
    }

    #[tokio::test]
    async fn an_automatic_sync_is_dropped_while_another_runs() {
        let (runner, _, _) = runner();
        let (release, wait) = tokio::sync::oneshot::channel::<()>();

        let running = runner.run(Trigger::Manual, || async {
            let _ = wait.await;
            Ok(())
        });
        let duplicate = async {
            tokio::task::yield_now().await;
            let outcome = runner.run(Trigger::Automatic, || async { Ok(()) }).await;
            let _ = release.send(());
            outcome
        };
        let (first, second) = tokio::join!(running, duplicate);

        assert_eq!(first.expect("first"), SyncOutcome::Ran);
        assert_eq!(second.expect("second"), SyncOutcome::Coalesced);
    }

    #[tokio::test]
    async fn shutdown_cancels_a_running_sync() {
        let (runner, _, shutdown) = runner();
        shutdown.cancel();

        let outcome = runner
            .run(Trigger::Manual, std::future::pending)
            .await
            .expect("cancelled");

        assert_eq!(outcome, SyncOutcome::Cancelled);
    }
}
