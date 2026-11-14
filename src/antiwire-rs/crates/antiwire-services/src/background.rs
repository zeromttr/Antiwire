//! The tasks a background service owns, stopped by the daemon's shutdown.

use std::future::Future;
use std::time::Duration;

use tokio::time::MissedTickBehavior;
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;

/// The tasks one background service owns.
///
/// Every task stops at its next await once shutdown begins, and no task
/// starts after it, so [`BackgroundTasks::join`] returns promptly even when a
/// download was in flight.
pub(crate) struct BackgroundTasks {
    tracker: TaskTracker,
    shutdown: CancellationToken,
}

impl BackgroundTasks {
    pub(crate) fn new(shutdown: CancellationToken) -> Self {
        Self {
            tracker: TaskTracker::new(),
            shutdown,
        }
    }

    /// Starts `task`, unless shutdown has begun. Returns whether it started.
    pub(crate) fn spawn(&self, task: impl Future<Output = ()> + Send + 'static) -> bool {
        if self.shutdown.is_cancelled() {
            return false;
        }
        let shutdown = self.shutdown.clone();
        self.tracker.spawn(async move {
            shutdown.run_until_cancelled(task).await;
        });
        true
    }

    /// Runs `tick` now and then every `period`, one at a time, until shutdown.
    pub(crate) fn every<F, Fut>(&self, period: Duration, mut tick: F) -> bool
    where
        F: FnMut() -> Fut + Send + 'static,
        Fut: Future<Output = ()> + Send,
    {
        self.spawn(async move {
            let mut ticker = tokio::time::interval(period);
            ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
            loop {
                ticker.tick().await;
                tick().await;
            }
        })
    }

    /// The token cancelled when the daemon shuts down.
    pub(crate) fn shutdown(&self) -> &CancellationToken {
        &self.shutdown
    }

    /// Waits for every task to stop. Call once shutdown has begun.
    pub(crate) async fn join(&self) {
        self.tracker.close();
        self.tracker.wait().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    #[tokio::test]
    async fn shutdown_stops_running_tasks_and_refuses_new_ones() {
        let shutdown = CancellationToken::new();
        let tasks = BackgroundTasks::new(shutdown.clone());
        let ticks = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&ticks);
        assert!(tasks.every(Duration::from_millis(1), move || {
            counter.fetch_add(1, Ordering::Relaxed);
            async {}
        }));
        assert!(tasks.spawn(std::future::pending()));

        tokio::time::sleep(Duration::from_millis(20)).await;
        shutdown.cancel();
        tokio::time::timeout(Duration::from_secs(1), tasks.join())
            .await
            .expect("a pending task stops at shutdown");

        assert!(ticks.load(Ordering::Relaxed) > 0);
        assert!(!tasks.spawn(async {}), "nothing starts after shutdown");
    }
}
