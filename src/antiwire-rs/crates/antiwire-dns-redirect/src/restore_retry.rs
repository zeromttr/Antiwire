//! Retries an owed OS DNS restore after a failed start, without requiring
//! another settings change or a daemon restart.

use std::sync::Arc;

use antiwire_tuning::{DNS_RESTORE_RETRY_INITIAL_DELAY, DNS_RESTORE_RETRY_MAX_DELAY};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use crate::blocking::blocking_os;
use crate::host::Host;
use crate::restore::restore_redirect;
use crate::state::SharedRedirect;

pub(crate) struct RestoreRetry {
    cancel: CancellationToken,
    task: Option<JoinHandle<()>>,
}

impl RestoreRetry {
    pub(crate) fn start(redirect: Arc<SharedRedirect>, host: Host) -> Self {
        let cancel = CancellationToken::new();
        let cancelled = cancel.clone();
        let task = tokio::spawn(async move {
            let mut delay = DNS_RESTORE_RETRY_INITIAL_DELAY;
            loop {
                tokio::select! {
                    () = cancelled.cancelled() => return,
                    () = tokio::time::sleep(delay) => {}
                }
                let _changes = tokio::select! {
                    () = cancelled.cancelled() => return,
                    guard = redirect.lock_changes() => guard,
                };
                if cancelled.is_cancelled() || !redirect.applied() {
                    return;
                }
                let job = Arc::clone(&redirect);
                let host = host.clone();
                // Do not race cancellation against the blocking job: stopping
                // this task must wait for any OS write and its settling before
                // a new listener is allowed to redirect DNS again.
                match blocking_os(move || restore_redirect(&job, &host)).await {
                    Some(Ok(())) => {
                        info!("adapter DNS restored by background recovery");
                        return;
                    }
                    // Restored; the record left behind is the next start's to clear.
                    Some(Err(error)) if error.dns_restored() => return,
                    _ => {}
                }
                delay = delay.saturating_mul(2).min(DNS_RESTORE_RETRY_MAX_DELAY);
            }
        });
        Self {
            cancel,
            task: Some(task),
        }
    }

    /// Cancels future retries and joins any OS restore already in progress.
    /// Keep the handle until the await completes, so cancellation of a settings
    /// request does not detach a restore that the next request must still join.
    pub(crate) async fn stop(&mut self) {
        self.cancel.cancel();
        if let Some(task) = self.task.as_mut() {
            if let Err(error) = task.await {
                warn!(%error, "dns restore retry task failed");
            }
        }
        self.task = None;
    }
}

impl Drop for RestoreRetry {
    fn drop(&mut self) {
        // A running blocking restore finishes and settles under the OS gate;
        // the emergency restore `DnsRedirect` makes as it drops waits for it
        // and avoids doing the same work twice. No later scheduled retry
        // should run after Drop.
        self.cancel.cancel();
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::time::Duration;

    use super::*;

    #[tokio::test]
    async fn cancelling_the_join_keeps_an_in_progress_restore_joinable() {
        static ENTERED: AtomicBool = AtomicBool::new(false);
        static RELEASED: AtomicBool = AtomicBool::new(false);
        static RESTORES: AtomicUsize = AtomicUsize::new(0);
        fn held_restore(_: &str) -> bool {
            RESTORES.fetch_add(1, Ordering::SeqCst);
            ENTERED.store(true, Ordering::SeqCst);
            while !RELEASED.load(Ordering::SeqCst) {
                std::thread::sleep(Duration::from_millis(1));
            }
            true
        }
        // Never leave a blocking OS stand-in hung if an assertion fails.
        struct ReleaseOnDrop;
        impl Drop for ReleaseOnDrop {
            fn drop(&mut self) {
                RELEASED.store(true, Ordering::SeqCst);
            }
        }
        let _release = ReleaseOnDrop;
        let (_dir, store) = crate::test_support::temp_store();
        let redirect = Arc::new(SharedRedirect::default());
        redirect.record("snapshot".to_owned());
        let mut retry = RestoreRetry::start(
            Arc::clone(&redirect),
            crate::test_support::host(&store, crate::test_support::restoring(held_restore)),
        );
        tokio::time::timeout(Duration::from_secs(3), async {
            while !ENTERED.load(Ordering::SeqCst) {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("background restore started");

        assert!(
            tokio::time::timeout(Duration::from_millis(20), retry.stop())
                .await
                .is_err()
        );
        assert!(redirect.applied(), "the OS write is still in progress");
        // A later lifecycle operation must still join it, even after the
        // previous settings operation was cancelled while waiting.
        assert!(
            tokio::time::timeout(Duration::from_millis(20), retry.stop())
                .await
                .is_err()
        );
        RELEASED.store(true, Ordering::SeqCst);
        tokio::time::timeout(Duration::from_secs(3), retry.stop())
            .await
            .expect("restore joined");
        assert!(!redirect.applied(), "joined only after the restore settled");
        assert_eq!(RESTORES.load(Ordering::SeqCst), 1);
        assert!(retry.task.is_none());
    }
}
