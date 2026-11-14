//! The state a redirect shares with its extensions and restores.
//!
//! [`DnsRedirect`](crate::DnsRedirect) applies and restores the redirect, and
//! its [`RedirectExtender`](crate::RedirectExtender) extends it to adapters
//! that appear while the resolver runs, so the state is shared, and every
//! change to adapter DNS goes through one gate: an extension can never land
//! after a restore has run.
//!
//! The gate is held on the blocking thread that makes the OS call, not by the
//! async task waiting for it. Cancelling that task, as a shutdown deadline or
//! an aborted network watcher does, cannot stop a blocking call already under
//! way, so the call and the state update that records it finish together
//! under the gate, and a restore waits for both.

use std::time::{Duration, Instant};

use antiwire_dns_os::RedirectCoverage;
use antiwire_tuning::DNS_REDIRECT_EXTENSION_RETRY;
use parking_lot::Mutex;

#[derive(Debug, Default)]
struct RedirectState {
    /// The snapshot that restores the redirect in place: the adapters'
    /// original DNS, which a restore writes back. `None` while no redirect is
    /// in place.
    redirected: Option<String>,
    /// Set while adapters may be missing from the redirect because their
    /// originals could not be captured or persisted, or the redirect could
    /// not be applied to them: when to extend it again.
    retry: Option<ExtensionRetry>,
    /// A redirect the resolver is waiting to make: none is applied because
    /// none could be when it started, as before any adapter is up.
    wanted: bool,
}

#[derive(Debug, Clone, Copy)]
struct ExtensionRetry {
    due: Instant,
    delay: Duration,
}

/// The redirect state a [`DnsRedirect`](crate::DnsRedirect) shares with its
/// extenders and restores.
#[derive(Debug, Default)]
pub(crate) struct SharedRedirect {
    state: Mutex<RedirectState>,
    changes: tokio::sync::Mutex<()>,
    /// Held across each OS change to adapter DNS and the state update that
    /// records it, on the blocking thread making the change. See the module docs.
    os: Mutex<()>,
}

impl SharedRedirect {
    /// Whether adapter DNS is (or may still be) pointed at the resolver.
    pub(crate) fn applied(&self) -> bool {
        self.state.lock().redirected.is_some()
    }

    /// The snapshot that restores the redirect in place, or `None` while no
    /// redirect is in place.
    pub(crate) fn snapshot(&self) -> Option<String> {
        self.state.lock().redirected.clone()
    }

    /// Records a redirect in place, reversed by `snapshot`.
    pub(crate) fn record(&self, snapshot: String) {
        self.state.lock().redirected = Some(snapshot);
    }

    /// Records that no redirect is left in place.
    ///
    /// A pending retry is kept, so a redirect that is still wanted backs off
    /// from where it was; [`Self::cancel_pending`] ends both.
    pub(crate) fn release(&self) {
        self.state.lock().redirected = None;
    }

    /// Marks a redirect as wanted though none is in place, for the network
    /// watcher to make once an adapter can be redirected.
    pub(crate) fn want(&self) {
        self.state.lock().wanted = true;
    }

    /// Whether a redirect is wanted though none is in place.
    pub(crate) fn wanted(&self) -> bool {
        self.state.lock().wanted
    }

    /// Cancels a wanted redirect and any pending retry, and returns whether
    /// a redirect is (or may still be) in place, which is then owed a
    /// restore.
    ///
    /// One step under the state lock, the same one a first redirect claims
    /// before it writes anything. So a first redirect under way is either
    /// claimed already, and the returned `true` makes the caller restore it,
    /// or finds the redirect no longer wanted and writes nothing.
    pub(crate) fn cancel_pending(&self) -> bool {
        let mut state = self.state.lock();
        state.wanted = false;
        state.retry = None;
        state.redirected.is_some()
    }

    /// Records `plan` as applied if a redirect is still wanted and none is in
    /// place. A first redirect writes nothing unless this returns `true`.
    pub(crate) fn claim(&self, plan: &str) -> bool {
        let mut state = self.state.lock();
        if !state.wanted || state.redirected.is_some() {
            return false;
        }
        state.redirected = Some(plan.to_owned());
        true
    }

    /// Schedules another extension, since adapters may be missing from the
    /// redirect. Each consecutive retry waits twice as long as the last, up to
    /// a cap. Returns whether this is the first, for the caller's log level.
    pub(crate) fn defer_extension(&self) -> bool {
        let mut state = self.state.lock();
        let first = state.retry.is_none();
        let delay = state
            .retry
            .map_or(DNS_REDIRECT_EXTENSION_RETRY.base, |retry| {
                DNS_REDIRECT_EXTENSION_RETRY.after(retry.delay)
            });
        state.retry = Some(ExtensionRetry {
            due: Instant::now() + delay,
            delay,
        });
        first
    }

    /// Whether an extension deferred by [`Self::defer_extension`] is due.
    pub(crate) fn extension_due(&self) -> bool {
        self.extension_due_at(Instant::now())
    }

    pub(crate) fn extension_due_at(&self, now: Instant) -> bool {
        self.state
            .lock()
            .retry
            .is_some_and(|retry| now >= retry.due)
    }

    /// Records that the redirect is in place as far as `coverage` reaches:
    /// none is left to make, and a complete one leaves nothing to retry.
    ///
    /// A partial one keeps its pending retry, so the adapters it missed back
    /// off from where they were rather than start again at the shortest delay.
    pub(crate) fn settle(&self, coverage: RedirectCoverage) {
        let mut state = self.state.lock();
        state.wanted = false;
        if coverage == RedirectCoverage::Complete {
            state.retry = None;
        }
    }

    /// Serializes the async sequences that change adapter DNS: a start, an
    /// extension, a stop. Their OS calls also take [`Self::lock_os`].
    pub(crate) async fn lock_changes(&self) -> tokio::sync::MutexGuard<'_, ()> {
        self.changes.lock().await
    }

    /// Blocks until no other OS change to adapter DNS is under way. Hold it on
    /// the blocking thread across the OS call and the state update recording it.
    pub(crate) fn lock_os(&self) -> parking_lot::MutexGuard<'_, ()> {
        self.os.lock()
    }
}

#[cfg(test)]
mod tests {
    use std::time::Instant;

    use antiwire_tuning::DNS_REDIRECT_EXTENSION_RETRY;

    use super::SharedRedirect;
    use crate::test_support::far_future;

    #[test]
    fn retries_back_off_and_end_with_the_redirect() {
        let redirect = SharedRedirect::default();
        redirect.record("wifi".to_owned());
        assert!(!redirect.extension_due_at(far_future()), "nothing owed yet");

        let start = Instant::now();
        assert!(redirect.defer_extension(), "the first deferral");
        assert!(!redirect.extension_due_at(start));
        assert!(redirect.extension_due_at(start + DNS_REDIRECT_EXTENSION_RETRY.base * 2));

        assert!(!redirect.defer_extension(), "a repeat");
        let second = Instant::now();
        assert!(!redirect.extension_due_at(second + DNS_REDIRECT_EXTENSION_RETRY.base));
        assert!(redirect.extension_due_at(second + DNS_REDIRECT_EXTENSION_RETRY.base * 2));

        for _ in 0..20 {
            redirect.defer_extension();
        }
        assert!(redirect.extension_due_at(Instant::now() + DNS_REDIRECT_EXTENSION_RETRY.cap));

        assert!(redirect.cancel_pending(), "the redirect is still owed");
        assert!(
            !redirect.extension_due_at(far_future()),
            "a cancelled retry is not due"
        );
    }
}
