//! [`RedirectExtender`]: extends a redirect to adapters that come up while the
//! resolver runs, and retries what a start could not do.
//!
//! No adapter changes before its original is on disk and in the record a
//! restore reverses. An extension that cannot capture or persist those
//! originals changes nothing and is retried, rather than redirect an adapter
//! nothing could put back.
//!
//! A redirect that reaches only some of the adapters it tries is in place,
//! and is retried for the rest like one that could not be applied at all:
//! until a retry reaches them, they resolve unfiltered.
//!
//! A start that could redirect nothing, as at boot before any adapter is up,
//! leaves the redirect wanted, and the extender makes it once an adapter can
//! be redirected. A stop cancels that in the same step that checks for a
//! redirect to restore, so one made concurrently is either restored or never
//! written.

use std::future::Future;
use std::sync::Arc;

use antiwire_dns_os::{AppliedRedirect, RedirectCoverage};
use antiwire_store::StoreError;
use tracing::{debug, info, warn};

use crate::blocking::blocking_os;
use crate::host::Host;
use crate::restore::restore_locked;
use crate::state::SharedRedirect;
use crate::RedirectError;

/// Extends a [`DnsRedirect`](crate::DnsRedirect) to adapters that come up
/// after it was made, and retries what it could not do: adapters it did not
/// reach, or the whole redirect when none could be made at start.
///
/// Cheap to clone. It shares the redirect's state, so an extension can never
/// land after the redirect's restore has run.
#[derive(Clone)]
pub struct RedirectExtender {
    shared: Arc<SharedRedirect>,
    host: Host,
    ipv6: bool,
}

impl RedirectExtender {
    /// The extender of the redirect `shared` records, which redirects IPv6
    /// too when `ipv6`.
    pub(crate) const fn new(shared: Arc<SharedRedirect>, host: Host, ipv6: bool) -> Self {
        Self { shared, host, ipv6 }
    }

    /// Whether a retry is due, of an extension or of a redirect not made yet.
    /// Between network transitions, extend only when it is.
    #[must_use]
    pub fn is_due(&self) -> bool {
        self.shared.extension_due()
    }

    /// Redirects adapters added since the redirect was made, after recording
    /// their originals, or makes the redirect a start could not.
    ///
    /// Cancelling the returned future cannot leave a redirect that nothing
    /// records: the OS calls and the record of what they changed run as one
    /// blocking job.
    pub fn extend(&self) -> impl Future<Output = ()> + Send + 'static {
        let backend = self.host.backend;
        let ipv6 = self.ipv6;
        extend_to_new_adapters(
            Arc::clone(&self.shared),
            self.host.clone(),
            move |prior| (backend.plan)(ipv6, prior),
            move |plan| (backend.apply)(ipv6, plan),
        )
    }
}

/// Extends an applied redirect to adapters added since it was applied, after a
/// network transition, and records their originals in the persisted snapshot.
///
/// The OS calls are `plan`, which returns the prior snapshot extended with
/// the originals of new adapters and changes nothing, and `apply`, which
/// redirects the adapters a plan records, and no others, and returns the
/// snapshot restore must reverse and whether it reached all of them. The plan
/// is persisted and recorded between the two, so no adapter changes before
/// its original is on disk and in the record a clean stop restores. The calls
/// and the record of what they changed run as one blocking job, so cancelling
/// this future cannot leave a redirect that nothing records.
///
/// When the plan cannot be captured or persisted, or the redirect does not
/// apply, nothing new changes and the extension is deferred: see
/// [`SharedRedirect::extension_due`]. A redirect that reaches only some
/// adapters is deferred the same way, for the rest.
///
/// With no redirect in place but one wanted, this makes the first one
/// instead, from a fresh capture. `host` restores it if it fails, and arms
/// boot recovery before any adapter changes.
async fn extend_to_new_adapters<P, A>(redirect: Arc<SharedRedirect>, host: Host, plan: P, apply: A)
where
    P: FnOnce(Option<&str>) -> Option<String> + Send + 'static,
    A: FnOnce(&str) -> Option<AppliedRedirect> + Send + 'static,
{
    let _changes = redirect.lock_changes().await;
    let job = Arc::clone(&redirect);
    let undo_redirect = Arc::clone(&redirect);
    let undo_host = host.clone();
    // Undone when the adapters are back, even if the record could not be
    // cleared: the next start restores them again from it.
    let undo = move || {
        !matches!(
            restore_locked(&undo_redirect, &undo_host),
            Err(RedirectError::RestoreNotConfirmed)
        )
    };
    let persist = move |snapshot: &str| {
        host.save_record(snapshot)?;
        // Boot recovery restores the recorded snapshot after an unclean
        // shutdown, so it is armed before the adapters it covers change.
        host.arm_boot_recovery();
        Ok(())
    };
    blocking_os(move || extend_now(&job, persist, plan, apply, undo)).await;
}

/// The blocking half of [`extend_to_new_adapters`]. `persist` makes a
/// snapshot durable, and `undo` restores and settles a failed first redirect;
/// it runs under the OS gate this already holds.
fn extend_now<S, P, A, U>(redirect: &SharedRedirect, mut persist: S, plan: P, apply: A, undo: U)
where
    S: FnMut(&str) -> Result<(), StoreError>,
    P: FnOnce(Option<&str>) -> Option<String>,
    A: FnOnce(&str) -> Option<AppliedRedirect>,
    U: FnOnce() -> bool,
{
    let _os = redirect.lock_os();
    let Some(prior) = redirect.snapshot() else {
        // Without a redirect in place there is nothing to extend: either a
        // restore ran first and released it, and extending it now would put
        // adapters back on a resolver that is going away, or none has been
        // made yet. Only the second is wanted.
        if redirect.wanted() {
            make_first_redirect(redirect, persist, plan, apply, undo);
        }
        return;
    };
    let Some(planned) = plan(Some(&prior)) else {
        defer_extension(redirect, "adapter DNS could not be captured");
        return;
    };
    let extended = planned != prior;
    if extended {
        // The new adapters' originals reach disk before any of them changes.
        // If they cannot, nothing changes now: an adapter is never redirected
        // without a record that could put it back.
        if let Err(error) = persist(&planned) {
            warn!(%error, "could not persist the DNS of new adapters");
            defer_extension(redirect, "the new adapters' DNS could not be persisted");
            return;
        }
        // Recorded before the write too, so a clean stop reverses whatever
        // the write changes, even if it fails partway or never reports back.
        // Restoring an adapter it did not change writes back what it has.
        redirect.record(planned.clone());
    }
    let Some(applied) = apply(&planned) else {
        defer_extension(redirect, "the redirect could not be applied");
        return;
    };
    settle_applied(redirect, applied.coverage);
    let snapshot = applied.snapshot;
    // `snapshot` is `planned` less legacy entries whose adapter went away, so
    // the record already on disk covers it even if this write fails.
    if snapshot != planned {
        redirect.record(snapshot.clone());
        if let Err(error) = persist(&snapshot) {
            warn!(%error, "failed to persist the extended dns redirect state");
        }
    }
    if extended {
        info!("dns redirect extended to adapters added since it was applied");
    }
}

/// Makes the redirect a start could not, such as one at boot before any
/// adapter was up, from a fresh capture. Runs under the OS gate.
///
/// The plan is claimed before anything is written: from then on a stop finds
/// the redirect in place and restores it, and a stop that came first leaves
/// it unwanted and nothing is written. Then, as at a start, the plan reaches
/// disk before any adapter changes, and a write that fails is undone.
fn make_first_redirect<S, P, A, U>(
    redirect: &SharedRedirect,
    mut persist: S,
    plan: P,
    apply: A,
    undo: U,
) where
    S: FnMut(&str) -> Result<(), StoreError>,
    P: FnOnce(Option<&str>) -> Option<String>,
    A: FnOnce(&str) -> Option<AppliedRedirect>,
    U: FnOnce() -> bool,
{
    let Some(planned) = plan(None) else {
        defer_extension(redirect, "there is no adapter DNS to redirect yet");
        return;
    };
    if !redirect.claim(&planned) {
        return;
    }
    if let Err(error) = persist(&planned) {
        warn!(%error, "could not persist adapter DNS before redirecting");
        redirect.release();
        defer_extension(redirect, "adapter DNS could not be persisted");
        return;
    }
    let Some(applied) = apply(&planned) else {
        // The write may have changed some adapters before it failed.
        // Restoring the plan puts back whatever it changed and settles the
        // redirect; one that cannot be confirmed stays owed to the stop.
        if !undo() {
            warn!("a failed DNS redirect could not be confirmed undone; adapter DNS will be restored when the resolver stops");
        }
        defer_extension(redirect, "the redirect could not be applied");
        return;
    };
    settle_applied(redirect, applied.coverage);
    let snapshot = applied.snapshot;
    if snapshot != planned {
        redirect.record(snapshot.clone());
        if let Err(error) = persist(&snapshot) {
            warn!(%error, "failed to persist the final dns redirect state");
        }
    }
    info!("OS DNS redirected to the resolver now that adapters can be");
}

/// Settles a redirect that `apply` put in place. One that missed some
/// adapters is retried for them, since they still resolve unfiltered.
fn settle_applied(redirect: &SharedRedirect, coverage: RedirectCoverage) {
    redirect.settle(coverage);
    if coverage == RedirectCoverage::Partial {
        defer_extension(redirect, "some adapters could not be redirected");
    }
}

/// Defers an extension that did not finish, logging the first failure in a
/// run of them as a warning and the retries after it quietly.
fn defer_extension(redirect: &SharedRedirect, reason: &'static str) {
    if redirect.defer_extension() {
        warn!(
            reason,
            "dns redirect not extended to new adapters; retrying"
        );
    } else {
        debug!(reason, "dns redirect extension retry did not finish");
    }
}

#[cfg(test)]
mod tests;
