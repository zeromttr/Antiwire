//! [`DnsRedirect`]: one resolver's redirect of system DNS, from its start to
//! its restore.

use std::path::Path;
use std::sync::Arc;

use antiwire_dns_os::RedirectCoverage;
use antiwire_store::Store;
use tracing::{error, info, warn};

use crate::backend::RedirectBackend;
use crate::blocking::{blocking_os, run_off_runtime};
use crate::extend::RedirectExtender;
use crate::host::Host;
use crate::restore::restore_redirect;
use crate::restore_retry::RestoreRetry;
use crate::state::SharedRedirect;
use crate::RedirectError;

/// How far [`DnsRedirect::redirect`] pointed system DNS at the resolver.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RedirectOutcome {
    /// This process may not change system DNS: it is not running as
    /// administrator or root.
    NotPermitted,
    /// Nothing was redirected. The redirect is retried in the background.
    Failed,
    /// Some adapters were redirected, and the rest are retried.
    Partial,
    /// Every adapter that could be redirected was.
    Complete,
}

/// One resolver's redirect of system DNS to its loopback listener.
///
/// A resolver makes the redirect when it starts, with [`Self::redirect`],
/// hands a [`RedirectExtender`] to whatever watches the network so adapters
/// that come up later are redirected too, and puts system DNS back when it
/// stops, with [`Self::restore`]. A resolver that is disabled at boot, or
/// fails to start, uses [`Self::restore_if_dirty`] to undo what an earlier
/// run left.
///
/// Every change follows the same rules:
///
/// - No adapter changes before its original DNS is on disk, in the database
///   and in the journal beside it, and recorded here for a restore.
/// - The record is cleared only once a restore is confirmed. One that is not
///   stays owed: to a later stop, to the background retry, to the emergency
///   restore when this is dropped, or to the next launch.
/// - Changes to adapter DNS are serialized, and a blocking OS call and the
///   record of what it changed finish together even when the task waiting
///   for them is cancelled. A restore waits for both.
///
/// Dropping a `DnsRedirect` that still has a redirect in place starts a
/// restore off the async runtime, without waiting for it.
pub struct DnsRedirect {
    /// Shared with extensions, retries, and the blocking jobs of both.
    shared: Arc<SharedRedirect>,
    host: Host,
    /// Owed restore after a failed one. Stopped before any new redirect.
    restore_retry: Option<RestoreRetry>,
    /// Whether `Drop` should still try an emergency restore. Cleared once
    /// [`Self::finish_failed_restore`] has started its own final attempt,
    /// which runs to completion whether or not it is awaited.
    restore_on_drop: bool,
}

impl DnsRedirect {
    /// A redirect of the host's own DNS, recorded in `store` and in a journal
    /// in `data_dir`, the daemon's data directory, where recovery looks for
    /// it.
    ///
    /// `arm_boot_recovery` arms recovery at the next boot once a redirect is
    /// made, for a daemon that is not a service: nothing stops it cleanly at
    /// shutdown, so it may be killed before it restores.
    #[must_use]
    pub fn new(store: Arc<Store>, data_dir: &Path, arm_boot_recovery: bool) -> Self {
        Self::with_host(Host::new(
            store,
            data_dir,
            RedirectBackend::OS,
            arm_boot_recovery,
        ))
    }

    fn with_host(host: Host) -> Self {
        Self {
            shared: Arc::default(),
            host,
            restore_retry: None,
            restore_on_drop: true,
        }
    }

    /// Whether this redirect arms boot recovery once it is made.
    #[must_use]
    pub const fn arms_boot_recovery(&self) -> bool {
        self.host.arms_boot_recovery()
    }

    /// Whether this process may change system DNS at all.
    fn can_redirect(&self) -> bool {
        (self.host.backend.can_redirect)()
    }

    /// Points system DNS at the resolver, which must already be serving on
    /// loopback: on `127.0.0.1`, and on `::1` too when `ipv6`.
    ///
    /// A background restore still retrying is stopped first, so it cannot
    /// undo this redirect. A redirect an earlier run left recorded is reused
    /// rather than captured again, since the adapters may point at loopback
    /// right now, and it is owed a restore even when nothing is redirected
    /// this time.
    ///
    /// What could not be redirected, an adapter or the whole redirect, is
    /// retried by the [`RedirectExtender`] without waiting for the network to
    /// change.
    ///
    /// # Errors
    ///
    /// [`RedirectError::RecordUnreadable`] when the record of an earlier
    /// redirect could not be read. Nothing changes then, and nothing is
    /// retried: a fresh capture could take adapters an earlier run left on
    /// loopback for their originals.
    pub async fn redirect(&mut self, ipv6: bool) -> Result<RedirectOutcome, RedirectError> {
        self.stop_restoring().await;
        let recovered = self
            .host
            .load_record()
            .map_err(RedirectError::RecordUnreadable)?;
        if recovered.is_some() && !self.shared.applied() {
            warn!("recovered saved DNS state from previous unclean shutdown");
        }
        let outcome = if self.can_redirect() {
            match self.redirect_os_dns(ipv6, recovered.as_deref()).await {
                Some(RedirectCoverage::Complete) => RedirectOutcome::Complete,
                Some(RedirectCoverage::Partial) => RedirectOutcome::Partial,
                None => RedirectOutcome::Failed,
            }
        } else {
            warn!("DNS resolver started but OS DNS not redirected — run elevated");
            RedirectOutcome::NotPermitted
        };
        if let Some(recovered) = recovered {
            if !self.shared.applied() {
                self.owe_recovered_restore(recovered);
            }
        }
        Ok(outcome)
    }

    /// Points adapter DNS at the loopback listener, returning how much of it
    /// was, or `None` when none was.
    ///
    /// `recovered` is a snapshot an earlier run left recorded, to reuse.
    async fn redirect_os_dns(
        &mut self,
        ipv6: bool,
        recovered: Option<&str>,
    ) -> Option<RedirectCoverage> {
        let recovering = recovered.is_some();
        let redirect = Arc::clone(&self.shared);
        let _changes = redirect.lock_changes().await;
        // A redirect the previous stack was still waiting to make is this
        // start's to make now.
        redirect.cancel_pending();
        // IPv6 is redirected only when [::1]:53 is actually being served.
        // Pointing adapters at a socket nothing is listening on would turn
        // an IPv6 DNS leak into an IPv6 DNS outage.
        if !ipv6 {
            warn!(
                "IPv6 DNS listener unavailable; adapter IPv6 DNS left pointing upstream \
                 and will not be filtered"
            );
        }

        // The originals of every adapter this start may change must be on disk
        // before any of them changes: a crash in between would otherwise
        // leave adapters on loopback with nothing to restore. So the plan is
        // captured, persisted, and then applied as it stands; an adapter
        // that appears after the plan is left for the extender.
        let durable = self.persist_redirect_plan(ipv6, recovered).await;

        // Redirect what the plan records. The plan is recorded first, in the
        // same job, so a stop reverses whatever the write changes even if it
        // fails partway or never reports back, and a start cancelled mid-call
        // still leaves the redirect for `Drop` to find and restore.
        let redirected = if let Some(plan) = durable.as_ref().map(|plan| plan.snapshot.clone()) {
            let job = Arc::clone(&redirect);
            let host = self.host.clone();
            blocking_os(move || {
                let _os = job.lock_os();
                // Boot recovery restores the recorded plan after an unclean
                // shutdown, so it is armed before the adapters it covers
                // change.
                host.arm_boot_recovery();
                job.record(plan.clone());
                let applied = (host.backend.apply)(ipv6, &plan)?;
                if applied.snapshot != plan {
                    job.record(applied.snapshot.clone());
                }
                Some(applied)
            })
            .await
            .flatten()
        } else {
            None
        };

        let coverage = redirected.as_ref().map(|applied| applied.coverage);
        if let Some(applied) = &redirected {
            // What was redirected is the plan, less only legacy entries whose
            // adapter went away, so the plan on disk already covers it if this
            // write fails.
            if durable.as_ref().map(|plan| &plan.snapshot) != Some(&applied.snapshot) {
                if let Err(error) = self.host.save_record(&applied.snapshot) {
                    warn!(%error, "failed to persist the final dns redirect state");
                }
            }
        }

        if coverage.is_none() && durable.is_some() && !recovering {
            // The write failed, but it may have changed some adapters first,
            // as a script stopped at its timeout can. Restoring the plan puts
            // back whatever it changed, then settles the redirect and clears
            // the snapshot on disk. A restore that cannot be confirmed leaves
            // the redirect owed to the stop, like any other.
            if let Err(error) = self.restore_off_runtime().await {
                if error.is_retryable() {
                    warn!("a failed DNS redirect could not be confirmed undone; adapter DNS will be restored when the resolver stops");
                }
            }
        }

        if !self.shared.applied() {
            // Nothing is redirected, as when the resolver starts at boot
            // before any adapter is up. The extender makes the redirect once
            // there is an adapter to redirect: on the transition that brings
            // one, or on a retry.
            self.shared.want();
            self.shared.defer_extension();
        } else if coverage != Some(RedirectCoverage::Complete)
            || durable.as_ref().is_some_and(|plan| !plan.complete)
        {
            // Adapters the plan could not cover, adapters the redirect did not
            // reach, and a redirect that is owed but did not apply, are
            // retried by the extender without waiting for the network to
            // change.
            self.shared.defer_extension();
        }

        match coverage {
            Some(RedirectCoverage::Complete) if ipv6 => {
                info!("OS DNS redirected to 127.0.0.1 and ::1 on all changed devices");
            }
            Some(RedirectCoverage::Complete) => {
                info!("OS DNS redirected to 127.0.0.1 (IPv4 only) on all changed devices");
            }
            Some(RedirectCoverage::Partial) => {
                warn!(
                    "OS DNS redirected to the loopback stub on some adapters only; \
                     retrying the rest in the background"
                );
            }
            None => {
                warn!("failed to redirect OS DNS to loopback stub; retrying in the background");
            }
        }
        coverage
    }

    /// Captures the redirect plan, `recovered` plus the originals of any
    /// adapter it does not cover, and persists it. Returns the plan now on
    /// disk.
    ///
    /// A `recovered` snapshot is already persisted: if the larger plan cannot
    /// be captured or written, `recovered` alone is returned, marked
    /// incomplete, so only adapters it records are redirected and the rest
    /// are retried. `None`, leaving DNS alone, when nothing durable can be
    /// had.
    async fn persist_redirect_plan(
        &self,
        ipv6: bool,
        recovered: Option<&str>,
    ) -> Option<DurablePlan> {
        let prior = recovered.map(str::to_owned);
        let plan_redirect = self.host.backend.plan;
        let planned = blocking_os(move || plan_redirect(ipv6, prior.as_deref()))
            .await
            .flatten();
        let Some(plan) = planned else {
            if let Some(recovered) = recovered {
                warn!("could not capture adapter DNS; only adapters recorded by the last run are redirected, and the rest are retried");
                return Some(DurablePlan::recovered(recovered));
            }
            warn!("could not capture adapter DNS; OS DNS not redirected");
            return None;
        };
        if recovered == Some(plan.as_str()) {
            return Some(DurablePlan::complete(plan));
        }
        match (self.host.save_record(&plan), recovered) {
            (Ok(()), _) => Some(DurablePlan::complete(plan)),
            (Err(error), Some(recovered)) => {
                warn!(%error, "could not persist the DNS of adapters added since the last run; they are not redirected yet, and are retried");
                Some(DurablePlan::recovered(recovered))
            }
            (Err(error), None) => {
                error!(%error, "could not persist adapter DNS before redirecting; OS DNS not redirected");
                None
            }
        }
    }

    /// Arms the restore of a snapshot recovered from an unclean shutdown that
    /// this start did not redirect over.
    ///
    /// Adapters may still point at loopback from the previous run, so the
    /// snapshot is owed even though nothing was redirected now: without it,
    /// [`Self::restore`] would skip the restore and the resolver would stop
    /// serving the only listener those adapters can reach. The snapshot is
    /// already persisted.
    fn owe_recovered_restore(&self, recovered: String) {
        self.shared.record(recovered);
    }

    /// What extends this redirect to adapters that come up later, and retries
    /// what [`Self::redirect`] could not do. `None` when this process may not
    /// change system DNS, so has nothing to extend.
    #[must_use]
    pub fn extender(&self, ipv6: bool) -> Option<RedirectExtender> {
        self.can_redirect()
            .then(|| RedirectExtender::new(Arc::clone(&self.shared), self.host.clone(), ipv6))
    }

    /// Restores system DNS if a redirect is in place or owed.
    ///
    /// A redirect still waiting to be made is cancelled, and one an extension
    /// is still making finishes first and is restored too.
    ///
    /// The restore and its settling are one blocking job. A caller that gives
    /// up waiting, such as a shutdown deadline, does not stop it: it finishes
    /// and settles on its own, and `Drop` then finds nothing left to restore.
    ///
    /// # Errors
    ///
    /// [`RedirectError::RestoreNotConfirmed`] when the restore was not
    /// confirmed: the redirect and its record are kept, for a later
    /// [`Self::restore`], [`Self::keep_restoring`] or
    /// [`Self::finish_failed_restore`]. [`RedirectError::RecordNotCleared`]
    /// when DNS was restored but its record could not be cleared; the next
    /// start restores again from it.
    pub async fn restore(&mut self) -> Result<(), RedirectError> {
        // Nothing may make a redirect the stopping resolver was waiting for.
        self.shared.cancel_pending();
        self.revert().await
    }

    /// Restores the redirect when one is in place.
    async fn revert(&self) -> Result<(), RedirectError> {
        let redirect = Arc::clone(&self.shared);
        let _changes = redirect.lock_changes().await;
        if !redirect.applied() {
            return Ok(());
        }
        self.restore_off_runtime().await
    }

    /// Undoes a redirect an earlier run left recorded, or this one's own, when
    /// the resolver is not started to take it over: it is disabled, or it
    /// failed to start. Succeeds at once when nothing is recorded.
    ///
    /// # Errors
    ///
    /// [`RedirectError::RecordUnreadable`] when the record cannot be read,
    /// and the errors of [`Self::restore`]. A restore that is not confirmed
    /// is then retried in the background.
    pub async fn restore_if_dirty(&mut self) -> Result<(), RedirectError> {
        self.stop_restoring().await;
        if !self.shared.applied() {
            let recorded = self
                .host
                .load_record()
                .map_err(RedirectError::RecordUnreadable)?;
            let Some(recorded) = recorded else {
                return Ok(());
            };
            self.shared.record(recorded);
        }

        warn!("restoring DNS adapter settings from previous redirect");
        let restored = self.revert().await;
        if restored.as_ref().is_err_and(RedirectError::is_retryable) {
            self.keep_restoring();
        }
        restored
    }

    /// Keeps retrying a restore that was not confirmed, in the background and
    /// backing off, until one is, or [`Self::stop_restoring`] or a new
    /// [`Self::redirect`] ends it. For when no resolver is left serving the
    /// adapters still pointed at it.
    pub fn keep_restoring(&mut self) {
        self.restore_retry = Some(RestoreRetry::start(
            Arc::clone(&self.shared),
            self.host.clone(),
        ));
    }

    /// Ends the background restore retry, waiting for a restore it is making.
    ///
    /// The retry is kept across a cancelled wait, so the next call still
    /// joins it.
    pub async fn stop_restoring(&mut self) {
        if let Some(retry) = self.restore_retry.as_mut() {
            retry.stop().await;
        }
        self.restore_retry = None;
    }

    /// Makes the last restore attempt after a [`Self::restore`] that failed.
    ///
    /// Without this the attempt would come from `Drop`, detached, and the
    /// caller would report the stop as failed even when that restore landed.
    /// Once the restore job has started, `Drop` does not repeat it: the job
    /// finishes and settles even if this future is cancelled.
    ///
    /// # Errors
    ///
    /// Those of [`Self::restore`].
    pub async fn finish_failed_restore(&mut self) -> Result<(), RedirectError> {
        self.stop_restoring().await;
        let redirect = Arc::clone(&self.shared);
        let _changes = redirect.lock_changes().await;
        if !redirect.applied() {
            return Ok(());
        }
        self.restore_on_drop = false;
        self.restore_off_runtime().await
    }

    /// Runs [`Self::restore_job`] off the runtime and waits for it. A job that
    /// panicked restored nothing anyone confirmed.
    async fn restore_off_runtime(&self) -> Result<(), RedirectError> {
        blocking_os(self.restore_job())
            .await
            .unwrap_or(Err(RedirectError::RestoreNotConfirmed))
    }

    /// A blocking job that restores and settles the redirect; see
    /// [`restore_redirect`]. It owns what it needs, so it can outlive `self`.
    fn restore_job(&self) -> impl FnOnce() -> Result<(), RedirectError> + Send + 'static {
        let redirect = Arc::clone(&self.shared);
        let host = self.host.clone();
        move || restore_redirect(&redirect, &host)
    }
}

#[cfg(any(test, feature = "test-support"))]
impl DnsRedirect {
    /// A redirect made through `backend`, as a test makes one.
    #[must_use]
    pub fn with_backend(
        store: Arc<Store>,
        data_dir: &Path,
        arm_boot_recovery: bool,
        backend: RedirectBackend,
    ) -> Self {
        Self::with_host(Host::new(store, data_dir, backend, arm_boot_recovery))
    }

    /// Replaces the OS calls, as a test does to fail or observe them. An
    /// extender already handed out keeps the calls it was made with.
    pub fn set_backend(&mut self, backend: RedirectBackend) {
        self.host.backend = backend;
    }

    /// Whether system DNS is, or may still be, pointed at the resolver, and
    /// so is owed a restore.
    #[must_use]
    pub fn is_applied(&self) -> bool {
        self.shared.applied()
    }

    /// Records `snapshot` as a redirect in place, as one an earlier run left,
    /// without changing system DNS.
    pub fn assume_redirected(&mut self, snapshot: impl Into<String>) {
        self.shared.record(snapshot.into());
    }

    /// The snapshot a restore writes back, or `None` while no redirect is in
    /// place.
    #[must_use]
    pub fn snapshot(&self) -> Option<String> {
        self.shared.snapshot()
    }
}

impl Drop for DnsRedirect {
    fn drop(&mut self) {
        self.restore_retry = None;
        // Always try a restore while we still can. A timed-out stop is
        // cancelled mid-flight; this is the last chance before a reboot
        // leaves adapters pointed at loopback. The restore runs off the
        // runtime: inline, it would hold up the worker dropping the timed-out
        // future, and the shutdown deadline with it. Under the OS gate it also
        // waits for an extension or a cancelled restore still in its OS call.
        //
        // Cancelling a wanted redirect and checking for one in place are one
        // step, so a first redirect an aborted extension left writing is
        // either restored here or never written.
        if self.shared.cancel_pending() && self.restore_on_drop {
            let job = self.restore_job();
            // The restore logs what it could not do, and the record keeps it
            // owed to the next launch.
            run_off_runtime(move || {
                let _ = job();
            });
        }
    }
}

/// A redirect plan that is on disk.
struct DurablePlan {
    snapshot: String,
    /// Whether it covers every adapter there was. A plan that fell back to
    /// the recovered snapshot leaves adapters added since to an extension.
    complete: bool,
}

impl DurablePlan {
    const fn complete(snapshot: String) -> Self {
        Self {
            snapshot,
            complete: true,
        }
    }

    fn recovered(recovered: &str) -> Self {
        Self {
            snapshot: recovered.to_owned(),
            complete: false,
        }
    }
}

#[cfg(test)]
mod tests;
