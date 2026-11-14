use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use antiwire_dns_os::{AppliedRedirect, RedirectCoverage};
use antiwire_store::Store;

use super::{DnsRedirect, RedirectOutcome};
use crate::test_support::{far_future, restoring, temp_store};
use crate::{RedirectBackend, RedirectError};

/// A backend that may redirect, and plans `wifi` unless an earlier redirect
/// left a snapshot to reuse.
fn redirecting(apply: fn(bool, &str) -> Option<AppliedRedirect>) -> RedirectBackend {
    RedirectBackend {
        can_redirect: || true,
        plan: |_, prior| Some(prior.unwrap_or("wifi").to_owned()),
        apply,
        ..RedirectBackend::INERT
    }
}

#[allow(clippy::unnecessary_wraps)]
fn apply_all(_: bool, plan: &str) -> Option<AppliedRedirect> {
    Some(AppliedRedirect::complete(plan))
}

fn recorded(store: &Store) -> Option<String> {
    store.get_dns_redirect().expect("record")
}

fn journal_in(dir: &std::path::Path) -> bool {
    dir.join("dns-redirect-state.json").exists()
}

#[tokio::test]
async fn a_complete_redirect_is_recorded_and_leaves_nothing_to_retry() {
    let (dir, store) = temp_store();
    let mut redirect = DnsRedirect::with_backend(
        Arc::clone(&store),
        dir.path(),
        false,
        redirecting(apply_all),
    );

    let outcome = redirect.redirect(true).await.expect("redirect");

    assert_eq!(outcome, RedirectOutcome::Complete);
    assert_eq!(redirect.snapshot().as_deref(), Some("wifi"));
    assert_eq!(recorded(&store).as_deref(), Some("wifi"));
    assert!(!redirect.shared.extension_due_at(far_future()));
}

/// The regression this guards: a start that redirected some adapters and
/// failed on others counted as complete, so nothing retried the others.
#[tokio::test]
async fn a_partial_redirect_at_start_is_retried() {
    let (dir, store) = temp_store();
    let mut redirect = DnsRedirect::with_backend(
        Arc::clone(&store),
        dir.path(),
        false,
        redirecting(|_, plan| {
            Some(AppliedRedirect {
                snapshot: plan.to_owned(),
                coverage: RedirectCoverage::Partial,
            })
        }),
    );

    let outcome = redirect.redirect(true).await.expect("redirect");

    assert_eq!(outcome, RedirectOutcome::Partial);
    assert!(redirect.is_applied());
    assert!(redirect.shared.extension_due_at(far_future()));
    assert!(redirect.extender(true).is_some());
}

/// A write that fails may have changed some adapters first, so the plan is
/// restored at once, and the redirect is left for the extender to make.
#[tokio::test]
async fn a_failed_redirect_at_start_is_undone_and_wanted() {
    static RESTORES: AtomicUsize = AtomicUsize::new(0);
    let (dir, store) = temp_store();
    let mut redirect = DnsRedirect::with_backend(
        Arc::clone(&store),
        dir.path(),
        false,
        RedirectBackend {
            restore: |snapshot| {
                assert_eq!(snapshot, "wifi");
                RESTORES.fetch_add(1, Ordering::SeqCst);
                true
            },
            ..redirecting(|_, _| None)
        },
    );

    let outcome = redirect.redirect(true).await.expect("redirect");

    assert_eq!(outcome, RedirectOutcome::Failed);
    assert_eq!(RESTORES.load(Ordering::SeqCst), 1);
    assert!(!redirect.is_applied());
    assert_eq!(recorded(&store), None);
    assert!(redirect.shared.extension_due_at(far_future()));
    assert!(
        redirect.shared.claim("wifi"),
        "the redirect is still wanted"
    );
}

/// Adapters may still point at loopback from an earlier run, so a snapshot
/// that run left is owed a restore even when this one may redirect nothing.
/// The redirect finds it in its own record.
#[tokio::test]
async fn a_recorded_snapshot_is_owed_a_restore_without_a_new_redirect() {
    let (dir, store) = temp_store();
    store
        .set_dns_redirect("recovered snapshot")
        .expect("record");
    let mut redirect = DnsRedirect::with_backend(
        Arc::clone(&store),
        dir.path(),
        false,
        restoring(|snapshot| snapshot == "recovered snapshot"),
    );

    let outcome = redirect.redirect(true).await.expect("redirect");

    assert_eq!(outcome, RedirectOutcome::NotPermitted);
    assert!(redirect.extender(true).is_none());
    assert_eq!(redirect.snapshot().as_deref(), Some("recovered snapshot"));
    redirect
        .restore()
        .await
        .expect("the recovered snapshot is restored");
    assert!(!redirect.is_applied());
    assert_eq!(recorded(&store), None);
}

/// The regression this guards: `redirect` left a background restore
/// running, and its next pass found the new redirect in place and restored
/// it, leaving the resolver serving with system DNS no longer pointed at it.
#[tokio::test]
async fn a_new_redirect_stops_a_background_restore_first() {
    let (dir, store) = temp_store();
    let mut redirect = DnsRedirect::with_backend(
        Arc::clone(&store),
        dir.path(),
        false,
        RedirectBackend {
            restore: |_| false,
            ..redirecting(apply_all)
        },
    );
    redirect.assume_redirected("wifi");
    assert!(redirect
        .restore()
        .await
        .is_err_and(|error| error.is_retryable()));
    redirect.keep_restoring();

    let outcome = redirect.redirect(true).await.expect("redirect");

    assert!(
        redirect.restore_retry.is_none(),
        "the background restore is stopped before anything is redirected"
    );
    assert_eq!(outcome, RedirectOutcome::Complete);
    assert_eq!(recorded(&store).as_deref(), Some("wifi"));
}

/// The journal goes to the data directory the caller names, where recovery
/// of a dead daemon reads it, not to wherever the database happens to be.
#[tokio::test]
async fn the_journal_is_kept_in_the_named_data_directory() {
    let (store_dir, store) = temp_store();
    let data_dir = tempfile::tempdir().expect("data dir");
    let mut redirect = DnsRedirect::with_backend(
        Arc::clone(&store),
        data_dir.path(),
        false,
        RedirectBackend {
            restore: |_| true,
            ..redirecting(apply_all)
        },
    );

    redirect.redirect(true).await.expect("redirect");
    assert!(journal_in(data_dir.path()));
    assert!(!journal_in(store_dir.path()));

    redirect.restore().await.expect("restore");
    assert!(!journal_in(data_dir.path()));
}

#[tokio::test]
async fn restore_if_dirty_reports_an_unconfirmed_restore_and_keeps_retrying() {
    let (dir, store) = temp_store();
    store.set_dns_redirect("adapter snapshot").expect("record");
    let mut redirect =
        DnsRedirect::with_backend(Arc::clone(&store), dir.path(), false, restoring(|_| false));

    let result = redirect.restore_if_dirty().await;

    assert!(matches!(result, Err(RedirectError::RestoreNotConfirmed)));
    assert!(
        redirect.restore_retry.is_some(),
        "retried in the background"
    );
    assert_eq!(redirect.snapshot().as_deref(), Some("adapter snapshot"));
    assert_eq!(recorded(&store).as_deref(), Some("adapter snapshot"));
    redirect.set_backend(restoring(|_| true));
    redirect.stop_restoring().await;
    redirect.restore().await.expect("cleanup");
}

#[tokio::test]
async fn restore_if_dirty_without_a_recorded_redirect_changes_nothing() {
    let (dir, store) = temp_store();
    let mut redirect = DnsRedirect::with_backend(
        Arc::clone(&store),
        dir.path(),
        false,
        restoring(|_| panic!("nothing is recorded as redirected")),
    );
    redirect
        .restore_if_dirty()
        .await
        .expect("nothing to restore");
    assert!(!redirect.is_applied());
}

/// The last attempt after a failed restore is awaited, so its outcome is the
/// caller's to report, and `Drop` does not repeat it.
#[tokio::test]
async fn a_failed_restore_is_finished_once_and_not_repeated_on_drop() {
    static RESTORES: AtomicUsize = AtomicUsize::new(0);
    fn fails_once(_: &str) -> bool {
        RESTORES.fetch_add(1, Ordering::SeqCst) > 0
    }
    let (dir, store) = temp_store();
    let mut redirect =
        DnsRedirect::with_backend(Arc::clone(&store), dir.path(), false, restoring(fails_once));
    redirect.assume_redirected("adapter snapshot");

    assert!(redirect.restore().await.is_err());
    redirect
        .finish_failed_restore()
        .await
        .expect("the second attempt lands");
    drop(redirect);
    // Long enough for a detached restore from `Drop`, had one started.
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(RESTORES.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn a_redirect_dropped_in_place_is_restored_off_the_runtime() {
    static RESTORES: AtomicUsize = AtomicUsize::new(0);
    let (dir, store) = temp_store();
    store.set_dns_redirect("adapter snapshot").expect("record");
    let mut redirect = DnsRedirect::with_backend(
        Arc::clone(&store),
        dir.path(),
        false,
        restoring(|_| {
            RESTORES.fetch_add(1, Ordering::SeqCst);
            true
        }),
    );
    redirect.assume_redirected("adapter snapshot");

    drop(redirect);

    let deadline = Instant::now() + Duration::from_secs(10);
    while recorded(&store).is_some() {
        assert!(
            Instant::now() < deadline,
            "the dropped redirect was never restored"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(RESTORES.load(Ordering::SeqCst), 1);
}
