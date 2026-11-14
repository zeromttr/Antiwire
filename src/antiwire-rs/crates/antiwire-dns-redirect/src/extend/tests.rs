use std::sync::{mpsc, Arc};
use std::time::{Duration, Instant};

use antiwire_dns_os::{AppliedRedirect, RedirectCoverage};
use antiwire_store::StoreError;
use antiwire_tuning::DNS_REDIRECT_EXTENSION_RETRY;

use super::{extend_now, extend_to_new_adapters};
use crate::restore::restore_redirect;
use crate::state::SharedRedirect;
use crate::test_support::{far_future, host, restoring, temp_store as store};

#[tokio::test]
async fn new_adapters_join_an_applied_redirect_and_its_persisted_snapshot() {
    let (_dir, store) = store();
    let redirect = Arc::new(SharedRedirect::default());
    redirect.record("wifi".to_owned());

    extend_to_new_adapters(
        Arc::clone(&redirect),
        host(&store, restoring(no_restore)),
        add_vpn,
        apply_plan,
    )
    .await;

    assert!(redirect.applied());
    assert_eq!(redirect.snapshot().as_deref(), Some("wifi+vpn"));
    assert_eq!(
        store.get_dns_redirect().expect("record").as_deref(),
        Some("wifi+vpn")
    );
}

#[allow(clippy::unnecessary_wraps)]
fn add_vpn(prior: Option<&str>) -> Option<String> {
    let prior = prior.expect("an extension plans on top of its redirect");
    Some(format!("{prior}+vpn"))
}

#[allow(clippy::unnecessary_wraps)]
fn apply_plan(plan: &str) -> Option<AppliedRedirect> {
    Some(AppliedRedirect::complete(plan))
}

/// An apply that redirects some adapters of `plan` and fails on others.
#[allow(clippy::unnecessary_wraps)]
fn apply_partly(plan: &str) -> Option<AppliedRedirect> {
    Some(AppliedRedirect {
        snapshot: plan.to_owned(),
        coverage: RedirectCoverage::Partial,
    })
}

/// The regression this guards: a new adapter was redirected first and its
/// original saved after, so a crash in between left it on loopback with
/// nothing to restore.
#[tokio::test]
async fn a_new_adapters_original_is_on_disk_before_it_is_redirected() {
    let (_dir, store) = store();
    let redirect = Arc::new(SharedRedirect::default());
    redirect.record("wifi".to_owned());
    let seen = Arc::clone(&store);

    extend_to_new_adapters(
        Arc::clone(&redirect),
        host(&store, restoring(no_restore)),
        add_vpn,
        move |plan| {
            assert_eq!(
                seen.get_dns_redirect().expect("record").as_deref(),
                Some("wifi+vpn"),
                "the plan must be persisted before any adapter changes"
            );
            Some(AppliedRedirect::complete(plan))
        },
    )
    .await;

    assert_eq!(redirect.snapshot().as_deref(), Some("wifi+vpn"));
}

/// The new adapters are in the record a clean stop restores before the
/// write starts, not only once it reports back.
#[tokio::test]
async fn a_new_adapters_original_is_recorded_before_it_is_redirected() {
    let (_dir, store) = store();
    let redirect = Arc::new(SharedRedirect::default());
    redirect.record("wifi".to_owned());
    let seen = Arc::clone(&redirect);

    extend_to_new_adapters(
        Arc::clone(&redirect),
        host(&store, restoring(no_restore)),
        add_vpn,
        move |plan| {
            assert_eq!(seen.snapshot().as_deref(), Some("wifi+vpn"));
            Some(AppliedRedirect::complete(plan))
        },
    )
    .await;

    assert!(!redirect.extension_due_at(far_future()));
}

/// The regression this guards: a redirect that failed, or changed some
/// adapters before it failed, left the new adapters out of the record, so
/// a clean stop restored only the old ones. Restoring an adapter that did
/// not change writes back what it already has, so keeping it is harmless.
#[tokio::test]
async fn a_failed_apply_keeps_the_new_adapters_owed_and_retries() {
    let (_dir, store) = store();
    let redirect = Arc::new(SharedRedirect::default());
    redirect.record("wifi".to_owned());

    extend_to_new_adapters(
        Arc::clone(&redirect),
        host(&store, restoring(no_restore)),
        add_vpn,
        |_| None,
    )
    .await;

    assert!(redirect.applied());
    assert_eq!(redirect.snapshot().as_deref(), Some("wifi+vpn"));
    assert_eq!(
        store.get_dns_redirect().expect("record").as_deref(),
        Some("wifi+vpn")
    );
    assert!(redirect.extension_due_at(far_future()));
}

/// The regression this guards: a failed recapture went ahead with the
/// prior snapshot, and the redirect reached adapters connected since with
/// no original recorded. Now nothing is applied, and the extension is
/// retried even if the network does not change again.
#[tokio::test]
async fn a_failed_capture_changes_nothing_and_retries() {
    let (_dir, store) = store();
    let redirect = Arc::new(SharedRedirect::default());
    redirect.record("wifi".to_owned());

    extend_to_new_adapters(
        Arc::clone(&redirect),
        host(&store, restoring(no_restore)),
        |_| None,
        |_| panic!("nothing may change without a captured plan"),
    )
    .await;

    assert_eq!(redirect.snapshot().as_deref(), Some("wifi"));
    assert_eq!(store.get_dns_redirect().expect("record"), None);
    assert!(!redirect.extension_due(), "the first retry waits a tick");
    assert!(redirect.extension_due_at(far_future()));
}

/// The regression this guards: when the new adapters' originals could
/// not be persisted, the prior snapshot was applied instead, and on a
/// backend that redirects every adapter that reached the new ones too.
#[test]
fn a_failed_persist_changes_nothing_and_retries() {
    let redirect = SharedRedirect::default();
    redirect.record("wifi".to_owned());

    extend_now(
        &redirect,
        |_| Err(StoreError::Database("disk full".to_owned())),
        add_vpn,
        |_| panic!("nothing may change before the plan is on disk"),
        never_undone,
    );

    assert_eq!(redirect.snapshot().as_deref(), Some("wifi"));
    assert!(redirect.extension_due_at(far_future()));
}

/// A retry that finishes clears the schedule, and a plan with nothing new
/// re-applies the record without persisting it again.
#[test]
fn a_retry_that_finishes_is_settled() {
    let redirect = SharedRedirect::default();
    redirect.record("wifi".to_owned());
    assert!(redirect.defer_extension());

    extend_now(
        &redirect,
        |_| panic!("an unchanged plan is already on disk"),
        |prior| prior.map(str::to_owned),
        |plan| Some(AppliedRedirect::complete(plan)),
        never_undone,
    );

    assert!(!redirect.extension_due_at(far_future()));
}

/// The regression this guards: an apply that redirected some adapters
/// and failed on others counted as done, so the retry was cleared and
/// the others stayed unfiltered until the network next changed.
#[test]
fn a_partial_extension_is_retried() {
    let redirect = SharedRedirect::default();
    redirect.record("wifi".to_owned());

    extend_now(&redirect, |_| Ok(()), add_vpn, apply_partly, never_undone);

    assert_eq!(redirect.snapshot().as_deref(), Some("wifi+vpn"));
    assert!(redirect.extension_due_at(far_future()));

    extend_now(
        &redirect,
        |_| panic!("an unchanged plan is already on disk"),
        |prior| prior.map(str::to_owned),
        apply_plan,
        never_undone,
    );
    assert!(
        !redirect.extension_due_at(far_future()),
        "a retry that reaches every adapter is settled"
    );
}

/// A host where some adapter keeps refusing the redirect backs off like
/// any other failing extension, rather than retrying at the base delay.
#[test]
fn repeated_partial_redirects_back_off() {
    let redirect = SharedRedirect::default();
    redirect.record("wifi".to_owned());
    let unchanged = |prior: Option<&str>| prior.map(str::to_owned);

    extend_now(&redirect, |_| Ok(()), unchanged, apply_partly, never_undone);
    extend_now(&redirect, |_| Ok(()), unchanged, apply_partly, never_undone);

    let now = Instant::now();
    assert!(!redirect.extension_due_at(now + DNS_REDIRECT_EXTENSION_RETRY.base));
    assert!(redirect.extension_due_at(now + DNS_REDIRECT_EXTENSION_RETRY.base * 3));
}

/// A first redirect that reaches only some adapters is made, so nothing
/// is wanted any more, and the rest are retried as an extension of it.
#[test]
fn a_partial_first_redirect_is_made_and_retried() {
    let redirect = SharedRedirect::default();
    redirect.want();

    extend_now(
        &redirect,
        |_| Ok(()),
        |_| Some("wifi".to_owned()),
        apply_partly,
        never_undone,
    );

    assert!(redirect.applied());
    assert_eq!(redirect.snapshot().as_deref(), Some("wifi"));
    assert!(redirect.extension_due_at(far_future()));
    assert!(!redirect.claim("again"), "the redirect is made");
}

fn no_restore(_: &str) -> bool {
    panic!("only a failed first redirect is restored here")
}

fn never_undone() -> bool {
    panic!("only a failed first redirect is undone")
}

/// The regression this guards: a resolver that started at boot before any
/// adapter was up redirected nothing, and the watcher never tried again,
/// so adapter DNS went unfiltered until the next restart.
#[tokio::test]
async fn a_wanted_redirect_is_made_once_there_is_an_adapter() {
    let (_dir, store) = store();
    let redirect = Arc::new(SharedRedirect::default());
    redirect.want();
    redirect.defer_extension();

    extend_to_new_adapters(
        Arc::clone(&redirect),
        host(&store, restoring(no_restore)),
        |prior| {
            assert_eq!(prior, None, "a first redirect captures afresh");
            Some("wifi".to_owned())
        },
        |plan| Some(AppliedRedirect::complete(plan)),
    )
    .await;

    assert!(redirect.applied());
    assert_eq!(redirect.snapshot().as_deref(), Some("wifi"));
    assert_eq!(
        store.get_dns_redirect().expect("record").as_deref(),
        Some("wifi")
    );
    assert!(
        !redirect.extension_due_at(far_future()),
        "nothing left to retry"
    );
    assert!(
        !redirect.claim("again"),
        "nothing is wanted once it is made"
    );
}

#[tokio::test]
async fn a_redirect_nobody_wants_is_not_made() {
    let (_dir, store) = store();
    let redirect = Arc::new(SharedRedirect::default());

    extend_to_new_adapters(
        Arc::clone(&redirect),
        host(&store, restoring(no_restore)),
        |_| panic!("no redirect is wanted"),
        |_| panic!("no redirect is wanted"),
    )
    .await;

    assert!(!redirect.applied());
}

/// With no adapter to capture yet, nothing is written and the attempt is
/// retried, backing off from where it was.
#[test]
fn a_first_redirect_with_nothing_to_capture_is_retried() {
    let redirect = SharedRedirect::default();
    redirect.want();

    for _ in 0..2 {
        extend_now(
            &redirect,
            |_| panic!("nothing to persist"),
            |_| None,
            |_| panic!("nothing to apply"),
            never_undone,
        );
    }

    assert!(!redirect.applied());
    let now = Instant::now();
    assert!(!redirect.extension_due_at(now + DNS_REDIRECT_EXTENSION_RETRY.base));
    assert!(redirect.extension_due_at(now + DNS_REDIRECT_EXTENSION_RETRY.base * 3));
}

#[test]
fn a_first_redirect_that_cannot_be_persisted_writes_nothing() {
    let redirect = SharedRedirect::default();
    redirect.want();

    extend_now(
        &redirect,
        |_| Err(StoreError::Database("disk full".to_owned())),
        |_| Some("wifi".to_owned()),
        |_| panic!("nothing may change before the plan is on disk"),
        never_undone,
    );

    assert!(!redirect.applied());
    assert!(redirect.extension_due_at(far_future()));
    assert!(redirect.claim("wifi"), "the redirect is still wanted");
}

/// A first redirect that fails may have changed some adapters, so it is
/// restored at once; a restore that is confirmed leaves it wanted again.
#[tokio::test]
async fn a_failed_first_redirect_is_undone_and_retried() {
    static RESTORED: parking_lot::Mutex<Vec<String>> = parking_lot::Mutex::new(Vec::new());
    fn restore(snapshot: &str) -> bool {
        RESTORED.lock().push(snapshot.to_owned());
        true
    }

    let (_dir, store) = store();
    let redirect = Arc::new(SharedRedirect::default());
    redirect.want();

    extend_to_new_adapters(
        Arc::clone(&redirect),
        host(&store, restoring(restore)),
        |_| Some("wifi".to_owned()),
        |_| None,
    )
    .await;

    assert_eq!(*RESTORED.lock(), ["wifi"]);
    assert!(!redirect.applied());
    assert_eq!(store.get_dns_redirect().expect("record"), None);
    assert!(redirect.extension_due_at(far_future()));
    assert!(redirect.claim("wifi"), "the redirect is still wanted");
}

/// An undo that cannot be confirmed keeps the redirect owed, so the stop
/// restores it, and the retry goes on as an extension of it.
#[tokio::test]
async fn a_first_redirect_whose_undo_fails_stays_owed() {
    let (_dir, store) = store();
    let redirect = Arc::new(SharedRedirect::default());
    redirect.want();

    extend_to_new_adapters(
        Arc::clone(&redirect),
        host(&store, restoring(|_| false)),
        |_| Some("wifi".to_owned()),
        |_| None,
    )
    .await;

    assert!(redirect.applied());
    assert_eq!(redirect.snapshot().as_deref(), Some("wifi"));
    assert!(store.get_dns_redirect().expect("record").is_some());
    assert!(redirect.extension_due_at(far_future()));
}

/// A stop that cancels the wanted redirect before the first redirect
/// claims it leaves nothing written, even though the capture was taken.
#[tokio::test(flavor = "multi_thread")]
async fn a_first_redirect_cancelled_before_it_claims_writes_nothing() {
    let (_dir, store) = store();
    let redirect = Arc::new(SharedRedirect::default());
    redirect.want();
    let (started_tx, started) = mpsc::channel();
    let (release, release_rx) = mpsc::channel::<()>();
    let extension = tokio::spawn(extend_to_new_adapters(
        Arc::clone(&redirect),
        host(&store, restoring(no_restore)),
        move |_| {
            started_tx.send(()).expect("started");
            release_rx.recv().expect("released");
            Some("wifi".to_owned())
        },
        |_| panic!("a cancelled redirect must not be written"),
    ));
    started.recv().expect("the first redirect is capturing");

    assert!(!redirect.cancel_pending(), "nothing is in place to restore");
    release.send(()).expect("release");
    extension.await.expect("extension");

    assert!(!redirect.applied());
    assert_eq!(store.get_dns_redirect().expect("record"), None);
}

/// The race this guards: a stop that gave up the wanted redirect while a
/// first redirect was writing would see nothing applied and skip the
/// restore, leaving the adapters on a resolver that is gone. A claimed
/// redirect is owed, and the restore waits for the write to finish.
#[tokio::test(flavor = "multi_thread")]
async fn a_stop_during_a_first_redirect_restores_it() {
    static RESTORED: parking_lot::Mutex<Vec<String>> = parking_lot::Mutex::new(Vec::new());
    fn restore(snapshot: &str) -> bool {
        RESTORED.lock().push(snapshot.to_owned());
        true
    }

    let (_dir, store) = store();
    let redirect = Arc::new(SharedRedirect::default());
    redirect.want();
    let (started_tx, started) = mpsc::channel();
    let (release, release_rx) = mpsc::channel();
    let extension = tokio::spawn(extend_to_new_adapters(
        Arc::clone(&redirect),
        host(&store, restoring(no_restore)),
        |_| Some("wifi".to_owned()),
        held_extension(started_tx, release_rx),
    ));
    started.recv().expect("the first redirect is writing");

    assert!(
        redirect.cancel_pending(),
        "a claimed redirect is owed a restore"
    );
    let restore_handle = {
        let redirect = Arc::clone(&redirect);
        let store = Arc::clone(&store);
        std::thread::spawn(move || restore_redirect(&redirect, &host(&store, restoring(restore))))
    };
    std::thread::sleep(Duration::from_millis(100));
    assert!(
        RESTORED.lock().is_empty(),
        "the restore must wait for the write"
    );

    release.send(()).expect("release");
    extension.await.expect("extension");
    assert!(restore_handle.join().expect("restore").is_ok());
    assert_eq!(*RESTORED.lock(), ["wifi"]);
    assert!(!redirect.applied());
    assert_eq!(store.get_dns_redirect().expect("record"), None);
}

#[tokio::test]
async fn a_released_redirect_is_not_extended() {
    let (_dir, store) = store();
    let redirect = Arc::new(SharedRedirect::default());
    redirect.record("wifi".to_owned());
    redirect.release();

    extend_to_new_adapters(
        Arc::clone(&redirect),
        host(&store, restoring(no_restore)),
        |_| panic!("a restored redirect must not be planned again"),
        |_| panic!("a restored redirect must not be reapplied"),
    )
    .await;

    assert!(!redirect.applied());
    assert_eq!(store.get_dns_redirect().expect("record"), None);
}

/// An extension whose OS call is held until `release` is sent, after it
/// tells `started` it is under way.
fn held_extension(
    started: mpsc::Sender<()>,
    release: mpsc::Receiver<()>,
) -> impl FnOnce(&str) -> Option<AppliedRedirect> + Send + 'static {
    move |plan| {
        started.send(()).expect("started");
        release.recv().expect("released");
        Some(AppliedRedirect::complete(plan))
    }
}

/// The regression this guards: a shutdown restore ran while an extension
/// was still in its OS call. The extension then put the adapters back on
/// loopback after the restore had cleared the persisted redirect, so the
/// next launch had nothing to restore.
#[tokio::test(flavor = "multi_thread")]
async fn a_restore_waits_for_an_extension_in_its_os_call_and_reverses_it_too() {
    static RESTORED: parking_lot::Mutex<Vec<String>> = parking_lot::Mutex::new(Vec::new());
    fn restore(snapshot: &str) -> bool {
        RESTORED.lock().push(snapshot.to_owned());
        true
    }

    let (_dir, store) = store();
    let redirect = Arc::new(SharedRedirect::default());
    redirect.record("wifi".to_owned());
    let (started_tx, started) = mpsc::channel();
    let (release, release_rx) = mpsc::channel();
    let extension = tokio::spawn(extend_to_new_adapters(
        Arc::clone(&redirect),
        host(&store, restoring(no_restore)),
        add_vpn,
        held_extension(started_tx, release_rx),
    ));
    started.recv().expect("the extension is in its OS call");

    let restore_redirect_handle = {
        let redirect = Arc::clone(&redirect);
        let store = Arc::clone(&store);
        std::thread::spawn(move || restore_redirect(&redirect, &host(&store, restoring(restore))))
    };
    std::thread::sleep(Duration::from_millis(100));
    assert!(
        RESTORED.lock().is_empty(),
        "the restore must wait for the extension's OS call"
    );

    release.send(()).expect("release");
    extension.await.expect("extension");
    assert!(restore_redirect_handle.join().expect("restore").is_ok());
    assert_eq!(
        *RESTORED.lock(),
        ["wifi+vpn"],
        "the new adapter is restored too"
    );
    assert!(!redirect.applied());
    assert_eq!(store.get_dns_redirect().expect("record"), None);
}

/// Aborting the network watcher cancels the extension's task, not its OS
/// call. What that call changed must still be recorded and persisted.
#[tokio::test(flavor = "multi_thread")]
async fn an_aborted_extension_still_records_what_its_os_call_changed() {
    let (_dir, store) = store();
    let redirect = Arc::new(SharedRedirect::default());
    redirect.record("wifi".to_owned());
    let (started_tx, started) = mpsc::channel();
    let (release, release_rx) = mpsc::channel();
    let extension = tokio::spawn(extend_to_new_adapters(
        Arc::clone(&redirect),
        host(&store, restoring(no_restore)),
        add_vpn,
        move |_plan| {
            started_tx.send(()).expect("started");
            release_rx.recv().expect("released");
            // The call reports less than the plan, as when an adapter it
            // records went away. The plan was recorded before the call,
            // so only this result shows the call itself was recorded.
            Some(AppliedRedirect::complete("wifi+vpn-gone"))
        },
    ));
    started.recv().expect("the extension is in its OS call");

    extension.abort();
    assert!(extension.await.expect_err("aborted").is_cancelled());
    release.send(()).expect("release");

    let deadline = Instant::now() + Duration::from_secs(10);
    while store.get_dns_redirect().expect("record").as_deref() != Some("wifi+vpn-gone") {
        assert!(
            Instant::now() < deadline,
            "the extension was never recorded"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(redirect.applied());
    assert_eq!(redirect.snapshot().as_deref(), Some("wifi+vpn-gone"));
    assert!(store.get_dns_redirect().expect("record").is_some());
}
