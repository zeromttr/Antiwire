//! Shared helpers for OS DNS backends.
//!
//! [`plan_redirect`] and [`apply_redirect`] are the capture-then-redirect
//! pattern used by macOS and the Windows PowerShell fallback. Linux plans its
//! single resolver file itself, and the native Windows path keeps its own
//! per-adapter merge logic.

use crate::{AppliedRedirect, RedirectCoverage};

/// Plan, then apply, in one call, for callers that hold no durable record.
#[cfg(any(windows, target_os = "macos", test))]
pub(crate) fn redirect_capturing(
    redirect_v6: bool,
    prior_saved_json: &str,
    capture_state: impl FnOnce() -> Option<String>,
    add_new: impl FnOnce(&str, &str) -> String,
    redirect: impl FnOnce(bool, &str) -> Option<RedirectCoverage>,
    flush_cache: impl FnOnce(),
) -> Option<AppliedRedirect> {
    let plan = plan_redirect(prior_saved_json, capture_state, add_new)?;
    apply_redirect(redirect_v6, &plan, redirect, flush_cache)
}

/// The snapshot a redirect must be able to reverse, captured before anything
/// changes. The caller persists it, then calls [`apply_redirect`].
///
/// When `prior_saved_json` is empty, this is the current capture, so a first
/// redirect does not record loopback as the original. A failed capture
/// refuses the redirect rather than persisting an empty snapshot that restore
/// would later apply.
///
/// A prior snapshot, even a persisted `"[]"`, is never replaced: adapters it
/// covers may already point at `127.0.0.1` / `::1`, and recapturing them would
/// record that loopback as the "original". `add_new` instead adds what the
/// current capture holds for adapters the prior does not cover.
///
/// `None` whenever the capture fails, even with a prior snapshot. Applying
/// the prior alone would be safe, since [`apply_redirect`] changes only what
/// a plan records, but it would hide that adapters added since were neither
/// recorded nor redirected. `None` tells the caller to try again later.
#[cfg(any(windows, target_os = "macos", test))]
pub(crate) fn plan_redirect(
    prior_saved_json: &str,
    capture_state: impl FnOnce() -> Option<String>,
    add_new: impl FnOnce(&str, &str) -> String,
) -> Option<String> {
    let current = capture_state()?;
    Some(if prior_saved_json.trim().is_empty() {
        current
    } else {
        add_new(prior_saved_json, &current)
    })
}

/// Redirects what `plan` records to loopback, and returns `plan` as the
/// snapshot restore reverses, with how much of it `redirect` reached.
///
/// `redirect` receives the plan and must change nothing it does not record:
/// an adapter that appeared after the plan was captured has no original on
/// disk yet, and waits for a later plan. It returns `None` when it changed
/// nothing.
pub(crate) fn apply_redirect(
    redirect_v6: bool,
    plan: &str,
    redirect: impl FnOnce(bool, &str) -> Option<RedirectCoverage>,
    flush_cache: impl FnOnce(),
) -> Option<AppliedRedirect> {
    let coverage = redirect(redirect_v6, plan)?;
    flush_cache();
    Some(AppliedRedirect {
        snapshot: plan.to_owned(),
        coverage,
    })
}

#[cfg(test)]
mod tests {
    use super::{apply_redirect, redirect_capturing};
    use crate::{AppliedRedirect, RedirectCoverage};
    use std::sync::atomic::{AtomicBool, Ordering};

    #[allow(clippy::unnecessary_wraps)]
    fn all(_: bool, _: &str) -> Option<RedirectCoverage> {
        Some(RedirectCoverage::Complete)
    }

    fn snapshot(applied: Option<AppliedRedirect>) -> Option<String> {
        applied.map(|applied| applied.snapshot)
    }

    /// The regression this guards: a redirect that changed some adapters and
    /// failed on others reported plain success, so the caller stopped
    /// retrying and the others stayed unfiltered.
    #[test]
    fn a_partial_redirect_is_reported_as_partial() {
        let flushed = AtomicBool::new(false);
        let applied = apply_redirect(
            false,
            "plan",
            |_, _| Some(RedirectCoverage::Partial),
            || flushed.store(true, Ordering::SeqCst),
        )
        .expect("some adapters were redirected");
        assert_eq!(applied.snapshot, "plan");
        assert_eq!(applied.coverage, RedirectCoverage::Partial);
        assert!(!applied.is_complete());
        assert!(
            flushed.load(Ordering::SeqCst),
            "the adapters that did change are flushed"
        );

        let applied = apply_redirect(false, "plan", all, || {}).expect("redirected");
        assert!(applied.is_complete());
    }

    fn keep_prior(prior: &str, _current: &str) -> String {
        prior.to_owned()
    }

    #[test]
    fn failed_redirect_does_not_yield_a_snapshot() {
        let flushed = AtomicBool::new(false);
        let result = redirect_capturing(
            false,
            "[]",
            || Some(r#"[{"InterfaceAlias":"Wi-Fi"}]"#.to_owned()),
            keep_prior,
            |_, _| None,
            || flushed.store(true, Ordering::SeqCst),
        );
        assert_eq!(result, None);
        assert!(
            !flushed.load(Ordering::SeqCst),
            "cache must not be flushed when redirect failed"
        );
    }

    #[test]
    fn failed_capture_refuses_to_redirect() {
        let redirected = AtomicBool::new(false);
        let result = redirect_capturing(
            false,
            "",
            || None,
            keep_prior,
            |_, _| {
                redirected.store(true, Ordering::SeqCst);
                Some(RedirectCoverage::Complete)
            },
            || {},
        );
        assert_eq!(result, None);
        assert!(
            !redirected.load(Ordering::SeqCst),
            "redirect must not run without a real snapshot to reverse it"
        );
    }

    #[test]
    fn successful_redirect_preserves_prior_snapshot() {
        let prior =
            r#"[{"InterfaceAlias":"Wi-Fi","AddressFamily":2,"Dhcp":false,"Servers":["8.8.8.8"]}]"#;
        let flushed = AtomicBool::new(false);
        let result = redirect_capturing(
            true,
            prior,
            || Some(r#"[{"InterfaceAlias":"Wi-Fi","Servers":["127.0.0.1"]}]"#.to_owned()),
            keep_prior,
            all,
            || flushed.store(true, Ordering::SeqCst),
        );
        assert_eq!(snapshot(result).as_deref(), Some(prior));
        assert!(flushed.load(Ordering::SeqCst));
    }

    #[test]
    fn a_prior_snapshot_gains_what_the_current_capture_adds() {
        let result = redirect_capturing(
            false,
            "prior",
            || Some("current".to_owned()),
            |prior, current| format!("{prior}+{current}"),
            all,
            || {},
        );
        assert_eq!(snapshot(result).as_deref(), Some("prior+current"));
    }

    /// The redirect is handed the plan it must stay within, not left to find
    /// adapters on its own.
    #[test]
    fn the_redirect_receives_the_plan() {
        let result = redirect_capturing(
            true,
            "prior",
            || Some("current".to_owned()),
            |prior, current| format!("{prior}+{current}"),
            |redirect_v6, plan| {
                (redirect_v6 && plan == "prior+current").then_some(RedirectCoverage::Complete)
            },
            || {},
        );
        assert_eq!(snapshot(result).as_deref(), Some("prior+current"));
    }

    /// The regression this guards: a failed recapture fell back to the prior
    /// snapshot and the redirect went ahead, reaching an adapter connected
    /// since, such as a VPN, with no original recorded for it.
    #[test]
    fn a_failed_recapture_refuses_the_redirect() {
        let redirected = AtomicBool::new(false);
        let result = redirect_capturing(
            false,
            "prior",
            || None,
            |_, _| panic!("nothing to add without a capture"),
            |_, _| {
                redirected.store(true, Ordering::SeqCst);
                Some(RedirectCoverage::Complete)
            },
            || {},
        );
        assert_eq!(result, None);
        assert!(!redirected.load(Ordering::SeqCst));
    }

    #[test]
    fn successful_redirect_captures_when_no_prior_snapshot() {
        let captured = r#"[{"InterfaceAlias":"Ethernet"}]"#;
        let result = redirect_capturing(
            false,
            "",
            || Some(captured.to_owned()),
            |_, _| panic!("no prior to add to"),
            all,
            || {},
        );
        assert_eq!(snapshot(result).as_deref(), Some(captured));
    }

    #[test]
    fn empty_array_prior_is_kept() {
        let result = redirect_capturing(
            false,
            "[]",
            || Some(r#"[{"InterfaceAlias":"Wi-Fi","Servers":["127.0.0.1"]}]"#.to_owned()),
            keep_prior,
            all,
            || {},
        );
        assert_eq!(snapshot(result).as_deref(), Some("[]"));
    }
}
