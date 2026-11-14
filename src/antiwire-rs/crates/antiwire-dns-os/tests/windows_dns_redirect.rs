//! Elevated Windows integration test for DNS redirect lifecycle.
#![cfg(windows)]

use antiwire_dns_os::windows::{
    apply_redirect, capture_state, is_elevated, plan_redirect, redirect_capturing, restore,
};

/// Always attempt recovery even if redirect or a later assertion fails.
struct RestoreOnDrop {
    saved: String,
    restored: bool,
}

impl RestoreOnDrop {
    fn restore(&mut self) -> bool {
        self.restored = restore(&self.saved);
        self.restored
    }
}

impl Drop for RestoreOnDrop {
    fn drop(&mut self) {
        if !self.restored && !restore(&self.saved) {
            eprintln!(
                "DNS test cleanup failed; saved adapter state: {}",
                self.saved
            );
        }
    }
}

/// Reads adapter DNS again, independently of what `restore` reported, and
/// checks it matches what was captured before the redirect.
fn assert_adapters_match(saved: &str) {
    let after = capture_state().expect("adapter DNS captured after restore");
    assert_eq!(
        after, saved,
        "adapter DNS after restore differs from before the redirect"
    );
}

#[test]
#[ignore = "requires elevated Windows shell and modifies adapter DNS settings"]
fn elevated_capture_redirect_and_restore() {
    assert!(
        is_elevated(),
        "run this ignored test from an elevated Windows shell"
    );

    let saved = capture_state().expect("adapter DNS captured");
    assert_ne!(saved, "");
    let mut recovery = RestoreOnDrop {
        saved: saved.clone(),
        restored: false,
    };

    assert!(redirect_capturing(false, "").is_some());
    assert!(recovery.restore());
    assert_adapters_match(&saved);
}

/// The dual-stack redirect the interceptor performs when `[::1]:53` is served.
/// Restore has to put both address families back, or IPv6 DNS stays on `::1`
/// after shutdown with nothing listening there.
#[test]
#[ignore = "requires elevated Windows shell and modifies adapter DNS settings"]
fn elevated_dual_stack_redirect_and_restore() {
    assert!(
        is_elevated(),
        "run this ignored test from an elevated Windows shell"
    );

    let saved = capture_state().expect("adapter DNS captured");
    assert_ne!(saved, "");
    let mut recovery = RestoreOnDrop {
        saved: saved.clone(),
        restored: false,
    };

    assert!(redirect_capturing(true, "").is_some());
    assert!(recovery.restore());
    assert_adapters_match(&saved);
}

/// The daemon's order: plan, persist, apply. Applying the plan's snapshot
/// must be reversible by restoring that same plan.
#[test]
#[ignore = "requires elevated Windows shell and modifies adapter DNS settings"]
fn elevated_planned_redirect_restores_from_the_plan() {
    assert!(
        is_elevated(),
        "run this ignored test from an elevated Windows shell"
    );

    let saved = capture_state().expect("adapter DNS captured");
    let plan = plan_redirect(true, "").expect("plan");
    let mut recovery = RestoreOnDrop {
        saved: plan.clone(),
        restored: false,
    };

    assert!(apply_redirect(true, &plan).is_some());
    assert!(recovery.restore());
    assert_adapters_match(&saved);
}

/// An adapter missing from the plan is never changed: a plan recording no
/// adapter redirects nothing.
#[test]
#[ignore = "requires elevated Windows shell and modifies adapter DNS settings"]
fn elevated_empty_plan_changes_no_adapter() {
    assert!(
        is_elevated(),
        "run this ignored test from an elevated Windows shell"
    );

    let saved = capture_state().expect("adapter DNS captured");
    let mut recovery = RestoreOnDrop {
        saved: saved.clone(),
        restored: false,
    };

    assert_eq!(apply_redirect(true, "[]"), None);
    assert_adapters_match(&saved);
    recovery.restored = true;
}
