//! Moving an application's rules to a new executable path.

use std::sync::Arc;

use antiwire_policy::{EnforcementOp, RuleEngine, Verdict};
use parking_lot::RwLock;

use super::{app, harness, is_add, Harness};
use crate::rule_service::classify::snapshots;
use crate::rule_service::RetargetOutcome;

const V1: &str = r"C:\Users\me\app-1.0\app.exe";
const V2: &str = r"C:\Users\me\app-2.0\app.exe";
const V3: &str = r"C:\Users\me\app-3.0\app.exe";

fn saved_targets(h: &Harness) -> Vec<String> {
    h.store
        .list_rules()
        .expect("rules")
        .into_iter()
        .map(|rule| rule.target_value)
        .collect()
}

#[test]
fn a_rule_and_its_enforcement_move_to_the_new_path() {
    let h = harness();
    let saved = h.service.add_rule(&app(V1, Verdict::Block)).expect("add");
    h.firewall.clear();

    let outcome = h
        .service
        .retarget_app_rules(V1, V2, true)
        .expect("retarget");

    assert_eq!(outcome.moved, 1);
    let rules = h.store.list_rules().expect("rules");
    assert_eq!(rules[0].id, saved.id, "the rule keeps its identity");
    assert_eq!(rules[0].target_value, r"c:\users\me\app-2.0\app.exe");
    assert_eq!(h.engine.read().evaluate(V2, "", ""), Some(Verdict::Block));
    assert_eq!(
        h.engine.read().evaluate(V1, "", ""),
        Some(Verdict::Block),
        "an older version directory is still the same application family"
    );
    let applied = h.firewall.applied();
    assert!(applied.iter().any(|op| matches!(
        op,
        EnforcementOp::RemoveAppRule { app_path, .. } if app_path.ends_with(r"app-1.0\app.exe")
    )));
    assert!(applied.iter().any(|op| matches!(
        op,
        EnforcementOp::AddAppRule { app_path, .. } if app_path.ends_with(r"app-2.0\app.exe")
    )));
}

#[test]
fn rules_left_on_older_versions_are_caught() {
    let h = harness();
    // The rule predates a skipped update: the app already moved to 2.0
    // while the rule still targets 1.0.
    h.service
        .add_rule(&app(V1, Verdict::Block))
        .expect("old block");
    h.service
        .add_rule(&app(r"C:\Users\me\Desktop\app.exe", Verdict::Block))
        .expect("unrelated block");

    let outcome = h
        .service
        .retarget_app_rules(V2, V3, true)
        .expect("retarget");

    assert_eq!(outcome.moved, 1, "only the family rule moves");
    let targets = saved_targets(&h);
    assert!(targets.contains(&r"c:\users\me\app-3.0\app.exe".to_owned()));
    assert!(
        targets.contains(&r"c:\users\me\desktop\app.exe".to_owned()),
        "a different install root is untouched"
    );
    assert_eq!(h.engine.read().evaluate(V3, "", ""), Some(Verdict::Block));
}

#[test]
fn precedence_matches_a_restart_after_the_move() {
    let h = harness();
    h.service
        .add_rule(&app(V1, Verdict::Block))
        .expect("older block");
    h.service
        .add_rule(&app(V2, Verdict::Allow))
        .expect("newer allow");
    assert_eq!(h.engine.read().evaluate(V3, "", ""), None);

    let outcome = h
        .service
        .retarget_app_rules(V2, V3, true)
        .expect("retarget");
    assert_eq!(
        outcome.moved, 2,
        "both family rules follow the current path"
    );

    let rules = h.store.list_rules().expect("rules");
    let networks = h.store.list_all_rule_cidrs().expect("networks");
    let (simple, countries) = snapshots(&rules, &networks);
    let restarted = Arc::new(RwLock::new(RuleEngine::new()));
    restarted.write().replace_user_rules(simple, countries);
    for path in [V1, V2, V3, r"C:\Users\me\app-4.0\app.exe"] {
        assert_eq!(
            h.engine.read().evaluate(path, "", ""),
            restarted.read().evaluate(path, "", ""),
            "runtime precedence diverges from a restart for {path}"
        );
    }
    assert_eq!(
        h.engine.read().evaluate(V3, "", ""),
        Some(Verdict::Allow),
        "the newer allow still wins after the move"
    );
}

#[test]
fn an_unverified_move_does_not_carry_allow_rules() {
    // An executable dropped into a new version folder of a user-writable
    // install used to have the application's allow rules moved onto it.
    let h = harness();
    h.service.add_rule(&app(V1, Verdict::Allow)).expect("allow");
    h.firewall.clear();

    let outcome = h
        .service
        .retarget_app_rules(V1, r"C:\Users\me\app-9.9\app.exe", false)
        .expect("retarget");

    assert_eq!(
        outcome,
        RetargetOutcome {
            moved: 0,
            held_allows: 1
        }
    );
    assert_eq!(saved_targets(&h), vec![r"c:\users\me\app-1.0\app.exe"]);
    assert_eq!(
        h.engine
            .read()
            .evaluate(r"C:\Users\me\app-9.9\app.exe", "", ""),
        None,
        "the unverified executable inherits nothing"
    );
    assert!(h.firewall.applied().is_empty());
}

#[test]
fn an_unverified_move_carries_an_effective_block_only() {
    // Carrying a block forward only restricts the new executable, so it
    // needs no publisher check, but it must not take an allow with it.
    let h = harness();
    h.service
        .add_rule(&app(V1, Verdict::Allow))
        .expect("older allow");
    h.service
        .add_rule(&app(V2, Verdict::Block))
        .expect("newer block");

    let outcome = h
        .service
        .retarget_app_rules(V2, V3, false)
        .expect("retarget");

    assert_eq!(
        outcome,
        RetargetOutcome {
            moved: 1,
            held_allows: 1
        }
    );
    assert_eq!(h.engine.read().evaluate(V3, "", ""), Some(Verdict::Block));
    assert!(saved_targets(&h).contains(&r"c:\users\me\app-1.0\app.exe".to_owned()));
}

#[test]
fn a_move_that_is_fully_undone_keeps_the_old_path() {
    let h = harness();
    h.service.add_rule(&app(V1, Verdict::Block)).expect("add");
    // Only the install at the new path fails; reinstalling the old one works.
    h.firewall.fail(1, is_add);

    let outcome = h
        .service
        .retarget_app_rules(V1, V2, true)
        .expect("a fully undone move is not an error");

    assert_eq!(outcome.moved, 0);
    assert_eq!(saved_targets(&h), vec![r"c:\users\me\app-1.0\app.exe"]);
    assert_eq!(h.engine.read().evaluate(V1, "", ""), Some(Verdict::Block));
}

#[test]
fn a_move_that_cannot_be_undone_is_reported() {
    let h = harness();
    let saved = h.service.add_rule(&app(V1, Verdict::Block)).expect("add");
    // The old rule comes out, then both the new install and reinstalling
    // the old one fail.
    h.firewall.fail(2, is_add);

    let error = h
        .service
        .retarget_app_rules(V1, V2, true)
        .expect_err("an unrestorable move must be surfaced");

    assert!(error.is_inconsistent(), "{error}");
    assert!(
        error.to_string().contains(&format!(
            "the firewall rule for rule {} was not restored",
            saved.id
        )),
        "{error}"
    );
    assert_eq!(
        saved_targets(&h),
        vec![r"c:\users\me\app-1.0\app.exe"],
        "the saved row is put back even though the firewall could not be"
    );
}
