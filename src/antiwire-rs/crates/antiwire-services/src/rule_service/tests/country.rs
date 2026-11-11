//! Country blocks.

use antiwire_policy::{EnforcementOp, RuleDirection, Verdict};

use super::{country, harness, is_country};
use crate::rule_service::{CountrySelector, RuleServiceError};

#[test]
fn invalid_codes_and_networks_are_refused_before_anything_is_saved() {
    let h = harness();

    for block in [
        country("K", &["175.45.176.0/22"]),
        country("K1", &["175.45.176.0/22"]),
        country("KP", &[]),
        country("KP", &["nonsense"]),
    ] {
        let error = h.service.add_country_rule(&block).expect_err("refused");
        assert!(matches!(error, RuleServiceError::Invalid(_)), "{error}");
    }
    assert!(h.store.list_rules().expect("rules").is_empty());
}

#[test]
fn a_country_is_saved_canonically_and_installed_as_one_op() {
    let h = harness();

    // Deliberately unsorted, with a duplicate and a bare address.
    let summary = h
        .service
        .add_country_rule(&country(
            "kp",
            &[
                "210.52.109.0/24",
                "175.45.176.0/22",
                "175.45.176.0/22",
                "175.45.180.1",
            ],
        ))
        .expect("add country");

    assert_eq!(summary.code, "KP");
    assert_eq!(summary.network_count, 3, "duplicates collapse");
    assert_eq!(summary.direction, RuleDirection::Both);
    assert_eq!(
        h.store.list_rule_cidrs(summary.id).expect("cidrs"),
        vec!["175.45.176.0/22", "175.45.180.1/32", "210.52.109.0/24"]
    );
    assert_eq!(h.engine.read().rule_count(), 1);
    assert!(matches!(
        h.firewall.applied().as_slice(),
        [EnforcementOp::AddCountryBlock {
            verdict: Verdict::Block,
            direction: RuleDirection::Both,
            ..
        }]
    ));
}

#[test]
fn a_country_already_blocked_is_a_conflict() {
    let h = harness();
    h.service
        .add_country_rule(&country("KP", &["175.45.176.0/22"]))
        .expect("first");

    let error = h
        .service
        .add_country_rule(&country("kp", &["175.45.176.0/22"]))
        .expect_err("duplicate");

    assert!(matches!(error, RuleServiceError::Conflict(_)));
    assert_eq!(h.store.list_rules().expect("rules").len(), 1);
}

#[test]
fn removing_a_country_clears_it_everywhere() {
    let h = harness();
    let summary = h
        .service
        .add_country_rule(&country("KP", &["175.45.176.0/22"]))
        .expect("add");

    assert!(h
        .service
        .remove_country_rule(&CountrySelector::Code("kp".to_owned()))
        .expect("remove"));

    assert!(h.store.list_rules().expect("rules").is_empty());
    assert!(h
        .store
        .list_rule_cidrs(summary.id)
        .expect("cidrs")
        .is_empty());
    assert_eq!(h.engine.read().rule_count(), 0);
    assert_eq!(
        h.engine.read().evaluate("app.exe", "175.45.176.5", ""),
        None
    );
    assert!(!h
        .service
        .remove_country_rule(&CountrySelector::Id(summary.id))
        .expect("second remove"));
}

#[test]
fn a_failed_firewall_removal_leaves_the_block_in_place() {
    let h = harness();
    let summary = h
        .service
        .add_country_rule(&country("KP", &["175.45.176.0/22"]))
        .expect("add");
    h.firewall.fail(1, is_country);

    let error = h
        .service
        .remove_country_rule(&CountrySelector::Id(summary.id))
        .expect_err("removal fails");

    assert!(!error.is_inconsistent(), "{error}");
    assert_eq!(h.store.list_rules().expect("rules").len(), 1);
    assert_eq!(
        h.engine.read().evaluate("app.exe", "175.45.176.5", ""),
        Some(Verdict::Block)
    );
}

#[test]
fn a_failed_removal_that_cannot_reinstall_says_so() {
    // Rollback failures used to be discarded, reporting only the first error
    // while the saved block was no longer enforced.
    let h = harness();
    let summary = h
        .service
        .add_country_rule(&country("KP", &["175.45.176.0/22"]))
        .expect("add");
    // The firewall removal succeeds, the row delete fails, and so does
    // putting the block back.
    let fault = rusqlite::Connection::open(h.store.path()).expect("second connection");
    fault
        .execute_batch(
            "CREATE TRIGGER refuse_delete BEFORE DELETE ON firewall_rules
             BEGIN SELECT RAISE(ABORT, 'scripted delete failure'); END;",
        )
        .expect("install fault");
    h.firewall
        .fail(1, |op| matches!(op, EnforcementOp::AddCountryBlock { .. }));

    let error = h
        .service
        .remove_country_rule(&CountrySelector::Id(summary.id))
        .expect_err("removal fails");

    assert!(error.is_inconsistent(), "{error}");
    assert!(
        error.to_string().contains(&format!(
            "the firewall rule for rule {} was not restored",
            summary.id
        )),
        "{error}"
    );
    assert_eq!(h.store.list_rules().expect("rules").len(), 1);
    assert_eq!(
        h.engine.read().rule_count(),
        1,
        "the engine still matches the saved rule"
    );
}
