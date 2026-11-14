//! Rules changed outside Antiwire, reported by the service itself.

use std::time::Duration;

use antiwire_events::AlertKind;
use antiwire_policy::{TargetType, Verdict};

use super::{harness, rule};

#[tokio::test]
async fn drift_found_during_a_change_is_reported_once() {
    let mut h = harness();
    h.firewall.drift(&["Antiwire rule 7"]);

    h.service
        .add_rule(&rule(TargetType::Dns, "blocked.test", Verdict::Block))
        .expect("add");

    let alert = h.alerts.recv().await.expect("drift alert");
    assert_eq!(alert.kind, AlertKind::FirewallRuleDrift);
    assert!(alert.message.contains("Antiwire rule 7"));

    h.service
        .add_rule(&rule(TargetType::Dns, "other.test", Verdict::Block))
        .expect("add");
    assert!(
        tokio::time::timeout(Duration::from_millis(50), h.alerts.recv())
            .await
            .is_err(),
        "each name is reported once"
    );
}

#[tokio::test]
async fn listing_rules_has_no_side_effects() {
    // Reading the rules used to drain drift and raise alerts.
    let mut h = harness();
    h.firewall.drift(&["Antiwire rule 7"]);

    h.service.list().expect("list");

    assert!(
        tokio::time::timeout(Duration::from_millis(50), h.alerts.recv())
            .await
            .is_err()
    );
}
