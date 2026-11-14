use std::sync::atomic::{AtomicUsize, Ordering};

use super::*;
use crate::rule::{RuleSnapshot, TargetType, Verdict};
use crate::{normalize_rule, RuleDirection};

/// Minimal implementation providing only the trait's required method, the
/// shape an external integrator would write. Guards the single-pass
/// contract: derived methods must never re-run the primitive.
struct CountingPolicy {
    evaluations: AtomicUsize,
}

impl PolicyEngine for CountingPolicy {
    fn evaluate_domain_with_source(&self, domain: &str) -> Option<DomainDecision> {
        self.evaluations.fetch_add(1, Ordering::Relaxed);
        (domain == "blocked.test").then_some(DomainDecision {
            verdict: Verdict::Block,
            source: Some(DomainBlockSource::DnsRule),
        })
    }
}

#[test]
fn derived_domain_methods_run_a_single_evaluation() {
    let policy = CountingPolicy {
        evaluations: AtomicUsize::new(0),
    };

    // Each public view costs exactly one primitive call.
    assert_eq!(policy.evaluate_domain("blocked.test"), Some(Verdict::Block));
    assert_eq!(policy.evaluations.load(Ordering::Relaxed), 1);
    assert_eq!(
        policy
            .evaluate_domain_with_source("blocked.test")
            .and_then(|decision| decision.source),
        Some(DomainBlockSource::DnsRule)
    );
    assert_eq!(policy.evaluations.load(Ordering::Relaxed), 2);

    assert_eq!(policy.evaluate_domain("clear.test"), None);
    assert_eq!(policy.evaluations.load(Ordering::Relaxed), 3);

    // The normalized variant defaults to the same primitive.
    assert_eq!(
        policy.evaluate_normalized_domain_with_source("blocked.test"),
        Some(DomainDecision {
            verdict: Verdict::Block,
            source: Some(DomainBlockSource::DnsRule),
        })
    );
    assert_eq!(policy.evaluations.load(Ordering::Relaxed), 4);

    // Attribution defaults preserve source compatibility for test doubles.
    assert_eq!(
        policy.matching_normalized_blocklists("blocked.test"),
        [] as [String; 0]
    );
}

#[test]
fn ruleengine_trait_surface_matches_the_inherent_single_pass() {
    let mut engine = RuleEngine::new();
    let block = normalize_rule(
        TargetType::Dns,
        "blocked.example",
        Verdict::Block,
        RuleDirection::Outbound,
    )
    .expect("dns rule");
    let _ = engine.upsert_rule(RuleSnapshot { id: 1, ..block });

    // Fully-qualified calls exercise the trait surface; inherent methods
    // would otherwise shadow them on the concrete type.
    let decision =
        <RuleEngine as PolicyEngine>::evaluate_domain_with_source(&engine, "blocked.example");
    assert_eq!(
        decision,
        Some(DomainDecision {
            verdict: Verdict::Block,
            source: Some(DomainBlockSource::DnsRule),
        })
    );
    assert_eq!(
        <RuleEngine as PolicyEngine>::evaluate_domain(&engine, "blocked.example"),
        Some(Verdict::Block)
    );
    assert_eq!(
        <RuleEngine as PolicyEngine>::evaluate_normalized_domain_with_source(
            &engine,
            "blocked.example"
        ),
        decision
    );
    assert_eq!(
        <RuleEngine as PolicyEngine>::evaluate_domain_with_source(&engine, "clear.example"),
        None
    );
}
