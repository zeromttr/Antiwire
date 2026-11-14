use antiwire_store::{DomainDecision, DomainDecisionQuery};
use time::macros::datetime;

use super::{AiDecisionError, AiDecisionService, Scan};
use crate::lookup_fakes::LookupHarness;

fn saved(domain: &str, verdict: &str) -> DomainDecision {
    let seen = datetime!(2026-01-01 00:00 UTC);
    DomainDecision {
        domain: domain.to_owned(),
        model: "mock".to_owned(),
        rating_advertising: 0.2,
        rating_tracking: 0.0,
        rating_telemetry: 0.0,
        rating_analytics: 0.0,
        rating_malicious: 0.0,
        rating_fraud: 0.0,
        rating_cryptomining: 0.0,
        rating_tunnel: 0.0,
        verdict: verdict.to_owned(),
        top_category: "advertising".to_owned(),
        top_score: 0.2,
        rating_newly_registered: 0.0,
        rating_registry_hold: 0.0,
        rating_hidden_registrant: 0.0,
        rating_abusive_registrar: 0.0,
        scan_tier: "basic".to_owned(),
        first_seen: seen,
        updated_at: seen,
    }
}

fn service(h: &LookupHarness) -> AiDecisionService {
    AiDecisionService::new(&h.context, &h.clients)
}

#[tokio::test]
async fn reclassifying_needs_a_domain_a_saved_row_and_an_api_key() {
    let h = LookupHarness::new(0.9);
    let decisions = service(&h);
    for scan in [Scan::Basic, Scan::Advanced] {
        assert!(matches!(
            decisions.reclassify("  ", scan).await,
            Err(AiDecisionError::EmptyDomain)
        ));
        assert!(matches!(
            decisions.reclassify("missing.example", scan).await,
            Err(AiDecisionError::NotFound)
        ));
    }

    h.context
        .store
        .upsert_domain_decision(&saved("ads.example", "record"))
        .expect("save");
    for scan in [Scan::Basic, Scan::Advanced] {
        assert!(matches!(
            decisions.reclassify("ads.example", scan).await,
            Err(AiDecisionError::NoApiKey)
        ));
    }
    assert_eq!(h.registry_calls(), 0, "the key is checked first");
}

#[tokio::test]
async fn a_basic_scan_replaces_the_scores_and_keeps_first_seen() {
    let h = LookupHarness::new(0.95);
    h.configure("sk-test", true);
    let original = saved("ads.example", "record");
    h.context
        .store
        .upsert_domain_decision(&original)
        .expect("save");

    let updated = service(&h)
        .reclassify("ADS.example.", Scan::Basic)
        .await
        .expect("reclassify");

    assert!((updated.rating_advertising - 0.95).abs() < f64::EPSILON);
    assert_eq!(updated.first_seen, original.first_seen);
    let stored = h
        .context
        .store
        .get_domain_decision("ads.example")
        .expect("read")
        .expect("row");
    assert!((stored.rating_advertising - 0.95).abs() < f64::EPSILON);
    assert_eq!(h.registry_calls(), 0, "a basic scan asks no registry");
}

#[tokio::test]
async fn an_advanced_scan_saves_the_registration_only_when_asked_to() {
    for save_domain_lookups in [false, true] {
        let h = LookupHarness::new(0.1);
        h.configure("sk-test", save_domain_lookups);
        h.context
            .store
            .upsert_domain_decision(&saved("ads.example", "record"))
            .expect("save");

        let updated = service(&h)
            .reclassify("ads.example", Scan::Advanced)
            .await
            .expect("reclassify");

        assert_eq!(updated.scan_tier, "advanced");
        assert!((updated.rating_hidden_registrant - 1.0).abs() < f64::EPSILON);
        assert_eq!(
            h.context
                .store
                .get_domain_lookup("ads.example")
                .expect("read")
                .is_some(),
            save_domain_lookups
        );
    }
}

#[tokio::test]
async fn a_failed_registry_lookup_leaves_the_decision_alone() {
    let h = LookupHarness::new(0.9);
    h.configure("sk-test", true);
    let original = saved("unregistered.example", "record");
    h.context
        .store
        .upsert_domain_decision(&original)
        .expect("save");

    assert!(matches!(
        service(&h)
            .reclassify("unregistered.example", Scan::Advanced)
            .await,
        Err(AiDecisionError::Registry(_))
    ));
    let kept = h
        .context
        .store
        .get_domain_decision("unregistered.example")
        .expect("read")
        .expect("row");
    assert_eq!(kept.scan_tier, "basic");
    assert!((kept.rating_advertising - original.rating_advertising).abs() < f64::EPSILON);
}

#[tokio::test]
async fn deleting_reports_whether_a_decision_existed() {
    let h = LookupHarness::new(0.9);
    let decisions = service(&h);
    h.context
        .store
        .upsert_domain_decision(&saved("ads.example", "block"))
        .expect("save");

    assert!(decisions.delete("ADS.EXAMPLE.").await.expect("delete"));
    assert!(!decisions.delete("ads.example").await.expect("again"));
    assert!(matches!(
        decisions.delete("   ").await,
        Err(AiDecisionError::EmptyDomain)
    ));
    let page = decisions
        .page(DomainDecisionQuery::default())
        .await
        .expect("page");
    assert_eq!(page.total_count, 0);
}
