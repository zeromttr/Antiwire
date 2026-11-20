//! Builds the shared AI coordinator from persisted daemon settings.
//!
//! The daemon never relies on the classifier's environment-based `connect()`:
//! the client is built from the saved credentials with the existing builder.
//! The endpoint comes from [`antiwire_ai::endpoint`]; its DNS resolution uses
//! the narrow bootstrap path (no AI classification, normal policy still enforced).

use std::sync::Arc;

use antiwire_store::{DomainDecision, Store};

use crate::ai::classifier::SharedClassifier;
use crate::ai::decision;
use crate::ai::{AiBackendClassifier, AiCoordinator, AiPolicySnapshot};

/// All synchronous work needed to apply one AI settings snapshot.
///
/// The lifecycle path builds this value on a blocking thread, then publishes it
/// to the running stub without reading the store or constructing an HTTP client
/// on a Tokio worker.
#[derive(Clone)]
pub(crate) struct AiRuntimeConfig {
    pub(crate) policy: AiPolicySnapshot,
    pub(crate) classifier: Option<SharedClassifier>,
    pub(crate) bootstrap_host: Option<String>,
}

/// Hostname of the endpoint the AI backend connects to.
///
/// Resolving this host must skip AI classification (while preserving policy
/// enforcement) so the provider lookup cannot wait on itself.
fn ai_bootstrap_host() -> Option<String> {
    let endpoint = url::Url::parse(&antiwire_ai::endpoint()).ok()?;
    crate::ai::canonical_ai_key(endpoint.host_str()?)
}

/// A new classification of a domain that already has a saved row, judged by
/// the saved AI settings.
///
/// Scores, model, verdict, and `updated_at` come from `assessment`. The domain
/// key and `first_seen` stay on `existing`.
#[must_use]
pub fn refreshed_decision(
    existing: &DomainDecision,
    assessment: &antiwire_ai::DomainAssessment,
    settings: &antiwire_store::DaemonSetting,
    now: time::OffsetDateTime,
) -> DomainDecision {
    decision::refreshed_decision(
        existing,
        assessment,
        &AiPolicySnapshot::from_settings(settings, 0),
        now,
    )
}

/// Same replacement as [`refreshed_decision`], marked as an advanced check
/// and carrying its registration signals.
#[must_use]
pub fn advanced_decision(
    existing: &DomainDecision,
    advanced: &antiwire_ai::AdvancedAssessment,
    settings: &antiwire_store::DaemonSetting,
    now: time::OffsetDateTime,
) -> DomainDecision {
    decision::advanced_decision(
        existing,
        advanced,
        &AiPolicySnapshot::from_settings(settings, 0),
        now,
    )
}

/// Applies a saved verdict moving from `previous` to `next`.
///
/// A block starting or ending changes what the resolver should answer; see
/// [`forget_cached_answers`](crate::forget_cached_answers).
pub fn apply_verdict_change(previous: &str, next: &str) {
    if verdict_changes_enforcement(previous, next) {
        crate::forget_cached_answers();
    }
}

fn verdict_changes_enforcement(previous: &str, next: &str) -> bool {
    previous != next && (previous == "block" || next == "block")
}

/// Builds a classifier from saved credentials, if AI is enabled.
pub(crate) fn build_classifier_from_settings(
    settings: &antiwire_store::DaemonSetting,
) -> Result<Option<AiBackendClassifier>, String> {
    if !settings.ai_enabled {
        return Ok(None);
    }
    let api_key = settings.ai_api_key.as_str().unwrap_or_default().to_owned();
    AiBackendClassifier::from_settings(&api_key, antiwire_tuning::DNS_AI_BACKGROUND_TIMEOUT)
        .map(Some)
}

/// Builds the runtime AI state from one already-loaded settings snapshot.
///
/// An enabled but unusable configuration is an error so callers can report it
/// and install an unavailable classifier, preserving saved proactive decisions
/// while unknown domains fail open.
pub(crate) fn build_runtime_config(
    settings: &antiwire_store::DaemonSetting,
) -> Result<AiRuntimeConfig, String> {
    let policy = AiPolicySnapshot::from_settings(settings, 0);
    let classifier = build_classifier_from_settings(settings)?
        .map(|classifier| Arc::new(classifier) as SharedClassifier);
    Ok(AiRuntimeConfig {
        policy,
        classifier,
        bootstrap_host: ai_bootstrap_host(),
    })
}

/// Runtime state to use when AI configuration cannot be constructed.
///
/// Keep the policy enabled so saved ratings remain enforceable in proactive
/// mode; the coordinator treats the missing classifier as unavailable and
/// fails open only for domains without a saved decision.
#[must_use]
pub(crate) fn unavailable_runtime_config(
    settings: &antiwire_store::DaemonSetting,
) -> AiRuntimeConfig {
    AiRuntimeConfig {
        policy: AiPolicySnapshot::from_settings(settings, 0),
        classifier: None,
        bootstrap_host: ai_bootstrap_host(),
    }
}

/// Builds a coordinator from the store's current settings, if AI is enabled.
///
/// Returns `None` only when AI is disabled or the settings cannot be read. An
/// enabled configuration with an unavailable client still gets a coordinator
/// so saved proactive decisions remain enforceable.
#[must_use]
pub(crate) fn build_coordinator_from_store(store: Arc<Store>) -> Option<Arc<AiCoordinator>> {
    let settings = match store.get_settings() {
        Ok(settings) => settings,
        Err(error) => {
            tracing::error!(
                %error,
                "could not read settings; saved AI verdicts are not enforced until DNS restarts"
            );
            return None;
        }
    };
    if !settings.ai_enabled {
        return None;
    }
    let runtime = match build_runtime_config(&settings) {
        Ok(runtime) => runtime,
        Err(error) => {
            tracing::warn!(error = %error, "AI classifier configuration unavailable; saved decisions remain active");
            unavailable_runtime_config(&settings)
        }
    };
    Some(AiCoordinator::new(
        store,
        runtime.classifier,
        &runtime.policy,
        runtime.bootstrap_host,
    ))
}

/// True when the settings produce a different AI configuration: the
/// credentials, or the policy [`AiPolicySnapshot::from_settings`] builds.
///
/// Comparing the built policy rather than listing fields means a category
/// setting it starts reading is picked up here too.
#[must_use]
pub(crate) fn ai_config_changed(
    prev: &antiwire_store::DaemonSetting,
    next: &antiwire_store::DaemonSetting,
) -> bool {
    prev.ai_api_key != next.ai_api_key
        || AiPolicySnapshot::from_settings(prev, 0) != AiPolicySnapshot::from_settings(next, 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deleting_a_block_needs_a_resolver_flush() {
        assert!(verdict_changes_enforcement("block", ""));
        assert!(!verdict_changes_enforcement("record", ""));
        assert!(!verdict_changes_enforcement("", ""));
    }

    #[test]
    fn bootstrap_host_comes_from_the_ai_endpoint() {
        assert!(ai_bootstrap_host().is_some());
    }

    #[test]
    fn ai_config_change_detects_mode_and_thresholds() {
        let prev = antiwire_store::DaemonSetting::default();
        let mut next = prev.clone();
        assert!(!ai_config_changed(&prev, &next));
        next.ai_decision_mode = "proactive".to_owned();
        assert!(ai_config_changed(&prev, &next));

        // Every category setting the policy reads counts, with no list to
        // keep in step with the settings model.
        let mut threshold = prev.clone();
        threshold.ai_confidence_tunnel += 1;
        assert!(ai_config_changed(&prev, &threshold));
        let mut action = prev.clone();
        action.ai_cryptomining_action = "block".to_owned();
        assert!(ai_config_changed(&prev, &action));

        // A value the policy clamps away is not a change.
        let mut clamped = prev.clone();
        clamped.ai_confidence_fraud = 100;
        let mut beyond = prev.clone();
        beyond.ai_confidence_fraud = 150;
        assert!(!ai_config_changed(&clamped, &beyond));
        let mut below = prev.clone();
        below.ai_confidence_fraud = 40;
        let mut floor = prev.clone();
        floor.ai_confidence_fraud = antiwire_store::MIN_AI_CONFIDENCE;
        assert!(!ai_config_changed(&below, &floor));
    }

    #[test]
    fn enabled_settings_with_empty_credentials_are_unavailable() {
        let settings = antiwire_store::DaemonSetting {
            ai_enabled: true,
            ..Default::default()
        };
        let result = build_runtime_config(&settings);
        let Err(error) = result else {
            panic!("empty credentials must not use process environment fallback");
        };
        assert!(error.contains("API key is empty"));

        let unavailable = unavailable_runtime_config(&settings);
        assert!(unavailable.policy.enabled);
        assert!(unavailable.classifier.is_none());
    }

    #[tokio::test]
    async fn unavailable_replacement_clears_old_client_but_keeps_saved_blocks() {
        use crate::ai::classifier::test_helpers::{assessment_for, MockClassifier};
        use crate::ai::decision::{AiCategorySetting, AiDecisionMode};
        use crate::ai::AiCoordinator;
        use antiwire_store::DomainDecision;
        use time::OffsetDateTime;

        let (_dir, store) = crate::test_support::temp_store();
        let mut categories = [AiCategorySetting {
            id: "advertising",
            enabled: false,
            threshold_percent: 80,
            block: false,
        }; 8];
        categories[4] = AiCategorySetting {
            id: "malicious",
            enabled: true,
            threshold_percent: 80,
            block: true,
        };
        let policy = AiPolicySnapshot {
            enabled: true,
            mode: AiDecisionMode::Proactive,
            categories,
            generation: 0,
        };
        let classifier = MockClassifier::with_assessment(
            "unknown.example",
            assessment_for("unknown.example", 0.99),
        );
        let coordinator = AiCoordinator::new(
            Arc::clone(&store),
            Some(classifier.clone()),
            &policy.clone(),
            None,
        );
        let now = OffsetDateTime::now_utc();
        store
            .upsert_domain_decision(&DomainDecision {
                domain: "saved.example".to_owned(),
                model: "mock".to_owned(),
                rating_advertising: 0.0,
                rating_tracking: 0.0,
                rating_telemetry: 0.0,
                rating_analytics: 0.0,
                rating_malicious: 0.99,
                rating_fraud: 0.0,
                rating_cryptomining: 0.0,
                rating_tunnel: 0.0,
                verdict: "block".to_owned(),
                top_category: "malicious".to_owned(),
                top_score: 0.99,
                rating_newly_registered: 0.0,
                rating_registry_hold: 0.0,
                rating_hidden_registrant: 0.0,
                rating_abusive_registrar: 0.0,
                scan_tier: "basic".to_owned(),
                first_seen: now,
                updated_at: now,
            })
            .expect("save decision");

        coordinator.update_config(&policy, None, None);
        assert!(matches!(
            coordinator
                .proactive_gate("saved.example", std::time::Duration::from_secs(2))
                .await,
            crate::ai::coordinator::ProactiveOutcome::Block(_)
        ));
        assert!(matches!(
            coordinator
                .proactive_gate("unknown.example", std::time::Duration::from_secs(2))
                .await,
            crate::ai::coordinator::ProactiveOutcome::Proceed
        ));
        assert_eq!(classifier.call_count(), 0);
        coordinator.shutdown().await;
    }
}
