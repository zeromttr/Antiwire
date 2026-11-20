//! Score-to-decision evaluation against current category settings.
//!
//! One canonical domain key is used throughout lookup, classification,
//! persistence, and concurrent-request coordination: lowercase ASCII without
//! a trailing dot.

use antiwire_store::{DaemonSetting, DomainDecision as StoredDecision, OutcomeRevision};
use time::OffsetDateTime;

/// Canonical AI domain key: lowercase ASCII without a trailing dot.
///
/// Returns `None` for empty names. This is the store's
/// [`antiwire_store::normalize_domain_key`], so equivalent names share one row.
#[must_use]
pub fn canonical_ai_key(domain: &str) -> Option<String> {
    antiwire_store::normalize_domain_key(domain).ok()
}

/// Whether a new classification waits on the lookup (`proactive`) or runs
/// after the answer (`retroactive`). A saved score still blocks the next
/// query in both modes when its category action is block.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum AiDecisionMode {
    Proactive,
    #[default]
    Retroactive,
}

impl AiDecisionMode {
    #[must_use]
    pub(crate) fn from_settings(mode: &str) -> Self {
        if mode.trim().eq_ignore_ascii_case("proactive") {
            Self::Proactive
        } else {
            Self::Retroactive
        }
    }

    #[must_use]
    pub(crate) const fn enforces(self) -> bool {
        matches!(self, Self::Proactive)
    }
}

/// Per-category policy: enablement, percentage threshold, block vs record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct AiCategorySetting {
    /// Category id (`advertising`, `tracking`, ... `tunnel`).
    pub id: &'static str,
    /// Whether the category participates at all.
    pub enabled: bool,
    /// Percentage threshold (60-100); score*100 must meet it.
    pub threshold_percent: i32,
    /// True when a qualifying score blocks. Record-only categories stay false.
    pub block: bool,
}

/// Snapshot of the AI policy governing one evaluation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct AiPolicySnapshot {
    pub enabled: bool,
    pub mode: AiDecisionMode,
    /// Eight categories in deterministic (`DomainUse::ALL`) order.
    pub categories: [AiCategorySetting; 8],
    /// Configuration generation; stale jobs must not enforce old settings.
    pub generation: u64,
}

impl AiPolicySnapshot {
    /// Builds the snapshot from daemon settings and a generation counter.
    #[must_use]
    pub(crate) fn from_settings(settings: &DaemonSetting, generation: u64) -> Self {
        let category = |id, enabled, confidence, action: &str| AiCategorySetting {
            id,
            enabled,
            threshold_percent: antiwire_store::clamp_ai_confidence(confidence),
            block: action == "block",
        };
        let categories = [
            category(
                "advertising",
                settings.ai_advertising_enabled,
                settings.ai_confidence_advertising,
                &settings.ai_advertising_action,
            ),
            category(
                "tracking",
                settings.ai_tracking_enabled,
                settings.ai_confidence_tracking,
                &settings.ai_tracking_action,
            ),
            category(
                "telemetry",
                settings.ai_telemetry_enabled,
                settings.ai_confidence_telemetry,
                &settings.ai_telemetry_action,
            ),
            category(
                "analytics",
                settings.ai_analytics_enabled,
                settings.ai_confidence_analytics,
                &settings.ai_analytics_action,
            ),
            category(
                "malicious",
                settings.ai_malicious_enabled,
                settings.ai_confidence_malicious,
                &settings.ai_malicious_action,
            ),
            category(
                "fraud",
                settings.ai_fraud_enabled,
                settings.ai_confidence_fraud,
                &settings.ai_fraud_action,
            ),
            category(
                "cryptomining",
                settings.ai_cryptomining_enabled,
                settings.ai_confidence_cryptomining,
                &settings.ai_cryptomining_action,
            ),
            category(
                "tunnel",
                settings.ai_tunnel_enabled,
                settings.ai_confidence_tunnel,
                &settings.ai_tunnel_action,
            ),
        ];
        Self {
            enabled: settings.ai_enabled,
            mode: AiDecisionMode::from_settings(&settings.ai_decision_mode),
            categories,
            generation,
        }
    }
}

/// Eight raw category scores (0.0-1.0 probabilities).
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) struct CategoryScores {
    pub scores: [f64; 8],
}

impl CategoryScores {
    #[cfg(test)]
    #[must_use]
    pub(crate) const fn new(scores: [f64; 8]) -> Self {
        Self { scores }
    }

    /// Scores from a stored decision row.
    #[must_use]
    pub(crate) fn from_stored(decision: &StoredDecision) -> Self {
        Self {
            scores: [
                decision.rating_advertising,
                decision.rating_tracking,
                decision.rating_telemetry,
                decision.rating_analytics,
                decision.rating_malicious,
                decision.rating_fraud,
                decision.rating_cryptomining,
                decision.rating_tunnel,
            ],
        }
    }

    /// Scores from a live classification.
    #[must_use]
    pub(crate) fn from_assessment(assessment: &antiwire_ai::DomainAssessment) -> Self {
        Self {
            scores: [
                assessment.advertising,
                assessment.tracking,
                assessment.telemetry,
                assessment.analytics,
                assessment.malicious,
                assessment.security_fraud,
                assessment.cryptomining,
                assessment.tunnel,
            ],
        }
    }

    /// Highest score across all categories (for observability on allows).
    #[must_use]
    pub(crate) fn max_score(&self) -> f64 {
        self.scores.iter().copied().fold(0.0_f64, f64::max)
    }
}

/// Outcome of evaluating scores against current settings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AiOutcome {
    /// A qualifying category is set to block.
    Block,
    /// Qualifying categories exist but none is set to block.
    Record,
    /// No enabled category met its threshold.
    Allow,
}

/// Deterministic evaluation of scores against the current policy.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct AiEvaluation {
    pub outcome: AiOutcome,
    /// Category responsible for the outcome; empty when none qualified.
    pub top_category: &'static str,
    pub top_score: f64,
}

impl AiEvaluation {
    /// Evaluates scores against the policy snapshot.
    ///
    /// - Disabled categories are ignored.
    /// - Scores are compared against configured percentage thresholds.
    /// - Any qualifying category whose action is block causes a block, in
    ///   both modes. Retroactive mode only delays that block until the next
    ///   query; it does not change this result.
    /// - Record-only categories never block by themselves.
    /// - The reported category is deterministic: highest qualifying score,
    ///   ties broken by category order.
    #[must_use]
    pub(crate) fn evaluate(scores: &CategoryScores, policy: &AiPolicySnapshot) -> Self {
        let mut best_qualifying: Option<(usize, f64)> = None;
        let mut best_block: Option<(usize, f64)> = None;
        let mut max_score: f64 = 0.0;

        for (index, category) in policy.categories.iter().enumerate() {
            if !category.enabled {
                continue;
            }
            let score = scores.scores.get(index).copied().unwrap_or(0.0);
            if score.is_nan() {
                continue;
            }
            max_score = max_score.max(score);
            let threshold = f64::from(category.threshold_percent) / 100.0;
            if score >= threshold {
                let better = |current: Option<(usize, f64)>| {
                    current.is_none_or(|(_, best_score)| score > best_score)
                };
                if better(best_qualifying) {
                    best_qualifying = Some((index, score));
                }
                if category.block && better(best_block) {
                    best_block = Some((index, score));
                }
            }
        }

        match best_qualifying {
            None => Self {
                outcome: AiOutcome::Allow,
                top_category: "",
                top_score: max_score,
            },
            Some((index, score)) => {
                if let Some((block_index, block_score)) = best_block {
                    return Self {
                        outcome: AiOutcome::Block,
                        top_category: policy.categories[block_index].id,
                        top_score: block_score,
                    };
                }
                Self {
                    outcome: AiOutcome::Record,
                    top_category: policy.categories[index].id,
                    top_score: score,
                }
            }
        }
    }

    /// Whether this evaluation requires blocking the current request.
    #[must_use]
    pub(crate) const fn should_block(&self) -> bool {
        matches!(self.outcome, AiOutcome::Block)
    }

    /// Verdict string for persistence (`block`, `record`, or an empty string).
    #[must_use]
    pub(crate) const fn verdict_str(&self) -> &'static str {
        match self.outcome {
            AiOutcome::Block => "block",
            AiOutcome::Record => "record",
            AiOutcome::Allow => "",
        }
    }

    /// Builds the store row for a successful classification.
    #[must_use]
    pub(crate) fn to_stored(
        &self,
        domain: &str,
        model: &str,
        scores: &CategoryScores,
        now: OffsetDateTime,
        first_seen: Option<OffsetDateTime>,
    ) -> StoredDecision {
        StoredDecision {
            domain: domain.to_owned(),
            model: model.to_owned(),
            rating_advertising: scores.scores[0],
            rating_tracking: scores.scores[1],
            rating_telemetry: scores.scores[2],
            rating_analytics: scores.scores[3],
            rating_malicious: scores.scores[4],
            rating_fraud: scores.scores[5],
            rating_cryptomining: scores.scores[6],
            rating_tunnel: scores.scores[7],
            verdict: self.verdict_str().to_owned(),
            top_category: self.top_category.to_owned(),
            top_score: self.top_score,
            rating_newly_registered: 0.0,
            rating_registry_hold: 0.0,
            rating_hidden_registrant: 0.0,
            rating_abusive_registrar: 0.0,
            scan_tier: "basic".to_owned(),
            first_seen: first_seen.unwrap_or(now),
            updated_at: now,
        }
    }
}

/// Rewrites saved verdicts so they match `policy`, using each row's stored scores.
///
/// Returns how many rows changed. Scores, `first_seen`, and `updated_at` stay
/// as classified. A disabled policy clears block verdicts; turning AI back on
/// restores them from the same scores.
///
/// Each page's changes are written in one transaction. A transaction per row
/// made a toggle of AI over twenty thousand saved domains take seconds.
pub(crate) fn recompute_saved_verdicts(
    store: &antiwire_store::Store,
    policy: &AiPolicySnapshot,
) -> Result<u64, String> {
    const PAGE: usize = 200;
    let mut changed = 0_u64;
    let mut after = String::new();
    loop {
        let page = store
            .list_domain_decisions_after(&after, PAGE)
            .map_err(|error| error.to_string())?;
        let Some(last) = page.last().map(|row| row.domain.clone()) else {
            break;
        };
        let revisions: Vec<OutcomeRevision<'_>> = page
            .iter()
            .filter_map(|decision| {
                let evaluation =
                    persisted_evaluation(&CategoryScores::from_stored(decision), policy);
                let unchanged = decision.verdict == evaluation.verdict_str()
                    && decision.top_category == evaluation.top_category
                    && (decision.top_score - evaluation.top_score).abs() <= f64::EPSILON;
                (!unchanged).then_some(OutcomeRevision {
                    domain: &decision.domain,
                    verdict: evaluation.verdict_str(),
                    top_category: evaluation.top_category,
                    top_score: evaluation.top_score,
                })
            })
            .collect();
        if !revisions.is_empty() {
            changed += store
                .revise_domain_decision_outcomes(&revisions)
                .map_err(|error| error.to_string())?;
        }
        if page.len() < PAGE {
            break;
        }
        after = last;
    }
    Ok(changed)
}

/// Evaluation written back onto a saved row.
///
/// Enforcement already re-reads scores against the live policy. This is the
/// same rule, with AI disabled treated as nothing blocked.
fn persisted_evaluation(scores: &CategoryScores, policy: &AiPolicySnapshot) -> AiEvaluation {
    if !policy.enabled {
        return AiEvaluation {
            outcome: AiOutcome::Allow,
            top_category: "",
            top_score: scores.max_score(),
        };
    }
    AiEvaluation::evaluate(scores, policy)
}

/// A new classification of a domain that already has a saved row.
///
/// Scores, model, verdict, and `updated_at` come from this assessment. The
/// domain key and `first_seen` stay on the existing row.
#[must_use]
pub(crate) fn refreshed_decision(
    existing: &StoredDecision,
    assessment: &antiwire_ai::DomainAssessment,
    policy: &AiPolicySnapshot,
    now: OffsetDateTime,
) -> StoredDecision {
    let scores = CategoryScores::from_assessment(assessment);
    persisted_evaluation(&scores, policy).to_stored(
        &existing.domain,
        &assessment.model,
        &scores,
        now,
        Some(existing.first_seen),
    )
}

/// Same replacement as [`refreshed_decision`], marked as an advanced check.
#[must_use]
pub(crate) fn advanced_decision(
    existing: &StoredDecision,
    advanced: &antiwire_ai::AdvancedAssessment,
    policy: &AiPolicySnapshot,
    now: OffsetDateTime,
) -> StoredDecision {
    let mut stored = refreshed_decision(existing, &advanced.assessment, policy, now);
    "advanced".clone_into(&mut stored.scan_tier);
    stored.rating_newly_registered = advanced.newly_registered;
    stored.rating_registry_hold = advanced.registry_hold;
    stored.rating_hidden_registrant = advanced.hidden_registrant;
    stored.rating_abusive_registrar = advanced.abusive_registrar;
    stored
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy_with(mode: AiDecisionMode, block_malicious: bool) -> AiPolicySnapshot {
        let mk = |id: &'static str, block: bool| AiCategorySetting {
            id,
            enabled: true,
            threshold_percent: 80,
            block,
        };
        AiPolicySnapshot {
            enabled: true,
            mode,
            categories: [
                mk("advertising", false),
                mk("tracking", false),
                mk("telemetry", false),
                mk("analytics", false),
                mk("malicious", block_malicious),
                mk("security_fraud", false),
                mk("cryptomining", false),
                mk("tunnel", false),
            ],
            generation: 1,
        }
    }

    #[test]
    fn fraud_category_id_matches_the_client() {
        let policy = AiPolicySnapshot::from_settings(&DaemonSetting::default(), 1);
        assert_eq!(policy.categories[5].id, "fraud");
    }

    #[test]
    fn zero_confidence_settings_cannot_match_zero_scores() {
        let settings = DaemonSetting {
            ai_enabled: true,
            ai_confidence_advertising: 0,
            ai_confidence_tracking: 0,
            ai_confidence_telemetry: 0,
            ai_confidence_analytics: 0,
            ai_confidence_malicious: 0,
            ai_confidence_fraud: 0,
            ai_confidence_cryptomining: 0,
            ai_confidence_tunnel: 0,
            ..DaemonSetting::default()
        };
        let policy = AiPolicySnapshot::from_settings(&settings, 1);
        assert!(policy
            .categories
            .iter()
            .all(|category| category.threshold_percent == 60));
        let evaluation = AiEvaluation::evaluate(&CategoryScores::new([0.0; 8]), &policy);
        assert_eq!(evaluation.outcome, AiOutcome::Allow);
    }

    #[test]
    fn refreshing_replaces_scores_and_keeps_first_seen() {
        let first_seen = OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap();
        let now = OffsetDateTime::from_unix_timestamp(1_700_000_100).unwrap();
        let existing = StoredDecision {
            domain: "ads.example".to_owned(),
            model: "old".to_owned(),
            rating_advertising: 0.1,
            rating_tracking: 0.1,
            rating_telemetry: 0.1,
            rating_analytics: 0.1,
            rating_malicious: 0.1,
            rating_fraud: 0.1,
            rating_cryptomining: 0.1,
            rating_tunnel: 0.1,
            verdict: String::new(),
            top_category: String::new(),
            top_score: 0.1,
            rating_newly_registered: 0.0,
            rating_registry_hold: 0.0,
            rating_hidden_registrant: 0.0,
            rating_abusive_registrar: 0.0,
            scan_tier: "basic".to_owned(),
            first_seen,
            updated_at: first_seen,
        };
        let assessment = antiwire_ai::DomainAssessment {
            domain: "ADS.EXAMPLE.".to_owned(),
            model: "jev-1.13.0".to_owned(),
            advertising: 0.01,
            tracking: 0.01,
            telemetry: 0.01,
            analytics: 0.01,
            malicious: 0.96,
            security_fraud: 0.01,
            cryptomining: 0.01,
            tunnel: 0.01,
        };
        let refreshed = refreshed_decision(
            &existing,
            &assessment,
            &policy_with(AiDecisionMode::Proactive, true),
            now,
        );
        assert_eq!(refreshed.domain, "ads.example");
        assert_eq!(refreshed.model, "jev-1.13.0");
        assert_eq!(refreshed.verdict, "block");
        assert_eq!(refreshed.top_category, "malicious");
        assert_eq!(refreshed.first_seen, first_seen);
        assert_eq!(refreshed.updated_at, now);
        assert_eq!(refreshed.rating_malicious.to_bits(), 0.96_f64.to_bits());

        let mut disabled = policy_with(AiDecisionMode::Proactive, true);
        disabled.enabled = false;
        let cleared = refreshed_decision(&existing, &assessment, &disabled, now);
        assert_eq!(cleared.verdict, "");
        assert_eq!(cleared.rating_malicious.to_bits(), 0.96_f64.to_bits());
        assert_eq!(cleared.first_seen, first_seen);

        let advanced = advanced_decision(
            &existing,
            &antiwire_ai::AdvancedAssessment {
                assessment: assessment.clone(),
                newly_registered: 0.2,
                registry_hold: 0.0,
                hidden_registrant: 0.4,
                abusive_registrar: 0.0,
            },
            &policy_with(AiDecisionMode::Proactive, true),
            now,
        );
        assert_eq!(
            advanced.rating_hidden_registrant.to_bits(),
            0.4_f64.to_bits()
        );
        assert_eq!(advanced.scan_tier, "advanced");
        assert_eq!(advanced.first_seen, first_seen);
        assert_eq!(advanced.verdict, "block");
    }

    #[test]
    fn canonical_key_strips_dot_and_lowercases() {
        assert_eq!(
            canonical_ai_key("Example.COM.").as_deref(),
            Some("example.com")
        );
        assert_eq!(
            canonical_ai_key("  ADS.Example.COM ").as_deref(),
            Some("ads.example.com")
        );
        assert!(canonical_ai_key("  . ").is_none());
        assert!(canonical_ai_key("").is_none());
    }

    #[test]
    fn proactive_block_category_blocks() {
        let policy = policy_with(AiDecisionMode::Proactive, true);
        let scores = CategoryScores::new([0.1, 0.1, 0.1, 0.1, 0.95, 0.1, 0.1, 0.1]);
        let eval = AiEvaluation::evaluate(&scores, &policy);
        assert_eq!(eval.outcome, AiOutcome::Block);
        assert_eq!(eval.top_category, "malicious");
        assert!(eval.should_block());
    }

    #[test]
    fn record_only_category_never_blocks() {
        let policy = policy_with(AiDecisionMode::Proactive, false);
        let scores = CategoryScores::new([0.1, 0.1, 0.1, 0.1, 0.95, 0.1, 0.1, 0.1]);
        let eval = AiEvaluation::evaluate(&scores, &policy);
        assert_eq!(eval.outcome, AiOutcome::Record);
        assert!(!eval.should_block());
    }

    #[test]
    fn retroactive_block_category_blocks_on_the_saved_score() {
        let policy = policy_with(AiDecisionMode::Retroactive, true);
        let scores = CategoryScores::new([0.1, 0.1, 0.1, 0.1, 0.95, 0.1, 0.1, 0.1]);
        let eval = AiEvaluation::evaluate(&scores, &policy);
        assert_eq!(eval.outcome, AiOutcome::Block);
        assert!(eval.should_block());
    }

    #[test]
    fn negative_classification_is_allow_but_counts_as_decision() {
        let policy = policy_with(AiDecisionMode::Proactive, true);
        let scores = CategoryScores::new([0.1; 8]);
        let eval = AiEvaluation::evaluate(&scores, &policy);
        assert_eq!(eval.outcome, AiOutcome::Allow);
        assert_eq!(eval.verdict_str(), "");
    }

    #[test]
    fn disabled_categories_are_ignored() {
        let mut policy = policy_with(AiDecisionMode::Proactive, true);
        policy.categories[4].enabled = false;
        let scores = CategoryScores::new([0.1, 0.1, 0.1, 0.1, 0.99, 0.1, 0.1, 0.1]);
        let eval = AiEvaluation::evaluate(&scores, &policy);
        assert_eq!(eval.outcome, AiOutcome::Allow);
    }

    #[test]
    fn deterministic_top_category_on_ties() {
        let policy = policy_with(AiDecisionMode::Proactive, false);
        let scores = CategoryScores::new([0.9, 0.9, 0.1, 0.1, 0.1, 0.1, 0.1, 0.1]);
        let eval = AiEvaluation::evaluate(&scores, &policy);
        assert_eq!(eval.top_category, "advertising");
    }

    #[test]
    fn stored_scores_reevaluate_against_current_settings() {
        // Old verdict said block, but current settings set the category to record:
        // the stored scores must be re-evaluated, not trusted.
        let policy = policy_with(AiDecisionMode::Proactive, false);
        let stored = StoredDecision {
            domain: "evil.example".to_owned(),
            model: "jev-latest".to_owned(),
            rating_advertising: 0.1,
            rating_tracking: 0.1,
            rating_telemetry: 0.1,
            rating_analytics: 0.1,
            rating_malicious: 0.95,
            rating_fraud: 0.1,
            rating_cryptomining: 0.1,
            rating_tunnel: 0.1,
            verdict: "block".to_owned(),
            top_category: "malicious".to_owned(),
            top_score: 0.95,
            rating_newly_registered: 0.0,
            rating_registry_hold: 0.0,
            rating_hidden_registrant: 0.0,
            rating_abusive_registrar: 0.0,
            scan_tier: "basic".to_owned(),
            first_seen: OffsetDateTime::now_utc(),
            updated_at: OffsetDateTime::now_utc(),
        };
        let scores = CategoryScores::from_stored(&stored);
        let eval = AiEvaluation::evaluate(&scores, &policy);
        assert_eq!(eval.outcome, AiOutcome::Record);
        assert!(!eval.should_block());
    }

    fn classified(domain: &str, malicious: f64, verdict: &str) -> StoredDecision {
        let seen = OffsetDateTime::from_unix_timestamp(1_700_000_000).expect("timestamp");
        StoredDecision {
            domain: domain.to_owned(),
            model: "test".to_owned(),
            rating_advertising: 0.1,
            rating_tracking: 0.1,
            rating_telemetry: 0.1,
            rating_analytics: 0.1,
            rating_malicious: malicious,
            rating_fraud: 0.1,
            rating_cryptomining: 0.1,
            rating_tunnel: 0.1,
            verdict: verdict.to_owned(),
            top_category: "malicious".to_owned(),
            top_score: malicious,
            rating_newly_registered: 0.0,
            rating_registry_hold: 0.0,
            rating_hidden_registrant: 0.0,
            rating_abusive_registrar: 0.0,
            scan_tier: "basic".to_owned(),
            first_seen: seen,
            updated_at: seen,
        }
    }

    fn blocking_malicious(threshold: i32) -> AiPolicySnapshot {
        let settings = antiwire_store::DaemonSetting {
            ai_enabled: true,
            ai_decision_mode: "proactive".to_owned(),
            ai_malicious_action: "block".to_owned(),
            ai_confidence_malicious: threshold,
            ..antiwire_store::DaemonSetting::default()
        };
        AiPolicySnapshot::from_settings(&settings, 1)
    }

    #[test]
    fn recomputing_verdicts_follows_a_raised_then_lowered_threshold() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = antiwire_store::Store::open(dir.path().join("antiwire.libsql")).expect("open");
        let edge = classified("edge.example", 0.82, "block");
        let solid = classified("solid.example", 0.95, "block");
        store.upsert_domain_decision(&edge).expect("save edge");
        store.upsert_domain_decision(&solid).expect("save solid");

        let changed =
            recompute_saved_verdicts(&store, &blocking_malicious(85)).expect("recompute at 85");
        assert_eq!(changed, 1, "only the 82% row falls below 85");

        let edge_after = store
            .get_domain_decision("edge.example")
            .expect("read")
            .expect("edge");
        assert_eq!(edge_after.verdict, "");
        assert_eq!(edge_after.top_category, "");
        assert_eq!(edge_after.rating_malicious.to_bits(), 0.82_f64.to_bits());
        assert_eq!(edge_after.updated_at, edge.updated_at);
        assert_eq!(edge_after.first_seen, edge.first_seen);
        assert_eq!(
            store
                .get_domain_decision("solid.example")
                .expect("read")
                .expect("solid")
                .verdict,
            "block"
        );

        let changed =
            recompute_saved_verdicts(&store, &blocking_malicious(80)).expect("recompute at 80");
        assert_eq!(changed, 1);
        let edge_blocked = store
            .get_domain_decision("edge.example")
            .expect("read")
            .expect("edge");
        assert_eq!(edge_blocked.verdict, "block");
        assert_eq!(edge_blocked.top_category, "malicious");
        assert_eq!(edge_blocked.rating_malicious.to_bits(), 0.82_f64.to_bits());
        assert_eq!(edge_blocked.updated_at, edge.updated_at);
    }
}
