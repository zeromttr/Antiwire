//! AI decision query and response conversions.

use super::timestamps::datetime_to_unix_secs;

use antiwire_proto::{AiDecision, AiDecisionsRequest, AiDecisionsResponse};
use antiwire_store::{
    DomainDecision, DomainDecisionPage, DomainDecisionQuery, DomainDecisionVerdictFilter,
};

pub(crate) fn ai_decisions_query_from_proto(
    request: &AiDecisionsRequest,
) -> Result<DomainDecisionQuery, String> {
    let verdict = match request.verdict_filter.trim().to_ascii_lowercase().as_str() {
        "" | "all" => DomainDecisionVerdictFilter::All,
        "block" => DomainDecisionVerdictFilter::Block,
        "record" => DomainDecisionVerdictFilter::Record,
        "clean" => DomainDecisionVerdictFilter::Clean,
        other => return Err(format!("unknown verdict filter `{other}`")),
    };
    Ok(DomainDecisionQuery {
        limit: request.limit as usize,
        offset: request.offset as usize,
        verdict,
        search_query: Some(request.search_query.clone()).filter(|search| !search.trim().is_empty()),
    })
}

pub(crate) fn domain_decision_to_proto(decision: &DomainDecision) -> AiDecision {
    AiDecision {
        domain: decision.domain.clone(),
        model: decision.model.clone(),
        verdict: decision.verdict.clone(),
        top_category: decision.top_category.clone(),
        top_score: decision.top_score,
        rating_advertising: decision.rating_advertising,
        rating_tracking: decision.rating_tracking,
        rating_telemetry: decision.rating_telemetry,
        rating_analytics: decision.rating_analytics,
        rating_malicious: decision.rating_malicious,
        rating_fraud: decision.rating_fraud,
        rating_cryptomining: decision.rating_cryptomining,
        rating_tunnel: decision.rating_tunnel,
        scan_tier: decision.scan_tier.clone(),
        rating_newly_registered: decision.rating_newly_registered,
        rating_registry_hold: decision.rating_registry_hold,
        rating_hidden_registrant: decision.rating_hidden_registrant,
        rating_abusive_registrar: decision.rating_abusive_registrar,
        first_seen: datetime_to_unix_secs(decision.first_seen),
        updated_at: datetime_to_unix_secs(decision.updated_at),
    }
}

pub(crate) fn ai_decision_page_to_response(page: &DomainDecisionPage) -> AiDecisionsResponse {
    let count = |value: u64| u32::try_from(value).unwrap_or(u32::MAX);
    AiDecisionsResponse {
        decisions: page
            .decisions
            .iter()
            .map(domain_decision_to_proto)
            .collect(),
        total_count: count(page.total_count),
        block_count: count(page.block_count),
        record_count: count(page.record_count),
        clean_count: count(page.clean_count),
    }
}
