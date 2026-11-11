//! How queries meet the AI classifier: the proactive gate before a miss goes
//! upstream, and the post-response work that lets answers be classified.

use std::sync::Arc;
use std::time::Instant;

use antiwire_policy::{PolicyEngine, AI_BLOCK_LABEL};
use hickory_proto::op::{Message, ResponseCode};
use tracing::debug;

use super::local::GateBlock;
use super::miss::remaining_deadline;
use super::request::{PreparedQuery, RequestView};
use super::QueryEngine;
use crate::ai::coordinator::{ProactiveOutcome, ResidentOutcome};
use crate::ai::decision::AiEvaluation;
use crate::ai::{AiCoordinator, PostResponseWork};
use crate::block::DnsQueryContext;
use crate::domain_key::DomainKey;
use crate::messages::build_servfail_response;
use crate::response_cache::CachedAnswer;

/// What the AI gate decides on the synchronous path.
pub(super) enum AiLocal {
    /// AI has nothing against this query. An answer served now is classified
    /// afterwards if AI applies to the name.
    Clear,
    /// A saved decision allows the name, so there is nothing to classify.
    Decided,
    /// A saved decision blocks the name.
    Block(AiEvaluation),
    /// Deciding needs the store or the classifier: the miss path runs the
    /// gate.
    Pending,
}

impl<P> QueryEngine<P>
where
    P: PolicyEngine + Send + Sync,
{
    /// The coordinator, when AI applies to `domain`: one is attached, AI is
    /// enabled, the classifier accepts the name, and it is not the AI
    /// endpoint's own host, whose resolution must never wait on AI.
    fn ai_for(&self, domain: &DomainKey) -> Option<Arc<AiCoordinator>> {
        let ai = self.ai.read().clone()?;
        (ai.policy_snapshot().enabled
            && ai_domain_eligible(domain)
            && !ai.is_bootstrap_domain(domain.as_str()))
        .then_some(ai)
    }

    /// The AI gate's decision from memory alone, for the sync fast path.
    ///
    /// A saved decision that is in memory is applied here, so a cached answer
    /// for a name AI has already judged never leaves the receive loop. Only a
    /// decision that needs the store or the classifier defers to the async
    /// gate: proactive mode may classify before answering, and retroactive
    /// mode must look for a saved score it does not have in memory.
    /// Explicitly allowed names skip AI, and special-use names never reach
    /// here.
    pub(super) fn ai_local(&self, prepared: &PreparedQuery) -> AiLocal {
        if prepared.explicit_allow {
            return AiLocal::Clear;
        }
        let domain = &prepared.cache_key.domain;
        let Some(ai) = self.ai_for(domain) else {
            return AiLocal::Clear;
        };
        match ai.resident_gate(domain.as_str()) {
            ResidentOutcome::Proceed { saved: true } => AiLocal::Decided,
            ResidentOutcome::Proceed { saved: false } => AiLocal::Clear,
            ResidentOutcome::Block(evaluation) => AiLocal::Block(evaluation),
            ResidentOutcome::Deferred => AiLocal::Pending,
        }
    }

    /// Answers a block the AI gate decided on.
    pub(super) fn ai_block_response<R: RequestView>(
        &self,
        request: &R,
        prepared: &PreparedQuery,
        context: Option<DnsQueryContext>,
        evaluation: &AiEvaluation,
    ) -> Option<Message> {
        let domain = prepared.cache_key.domain.as_str();
        debug!(
            domain = %domain,
            category = %evaluation.top_category,
            score = evaluation.top_score,
            "ai proactive block"
        );
        self.block_response(request, domain, prepared.qtype, Some("ai"), context, || {
            vec![AI_BLOCK_LABEL.to_owned()]
        })
    }

    /// Post-response work for a served cache answer.
    ///
    /// Retroactive answers learn in the background; disabled AI and the
    /// bootstrap host never produce work. Provider answers, cached answers,
    /// and NXDOMAIN are eligible; malformed, special-use, SERVFAIL, and
    /// prefetch are never attached by callers.
    pub(super) fn post_work_for_domain_key(
        &self,
        domain_key: &DomainKey,
        was_block: bool,
    ) -> Option<PostResponseWork> {
        self.ai_for(domain_key)?;
        Some(PostResponseWork {
            domain: domain_key.as_str().to_owned(),
            was_block,
            eligible: true,
        })
    }

    /// An upstream/cache response is learnable only if DNS actually answered
    /// the question. Error RCODEs may still be sent to the client, but never
    /// create AI work. Policy blocks use the separate `was_block` path.
    pub(super) fn post_work_for_answer(
        &self,
        domain_key: &DomainKey,
        answer: &CachedAnswer,
    ) -> Option<PostResponseWork> {
        self.post_work_for_domain_key(domain_key, false)
            .filter(|_| answer_is_ai_eligible(answer))
    }

    /// Runs the proactive AI gate on the miss path before any cache probe,
    /// prefetch reservation, or upstream admission.
    ///
    /// Returns a block response when AI requires blocking, or when a policy
    /// rule added during the gate does; `None` means continue normal
    /// resolution (allow, record, fail-open, disabled, explicit allow, or
    /// bootstrap).
    pub(super) async fn ai_proactive_block(
        &self,
        request: &Message,
        prepared: &PreparedQuery,
        context: Option<DnsQueryContext>,
        enqueued_at: Instant,
    ) -> Option<GateBlock> {
        if prepared.explicit_allow {
            return None;
        }
        let ai = self.ai_for(&prepared.cache_key.domain)?;
        let domain = prepared.cache_key.domain.as_str();
        // An expired deadline still runs the gate: with no budget it waits on
        // nothing, but a saved verdict already in memory is enforced, so the
        // stale fallback that follows cannot serve a name AI blocks.
        let outcome = ai
            .proactive_gate(domain, remaining_deadline(enqueued_at))
            .await;

        // The gate awaited the store or the classifier, so policy may have
        // changed underneath it.
        self.recheck_policy_after_gate(request, prepared, context, || match outcome {
            ProactiveOutcome::Block(evaluation) => Some(
                self.ai_block_response(request, prepared, context, &evaluation)
                    .unwrap_or_else(|| build_servfail_response(request)),
            ),
            ProactiveOutcome::Proceed => None,
        })
    }
}

/// Whether the normalized DNS name can be sent to the AI classifier.
///
/// Keep this allocation-free and in sync with the classifier's input
/// validation. DNS permits names such as `_dmarc.example`, while the AI
/// classifier accepts conventional host labels only.
pub(super) fn ai_domain_eligible(domain: &DomainKey) -> bool {
    let raw = domain.as_str();
    if raw.is_empty() || raw.contains([' ', '\t', '/', '\\', ':', '@', '?', '#']) {
        return false;
    }

    raw.split('.').all(|label| {
        let bytes = label.as_bytes();
        let (Some(first), Some(last)) = (bytes.first(), bytes.last()) else {
            return false;
        };
        first.is_ascii_alphanumeric()
            && last.is_ascii_alphanumeric()
            && bytes
                .iter()
                .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'-')
    })
}

pub(super) fn answer_is_ai_eligible(answer: &CachedAnswer) -> bool {
    answer.parsed_message.as_ref().is_some_and(|message| {
        matches!(
            message.metadata.response_code,
            ResponseCode::NoError | ResponseCode::NXDomain
        )
    })
}
