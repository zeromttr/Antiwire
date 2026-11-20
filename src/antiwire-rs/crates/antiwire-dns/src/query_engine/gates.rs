//! The gates a query passes before it is answered from the cache or sent
//! upstream: proactive AI and the new-domain guard.
//!
//! Each decides from memory on the sync path where it can. On the miss path the
//! gates that have to wait for the store, the classifier or a registry wait side
//! by side, and the first to block answers. A blocked name still never goes
//! upstream, and a name both let through waits for the slower of them, not for
//! the two one after the other.

use std::future::Future;
use std::pin::pin;
use std::time::Instant;

use antiwire_policy::PolicyEngine;
use futures_util::future::{self, Either};
use hickory_proto::op::Message;

use super::ai::AiLocal;
use super::local::GateBlock;
use super::miss::remaining_deadline;
use super::request::PreparedQuery;
use super::QueryEngine;
use crate::ai::coordinator::ProactiveOutcome;
use crate::ai::decision::AiEvaluation;
use crate::block::DnsQueryContext;
use crate::messages::build_servfail_response;
use crate::new_domain::NewDomainVerdict;
use crate::port_mapper::QueryClient;

/// The gate that blocked a query.
pub(super) enum Blocked {
    /// The name's registered domain is younger than the guard allows.
    NewDomain,
    /// AI judged the name.
    Ai(AiEvaluation),
}

/// What the gates decide from memory alone.
pub(super) enum GatesLocal {
    /// Every gate lets the query through. `ai_decided` is set when a saved AI
    /// decision allows the name, so its answer needs no classifying afterwards.
    Pass {
        ai_decided: bool,
    },
    Block(Blocked),
    /// A gate has to wait for the store, the classifier or a registry: the
    /// miss path runs the gates.
    Pending,
}

impl<P> QueryEngine<P>
where
    P: PolicyEngine + Send + Sync,
{
    /// The gates' decision from memory, for the sync path. A block either one
    /// already knows of is answered here, even while the other has to wait.
    pub(super) fn gates_local(&self, prepared: &PreparedQuery) -> GatesLocal {
        let new_domain = self.new_domain_verdict(prepared);
        if new_domain == NewDomainVerdict::Block {
            return GatesLocal::Block(Blocked::NewDomain);
        }
        match self.ai_local(prepared) {
            AiLocal::Block(evaluation) => GatesLocal::Block(Blocked::Ai(evaluation)),
            AiLocal::Pending => GatesLocal::Pending,
            _ if new_domain == NewDomainVerdict::Pending => GatesLocal::Pending,
            AiLocal::Decided => GatesLocal::Pass { ai_decided: true },
            AiLocal::Clear => GatesLocal::Pass { ai_decided: false },
        }
    }

    /// Answers a block a gate decided on.
    pub(super) fn gate_block_response(
        &self,
        request: &Message,
        prepared: &PreparedQuery,
        client: Option<QueryClient<'_>>,
        blocked: &Blocked,
    ) -> Option<Message> {
        match blocked {
            Blocked::NewDomain => self.new_domain_block_response(request, prepared, client),
            Blocked::Ai(evaluation) => {
                self.ai_block_response(request, prepared, client, evaluation)
            }
        }
    }

    /// Runs the gates on the miss path, before any cache probe, prefetch
    /// reservation or upstream admission.
    ///
    /// Each waits within the query's deadline, less what it leaves for
    /// upstream ([`antiwire_tuning::DNS_GATE_UPSTREAM_RESERVE`]), and fails
    /// open when that runs out. Returns a block response when a gate blocks,
    /// or when a policy rule added while they waited does; `None` continues
    /// normal resolution.
    pub(super) async fn gates_block(
        &self,
        request: &Message,
        prepared: &PreparedQuery,
        context: Option<DnsQueryContext>,
        enqueued_at: Instant,
    ) -> Option<GateBlock> {
        if prepared.explicit_allow {
            return None;
        }
        let ai = self.ai_for(&prepared.cache_key.domain);
        let guard = self.new_domains.as_ref();
        if ai.is_none() && guard.is_none() {
            return None;
        }
        let domain = prepared.cache_key.domain.as_str();
        // An expired deadline still runs the gates: with no budget they wait
        // on nothing, but what they already know is enforced, so the stale
        // fallback that follows cannot serve a name they block.
        let remaining = remaining_deadline(enqueued_at);
        let new_domain = async {
            let verdict = guard?.check(domain, remaining).await;
            (verdict == NewDomainVerdict::Block).then_some(Blocked::NewDomain)
        };
        let ai = async {
            match ai?.proactive_gate(domain, remaining).await {
                ProactiveOutcome::Block(evaluation) => Some(Blocked::Ai(evaluation)),
                ProactiveOutcome::Proceed => None,
            }
        };
        let blocked = first_block(new_domain, ai).await;
        // The gates waited, so policy may have changed underneath them.
        self.recheck_policy_after_gate(request, prepared, context, || {
            blocked.map(|blocked| {
                self.gate_block_response(
                    request,
                    prepared,
                    context.map(QueryClient::scanned_here),
                    &blocked,
                )
                .unwrap_or_else(|| build_servfail_response(request))
            })
        })
    }
}

/// The block of whichever gate blocks first, without waiting for the other;
/// `None` once both have let the query through. `first` wins a tie, as it does
/// on the sync path.
///
/// A gate left waiting is dropped. A registry lookup or a classification it
/// started runs on a task of its own, so it still finishes, and what it learns
/// decides the next query for the name.
async fn first_block(
    first: impl Future<Output = Option<Blocked>>,
    second: impl Future<Output = Option<Blocked>>,
) -> Option<Blocked> {
    match future::select(pin!(first), pin!(second)).await {
        Either::Left((Some(blocked), _)) | Either::Right((Some(blocked), _)) => Some(blocked),
        Either::Left((None, second)) => second.await,
        Either::Right((None, first)) => first.await,
    }
}
