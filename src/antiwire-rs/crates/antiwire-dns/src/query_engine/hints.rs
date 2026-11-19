//! Reports answered addresses to the flow tracker so connections can be named.

use std::sync::Arc;

use antiwire_policy::PolicyEngine;
use hickory_proto::op::Message;

use super::QueryEngine;
use crate::answers::{answered_addresses, AnswerHint};
use crate::block::DnsQueryContext;
use crate::port_mapper::{
    deferred_query_owner, recorded_owners_available, reply_path_query_owner, Purpose,
    ReplyPathOwner,
};
use crate::response_cache::{CachedAnswer, ResponseCache};

impl<P> QueryEngine<P>
where
    P: PolicyEngine + Send + Sync,
{
    /// Records a block answer's sinkhole addresses under `domain`.
    ///
    /// Served answers reach the flow tracker as hints; block answers do not,
    /// because their sinkhole addresses must not name a process's traffic.
    pub(super) fn record_block_resolution(&self, domain: &str, message: &Message) {
        let Some(sink) = self.hint_sink.read().clone() else {
            return;
        };
        if let Some(hint) = answered_addresses(message, &message.answers, &message.additionals) {
            sink.record_resolution(domain, &hint.addresses);
        }
    }

    /// Attributes a served answer to the client socket so flow logs can name it.
    pub(super) fn note_client_hint(
        &self,
        context: Option<DnsQueryContext>,
        domain: &str,
        answer: &CachedAnswer,
    ) {
        let Some(sink) = self.hint_sink.read().clone() else {
            return;
        };
        let Some(context) = context else {
            return;
        };
        let Some(message) = answer.parsed_message.as_deref() else {
            return;
        };
        if self.provider_filter.read().is_block(message) {
            return;
        }
        let Some(AnswerHint { addresses, ttl_ms }) = ResponseCache::answer_hint(answer, message)
        else {
            return;
        };
        // The client has the address from this moment and can connect at
        // once. Finding its owner, below, can take longer than that.
        let answered_at_ms = unix_now_ms();
        let promised = if recorded_owners_available() {
            None
        } else {
            match reply_path_query_owner(&context, Purpose::ServedAnswer) {
                ReplyPathOwner::Known(owner) => {
                    let pid = owner.resolved_pid().unwrap_or(0);
                    sink.record_hint(pid, domain, &addresses, ttl_ms, answered_at_ms);
                    return;
                }
                ReplyPathOwner::Promised(owner) => Some(owner),
                ReplyPathOwner::Busy => None,
            }
        };
        // The recorded owner can lag the query, a socket-table scan the reply
        // path may not run now would stall it, and a scan handed off the
        // receive loop is still running, so each is finished on the
        // attribution worker rather than holding up the answer.
        let deferred_sink = Arc::clone(&sink);
        let deferred_domain = domain.to_owned();
        let deferred_answers = Arc::clone(&addresses);
        let submitted = self.owner_worker.submit(Box::new(move || {
            let owner = promised
                .and_then(|owner| owner.wait(&context))
                .unwrap_or_else(|| deferred_query_owner(&context, Purpose::ServedAnswer));
            deferred_sink.record_hint(
                owner.resolved_pid().unwrap_or(0),
                &deferred_domain,
                &deferred_answers,
                ttl_ms,
                answered_at_ms,
            );
        }));
        if submitted.is_ok() {
            return;
        }
        // The worker's queue is full: name what the newest snapshot can.
        let pid = match reply_path_query_owner(&context, Purpose::ServedAnswer) {
            ReplyPathOwner::Known(owner) => owner.resolved_pid().unwrap_or(0),
            ReplyPathOwner::Promised(_) | ReplyPathOwner::Busy => 0,
        };
        sink.record_hint(pid, domain, &addresses, ttl_ms, answered_at_ms);
    }
}

/// The wall-clock time in Unix epoch milliseconds, zero for a clock set
/// before the epoch.
fn unix_now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| {
            u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX)
        })
}
