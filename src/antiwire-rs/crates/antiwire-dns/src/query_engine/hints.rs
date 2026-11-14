//! Reports answered addresses to the flow tracker so connections can be named.

use std::sync::Arc;

use antiwire_policy::PolicyEngine;
use hickory_proto::op::Message;

use super::QueryEngine;
use crate::answers::answered_addresses;
use crate::block::DnsQueryContext;
use crate::port_mapper::{
    deferred_query_owner, recorded_owners_available, reply_path_query_owner, Ownership,
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
        if let Some((answers, _)) =
            answered_addresses(message, &message.answers, &message.additionals)
        {
            sink.record_resolution(domain, &answers);
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
        let aged = ResponseCache::age_sections(answer, message);
        let (records, additionals) = aged.as_ref().map_or(
            (&message.answers[..], &message.additionals[..]),
            |sections| (&sections.answers[..], &sections.additionals[..]),
        );
        let Some((answers, ttl_ms)) = answered_addresses(message, records, additionals) else {
            return;
        };
        // The client has the address from this moment and can connect at
        // once. Finding its owner, below, can take longer than that.
        let answered_at_ms = unix_now_ms();
        let mut owner = None;
        if !recorded_owners_available() {
            owner = reply_path_query_owner(&context);
        }
        if owner.is_none() {
            // The recorded owner can lag the query, and a socket-table scan the
            // reply path may not run now would stall it, so either is finished
            // on the attribution worker rather than holding up the answer.
            let deferred_sink = Arc::clone(&sink);
            let deferred_domain = domain.to_owned();
            let deferred_answers = answers.clone();
            let submitted = self.owner_worker.submit(Box::new(move || {
                let pid = deferred_query_owner(&context).resolved_pid().unwrap_or(0);
                deferred_sink.record_hint(
                    pid,
                    &deferred_domain,
                    &deferred_answers,
                    ttl_ms,
                    answered_at_ms,
                );
            }));
            if submitted.is_ok() {
                return;
            }
            // The worker's queue is full.
            owner = reply_path_query_owner(&context);
        }
        let pid = owner.and_then(Ownership::resolved_pid).unwrap_or(0);
        sink.record_hint(pid, domain, &answers, ttl_ms, answered_at_ms);
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
