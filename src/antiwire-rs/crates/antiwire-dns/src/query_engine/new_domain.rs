//! How queries meet the new-domain guard: a cached registration date decides on
//! the sync path, and an unknown one waits for its lookup on the miss path.

use std::time::Instant;

use antiwire_policy::PolicyEngine;
use hickory_proto::op::Message;

use super::local::GateBlock;
use super::miss::remaining_deadline;
use super::request::{PreparedQuery, RequestView};
use super::QueryEngine;
use crate::block::DnsQueryContext;
use crate::messages::build_servfail_response;
use crate::new_domain::{NewDomainVerdict, NEW_DOMAIN_BLOCK_LABEL};

impl<P> QueryEngine<P>
where
    P: PolicyEngine + Send + Sync,
{
    /// The guard's verdict from cached dates alone. Explicitly allowed names
    /// and a disabled guard always pass.
    pub(super) fn new_domain_verdict(&self, prepared: &PreparedQuery) -> NewDomainVerdict {
        match &self.new_domains {
            Some(guard) if !prepared.explicit_allow => {
                guard.check_cached(prepared.cache_key.domain.as_str())
            }
            _ => NewDomainVerdict::Allow,
        }
    }

    /// Runs the guard on the miss path before any cache probe or upstream
    /// admission, waiting for an uncached date within the query's deadline.
    ///
    /// Returns a block response for a recently registered domain, or for a
    /// policy rule added during the lookup; `None` continues normal
    /// resolution.
    pub(super) async fn new_domain_block(
        &self,
        request: &Message,
        prepared: &PreparedQuery,
        context: Option<DnsQueryContext>,
        enqueued_at: Instant,
    ) -> Option<GateBlock> {
        let guard = self
            .new_domains
            .as_ref()
            .filter(|_| !prepared.explicit_allow)?;
        let verdict = guard
            .check(
                prepared.cache_key.domain.as_str(),
                remaining_deadline(enqueued_at),
            )
            .await;
        if verdict != NewDomainVerdict::Block {
            return None;
        }
        // A rule added while the lookup ran wins, as it does for AI blocks.
        self.recheck_policy_after_gate(request, prepared, context, || {
            Some(
                self.new_domain_block_response(request, prepared, context)
                    .unwrap_or_else(|| build_servfail_response(request)),
            )
        })
    }

    /// Answers a block for a recently registered domain.
    pub(super) fn new_domain_block_response<R: RequestView>(
        &self,
        request: &R,
        prepared: &PreparedQuery,
        context: Option<DnsQueryContext>,
    ) -> Option<Message> {
        self.block_response(
            request,
            &prepared.cache_key.domain,
            prepared.qtype,
            Some("new_domain"),
            context,
            || vec![NEW_DOMAIN_BLOCK_LABEL.to_owned()],
        )
    }
}
