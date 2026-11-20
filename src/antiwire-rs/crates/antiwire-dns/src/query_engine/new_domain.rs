//! How queries meet the new-domain guard: a cached registration date decides on
//! the sync path, and an unknown one waits for its lookup on the miss path,
//! with the other gates (see [`super::gates`]).

use antiwire_policy::PolicyEngine;
use hickory_proto::op::Message;

use super::request::PreparedQuery;
use super::QueryEngine;
use crate::new_domain::{NewDomainVerdict, NEW_DOMAIN_BLOCK_LABEL};
use crate::port_mapper::QueryClient;

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

    /// Answers a block for a recently registered domain.
    pub(super) fn new_domain_block_response(
        &self,
        request: &Message,
        prepared: &PreparedQuery,
        client: Option<QueryClient<'_>>,
    ) -> Option<Message> {
        self.block_response(
            request,
            &prepared.cache_key.domain,
            prepared.qtype,
            Some("new_domain"),
            client,
            || vec![NEW_DOMAIN_BLOCK_LABEL.to_owned()],
        )
    }
}
