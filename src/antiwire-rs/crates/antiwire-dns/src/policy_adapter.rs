//! [`RuleEngine`] adapter for [`PolicyEngine`].

use std::sync::Arc;

use antiwire_policy::{DomainDecision, PolicyEngine, PublishedDnsPolicyHandle, RuleEngine};
use parking_lot::RwLock;

/// Shares the published DNS policy view with the DNS stub.
#[derive(Clone)]
pub(crate) struct EnginePolicy(pub(crate) PublishedDnsPolicyHandle);

impl EnginePolicy {
    pub(crate) fn from_engine_lock(engine: &Arc<RwLock<RuleEngine>>) -> Self {
        Self(engine.read().dns_policy_handle())
    }
}

impl PolicyEngine for EnginePolicy {
    fn evaluate_domain_with_source(&self, domain: &str) -> Option<DomainDecision> {
        self.0.load().evaluate_domain_with_source(domain)
    }

    fn evaluate_normalized_domain_with_source(&self, domain: &str) -> Option<DomainDecision> {
        self.0.load().evaluate_normalized_domain_with_source(domain)
    }

    fn matching_normalized_blocklists(&self, domain: &str) -> Vec<String> {
        self.0.load().matching_normalized_blocklists(domain)
    }
}
