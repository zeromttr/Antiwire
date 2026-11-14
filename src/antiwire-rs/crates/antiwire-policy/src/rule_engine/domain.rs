use crate::rule::Verdict;

/// User-facing label when a firewall rule, not a hosts list, blocked the domain.
pub const FIREWALL_RULE_LABEL: &str = "Firewall Rule";

/// User-facing label when proactive AI, not a hosts list or firewall rule, blocked the domain.
pub const AI_BLOCK_LABEL: &str = "AI";

/// User-facing label while hosts lists are still loading and the boot gate is closed.
pub const LOADING_BLOCKLISTS_LABEL: &str = "Loading Block Lists";

/// Policy layer that blocked a domain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DomainBlockSource {
    DnsRule,
    Blocklist,
    BlocklistPending,
}

impl DomainBlockSource {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DnsRule => "dns_rule",
            Self::Blocklist => "blocklist",
            Self::BlocklistPending => "blocklist_pending",
        }
    }

    /// Names the client should show for this block. Firewall DNS rules report
    /// [`FIREWALL_RULE_LABEL`]; hosts-list hits use `matching_lists`.
    #[must_use]
    pub fn reported_blocklist_names(self, matching_lists: Vec<String>) -> Vec<String> {
        match self {
            Self::DnsRule => vec![FIREWALL_RULE_LABEL.to_owned()],
            Self::Blocklist => matching_lists,
            Self::BlocklistPending => vec![LOADING_BLOCKLISTS_LABEL.to_owned()],
        }
    }
}

/// Domain verdict paired with the policy source that produced a block.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DomainDecision {
    pub verdict: Verdict,
    /// Matching policy source when `verdict` is [`Verdict::Block`].
    pub source: Option<DomainBlockSource>,
}

/// Shared policy surface for DNS and enforce crates.
///
/// [`Self::evaluate_domain_with_source`] is the single verdict primitive;
/// every other verdict method derives from it.
pub trait PolicyEngine {
    /// Evaluates `domain` once, returning the verdict and block source together.
    ///
    /// `source` is `Some` only when the verdict is [`Verdict::Block`].
    fn evaluate_domain_with_source(&self, domain: &str) -> Option<DomainDecision>;

    /// Domain-only view of [`Self::evaluate_domain_with_source`].
    fn evaluate_domain(&self, domain: &str) -> Option<Verdict> {
        self.evaluate_domain_with_source(domain)
            .map(|decision| decision.verdict)
    }

    /// Variant of [`Self::evaluate_domain_with_source`] for callers that
    /// guarantee `domain` is already lowercase ASCII without a trailing dot.
    ///
    /// Override only to skip re-normalization work; the decision returned must
    /// be identical to [`Self::evaluate_domain_with_source`]'s for such input.
    fn evaluate_normalized_domain_with_source(&self, domain: &str) -> Option<DomainDecision> {
        self.evaluate_domain_with_source(domain)
    }

    /// Named lists that currently match `domain`. Default is empty so test
    /// doubles that only implement evaluation stay source-compatible.
    fn matching_blocklists(&self, _domain: &str) -> Vec<String> {
        Vec::new()
    }

    /// Attribution variant for callers that guarantee `domain` is already
    /// lowercase ASCII without a trailing dot.
    ///
    /// The default preserves source compatibility for policy test doubles.
    fn matching_normalized_blocklists(&self, domain: &str) -> Vec<String> {
        self.matching_blocklists(domain)
    }
}
