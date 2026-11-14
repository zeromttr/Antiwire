//! What callers ask the rule service to do, and what it reports back.

use antiwire_policy::{RuleDirection, TargetType, Verdict};
use antiwire_store::FirewallRule;

/// A rule on one application, address, or domain, to add.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewRule {
    pub target_type: TargetType,
    /// Normalized by the service before it is saved.
    pub target: String,
    pub verdict: Verdict,
    pub direction: RuleDirection,
}

/// A rule covering every network of one country, to add.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewCountryBlock {
    /// ISO-3166-1 alpha-2 code, in any case.
    pub code: String,
    /// Networks or single addresses; sorted and deduplicated by the service.
    pub networks: Vec<String>,
    pub verdict: Verdict,
    pub direction: RuleDirection,
}

/// Which rule on one application, address, or domain to remove.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuleSelector {
    Id(i32),
    /// The rule whose target normalizes to the same value.
    Target {
        target_type: TargetType,
        target: String,
    },
}

/// Which country block to remove.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CountrySelector {
    Id(i32),
    /// ISO-3166-1 alpha-2 code, in any case.
    Code(String),
}

/// A saved country block, without its networks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CountryRuleSummary {
    pub id: i32,
    /// ISO-3166-1 alpha-2 code, uppercase.
    pub code: String,
    pub verdict: Verdict,
    pub direction: RuleDirection,
    pub network_count: u32,
}

/// Every saved rule, read at one moment.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RuleListing {
    /// Rules on one application, address, or domain, oldest first.
    pub rules: Vec<FirewallRule>,
    /// Country blocks, oldest first.
    pub countries: Vec<CountryRuleSummary>,
}
