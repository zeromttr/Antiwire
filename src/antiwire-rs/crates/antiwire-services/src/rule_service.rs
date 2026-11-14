//! The user's firewall rules: saved, evaluated, and enforced in agreement.

mod change;
mod classify;
mod country;
mod error;
mod load;
mod request;
mod retarget;
mod rules;
mod service;
#[cfg(test)]
mod tests;

pub use error::RuleServiceError;
pub use request::{
    CountryRuleSummary, CountrySelector, NewCountryBlock, NewRule, RuleListing, RuleSelector,
};
pub use retarget::RetargetOutcome;
pub use rules::DomainBlock;
pub use service::RuleService;
