//! Private backend contract for firew-rs.

mod backend;
mod config;
mod drift;
mod expansion;
mod filter;
mod forward;
mod health;
mod marker;
mod native_ref;
mod reconstruct;
mod unavailable;

#[cfg(test)]
pub mod mock;

pub use backend::{
    classify_cli_failure, duplicate_rule, key_mismatch, reject_application_matchers,
    reject_unresolved_domains, reports_missing_object, rule_not_found, unsupported_matcher,
    validate_address_set, validate_native_rule, Backend, APPLICATION_MATCHERS_SUPPORTED,
};
pub use config::{
    BackendConfig, BackendPreference, DEFAULT_INETFW_ADDRESS_SET_LIMIT, MAX_MANAGER_NAME_LEN,
};
pub use drift::DriftTracker;
pub use expansion::{address_pairs, alternatives};
pub use filter::RuleFilter;
pub use health::HealthSnapshot;
pub use marker::{split_directions, ManagedMarker, ManagedNamespace, PartMarkers};
pub use native_ref::NativeRuleRef;
pub use reconstruct::{
    complete_parts, merged_direction, parse_native_net, rebuild_rule, NativeRow,
};
#[doc(hidden)]
pub use unavailable::__private;
