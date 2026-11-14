//! Cross-platform native firewall CRUD library.

mod backend_factory;
mod builder;
mod bulk_executor;
mod domain_manager;
mod engine;
mod firewall;
mod health;
mod rule_id;
#[cfg(test)]
mod test_support;

#[cfg(feature = "async-std")]
mod async_async_std;
#[cfg(any(feature = "async-std", feature = "smol", feature = "tokio"))]
mod async_facade;
#[cfg(feature = "smol")]
mod async_smol;
#[cfg(feature = "tokio")]
mod async_tokio;
#[cfg(feature = "async-std")]
pub use async_async_std::AsyncStdFirewall;
#[cfg(feature = "smol")]
pub use async_smol::SmolFirewall;
#[cfg(feature = "tokio")]
pub use async_tokio::TokioFirewall;

pub use builder::FirewallBuilder;
pub use firewall::{Firewall, ReconcileItem, ReconcileReport, ReconcileStatus};
pub use health::{HealthMonitor, HealthMonitorConfig, HealthMonitorHandle, HealthReport};
pub use rule_id::RuleId;

pub use firew_core::{
    Action, AddressSetMode, BulkExecution, BulkItemResult, BulkOperation, BulkOutcome, BulkRead,
    BulkRequest, BulkUpdate, Direction, Error, ErrorKind, ExecutionAtomicity, PortRange, Protocol,
    Rule, RuleBuilder, RuleKey, TransactionMode, MAX_ADDRESS_SET_ENTRIES, MAX_MATCHERS_PER_FIELD,
    MAX_NATIVE_EXPANSION, MAX_RULE_KEY_LEN,
};
pub use firew_sys::{BackendPreference, RuleFilter, APPLICATION_MATCHERS_SUPPORTED};
