//! Portable firewall rule types and bulk operations.

mod action;
mod bulk;
mod direction;
mod domain;
mod error;
mod port_range;
mod protocol;
mod registry;
mod rule;
mod rule_key;

pub use action::Action;
pub use bulk::{
    BulkExecution, BulkItemResult, BulkOperation, BulkOutcome, BulkRead, BulkRequest, BulkUpdate,
    ExecutionAtomicity, TransactionMode,
};
pub use direction::Direction;
pub use domain::normalize_domain;
pub use error::{Error, ErrorKind};
pub use port_range::PortRange;
pub use protocol::Protocol;
pub use registry::RuleRegistry;
pub use rule::{
    cartesian_exceeds_limits, AddressSetMode, Rule, RuleBuilder, MAX_ADDRESS_SET_ENTRIES,
    MAX_MATCHERS_PER_FIELD, MAX_NATIVE_EXPANSION, MAX_RULE_LABEL_LEN,
};
pub use rule_key::{RuleKey, MAX_RULE_KEY_LEN};
