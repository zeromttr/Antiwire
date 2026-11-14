//! Bulk CRUD operation types.

use crate::{Direction, Error, Rule, RuleKey};

/// Filter for bulk read operations.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct BulkRead {
    /// Match rules whose logical key starts with this prefix.
    pub key_prefix: Option<RuleKey>,
    /// Match rules with this direction.
    pub direction: Option<Direction>,
}

/// Single rule update in a bulk batch.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BulkUpdate {
    /// Logical key of the rule to update.
    pub logical_key: RuleKey,
    /// Replacement rule definition.
    pub rule: Rule,
}

/// One operation in a bulk request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BulkOperation {
    /// Read rules matching a filter.
    Read(BulkRead),
    /// Create rules.
    Create(Vec<Rule>),
    /// Update rules by logical key.
    Update(Vec<BulkUpdate>),
    /// Delete rules by logical key.
    Delete(Vec<RuleKey>),
}

/// Transaction preference for a bulk request.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum TransactionMode {
    /// Execute each item independently.
    #[default]
    Sequential,
    /// Prefer a native transaction and fall back to sequential execution.
    PreferNative,
    /// Require a real native transaction or reject the request before mutation.
    RequireNative,
}

/// Agnostic bulk request spanning matcher types.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BulkRequest {
    /// Ordered list of bulk operations.
    pub operations: Vec<BulkOperation>,
    /// Requested transaction behavior.
    pub transaction_mode: TransactionMode,
}

impl BulkRequest {
    /// Creates a non-atomic bulk request.
    #[must_use]
    pub fn new(operations: Vec<BulkOperation>) -> Self {
        Self {
            operations,
            transaction_mode: TransactionMode::Sequential,
        }
    }

    /// Creates a request that prefers a native transaction.
    #[must_use]
    pub fn prefer_native(operations: Vec<BulkOperation>) -> Self {
        Self {
            operations,
            transaction_mode: TransactionMode::PreferNative,
        }
    }

    /// Sets the transaction behavior.
    #[must_use]
    pub fn with_transaction_mode(mut self, transaction_mode: TransactionMode) -> Self {
        self.transaction_mode = transaction_mode;
        self
    }
}

/// Outcome of one bulk operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BulkOutcome {
    /// Read results: logical keys and rules.
    Read(Vec<(RuleKey, Rule)>),
    /// A rule was created.
    Created(RuleKey),
    /// A rule was updated.
    Updated(RuleKey),
    /// A rule was deleted.
    Deleted(RuleKey),
    /// An item completed but was rolled back with its native transaction.
    RolledBack,
}

/// Atomicity actually used for a bulk execution.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExecutionAtomicity {
    /// The complete request ran in a native transaction.
    NativeAtomic,
    /// Items ran sequentially and successful mutations remain applied.
    SequentialBestEffort,
}

/// Result for one item within one bulk operation.
#[derive(Debug)]
pub struct BulkItemResult {
    /// Index into the original [`BulkRequest::operations`].
    pub operation_index: usize,
    /// Index within the operation's item vector.
    pub item_index: usize,
    /// Item outcome or structured error.
    pub outcome: Result<BulkOutcome, Error>,
}

/// Complete bulk execution report.
#[derive(Debug)]
pub struct BulkExecution {
    /// Atomicity actually provided by the backend.
    pub atomicity: ExecutionAtomicity,
    /// Per-item results in caller order.
    pub results: Vec<BulkItemResult>,
}
