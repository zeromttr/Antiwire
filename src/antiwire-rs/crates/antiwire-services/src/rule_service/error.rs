//! Why a rule change was refused or failed.

use antiwire_enforce::EnforceError;
use antiwire_store::StoreError;

/// Why a rule change was refused or failed.
#[derive(Debug, thiserror::Error)]
pub enum RuleServiceError {
    /// The request is not a valid rule. Nothing was changed.
    #[error("{0}")]
    Invalid(String),
    /// No rule has this id.
    #[error("rule {0} was not found")]
    NotFound(i32),
    /// The rule would duplicate one that exists. Nothing was changed.
    #[error("{0}")]
    Conflict(String),
    #[error(transparent)]
    Store(StoreError),
    #[error(transparent)]
    Enforce(#[from] EnforceError),
    /// The change failed and part of it could not be undone, so the saved
    /// rules, the policy engine, and the firewall may disagree.
    #[error("{cause}; it could not be fully undone: {}", .unrestored.join("; "))]
    Inconsistent {
        cause: Box<RuleServiceError>,
        /// What was left changed, one entry per step that could not be undone.
        unrestored: Vec<String>,
    },
    /// Several independent changes failed.
    #[error("{}", join(.0))]
    Several(Vec<RuleServiceError>),
}

impl RuleServiceError {
    pub(super) fn invalid(message: impl Into<String>) -> Self {
        Self::Invalid(message.into())
    }

    /// Whether saved and enforced state may now disagree.
    #[must_use]
    pub fn is_inconsistent(&self) -> bool {
        match self {
            Self::Inconsistent { .. } => true,
            Self::Several(errors) => errors.iter().any(Self::is_inconsistent),
            _ => false,
        }
    }
}

impl From<StoreError> for RuleServiceError {
    fn from(error: StoreError) -> Self {
        match error {
            StoreError::RuleNotFound(id) => Self::NotFound(id),
            other => Self::Store(other),
        }
    }
}

fn join(errors: &[RuleServiceError]) -> String {
    errors
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join("; ")
}

pub(super) type Result<T> = std::result::Result<T, RuleServiceError>;
