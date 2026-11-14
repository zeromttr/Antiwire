//! Structured errors for firew-rs.

use std::fmt::{Display, Formatter};

use crate::RuleKey;

/// Broad category of failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[non_exhaustive]
pub enum ErrorKind {
    /// Insufficient privileges for the native backend.
    PermissionDenied,
    /// Rule matcher not supported on this platform/backend.
    UnsupportedMatcher,
    /// Referenced rule does not exist.
    RuleNotFound,
    /// Native backend unavailable.
    BackendUnavailable,
    /// Transaction commit failed.
    TransactionFailed,
    /// Invalid portable rule definition.
    InvalidRule,
    /// Invalid manager or backend configuration.
    InvalidConfiguration,
    /// Requested matcher or operation cannot be represented exactly.
    UnsupportedOperation,
    /// A portable or native resource limit was exceeded.
    LimitExceeded,
    /// Initial or periodic DNS resolution failed.
    DnsResolutionFailed,
    /// DNS resolution exceeded its configured deadline.
    DnsResolutionTimeout,
    /// Managed native state could not be decoded safely.
    CorruptNativeState,
    /// A rollback failed after another operation failed.
    RollbackFailed,
    /// Native state was only partially mutated.
    PartialMutation,
    /// Internal or unexpected failure.
    Internal,
}

/// Error returned by firew-rs operations.
#[derive(Debug)]
pub struct Error {
    kind: ErrorKind,
    message: String,
    logical_key: Option<RuleKey>,
    platform_detail: Option<String>,
    source: Option<Box<dyn std::error::Error + Send + Sync>>,
}

impl Error {
    /// Creates a new error with the given kind and message.
    #[must_use]
    pub fn new(kind: ErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
            logical_key: None,
            platform_detail: None,
            source: None,
        }
    }

    /// Error kind.
    #[must_use]
    pub fn kind(&self) -> ErrorKind {
        self.kind
    }

    /// Human-readable message.
    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }

    /// Logical rule key when applicable.
    #[must_use]
    pub fn logical_key(&self) -> Option<&RuleKey> {
        self.logical_key.as_ref()
    }

    /// Attaches a logical key.
    #[must_use]
    pub fn with_logical_key(mut self, key: impl Into<RuleKey>) -> Self {
        self.logical_key = Some(key.into());
        self
    }

    /// Attaches platform detail.
    #[must_use]
    pub fn with_platform_detail(mut self, detail: impl Into<String>) -> Self {
        self.platform_detail = Some(detail.into());
        self
    }

    /// Preserves an underlying platform or runtime error.
    #[must_use]
    pub fn with_source(mut self, source: impl std::error::Error + Send + Sync + 'static) -> Self {
        self.source = Some(Box::new(source));
        self
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)?;
        if let Some(key) = &self.logical_key {
            write!(f, " (rule: {key})")?;
        }
        if let Some(detail) = &self.platform_detail {
            write!(f, " [{detail}]")?;
        }
        Ok(())
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.source
            .as_deref()
            .map(|source| source as &(dyn std::error::Error + 'static))
    }
}
