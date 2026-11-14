//! Native rule handle bookkeeping.

use std::fmt::{Display, Formatter};
use std::sync::Arc;

use firew_core::RuleKey;

/// Opaque native rule reference stored by platform backends.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct NativeRuleRef {
    inner: Arc<NativeRuleRefInner>,
}

#[derive(Debug, Eq, PartialEq, Hash)]
struct NativeRuleRefInner {
    backend: String,
    handles: Arc<[String]>,
    logical_key: RuleKey,
}

impl NativeRuleRef {
    /// Creates a new native reference.
    #[must_use]
    pub fn new(
        backend: impl Into<String>,
        handle: impl Into<String>,
        logical_key: RuleKey,
    ) -> Self {
        Self::from_handles(backend, [handle.into()], logical_key)
    }

    /// Creates a native reference containing every row for a logical rule.
    #[must_use]
    pub fn from_handles(
        backend: impl Into<String>,
        handles: impl IntoIterator<Item = String>,
        logical_key: RuleKey,
    ) -> Self {
        Self {
            inner: Arc::new(NativeRuleRefInner {
                backend: backend.into(),
                handles: handles.into_iter().collect(),
                logical_key,
            }),
        }
    }

    /// Backend identifier (`nftables`, `iptables`, `inetfw`, `wfp`, `pf`).
    #[must_use]
    pub fn backend(&self) -> &str {
        &self.inner.backend
    }

    /// Native handle string (backend-specific).
    #[must_use]
    pub fn handle(&self) -> &str {
        self.inner.handles.first().map_or("", String::as_str)
    }

    /// All native row handles belonging to the logical rule.
    #[must_use]
    pub fn handles(&self) -> &[String] {
        &self.inner.handles
    }

    /// Logical rule key.
    #[must_use]
    pub fn logical_key(&self) -> &RuleKey {
        &self.inner.logical_key
    }
}

impl Display for NativeRuleRef {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}:{}:{}",
            self.inner.backend,
            self.inner.handles.join(","),
            self.inner.logical_key
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clone_shares_immutable_reference_storage() {
        let native = NativeRuleRef::new(
            "mock",
            "handle",
            firew_core::RuleKey::try_from("key").expect("valid key"),
        );
        let cloned = native.clone();

        assert!(Arc::ptr_eq(&native.inner, &cloned.inner));
        assert_eq!(native, cloned);
    }
}
