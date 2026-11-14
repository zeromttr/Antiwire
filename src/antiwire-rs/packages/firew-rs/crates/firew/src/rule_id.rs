//! Public logical rule identifier.

use firew_core::RuleKey;

/// Opaque identifier for an installed firewall rule.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct RuleId {
    key: RuleKey,
}

impl RuleId {
    pub(crate) fn new(key: RuleKey) -> Self {
        Self { key }
    }

    /// Logical rule key.
    #[must_use]
    pub fn key(&self) -> &RuleKey {
        &self.key
    }
}
