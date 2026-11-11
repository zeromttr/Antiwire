//! Health probe snapshot.

use std::collections::HashSet;

use firew_core::RuleKey;

/// Result of a native health probe for managed rules.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct HealthSnapshot {
    /// Logical keys missing from native but expected.
    pub missing_keys: HashSet<RuleKey>,
    /// Extra managed keys found natively but not in the registry.
    pub extra_keys: HashSet<RuleKey>,
}

impl HealthSnapshot {
    /// Builds a snapshot without cloning keys that are present in both inputs.
    pub fn from_present<'a>(
        present_keys: impl IntoIterator<Item = &'a RuleKey>,
        expected_keys: &[RuleKey],
    ) -> Self {
        let present: HashSet<&RuleKey> = present_keys.into_iter().collect();
        let expected: HashSet<&RuleKey> = expected_keys.iter().collect();
        let missing_keys = expected_keys
            .iter()
            .filter(|key| !present.contains(*key))
            .cloned()
            .collect();
        let extra_keys = present
            .into_iter()
            .filter(|key| !expected.contains(key))
            .cloned()
            .collect();

        Self {
            missing_keys,
            extra_keys,
        }
    }

    /// Whether any drift was detected.
    #[cfg(test)]
    #[must_use]
    pub fn has_drift(&self) -> bool {
        !self.missing_keys.is_empty() || !self.extra_keys.is_empty()
    }

    /// Total drift count.
    #[cfg(test)]
    #[must_use]
    pub fn drift_count(&self) -> usize {
        self.missing_keys.len() + self.extra_keys.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(value: &str) -> RuleKey {
        RuleKey::try_from(value).expect("valid key")
    }

    #[test]
    fn detects_drift() {
        let snap = HealthSnapshot {
            missing_keys: [key("b")].into_iter().collect(),
            extra_keys: [key("c")].into_iter().collect(),
        };
        assert!(snap.has_drift());
        assert_eq!(snap.drift_count(), 2);
    }

    #[test]
    fn builds_snapshot_from_borrowed_keys() {
        let present = [key("a"), key("c")];
        let expected = vec![key("a"), key("b")];
        let snap = HealthSnapshot::from_present(&present, &expected);

        assert_eq!(snap.missing_keys, [key("b")].into());
        assert_eq!(snap.extra_keys, [key("c")].into());
    }
}
