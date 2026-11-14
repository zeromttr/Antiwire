//! Namespace-isolated naming helpers for Windows firewall objects.

use firew_core::RuleKey;
use firew_sys::ManagedNamespace;

/// Returns the `INetFw` `Grouping` string for a managed namespace.
#[must_use]
pub fn native_group_name(namespace: &ManagedNamespace) -> String {
    format!("firew-rs:{}", namespace.as_str())
}

/// Returns the namespace-scoped native rule name for one `INetFw` row.
///
/// `INetFwRules::Remove` deletes rules by `Name` alone without filtering on
/// `Grouping`, so embedding the stable [`ManagedNamespace`] in the name ensures
/// two managers using identical [`RuleKey`]s never collide on deletion.
#[must_use]
pub fn native_display_name(
    namespace: &ManagedNamespace,
    key: &RuleKey,
    part: u16,
    total: u16,
) -> String {
    format!(
        "firew-rs:{}:{} [{}/{}]",
        namespace.as_str(),
        key.as_str(),
        part + 1,
        total
    )
}

/// Legacy `INetFw` rule name format (`{key} [{part}/{total}]`) used before
/// namespace-scoped deletion names were introduced.
#[must_use]
pub fn legacy_display_name(key: &RuleKey, part: u16, total: u16) -> String {
    format!("{} [{}/{}]", key.as_str(), part + 1, total)
}
