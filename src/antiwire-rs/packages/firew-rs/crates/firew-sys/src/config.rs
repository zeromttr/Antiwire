//! Backend configuration.

use firew_core::{Error, ErrorKind};

use crate::marker::ManagedNamespace;

/// Maximum bytes in manager and application display names.
pub const MAX_MANAGER_NAME_LEN: usize = 64;

/// Default ceiling for addresses in one native Windows `INetFw` rule.
///
/// Measured, not guessed: `INetFwRules::Add` accepts exactly 10,000 remote
/// addresses and rejects 10,001 with `RPC_S_INVALID_BOUND` (0x800706C6). The
/// limit is on the address *count* rather than the rendered string length, and
/// the COM path and PowerShell's `New-NetFirewallRule` hit it identically.
///
/// At 10,000 the round trip is exact — read-back preserves the count, the set,
/// and the ordering — and installation costs roughly 90 ms.
///
/// Reproduce with `firew-windows`'s `live_inetfw_address_set_ceiling` test, or
/// `scripts/measure-inetfw-address-ceiling.ps1`.
pub const DEFAULT_INETFW_ADDRESS_SET_LIMIT: usize = 10_000;

/// Explicit backend selection for testing or overrides.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum BackendPreference {
    /// Auto-detect the best available backend.
    #[default]
    Auto,
    /// Linux nftables.
    Nftables,
    /// Linux iptables.
    Iptables,
    /// Windows `INetFw` COM.
    InetFw,
    /// Windows WFP.
    Wfp,
    /// macOS/BSD PF.
    Pf,
}

/// Configuration passed when opening a native backend.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BackendConfig {
    /// Manager tag isolating managed rules (e.g. `firew`).
    pub name_prefix: String,
    /// Application name appended to Windows rule display names.
    pub application_name: String,
    /// Memory-mode semantics: facade tracks rules for cleanup.
    pub memory_mode: bool,
    /// Backend preference override.
    pub prefer_backend: BackendPreference,
    /// Overrides a backend's native address-set ceiling.
    ///
    /// `None` keeps each backend's own default. `Some(n)` caps the number of
    /// remote addresses a single native set may hold, which is how the Windows
    /// ceiling is tuned once measured.
    pub max_address_set_entries: Option<usize>,
}

impl BackendConfig {
    /// Creates config with defaults.
    #[must_use]
    pub fn new(name_prefix: impl Into<String>) -> Self {
        Self {
            name_prefix: name_prefix.into(),
            application_name: String::new(),
            memory_mode: false,
            prefer_backend: BackendPreference::Auto,
            max_address_set_entries: None,
        }
    }

    /// Validates portable manager configuration before native initialization.
    ///
    /// # Errors
    ///
    /// Returns an error for empty, oversized, or NUL-containing names.
    pub fn validate(&self) -> Result<(), Error> {
        validate_name("manager name", &self.name_prefix, false)?;
        validate_name("application name", &self.application_name, true)?;
        Ok(())
    }

    /// Stable ownership namespace used by native markers and containers.
    #[must_use]
    pub fn managed_namespace(&self) -> ManagedNamespace {
        ManagedNamespace::derive(&self.name_prefix, &self.application_name)
    }

    /// Display name for Windows rules: `{prefix}:{app}:{logical_key}`.
    #[must_use]
    pub fn display_name(&self, logical_key: impl std::fmt::Display) -> String {
        if self.application_name.is_empty() {
            format!("{}:{}", self.name_prefix, logical_key)
        } else {
            format!(
                "{}:{}:{}",
                self.name_prefix, self.application_name, logical_key
            )
        }
    }

    /// Managed key prefix for health probes and listing.
    #[cfg(test)]
    #[must_use]
    pub fn managed_prefix(&self) -> String {
        if self.application_name.is_empty() {
            format!("{}:", self.name_prefix)
        } else {
            format!("{}:{}:", self.name_prefix, self.application_name)
        }
    }
}

fn validate_name(name: &str, value: &str, allow_empty: bool) -> Result<(), Error> {
    if (!allow_empty && value.is_empty()) || value.contains('\0') {
        return Err(Error::new(
            ErrorKind::InvalidConfiguration,
            format!("{name} is empty or contains a NUL"),
        ));
    }
    if value.len() > MAX_MANAGER_NAME_LEN {
        return Err(Error::new(
            ErrorKind::LimitExceeded,
            format!("{name} exceeds {MAX_MANAGER_NAME_LEN} bytes"),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_name_formats() {
        let config = BackendConfig::new("p");
        assert_eq!(config.display_name("k"), "p:k");
    }

    #[test]
    fn managed_prefix_with_app() {
        let mut config = BackendConfig::new("p");
        config.application_name = "app".to_owned();
        assert_eq!(config.managed_prefix(), "p:app:");
    }
}
