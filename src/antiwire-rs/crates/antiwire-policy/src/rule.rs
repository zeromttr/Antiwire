use std::fmt;
use std::sync::Arc;

use ipnet::IpNet;

/// Firewall action for a matched rule or blocklist entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Verdict {
    Allow,
    Block,
}

impl Verdict {
    #[must_use]
    pub const fn is_block(self) -> bool {
        matches!(self, Self::Block)
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "ALLOW",
            Self::Block => "BLOCK",
        }
    }

    /// Parses a wire/database action string, case-insensitively.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        let value = value.trim();
        if value.eq_ignore_ascii_case("ALLOW") {
            Some(Self::Allow)
        } else if value.eq_ignore_ascii_case("BLOCK") {
            Some(Self::Block)
        } else {
            None
        }
    }
}

impl fmt::Display for Verdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Traffic direction a rule applies to.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, Default, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "UPPERCASE")]
pub enum RuleDirection {
    /// Traffic arriving at this host.
    Inbound,
    /// Traffic leaving this host.
    #[default]
    Outbound,
    /// Both directions.
    Both,
}

impl RuleDirection {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Inbound => "INBOUND",
            Self::Outbound => "OUTBOUND",
            Self::Both => "BOTH",
        }
    }

    /// Parses a wire/database direction string, case-insensitively.
    ///
    /// An empty value maps to [`RuleDirection::Outbound`] so rows and clients
    /// predating the direction field keep their original behaviour.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        let value = value.trim();
        if value.is_empty()
            || value.eq_ignore_ascii_case("OUT")
            || value.eq_ignore_ascii_case("OUTBOUND")
        {
            Some(Self::Outbound)
        } else if value.eq_ignore_ascii_case("IN") || value.eq_ignore_ascii_case("INBOUND") {
            Some(Self::Inbound)
        } else if value.eq_ignore_ascii_case("BOTH") || value.eq_ignore_ascii_case("ANY") {
            Some(Self::Both)
        } else {
            None
        }
    }
}

impl fmt::Display for RuleDirection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Rule target category.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TargetType {
    App,
    Dns,
    Ip,
}

impl TargetType {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::App => "APPLICATION",
            Self::Dns => "DNS",
            Self::Ip => "IP",
        }
    }
}

impl fmt::Display for TargetType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Immutable rule snapshot used on evaluation hot paths.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleSnapshot {
    pub id: i32,
    pub target_type: TargetType,
    pub target: String,
    pub verdict: Verdict,
    pub direction: RuleDirection,
}

impl RuleSnapshot {
    #[must_use]
    pub(crate) fn new(
        id: i32,
        target_type: TargetType,
        target: impl Into<String>,
        verdict: Verdict,
        direction: RuleDirection,
    ) -> Self {
        Self {
            id,
            target_type,
            target: target.into(),
            verdict,
            direction,
        }
    }
}

/// A country block: one logical rule covering many networks.
///
/// Deliberately not a [`TargetType`] variant — that enum drives a three-way
/// dispatch keyed on a single target string, and a country is a set of
/// networks rather than one target.
///
/// `networks` is an [`Arc`] slice so cloning a snapshot into an enforcement op
/// is a refcount bump rather than copying tens of thousands of entries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CountrySnapshot {
    pub id: i32,
    /// ISO-3166-1 alpha-2 code, uppercase.
    pub code: String,
    /// Normalized, deduplicated, sorted networks.
    pub networks: Arc<[IpNet]>,
    pub verdict: Verdict,
    pub direction: RuleDirection,
}

impl CountrySnapshot {
    #[must_use]
    pub fn new(
        id: i32,
        code: impl Into<String>,
        networks: Arc<[IpNet]>,
        verdict: Verdict,
        direction: RuleDirection,
    ) -> Self {
        Self {
            id,
            code: code.into(),
            networks,
            verdict,
            direction,
        }
    }
}

/// What a stored firewall rule targets: one of the [`TargetType`]s, or a country.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum RuleTargetKind {
    Application,
    Dns,
    Ip,
    Country,
}

impl RuleTargetKind {
    /// The name the store and the wire use.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Application => "APPLICATION",
            Self::Dns => "DNS",
            Self::Ip => "IP",
            Self::Country => "COUNTRY",
        }
    }

    /// Parses a stored or wire name, case-insensitively. Accepts the `APP` and
    /// `IP_CIDR` aliases older clients and rows use.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_uppercase().as_str() {
            "APPLICATION" | "APP" => Some(Self::Application),
            "DNS" => Some(Self::Dns),
            "IP" | "IP_CIDR" => Some(Self::Ip),
            "COUNTRY" => Some(Self::Country),
            _ => None,
        }
    }

    /// The single-target type of a simple rule, or `None` for a country.
    #[must_use]
    pub const fn target_type(self) -> Option<TargetType> {
        match self {
            Self::Application => Some(TargetType::App),
            Self::Dns => Some(TargetType::Dns),
            Self::Ip => Some(TargetType::Ip),
            Self::Country => None,
        }
    }
}

impl From<TargetType> for RuleTargetKind {
    fn from(target_type: TargetType) -> Self {
        match target_type {
            TargetType::App => Self::Application,
            TargetType::Dns => Self::Dns,
            TargetType::Ip => Self::Ip,
        }
    }
}

impl fmt::Display for RuleTargetKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn target_kinds_round_trip_and_accept_legacy_aliases() {
        for kind in [
            RuleTargetKind::Application,
            RuleTargetKind::Dns,
            RuleTargetKind::Ip,
            RuleTargetKind::Country,
        ] {
            assert_eq!(RuleTargetKind::parse(kind.as_str()), Some(kind));
        }
        assert_eq!(
            RuleTargetKind::parse(" app "),
            Some(RuleTargetKind::Application)
        );
        assert_eq!(RuleTargetKind::parse("ip_cidr"), Some(RuleTargetKind::Ip));
        assert_eq!(RuleTargetKind::parse("PORT"), None);
        assert_eq!(RuleTargetKind::Country.target_type(), None);
        assert_eq!(RuleTargetKind::from(TargetType::Dns), RuleTargetKind::Dns);
    }
}
