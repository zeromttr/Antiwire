use std::sync::Arc;

use ipnet::IpNet;

use crate::rule::{CountrySnapshot, RuleDirection, RuleSnapshot, TargetType, Verdict};

/// Enforcement intent emitted by policy for the platform layer to apply.
///
/// DNS user rules are name-only: they are never installed natively. [`RemoveDnsRule`]
/// exists so an upgrade can tear down leftover `dr*` keys from older builds that
/// still mapped domains into the host firewall. Daemon load also calls
/// `remove_all_managed`, which clears the same namespace.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnforcementOp {
    AddAppRule {
        rule_id: i32,
        app_path: String,
        verdict: Verdict,
        direction: RuleDirection,
    },
    RemoveAppRule {
        rule_id: i32,
        app_path: String,
    },
    /// Teardown only. New DNS rules are not installed as native firewall rows.
    RemoveDnsRule {
        rule_id: i32,
        domain: String,
    },
    AddIpRule {
        rule_id: i32,
        ip: String,
        verdict: Verdict,
        direction: RuleDirection,
    },
    RemoveIpRule {
        rule_id: i32,
        ip: String,
    },
    /// Blocks outbound TCP and UDP to public `DoH` resolvers for every process,
    /// replacing any previous `DoH` block.
    AddDohBlock {
        doh_ips: Vec<String>,
        port: u16,
    },
    RemoveDohBlocks,
    /// Installs one country's networks as a single logical rule.
    ///
    /// Carries [`IpNet`] rather than strings — unlike the other variants —
    /// because the list can be tens of thousands of entries and is already
    /// normalized by the time it reaches enforcement.
    AddCountryBlock {
        rule_id: i32,
        code: String,
        networks: Arc<[IpNet]>,
        verdict: Verdict,
        direction: RuleDirection,
    },
    RemoveCountryBlock {
        rule_id: i32,
        code: String,
    },
}

impl EnforcementOp {
    /// Native firewall install for an app or IP rule.
    ///
    /// DNS snapshots return [`None`]; those rules stay in the name index only.
    #[must_use]
    pub fn native_add(rule: &RuleSnapshot) -> Option<Self> {
        match rule.target_type {
            TargetType::App => Some(Self::AddAppRule {
                rule_id: rule.id,
                app_path: rule.target.clone(),
                verdict: rule.verdict,
                direction: rule.direction,
            }),
            TargetType::Ip => Some(Self::AddIpRule {
                rule_id: rule.id,
                ip: rule.target.clone(),
                verdict: rule.verdict,
                direction: rule.direction,
            }),
            TargetType::Dns => None,
        }
    }

    /// Native firewall install for a country's networks.
    #[must_use]
    pub fn country_add(country: &CountrySnapshot) -> Self {
        Self::AddCountryBlock {
            rule_id: country.id,
            code: country.code.clone(),
            networks: Arc::clone(&country.networks),
            verdict: country.verdict,
            direction: country.direction,
        }
    }

    /// The op that takes this one back out, for an op that installs a rule.
    ///
    /// `None` for removals, whose inverse needs the removed rule's verdict and
    /// direction, and for the `DoH` block, which is a setting rather than a rule.
    #[must_use]
    pub fn undo_install(&self) -> Option<Self> {
        match self {
            Self::AddAppRule {
                rule_id, app_path, ..
            } => Some(Self::RemoveAppRule {
                rule_id: *rule_id,
                app_path: app_path.clone(),
            }),
            Self::AddIpRule { rule_id, ip, .. } => Some(Self::RemoveIpRule {
                rule_id: *rule_id,
                ip: ip.clone(),
            }),
            Self::AddCountryBlock { rule_id, code, .. } => Some(Self::RemoveCountryBlock {
                rule_id: *rule_id,
                code: code.clone(),
            }),
            Self::RemoveAppRule { .. }
            | Self::RemoveDnsRule { .. }
            | Self::RemoveIpRule { .. }
            | Self::RemoveCountryBlock { .. }
            | Self::AddDohBlock { .. }
            | Self::RemoveDohBlocks => None,
        }
    }

    /// The stored rule this op installs or removes, if it belongs to one.
    #[must_use]
    pub const fn rule_id(&self) -> Option<i32> {
        match self {
            Self::AddAppRule { rule_id, .. }
            | Self::RemoveAppRule { rule_id, .. }
            | Self::RemoveDnsRule { rule_id, .. }
            | Self::AddIpRule { rule_id, .. }
            | Self::RemoveIpRule { rule_id, .. }
            | Self::AddCountryBlock { rule_id, .. }
            | Self::RemoveCountryBlock { rule_id, .. } => Some(*rule_id),
            Self::AddDohBlock { .. } | Self::RemoveDohBlocks => None,
        }
    }

    /// Native firewall teardown for an app, IP, or leftover DNS rule.
    #[must_use]
    pub fn native_remove(rule: &RuleSnapshot) -> Option<Self> {
        match rule.target_type {
            TargetType::App => Some(Self::RemoveAppRule {
                rule_id: rule.id,
                app_path: rule.target.clone(),
            }),
            TargetType::Ip => Some(Self::RemoveIpRule {
                rule_id: rule.id,
                ip: rule.target.clone(),
            }),
            TargetType::Dns => Some(Self::RemoveDnsRule {
                rule_id: rule.id,
                domain: rule.target.clone(),
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_install_is_undone_by_the_matching_removal() {
        let rule = RuleSnapshot::new(
            7,
            TargetType::App,
            r"c:\app.exe",
            Verdict::Block,
            RuleDirection::Both,
        );
        let install = EnforcementOp::native_add(&rule).expect("app rules install natively");

        assert_eq!(install.undo_install(), EnforcementOp::native_remove(&rule));
        assert_eq!(install.rule_id(), Some(7));

        let country = CountrySnapshot::new(
            8,
            "KP",
            Arc::from(vec!["175.45.176.0/22".parse::<IpNet>().expect("network")]),
            Verdict::Block,
            RuleDirection::Both,
        );
        assert_eq!(
            EnforcementOp::country_add(&country).undo_install(),
            Some(EnforcementOp::RemoveCountryBlock {
                rule_id: 8,
                code: "KP".to_owned(),
            })
        );
        assert_eq!(
            EnforcementOp::native_remove(&rule).and_then(|op| op.undo_install()),
            None,
            "a removal cannot be undone from the op alone"
        );
    }
}
