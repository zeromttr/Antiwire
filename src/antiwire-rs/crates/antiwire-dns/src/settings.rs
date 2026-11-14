use std::net::IpAddr;
use std::str::FromStr;

use crate::upstream::upstreams_for_settings;

/// Upstream transport selected from daemon settings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum DnsProtocol {
    #[default]
    Udp,
    Tcp,
    Tls,
    Quic,
    Https,
    H3,
}

impl DnsProtocol {
    fn parse(value: &str) -> Option<Self> {
        Some(match value.trim().to_ascii_lowercase().as_str() {
            "udp" | "plain" => Self::Udp,
            "tcp" => Self::Tcp,
            "dot" | "tls" => Self::Tls,
            "doq" | "quic" => Self::Quic,
            "doh" | "https" => Self::Https,
            "doh3" | "h3" => Self::H3,
            _ => return None,
        })
    }

    /// The protocol a settings string selects.
    ///
    /// Plaintext is used only when asked for by name. An empty or unknown value
    /// falls back to DNS-over-HTTPS, the settings default, rather than sending
    /// every query unencrypted.
    #[must_use]
    pub(crate) fn from_settings(value: &str) -> Self {
        let value = value.trim();
        if value.is_empty() {
            return Self::Https;
        }
        Self::parse(value).unwrap_or_else(|| {
            tracing::warn!(
                protocol = value,
                "unknown DNS protocol in settings; using DNS-over-HTTPS"
            );
            Self::Https
        })
    }
}

/// Whether `value` names a DNS protocol the resolver supports. Empty selects
/// the default.
#[must_use]
pub fn is_known_dns_protocol(value: &str) -> bool {
    value.trim().is_empty() || DnsProtocol::parse(value).is_some()
}

/// Checks that the resolver could start with the upstreams `settings` select,
/// using the same parsing it starts with, so a setting it would reject (such as
/// a custom upstream it cannot dial) is refused before it is saved.
///
/// # Errors
///
/// Returns [`crate::DnsError::Config`] naming the upstream that cannot be used.
pub fn check_upstream_settings(settings: &antiwire_store::DaemonSetting) -> crate::Result<()> {
    let (protocol, upstreams) = upstreams_for_settings(settings);
    crate::upstream::check_upstream_endpoints(protocol, &upstreams)
}

/// Runtime configuration for [`crate::query_engine::QueryEngine`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DnsConfig {
    pub(crate) protocol: DnsProtocol,
    pub(crate) upstreams: Vec<String>,
    pub(crate) block_mode: crate::block::BlockResponseMode,
    pub(crate) custom_block_ip: Option<IpAddr>,
    pub(crate) rebinding_protection_enabled: bool,
    /// False forwards `.local` names upstream (Active Directory domains).
    pub(crate) answer_local_names: bool,
    /// Blocks names registered fewer than this many days ago; `None` is off.
    pub(crate) new_domain_max_age_days: Option<u32>,
}

impl Default for DnsConfig {
    fn default() -> Self {
        Self {
            protocol: DnsProtocol::Udp,
            upstreams: vec!["1.1.1.1:53".to_owned()],
            block_mode: crate::block::BlockResponseMode::Sinkhole,
            custom_block_ip: None,
            rebinding_protection_enabled: false,
            answer_local_names: true,
            new_domain_max_age_days: None,
        }
    }
}

impl DnsConfig {
    #[must_use]
    pub(crate) fn from_settings(
        protocol: DnsProtocol,
        upstreams: &[String],
        block_mode: &str,
        custom_block_ip: &str,
        rebinding_protection_enabled: bool,
        answer_local_names: bool,
    ) -> Self {
        let custom_block_ip = IpAddr::from_str(custom_block_ip.trim()).ok();
        let mut block_mode = crate::block::BlockResponseMode::from_settings(block_mode);
        if block_mode == crate::block::BlockResponseMode::Custom && custom_block_ip.is_none() {
            // Custom mode has nothing to answer with, which would turn every
            // block into a build error. Sinkhole still blocks.
            tracing::warn!("custom dns block mode has no valid custom_block_ip; using sinkhole");
            block_mode = crate::block::BlockResponseMode::Sinkhole;
        }
        Self {
            protocol,
            upstreams: upstreams.to_vec(),
            block_mode,
            custom_block_ip,
            rebinding_protection_enabled,
            answer_local_names,
            new_domain_max_age_days: None,
        }
    }
}

/// Builds stub configuration from daemon settings.
#[must_use]
pub(crate) fn dns_config_from_settings(settings: &antiwire_store::DaemonSetting) -> DnsConfig {
    let (protocol, upstreams) = upstreams_for_settings(settings);
    let config = DnsConfig::from_settings(
        protocol,
        &upstreams,
        &settings.dns_block_response_mode,
        &settings.dns_block_custom_ip,
        settings.power_user_settings_enabled && settings.dns_rebinding_protection_enabled,
        // Like rebinding, the stored value only applies with power-user settings on.
        // Hidden, it is inert and `.local` names stay answered locally (the default).
        !settings.power_user_settings_enabled || settings.dns_answer_local_names_enabled,
    );
    DnsConfig {
        new_domain_max_age_days: settings
            .dns_new_domain_blocking_enabled
            .then(|| new_domain_max_age_days(settings.dns_new_domain_max_age_days)),
        ..config
    }
}

/// A saved age the settings no longer offer uses the default rather than
/// turning the block off.
fn new_domain_max_age_days(days: u32) -> u32 {
    if crate::new_domain::is_supported_new_domain_max_age(days) {
        days
    } else {
        crate::new_domain::DEFAULT_NEW_DOMAIN_MAX_AGE_DAYS
    }
}

/// Returns true when the settings produce a different resolver configuration.
///
/// Compares what [`dns_config_from_settings`] builds rather than listing
/// fields, so a setting it starts reading is picked up here too, and an edit
/// that changes nothing the resolver uses does not restart it.
#[must_use]
pub(crate) fn dns_config_changed(
    prev: &antiwire_store::DaemonSetting,
    next: &antiwire_store::DaemonSetting,
) -> bool {
    dns_config_from_settings(prev) != dns_config_from_settings(next)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_protocol_aliases() {
        assert_eq!(DnsProtocol::from_settings("DoQ"), DnsProtocol::Quic);
        assert_eq!(DnsProtocol::from_settings("doh3"), DnsProtocol::H3);
        assert_eq!(DnsProtocol::from_settings("plain"), DnsProtocol::Udp);
        assert_eq!(DnsProtocol::from_settings("udp"), DnsProtocol::Udp);
    }

    /// The regression this guards: a typo in the protocol silently sent every
    /// query as plaintext UDP.
    #[test]
    fn unknown_or_empty_protocol_falls_back_to_https() {
        assert_eq!(
            DnsProtocol::from_settings("dns-over-http"),
            DnsProtocol::Https
        );
        assert_eq!(DnsProtocol::from_settings(""), DnsProtocol::Https);
        assert!(!is_known_dns_protocol("dns-over-http"));
        assert!(is_known_dns_protocol("DoQ"));
        assert!(is_known_dns_protocol(""));
    }

    #[test]
    fn builds_config_from_settings_values() {
        let config = DnsConfig::from_settings(
            DnsProtocol::Tls,
            &["9.9.9.9:853".to_owned()],
            "custom",
            "10.0.0.1",
            true,
            false,
        );
        assert_eq!(config.protocol, DnsProtocol::Tls);
        assert_eq!(config.custom_block_ip, Some("10.0.0.1".parse().unwrap()));
        assert!(config.rebinding_protection_enabled);
        assert!(!config.answer_local_names);
    }

    /// Custom mode with no usable address cannot answer anything; it falls
    /// back to sinkhole rather than turning every block into SERVFAIL.
    #[test]
    fn custom_mode_without_a_valid_ip_falls_back_to_sinkhole() {
        for ip in ["", "  ", "not-an-ip", "10.0.0"] {
            let config =
                DnsConfig::from_settings(DnsProtocol::Https, &[], "custom", ip, false, true);
            assert_eq!(
                config.block_mode,
                crate::block::BlockResponseMode::Sinkhole,
                "{ip:?}"
            );
        }
    }

    #[test]
    fn local_names_setting_applies_only_with_power_user_settings() {
        let mut settings = antiwire_store::DaemonSetting {
            dns_answer_local_names_enabled: false,
            power_user_settings_enabled: false,
            ..antiwire_store::DaemonSetting::default()
        };
        assert!(dns_config_from_settings(&settings).answer_local_names);

        settings.power_user_settings_enabled = true;
        assert!(!dns_config_from_settings(&settings).answer_local_names);

        settings.dns_answer_local_names_enabled = true;
        assert!(dns_config_from_settings(&settings).answer_local_names);
    }

    #[test]
    fn rebinding_requires_power_user_settings() {
        let mut settings = antiwire_store::DaemonSetting {
            dns_rebinding_protection_enabled: true,
            power_user_settings_enabled: false,
            ..antiwire_store::DaemonSetting::default()
        };
        let config = dns_config_from_settings(&settings);
        assert!(!config.rebinding_protection_enabled);

        settings.power_user_settings_enabled = true;
        let config = dns_config_from_settings(&settings);
        assert!(config.rebinding_protection_enabled);
    }

    #[test]
    fn default_daemon_settings_yield_cloudflare_doh_upstreams() {
        let settings = antiwire_store::DaemonSetting::default();
        let config = dns_config_from_settings(&settings);
        assert_eq!(config.protocol, DnsProtocol::Https);
        let dialled = crate::upstream::dialled_addresses(config.protocol, &config.upstreams);
        assert!(
            dialled.contains(&"1.1.1.1".parse().expect("ip")),
            "{dialled:?}"
        );
    }

    #[test]
    fn dot_daemon_settings_yield_cloudflare_endpoints() {
        let settings = antiwire_store::DaemonSetting {
            dns_protocol: "dot".to_owned(),
            ..antiwire_store::DaemonSetting::default()
        };
        let config = dns_config_from_settings(&settings);
        assert_eq!(config.protocol, DnsProtocol::Tls);
        let dialled = crate::upstream::dialled_addresses(config.protocol, &config.upstreams);
        assert!(
            dialled.contains(&"1.1.1.1".parse().expect("ip")),
            "{dialled:?}"
        );
        assert!(config.upstreams[0].ends_with(":853"));
    }

    #[test]
    fn dns_config_changed_detects_provider_updates() {
        let prev = antiwire_store::DaemonSetting::default();
        let mut next = prev.clone();
        next.doh_provider = "quad9".to_owned();
        assert!(dns_config_changed(&prev, &next));
    }

    #[test]
    fn dns_config_change_follows_what_the_resolver_uses() {
        let prev = antiwire_store::DaemonSetting::default();

        // Rebinding protection only applies with power-user settings on.
        let mut hidden = prev.clone();
        hidden.power_user_settings_enabled = false;
        hidden.dns_rebinding_protection_enabled = !prev.dns_rebinding_protection_enabled;
        let mut base = prev.clone();
        base.power_user_settings_enabled = false;
        assert!(!dns_config_changed(&base, &hidden));

        let mut active = hidden.clone();
        active.power_user_settings_enabled = true;
        active.dns_rebinding_protection_enabled = true;
        let mut inactive = active.clone();
        inactive.dns_rebinding_protection_enabled = false;
        assert!(dns_config_changed(&inactive, &active));

        let mut block_ip = prev.clone();
        block_ip.dns_block_custom_ip = "10.0.0.1".to_owned();
        assert!(dns_config_changed(&prev, &block_ip));
    }

    #[test]
    fn new_domain_blocking_uses_the_saved_age_only_when_enabled() {
        let mut settings = antiwire_store::DaemonSetting {
            dns_new_domain_max_age_days: 14,
            ..antiwire_store::DaemonSetting::default()
        };
        assert_eq!(
            dns_config_from_settings(&settings).new_domain_max_age_days,
            None
        );

        settings.dns_new_domain_blocking_enabled = true;
        assert_eq!(
            dns_config_from_settings(&settings).new_domain_max_age_days,
            Some(14)
        );

        settings.dns_new_domain_max_age_days = 45;
        assert_eq!(
            dns_config_from_settings(&settings).new_domain_max_age_days,
            Some(crate::new_domain::DEFAULT_NEW_DOMAIN_MAX_AGE_DAYS),
            "an age the settings do not offer uses the default"
        );
    }

    #[test]
    fn new_domain_age_change_restarts_the_resolver_only_when_enabled() {
        let prev = antiwire_store::DaemonSetting::default();
        let mut next = prev.clone();
        next.dns_new_domain_max_age_days = 90;
        assert!(!dns_config_changed(&prev, &next));

        let mut enabled = prev.clone();
        enabled.dns_new_domain_blocking_enabled = true;
        assert!(dns_config_changed(&prev, &enabled));
        let mut longer = enabled.clone();
        longer.dns_new_domain_max_age_days = 90;
        assert!(dns_config_changed(&enabled, &longer));
    }

    #[test]
    fn dns_config_change_excludes_lifecycle_enablement() {
        let prev = antiwire_store::DaemonSetting::default();
        let mut next = prev.clone();
        next.dns_resolver_enabled = !prev.dns_resolver_enabled;

        assert!(!dns_config_changed(&prev, &next));
    }
}
