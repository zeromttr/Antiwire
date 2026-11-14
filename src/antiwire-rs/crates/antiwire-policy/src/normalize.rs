use std::net::IpAddr;

use ipnet::IpNet;
use url::Host;

use crate::rule::{RuleDirection, RuleSnapshot, TargetType, Verdict};

/// Normalizes a rule target into the canonical representation used by policy indexes.
#[must_use]
pub fn normalize_rule(
    target_type: TargetType,
    target_value: &str,
    verdict: Verdict,
    direction: RuleDirection,
) -> Option<RuleSnapshot> {
    let trimmed = target_value.trim();
    if trimmed.is_empty() {
        return None;
    }

    let normalized = match target_type {
        TargetType::Dns => normalize_dns_target(trimmed)?,
        TargetType::App => {
            if trimmed.len() > antiwire_tuning::MAX_APP_RULE_TARGET_LENGTH as usize {
                return None;
            }
            trimmed.to_ascii_lowercase()
        }
        TargetType::Ip => parse_ip_net(trimmed)?.trunc().to_string(),
    };
    if normalized.is_empty() {
        return None;
    }

    Some(RuleSnapshot::new(
        0,
        target_type,
        normalized,
        verdict,
        direction,
    ))
}

/// Canonical DNS rule target: ASCII/punycode, no trailing dot, optional leading `*.`.
///
/// `example.com` is this host and all subdomains (Control D / `NextDNS`).
/// `*.example.com` and `*.com` match children of that suffix, not the suffix itself.
/// A leading dot (`.com`, `.co.uk`) is the bare suffix, not children-only.
pub(crate) fn normalize_dns_target(raw: &str) -> Option<String> {
    if raw.len() > antiwire_tuning::MAX_DNS_RULE_TARGET_LENGTH as usize {
        return None;
    }

    let trimmed = raw.trim_end_matches('.');
    if trimmed.is_empty() {
        return None;
    }

    let (wildcard, host) = match trimmed.strip_prefix("*.") {
        Some(suffix) => (true, suffix),
        None if trimmed.contains('*') => return None,
        None => (false, trimmed),
    };

    let host = host.trim_start_matches('.');
    if host.is_empty() || host.contains('*') {
        return None;
    }

    let ascii = hostname_to_ascii(host)?;
    if !is_valid_hostname(&ascii) {
        return None;
    }

    let normalized = if wildcard {
        format!("*.{ascii}")
    } else {
        ascii
    };
    (normalized.len() <= antiwire_tuning::MAX_DNS_RULE_TARGET_LENGTH as usize).then_some(normalized)
}

/// Lowercase ASCII, or IDNA/punycode for Unicode names (`рф` → `xn--p1ai`).
/// Runs `evaluate` on `domain` as lowercase ASCII without a trailing dot, the
/// form every `*_normalized` lookup expects. `None` for an empty name or a
/// name that has no ASCII form.
pub(crate) fn with_normalized_domain<T>(
    domain: &str,
    evaluate: impl FnOnce(&str) -> Option<T>,
) -> Option<T> {
    let domain = domain.trim_end_matches('.');
    if domain.is_empty() {
        return None;
    }
    if !domain.is_ascii() {
        return evaluate(&hostname_to_ascii(domain)?);
    }
    let mut buf = [0u8; 256];
    if let Some(lower) = crate::hash::ascii_lower_into(domain, &mut buf) {
        return evaluate(lower);
    }
    evaluate(&domain.to_ascii_lowercase())
}

pub(crate) fn hostname_to_ascii(host: &str) -> Option<String> {
    if host.is_ascii() {
        return Some(host.to_ascii_lowercase());
    }
    match Host::parse(host) {
        Ok(Host::Domain(ascii)) => Some(ascii),
        _ => None,
    }
}

/// Shared label checks for DNS rule targets and blocklist host entries.
pub(crate) fn is_valid_hostname(domain: &str) -> bool {
    if domain.is_empty() || domain.len() > 253 {
        return false;
    }
    if domain.parse::<IpAddr>().is_ok() {
        return false;
    }

    domain.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
            && label
                .as_bytes()
                .first()
                .is_some_and(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
            && label
                .as_bytes()
                .last()
                .is_some_and(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
    })
}

pub(crate) fn parse_ip_net(value: &str) -> Option<IpNet> {
    if let Ok(network) = value.parse::<IpNet>() {
        return Some(network.trunc());
    }

    let address: IpAddr = value.parse().ok()?;
    let prefix_len = if address.is_ipv4() { 32 } else { 128 };
    IpNet::new(address, prefix_len).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{RuleDirection, TargetType, Verdict};

    fn dns(target: &str) -> Option<String> {
        normalize_rule(
            TargetType::Dns,
            target,
            Verdict::Allow,
            RuleDirection::Outbound,
        )
        .map(|rule| rule.target)
    }

    #[test]
    fn accepts_exact_and_wildcard_dns_targets() {
        assert_eq!(dns("Example.COM.").as_deref(), Some("example.com"));
        assert_eq!(dns("*.Mixed.Example.").as_deref(), Some("*.mixed.example"));
        assert_eq!(dns("*.COM").as_deref(), Some("*.com"));
    }

    #[test]
    fn rejects_invalid_dns_wildcards() {
        assert!(dns("*").is_none());
        assert!(dns("*.").is_none());
        assert!(dns("foo.*.example.com").is_none());
        assert!(dns("*example.com").is_none());
        assert!(dns("example.*").is_none());
        assert!(dns("*.*.example.com").is_none());
    }

    #[test]
    fn accepts_leading_dot_tld_paste() {
        assert_eq!(dns(".com").as_deref(), Some("com"));
        assert_eq!(dns(".COM.").as_deref(), Some("com"));
        assert_eq!(dns(".co.uk").as_deref(), Some("co.uk"));
        assert!(dns("*. .com").is_none());
        assert_eq!(dns("*.com").as_deref(), Some("*.com"));
    }

    #[test]
    fn idna_encodes_unicode_dns_targets() {
        assert_eq!(dns("*.рф").as_deref(), Some("*.xn--p1ai"));
        assert_eq!(dns(".рф").as_deref(), Some("xn--p1ai"));
        assert_eq!(dns("пример.рф").as_deref(), Some("xn--e1afmkfd.xn--p1ai"));
        assert_eq!(dns("*.xn--p1ai").as_deref(), Some("*.xn--p1ai"));
    }
}
