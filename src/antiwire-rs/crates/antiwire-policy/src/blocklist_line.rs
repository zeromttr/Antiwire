use std::borrow::Cow;

use crate::normalize::{hostname_to_ascii, is_valid_hostname};

/// Normalizes delimiters, borrowing the original input for ASCII names.
///
/// An internationalized name (`пример.рф`) is converted to the A-label form
/// queries arrive in (`xn--e1afmkfd.xn--p1ai`), as DNS rule targets are, so it
/// still matches instead of being dropped.
#[must_use]
pub(crate) fn normalized_blocklist_domain(raw: &str) -> Option<Cow<'_, str>> {
    let mut domain = raw.trim();
    if let Some(stripped) = domain.strip_prefix("*.") {
        domain = stripped;
    }
    domain = domain.trim_end_matches('.');

    let domain = if domain.is_ascii() {
        Cow::Borrowed(domain)
    } else {
        Cow::Owned(hostname_to_ascii(domain)?)
    };
    is_valid_hostname(&domain).then_some(domain)
}

/// Normalizes a raw domain token from any supported blocklist format.
#[cfg(test)]
#[must_use]
pub(crate) fn normalize_domain(raw: &str) -> Option<String> {
    normalize_listed_domain(raw, false)
}

/// Like [`normalize_domain`], optionally keeping single-label names (TLDs).
#[must_use]
pub(crate) fn normalize_listed_domain(raw: &str, allow_single_label: bool) -> Option<String> {
    let domain = normalized_blocklist_domain(raw)?;
    if !allow_single_label && !domain.contains('.') {
        return None;
    }
    Some(domain.to_ascii_lowercase())
}

/// Extracts a blocked domain from an Adblock-style DNS rule line.
#[cfg(test)]
#[must_use]
pub(crate) fn parse_adblock_line(line: &str) -> Option<String> {
    parse_adblock_line_allowing(line, false)
}

#[must_use]
pub(crate) fn parse_adblock_line_allowing(line: &str, allow_single_label: bool) -> Option<String> {
    let trimmed = line.trim();
    if trimmed.is_empty() || trimmed.starts_with("@@") {
        return None;
    }

    if is_adblock_cosmetic_rule(trimmed) {
        return None;
    }

    if trimmed.starts_with('/') && !trimmed.starts_with("||") {
        return None;
    }

    if let Some(rest) = trimmed.strip_prefix("||") {
        let domain = extract_adblock_pattern(rest);
        return normalize_listed_domain(domain, allow_single_label);
    }

    if trimmed.find([' ', '\t']).is_none() {
        return normalize_listed_domain(trimmed, allow_single_label);
    }

    None
}

/// Extracts a blocked domain from a dnsmasq `local=/` or `address=/` directive.
#[cfg(test)]
#[must_use]
pub(crate) fn parse_dnsmasq_line(line: &str) -> Option<String> {
    parse_dnsmasq_line_allowing(line, false)
}

#[must_use]
pub(crate) fn parse_dnsmasq_line_allowing(line: &str, allow_single_label: bool) -> Option<String> {
    let trimmed = line.trim();
    if trimmed.starts_with("server=/") {
        return None;
    }

    for prefix in ["local=/", "address=/"] {
        if let Some(rest) = trimmed.strip_prefix(prefix) {
            let domain = rest.split('/').next().unwrap_or("");
            return normalize_listed_domain(domain, allow_single_label);
        }
    }

    None
}

fn extract_adblock_pattern(rest: &str) -> &str {
    let end = rest.find(['^', '$', ' ', '\t']).unwrap_or(rest.len());
    &rest[..end]
}

fn is_adblock_cosmetic_rule(line: &str) -> bool {
    ["##", "#?#", "#@#", "#$#"]
        .iter()
        .any(|marker| line.contains(marker))
}

#[cfg(test)]
mod tests {
    use super::{
        normalize_domain, normalize_listed_domain, parse_adblock_line, parse_adblock_line_allowing,
        parse_dnsmasq_line,
    };
    use crate::normalize::is_valid_hostname;

    #[test]
    fn adblock_extracts_domain_anchor_rules() {
        assert_eq!(
            parse_adblock_line("||ad.xyz.com^"),
            Some("ad.xyz.com".to_owned())
        );
        assert_eq!(
            parse_adblock_line("||ad.xyz.com^$important,client=127.0.0.1"),
            Some("ad.xyz.com".to_owned())
        );
        assert_eq!(
            parse_adblock_line("||ad.xyz.com"),
            Some("ad.xyz.com".to_owned())
        );
        assert_eq!(
            parse_adblock_line("||AD.XYZ.COM^"),
            Some("ad.xyz.com".to_owned())
        );
    }

    #[test]
    fn adblock_skips_exceptions_and_non_dns_rules() {
        assert_eq!(parse_adblock_line("@@||ad.xyz.com^"), None);
        assert_eq!(parse_adblock_line("/ads/"), None);
        assert_eq!(parse_adblock_line("example.com##.ad"), None);
        assert_eq!(parse_adblock_line("127.0.0.1 ||ad.xyz.com^"), None);
    }

    #[test]
    fn adblock_accepts_domains_only_syntax() {
        assert_eq!(
            parse_adblock_line("bare.example.com"),
            Some("bare.example.com".to_owned())
        );
    }

    #[test]
    fn dnsmasq_extracts_local_and_address_directives() {
        assert_eq!(
            parse_dnsmasq_line("local=/ad.xyz.com/"),
            Some("ad.xyz.com".to_owned())
        );
        assert_eq!(
            parse_dnsmasq_line("local=/ad.xyz.com"),
            Some("ad.xyz.com".to_owned())
        );
        assert_eq!(
            parse_dnsmasq_line("address=/ad.xyz.com/0.0.0.0"),
            Some("ad.xyz.com".to_owned())
        );
        assert_eq!(
            parse_dnsmasq_line("address=/ad.xyz.com/#"),
            Some("ad.xyz.com".to_owned())
        );
        assert_eq!(
            parse_dnsmasq_line("address=/*.google.com/"),
            Some("google.com".to_owned())
        );
    }

    #[test]
    fn dnsmasq_skips_server_directives() {
        assert_eq!(parse_dnsmasq_line("server=/ad.xyz.com/#"), None);
        assert_eq!(parse_dnsmasq_line("server=/ad.xyz.com/1.2.3.4"), None);
    }

    #[test]
    fn normalize_domain_strips_wildcard_and_dots() {
        assert_eq!(
            normalize_domain("*.ab.xyz.com"),
            Some("ab.xyz.com".to_owned())
        );
        assert_eq!(
            normalize_domain("tracker.example.com."),
            Some("tracker.example.com".to_owned())
        );
        assert_eq!(normalize_domain("christmas"), None);
        assert_eq!(
            normalize_listed_domain("christmas", true),
            Some("christmas".to_owned())
        );
        assert_eq!(parse_adblock_line("||christmas^"), None);
        assert_eq!(
            parse_adblock_line_allowing("||christmas^", true),
            Some("christmas".to_owned())
        );
    }

    #[test]
    fn blocklist_domain_validation_rejects_ips_and_bad_labels() {
        assert!(!is_valid_hostname("127.0.0.1"));
        assert!(!is_valid_hostname("bad..example"));
        assert!(!is_valid_hostname("-bad.example"));
        assert!(is_valid_hostname("localhost"));
        assert!(is_valid_hostname("ads.example"));
    }

    #[test]
    fn internationalized_entries_become_a_labels_in_every_format() {
        let a_label = Some("xn--e1afmkfd.xn--p1ai".to_owned());
        assert_eq!(normalize_domain("пример.рф"), a_label);
        assert_eq!(normalize_domain("ПРИМЕР.РФ."), a_label);
        assert_eq!(normalize_domain("xn--e1afmkfd.xn--p1ai"), a_label);
        assert_eq!(parse_adblock_line("||пример.рф^"), a_label);
        assert_eq!(parse_dnsmasq_line("address=/пример.рф/0.0.0.0"), a_label);
        assert_eq!(normalize_domain("bad..пример.рф"), None);
    }
}
