use crate::blocklist_line::{
    normalize_listed_domain, parse_adblock_line_allowing, parse_dnsmasq_line_allowing,
};

/// Parses hosts-file and blocklist lines into normalized domain entries.
pub struct HostsParser;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostsParserMode {
    RequireHostsAddress,
    AllowBareDomains,
    /// Bare names including single-label TLDs (`christmas`, `||lol^`).
    AllowSingleLabelNames,
}

impl HostsParserMode {
    #[must_use]
    const fn allows_single_label(self) -> bool {
        matches!(self, Self::AllowSingleLabelNames)
    }
}

impl HostsParser {
    /// Visits normalized domains from one raw hosts/blocklist line without an
    /// intermediate collection.
    pub fn for_each_line_domain(line: &str, mode: HostsParserMode, mut visit: impl FnMut(String)) {
        let trimmed = line.trim();
        if trimmed.is_empty()
            || trimmed.starts_with('#')
            || trimmed.starts_with('!')
            || is_filter_list_header(trimmed)
        {
            return;
        }

        let allow_single_label = mode.allows_single_label();
        if let Some(domain) = parse_dnsmasq_line_allowing(trimmed, allow_single_label) {
            visit(domain);
            return;
        }

        if let Some(domain) = parse_adblock_line_allowing(trimmed, allow_single_label) {
            visit(domain);
            return;
        }

        let Some(rest) = split_hosts_prefix(trimmed, mode) else {
            return;
        };

        for_each_hostname(rest, allow_single_label, visit);
    }

    /// Visits normalized domains from a complete hosts file without retaining
    /// the complete parsed list.
    pub fn for_each_domain(content: &str, mode: HostsParserMode, mut visit: impl FnMut(String)) {
        for line in content.lines() {
            Self::for_each_line_domain(line, mode, &mut visit);
        }
    }
}

fn is_filter_list_header(trimmed: &str) -> bool {
    trimmed.starts_with('[') && trimmed.ends_with(']')
}

/// Strips a leading block address and returns the hostname part, or `None`
/// when `mode` requires an address and the line has none.
fn split_hosts_prefix(trimmed: &str, mode: HostsParserMode) -> Option<&str> {
    let space_idx = trimmed.find([' ', '\t']);

    if mode == HostsParserMode::RequireHostsAddress {
        let idx = space_idx?;
        if !is_block_ip(trimmed[..idx].trim()) {
            return None;
        }
        Some(&trimmed[idx..])
    } else if let Some(idx) = space_idx {
        if is_block_ip(trimmed[..idx].trim()) {
            Some(&trimmed[idx..])
        } else {
            Some(trimmed)
        }
    } else {
        Some(trimmed)
    }
}

fn for_each_hostname(mut rest: &str, allow_single_label: bool, mut visit: impl FnMut(String)) {
    rest = rest.trim();

    while !rest.is_empty() {
        if rest.starts_with('#') {
            break;
        }

        let (host, remainder) = match rest.find([' ', '\t']) {
            Some(idx) => (&rest[..idx], rest[idx..].trim_start()),
            None => (rest, ""),
        };

        if let Some(domain) = normalize_listed_domain(host, allow_single_label) {
            visit(domain);
        } else if let Some(domain) = parse_adblock_line_allowing(host, allow_single_label) {
            visit(domain);
        }

        if remainder.is_empty() {
            break;
        }
        rest = remainder;
    }
}

fn is_block_ip(ip: &str) -> bool {
    matches!(ip, "127.0.0.1" | "0.0.0.0" | "::1")
}

#[cfg(test)]
mod tests {
    use super::{HostsParser, HostsParserMode};
    use crate::blocklist::BlocklistEngine;
    use std::fs;

    fn parse_line(line: &str, mode: HostsParserMode) -> Vec<String> {
        let mut domains = Vec::new();
        HostsParser::for_each_line_domain(line, mode, |domain| domains.push(domain));
        domains
    }

    fn parse_hosts_content(content: &str, built_in_ip_prefix: bool) -> Vec<String> {
        let mut domains = Vec::new();
        let mode = if built_in_ip_prefix {
            HostsParserMode::RequireHostsAddress
        } else {
            HostsParserMode::AllowBareDomains
        };
        HostsParser::for_each_domain(content, mode, |domain| domains.push(domain));
        domains
    }

    #[test]
    fn parses_standard_hosts_lines() {
        let content = fs::read_to_string("tests/fixtures/hosts/standard_hosts.txt")
            .expect("fixture should exist");

        let domains = parse_hosts_content(&content, true);
        assert!(domains.contains(&"ads.example.com".to_owned()));
        assert!(domains.contains(&"tracker.example.com".to_owned()));
        assert!(domains.contains(&"wildcard.example.com".to_owned()));
        assert!(!domains.contains(&"public-dns.example.com".to_owned()));
    }

    #[test]
    fn ignores_comments_and_invalid_tokens() {
        let content =
            fs::read_to_string("tests/fixtures/hosts/comments_and_noise.txt").expect("fixture");

        let domains = parse_hosts_content(&content, true);
        assert_eq!(
            domains,
            vec![
                "valid.example.com".to_owned(),
                "adblock-syntax.example".to_owned(),
            ]
        );
    }

    #[test]
    fn custom_lists_accept_bare_domains() {
        let line = "bare-domain.example";
        assert_eq!(
            parse_line(line, HostsParserMode::AllowBareDomains),
            vec!["bare-domain.example".to_owned()]
        );
    }

    #[test]
    fn rejects_ip_like_domains() {
        assert!(parse_line("127.0.0.1", HostsParserMode::AllowBareDomains).is_empty());
        assert!(parse_line("no-dot", HostsParserMode::AllowBareDomains).is_empty());
        assert!(parse_line("bad|domain.example", HostsParserMode::AllowBareDomains).is_empty());
    }

    #[test]
    fn parses_adblock_fixture_lines() {
        let content = fs::read_to_string("tests/fixtures/blocklists/adblock.txt")
            .expect("fixture should exist");

        let domains = parse_hosts_content(&content, false);
        assert!(domains.contains(&"ad.xyz.com".to_owned()));
        assert!(!domains.iter().any(|domain| domain.contains("@@")));
    }

    #[test]
    fn parses_dnsmasq_fixture_lines() {
        let content = fs::read_to_string("tests/fixtures/blocklists/dnsmasq.txt")
            .expect("fixture should exist");

        let domains = parse_hosts_content(&content, false);
        assert!(domains.contains(&"ad.xyz.com".to_owned()));
        assert!(!domains.iter().any(|domain| domain.starts_with("server=")));
    }

    #[test]
    fn parses_wildcard_fixture_lines() {
        let content = fs::read_to_string("tests/fixtures/blocklists/wildcard.txt")
            .expect("fixture should exist");

        let domains = parse_hosts_content(&content, false);
        assert_eq!(domains, vec!["ab.xyz.com".to_owned()]);

        let engine = BlocklistEngine::new();
        engine.load_blocklist(domains);
        assert!(engine.is_domain_blocked("foo.ab.xyz.com"));
        assert!(engine.is_domain_blocked("ab.xyz.com"));
    }

    #[test]
    fn parses_mixed_custom_list_formats() {
        let content = fs::read_to_string("tests/fixtures/blocklists/mixed.txt")
            .expect("fixture should exist");

        let domains = parse_hosts_content(&content, false);
        assert_eq!(
            domains,
            vec![
                "ads.example.com".to_owned(),
                "tracker.example.com".to_owned(),
                "wildcard.example.com".to_owned(),
                "bare.example.com".to_owned(),
                "hosts-style.example.com".to_owned(),
            ]
        );
    }

    #[test]
    fn streaming_parser_matches_collecting_parser() {
        let content = "0.0.0.0 ads.example tracker.example\n||anchor.example^\n";
        let expected = parse_hosts_content(content, false);
        let mut streamed = Vec::new();

        HostsParser::for_each_domain(content, HostsParserMode::AllowBareDomains, |domain| {
            streamed.push(domain);
        });

        assert_eq!(streamed, expected);
    }

    #[test]
    fn parses_single_label_tld_blocklist_lines() {
        assert!(parse_line("christmas", HostsParserMode::AllowBareDomains).is_empty());
        assert_eq!(
            parse_line("christmas", HostsParserMode::AllowSingleLabelNames),
            vec!["christmas".to_owned()]
        );
        assert_eq!(
            parse_line("||lol^", HostsParserMode::AllowSingleLabelNames),
            vec!["lol".to_owned()]
        );
        assert!(parse_line("||lol^", HostsParserMode::RequireHostsAddress).is_empty());
        assert!(parse_line("||lol^", HostsParserMode::AllowBareDomains).is_empty());
    }

    #[test]
    fn extracts_adblock_tokens_from_hosts_lines() {
        assert_eq!(
            parse_line(
                "127.0.0.1 ||ad.xyz.com^",
                HostsParserMode::RequireHostsAddress
            ),
            vec!["ad.xyz.com".to_owned()]
        );
    }
}
