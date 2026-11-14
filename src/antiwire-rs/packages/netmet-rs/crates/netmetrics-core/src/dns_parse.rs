use std::net::IpAddr;

/// Addresses that should share one DNS hint so dual-stack lookups hit the same domain.
#[must_use]
pub fn ip_aliases(addr: IpAddr) -> Vec<IpAddr> {
    let canonical = canonicalize_ip(addr);
    match canonical {
        IpAddr::V4(v4) => vec![IpAddr::V4(v4), IpAddr::V6(v4.to_ipv6_mapped())],
        IpAddr::V6(v6) => vec![IpAddr::V6(v6)],
    }
}

/// Maps IPv4-mapped IPv6 addresses onto the IPv4 they represent.
#[must_use]
pub fn canonicalize_ip(addr: IpAddr) -> IpAddr {
    match addr {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(addr, IpAddr::V4),
        IpAddr::V4(_) => addr,
    }
}

/// Extracts IP answers and an optional TTL from Windows DNS-Client `QueryResults` text.
///
/// Compatibility wrapper around [`parse_dns_result_addresses`].
#[must_use]
pub fn parse_dns_result_text(text: &str) -> (Vec<String>, u64) {
    let (answers, ttl_ms) = parse_dns_result_addresses(text);
    (
        answers
            .into_iter()
            .map(|address| address.to_string())
            .collect(),
        ttl_ms,
    )
}

/// Parses Windows DNS-Client `QueryResults` text into canonical, deduplicated addresses.
#[must_use]
pub fn parse_dns_result_addresses(text: &str) -> (Vec<IpAddr>, u64) {
    let (answers, ttl_ms) = parse_dns_result_addresses_with_ttl(text);
    (answers, ttl_ms.unwrap_or(0))
}

/// Parses Windows DNS result text while retaining whether a TTL was absent.
#[doc(hidden)]
#[must_use]
pub fn parse_dns_result_addresses_with_ttl(text: &str) -> (Vec<IpAddr>, Option<u64>) {
    let mut answers = Vec::new();
    for token in text.split([';', ',', ' ', '\t', '\r', '\n']) {
        let token = token.trim();
        if token.is_empty()
            || token.eq_ignore_ascii_case("ttl")
            || token
                .strip_suffix(':')
                .is_some_and(|label| label.eq_ignore_ascii_case("ttl"))
        {
            continue;
        }
        if let Ok(address) = token.parse::<IpAddr>() {
            let address = canonicalize_ip(address);
            if !answers.contains(&address) {
                answers.push(address);
            }
        }
    }
    (answers, parse_ttl_ms(text))
}

fn parse_ttl_ms(text: &str) -> Option<u64> {
    let mut rest = text;
    let mut ttl_ms = None::<u64>;
    while let Some(index) = find_ttl_marker(rest) {
        rest = rest[index.saturating_add(4)..].trim_start();
        let digits_end = rest
            .char_indices()
            .find(|(_, ch)| !ch.is_ascii_digit())
            .map_or(rest.len(), |(offset, _)| offset);
        if let Ok(seconds) = rest[..digits_end].parse::<u64>() {
            let this_ttl = seconds.saturating_mul(1_000);
            ttl_ms = Some(ttl_ms.map_or(this_ttl, |current| current.min(this_ttl)));
        }
        rest = &rest[digits_end..];
    }
    ttl_ms
}

fn find_ttl_marker(text: &str) -> Option<usize> {
    let bytes = text.as_bytes();
    if bytes.len() < 4 {
        return None;
    }
    bytes.windows(4).position(|window| {
        window[0].eq_ignore_ascii_case(&b't')
            && window[1].eq_ignore_ascii_case(&b't')
            && window[2].eq_ignore_ascii_case(&b'l')
            && window[3] == b':'
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn result_text_unwraps_mapped_v4_and_reads_ttl() {
        let (answers, ttl_ms) = parse_dns_result_text(
            "type: 1 example.test ::ffff:203.0.113.5 TTL: 45; type: 28 2001:db8::1 TTL: 90",
        );
        assert_eq!(answers, vec!["203.0.113.5", "2001:db8::1"]);
        assert_eq!(ttl_ms, 45_000);
        let (typed, typed_ttl) = parse_dns_result_addresses(
            "type: 1 example.test ::ffff:203.0.113.5 TTL: 45; type: 28 2001:db8::1 TTL: 90",
        );
        assert_eq!(
            typed,
            vec![
                IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5)),
                IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
            ]
        );
        assert_eq!(typed_ttl, 45_000);
    }

    #[test]
    fn ttl_markers_are_matched_without_lowercasing_the_input() {
        let (_, ttl_ms) = parse_dns_result_addresses("203.0.113.1 Ttl: 12; 2001:db8::1 tTL: 8");
        assert_eq!(ttl_ms, 8_000);
        let (_, missing) = parse_dns_result_addresses("203.0.113.1 ttl 5");
        assert_eq!(missing, 0);
        let (_, explicit_zero) = parse_dns_result_addresses_with_ttl("203.0.113.1 TTL: 0");
        assert_eq!(explicit_zero, Some(0));
        let (_, absent) = parse_dns_result_addresses_with_ttl("203.0.113.1 ttl 5");
        assert_eq!(absent, None);
        let (_, malformed) = parse_dns_result_addresses("203.0.113.1 TTL: nope TTL: 3");
        assert_eq!(malformed, 3_000);
    }

    #[test]
    fn result_text_preserves_ipv6_addresses_ending_in_double_colon() {
        let (answers, _) = parse_dns_result_addresses("2001:db8:: :: TTL: 12");
        assert_eq!(
            answers,
            vec![
                IpAddr::V6("2001:db8::".parse().unwrap()),
                IpAddr::V6(Ipv6Addr::UNSPECIFIED),
            ]
        );
    }

    #[test]
    fn aliases_include_v4_mapped_form() {
        let v4 = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 9));
        let aliases = ip_aliases(v4);
        assert_eq!(aliases[0], v4);
        assert_eq!(
            aliases[1],
            IpAddr::V6(Ipv4Addr::new(192, 0, 2, 9).to_ipv6_mapped())
        );
        assert_eq!(
            canonicalize_ip(IpAddr::V6(Ipv4Addr::new(192, 0, 2, 9).to_ipv6_mapped())),
            v4
        );
    }
}
