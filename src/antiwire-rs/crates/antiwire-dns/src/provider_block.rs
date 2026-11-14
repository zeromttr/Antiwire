//! Detects an upstream filtering resolver's own block, as distinct from a
//! name that simply does not exist.
//!
//! Providers do not share one wire shape:
//! - `NextDNS`, Control D, Cloudflare Security/Family, and `AdGuard` default to
//!   `NOERROR` with `0.0.0.0` / `::`.
//! - Quad9 returns `NXDOMAIN` with an empty authority section. A real
//!   nonexistent name from Quad9 carries an SOA in that section.
//! - RFC 8914 EDE 15 (Blocked) or 17 (Filtered) is an explicit withhold and
//!   applies to any upstream, including a custom `NextDNS` or Control D URL
//!   that answers with a block-page address instead of `0.0.0.0`.
//!
//! Plain `NXDOMAIN` from `CleanBrowsing` is not labeled: it uses the same code
//! for a block and for a name that does not exist.

use hickory_proto::op::{Message, ResponseCode};
use hickory_proto::rr::rdata::opt::EdnsOption;
use hickory_proto::rr::RData;

use crate::ede::{EDE_BLOCKED, EDE_FILTERED, EDNS_OPTION_CODE_EDE};
use crate::upstream::{upstream_host, withhold_shape, WithholdShape};

/// Stored blocked-by value when the configured resolver withheld the name.
pub(crate) const DNS_PROVIDER_BLOCK_LABEL: &str = "DNS Provider";

/// Which provider block shapes the configured resolvers can answer with.
///
/// Derived once from the endpoints, so classifying an answer on the miss path
/// does no host parsing.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct ProviderFilter {
    zero_address: bool,
    empty_nxdomain: bool,
}

impl ProviderFilter {
    /// The block shapes any of `endpoints` is known to use.
    pub(crate) fn for_endpoints(endpoints: &[String]) -> Self {
        let mut filter = Self::default();
        for host in endpoints
            .iter()
            .filter_map(|endpoint| upstream_host(endpoint))
        {
            match withhold_shape(host.trim_end_matches('.')) {
                WithholdShape::ZeroAddress => filter.zero_address = true,
                WithholdShape::EmptyNxDomain => filter.empty_nxdomain = true,
                WithholdShape::Unlabeled => {}
            }
        }
        filter
    }

    /// True when `message` is a block from one of the resolvers this filter
    /// was built for.
    #[must_use]
    pub(crate) fn is_block(self, message: &Message) -> bool {
        ede_is_policy_block(message)
            || (self.zero_address && answers_are_unspecified(message))
            || (self.empty_nxdomain && empty_nxdomain_block(message))
    }
}

/// True when `message` is a block from one of the resolvers in `endpoints`.
#[cfg(test)]
fn upstream_answer_is_provider_block(endpoints: &[String], message: &Message) -> bool {
    ProviderFilter::for_endpoints(endpoints).is_block(message)
}

fn ede_is_policy_block(message: &Message) -> bool {
    let Some(edns) = message.edns.as_ref() else {
        return false;
    };
    let Some(option) = edns.option(hickory_proto::rr::rdata::opt::EdnsCode::from(
        EDNS_OPTION_CODE_EDE,
    )) else {
        return false;
    };
    match option {
        EdnsOption::Unknown(_, data) if data.len() >= 2 => {
            let info = u16::from_be_bytes([data[0], data[1]]);
            info == EDE_BLOCKED || info == EDE_FILTERED
        }
        _ => false,
    }
}

fn answers_are_unspecified(message: &Message) -> bool {
    if message.metadata.response_code != ResponseCode::NoError {
        return false;
    }
    let mut saw_unspecified = false;
    for record in &message.answers {
        match &record.data {
            RData::A(addr) if addr.0.is_unspecified() => saw_unspecified = true,
            RData::AAAA(addr) if addr.0.is_unspecified() => saw_unspecified = true,
            RData::CNAME(_) => {}
            _ => return false,
        }
    }
    saw_unspecified
}

/// Quad9 documents a block as `NXDOMAIN` with `AUTHORITY: 0`. A name that does
/// not exist has an SOA, so the authority section is not empty.
fn empty_nxdomain_block(message: &Message) -> bool {
    message.metadata.response_code == ResponseCode::NXDomain
        && message.answers.is_empty()
        && message.authorities.is_empty()
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use hickory_proto::op::{MessageType, OpCode};
    use hickory_proto::rr::{rdata, Name, RData, Record};

    use super::*;
    use crate::ede::build_ede_option;

    fn endpoints(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_owned()).collect()
    }

    fn noerror() -> Message {
        Message::new(1, MessageType::Response, OpCode::Query)
    }

    fn with_a(ip: Ipv4Addr) -> Message {
        let mut message = noerror();
        message.add_answer(Record::from_rdata(
            Name::from_ascii("blocked.example.").expect("name"),
            60,
            RData::A(rdata::A(ip)),
        ));
        message
    }

    fn with_aaaa(ip: Ipv6Addr) -> Message {
        let mut message = noerror();
        message.add_answer(Record::from_rdata(
            Name::from_ascii("blocked.example.").expect("name"),
            60,
            RData::AAAA(rdata::AAAA(ip)),
        ));
        message
    }

    fn nxdomain(with_soa: bool) -> Message {
        let mut message = noerror();
        message.metadata.response_code = ResponseCode::NXDomain;
        if with_soa {
            message.authorities.push(Record::from_rdata(
                Name::from_ascii("example.").expect("name"),
                60,
                RData::SOA(rdata::SOA::new(
                    Name::from_ascii("ns.example.").expect("mname"),
                    Name::from_ascii("hostmaster.example.").expect("rname"),
                    1,
                    7200,
                    3600,
                    1_209_600,
                    60,
                )),
            ));
        }
        message
    }

    fn with_ede(info_code: u16) -> Message {
        let mut message = with_a(Ipv4Addr::new(146, 112, 61, 104));
        let mut edns = hickory_proto::op::Edns::new();
        edns.options_mut()
            .insert(build_ede_option(info_code, Some("Blocked by NextDNS")));
        message.set_edns(edns);
        message
    }

    #[test]
    fn cloudflare_security_zero_address_is_a_provider_block() {
        let endpoints = endpoints(&["https://security.cloudflare-dns.com/dns-query"]);
        assert!(upstream_answer_is_provider_block(
            &endpoints,
            &with_a(Ipv4Addr::UNSPECIFIED)
        ));
        assert!(upstream_answer_is_provider_block(
            &endpoints,
            &with_aaaa(Ipv6Addr::UNSPECIFIED)
        ));
        assert!(!upstream_answer_is_provider_block(
            &endpoints,
            &with_a(Ipv4Addr::new(192, 0, 2, 1))
        ));
    }

    #[test]
    fn unfiltered_cloudflare_zero_address_is_not_a_provider_block() {
        let endpoints = endpoints(&["https://cloudflare-dns.com/dns-query"]);
        assert!(!upstream_answer_is_provider_block(
            &endpoints,
            &with_a(Ipv4Addr::UNSPECIFIED)
        ));
    }

    #[test]
    fn nextdns_and_controld_zero_address_is_a_provider_block() {
        for endpoint in [
            "https://dns.nextdns.io/abc123",
            "https://dns.controld.com/profile",
        ] {
            assert!(
                upstream_answer_is_provider_block(
                    &endpoints(&[endpoint]),
                    &with_a(Ipv4Addr::UNSPECIFIED)
                ),
                "{endpoint}"
            );
        }
    }

    #[test]
    fn ede_blocked_or_filtered_is_a_provider_block_on_any_upstream() {
        let google = endpoints(&["https://dns.google/dns-query"]);
        assert!(upstream_answer_is_provider_block(
            &google,
            &with_ede(EDE_FILTERED)
        ));
        assert!(upstream_answer_is_provider_block(
            &google,
            &with_ede(EDE_BLOCKED)
        ));
    }

    #[test]
    fn quad9_empty_authority_nxdomain_is_a_block_and_soa_nxdomain_is_not() {
        let quad9 = endpoints(&["https://dns.quad9.net/dns-query"]);
        assert!(upstream_answer_is_provider_block(&quad9, &nxdomain(false)));
        assert!(!upstream_answer_is_provider_block(&quad9, &nxdomain(true)));

        let unfiltered = endpoints(&["https://dns10.quad9.net/dns-query"]);
        assert!(!upstream_answer_is_provider_block(
            &unfiltered,
            &nxdomain(false)
        ));

        let cloudflare = endpoints(&["https://security.cloudflare-dns.com/dns-query"]);
        assert!(!upstream_answer_is_provider_block(
            &cloudflare,
            &nxdomain(false)
        ));
    }

    #[test]
    fn every_endpoint_shape_names_its_provider() {
        for endpoint in [
            "https://Dns.Quad9.net/dns-query",
            "dns.quad9.net/dns-query",
            "tls://dns.quad9.net",
            "9.9.9.9:853",
            "dns.quad9.net.",
        ] {
            assert_eq!(
                ProviderFilter::for_endpoints(&endpoints(&[endpoint])),
                ProviderFilter {
                    zero_address: false,
                    empty_nxdomain: true
                },
                "{endpoint}"
            );
        }
        for endpoint in [
            "https://abc123.dns.nextdns.io/dns-query",
            "https://dns.controld.com/xyz",
            "1.1.1.2",
        ] {
            assert_eq!(
                ProviderFilter::for_endpoints(&endpoints(&[endpoint])),
                ProviderFilter {
                    zero_address: true,
                    empty_nxdomain: false
                },
                "{endpoint}"
            );
        }
        // Addresses compare as addresses, in any IPv6 spelling.
        for (endpoint, expected) in [
            ("https://[2620:fe::fe]/dns-query", (false, true)),
            ("[2620:00FE:0::fe:11]:853", (false, true)),
            ("149.112.112.112", (false, true)),
            ("[2606:4700:4700::1112]:853", (true, false)),
            ("https://94.140.14.15/dns-query", (true, false)),
            // Quad9's unfiltered service and look-alike hosts are not filters.
            ("[2620:fe::10]:853", (false, false)),
            ("149.112.112.10", (false, false)),
            ("evilnextdns.io", (false, false)),
        ] {
            assert_eq!(
                ProviderFilter::for_endpoints(&endpoints(&[endpoint])),
                ProviderFilter {
                    zero_address: expected.0,
                    empty_nxdomain: expected.1
                },
                "{endpoint}"
            );
        }
    }

    #[test]
    fn adguard_family_zero_address_is_a_provider_block() {
        let family = endpoints(&["https://family.adguard-dns.com/dns-query"]);
        assert!(upstream_answer_is_provider_block(
            &family,
            &with_a(Ipv4Addr::UNSPECIFIED)
        ));
        let unfiltered = endpoints(&["https://unfiltered.adguard-dns.com/dns-query"]);
        assert!(!upstream_answer_is_provider_block(
            &unfiltered,
            &with_a(Ipv4Addr::UNSPECIFIED)
        ));
    }
}
