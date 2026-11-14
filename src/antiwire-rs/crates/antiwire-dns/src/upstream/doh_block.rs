//! Addresses of public `DoH` resolvers to block so applications cannot bypass
//! the local resolver with their own encrypted DNS.
//!
//! The daemon is itself a `DoH` client, so the addresses its configured
//! upstreams dial are never blocked: a rule matching `1.1.1.1:443` for every
//! process would cut the daemon off from Cloudflare too, and on Windows a block
//! rule cannot be overridden by a per-application allow. Only those addresses
//! are spared. A provider's other services stay blocked, so choosing its family
//! filter does not leave its unfiltered resolver open to other applications.
//!
//! The dialled addresses come from the same endpoint parsing the resolver
//! starts with, and the families' addresses from the resolver services in
//! `providers`, so neither can drift from what the resolver uses.

use std::collections::BTreeSet;
use std::net::IpAddr;

use antiwire_store::DaemonSetting;

use crate::dns_name::is_at_or_below;

use super::dialled_addresses;
use super::providers::{upstreams_for_settings, ResolverService, RESOLVER_SERVICES};

/// Port `DoH` runs on. HTTP/3 `DoH` uses the same port over UDP.
pub const DOH_PORT: u16 = 443;

/// One provider's `DoH` services, named by the domains they are published
/// under. Every resolver service under one of them contributes its addresses.
struct ResolverFamily {
    domains: &'static [&'static str],
}

const RESOLVER_FAMILIES: &[ResolverFamily] = &[
    ResolverFamily {
        domains: &["cloudflare-dns.com", "one.one.one.one"],
    },
    ResolverFamily {
        domains: &["dns.google", "dns.google.com"],
    },
    ResolverFamily {
        domains: &["quad9.net"],
    },
    ResolverFamily {
        domains: &["adguard-dns.com", "adguard.com"],
    },
    ResolverFamily {
        domains: &["opendns.com"],
    },
    ResolverFamily {
        domains: &["cleanbrowsing.org"],
    },
];

impl ResolverFamily {
    fn contains(&self, host: &str) -> bool {
        self.domains
            .iter()
            .any(|domain| is_at_or_below(host, domain))
    }

    /// Every address this family is blocked on, without duplicates, sorted.
    fn addresses(&self) -> Vec<String> {
        RESOLVER_SERVICES
            .iter()
            .copied()
            .filter(|service| self.contains(service.host))
            .flat_map(ResolverService::addresses)
            .map(str::to_owned)
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect()
    }
}

/// Resolver addresses to block on [`DOH_PORT`], sparing the ones the upstreams
/// of `in_use` dial.
///
/// Pass both the old and new settings while a resolver change is in flight, so
/// neither upstream is blocked until the switch has completed.
#[must_use]
pub fn doh_block_targets(in_use: &[&DaemonSetting]) -> Vec<String> {
    let dialled: Vec<IpAddr> = in_use
        .iter()
        .flat_map(|settings| {
            let (protocol, upstreams) = upstreams_for_settings(settings);
            dialled_addresses(protocol, &upstreams)
        })
        .collect();
    RESOLVER_FAMILIES
        .iter()
        .flat_map(ResolverFamily::addresses)
        .filter(|address| {
            !address
                .parse::<IpAddr>()
                .is_ok_and(|address| dialled.contains(&address))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::super::providers::bootstrap_ipv4_for_host;
    use super::super::upstream_host;
    use super::*;

    fn settings(protocol: &str, provider: &str, custom_url: &str) -> DaemonSetting {
        DaemonSetting {
            dns_protocol: protocol.to_owned(),
            doh_provider: provider.to_owned(),
            doh_custom_url: custom_url.to_owned(),
            ..DaemonSetting::default()
        }
    }

    fn blocks(targets: &[String], ip: &str) -> bool {
        targets.iter().any(|target| target == ip)
    }

    #[test]
    fn every_family_address_parses() {
        for family in RESOLVER_FAMILIES {
            for address in family.addresses() {
                assert!(address.parse::<IpAddr>().is_ok(), "{address}");
            }
        }
    }

    #[test]
    fn every_resolver_service_belongs_to_a_family() {
        // A resolver service added without a family would have its
        // addresses left unblocked.
        for service in RESOLVER_SERVICES {
            let family = RESOLVER_FAMILIES
                .iter()
                .find(|family| family.contains(service.host))
                .unwrap_or_else(|| panic!("{} is in no family", service.host));
            for address in service.addresses() {
                assert!(
                    family.addresses().iter().any(|listed| listed == address),
                    "{} {address}",
                    service.host
                );
            }
        }
    }

    #[test]
    fn quad9_secondary_addresses_are_blocked() {
        let targets = doh_block_targets(&[&settings("doh", "cloudflare", "")]);
        for ip in [
            "9.9.9.10",
            "149.112.112.10",
            "9.9.9.11",
            "149.112.112.11",
            "2620:fe::11",
            "2620:fe::fe:11",
        ] {
            assert!(blocks(&targets, ip), "{ip} left open");
        }
    }

    #[test]
    fn the_configured_provider_is_never_blocked() {
        for (provider, own, other) in [
            ("cloudflare", "1.1.1.1", "8.8.8.8"),
            ("google", "8.8.8.8", "1.1.1.1"),
            ("quad9", "9.9.9.9", "1.1.1.1"),
            ("adguard", "94.140.14.14", "8.8.8.8"),
            ("opendns", "208.67.222.222", "8.8.8.8"),
            ("cleanbrowsing", "185.228.168.9", "8.8.8.8"),
        ] {
            let targets = doh_block_targets(&[&settings("doh", provider, "")]);
            assert!(!blocks(&targets, own), "{provider} blocked its own {own}");
            assert!(blocks(&targets, other), "{provider} left {other} open");
        }
    }

    #[test]
    fn every_built_in_upstream_belongs_to_a_spared_family() {
        // The safety property: no provider the daemon can be configured with
        // resolves into an address this module would block.
        for protocol in ["doh", "doq", "dot"] {
            for provider in [
                "cloudflare",
                "cloudflare-fam",
                "cloudflare-sec",
                "google",
                "quad9",
                "quad9-ecs",
                "quad9-unfiltered",
                "adguard",
                "adguard-fam",
                "adguard-unfiltered",
                "opendns",
                "opendns-fam",
                "cleanbrowsing",
                "cleanbrowsing-fam",
                "cleanbrowsing-adult",
                "",
            ] {
                let setting = settings(protocol, provider, "");
                let targets = doh_block_targets(&[&setting]);
                for url in upstreams_for_settings(&setting).1 {
                    let host = upstream_host(&url).expect("upstream host");
                    let mut reached: Vec<String> =
                        bootstrap_ipv4_for_host(&host).unwrap_or_default();
                    if host.parse::<IpAddr>().is_ok() {
                        reached.push(host.clone());
                    }
                    for ip in reached {
                        assert!(
                            !blocks(&targets, &ip),
                            "{protocol}/{provider} upstream {url} reaches blocked {ip}"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn custom_upstreams_spare_the_addresses_they_dial() {
        for (url, spared) in [
            ("https://1.1.1.1/dns-query", "1.1.1.1"),
            ("https://dns.google/dns-query", "8.8.8.8"),
            ("https://dns.google/dns-query", "8.8.4.4"),
            (
                "https://[2606:4700:4700::1111]/dns-query",
                "2606:4700:4700::1111",
            ),
        ] {
            let targets = doh_block_targets(&[&settings("doh", "custom", url)]);
            assert!(!blocks(&targets, spared), "{url} blocked {spared}");
        }
    }

    #[test]
    fn a_filtering_provider_leaves_its_unfiltered_siblings_blocked() {
        let targets = doh_block_targets(&[&settings("doh", "cloudflare-fam", "")]);
        for spared in ["1.1.1.3", "1.0.0.3"] {
            assert!(!blocks(&targets, spared), "{spared} is dialled");
        }
        for sibling in ["1.1.1.1", "1.1.1.2", "2606:4700:4700::1111"] {
            assert!(
                blocks(&targets, sibling),
                "{sibling} lets other applications bypass the family filter"
            );
        }
    }

    #[test]
    fn an_unrelated_custom_upstream_spares_nothing() {
        let targets =
            doh_block_targets(&[&settings("doh", "custom", "https://dns.example.test/q")]);
        let total: usize = RESOLVER_FAMILIES.iter().map(|f| f.addresses().len()).sum();
        assert_eq!(targets.len(), total);
    }

    #[test]
    fn a_provider_change_spares_both_sides() {
        let before = settings("doh", "cloudflare", "");
        let after = settings("doh", "google", "");
        let targets = doh_block_targets(&[&before, &after]);
        assert!(!blocks(&targets, "1.1.1.1"));
        assert!(!blocks(&targets, "8.8.8.8"));
        assert!(blocks(&targets, "9.9.9.9"));
    }

    #[test]
    fn hosts_are_extracted_from_every_upstream_shape() {
        assert_eq!(
            upstream_host("https://Dns.Quad9.net/dns-query").as_deref(),
            Some("dns.quad9.net")
        );
        assert_eq!(
            upstream_host("dns.quad9.net").as_deref(),
            Some("dns.quad9.net")
        );
        assert_eq!(upstream_host("1.1.1.1:853").as_deref(), Some("1.1.1.1"));
        // The endpoint parser reads a scheme-less `host/path` as `DoH`.
        assert_eq!(
            upstream_host("Dns.Quad9.net/dns-query").as_deref(),
            Some("dns.quad9.net")
        );
        assert_eq!(
            upstream_host("[2620:fe::fe]/dns-query").as_deref(),
            Some("2620:fe::fe")
        );
        assert_eq!(upstream_host("2620:fe::fe").as_deref(), Some("2620:fe::fe"));
        assert_eq!(
            upstream_host("[2620:fe::fe]:853").as_deref(),
            Some("2620:fe::fe")
        );
        assert_eq!(
            upstream_host("https://[2620:fe::fe]/dns-query").as_deref(),
            Some("2620:fe::fe")
        );
        assert!(!is_at_or_below("evilquad9.net", "quad9.net"));
        assert!(is_at_or_below("dns11.quad9.net", "quad9.net"));
    }
}
