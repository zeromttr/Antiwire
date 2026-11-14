//! Everything Antiwire knows about DNS providers, in one place.
//!
//! - **Resolver services** ([`RESOLVER_SERVICES`]): each hostname, the
//!   addresses it answers on, and how it answers a name it withholds. The
//!   bootstrap addresses the resolver dials, the TLS names it presents when
//!   dialling by address, provider-block detection in `provider_block`, and
//!   the `DoH` block list are all derived from it.
//! - **Provider selections** ([`PROVIDERS`]): each id refers to one of those
//!   services, says which transports it offers, and records a `DoH` path only
//!   where it is not `/dns-query`. A row cannot name an unknown host, because
//!   it holds the service rather than a hostname.
//!
//! Both lists come first, side by side, so adding or changing a provider is an
//! edit to this one file.

use std::net::IpAddr;

use antiwire_store::DaemonSetting;

use crate::dns_name::is_at_or_below;
use crate::settings::DnsProtocol;

/// How a resolver answers a name it withholds, as distinct from one that does
/// not exist.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum WithholdShape {
    /// No shape tells a withheld name from a nonexistent one, or the service
    /// does not filter.
    Unlabeled,
    /// `NOERROR` with `0.0.0.0` / `::`.
    ZeroAddress,
    /// `NXDOMAIN` with an empty authority section; a real nonexistent name
    /// carries an SOA there.
    EmptyNxDomain,
}

/// One resolver service: a hostname and the addresses it answers on.
#[derive(Debug)]
pub(crate) struct ResolverService {
    pub(crate) host: &'static str,
    pub(crate) ipv4: &'static [&'static str],
    pub(crate) ipv6: &'static [&'static str],
    pub(crate) withholds: WithholdShape,
}

impl ResolverService {
    /// Every address the service answers on.
    pub(crate) fn addresses(&self) -> impl Iterator<Item = &'static str> {
        self.ipv4.iter().chain(self.ipv6).copied()
    }

    fn answers_on(&self, address: IpAddr) -> bool {
        self.addresses()
            .any(|listed| listed.parse::<IpAddr>().ok() == Some(address))
    }
}

const fn service(
    host: &'static str,
    ipv4: &'static [&'static str],
    ipv6: &'static [&'static str],
    withholds: WithholdShape,
) -> ResolverService {
    ResolverService {
        host,
        ipv4,
        ipv6,
        withholds,
    }
}

use WithholdShape::{EmptyNxDomain, Unlabeled, ZeroAddress};

const CLOUDFLARE: ResolverService = service(
    "cloudflare-dns.com",
    &["1.1.1.1", "1.0.0.1"],
    &["2606:4700:4700::1111", "2606:4700:4700::1001"],
    Unlabeled,
);
const CLOUDFLARE_SECURITY: ResolverService = service(
    "security.cloudflare-dns.com",
    &["1.1.1.2", "1.0.0.2"],
    &["2606:4700:4700::1112", "2606:4700:4700::1002"],
    ZeroAddress,
);
const CLOUDFLARE_FAMILY: ResolverService = service(
    "family.cloudflare-dns.com",
    &["1.1.1.3", "1.0.0.3"],
    &["2606:4700:4700::1113", "2606:4700:4700::1003"],
    ZeroAddress,
);
const GOOGLE: ResolverService = service(
    "dns.google",
    &["8.8.8.8", "8.8.4.4"],
    &["2001:4860:4860::8888", "2001:4860:4860::8844"],
    Unlabeled,
);
const QUAD9: ResolverService = service(
    "dns.quad9.net",
    &["9.9.9.9", "149.112.112.112"],
    &["2620:fe::fe", "2620:fe::9"],
    EmptyNxDomain,
);
const QUAD9_ECS: ResolverService = service(
    "dns11.quad9.net",
    &["9.9.9.11", "149.112.112.11"],
    &["2620:fe::11", "2620:fe::fe:11"],
    EmptyNxDomain,
);
const QUAD9_UNFILTERED: ResolverService = service(
    "dns10.quad9.net",
    &["9.9.9.10", "149.112.112.10"],
    &["2620:fe::10", "2620:fe::fe:10"],
    Unlabeled,
);
const ADGUARD: ResolverService = service(
    "dns.adguard-dns.com",
    &["94.140.14.14", "94.140.15.15"],
    &["2a10:50c0::ad1:ff", "2a10:50c0::ad2:ff"],
    ZeroAddress,
);
const ADGUARD_FAMILY: ResolverService = service(
    "family.adguard-dns.com",
    &["94.140.14.15", "94.140.15.16"],
    &["2a10:50c0::bad1:ff", "2a10:50c0::bad2:ff"],
    ZeroAddress,
);
const ADGUARD_UNFILTERED: ResolverService = service(
    "unfiltered.adguard-dns.com",
    &["94.140.14.140", "94.140.14.141"],
    &["2a10:50c0::1:ff", "2a10:50c0::2:ff"],
    Unlabeled,
);
const OPENDNS_DOH: ResolverService = service(
    "doh.opendns.com",
    &["208.67.222.222", "208.67.220.220"],
    &["2620:119:35::35", "2620:119:53::53"],
    Unlabeled,
);
const OPENDNS: ResolverService = service(
    "dns.opendns.com",
    &["208.67.222.222", "208.67.220.220"],
    &["2620:119:35::35", "2620:119:53::53"],
    Unlabeled,
);
const OPENDNS_FAMILY_DOH: ResolverService = service(
    "doh.familyshield.opendns.com",
    &["208.67.222.123", "208.67.220.123"],
    &[],
    Unlabeled,
);
const OPENDNS_FAMILY: ResolverService = service(
    "familyshield.opendns.com",
    &["208.67.222.123", "208.67.220.123"],
    &[],
    Unlabeled,
);
const CLEANBROWSING_SECURITY: ResolverService = service(
    "security-filter-dns.cleanbrowsing.org",
    &["185.228.168.9", "185.228.169.9"],
    &[],
    Unlabeled,
);
const CLEANBROWSING_FAMILY: ResolverService = service(
    "family-filter-dns.cleanbrowsing.org",
    &["185.228.168.168", "185.228.169.168"],
    &[],
    Unlabeled,
);
const CLEANBROWSING_ADULT: ResolverService = service(
    "adult-filter-dns.cleanbrowsing.org",
    &["185.228.168.10", "185.228.169.11"],
    &[],
    Unlabeled,
);
const CLEANBROWSING_DOH: ResolverService = service(
    "doh.cleanbrowsing.org",
    &["185.228.168.9", "185.228.169.9"],
    &[],
    Unlabeled,
);

/// Published resolver services. Hosts that share an anycast address (such as
/// OpenDNS's `dns.` and `doh.` names) are listed separately, each with it.
pub(crate) const RESOLVER_SERVICES: &[&ResolverService] = &[
    &CLOUDFLARE,
    &CLOUDFLARE_SECURITY,
    &CLOUDFLARE_FAMILY,
    &GOOGLE,
    &QUAD9,
    &QUAD9_ECS,
    &QUAD9_UNFILTERED,
    &ADGUARD,
    &ADGUARD_FAMILY,
    &ADGUARD_UNFILTERED,
    &OPENDNS_DOH,
    &OPENDNS,
    &OPENDNS_FAMILY_DOH,
    &OPENDNS_FAMILY,
    &CLEANBROWSING_SECURITY,
    &CLEANBROWSING_FAMILY,
    &CLEANBROWSING_ADULT,
    &CLEANBROWSING_DOH,
];

/// Providers whose every hostname (one per user profile) answers a withheld
/// name with `0.0.0.0`. They publish no fixed addresses, so they are matched
/// by domain alone.
const ZERO_ADDRESS_DOMAINS: &[&str] = &["nextdns.io", "controld.com"];

// Provider selections: which of the services above each provider id uses.

/// A provider id the settings can name, and the service behind it.
struct Provider {
    id: &'static str,
    /// The service for `DoT` and plain DNS, for `DoQ` when [`Self::doq`], and
    /// for `DoH` unless [`Self::doh_service`] names another one.
    service: &'static ResolverService,
    /// The `DoH` service, when it is not [`Self::service`]. OpenDNS and
    /// `CleanBrowsing` publish `DoH` on a different host from `DoT` and plain DNS.
    doh_service: Option<&'static ResolverService>,
    /// The `DoH` path, when it is not `/dns-query`. Includes the leading slash.
    doh_path: Option<&'static str>,
    /// Whether [`Self::service`] also serves DNS over QUIC. Every provider
    /// serves `DoH`, `DoT`, and plain DNS.
    doq: bool,
}

const fn provider(id: &'static str, service: &'static ResolverService) -> Provider {
    Provider {
        id,
        service,
        doh_service: None,
        doh_path: None,
        doq: false,
    }
}

impl Provider {
    const fn with_doq(self) -> Self {
        Self { doq: true, ..self }
    }

    const fn with_doh_service(self, service: &'static ResolverService) -> Self {
        Self {
            doh_service: Some(service),
            ..self
        }
    }

    const fn with_doh_path(self, path: &'static str) -> Self {
        Self {
            doh_path: Some(path),
            ..self
        }
    }

    fn doh_service(&self) -> &'static ResolverService {
        self.doh_service.unwrap_or(self.service)
    }

    fn doh_url(&self) -> String {
        let path = self.doh_path.unwrap_or("/dns-query");
        format!("https://{}{path}", self.doh_service().host)
    }

    /// Whether this provider answers on `transport`.
    fn offers(&self, transport: Transport) -> bool {
        match transport {
            Transport::Doq => self.doq,
            Transport::Doh | Transport::Dot | Transport::Plain => true,
        }
    }

    /// The upstream to configure for this provider on `transport`, or `None`
    /// when it does not serve that transport.
    fn endpoint(&self, transport: Transport) -> Option<String> {
        if !self.offers(transport) {
            return None;
        }
        Some(match transport {
            Transport::Doh => self.doh_url(),
            Transport::Dot => format!("{}:853", self.service.host),
            Transport::Doq | Transport::Plain => self.service.host.to_owned(),
        })
    }
}

const CLOUDFLARE_PROVIDER: Provider = provider("cloudflare", &CLOUDFLARE);
const CLOUDFLARE_FAMILY_PROVIDER: Provider = provider("cloudflare-fam", &CLOUDFLARE_FAMILY);
const CLOUDFLARE_SECURITY_PROVIDER: Provider = provider("cloudflare-sec", &CLOUDFLARE_SECURITY);
const GOOGLE_PROVIDER: Provider = provider("google", &GOOGLE);
const QUAD9_PROVIDER: Provider = provider("quad9", &QUAD9).with_doq();
const QUAD9_ECS_PROVIDER: Provider = provider("quad9-ecs", &QUAD9_ECS).with_doq();
const QUAD9_UNFILTERED_PROVIDER: Provider = provider("quad9-unfiltered", &QUAD9_UNFILTERED);
const ADGUARD_PROVIDER: Provider = provider("adguard", &ADGUARD).with_doq();
const ADGUARD_FAMILY_PROVIDER: Provider = provider("adguard-fam", &ADGUARD_FAMILY).with_doq();
const ADGUARD_UNFILTERED_PROVIDER: Provider = provider("adguard-unfiltered", &ADGUARD_UNFILTERED);
const OPENDNS_PROVIDER: Provider = provider("opendns", &OPENDNS).with_doh_service(&OPENDNS_DOH);
const OPENDNS_FAMILY_PROVIDER: Provider =
    provider("opendns-fam", &OPENDNS_FAMILY).with_doh_service(&OPENDNS_FAMILY_DOH);
const CLEANBROWSING_PROVIDER: Provider = provider("cleanbrowsing", &CLEANBROWSING_SECURITY)
    .with_doh_service(&CLEANBROWSING_DOH)
    .with_doh_path("/doh/security-filter/");
const CLEANBROWSING_FAMILY_PROVIDER: Provider =
    provider("cleanbrowsing-fam", &CLEANBROWSING_FAMILY)
        .with_doh_service(&CLEANBROWSING_DOH)
        .with_doh_path("/doh/family-filter/");
const CLEANBROWSING_ADULT_PROVIDER: Provider =
    provider("cleanbrowsing-adult", &CLEANBROWSING_ADULT)
        .with_doh_service(&CLEANBROWSING_DOH)
        .with_doh_path("/doh/adult-filter/");

/// Every provider id the settings can name. Each serves `DoH`, `DoT`, and
/// plain DNS; only those built with [`Provider::with_doq`] serve `DoQ`.
const PROVIDERS: &[&Provider] = &[
    &CLOUDFLARE_PROVIDER,
    &CLOUDFLARE_FAMILY_PROVIDER,
    &CLOUDFLARE_SECURITY_PROVIDER,
    &GOOGLE_PROVIDER,
    &QUAD9_PROVIDER,
    &QUAD9_ECS_PROVIDER,
    &QUAD9_UNFILTERED_PROVIDER,
    &ADGUARD_PROVIDER,
    &ADGUARD_FAMILY_PROVIDER,
    &ADGUARD_UNFILTERED_PROVIDER,
    &OPENDNS_PROVIDER,
    &OPENDNS_FAMILY_PROVIDER,
    &CLEANBROWSING_PROVIDER,
    &CLEANBROWSING_FAMILY_PROVIDER,
    &CLEANBROWSING_ADULT_PROVIDER,
];

/// Providers used, in order, when a selection names none that serves the
/// transport. Cloudflare for `DoH`, `DoT`, and plain DNS; Quad9, then `AdGuard`,
/// for `DoQ`.
const fn default_providers(transport: Transport) -> &'static [&'static Provider] {
    match transport {
        Transport::Doq => &[&QUAD9_PROVIDER, &ADGUARD_PROVIDER],
        Transport::Doh | Transport::Dot | Transport::Plain => &[&CLOUDFLARE_PROVIDER],
    }
}

// Lookups over the services and selections above.

/// The service published under `host`, matched without regard to case.
pub(crate) fn service_for_host(host: &str) -> Option<&'static ResolverService> {
    RESOLVER_SERVICES
        .iter()
        .copied()
        .find(|service| service.host.eq_ignore_ascii_case(host))
}

/// The IPv4 addresses to dial for `host`: the resolver cannot look up its own
/// upstream, since system DNS points back at it.
pub(crate) fn bootstrap_ipv4_for_host(host: &str) -> Option<Vec<String>> {
    service_for_host(host).map(|service| service.ipv4.iter().map(|&ip| ip.to_owned()).collect())
}

fn services_on(address: IpAddr) -> impl Iterator<Item = &'static ResolverService> {
    RESOLVER_SERVICES
        .iter()
        .copied()
        .filter(move |service| service.answers_on(address))
}

/// How the resolver at `host`, a hostname or an address, withholds a name.
pub(crate) fn withhold_shape(host: &str) -> WithholdShape {
    if let Ok(address) = host.parse::<IpAddr>() {
        // Services sharing an address are the same resolver.
        return services_on(address)
            .next()
            .map_or(Unlabeled, |service| service.withholds);
    }
    if let Some(service) = service_for_host(host) {
        return service.withholds;
    }
    if ZERO_ADDRESS_DOMAINS
        .iter()
        .any(|domain| is_at_or_below(host, domain))
    {
        return ZeroAddress;
    }
    Unlabeled
}

/// The TLS name to present when dialling `address` directly: the host of the
/// one service that answers on it. `None` when no service does, or when
/// several hosts share it and none can be preferred.
pub(crate) fn tls_name_for_address(address: &str) -> Option<&'static str> {
    let address = address.parse::<IpAddr>().ok()?;
    let mut hosts = services_on(address).map(|service| service.host);
    let first = hosts.next()?;
    hosts.all(|host| host == first).then_some(first)
}

fn provider_by_id(id: &str) -> Option<&'static Provider> {
    PROVIDERS
        .iter()
        .copied()
        .find(|provider| provider.id.eq_ignore_ascii_case(id))
}

// Resolving a provider setting to upstream URLs.

/// The transports a provider row describes. `DnsProtocol` distinguishes more
/// (`DoH` over HTTP/2 or HTTP/3, plain DNS over UDP or TCP), but each pair
/// uses the same provider endpoints.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Transport {
    Doh,
    Doq,
    Dot,
    Plain,
}

impl From<DnsProtocol> for Transport {
    fn from(protocol: DnsProtocol) -> Self {
        match protocol {
            DnsProtocol::Https | DnsProtocol::H3 => Self::Doh,
            DnsProtocol::Quic => Self::Doq,
            DnsProtocol::Tls => Self::Dot,
            DnsProtocol::Udp | DnsProtocol::Tcp => Self::Plain,
        }
    }
}

/// What a provider setting resolves to, decided once for both the primary
/// upstreams and their `DoH` failover.
enum Selection<'a> {
    /// A custom upstream URL. It is a single-party trust decision, so queries
    /// never fail over to another provider.
    Custom(&'a str),
    BuiltIn {
        primary: Vec<&'static Provider>,
        failover: Vec<&'static Provider>,
    },
}

impl<'a> Selection<'a> {
    fn new(transport: Transport, provider: &str, custom_url: &'a str) -> Self {
        let provider = provider.trim();
        let custom_url = custom_url.trim();
        if provider.eq_ignore_ascii_case("custom") && !custom_url.is_empty() {
            return Self::Custom(custom_url);
        }
        // An empty, unknown, or blank `custom` selection uses the transport's
        // defaults; so does a provider that does not serve the transport.
        let chosen = provider_by_id(provider);
        let primary = match chosen.filter(|chosen| chosen.offers(transport)) {
            Some(chosen) => vec![chosen],
            None => default_providers(transport).to_vec(),
        };
        // The failover stays with the provider the user chose, even when the
        // primary list had to come from the defaults.
        let failover = chosen.map_or_else(|| primary.clone(), |chosen| vec![chosen]);
        Self::BuiltIn { primary, failover }
    }
}

/// The upstream URLs a provider setting selects for `protocol`.
///
/// `DoQ` and `DoT` ride port 853, which NATs, VPNs, and filtering middleboxes
/// break far more often than TCP/443. When every 853 endpoint fails, fresh
/// (uncached) domains would otherwise burn the whole query deadline with
/// nowhere else to go, so for every transport but `DoH` the same provider's
/// `DoH` service follows the primary upstreams as a second tier. The exchange
/// tries the primary tier first and moves to `DoH` within a hedge delay when
/// it does not answer, skipping the primary entirely once it is down: still
/// encrypted, still the provider the user chose. Plain DNS carries the same
/// failover. A custom URL is used alone; see [`Selection::Custom`].
#[must_use]
pub(crate) fn resolve_upstream_urls(
    protocol: DnsProtocol,
    provider: &str,
    custom_url: &str,
) -> Vec<String> {
    let transport = Transport::from(protocol);
    let (primary, failover) = match Selection::new(transport, provider, custom_url) {
        Selection::Custom(url) => return vec![url.to_owned()],
        Selection::BuiltIn { primary, failover } => (primary, failover),
    };
    let mut urls: Vec<String> = primary
        .iter()
        .filter_map(|provider| provider.endpoint(transport))
        .collect();
    if transport != Transport::Doh {
        for url in failover
            .iter()
            .filter_map(|provider| provider.endpoint(Transport::Doh))
        {
            if !urls.contains(&url) {
                urls.push(url);
            }
        }
    }
    urls
}

/// The protocol and upstream URLs daemon `settings` select, parsed once.
pub(crate) fn upstreams_for_settings(settings: &DaemonSetting) -> (DnsProtocol, Vec<String>) {
    let protocol = DnsProtocol::from_settings(&settings.dns_protocol);
    let upstreams =
        resolve_upstream_urls(protocol, &settings.doh_provider, &settings.doh_custom_url);
    (protocol, upstreams)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_address_parses_in_its_family() {
        for service in RESOLVER_SERVICES {
            for address in service.ipv4 {
                assert!(
                    address.parse::<std::net::Ipv4Addr>().is_ok(),
                    "{}: {address}",
                    service.host
                );
            }
            for address in service.ipv6 {
                assert!(
                    address.parse::<std::net::Ipv6Addr>().is_ok(),
                    "{}: {address}",
                    service.host
                );
            }
        }
    }

    #[test]
    fn hosts_are_unique_and_lowercase() {
        for (index, service) in RESOLVER_SERVICES.iter().enumerate() {
            assert_eq!(service.host, service.host.to_ascii_lowercase());
            assert!(
                RESOLVER_SERVICES[..index]
                    .iter()
                    .all(|earlier| earlier.host != service.host),
                "{} is listed twice",
                service.host
            );
        }
    }

    #[test]
    fn withhold_shapes_follow_the_service_by_name_and_by_address() {
        for (host, shape) in [
            ("security.cloudflare-dns.com", ZeroAddress),
            ("1.1.1.3", ZeroAddress),
            ("2606:4700:4700::1113", ZeroAddress),
            ("1.1.1.1", Unlabeled),
            ("dns.adguard-dns.com", ZeroAddress),
            ("94.140.14.140", Unlabeled),
            ("dns11.quad9.net", EmptyNxDomain),
            ("2620:fe::fe", EmptyNxDomain),
            ("9.9.9.10", Unlabeled),
            ("abc123.dns.nextdns.io", ZeroAddress),
            ("evilnextdns.io", Unlabeled),
            ("dns.example.test", Unlabeled),
        ] {
            assert_eq!(withhold_shape(host), shape, "{host}");
        }
    }

    #[test]
    fn a_tls_name_is_given_only_for_an_address_one_host_owns() {
        assert_eq!(tls_name_for_address("1.1.1.1"), Some("cloudflare-dns.com"));
        assert_eq!(
            tls_name_for_address("1.0.0.2"),
            Some("security.cloudflare-dns.com")
        );
        assert_eq!(tls_name_for_address("8.8.4.4"), Some("dns.google"));
        assert_eq!(
            tls_name_for_address("2606:4700:4700::1111"),
            Some("cloudflare-dns.com")
        );
        assert_eq!(tls_name_for_address("208.67.222.222"), None, "two hosts");
        assert_eq!(tls_name_for_address("192.0.2.1"), None);
        assert_eq!(tls_name_for_address("not an address"), None);
    }

    #[test]
    fn adguard_unfiltered_dials_the_non_filtering_servers() {
        // Published at https://adguard-dns.io/kb/general/dns-providers/.
        assert_eq!(
            bootstrap_ipv4_for_host("unfiltered.adguard-dns.com"),
            Some(vec!["94.140.14.140".to_owned(), "94.140.14.141".to_owned()])
        );
        assert_ne!(
            bootstrap_ipv4_for_host("unfiltered.adguard-dns.com"),
            bootstrap_ipv4_for_host("dns.adguard-dns.com"),
            "the unfiltered service must not dial the filtering resolver"
        );
    }

    #[test]
    fn bootstrap_ips_for_quad9() {
        let ips = bootstrap_ipv4_for_host("dns.quad9.net").expect("ips");
        assert!(ips.contains(&"9.9.9.9".to_owned()));
    }

    #[test]
    fn quad9_secondary_addresses_follow_the_published_pattern() {
        // Quad9 pairs each dnsNN host with 9.9.9.NN and 149.112.112.NN.
        for (host, number) in [
            ("dns.quad9.net", None),
            ("dns10.quad9.net", Some("10")),
            ("dns11.quad9.net", Some("11")),
        ] {
            let ips = bootstrap_ipv4_for_host(host).expect("ips");
            match number {
                None => assert_eq!(ips, ["9.9.9.9", "149.112.112.112"], "{host}"),
                Some(n) => assert_eq!(
                    ips,
                    [format!("9.9.9.{n}"), format!("149.112.112.{n}")],
                    "{host}"
                ),
            }
        }
    }

    fn urls(protocol: DnsProtocol, provider: &str, custom_url: &str) -> Vec<String> {
        resolve_upstream_urls(protocol, provider, custom_url)
    }

    #[test]
    fn provider_ids_are_unique_and_every_service_is_listed() {
        for (index, provider) in PROVIDERS.iter().enumerate() {
            assert!(
                PROVIDERS[..index]
                    .iter()
                    .all(|earlier| earlier.id != provider.id),
                "{} is listed twice",
                provider.id
            );
            // A service a row uses but the list omits would be missing from
            // bootstrap and from the DoH block list.
            for service in [Some(provider.service), provider.doh_service]
                .into_iter()
                .flatten()
            {
                assert!(
                    RESOLVER_SERVICES
                        .iter()
                        .any(|listed| std::ptr::eq(*listed, service)),
                    "{} names {}, which is not in the service list",
                    provider.id,
                    service.host
                );
            }
        }
    }

    #[test]
    fn every_default_provider_serves_its_transport() {
        for transport in [
            Transport::Doh,
            Transport::Dot,
            Transport::Doq,
            Transport::Plain,
        ] {
            for provider in default_providers(transport) {
                assert!(
                    provider.offers(transport),
                    "{} does not serve {transport:?}",
                    provider.id
                );
            }
        }
    }

    #[test]
    fn doh_uses_the_provider_host_or_its_own_url() {
        assert_eq!(
            urls(DnsProtocol::Https, "cloudflare", ""),
            ["https://cloudflare-dns.com/dns-query"]
        );
        assert_eq!(
            urls(DnsProtocol::H3, "quad9", ""),
            ["https://dns.quad9.net/dns-query"]
        );
        assert_eq!(
            urls(DnsProtocol::Https, "cleanbrowsing", ""),
            ["https://doh.cleanbrowsing.org/doh/security-filter/"]
        );
        assert_eq!(
            urls(DnsProtocol::Https, "opendns-fam", ""),
            ["https://doh.familyshield.opendns.com/dns-query"]
        );
    }

    #[test]
    fn a_provider_id_is_matched_without_regard_to_case_or_spacing() {
        assert_eq!(
            urls(DnsProtocol::Https, " Quad9 ", ""),
            urls(DnsProtocol::Https, "quad9", "")
        );
    }

    #[test]
    fn a_custom_url_is_used_alone_on_every_transport() {
        for (protocol, url) in [
            (DnsProtocol::Https, "https://example.test/dns-query"),
            (DnsProtocol::Tls, "tls://dns.example.test:853"),
            (DnsProtocol::Quic, "quic://resolver.example.test"),
            (DnsProtocol::Udp, "192.0.2.53"),
        ] {
            assert_eq!(urls(protocol, "custom", url), [url], "{protocol:?}");
        }
    }

    #[test]
    fn port_853_and_plain_upstreams_carry_the_same_provider_doh_failover() {
        for (protocol, primary) in [
            (DnsProtocol::Tls, "dns.quad9.net:853"),
            (DnsProtocol::Quic, "dns.quad9.net"),
            (DnsProtocol::Udp, "dns.quad9.net"),
            (DnsProtocol::Tcp, "dns.quad9.net"),
        ] {
            assert_eq!(
                urls(protocol, "quad9", ""),
                [primary, "https://dns.quad9.net/dns-query"],
                "{protocol:?}"
            );
        }
    }

    #[test]
    fn doh_gets_no_extra_failover() {
        assert_eq!(
            urls(DnsProtocol::Https, "quad9", ""),
            ["https://dns.quad9.net/dns-query"]
        );
    }

    #[test]
    fn a_provider_without_doq_uses_the_doq_defaults_but_keeps_its_own_failover() {
        // Cloudflare has no DoQ service, so the primary list is the defaults;
        // the DoH failover must still be the provider the user chose.
        assert_eq!(
            urls(DnsProtocol::Quic, "cloudflare", ""),
            [
                "dns.quad9.net",
                "dns.adguard-dns.com",
                "https://cloudflare-dns.com/dns-query",
            ]
        );
    }

    #[test]
    fn empty_unknown_and_blank_custom_selections_use_the_defaults_with_their_failover() {
        for provider in ["", "quad-nine", "custom"] {
            assert_eq!(
                urls(DnsProtocol::Tls, provider, ""),
                [
                    "cloudflare-dns.com:853",
                    "https://cloudflare-dns.com/dns-query"
                ],
                "{provider:?}"
            );
            assert_eq!(
                urls(DnsProtocol::Quic, provider, ""),
                [
                    "dns.quad9.net",
                    "dns.adguard-dns.com",
                    "https://dns.quad9.net/dns-query",
                    "https://dns.adguard-dns.com/dns-query",
                ],
                "{provider:?}"
            );
        }
    }

    #[test]
    fn every_plain_service_has_bootstrap_addresses() {
        for provider in PROVIDERS {
            assert!(
                !provider.service.ipv4.is_empty(),
                "{} has no address to dial",
                provider.id
            );
        }
    }
}
