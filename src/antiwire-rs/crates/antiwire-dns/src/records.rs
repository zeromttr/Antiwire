//! On-demand DNS record lookups for one observed hostname.
//!
//! Queries go straight to the upstream the user configured, built fresh from
//! the saved settings, so Antiwire's own policy and cache never answer them:
//! a blocked name still shows its real records. The upstream provider sees
//! these queries like any other.
//!
//! DNS cannot list a zone (`ANY` is refused, RFC 8482, and zone transfers are
//! for secondaries), so this asks a fixed set of well-known names and types.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use antiwire_store::DaemonSetting;
use futures_util::stream::{self, StreamExt};
use hickory_proto::op::{Edns, Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::rdata::SVCB;
use hickory_proto::rr::{Name, RData, RecordType};

use crate::dns_name::is_at_or_below;
use crate::error::{DnsError, Result};
use crate::settings::{dns_config_from_settings, DnsProtocol};
use crate::upstream::{build_upstream_dns, UpstreamDns};

/// Time allowed for each query.
const QUERY_BUDGET: Duration = Duration::from_secs(5);
/// Queries in flight at once, so one lookup does not burst the upstream.
const PARALLEL_QUERIES: usize = 8;
/// How long lookups share the upstream pool the first of them built.
///
/// Inspecting a host asks for its records, its domain, and its certificates in
/// quick succession; sharing spares each a new TLS context and cold
/// handshakes. The pool is not told about network changes, so it is not kept
/// for long.
const POOL_REUSE: Duration = Duration::from_secs(60);

/// The upstream pool lookups last built, and what it was built from.
struct SharedPool {
    protocol: DnsProtocol,
    upstreams: Vec<String>,
    built_at: Instant,
    dns: Arc<UpstreamDns>,
}

static SHARED_POOL: parking_lot::Mutex<Option<SharedPool>> = parking_lot::Mutex::new(None);

/// DKIM keys live under a selector the domain chooses; these are the ones
/// the large mail and marketing providers use.
pub const DKIM_SELECTORS: &[&str] = &[
    "google",     // Google Workspace
    "selector1",  // Microsoft 365
    "selector2",  // Microsoft 365
    "k1",         // Mailchimp, Mailgun
    "k2",         // Mailchimp
    "s1",         // SendGrid and others
    "s2",         // SendGrid and others
    "default",    // many hosts and cPanel
    "dkim",       // generic
    "mail",       // generic
    "fm1",        // Fastmail
    "protonmail", // Proton Mail
    "zoho",       // Zoho Mail
    "amazonses",  // Amazon SES
    "mandrill",   // Mandrill
];

/// Why a set of records was asked for; the client groups answers by it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordPurpose {
    /// The observed hostname: addresses, aliases and HTTPS hints.
    Host,
    /// The registered domain's own records.
    Domain,
    /// Mail routing and sender policy.
    Mail,
    /// A guessed DKIM selector.
    Dkim,
    /// Reverse DNS for the address the connection reached.
    Reverse,
}

/// One answer record in presentation form.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordAnswer {
    /// Owner name, without the trailing dot.
    pub name: String,
    pub record_type: String,
    pub ttl: u32,
    pub data: String,
}

/// The answers to one question.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordSet {
    pub purpose: RecordPurpose,
    /// Name asked, without the trailing dot.
    pub name: String,
    pub record_type: String,
    /// `noerror`, `nxdomain`, `servfail`, `refused`, or `error` when the
    /// upstream did not answer.
    pub status: String,
    /// The upstream validated the answer with DNSSEC (the AD bit).
    pub authenticated: bool,
    pub answers: Vec<RecordAnswer>,
}

/// Every set asked for one lookup, and where they were asked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordLookup {
    /// Transport and endpoint, e.g. `DoH https://1.1.1.1/dns-query`.
    pub upstream: String,
    /// Domain the domain and mail questions were asked for.
    pub domain: String,
    pub sets: Vec<RecordSet>,
}

/// One question to ask.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlannedQuery {
    pub purpose: RecordPurpose,
    pub name: String,
    pub record_type: RecordType,
}

/// The questions for `host` under the registered `domain`, plus reverse DNS
/// for `address` when there is one. Duplicate questions are asked once.
#[must_use]
pub fn plan_queries(host: &str, domain: &str, address: Option<IpAddr>) -> Vec<PlannedQuery> {
    let host = host.trim().trim_end_matches('.').to_ascii_lowercase();
    let domain = domain.trim().trim_end_matches('.').to_ascii_lowercase();
    let mut plan: Vec<PlannedQuery> = Vec::new();
    let mut push = |purpose, name: String, record_type| {
        if !plan
            .iter()
            .any(|query| query.name == name && query.record_type == record_type)
        {
            plan.push(PlannedQuery {
                purpose,
                name,
                record_type,
            });
        }
    };

    for record_type in [RecordType::A, RecordType::AAAA, RecordType::HTTPS] {
        push(RecordPurpose::Host, host.clone(), record_type);
    }
    for record_type in [
        RecordType::A,
        RecordType::AAAA,
        RecordType::NS,
        RecordType::SOA,
        RecordType::TXT,
        RecordType::CAA,
        RecordType::HTTPS,
    ] {
        push(RecordPurpose::Domain, domain.clone(), record_type);
    }
    push(RecordPurpose::Mail, domain.clone(), RecordType::MX);
    for prefix in ["_dmarc", "_mta-sts", "_smtp._tls", "default._bimi"] {
        push(
            RecordPurpose::Mail,
            format!("{prefix}.{domain}"),
            RecordType::TXT,
        );
    }
    for selector in DKIM_SELECTORS {
        push(
            RecordPurpose::Dkim,
            format!("{selector}._domainkey.{domain}"),
            RecordType::TXT,
        );
    }
    if let Some(address) = address {
        push(
            RecordPurpose::Reverse,
            reverse_name(address),
            RecordType::PTR,
        );
    }
    plan
}

/// `in-addr.arpa` or `ip6.arpa` name for `address`.
#[must_use]
pub fn reverse_name(address: IpAddr) -> String {
    match address {
        IpAddr::V4(v4) => {
            let [a, b, c, d] = v4.octets();
            format!("{d}.{c}.{b}.{a}.in-addr.arpa")
        }
        IpAddr::V6(v6) => {
            let mut labels: Vec<String> = Vec::with_capacity(34);
            for byte in v6.octets().iter().rev() {
                labels.push(format!("{:x}", byte & 0x0f));
                labels.push(format!("{:x}", byte >> 4));
            }
            labels.push("ip6.arpa".to_owned());
            labels.join(".")
        }
    }
}

/// Asks the configured upstream about `host`, its domain, and the reverse
/// name of `address`.
///
/// The domain is `domain_hint` when it is `host` or a parent of it (the
/// registered name from a registration lookup); otherwise the zone apex the
/// upstream reports in its SOA answer for `host`; otherwise the registrable
/// domain of `host` under the Public Suffix List.
///
/// # Errors
///
/// Returns [`DnsError::Config`] when the saved settings do not produce a
/// usable upstream, and [`DnsError::Upstream`] for a name that is not a
/// hostname. A question that fails on its own is reported in its set's
/// `status` instead.
pub async fn lookup_records(
    settings: &DaemonSetting,
    host: &str,
    domain_hint: Option<&str>,
    address: Option<IpAddr>,
) -> Result<RecordLookup> {
    let host = hostname(host)?;
    let (dns, upstream) = connect(settings).await?;
    let domain = resolve_domain(&dns, &host, domain_hint).await;
    let plan = plan_queries(&host, &domain, address);

    let mut indexed: Vec<(usize, RecordSet)> = stream::iter(plan.into_iter().enumerate())
        .map(|(index, query)| {
            let dns = Arc::clone(&dns);
            async move {
                let set = match request(&query) {
                    Some(message) => match dns.exchange(&message, Some(QUERY_BUDGET)).await {
                        Ok(answer) => record_set(&query, &answer.message),
                        Err(_) => failed_set(&query),
                    },
                    None => failed_set(&query),
                };
                (index, set)
            }
        })
        .buffer_unordered(PARALLEL_QUERIES)
        .collect()
        .await;
    indexed.sort_by_key(|(index, _)| *index);
    Ok(RecordLookup {
        upstream,
        domain,
        sets: indexed.into_iter().map(|(_, set)| set).collect(),
    })
}

/// The domain `host` belongs to, as [`lookup_records`] decides it: the hint
/// when it is `host` or a parent of it, else the zone the upstream reports,
/// else the registrable domain under the Public Suffix List.
///
/// # Errors
///
/// As [`lookup_records`].
pub async fn find_domain(
    settings: &DaemonSetting,
    host: &str,
    domain_hint: Option<&str>,
) -> Result<String> {
    let host = hostname(host)?;
    if let Some(hint) = usable_hint(&host, domain_hint) {
        return Ok(hint);
    }
    let (dns, _) = connect(settings).await?;
    Ok(resolve_domain(&dns, &host, None).await)
}

fn hostname(host: &str) -> Result<String> {
    let host = host.trim().trim_end_matches('.').to_ascii_lowercase();
    if Name::from_ascii(format!("{host}.")).is_err() || !host.contains('.') {
        return Err(DnsError::Upstream(format!("{host} is not a hostname")));
    }
    Ok(host)
}

/// A fresh upstream client from the saved settings, and its description.
async fn connect(settings: &DaemonSetting) -> Result<(Arc<UpstreamDns>, String)> {
    let config = dns_config_from_settings(settings);
    let upstream = format!(
        "{} {}",
        protocol_name(config.protocol),
        config.upstreams.first().map_or("", String::as_str)
    )
    .trim()
    .to_owned();
    Ok((
        shared_pool(config.protocol, config.upstreams).await?,
        upstream,
    ))
}

/// An upstream pool for `upstreams`: the one lookups last built when it fits,
/// is younger than [`POOL_REUSE`], and has a tier up, else a new one.
async fn shared_pool(protocol: DnsProtocol, upstreams: Vec<String>) -> Result<Arc<UpstreamDns>> {
    let reusable = SHARED_POOL.lock().as_ref().and_then(|pool| {
        (pool.protocol == protocol
            && pool.upstreams == upstreams
            && pool.built_at.elapsed() < POOL_REUSE
            && !pool.dns.endpoints_degraded())
        .then(|| Arc::clone(&pool.dns))
    });
    if let Some(dns) = reusable {
        return Ok(dns);
    }
    let endpoints = upstreams.clone();
    let dns = tokio::task::spawn_blocking(move || build_upstream_dns(protocol, &endpoints))
        .await
        .map_err(|error| DnsError::Config(format!("upstream build task failed: {error}")))??;
    let dns = Arc::new(dns);
    *SHARED_POOL.lock() = Some(SharedPool {
        protocol,
        upstreams,
        built_at: Instant::now(),
        dns: Arc::clone(&dns),
    });
    Ok(dns)
}

fn usable_hint(host: &str, hint: Option<&str>) -> Option<String> {
    hint.map(|hint| hint.trim().trim_end_matches('.').to_ascii_lowercase())
        .filter(|hint| hint.contains('.') && is_at_or_below(host, hint))
}

async fn resolve_domain(dns: &UpstreamDns, host: &str, hint: Option<&str>) -> String {
    if let Some(hint) = usable_hint(host, hint) {
        return hint;
    }
    match zone_apex(dns, host).await {
        Some(zone) => zone,
        None => registrable_domain(host),
    }
}

/// The registrable domain (eTLD+1) of `host` under the Public Suffix List, so
/// `www.example.co.uk` gives `example.co.uk` and `user.github.io` gives
/// `user.github.io`. When the list has no registrable part (the host is a
/// public suffix such as `co.uk`, or a single label), the host itself is used.
fn registrable_domain(host: &str) -> String {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    psl::domain_str(&host).unwrap_or(&host).to_owned()
}

/// The zone `host` belongs to: the owner of the SOA record the upstream
/// returns for it, in the answer or (for a name with no SOA of its own) the
/// authority section. A zone of one label (a TLD) is not a domain.
async fn zone_apex(dns: &UpstreamDns, host: &str) -> Option<String> {
    let query = PlannedQuery {
        purpose: RecordPurpose::Domain,
        name: host.to_owned(),
        record_type: RecordType::SOA,
    };
    let message = request(&query)?;
    let answer = dns.exchange(&message, Some(QUERY_BUDGET)).await.ok()?;
    soa_owner(&answer.message).filter(|zone| zone.contains('.') && is_at_or_below(host, zone))
}

fn soa_owner(message: &Message) -> Option<String> {
    message
        .answers
        .iter()
        .chain(message.authorities.iter())
        .find(|record| record.record_type() == RecordType::SOA)
        .map(|record| {
            record
                .name
                .to_ascii()
                .trim_end_matches('.')
                .to_ascii_lowercase()
        })
}

fn protocol_name(protocol: DnsProtocol) -> &'static str {
    match protocol {
        DnsProtocol::Https => "DoH",
        DnsProtocol::H3 => "DoH3",
        DnsProtocol::Quic => "DoQ",
        DnsProtocol::Tls => "DoT",
        DnsProtocol::Tcp => "TCP",
        DnsProtocol::Udp => "UDP",
    }
}

fn request(query: &PlannedQuery) -> Option<Message> {
    let name = Name::from_ascii(format!("{}.", query.name)).ok()?;
    let mut message = Message::new(0, MessageType::Query, OpCode::Query);
    message.metadata.recursion_desired = true;
    // AD in a query asks a validating resolver to report validation (RFC 6840 §5.7).
    message.metadata.authentic_data = true;
    message.add_query(Query::query(name, query.record_type));
    let mut edns = Edns::new();
    edns.set_max_payload(1232);
    message.edns = Some(edns);
    Some(message)
}

fn failed_set(query: &PlannedQuery) -> RecordSet {
    RecordSet {
        purpose: query.purpose,
        name: query.name.clone(),
        record_type: query.record_type.to_string(),
        status: "error".to_owned(),
        authenticated: false,
        answers: Vec::new(),
    }
}

fn record_set(query: &PlannedQuery, message: &Message) -> RecordSet {
    let status = match message.metadata.response_code {
        ResponseCode::NoError => "noerror",
        ResponseCode::NXDomain => "nxdomain",
        ResponseCode::ServFail => "servfail",
        ResponseCode::Refused => "refused",
        _ => "error",
    };
    RecordSet {
        purpose: query.purpose,
        name: query.name.clone(),
        record_type: query.record_type.to_string(),
        status: status.to_owned(),
        authenticated: message.metadata.authentic_data,
        answers: message
            .answers
            .iter()
            .filter(|record| !matches!(record.record_type(), RecordType::RRSIG | RecordType::OPT))
            .map(|record| RecordAnswer {
                name: record.name.to_utf8().trim_end_matches('.').to_owned(),
                record_type: record.record_type().to_string(),
                ttl: record.ttl,
                data: presentation(&record.data),
            })
            .collect(),
    }
}

/// Record data in zone-file form, with names shown without their root dot
/// and TXT strings joined the way SPF and DKIM read them.
///
/// Only fields that are names lose the dot; a quoted value such as a CAA
/// tag or TXT string is shown exactly as published.
fn presentation(data: &RData) -> String {
    match data {
        RData::NS(ns) => bare(&ns.0),
        RData::CNAME(cname) => bare(&cname.0),
        RData::PTR(ptr) => bare(&ptr.0),
        RData::MX(mx) => format!("{} {}", mx.preference, bare(&mx.exchange)),
        RData::SOA(soa) => format!(
            "{} {} {} {} {} {} {}",
            bare(&soa.mname),
            bare(&soa.rname),
            soa.serial,
            soa.refresh,
            soa.retry,
            soa.expire,
            soa.minimum
        ),
        RData::HTTPS(https) => service_binding(&https.0),
        RData::SVCB(svcb) => service_binding(svcb),
        other => other.to_string(),
    }
}

/// An SVCB or HTTPS record: priority, target, then each parameter.
fn service_binding(svcb: &SVCB) -> String {
    use std::fmt::Write as _;

    let mut text = format!("{} {}", svcb.svc_priority, bare(&svcb.target_name));
    for (key, value) in &svcb.svc_params {
        // Writing to a `String` cannot fail.
        let _ = write!(text, " {key}={value}");
    }
    text
}

/// `name` without its root dot; the root itself stays `.`.
fn bare(name: &Name) -> String {
    let text = name.to_string();
    match text.strip_suffix('.') {
        Some(trimmed) if !trimmed.is_empty() => trimmed.to_owned(),
        _ => text,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::rr::rdata::{A, MX, TXT};
    use hickory_proto::rr::Record;

    #[test]
    fn plans_host_domain_mail_dkim_and_reverse_questions_once() {
        let plan = plan_queries(
            "www.Example.com.",
            "example.com",
            Some("192.0.2.7".parse().unwrap()),
        );
        let has = |name: &str, record_type| {
            plan.iter()
                .any(|query| query.name == name && query.record_type == record_type)
        };
        assert!(has("www.example.com", RecordType::A));
        assert!(has("example.com", RecordType::MX));
        assert!(has("_dmarc.example.com", RecordType::TXT));
        assert!(has("google._domainkey.example.com", RecordType::TXT));
        assert!(has("7.2.0.192.in-addr.arpa", RecordType::PTR));

        // The apex as the host is not asked twice.
        let apex = plan_queries("example.com", "example.com", None);
        let a_questions = apex
            .iter()
            .filter(|query| query.name == "example.com" && query.record_type == RecordType::A)
            .count();
        assert_eq!(a_questions, 1);
        assert!(apex
            .iter()
            .all(|query| query.purpose != RecordPurpose::Reverse));
    }

    #[test]
    fn the_soa_owner_names_the_zone() {
        use hickory_proto::rr::rdata::SOA;
        let zone = Name::from_ascii("example.co.uk.").unwrap();
        let mut message = Message::new(1, MessageType::Response, OpCode::Query);
        message.authorities.push(Record::from_rdata(
            zone.clone(),
            300,
            RData::SOA(SOA::new(
                Name::from_ascii("ns1.example.co.uk.").unwrap(),
                Name::from_ascii("hostmaster.example.co.uk.").unwrap(),
                1,
                3600,
                600,
                86400,
                300,
            )),
        ));
        assert_eq!(soa_owner(&message).as_deref(), Some("example.co.uk"));
        assert!(is_at_or_below("www.example.co.uk", "example.co.uk"));
        assert!(!is_at_or_below("www.example.co.uk", "ample.co.uk"));
    }

    /// The regression this guards: the fallback took the last two labels, so
    /// `www.example.co.uk` was reported as `co.uk`.
    #[test]
    fn falls_back_to_the_registrable_domain_under_the_public_suffix_list() {
        assert_eq!(registrable_domain("www.example.co.uk"), "example.co.uk");
        assert_eq!(registrable_domain("a.b.example.com"), "example.com");
        assert_eq!(registrable_domain("user.github.io"), "user.github.io");
        assert_eq!(registrable_domain("WWW.Example.COM."), "example.com");
    }

    #[test]
    fn a_public_suffix_or_single_label_is_its_own_domain() {
        assert_eq!(registrable_domain("co.uk"), "co.uk");
        assert_eq!(registrable_domain("github.io"), "github.io");
        assert_eq!(registrable_domain("localhost"), "localhost");
    }

    #[test]
    fn builds_reverse_names() {
        assert_eq!(
            reverse_name("2001:db8::1".parse().unwrap()),
            "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa"
        );
        assert_eq!(
            reverse_name("198.51.100.20".parse().unwrap()),
            "20.100.51.198.in-addr.arpa"
        );
    }

    #[test]
    fn reads_answers_in_presentation_form() {
        let query = PlannedQuery {
            purpose: RecordPurpose::Mail,
            name: "example.com".to_owned(),
            record_type: RecordType::MX,
        };
        let name = Name::from_ascii("example.com.").unwrap();
        let mut message = Message::new(1, MessageType::Response, OpCode::Query);
        message.metadata.authentic_data = true;
        message.answers.push(Record::from_rdata(
            name.clone(),
            300,
            RData::MX(MX::new(10, Name::from_ascii("mail.example.com.").unwrap())),
        ));
        message.answers.push(Record::from_rdata(
            name.clone(),
            60,
            RData::TXT(TXT::new(vec![
                "v=spf1 include:_spf.example.com".to_owned(),
                " -all".to_owned(),
            ])),
        ));
        message
            .answers
            .push(Record::from_rdata(name, 60, RData::A(A::new(192, 0, 2, 1))));

        let set = record_set(&query, &message);
        assert_eq!(set.status, "noerror");
        assert!(set.authenticated);
        assert_eq!(set.answers[0].data, "10 mail.example.com");
        assert_eq!(set.answers[0].name, "example.com");
        assert_eq!(set.answers[0].ttl, 300);
        assert_eq!(set.answers[1].data, "v=spf1 include:_spf.example.com -all");
        assert_eq!(set.answers[2].data, "192.0.2.1");
    }

    #[tokio::test]
    async fn lookups_share_a_pool_until_the_settings_change() {
        let upstreams = vec!["192.0.2.53".to_owned()];
        let first = shared_pool(DnsProtocol::Udp, upstreams.clone())
            .await
            .expect("pool");
        let again = shared_pool(DnsProtocol::Udp, upstreams.clone())
            .await
            .expect("pool");
        assert!(Arc::ptr_eq(&first, &again));

        let tcp = shared_pool(DnsProtocol::Tcp, upstreams)
            .await
            .expect("pool");
        assert!(!Arc::ptr_eq(&first, &tcp));
    }

    #[tokio::test]
    #[ignore = "queries the default upstream resolver over the network"]
    async fn looks_up_a_real_domain() {
        let settings = DaemonSetting::default();
        let lookup = lookup_records(
            &settings,
            "www.iana.org",
            None,
            Some("192.0.43.8".parse().unwrap()),
        )
        .await
        .unwrap();
        for set in &lookup.sets {
            if !set.answers.is_empty() {
                println!(
                    "{} {} {} {:?}",
                    set.name, set.record_type, set.status, set.answers
                );
            }
        }
        println!("via {} for {}", lookup.upstream, lookup.domain);
        assert_eq!(lookup.domain, "iana.org");
        assert!(lookup
            .sets
            .iter()
            .any(|set| set.record_type == "NS" && !set.answers.is_empty()));
    }

    #[test]
    fn a_missing_name_is_reported_not_raised() {
        let query = PlannedQuery {
            purpose: RecordPurpose::Dkim,
            name: "k1._domainkey.example.com".to_owned(),
            record_type: RecordType::TXT,
        };
        let mut message = Message::new(1, MessageType::Response, OpCode::Query);
        message.metadata.response_code = ResponseCode::NXDomain;
        let set = record_set(&query, &message);
        assert_eq!(set.status, "nxdomain");
        assert_eq!(set.answers, []);
    }

    #[test]
    fn only_name_fields_lose_their_root_dot() {
        use hickory_proto::rr::rdata::{HTTPS, NS, SOA};

        let name = |text: &str| Name::from_ascii(text).unwrap();
        assert_eq!(
            presentation(&RData::NS(NS(name("ns1.example.com.")))),
            "ns1.example.com"
        );
        assert_eq!(
            presentation(&RData::SOA(SOA::new(
                name("ns1.example.com."),
                name("hostmaster.example.com."),
                1,
                7_200,
                3_600,
                1_209_600,
                300,
            ))),
            "ns1.example.com hostmaster.example.com 1 7200 3600 1209600 300"
        );
        // An alias-mode target of the root stays `.`.
        assert_eq!(
            presentation(&RData::HTTPS(HTTPS(SVCB::new(1, Name::root(), Vec::new())))),
            "1 ."
        );
    }
}
