//! RFC 6761 & RFC 8375 Special-Use Domain Name (SUDN) local resolution.
//!
//! Synthesizes local authoritative responses for reserved and local domain names
//! (e.g. `localhost.`, `*.localhost.`, reverse loopback PTR, `*.invalid.`,
//! `*.home.arpa.`), preventing unnecessary network latency and leaks to
//! public upstream resolvers.
//!
//! Also answers the RFC 6303 / RFC 7793 locally-served reverse zones (private,
//! link-local, shared-address and ULA PTR space) and the `onion` (RFC 7686),
//! `alt` (RFC 9476) and `local` (RFC 6762) top-level names, and the RFC 9462
//! `resolver.arpa` discovery zone. A public upstream cannot answer any of
//! these; forwarding them only leaks LAN addressing, host names, or Tor service
//! names to the provider.
//!
//! Classification uses only the already-normalized question name so the cache
//! hit path never clones the client message. Synthesis runs only on a match.

use std::net::{Ipv4Addr, Ipv6Addr};

use hickory_proto::op::{Edns, Message, Metadata, OpCode, Query, ResponseCode};
use hickory_proto::rr::{rdata, Name, RData, Record, RecordType};

use crate::dns_name::{is_at_or_below, labels_below};

const SUDN_TTL: u32 = 3600;

/// Negative-cache TTL advertised on locally synthesized NXDOMAIN/NODATA. Kept
/// short because a name reserved today may become resolvable after a network
/// transition or an mDNS announcement.
const SUDN_NEGATIVE_TTL: u32 = 60;

/// Reserved zones that must never reach a public upstream. `home.arpa` is a
/// real locally-served zone, so its apex takes the empty-zone path and only
/// names below it are NXDOMAIN.
const RESERVED_NXDOMAIN_ZONES: &[&str] = &["invalid", "test", "home.arpa", "onion", "alt", "local"];

/// Locally-served zones where every name, apex included, is NODATA.
///
/// RFC 9462 §6.1 and §8.2: `resolver.arpa` names the resolver being asked, so
/// a forwarder must not pass it upstream, where `_dns.resolver.arpa` would
/// describe the upstream provider instead. Without Designated Resolvers to
/// advertise, §4 asks for NODATA throughout the zone.
const NODATA_ZONES: &[&str] = &["resolver.arpa"];

const IPV6_LOOPBACK_PTR: &str =
    "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa";

/// Reverse names of the two addresses the resolver listens on, `127.0.0.1`
/// and `::1` (see `listener::dns_listen_addr`).
const RESOLVER_ADDRESS_PTRS: [&str; 2] = ["1.0.0.127.in-addr.arpa", IPV6_LOOPBACK_PTR];

/// The name the resolver gives for its own addresses, where any other
/// loopback address is `localhost`. A tool that names the server it asked from
/// that server's reverse record, as `nslookup` does, then shows this instead
/// of `localhost`. One label, so nothing can mistake it for a name to look up
/// under a search domain.
const RESOLVER_NAME: &[u8] = b"Antiwire Resolver";

/// How a special-use name should be answered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SpecialUseKind {
    Localhost,
    /// The reverse name of an address the resolver listens on.
    ResolverAddress,
    ReverseLoopback,
    NxDomain,
    /// Apex of a locally-served empty zone: NOERROR with no answer, so a
    /// SOA/NS probe of the zone itself does not look like a missing name.
    EmptyZoneApex,
    /// Any name in a zone of [`NODATA_ZONES`]: NOERROR with no answer.
    NoData,
}

/// Classifies `normalized_domain` without touching the client message.
///
/// `normalized_domain` is the cache-key form: lowercase, no trailing dot.
/// Trailing dots and ASCII case are still tolerated so a mismatched caller
/// cannot leak a special-use name upstream.
///
/// With `answer_local_names` false, `.local` names are not special-use and
/// go upstream like any other name (for Active Directory domains ending in
/// `.local`). Every other reserved zone is unaffected.
#[must_use]
pub(crate) fn classify_special_use_with(
    normalized_domain: &str,
    answer_local_names: bool,
) -> Option<SpecialUseKind> {
    let domain = normalized_domain
        .strip_suffix('.')
        .unwrap_or(normalized_domain);
    if domain.is_empty() {
        return None;
    }
    if is_localhost(domain) {
        return Some(SpecialUseKind::Localhost);
    }
    if RESOLVER_ADDRESS_PTRS
        .iter()
        .any(|ptr| domain.eq_ignore_ascii_case(ptr))
    {
        return Some(SpecialUseKind::ResolverAddress);
    }
    if is_reverse_loopback(domain) {
        return Some(SpecialUseKind::ReverseLoopback);
    }
    if nodata_zone(domain).is_some() {
        return Some(SpecialUseKind::NoData);
    }
    if is_reserved_nxdomain(domain, answer_local_names) {
        // `home.arpa` is a locally-served zone, not a guaranteed-missing name:
        // its apex is NODATA, and only names below it are NXDOMAIN.
        return Some(if domain.eq_ignore_ascii_case("home.arpa") {
            SpecialUseKind::EmptyZoneApex
        } else {
            SpecialUseKind::NxDomain
        });
    }
    if let Some((position, _)) = locally_served_reverse_zone(domain) {
        return Some(match position {
            ZonePosition::Apex => SpecialUseKind::EmptyZoneApex,
            ZonePosition::Below => SpecialUseKind::NxDomain,
        });
    }
    None
}

/// Builds the local authoritative response for a classified special-use query.
#[must_use]
pub(crate) fn synthesize_special_use(
    metadata: &Metadata,
    question: &Query,
    edns: Option<&Edns>,
    kind: SpecialUseKind,
    qtype: RecordType,
) -> Message {
    let mut response = match kind {
        SpecialUseKind::Localhost => synthesize_localhost_response(metadata, question, edns, qtype),
        SpecialUseKind::ResolverAddress => {
            synthesize_ptr_response(metadata, question, edns, qtype, resolver_name())
        }
        SpecialUseKind::ReverseLoopback => {
            let localhost = Name::from_ascii("localhost.").expect("valid name");
            synthesize_ptr_response(metadata, question, edns, qtype, localhost)
        }
        SpecialUseKind::NxDomain => synthesize_nxdomain_response(metadata, question, edns),
        SpecialUseKind::EmptyZoneApex | SpecialUseKind::NoData => {
            create_base_response(metadata, question, edns, ResponseCode::NoError)
        }
    };
    // A synthesized negative must carry an SOA so the client can negative-cache
    // it (RFC 2308 §5) instead of retrying the name on every query.
    if response.answers.is_empty() {
        response.add_authority(negative_soa(question.name(), kind));
    }
    response
}

/// SOA for the zone a synthesized negative belongs to.
fn negative_soa(name: &Name, kind: SpecialUseKind) -> Record {
    crate::messages::synthetic_soa(negative_soa_zone(&name.to_utf8(), kind), SUDN_NEGATIVE_TTL)
}

fn negative_soa_zone(domain: &str, kind: SpecialUseKind) -> Name {
    let domain = domain.trim_end_matches('.');
    let zone = match kind {
        SpecialUseKind::Localhost => name_from_str("localhost"),
        SpecialUseKind::ResolverAddress | SpecialUseKind::ReverseLoopback => {
            if is_at_or_below(domain, "ip6.arpa") {
                name_from_str(domain)
            } else {
                name_from_str("127.in-addr.arpa")
            }
        }
        SpecialUseKind::EmptyZoneApex => name_from_str(domain),
        SpecialUseKind::NoData => nodata_zone(domain).and_then(name_from_str),
        SpecialUseKind::NxDomain => reserved_nxdomain_zone(domain)
            .and_then(name_from_str)
            .or_else(|| locally_served_reverse_zone(domain).map(|(_, zone)| zone)),
    };
    zone.unwrap_or_else(Name::root)
}

fn name_from_str(domain: &str) -> Option<Name> {
    let domain = domain.trim_end_matches('.');
    if domain.is_empty() {
        return None;
    }
    Name::from_ascii(format!("{domain}.")).ok()
}

/// [`classify_special_use_with`] with `.local` answered locally, the default.
#[cfg(test)]
#[must_use]
pub(crate) fn classify_special_use(normalized_domain: &str) -> Option<SpecialUseKind> {
    classify_special_use_with(normalized_domain, true)
}

/// Matches and locally synthesizes responses for RFC 6761 / RFC 8375 special-use names.
///
/// Prefer [`classify_special_use_with`] on the hot path so a non-match does not
/// require an owned [`Message`].
#[cfg(test)]
#[must_use]
pub(crate) fn match_special_use_domain(
    query: &Message,
    normalized_domain: &str,
    qtype: RecordType,
) -> Option<Message> {
    let kind = classify_special_use(normalized_domain)?;
    let question = query.queries.first()?;
    Some(synthesize_special_use(
        &query.metadata,
        question,
        query.edns.as_ref(),
        kind,
        qtype,
    ))
}

fn is_localhost(domain: &str) -> bool {
    is_at_or_below(domain, "localhost")
}

/// Whether this resolver answers `name` itself, with a loopback address,
/// whatever an upstream says. Of the special-use names, only `localhost` and
/// the names below it get addresses.
#[must_use]
pub(crate) fn answers_with_loopback(name: &Name) -> bool {
    let ascii = name.to_ascii();
    is_localhost(ascii.strip_suffix('.').unwrap_or(&ascii))
}

/// True only for an actual loopback PTR name, never the zone apex or a
/// non-numeric label below it.
///
/// The IPv4 loopback space is 127.0.0.0/8, so a PTR name always has exactly
/// three numeric octets below `127.in-addr.arpa` (`1.0.0.127.in-addr.arpa` for
/// 127.0.0.1). The apex and malformed names fall through to
/// [`locally_served_reverse_zone`], which serves the empty zone.
fn is_reverse_loopback(domain: &str) -> bool {
    if domain.eq_ignore_ascii_case(IPV6_LOOPBACK_PTR) {
        return true;
    }
    let Some(prefix) = labels_below(domain, "127.in-addr.arpa") else {
        return false;
    };
    let labels: Vec<&str> = prefix.split('.').collect();
    labels.len() == 3 && labels.iter().all(|label| label.parse::<u8>().is_ok())
}

fn is_reserved_nxdomain(domain: &str, answer_local_names: bool) -> bool {
    reserved_nxdomain_zone(domain).is_some_and(|zone| answer_local_names || zone != "local")
}

/// RFC 6761 `invalid` and `test`, RFC 8375 `home.arpa`, RFC 7686 `onion` (MUST
/// NOT be forwarded), RFC 9476 `alt`, RFC 6762 `local` (mDNS only; a unicast
/// resolver can never answer it).
fn reserved_nxdomain_zone(domain: &str) -> Option<&'static str> {
    RESERVED_NXDOMAIN_ZONES
        .iter()
        .copied()
        .find(|zone| is_at_or_below(domain, zone))
}

fn nodata_zone(domain: &str) -> Option<&'static str> {
    NODATA_ZONES
        .iter()
        .copied()
        .find(|zone| is_at_or_below(domain, zone))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ZonePosition {
    Apex,
    Below,
}

/// RFC 6303 §4 and RFC 7793 reverse zones a recursive resolver serves itself.
///
/// The loopback zones are handled separately by [`is_reverse_loopback`] because
/// a real PTR name gets a PTR answer; everything here is an empty zone, and the
/// returned [`ZonePosition`] tells the caller whether the query is the apex.
///
/// The zone apex travels with the position so a synthesized negative can carry
/// an SOA owned by the right zone.
fn locally_served_reverse_zone(domain: &str) -> Option<(ZonePosition, Name)> {
    if let Some(prefix) = labels_below(domain, "in-addr.arpa") {
        // Labels closest to the root first: `1.0.168.192.in-addr.arpa` →
        // [192, 168, 0, 1]. Non-numeric labels never match a served zone.
        let labels: Vec<Option<u8>> = prefix
            .rsplit('.')
            .map(|label| label.parse::<u8>().ok())
            .collect();
        let octet = |index: usize| labels.get(index).copied().flatten();
        let (zone_labels, served) = match (octet(0), octet(1), octet(2), octet(3)) {
            // "This network" (0/8), private 10/8, and loopback 127/8. Valid
            // loopback PTRs are answered by `is_reverse_loopback`; the apex and
            // malformed names below 127 are empty-zone territory.
            (Some(0 | 10 | 127), _, _, _) => (1, true),
            // 172.16/12, 192.168/16, 169.254/16 link-local, and RFC 7793's
            // 100.64/10 shared address space.
            (Some(172), Some(16..=31), _, _)
            | (Some(192), Some(168), _, _)
            | (Some(169), Some(254), _, _)
            | (Some(100), Some(64..=127), _, _) => (2, true),
            // TEST-NET-1/2/3 (RFC 5737) documentation networks.
            (Some(192), Some(0), Some(2), _)
            | (Some(198), Some(51), Some(100), _)
            | (Some(203), Some(0), Some(113), _) => (3, true),
            // 255.255.255.255 limited broadcast.
            (Some(255), Some(255), Some(255), Some(255)) => (4, true),
            _ => (0, false),
        };
        if !served {
            return None;
        }
        let zone = reverse_zone_name(&labels, zone_labels, "in-addr.arpa", ReverseLabel::Octet)?;
        return Some((zone_position(labels.len(), zone_labels), zone));
    }

    if let Some(prefix) = labels_below(domain, "ip6.arpa") {
        let labels: Vec<Option<u8>> = prefix.rsplit('.').map(nibble).collect();
        let nib = |index: usize| labels.get(index).copied().flatten();
        let (zone_labels, served) = match (nib(0), nib(1), nib(2)) {
            // fd00::/8 unique local addresses.
            (Some(b'f'), Some(b'd'), _) => (2, true),
            // fe80::/10 link-local.
            (Some(b'f'), Some(b'e'), Some(b'8'..=b'b')) => (3, true),
            // The unspecified address `::` (RFC 6303), symmetric with the
            // IPv4 0/8 arm. Its whole 32-nibble reverse name is the zone.
            (Some(b'0'), Some(b'0'), Some(b'0'))
                if labels.len() == 32 && labels.iter().all(|nibble| *nibble == Some(b'0')) =>
            {
                (32, true)
            }
            _ => (0, false),
        };
        if !served {
            return None;
        }
        let zone = reverse_zone_name(&labels, zone_labels, "ip6.arpa", ReverseLabel::Nibble)?;
        return Some((zone_position(labels.len(), zone_labels), zone));
    }

    None
}

fn zone_position(label_count: usize, zone_labels: usize) -> ZonePosition {
    if label_count == zone_labels {
        ZonePosition::Apex
    } else {
        ZonePosition::Below
    }
}

/// How a reverse-zone label byte is written back into a name.
#[derive(Clone, Copy)]
enum ReverseLabel {
    /// An `in-addr.arpa` octet, written in decimal.
    Octet,
    /// An `ip6.arpa` nibble, stored as its ASCII hex digit.
    Nibble,
}

/// Rebuilds a zone apex from root-first labels below `suffix`.
///
/// The labels are reversed back into DNS order, so octets `[192, 168, 0, 1]`
/// with two zone labels yields `168.192.in-addr.arpa.`.
fn reverse_zone_name(
    labels: &[Option<u8>],
    zone_labels: usize,
    suffix: &str,
    form: ReverseLabel,
) -> Option<Name> {
    let mut name = String::new();
    for label in labels.get(..zone_labels)?.iter().rev() {
        let label = (*label)?;
        match form {
            ReverseLabel::Octet => name.push_str(&label.to_string()),
            ReverseLabel::Nibble => name.push(char::from(label)),
        }
        name.push('.');
    }
    name.push_str(suffix);
    name.push('.');
    Name::from_ascii(name).ok()
}

/// One lowercase hex digit label of an `ip6.arpa` name, or `None`.
fn nibble(label: &str) -> Option<u8> {
    match label.as_bytes() {
        [byte] if byte.is_ascii_hexdigit() => Some(byte.to_ascii_lowercase()),
        _ => None,
    }
}

fn create_base_response(
    metadata: &Metadata,
    question: &Query,
    edns: Option<&Edns>,
    rcode: ResponseCode,
) -> Message {
    let mut response = Message::response(metadata.id, OpCode::Query);
    response.metadata.authoritative = true;
    response.metadata.recursion_available = true;
    response.metadata.recursion_desired = metadata.recursion_desired;
    response.metadata.response_code = rcode;
    response.add_query(question.clone());
    // Echo the client's OPT (DO bit, clamped payload) rather than dropping it,
    // matching the block/error response path.
    response.edns = crate::service::response_edns(edns, None);
    response
}

fn synthesize_localhost_response(
    metadata: &Metadata,
    question: &Query,
    edns: Option<&Edns>,
    qtype: RecordType,
) -> Message {
    let mut response = create_base_response(metadata, question, edns, ResponseCode::NoError);
    let name = question.name().clone();

    match qtype {
        RecordType::A => {
            response.add_answer(Record::from_rdata(
                name,
                SUDN_TTL,
                RData::A(rdata::A(Ipv4Addr::LOCALHOST)),
            ));
        }
        RecordType::AAAA => {
            response.add_answer(Record::from_rdata(
                name,
                SUDN_TTL,
                RData::AAAA(rdata::AAAA(Ipv6Addr::LOCALHOST)),
            ));
        }
        _ => {
            // NODATA response for non-address records
        }
    }
    response
}

/// [`RESOLVER_NAME`] as a fully qualified name.
fn resolver_name() -> Name {
    let mut name = Name::from_labels([RESOLVER_NAME]).expect("one valid label");
    name.set_fqdn(true);
    name
}

/// Answers a PTR query for a loopback address with `target`, and any other
/// type with NODATA.
fn synthesize_ptr_response(
    metadata: &Metadata,
    question: &Query,
    edns: Option<&Edns>,
    qtype: RecordType,
    target: Name,
) -> Message {
    let mut response = create_base_response(metadata, question, edns, ResponseCode::NoError);
    if qtype == RecordType::PTR {
        response.add_answer(Record::from_rdata(
            question.name().clone(),
            SUDN_TTL,
            RData::PTR(rdata::PTR(target)),
        ));
    }
    response
}

fn synthesize_nxdomain_response(
    metadata: &Metadata,
    question: &Query,
    edns: Option<&Edns>,
) -> Message {
    create_base_response(metadata, question, edns, ResponseCode::NXDomain)
}

#[cfg(test)]
mod tests {
    use hickory_proto::op::{MessageType, Query};

    use super::*;

    fn make_query(domain: &str, qtype: RecordType) -> Message {
        let mut msg = Message::new(0x1234, MessageType::Query, OpCode::Query);
        msg.metadata.recursion_desired = true;
        let name = Name::from_ascii(domain).expect("valid name");
        msg.add_query(Query::query(name, qtype));
        msg
    }

    #[test]
    fn classify_does_not_need_a_message() {
        assert_eq!(
            classify_special_use("localhost"),
            Some(SpecialUseKind::Localhost)
        );
        assert_eq!(
            classify_special_use("APP.LOCALHOST."),
            Some(SpecialUseKind::Localhost)
        );
        assert_eq!(
            classify_special_use("1.0.0.127.in-addr.arpa"),
            Some(SpecialUseKind::ResolverAddress)
        );
        assert_eq!(
            classify_special_use("2.0.0.127.in-addr.arpa"),
            Some(SpecialUseKind::ReverseLoopback)
        );
        assert_eq!(
            classify_special_use("test.invalid"),
            Some(SpecialUseKind::NxDomain)
        );
        // RFC 6761 §6.2 `test` is reserved and must not leak upstream.
        assert_eq!(
            classify_special_use("some.test"),
            Some(SpecialUseKind::NxDomain)
        );
        assert_eq!(classify_special_use("test"), Some(SpecialUseKind::NxDomain));
        // `home.arpa` is a real locally-served zone: apex NODATA, below NXDOMAIN.
        assert_eq!(
            classify_special_use("home.arpa"),
            Some(SpecialUseKind::EmptyZoneApex)
        );
        assert_eq!(
            classify_special_use("printer.home.arpa"),
            Some(SpecialUseKind::NxDomain)
        );
        // 127/8 apex is an empty zone; only real PTR names are ReverseLoopback.
        assert_eq!(
            classify_special_use("127.in-addr.arpa"),
            Some(SpecialUseKind::EmptyZoneApex)
        );
        assert_eq!(
            classify_special_use("foo.127.in-addr.arpa"),
            Some(SpecialUseKind::NxDomain)
        );
        assert_eq!(
            classify_special_use("1.0.127.in-addr.arpa"),
            Some(SpecialUseKind::NxDomain)
        );
        // RFC 5737 TEST-NET-1/2/3.
        assert_eq!(
            classify_special_use("2.0.192.in-addr.arpa"),
            Some(SpecialUseKind::EmptyZoneApex)
        );
        assert_eq!(
            classify_special_use("1.2.0.192.in-addr.arpa"),
            Some(SpecialUseKind::NxDomain)
        );
        assert_eq!(
            classify_special_use("5.113.0.203.in-addr.arpa"),
            Some(SpecialUseKind::NxDomain)
        );
        assert!(classify_special_use("google.com").is_none());
        assert!(classify_special_use("notlocalhost").is_none());
        assert!(classify_special_use("localhost.com").is_none());
        assert!(classify_special_use("foo.localhost.com").is_none());
        assert!(classify_special_use("invalid.com").is_none());
        assert!(classify_special_use("home.arpa.com").is_none());
        assert!(classify_special_use("127.in-addr.arpa.example").is_none());
        assert!(classify_special_use("1127.in-addr.arpa").is_none());
        assert!(classify_special_use("3.0.192.in-addr.arpa").is_none());
        assert!(classify_special_use("").is_none());
        assert!(classify_special_use(".").is_none());
        assert_eq!(
            classify_special_use(
                "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.IP6.ARPA."
            ),
            Some(SpecialUseKind::ResolverAddress)
        );
        // The unspecified address `::`, symmetric with the IPv4 0/8 arm.
        assert_eq!(
            classify_special_use(
                "0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa"
            ),
            Some(SpecialUseKind::EmptyZoneApex)
        );
    }

    #[test]
    fn non_ascii_names_never_split_a_zone_suffix() {
        // A multibyte character must never be split when the suffix is compared;
        // non-ASCII names neither match nor panic.
        assert!(!is_at_or_below("testé", "test"));
        assert!(!is_at_or_below("invalidé", "invalid"));
        for name in ["é", "héllo", "testé", "invalidé", "✈.example"] {
            assert!(classify_special_use(name).is_none(), "{name}");
        }
    }

    #[test]
    fn locally_served_reverse_zones_never_leave_the_host() {
        let below = [
            "1.0.0.10.in-addr.arpa",
            "5.4.16.172.in-addr.arpa",
            "5.4.31.172.in-addr.arpa",
            "1.1.168.192.in-addr.arpa",
            "9.9.254.169.in-addr.arpa",
            "1.0.64.100.in-addr.arpa",
            "1.0.127.100.in-addr.arpa",
            "7.0.0.0.in-addr.arpa",
            "1.2.0.192.in-addr.arpa",
            "9.100.51.198.in-addr.arpa",
            "5.113.0.203.in-addr.arpa",
            "foo.127.in-addr.arpa",
            "x.255.255.255.255.in-addr.arpa",
            "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.d.f.ip6.arpa",
            "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.e.f.ip6.arpa",
            "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.B.E.F.IP6.ARPA.",
        ];
        for name in below {
            assert_eq!(
                classify_special_use(name),
                Some(SpecialUseKind::NxDomain),
                "{name}"
            );
        }

        let apex = [
            "10.in-addr.arpa",
            "16.172.in-addr.arpa",
            "168.192.in-addr.arpa",
            "254.169.in-addr.arpa",
            "64.100.in-addr.arpa",
            "127.in-addr.arpa",
            "2.0.192.in-addr.arpa",
            "100.51.198.in-addr.arpa",
            "113.0.203.in-addr.arpa",
            "255.255.255.255.in-addr.arpa",
            "d.f.ip6.arpa",
            "a.e.f.ip6.arpa",
            "0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa",
        ];
        for name in apex {
            assert_eq!(
                classify_special_use(name),
                Some(SpecialUseKind::EmptyZoneApex),
                "{name}"
            );
        }

        // Public reverse space, near misses, and the parent zones still forward.
        let forwarded = [
            "1.1.1.1.in-addr.arpa",
            "5.4.15.172.in-addr.arpa",
            "5.4.32.172.in-addr.arpa",
            "1.0.63.100.in-addr.arpa",
            "1.0.128.100.in-addr.arpa",
            "3.0.192.in-addr.arpa",
            "101.51.198.in-addr.arpa",
            "114.0.203.in-addr.arpa",
            "1.255.255.255.in-addr.arpa",
            "in-addr.arpa",
            "ip6.arpa",
            "x10.in-addr.arpa",
            "10.in-addr.arpa.example",
            "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.c.f.ip6.arpa",
            "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.c.e.f.ip6.arpa",
            "ff.f.ip6.arpa",
        ];
        for name in forwarded {
            assert!(classify_special_use(name).is_none(), "{name}");
        }
    }

    #[test]
    fn onion_alt_and_local_are_answered_locally() {
        for name in [
            "onion",
            "abcdefghijklmnop.onion",
            "svc.alt",
            "printer.local",
            "LOCAL.",
        ] {
            assert_eq!(
                classify_special_use(name),
                Some(SpecialUseKind::NxDomain),
                "{name}"
            );
        }
        for name in [
            "onion.example",
            "localhost.local.example",
            "notlocal",
            "alt.example",
        ] {
            assert!(classify_special_use(name).is_none(), "{name}");
        }
    }

    #[test]
    fn corp_local_is_special_use_only_while_local_names_are_answered() {
        assert_eq!(
            classify_special_use_with("foo.corp.local", true),
            Some(SpecialUseKind::NxDomain)
        );
        assert_eq!(classify_special_use_with("foo.corp.local", false), None);
        assert_eq!(classify_special_use_with("local", false), None);
        assert_eq!(
            classify_special_use_with("x.invalid", false),
            Some(SpecialUseKind::NxDomain),
            "other reserved zones ignore the local-names setting"
        );
        assert_eq!(
            classify_special_use_with("x.invalid", true),
            Some(SpecialUseKind::NxDomain)
        );
    }

    #[test]
    fn empty_zone_apex_is_nodata_and_below_is_nxdomain() {
        let apex = make_query("168.192.in-addr.arpa.", RecordType::SOA);
        let resp = match_special_use_domain(&apex, "168.192.in-addr.arpa", RecordType::SOA)
            .expect("match");
        assert_eq!(resp.metadata.response_code, ResponseCode::NoError);
        assert_eq!(resp.answers, []);
        assert!(resp.metadata.authoritative);

        let ptr = make_query("1.1.168.192.in-addr.arpa.", RecordType::PTR);
        let resp = match_special_use_domain(&ptr, "1.1.168.192.in-addr.arpa", RecordType::PTR)
            .expect("match");
        assert_eq!(resp.metadata.response_code, ResponseCode::NXDomain);
    }

    #[test]
    fn localhost_resolves_ipv4_and_ipv6() {
        let q_a = make_query("localhost.", RecordType::A);
        let resp_a = match_special_use_domain(&q_a, "localhost", RecordType::A).expect("match");
        assert_eq!(resp_a.metadata.response_code, ResponseCode::NoError);
        assert!(resp_a.metadata.recursion_desired);
        assert_eq!(resp_a.answers.len(), 1);
        assert_eq!(
            resp_a.answers[0].data,
            RData::A(rdata::A(Ipv4Addr::LOCALHOST))
        );

        let q_aaaa = make_query("localhost.", RecordType::AAAA);
        let resp_aaaa =
            match_special_use_domain(&q_aaaa, "localhost", RecordType::AAAA).expect("match");
        assert_eq!(resp_aaaa.metadata.response_code, ResponseCode::NoError);
        assert_eq!(resp_aaaa.answers.len(), 1);
        assert_eq!(
            resp_aaaa.answers[0].data,
            RData::AAAA(rdata::AAAA(Ipv6Addr::LOCALHOST))
        );
    }

    #[test]
    fn sub_localhost_resolves() {
        let q = make_query("app.localhost.", RecordType::A);
        let resp = match_special_use_domain(&q, "app.localhost", RecordType::A).expect("match");
        assert_eq!(resp.metadata.response_code, ResponseCode::NoError);
        assert_eq!(
            resp.answers[0].data,
            RData::A(rdata::A(Ipv4Addr::LOCALHOST))
        );
    }

    #[test]
    fn localhost_non_address_returns_nodata() {
        let q = make_query("localhost.", RecordType::TXT);
        let resp = match_special_use_domain(&q, "localhost", RecordType::TXT).expect("match");
        assert_eq!(resp.metadata.response_code, ResponseCode::NoError);
        assert_eq!(resp.answers, []);
    }

    #[test]
    fn reverse_loopback_ptr_resolves() {
        let q = make_query("2.0.0.127.in-addr.arpa.", RecordType::PTR);
        let resp =
            match_special_use_domain(&q, "2.0.0.127.in-addr.arpa", RecordType::PTR).expect("match");
        assert_eq!(resp.metadata.response_code, ResponseCode::NoError);
        assert_eq!(resp.answers.len(), 1);
        assert_eq!(
            resp.answers[0].data,
            RData::PTR(rdata::PTR(Name::from_ascii("localhost.").unwrap()))
        );
    }

    /// The reverse names in [`RESOLVER_ADDRESS_PTRS`] are written out, so
    /// they have to follow the addresses the listener binds.
    #[test]
    fn the_resolver_addresses_are_the_ones_the_listener_binds() {
        for addr in [
            crate::listener::dns_listen_addr(),
            crate::listener::dns_listen_addr_v6(),
        ] {
            assert_eq!(
                classify_special_use(&crate::reverse_name(addr.ip())),
                Some(SpecialUseKind::ResolverAddress),
                "{addr}"
            );
        }
    }

    /// The name a client reads back, after the trip over the wire: one label,
    /// with its capitals and its space as written.
    #[test]
    fn the_resolvers_own_addresses_are_named_for_it() {
        for ptr in RESOLVER_ADDRESS_PTRS {
            let q = make_query(&format!("{ptr}."), RecordType::PTR);
            let resp = match_special_use_domain(&q, ptr, RecordType::PTR).expect("match");
            assert_eq!(resp.metadata.response_code, ResponseCode::NoError);

            let wire = crate::messages::encode_message(&resp).expect("encode");
            let decoded = Message::from_vec(&wire).expect("decode");
            let [answer] = decoded.answers.as_slice() else {
                panic!("{ptr}: one answer");
            };
            let RData::PTR(target) = &answer.data else {
                panic!("{ptr}: a PTR answer");
            };
            let labels: Vec<&[u8]> = target.0.iter().collect();
            assert_eq!(labels, [b"Antiwire Resolver".as_slice()], "{ptr}");
            assert!(target.0.is_fqdn());
        }
    }

    #[test]
    fn a_resolver_address_has_no_other_records() {
        let ptr = RESOLVER_ADDRESS_PTRS[0];
        let q = make_query(&format!("{ptr}."), RecordType::TXT);
        let resp = match_special_use_domain(&q, ptr, RecordType::TXT).expect("match");
        assert_eq!(resp.metadata.response_code, ResponseCode::NoError);
        assert_eq!(resp.answers, []);
        assert_eq!(
            resp.authorities.len(),
            1,
            "NODATA carries the zone's SOA so it can be cached"
        );
        assert_eq!(resp.authorities[0].name.to_ascii(), "127.in-addr.arpa.");
    }

    #[test]
    fn reserved_domains_return_nxdomain() {
        let q1 = make_query("test.invalid.", RecordType::A);
        let resp1 = match_special_use_domain(&q1, "test.invalid", RecordType::A).expect("match");
        assert_eq!(resp1.metadata.response_code, ResponseCode::NXDomain);

        let q2 = make_query("mydevice.home.arpa.", RecordType::A);
        let resp2 =
            match_special_use_domain(&q2, "mydevice.home.arpa", RecordType::A).expect("match");
        assert_eq!(resp2.metadata.response_code, ResponseCode::NXDomain);
    }

    #[test]
    fn public_domain_returns_none() {
        let q = make_query("google.com.", RecordType::A);
        assert!(match_special_use_domain(&q, "google.com", RecordType::A).is_none());
    }

    #[test]
    fn home_arpa_apex_is_nodata_and_below_is_nxdomain() {
        let apex = make_query("home.arpa.", RecordType::A);
        let resp = match_special_use_domain(&apex, "home.arpa", RecordType::A).expect("match");
        assert_eq!(resp.metadata.response_code, ResponseCode::NoError);
        assert!(resp.answers.is_empty(), "apex is NODATA, not NXDOMAIN");

        let below = make_query("printer.home.arpa.", RecordType::A);
        let resp =
            match_special_use_domain(&below, "printer.home.arpa", RecordType::A).expect("match");
        assert_eq!(resp.metadata.response_code, ResponseCode::NXDomain);
    }

    #[test]
    fn resolver_arpa_is_nodata_throughout_and_never_forwarded() {
        for (name, qtype) in [
            ("_dns.resolver.arpa", RecordType::SVCB),
            ("_dns.resolver.arpa", RecordType::A),
            ("resolver.arpa", RecordType::SOA),
            ("deep.below.resolver.arpa", RecordType::AAAA),
        ] {
            assert_eq!(
                classify_special_use_with(name, false),
                Some(SpecialUseKind::NoData),
                "{name}"
            );
            let query = make_query(&format!("{name}."), qtype);
            let resp = match_special_use_domain(&query, name, qtype).expect("match");
            assert_eq!(resp.metadata.response_code, ResponseCode::NoError, "{name}");
            assert!(resp.answers.is_empty(), "{name}");
            let soa = resp
                .authorities
                .iter()
                .find(|record| record.record_type() == RecordType::SOA)
                .expect("NODATA authority SOA");
            assert_eq!(soa.name.to_utf8().to_lowercase(), "resolver.arpa.");
        }
        assert!(classify_special_use("resolver.arpa.example.com").is_none());
        assert!(classify_special_use("myresolver.arpa").is_none());
    }

    #[test]
    fn negatives_carry_an_soa_for_negative_caching() {
        let nxdomain = make_query("missing.test.", RecordType::A);
        let resp =
            match_special_use_domain(&nxdomain, "missing.test", RecordType::A).expect("match");
        assert_eq!(resp.metadata.response_code, ResponseCode::NXDomain);
        let soa = resp
            .authorities
            .iter()
            .find(|record| record.record_type() == RecordType::SOA)
            .expect("NXDOMAIN authority SOA");
        assert_eq!(soa.name.to_utf8().to_lowercase(), "test.");

        // NODATA inside a locally-served zone carries its zone's SOA too.
        let nodata = make_query("localhost.", RecordType::TXT);
        let resp = match_special_use_domain(&nodata, "localhost", RecordType::TXT).expect("match");
        assert_eq!(resp.metadata.response_code, ResponseCode::NoError);
        assert_eq!(resp.answers, []);
        assert!(resp
            .authorities
            .iter()
            .any(|record| record.record_type() == RecordType::SOA));

        // A positive answer must not pretend to be a negative.
        let positive = make_query("localhost.", RecordType::A);
        let resp = match_special_use_domain(&positive, "localhost", RecordType::A).expect("match");
        assert_eq!(resp.answers.len(), 1);
        assert_eq!(resp.authorities, []);
    }

    #[test]
    fn synthesized_responses_echo_client_edns() {
        let mut edns = Edns::new();
        edns.set_dnssec_ok(true);
        edns.set_max_payload(1232);

        let mut q = make_query("localhost.", RecordType::A);
        q.edns = Some(edns);
        let kind = classify_special_use("localhost").expect("kind");
        let resp = synthesize_special_use(
            &q.metadata,
            &q.queries[0],
            q.edns.as_ref(),
            kind,
            RecordType::A,
        );
        let echoed = resp.edns.as_ref().expect("client OPT is echoed");
        assert!(echoed.flags().dnssec_ok);
        assert_eq!(echoed.max_payload(), 1232);

        // RFC 6891: never hand an OPT to a client that sent none.
        let plain = make_query("localhost.", RecordType::A);
        let resp = synthesize_special_use(
            &plain.metadata,
            &plain.queries[0],
            plain.edns.as_ref(),
            kind,
            RecordType::A,
        );
        assert!(resp.edns.is_none());
    }

    #[test]
    fn synthesize_echoes_the_original_question() {
        let q = make_query("Foo.Localhost.", RecordType::A);
        let kind = classify_special_use("foo.localhost").expect("kind");
        let resp = synthesize_special_use(
            &q.metadata,
            &q.queries[0],
            q.edns.as_ref(),
            kind,
            RecordType::A,
        );
        assert_eq!(resp.metadata.id, 0x1234);
        assert_eq!(resp.queries[0].name(), q.queries[0].name());
    }
}
