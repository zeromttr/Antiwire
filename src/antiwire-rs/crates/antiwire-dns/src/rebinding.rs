//! DNS rebinding detection on upstream wire-format responses.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use ipnet::{Ipv4Net, Ipv6Net};

use hickory_proto::op::Message;
use hickory_proto::rr::rdata::svcb::SvcParamValue;
use hickory_proto::rr::rdata::{NULL, SVCB};
use hickory_proto::rr::{Name, RData, RecordType};
use hickory_proto::serialize::binary::{BinDecodable, BinDecoder};

use crate::special_use::answers_with_loopback;

/// What makes an upstream answer resolve a public name into the local network.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RebindingTarget {
    /// A loopback, private, or link-local address.
    Address(IpAddr),
    /// An alias or service target that this resolver answers itself with a
    /// loopback address. The client's follow-up query for it never reaches an
    /// upstream, so no address check would see it.
    LoopbackName(Name),
}

impl fmt::Display for RebindingTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Address(ip) => ip.fmt(f),
            Self::LoopbackName(name) => write!(f, "alias to {name}"),
        }
    }
}

/// Returns true when answer or additional records carry loopback, private, or link-local addresses.
#[cfg(test)]
#[must_use]
pub(crate) fn contains_rebinding_address(response: &[u8]) -> bool {
    find_rebinding_address(response).is_some()
}

/// Returns the first rebinding target found in answer or additional records.
#[cfg(test)]
#[must_use]
pub(crate) fn find_rebinding_address(response: &[u8]) -> Option<RebindingTarget> {
    Message::from_vec(response)
        .ok()
        .and_then(|message| message_find_rebinding_address(&message))
}

/// Test-only convenience wrapper around [`message_find_rebinding_address`].
#[cfg(test)]
#[must_use]
pub(crate) fn message_contains_rebinding_address(message: &Message) -> bool {
    message_find_rebinding_address(message).is_some()
}

/// Returns the first rebinding target in parsed answer or additional records.
#[must_use]
pub(crate) fn message_find_rebinding_address(message: &Message) -> Option<RebindingTarget> {
    message
        .answers
        .iter()
        .chain(message.additionals.iter())
        .find_map(|record| rdata_find_rebinding_target(&record.data))
}

fn rdata_find_rebinding_target(rdata: &RData) -> Option<RebindingTarget> {
    match rdata {
        RData::A(addr) => address_target(IpAddr::V4(**addr)),
        RData::AAAA(addr) => address_target(IpAddr::V6(**addr)),
        RData::CNAME(cname) => loopback_name_target(&cname.0),
        RData::SVCB(svcb) => svcb_find_rebinding_target(svcb),
        RData::HTTPS(https) => svcb_find_rebinding_target(&https.0),
        RData::Unknown {
            code: RecordType::DNAME,
            rdata,
        } => dname_target(rdata).and_then(|target| loopback_name_target(&target)),
        _ => None,
    }
}

fn address_target(ip: IpAddr) -> Option<RebindingTarget> {
    is_rebinding_target(ip).then_some(RebindingTarget::Address(ip))
}

fn loopback_name_target(name: &Name) -> Option<RebindingTarget> {
    answers_with_loopback(name).then(|| RebindingTarget::LoopbackName(name.clone()))
}

/// The target of a DNAME, which hickory does not decode. RFC 6672 §2.5 forbids
/// compressing it, so the RDATA is a complete name on its own.
fn dname_target(rdata: &NULL) -> Option<Name> {
    let mut decoder = BinDecoder::new(&rdata.anything);
    let name = Name::read(&mut decoder).ok()?;
    decoder.is_empty().then_some(name)
}

/// Checks an SVCB or HTTPS record's target name, which the client resolves
/// for addresses in both `AliasMode` and `ServiceMode`, then its address hints.
fn svcb_find_rebinding_target(svcb: &SVCB) -> Option<RebindingTarget> {
    if let Some(target) = loopback_name_target(&svcb.target_name) {
        return Some(target);
    }
    svcb.svc_params.iter().find_map(|(_, value)| match value {
        SvcParamValue::Ipv4Hint(hints) => hints
            .0
            .iter()
            .find_map(|addr| address_target(IpAddr::V4(**addr))),
        SvcParamValue::Ipv6Hint(hints) => hints
            .0
            .iter()
            .find_map(|addr| address_target(IpAddr::V6(**addr))),
        _ => None,
    })
}

/// IPv4 networks a public name must not resolve into: "this network",
/// RFC 1918, CGNAT, loopback, and link-local.
const REBINDING_V4: [Ipv4Net; 7] = [
    Ipv4Net::new_assert(Ipv4Addr::UNSPECIFIED, 8),
    Ipv4Net::new_assert(Ipv4Addr::new(10, 0, 0, 0), 8),
    Ipv4Net::new_assert(Ipv4Addr::new(100, 64, 0, 0), 10),
    Ipv4Net::new_assert(Ipv4Addr::new(127, 0, 0, 0), 8),
    Ipv4Net::new_assert(Ipv4Addr::new(169, 254, 0, 0), 16),
    Ipv4Net::new_assert(Ipv4Addr::new(172, 16, 0, 0), 12),
    Ipv4Net::new_assert(Ipv4Addr::new(192, 168, 0, 0), 16),
];

/// IPv6 networks a public name must not resolve into: unspecified,
/// loopback, link-local, legacy site-local, and unique local.
const REBINDING_V6: [Ipv6Net; 5] = [
    Ipv6Net::new_assert(Ipv6Addr::UNSPECIFIED, 128),
    Ipv6Net::new_assert(Ipv6Addr::LOCALHOST, 128),
    Ipv6Net::new_assert(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0), 10),
    Ipv6Net::new_assert(Ipv6Addr::new(0xfec0, 0, 0, 0, 0, 0, 0, 0), 10),
    Ipv6Net::new_assert(Ipv6Addr::new(0xfc00, 0, 0, 0, 0, 0, 0, 0), 7),
];

/// IPv6 prefixes that carry an IPv4 address in their low 32 bits, which is
/// judged as that address: IPv4-mapped, IPv4-compatible (deprecated), the
/// NAT64 well-known prefix (RFC 6052), and the local-use NAT64 prefix
/// (RFC 8215) in its usual /96 layout.
const EMBEDDED_V4: [Ipv6Net; 4] = [
    Ipv6Net::new_assert(Ipv6Addr::new(0, 0, 0, 0, 0, 0xffff, 0, 0), 96),
    Ipv6Net::new_assert(Ipv6Addr::UNSPECIFIED, 96),
    Ipv6Net::new_assert(Ipv6Addr::new(0x64, 0xff9b, 0, 0, 0, 0, 0, 0), 96),
    Ipv6Net::new_assert(Ipv6Addr::new(0x64, 0xff9b, 1, 0, 0, 0, 0, 0), 48),
];

/// Returns true for loopback, unspecified, link-local, RFC1918, CGNAT, and ULA targets.
#[must_use]
pub(crate) fn is_rebinding_target(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(addr) => is_rebinding_ipv4(addr),
        IpAddr::V6(addr) => {
            REBINDING_V6.iter().any(|net| net.contains(&addr))
                || EMBEDDED_V4.iter().any(|net| net.contains(&addr)) && {
                    let [.., a, b, c, d] = addr.octets();
                    is_rebinding_ipv4(Ipv4Addr::new(a, b, c, d))
                }
        }
    }
}

fn is_rebinding_ipv4(addr: Ipv4Addr) -> bool {
    REBINDING_V4.iter().any(|net| net.contains(&addr))
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::op::Message;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn message_and_wire_parsers_agree() {
        let private_v4 = build_service_binding_hint_response(65, 4, &[192, 0, 2, 1, 10, 1, 2, 3]);
        let message = Message::from_vec(&private_v4).expect("message");
        assert!(contains_rebinding_address(&private_v4));
        assert!(message_contains_rebinding_address(&message));
        assert_eq!(
            find_rebinding_address(&private_v4),
            message_find_rebinding_address(&message)
        );
    }

    #[test]
    fn rebinding_target_detects_private_and_loopback() {
        assert!(is_rebinding_target(IpAddr::V4(Ipv4Addr::LOCALHOST)));
        assert!(is_rebinding_target(IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3))));
        assert!(is_rebinding_target(IpAddr::V4(Ipv4Addr::new(
            192, 168, 1, 1
        ))));
        assert!(is_rebinding_target(IpAddr::V4(Ipv4Addr::new(
            169, 254, 1, 1
        ))));
        assert!(!is_rebinding_target(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))));
        assert!(!is_rebinding_target(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))));
    }

    #[test]
    fn rebinding_target_detects_ipv6_ula() {
        assert!(is_rebinding_target(IpAddr::V6(Ipv6Addr::new(
            0xfc00, 0, 0, 0, 0, 0, 0, 1
        ))));
    }

    /// The regression this guards: a NAT64 address embedding a private IPv4
    /// passed the filter.
    #[test]
    fn rebinding_target_detects_nat64_embedded_private_ipv4() {
        let nat64 = |a, b| Ipv6Addr::new(0x0064, 0xff9b, 0, 0, 0, 0, a, b);
        assert!(is_rebinding_target(IpAddr::V6(nat64(0xc0a8, 0x0101))));
        assert!(is_rebinding_target(IpAddr::V6(nat64(0x7f00, 0x0001))));
        assert!(!is_rebinding_target(IpAddr::V6(nat64(0x0808, 0x0808))));
    }

    /// RFC 8215's local-use NAT64 prefix `64:ff9b:1::/48` translates the same
    /// way as the well-known one; with the usual /96 layout the IPv4 address
    /// is the low 32 bits.
    #[test]
    fn rebinding_target_detects_local_use_nat64_embedded_private_ipv4() {
        let nat64 = |a, b| Ipv6Addr::new(0x0064, 0xff9b, 0x0001, 0, 0, 0, a, b);
        assert!(is_rebinding_target(IpAddr::V6(nat64(0x7f00, 0x0001))));
        assert!(is_rebinding_target(IpAddr::V6(nat64(0x0a00, 0x0005))));
        assert!(!is_rebinding_target(IpAddr::V6(nat64(0x0808, 0x0808))));
    }

    /// The regression this guards: an IPv4-compatible address (`::a.b.c.d`)
    /// embedding a private IPv4 passed the filter. `::` and `::1` keep their result.
    #[test]
    fn rebinding_target_detects_ipv4_compatible_embedded_private_ipv4() {
        let compat = |a, b| Ipv6Addr::new(0, 0, 0, 0, 0, 0, a, b);
        assert!(is_rebinding_target(IpAddr::V6(compat(0xc0a8, 0x0101))));
        assert!(is_rebinding_target(IpAddr::V6(compat(0x0a00, 0x0001))));
        assert!(!is_rebinding_target(IpAddr::V6(compat(0x0808, 0x0808))));
        assert!(is_rebinding_target(IpAddr::V6(Ipv6Addr::UNSPECIFIED)));
        assert!(is_rebinding_target(IpAddr::V6(Ipv6Addr::LOCALHOST)));
    }

    #[test]
    fn rebinding_address_inspects_additional_records() {
        let mut public = build_a_response("example.com", [93, 184, 216, 34]);
        append_additional_a(&mut public, [93, 184, 216, 34]);
        assert!(!contains_rebinding_address(&public));

        let mut private = public.clone();
        let len = private.len();
        private[len - 4] = 10;
        private[len - 3] = 1;
        private[len - 2] = 2;
        private[len - 1] = 3;
        assert!(contains_rebinding_address(&private));
    }

    #[test]
    fn rebinding_address_inspects_svcb_hints() {
        let public = build_service_binding_hint_response(65, 4, &[192, 0, 2, 1]);
        assert!(!contains_rebinding_address(&public));

        let private_v4 = build_service_binding_hint_response(65, 4, &[192, 0, 2, 1, 10, 1, 2, 3]);
        assert!(contains_rebinding_address(&private_v4));

        let private_v6 = build_service_binding_hint_response(
            64,
            6,
            &[0xfc, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
        );
        assert!(contains_rebinding_address(&private_v6));
    }

    /// The same NAT64 case through an SVCB `ipv6hint` on the wire path.
    #[test]
    fn rebinding_address_inspects_nat64_svcb_hint() {
        let nat64_private = build_service_binding_hint_response(
            64,
            6,
            &[
                0x00, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0, 0xc0, 0xa8, 0x01, 0x01,
            ],
        );
        assert!(contains_rebinding_address(&nat64_private));
    }

    /// A NOERROR answer for `example.com.` holding only `answer`, sent through
    /// the wire format so it parses the way an upstream reply does.
    fn wire_answer(answer: RData) -> Vec<u8> {
        use hickory_proto::op::{OpCode, Query};
        use hickory_proto::rr::Record;

        let owner = Name::from_ascii("example.com.").expect("owner");
        let mut message = Message::response(0xABCD, OpCode::Query);
        message.add_query(Query::query(owner.clone(), RecordType::A));
        message.add_answer(Record::from_rdata(owner, 30, answer));
        message.to_vec().expect("encode")
    }

    fn name(ascii: &str) -> Name {
        Name::from_ascii(ascii).expect("name")
    }

    fn cname(target: &str) -> RData {
        RData::CNAME(hickory_proto::rr::rdata::CNAME(name(target)))
    }

    fn dname(target: &str) -> RData {
        use hickory_proto::serialize::binary::{BinEncodable, BinEncoder};

        let mut bytes = Vec::new();
        name(target)
            .emit(&mut BinEncoder::new(&mut bytes))
            .expect("target");
        RData::Unknown {
            code: RecordType::DNAME,
            rdata: NULL::with(bytes),
        }
    }

    fn https(priority: u16, target: &str, params: Vec<(SvcParamKey, SvcParamValue)>) -> RData {
        RData::HTTPS(hickory_proto::rr::rdata::HTTPS(SVCB::new(
            priority,
            name(target),
            params,
        )))
    }

    use hickory_proto::rr::rdata::svcb::{IpHint, SvcParamKey};

    /// The regression this guards: a public name aliased to `localhost` with
    /// no address passed, and the client's follow-up query for the target was
    /// answered locally with a loopback address.
    #[test]
    fn an_alias_to_a_name_answered_as_loopback_is_a_rebinding_target() {
        for target in [
            "localhost.",
            "app.localhost.",
            "LocalHost.",
            "a.b.LOCALHOST.",
        ] {
            let found = find_rebinding_address(&wire_answer(cname(target)));
            assert_eq!(
                found,
                Some(RebindingTarget::LoopbackName(name(target))),
                "CNAME {target}"
            );
        }
        assert!(contains_rebinding_address(&wire_answer(dname(
            "localhost."
        ))));
        assert!(contains_rebinding_address(&wire_answer(dname(
            "x.localhost."
        ))));
    }

    #[test]
    fn an_alias_to_any_other_name_is_not() {
        for target in [
            "cdn.example.net.",
            "localhost.example.net.",
            "notlocalhost.",
        ] {
            assert!(
                !contains_rebinding_address(&wire_answer(cname(target))),
                "CNAME {target}"
            );
            assert!(
                !contains_rebinding_address(&wire_answer(dname(target))),
                "DNAME {target}"
            );
        }
    }

    /// The client resolves an SVCB/HTTPS target for addresses in `AliasMode` and
    /// in `ServiceMode` alike.
    #[test]
    fn a_service_binding_target_answered_as_loopback_is_a_rebinding_target() {
        assert!(contains_rebinding_address(&wire_answer(https(
            0,
            "localhost.",
            Vec::new()
        ))));
        assert!(contains_rebinding_address(&wire_answer(https(
            1,
            "svc.localhost.",
            Vec::new()
        ))));
        let public_hint = vec![(
            SvcParamKey::Ipv4Hint,
            SvcParamValue::Ipv4Hint(IpHint(vec![hickory_proto::rr::rdata::A(Ipv4Addr::new(
                192, 0, 2, 1,
            ))])),
        )];
        assert!(!contains_rebinding_address(&wire_answer(https(
            1,
            ".",
            public_hint.clone()
        ))));
        assert!(!contains_rebinding_address(&wire_answer(https(
            1,
            "svc.example.net.",
            public_hint
        ))));
    }

    fn build_a_response(domain: &str, ipv4: [u8; 4]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&[0xAB, 0xCD, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0]);
        encode_name(domain, &mut out);
        out.extend_from_slice(&[0, 1, 0, 1]);
        encode_name(domain, &mut out);
        out.extend_from_slice(&[0, 1, 0, 1, 0, 0, 0, 30, 0, 4]);
        out.extend_from_slice(&ipv4);
        out
    }

    fn append_additional_a(packet: &mut Vec<u8>, ipv4: [u8; 4]) {
        let arcount = u16::from_be_bytes([packet[10], packet[11]]);
        packet[10] = ((arcount + 1) >> 8) as u8;
        packet[11] = ((arcount + 1) & 0xFF) as u8;
        encode_name("extra.example", packet);
        packet.extend_from_slice(&[0, 1, 0, 1, 0, 0, 0, 30, 0, 4]);
        packet.extend_from_slice(&ipv4);
    }

    #[expect(
        clippy::cast_possible_truncation,
        reason = "DNS wire fields are byte-wise by definition; each cast writes the low byte of a length or type field"
    )]
    fn build_service_binding_hint_response(
        record_type: u16,
        parameter_key: u16,
        hint_bytes: &[u8],
    ) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&[0xAB, 0xCD, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0]);
        encode_name("example.com", &mut out);
        out.extend_from_slice(&[0, 1, 0, 1]);
        encode_name("example.com", &mut out);
        let mut rdata = Vec::new();
        rdata.extend_from_slice(&[0, 1]);
        rdata.push(0);
        rdata.extend_from_slice(&[
            (parameter_key >> 8) as u8,
            (parameter_key & 0xFF) as u8,
            (hint_bytes.len() >> 8) as u8,
            (hint_bytes.len() & 0xFF) as u8,
        ]);
        rdata.extend_from_slice(hint_bytes);
        out.extend_from_slice(&[
            (record_type >> 8) as u8,
            (record_type & 0xFF) as u8,
            0,
            1,
            0,
            0,
            0,
            30,
            (rdata.len() >> 8) as u8,
            (rdata.len() & 0xFF) as u8,
        ]);
        out.extend_from_slice(&rdata);
        out
    }

    #[expect(
        clippy::cast_possible_truncation,
        reason = "DNS labels are at most 63 bytes, so the length byte cannot truncate"
    )]
    fn encode_name(domain: &str, out: &mut Vec<u8>) {
        if domain.is_empty() {
            out.push(0);
            return;
        }
        for label in domain.split('.') {
            let label = label.as_bytes();
            out.push(label.len() as u8);
            out.extend_from_slice(label);
        }
        out.push(0);
    }
}
