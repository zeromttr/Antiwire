//! Addresses a DNS answer gives for the name that was asked about.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::Arc;

use hickory_proto::op::Message;
use hickory_proto::rr::{Name, RData, Record};

/// The addresses an answer gives for the name asked about, and how long they
/// are good for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AnswerHint {
    /// A/AAAA addresses owned by the queried name. Shared, so a hint kept for
    /// many hits is handed out without copying it.
    pub(crate) addresses: Arc<[IpAddr]>,
    /// The shortest of their TTLs, in milliseconds, and at least one second.
    pub(crate) ttl_ms: u64,
}

/// A/AAAA addresses owned by the queried name, and the shortest of their TTLs.
/// `None` when the answer carries no such address.
///
/// Addresses are collected from the answer and additional sections, but only
/// for the question name and the targets of its CNAME chain. The additional
/// section can hold an answer that parks the address there, but it usually
/// carries glue and target-host addresses (NS, MX, SRV hosts) that belong to
/// *other* names and must not be attributed to this one.
pub(crate) fn answered_addresses(
    message: &Message,
    answers: &[Record],
    additionals: &[Record],
) -> Option<AnswerHint> {
    let owned = owned_addresses(message, answers, additionals);
    let min_ttl = owned.iter().map(|(_, ttl)| *ttl).min()?;
    Some(AnswerHint {
        addresses: owned.into_iter().map(|(ip, _)| ip).collect(),
        ttl_ms: u64::from(min_ttl).saturating_mul(1_000).max(1_000),
    })
}

/// Owned addresses with their record TTLs.
fn owned_addresses(
    message: &Message,
    answers: &[Record],
    additionals: &[Record],
) -> Vec<(IpAddr, u32)> {
    let Some(query) = message.queries.first() else {
        return Vec::new();
    };
    let records = || answers.iter().chain(additionals.iter());
    // Most answers attributed here have no address at all (NXDOMAIN, TXT,
    // HTTPS) or no CNAME chain to walk. Neither needs the allocations below.
    if !records().any(|record| ip_from_rdata(&record.data).is_some()) {
        return Vec::new();
    }
    if !records().any(|record| matches!(record.data, RData::CNAME(_))) {
        return records()
            .filter(|record| same_name(&record.name, &query.name))
            .filter_map(|record| ip_from_rdata(&record.data).map(|ip| (ip, record.ttl)))
            .collect();
    }

    // Index every CNAME by owner once, then walk from the question name with a
    // visited set. Rescanning all records on every hop would make a response
    // whose CNAMEs are ordered reverse to the chain cost O(n^3) on an
    // attacker-controlled message. Identity is case- and FQDN-insensitive.
    let mut cname_targets: HashMap<Vec<Vec<u8>>, Vec<Vec<u8>>> = HashMap::new();
    for record in records() {
        if let RData::CNAME(target) = &record.data {
            cname_targets
                .entry(name_identity(&record.name))
                .or_insert_with(|| name_identity(&target.0));
        }
    }

    let mut owners: HashSet<Vec<Vec<u8>>> = HashSet::new();
    let mut current = name_identity(&query.name);
    while owners.insert(current.clone()) {
        let Some(target) = cname_targets.get(&current) else {
            break;
        };
        current = target.clone();
    }

    records()
        .filter(|record| owners.contains(&name_identity(&record.name)))
        .filter_map(|record| ip_from_rdata(&record.data).map(|ip| (ip, record.ttl)))
        .collect()
}

/// Case-insensitive label identity that ignores FQDN-ness, which `Name`'s own
/// `Hash`/`PartialEq` do not.
fn name_identity(name: &Name) -> Vec<Vec<u8>> {
    name.iter().map(<[u8]>::to_ascii_lowercase).collect()
}

/// [`name_identity`] equality without building either identity.
fn same_name(left: &Name, right: &Name) -> bool {
    left.num_labels() == right.num_labels()
        && left
            .iter()
            .zip(right.iter())
            .all(|(left, right)| left.eq_ignore_ascii_case(right))
}

fn ip_from_rdata(data: &RData) -> Option<IpAddr> {
    match data {
        RData::A(addr) => Some(IpAddr::V4(addr.0)),
        RData::AAAA(addr) => Some(IpAddr::V6(addr.0)),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use hickory_proto::op::{MessageType, OpCode, Query, ResponseCode};
    use hickory_proto::rr::{rdata, RecordType};

    use super::*;

    fn response_for(domain: &str, qtype: RecordType) -> Message {
        let name = Name::from_ascii(format!("{domain}.")).expect("name");
        let mut message = Message::new(0, MessageType::Response, OpCode::Query);
        message.metadata.response_code = ResponseCode::NoError;
        message.add_query(Query::query(name, qtype));
        message
    }

    fn a_record(name: &str, ip: Ipv4Addr) -> Record {
        Record::from_rdata(
            Name::from_ascii(name).expect("name"),
            60,
            RData::A(rdata::A(ip)),
        )
    }

    fn cname_record(name: &str, target: &str) -> Record {
        Record::from_rdata(
            Name::from_ascii(name).expect("name"),
            60,
            RData::CNAME(rdata::CNAME(Name::from_ascii(target).expect("target"))),
        )
    }

    fn addresses(message: &Message) -> Vec<IpAddr> {
        answered_addresses(message, &message.answers, &message.additionals)
            .map(|hint| hint.addresses.to_vec())
            .unwrap_or_default()
    }

    #[test]
    fn aaaa_in_the_additional_section_counts() {
        let mut message = response_for("ipv6.example.test", RecordType::AAAA);
        let address = Ipv6Addr::new(0x2606, 0x2800, 0x220, 0x1, 0x248, 0x1893, 0x25c8, 0x1946);
        message.add_additional(Record::from_rdata(
            Name::from_ascii("ipv6.example.test.").expect("name"),
            60,
            RData::AAAA(rdata::AAAA(address)),
        ));
        assert_eq!(addresses(&message), vec![IpAddr::V6(address)]);
    }

    /// Glue for another host must not shorten the queried name's hint TTL.
    #[test]
    fn ttl_comes_only_from_addresses_owned_by_the_queried_name() {
        let mut message = response_for("example.test", RecordType::A);
        message.add_answer(Record::from_rdata(
            Name::from_ascii("example.test.").expect("name"),
            300,
            RData::A(rdata::A(Ipv4Addr::new(192, 0, 2, 1))),
        ));
        message.add_additional(Record::from_rdata(
            Name::from_ascii("ns1.provider.test.").expect("name"),
            5,
            RData::A(rdata::A(Ipv4Addr::new(203, 0, 113, 53))),
        ));
        let hint =
            answered_addresses(&message, &message.answers, &message.additionals).expect("hint");
        assert_eq!(*hint.addresses, [IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))]);
        assert_eq!(hint.ttl_ms, 300_000);
    }

    #[test]
    fn only_addresses_owned_by_the_queried_name_count() {
        // MX lookup: the answer names another host whose address arrives as
        // glue in the additional section. That address is the mail host's,
        // not example.test's.
        let mut mx = response_for("example.test", RecordType::MX);
        mx.add_answer(Record::from_rdata(
            Name::from_ascii("example.test.").expect("name"),
            60,
            RData::MX(rdata::MX::new(
                10,
                Name::from_ascii("mail.provider.test.").expect("mx"),
            )),
        ));
        mx.add_additional(a_record(
            "mail.provider.test.",
            Ipv4Addr::new(198, 51, 100, 9),
        ));
        assert_eq!(addresses(&mx), [] as [IpAddr; 0]);

        // Referral glue for the zone's name servers is likewise not the
        // queried name's address.
        let mut glue = response_for("example.test", RecordType::A);
        glue.add_answer(a_record("example.test.", Ipv4Addr::new(192, 0, 2, 1)));
        glue.add_additional(a_record(
            "ns1.provider.test.",
            Ipv4Addr::new(203, 0, 113, 53),
        ));
        assert_eq!(
            addresses(&glue),
            vec![IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))]
        );

        // Case and FQDN-ness of the owner name do not matter.
        let mut cased = response_for("example.test", RecordType::A);
        cased.add_answer(a_record("EXAMPLE.Test", Ipv4Addr::new(192, 0, 2, 2)));
        assert_eq!(
            addresses(&cased),
            vec![IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2))]
        );
    }

    #[test]
    fn cname_chain_targets_are_attributed_to_the_queried_name() {
        let mut message = response_for("www.example.test", RecordType::A);
        message.add_answer(cname_record("www.example.test.", "edge.cdn.test."));
        message.add_answer(cname_record("edge.cdn.test.", "pop3.cdn.test."));
        message.add_answer(a_record("pop3.cdn.test.", Ipv4Addr::new(192, 0, 2, 80)));
        // An unrelated record in the same section stays out.
        message.add_answer(a_record("other.cdn.test.", Ipv4Addr::new(192, 0, 2, 81)));

        assert_eq!(
            addresses(&message),
            vec![IpAddr::V4(Ipv4Addr::new(192, 0, 2, 80))]
        );

        // A CNAME loop terminates and yields nothing.
        let mut looped = response_for("a.test", RecordType::A);
        looped.add_answer(cname_record("a.test.", "b.test."));
        looped.add_answer(cname_record("b.test.", "a.test."));
        assert_eq!(addresses(&looped), [] as [IpAddr; 0]);
    }

    #[test]
    fn cname_chain_is_followed_regardless_of_record_order() {
        // Records are listed from the far end of the chain back toward the
        // question name, which is the worst case for a single-pass scan.
        let mut message = response_for("start.test", RecordType::A);
        message.add_answer(cname_record("d.test.", "answer.test."));
        message.add_answer(cname_record("c.test.", "d.test."));
        message.add_answer(cname_record("b.test.", "c.test."));
        message.add_answer(cname_record("start.test.", "b.test."));
        message.add_answer(a_record("answer.test.", Ipv4Addr::new(192, 0, 2, 90)));

        assert_eq!(
            addresses(&message),
            vec![IpAddr::V4(Ipv4Addr::new(192, 0, 2, 90))]
        );
    }

    #[test]
    fn names_match_without_regard_to_case_or_the_root_label() {
        let mut message = response_for("Mixed.Example.test", RecordType::A);
        message.add_answer(a_record("mixed.EXAMPLE.test", Ipv4Addr::new(192, 0, 2, 7)));
        message.add_answer(a_record(
            "mixed.example.test.other.",
            Ipv4Addr::new(192, 0, 2, 8),
        ));
        assert_eq!(
            addresses(&message),
            vec![IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7))]
        );
    }

    #[test]
    fn an_answer_without_addresses_gives_no_hint() {
        let mut message = response_for("alias.example.test", RecordType::A);
        message.add_answer(cname_record("alias.example.test.", "target.example.test."));
        assert!(answered_addresses(&message, &message.answers, &message.additionals).is_none());
    }
}
