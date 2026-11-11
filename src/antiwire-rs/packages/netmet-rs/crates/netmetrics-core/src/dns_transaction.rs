#![allow(missing_docs)]

use crate::{canonicalize_ip, locate_transport};
use hickory_proto::op::{Header, MessageType, Query};
use hickory_proto::rr::{DNSClass, Name, RData, Record};
use hickory_proto::serialize::binary::{BinDecodable, BinDecoder};
use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;

const DNS_PORT: u16 = 53;
const QUERY_TIMEOUT_MS: u64 = 10_000;

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct TransactionKey {
    id: u16,
    client_addr: IpAddr,
    client_port: u16,
    server_addr: IpAddr,
    question: String,
    qtype: u16,
    qclass: u16,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DnsPacket {
    pub source_addr: IpAddr,
    pub source_port: u16,
    pub destination_addr: IpAddr,
    pub destination_port: u16,
    pub id: u16,
    pub is_response: bool,
    pub opcode: u8,
    pub rcode: u8,
    pub question: String,
    pub qtype: u16,
    pub qclass: u16,
    pub answers: Vec<IpAddr>,
    pub ttl_ms: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CorrelatedDnsResponse {
    pub pid: u32,
    pub query: String,
    pub answers: Vec<IpAddr>,
    pub ttl_ms: u64,
}

#[derive(Clone, Copy, Debug)]
struct PendingQuery {
    pid: u32,
    expires_at: u64,
    generation: u64,
}

#[derive(Debug)]
pub struct DnsTransactionTracker {
    pending: HashMap<TransactionKey, PendingQuery>,
    expirations: VecDeque<(u64, u64, TransactionKey)>,
    max_pending: usize,
    generation: u64,
}

impl DnsTransactionTracker {
    pub fn new(max_flows: usize) -> Self {
        Self {
            pending: HashMap::new(),
            expirations: VecDeque::new(),
            max_pending: max_flows.clamp(1, 8_192),
            generation: 0,
        }
    }

    pub fn observe(
        &mut self,
        packet: DnsPacket,
        query_pid: u32,
        now: u64,
    ) -> Option<CorrelatedDnsResponse> {
        self.expire(now);
        if packet.opcode != 0 || packet.qclass == 0 || packet.question.is_empty() {
            return None;
        }
        let key = packet.transaction_key()?;
        if !packet.is_response {
            if packet.destination_port != DNS_PORT || packet.rcode != 0 {
                return None;
            }
            if self.pending.len() >= self.max_pending && !self.pending.contains_key(&key) {
                self.evict_oldest();
            }
            self.generation = self.generation.wrapping_add(1);
            let query = PendingQuery {
                pid: query_pid,
                expires_at: now.saturating_add(QUERY_TIMEOUT_MS),
                generation: self.generation,
            };
            self.pending.insert(key.clone(), query);
            self.expirations
                .push_back((query.expires_at, query.generation, key));
            return None;
        }
        if packet.source_port != DNS_PORT || packet.rcode != 0 || packet.answers.is_empty() {
            return None;
        }
        let query = self.pending.remove(&key)?;
        Some(CorrelatedDnsResponse {
            pid: query.pid,
            query: packet.question,
            answers: packet.answers,
            ttl_ms: packet.ttl_ms,
        })
    }

    fn expire(&mut self, now: u64) {
        while self
            .expirations
            .front()
            .is_some_and(|(expires_at, _, _)| *expires_at <= now)
        {
            let (_, generation, key) = self.expirations.pop_front().expect("front exists");
            if self
                .pending
                .get(&key)
                .is_some_and(|entry| entry.generation == generation)
            {
                self.pending.remove(&key);
            }
        }
    }

    fn evict_oldest(&mut self) {
        while let Some((_, generation, key)) = self.expirations.pop_front() {
            if self
                .pending
                .get(&key)
                .is_some_and(|entry| entry.generation == generation)
            {
                self.pending.remove(&key);
                break;
            }
        }
    }
}

impl DnsPacket {
    fn transaction_key(&self) -> Option<TransactionKey> {
        let (client_addr, client_port, server_addr) = if self.is_response {
            if self.source_port != DNS_PORT {
                return None;
            }
            (
                self.destination_addr,
                self.destination_port,
                self.source_addr,
            )
        } else {
            if self.destination_port != DNS_PORT {
                return None;
            }
            (self.source_addr, self.source_port, self.destination_addr)
        };
        Some(TransactionKey {
            id: self.id,
            client_addr,
            client_port,
            server_addr,
            question: self.question.clone(),
            qtype: self.qtype,
            qclass: self.qclass,
        })
    }
}

#[derive(Debug)]
struct AnswerRecord {
    owner: String,
    ttl_ms: u64,
    value: AnswerValue,
}

#[derive(Debug)]
enum AnswerValue {
    Address(IpAddr),
    Cname(String),
}

pub fn parse_dns_packet(packet: &[u8]) -> Option<DnsPacket> {
    let transport = locate_transport(packet)?;
    if transport.protocol != 17 {
        return None;
    }
    let udp = packet.get(transport.offset..transport.total_len)?;
    if udp.len() < 8 {
        return None;
    }
    let source_port = u16::from_be_bytes(udp[0..2].try_into().ok()?);
    let destination_port = u16::from_be_bytes(udp[2..4].try_into().ok()?);
    if source_port != DNS_PORT && destination_port != DNS_PORT {
        return None;
    }
    let payload = udp.get(8..)?;
    let mut decoder = BinDecoder::new(payload);
    let Header { metadata, counts } = Header::read(&mut decoder).ok()?;
    if counts.queries != 1 || counts.answers > 1_024 {
        return None;
    }
    let query = Query::read(&mut decoder).ok()?;
    let question = name_text(&query.name)?;
    let records = read_answer_records(&mut decoder, counts.answers, query.query_class)?;
    let (answers, ttl_ms) = chased_answers(&question, records);
    Some(DnsPacket {
        source_addr: transport.source,
        source_port,
        destination_addr: transport.destination,
        destination_port,
        id: metadata.id,
        is_response: metadata.message_type == MessageType::Response,
        opcode: u8::from(metadata.op_code),
        rcode: metadata.response_code.low(),
        question,
        qtype: u16::from(query.query_type),
        qclass: u16::from(query.query_class),
        answers,
        ttl_ms: ttl_ms.unwrap_or(0),
    })
}

/// The address and CNAME records of the answer section, which `decoder` is at.
///
/// The authority and additional sections are not read: they name no address
/// the question resolves to. `None` when any answer fails to decode, including
/// one whose RDATA length disagrees with its contents.
fn read_answer_records(
    decoder: &mut BinDecoder<'_>,
    count: u16,
    qclass: DNSClass,
) -> Option<Vec<AnswerRecord>> {
    let mut records = Vec::new();
    for _ in 0..count {
        let record = Record::read(decoder).ok()?;
        if record.dns_class != qclass {
            continue;
        }
        let value = match &record.data {
            RData::A(address) => AnswerValue::Address(IpAddr::V4(address.0)),
            RData::AAAA(address) => AnswerValue::Address(IpAddr::V6(address.0)),
            RData::CNAME(target) => AnswerValue::Cname(name_text(&target.0)?),
            _ => continue,
        };
        records.push(AnswerRecord {
            owner: name_text(&record.name)?,
            ttl_ms: u64::from(record.ttl).saturating_mul(1_000),
            value,
        });
    }
    Some(records)
}

/// The addresses `question` resolves to through `records`' CNAME chain, and
/// the lowest TTL along the way.
fn chased_answers(question: &str, records: Vec<AnswerRecord>) -> (Vec<IpAddr>, Option<u64>) {
    let mut relevant = vec![question.to_owned()];
    let mut ttl_ms = None::<u64>;
    for _ in 0..128 {
        let mut changed = false;
        for record in &records {
            if !relevant.contains(&record.owner) {
                continue;
            }
            if let AnswerValue::Cname(target) = &record.value
                && !relevant.contains(target)
            {
                relevant.push(target.clone());
                ttl_ms = Some(ttl_ms.map_or(record.ttl_ms, |ttl| ttl.min(record.ttl_ms)));
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }
    let mut answers = Vec::new();
    for record in records {
        if relevant.contains(&record.owner)
            && let AnswerValue::Address(address) = record.value
        {
            let address = canonicalize_ip(address);
            if !answers.contains(&address) {
                answers.push(address);
            }
            ttl_ms = Some(ttl_ms.map_or(record.ttl_ms, |ttl| ttl.min(record.ttl_ms)));
        }
    }
    (answers, ttl_ms)
}

/// `name` as lowercase dotted text without the root's trailing dot, the form
/// names are matched in. `None` for a label that is not ASCII.
fn name_text(name: &Name) -> Option<String> {
    let mut text = String::with_capacity(name.len());
    for label in name {
        if !label.is_ascii() {
            return None;
        }
        if !text.is_empty() {
            text.push('.');
        }
        text.push_str(std::str::from_utf8(label).ok()?);
    }
    text.make_ascii_lowercase();
    Some(text)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    /// Overwrites bytes of a well-formed seed and cuts it short, so the parser sees
    /// input that is almost valid rather than only noise.
    fn mutate(mut bytes: Vec<u8>, edits: &[(usize, u8)], keep: usize) -> Vec<u8> {
        let len = bytes.len();
        for &(index, value) in edits {
            bytes[index % len] = value;
        }
        bytes.truncate(keep);
        bytes
    }

    fn dns_packet(response: bool, id: u16, client_port: u16, answer: [u8; 4]) -> DnsPacket {
        DnsPacket {
            source_addr: if response { "8.8.8.8" } else { "10.0.0.2" }
                .parse()
                .unwrap(),
            source_port: if response { 53 } else { client_port },
            destination_addr: if response { "10.0.0.2" } else { "8.8.8.8" }
                .parse()
                .unwrap(),
            destination_port: if response { client_port } else { 53 },
            id,
            is_response: response,
            opcode: 0,
            rcode: 0,
            question: "example.test".to_owned(),
            qtype: 1,
            qclass: 1,
            answers: response
                .then_some(IpAddr::from(answer))
                .into_iter()
                .collect(),
            ttl_ms: 30_000,
        }
    }

    fn encode_name(name: &str) -> Vec<u8> {
        let mut encoded = Vec::new();
        for label in name.split('.') {
            encoded.push(u8::try_from(label.len()).unwrap());
            encoded.extend_from_slice(label.as_bytes());
        }
        encoded.push(0);
        encoded
    }

    fn wrap_ipv4_dns(payload: &[u8]) -> Vec<u8> {
        let mut packet = vec![0_u8; 28];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&u16::try_from(28 + payload.len()).unwrap().to_be_bytes());
        packet[9] = 17;
        packet[12..16].copy_from_slice(&[8, 8, 8, 8]);
        packet[16..20].copy_from_slice(&[10, 0, 0, 2]);
        packet[20..22].copy_from_slice(&53_u16.to_be_bytes());
        packet[22..24].copy_from_slice(&50_000_u16.to_be_bytes());
        packet.extend_from_slice(payload);
        packet
    }

    #[test]
    fn response_requires_exact_outstanding_query_and_is_consumed() {
        let mut tracker = DnsTransactionTracker::new(8);
        assert!(
            tracker
                .observe(dns_packet(false, 7, 50_000, [0; 4]), 42, 0)
                .is_none()
        );
        assert!(
            tracker
                .observe(dns_packet(true, 8, 50_000, [1, 2, 3, 4]), 0, 1)
                .is_none()
        );
        assert!(
            tracker
                .observe(dns_packet(true, 7, 50_001, [1, 2, 3, 4]), 0, 1)
                .is_none()
        );
        let matched = tracker
            .observe(dns_packet(true, 7, 50_000, [1, 2, 3, 4]), 0, 1)
            .expect("matched response");
        assert_eq!(matched.pid, 42);
        assert!(
            tracker
                .observe(dns_packet(true, 7, 50_000, [1, 2, 3, 4]), 0, 2)
                .is_none()
        );
    }

    #[test]
    fn timeout_and_capacity_are_bounded() {
        let mut tracker = DnsTransactionTracker::new(1);
        tracker.observe(dns_packet(false, 1, 40_001, [0; 4]), 1, 0);
        tracker.observe(dns_packet(false, 2, 40_002, [0; 4]), 2, 1);
        assert_eq!(tracker.pending.len(), 1);
        assert!(
            tracker
                .observe(dns_packet(true, 1, 40_001, [1, 1, 1, 1]), 0, 2)
                .is_none()
        );
        assert!(
            tracker
                .observe(dns_packet(true, 2, 40_002, [1, 1, 1, 1]), 0, 10_001)
                .is_none()
        );
        assert!(tracker.pending.is_empty());
    }

    #[test]
    fn rejects_error_and_wrong_question_responses() {
        let mut tracker = DnsTransactionTracker::new(8);
        tracker.observe(dns_packet(false, 1, 40_000, [0; 4]), 1, 0);
        let mut response = dns_packet(true, 1, 40_000, [1, 1, 1, 1]);
        response.rcode = 3;
        assert!(tracker.observe(response, 0, 1).is_none());
        let mut response = dns_packet(true, 1, 40_000, [1, 1, 1, 1]);
        response.question = "forged.test".to_owned();
        assert!(tracker.observe(response, 0, 1).is_none());
    }

    /// A response to an A query for `example.test` carrying one answer.
    fn a_response(id: u16, answer: [u8; 4], ttl_seconds: u32) -> Vec<u8> {
        let mut payload = response_payload("example.test", 1);
        payload[0..2].copy_from_slice(&id.to_be_bytes());
        push_a_for_question(&mut payload, answer, ttl_seconds);
        wrap_ipv4_dns(&payload)
    }

    /// A response header for one question and `answers` answers, then the question.
    fn response_payload(question: &str, answers: u16) -> Vec<u8> {
        let mut payload = vec![0_u8; 12];
        payload[2..4].copy_from_slice(&0x8180_u16.to_be_bytes());
        payload[4..6].copy_from_slice(&1_u16.to_be_bytes());
        payload[6..8].copy_from_slice(&answers.to_be_bytes());
        payload.extend(encode_name(question));
        payload.extend_from_slice(&1_u16.to_be_bytes());
        payload.extend_from_slice(&1_u16.to_be_bytes());
        payload
    }

    /// An A record for the question name, through a pointer to it.
    fn push_a_for_question(payload: &mut Vec<u8>, address: [u8; 4], ttl_seconds: u32) {
        payload.extend_from_slice(&0xc00c_u16.to_be_bytes());
        payload.extend_from_slice(&1_u16.to_be_bytes());
        payload.extend_from_slice(&1_u16.to_be_bytes());
        payload.extend_from_slice(&ttl_seconds.to_be_bytes());
        payload.extend_from_slice(&4_u16.to_be_bytes());
        payload.extend_from_slice(&address);
    }

    proptest! {
        #[test]
        fn arbitrary_bytes_never_panic(
            packet in proptest::collection::vec(any::<u8>(), 0..256),
        ) {
            let _ = parse_dns_packet(&packet);
        }

        #[test]
        fn mutated_responses_never_panic(
            edits in proptest::collection::vec((any::<usize>(), any::<u8>()), 0..8),
            keep in 0_usize..96,
        ) {
            let _ = parse_dns_packet(&mutate(a_response(7, [192, 0, 2, 1], 30), &edits, keep));
        }

        #[test]
        fn well_formed_responses_round_trip(
            id in any::<u16>(),
            answer in any::<[u8; 4]>(),
            ttl_seconds in 0_u32..=86_400,
        ) {
            let parsed = parse_dns_packet(&a_response(id, answer, ttl_seconds))
                .expect("well-formed response");
            prop_assert_eq!(parsed.id, id);
            prop_assert!(parsed.is_response);
            prop_assert_eq!(parsed.question, "example.test");
            prop_assert_eq!(parsed.answers, vec![IpAddr::from(answer)]);
            prop_assert_eq!(parsed.ttl_ms, u64::from(ttl_seconds) * 1_000);
        }
    }

    #[test]
    fn parser_keeps_only_answers_reachable_through_cname_records() {
        let mut payload = response_payload("alias.test", 3);

        payload.extend_from_slice(&0xc00c_u16.to_be_bytes());
        payload.extend_from_slice(&5_u16.to_be_bytes());
        payload.extend_from_slice(&1_u16.to_be_bytes());
        payload.extend_from_slice(&20_u32.to_be_bytes());
        let target = encode_name("target.test");
        payload.extend_from_slice(&u16::try_from(target.len()).unwrap().to_be_bytes());
        payload.extend_from_slice(&target);

        for (owner, address) in [
            ("target.test", [192, 0, 2, 1]),
            ("unrelated.test", [203, 0, 113, 9]),
        ] {
            payload.extend(encode_name(owner));
            payload.extend_from_slice(&1_u16.to_be_bytes());
            payload.extend_from_slice(&1_u16.to_be_bytes());
            payload.extend_from_slice(&30_u32.to_be_bytes());
            payload.extend_from_slice(&4_u16.to_be_bytes());
            payload.extend_from_slice(&address);
        }
        let parsed = parse_dns_packet(&wrap_ipv4_dns(&payload)).expect("DNS packet");
        assert!(parsed.is_response);
        assert_eq!(parsed.answers, vec!["192.0.2.1".parse::<IpAddr>().unwrap()]);
        assert_eq!(parsed.ttl_ms, 20_000);
    }

    #[test]
    fn parser_rejects_a_response_whose_cname_has_trailing_rdata() {
        let mut payload = response_payload("alias.test", 2);
        // CNAME back to the question name, with one byte left over in its RDATA.
        payload.extend_from_slice(&0xc00c_u16.to_be_bytes());
        payload.extend_from_slice(&5_u16.to_be_bytes());
        payload.extend_from_slice(&1_u16.to_be_bytes());
        payload.extend_from_slice(&20_u32.to_be_bytes());
        payload.extend_from_slice(&3_u16.to_be_bytes());
        payload.extend_from_slice(&[0xc0, 0x0c, 0xff]);
        push_a_for_question(&mut payload, [192, 0, 2, 1], 30);

        assert!(parse_dns_packet(&wrap_ipv4_dns(&payload)).is_none());
    }

    #[test]
    fn sections_after_the_answers_are_not_read() {
        let mut payload = response_payload("example.test", 1);
        push_a_for_question(&mut payload, [192, 0, 2, 1], 30);
        // Claims an additional record that is cut short.
        payload[11] = 1;
        payload.extend_from_slice(&[0, 0, 41]);

        let parsed = parse_dns_packet(&wrap_ipv4_dns(&payload)).expect("DNS packet");
        assert_eq!(parsed.answers, vec!["192.0.2.1".parse::<IpAddr>().unwrap()]);
    }

    #[test]
    fn names_are_lowercase_without_the_root_dot() {
        let mut payload = response_payload("WWW.Example.TEST", 1);
        push_a_for_question(&mut payload, [192, 0, 2, 1], 30);

        let parsed = parse_dns_packet(&wrap_ipv4_dns(&payload)).expect("DNS packet");
        assert_eq!(parsed.question, "www.example.test");
        assert_eq!(parsed.answers.len(), 1);
    }
}
