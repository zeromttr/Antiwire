use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use hickory_proto::op::{Edns, Message, Metadata, OpCode, Query, ResponseCode};
use hickory_proto::rr::{rdata, Name, RData, Record, RecordType};

use crate::ede::blocked_by_policy_option;
use crate::{DnsError, Result};

/// Policy block response style mirrored from daemon settings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum BlockResponseMode {
    #[default]
    Sinkhole,
    NxDomain,
    Refused,
    Custom,
}

impl BlockResponseMode {
    #[must_use]
    pub(crate) fn from_settings(value: &str) -> Self {
        match value.trim().to_ascii_lowercase().as_str() {
            "nxdomain" => Self::NxDomain,
            "refused" => Self::Refused,
            "custom" => Self::Custom,
            _ => Self::Sinkhole,
        }
    }

    #[must_use]
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Sinkhole => "sinkhole",
            Self::NxDomain => "nxdomain",
            Self::Refused => "refused",
            Self::Custom => "custom",
        }
    }
}

/// Builds a policy block response echoing the request's transaction id,
/// first question, and EDNS.
///
/// Takes the pieces rather than an owned request `Message` so the block path
/// clones only the one question it echoes (see `RequestView::first_query`).
pub(crate) fn build_block_response(
    metadata: &Metadata,
    question: Query,
    request_edns: Option<&Edns>,
    mode: BlockResponseMode,
    custom_ip: Option<IpAddr>,
) -> Result<Message> {
    let qtype = question.query_type();

    let mut response = Message::response(metadata.id, OpCode::Query);
    response.metadata.authoritative = true;
    response.metadata.recursion_available = true;

    let mut edns = request_edns.cloned().unwrap_or_default();
    edns.options_mut().insert(blocked_by_policy_option());
    response.set_edns(edns);

    match mode {
        BlockResponseMode::NxDomain => {
            response.metadata.response_code = ResponseCode::NXDomain;
        }
        BlockResponseMode::Refused => {
            response.metadata.response_code = ResponseCode::Refused;
        }
        BlockResponseMode::Custom => {
            let ip = custom_ip.ok_or_else(|| {
                DnsError::Config("custom block mode requires custom_block_ip".to_owned())
            })?;
            response.metadata.response_code = ResponseCode::NoError;
            append_custom_answer(&mut response, question.name().clone(), qtype, ip);
        }
        BlockResponseMode::Sinkhole => {
            response.metadata.response_code = ResponseCode::NoError;
            append_sinkhole_answer(&mut response, question.name().clone(), qtype);
        }
    }

    // Sinkhole and custom modes answer some types with NODATA. Every
    // negative needs an SOA, or the client's stub cannot cache it.
    if response.answers.is_empty() && response.metadata.response_code != ResponseCode::Refused {
        response.add_authority(block_soa(question.name(), response.metadata.response_code));
    }

    response.add_query(question);
    Ok(response)
}

/// Authority SOA for a blocked name's negative answer (RFC 2308 §5).
///
/// NODATA claims the blocked name as a zone apex holding no records of the
/// asked type. NXDOMAIN says the name does not exist, so its SOA belongs to
/// the parent instead, as a real authoritative server would answer. The
/// negative TTL matches the sinkhole addresses', so an unblock reaches every
/// client within the same time whichever mode was set.
fn block_soa(name: &Name, rcode: ResponseCode) -> Record {
    let zone = if rcode == ResponseCode::NXDomain {
        name.base_name()
    } else {
        name.clone()
    };
    crate::messages::synthetic_soa(zone, antiwire_tuning::DNS_DEFAULT_TTL_SECONDS as u32)
}

fn append_sinkhole_answer(response: &mut Message, name: Name, qtype: RecordType) {
    match qtype {
        RecordType::A => {
            let record = Record::from_rdata(
                name,
                antiwire_tuning::DNS_DEFAULT_TTL_SECONDS as u32,
                RData::A(rdata::A(Ipv4Addr::UNSPECIFIED)),
            );
            response.add_answer(record);
        }
        RecordType::AAAA => {
            let record = Record::from_rdata(
                name,
                antiwire_tuning::DNS_DEFAULT_TTL_SECONDS as u32,
                RData::AAAA(rdata::AAAA(Ipv6Addr::UNSPECIFIED)),
            );
            response.add_answer(record);
        }
        _ => {
            response.metadata.response_code = ResponseCode::NoError;
        }
    }
}

/// Answers with the custom address when it matches the query's family. One
/// address cannot answer the other family or a non-address type, so those get
/// NODATA, as in sinkhole mode: the name stays blocked either way.
fn append_custom_answer(response: &mut Message, name: Name, qtype: RecordType, ip: IpAddr) {
    let data = match (qtype, ip) {
        (RecordType::A, IpAddr::V4(ipv4)) => RData::A(rdata::A(ipv4)),
        (RecordType::AAAA, IpAddr::V6(ipv6)) => RData::AAAA(rdata::AAAA(ipv6)),
        _ => return,
    };
    response.add_answer(Record::from_rdata(
        name,
        antiwire_tuning::DNS_DEFAULT_TTL_SECONDS as u32,
        data,
    ));
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::op::MessageType;
    use hickory_proto::rr::rdata::opt::{EdnsCode, EdnsOption};
    use hickory_proto::rr::RecordType;

    fn sample_question(qtype: RecordType) -> Query {
        let name = Name::from_ascii("blocked.example.").expect("name");
        Query::query(name, qtype)
    }

    fn block(qtype: RecordType, mode: BlockResponseMode, ip: Option<IpAddr>) -> Result<Message> {
        let metadata = Metadata::new(0xBEEF, MessageType::Query, OpCode::Query);
        build_block_response(&metadata, sample_question(qtype), None, mode, ip)
    }

    #[test]
    fn sinkhole_returns_zero_addresses() {
        let response = block(RecordType::A, BlockResponseMode::Sinkhole, None).expect("sinkhole");

        assert_eq!(response.metadata.id, 0xBEEF);
        assert_eq!(response.metadata.response_code, ResponseCode::NoError);
        assert_eq!(response.queries, vec![sample_question(RecordType::A)]);
        assert_eq!(response.answers.len(), 1);
        assert_eq!(
            &response.answers[0].name,
            sample_question(RecordType::A).name()
        );
        assert!(matches!(
            &response.answers[0].data,
            RData::A(addr) if addr.0 == Ipv4Addr::UNSPECIFIED
        ));
    }

    #[test]
    fn nxdomain_and_refused_set_rcodes() {
        let nx = block(RecordType::A, BlockResponseMode::NxDomain, None).expect("nxdomain");
        assert_eq!(nx.metadata.response_code, ResponseCode::NXDomain);

        let refused = block(RecordType::A, BlockResponseMode::Refused, None).expect("refused");
        assert_eq!(refused.metadata.response_code, ResponseCode::Refused);
        assert!(
            refused.authorities.is_empty(),
            "REFUSED is not a negative answer"
        );
    }

    fn soa_owner(response: &Message) -> String {
        let soa = response
            .authorities
            .iter()
            .find(|record| record.record_type() == RecordType::SOA)
            .expect("negative answer carries an SOA");
        let RData::SOA(data) = &soa.data else {
            panic!("SOA record holds SOA data");
        };
        assert_eq!(soa.ttl, data.minimum, "SOA TTL is the negative TTL");
        soa.name.to_utf8()
    }

    /// RFC 2308 §5: without an SOA a stub may not cache the negative answer.
    #[test]
    fn negative_block_answers_carry_an_soa() {
        let nx = block(RecordType::A, BlockResponseMode::NxDomain, None).expect("nxdomain");
        assert_eq!(soa_owner(&nx), "example.");

        let sinkhole = block(RecordType::TXT, BlockResponseMode::Sinkhole, None).expect("txt");
        assert_eq!(sinkhole.metadata.response_code, ResponseCode::NoError);
        assert_eq!(sinkhole.answers, []);
        assert_eq!(soa_owner(&sinkhole), "blocked.example.");

        let custom = block(
            RecordType::AAAA,
            BlockResponseMode::Custom,
            Some("10.0.0.9".parse().expect("ip")),
        )
        .expect("custom");
        assert_eq!(soa_owner(&custom), "blocked.example.");

        let answered = block(RecordType::A, BlockResponseMode::Sinkhole, None).expect("a");
        assert!(answered.authorities.is_empty(), "an answer needs no SOA");
    }

    #[test]
    fn echoes_request_edns_and_adds_ede() {
        let metadata = Metadata::new(1, MessageType::Query, OpCode::Query);
        let mut request_edns = Edns::new();
        request_edns.set_max_payload(1232);
        let response = build_block_response(
            &metadata,
            sample_question(RecordType::A),
            Some(&request_edns),
            BlockResponseMode::Sinkhole,
            None,
        )
        .expect("sinkhole");

        let edns = response.edns.as_ref().expect("edns");
        assert_eq!(edns.max_payload(), 1232);
        let Some(EdnsOption::Unknown(15, data)) = edns.option(EdnsCode::Unknown(15)) else {
            panic!("expected EDE option");
        };
        assert_eq!(u16::from_be_bytes([data[0], data[1]]), 15);
    }

    /// One custom address answers its own family; every other type gets the
    /// same NODATA sinkhole mode gives instead of an error.
    #[test]
    fn custom_mode_answers_other_types_with_nodata() {
        let v4 = Some("10.0.0.9".parse().expect("ip"));
        let v6 = Some("fd00::9".parse().expect("ip"));
        for (qtype, ip) in [
            (RecordType::AAAA, v4),
            (RecordType::HTTPS, v4),
            (RecordType::TXT, v4),
            (RecordType::A, v6),
        ] {
            let response = block(qtype, BlockResponseMode::Custom, ip)
                .unwrap_or_else(|error| panic!("{qtype}: {error}"));
            assert_eq!(response.metadata.response_code, ResponseCode::NoError);
            assert!(response.answers.is_empty(), "{qtype}");
            assert_eq!(response.queries, vec![sample_question(qtype)]);
        }
    }

    #[test]
    fn custom_mode_uses_configured_ip() {
        let response = block(
            RecordType::A,
            BlockResponseMode::Custom,
            Some("10.0.0.9".parse().expect("ip")),
        )
        .expect("custom");

        assert!(matches!(
            &response.answers[0].data,
            RData::A(addr) if addr.0 == Ipv4Addr::new(10, 0, 0, 9)
        ));
    }
}
