//! DNS response message builders shared by the resolver.

use hickory_proto::op::{Edns, Message, Metadata, Query, ResponseCode};
use hickory_proto::rr::{rdata, Name, RData, Record};

use crate::{DnsError, Result};

/// NOERROR with the original question and no answers.
///
/// Used where the resolver itself suppresses an answer (rebinding protection),
/// not for upstream negative answers — those keep the authority SOA that
/// `upstream::resolver` preserves, and this would discard it.
pub(crate) fn build_nodata_response(request: &Message) -> Message {
    build_empty_response(request, ResponseCode::NoError)
}

/// SERVFAIL with the original question preserved for client retry semantics.
pub(crate) fn build_servfail_response(request: &Message) -> Message {
    build_empty_response(request, ResponseCode::ServFail)
}

/// Empty response with an arbitrary rcode for request validation failures.
pub(crate) fn build_error_response(request: &Message, rcode: ResponseCode) -> Message {
    build_empty_response(request, rcode)
}

fn build_empty_response(request: &Message, rcode: ResponseCode) -> Message {
    empty_response(&request.metadata, request.queries.iter().cloned(), rcode)
}

/// Empty response echoing `queries`, for callers holding only a request's
/// header and question rather than an owned `Message`.
pub(crate) fn empty_response(
    request: &Metadata,
    queries: impl IntoIterator<Item = Query>,
    rcode: ResponseCode,
) -> Message {
    let mut response = Message::response(request.id, request.op_code);
    response.metadata.recursion_desired = request.recursion_desired;
    response.metadata.recursion_available = true;
    response.metadata.response_code = rcode;
    for question in queries {
        response.add_query(question);
    }
    response
}

/// SERVFAIL for a name whose last resolution failed and is still held
/// (RFC 9520 §3.2), marked EDE 13 so a client can tell it was not re-asked.
///
/// The OPT reaches only a client that sent one; `service::response_edns`
/// drops it otherwise.
pub(crate) fn build_cached_failure_response(
    request: &Metadata,
    question: Option<Query>,
    request_edns: Option<&Edns>,
) -> Message {
    let mut response = empty_response(request, question, ResponseCode::ServFail);
    let mut edns = Edns::new();
    edns.set_dnssec_ok(request_edns.is_some_and(|edns| edns.flags().dnssec_ok));
    edns.options_mut().insert(crate::ede::build_ede_option(
        crate::ede::EDE_CACHED_ERROR,
        None,
    ));
    response.set_edns(edns);
    response
}

/// Seconds a client may keep the answer to an `ANY` query. RFC 8482 §4.2 asks for a TTL
/// long enough that the same client does not ask again at once.
const ANY_ANSWER_TTL: u32 = 3_600;

/// The answer to an `ANY` query: one made-up HINFO record whose CPU field is `RFC8482`,
/// which RFC 8482 §4.2 gives a server that will not list every record of a name.
///
/// The query is answered here and never forwarded. Public resolvers do not serve the type
/// either: Cloudflare answers NOTIMP, which came back to the client as SERVFAIL and, over
/// HTTP/2, cost the resolver its upstream connections each time a program asked.
pub(crate) fn build_any_response(request: &Metadata, question: Query) -> Message {
    let record = Record::from_rdata(
        question.name().clone(),
        ANY_ANSWER_TTL,
        RData::HINFO(rdata::HINFO::new("RFC8482".to_owned(), String::new())),
    );
    let mut response = empty_response(request, [question], ResponseCode::NoError);
    response.add_answer(record);
    response
}

const SYNTHETIC_SOA_SERIAL: u32 = 1;
const SYNTHETIC_SOA_REFRESH: i32 = 7_200;
const SYNTHETIC_SOA_RETRY: i32 = 3_600;
const SYNTHETIC_SOA_EXPIRE: i32 = 1_209_600;

/// Authority SOA for a negative answer the resolver makes up itself.
///
/// RFC 2308 §5: a negative answer without an SOA SHOULD NOT be cached, so a
/// downstream stub would ask again on every lookup. The record's own TTL and
/// its MINIMUM are both `negative_ttl`, which makes that the negative TTL.
pub(crate) fn synthetic_soa(zone: Name, negative_ttl: u32) -> Record {
    Record::from_rdata(
        zone.clone(),
        negative_ttl,
        RData::SOA(rdata::SOA::new(
            zone.clone(),
            zone,
            SYNTHETIC_SOA_SERIAL,
            SYNTHETIC_SOA_REFRESH,
            SYNTHETIC_SOA_RETRY,
            SYNTHETIC_SOA_EXPIRE,
            negative_ttl,
        )),
    )
}

/// Encodes a DNS message to wire format.
pub(crate) fn encode_message(message: &Message) -> Result<Vec<u8>> {
    use hickory_proto::serialize::binary::{BinEncodable, BinEncoder};

    let mut bytes = Vec::with_capacity(512);
    let mut encoder = BinEncoder::new(&mut bytes);
    message
        .emit(&mut encoder)
        .map_err(|error| DnsError::Encode(error.to_string()))?;
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use hickory_proto::op::{MessageType, OpCode, Query};
    use hickory_proto::rr::RecordType;

    use std::sync::Arc;
    use std::time::Instant;

    use super::*;
    use crate::query_engine::{EngineServices, QueryEngine};
    use crate::service::testing::respond;
    use crate::settings::DnsConfig;
    use antiwire_policy::{DomainBlockSource, DomainDecision, PolicyEngine, RuleEngine, Verdict};

    fn build_query_message(name: &str, qtype: RecordType) -> Result<Message> {
        let fqdn = hickory_proto::rr::Name::from_ascii(format!("{name}."))
            .map_err(|error| DnsError::InvalidQuery(error.to_string()))?;
        let mut query = Message::new(0, MessageType::Query, OpCode::Query);
        query.add_query(Query::query(fqdn, qtype));
        Ok(query)
    }

    async fn forward<P>(stub: &QueryEngine<P>, request: &Message) -> Result<Message>
    where
        P: PolicyEngine + Send + Sync + Unpin + 'static,
    {
        let bytes = respond(stub, request, Instant::now()).await;
        Message::from_vec(&bytes).map_err(|error| DnsError::InvalidQuery(error.to_string()))
    }

    async fn resolve<P>(stub: &QueryEngine<P>, name: &str, qtype: RecordType) -> Result<Message>
    where
        P: PolicyEngine + Send + Sync + Unpin + 'static,
    {
        let query = build_query_message(name, qtype)?;
        forward(stub, &query).await
    }

    struct BlockPolicy;

    impl PolicyEngine for BlockPolicy {
        fn evaluate_domain_with_source(&self, domain: &str) -> Option<DomainDecision> {
            (domain == "blocked.example").then_some(DomainDecision {
                verdict: Verdict::Block,
                source: Some(DomainBlockSource::DnsRule),
            })
        }
    }

    #[derive(Default)]
    struct RecordingSink {
        hints: std::sync::Mutex<Vec<String>>,
        resolutions: std::sync::Mutex<Vec<(String, Vec<std::net::IpAddr>)>>,
    }

    impl crate::DnsHintSink for RecordingSink {
        fn record_hint(
            &self,
            _pid: u32,
            query: &str,
            _answers: &[std::net::IpAddr],
            _: u64,
            _: u64,
        ) {
            self.hints.lock().expect("hints").push(query.to_owned());
        }

        fn record_resolution(&self, query: &str, answers: &[std::net::IpAddr]) {
            self.resolutions
                .lock()
                .expect("resolutions")
                .push((query.to_owned(), answers.to_vec()));
        }
    }

    #[tokio::test]
    async fn blocked_domain_records_its_sinkhole_without_a_process_hint() {
        let stub = QueryEngine::new(
            BlockPolicy,
            DnsConfig {
                block_mode: crate::block::BlockResponseMode::Sinkhole,
                upstreams: vec!["127.0.0.1:1".to_owned()],
                ..DnsConfig::default()
            },
        );
        let sink = Arc::new(RecordingSink::default());
        stub.set_hint_sink(Arc::clone(&sink) as Arc<dyn crate::DnsHintSink>);

        let _ = resolve(&stub, "blocked.example", RecordType::A).await;
        assert_eq!(
            *sink.resolutions.lock().expect("resolutions"),
            vec![(
                "blocked.example".to_owned(),
                vec![std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)]
            )]
        );
        assert!(
            sink.hints.lock().expect("hints").is_empty(),
            "a sinkhole address must not be attributed to the querying process"
        );
    }

    #[tokio::test]
    async fn blocked_domain_returns_sinkhole_without_upstream() {
        let stub = QueryEngine::new(
            BlockPolicy,
            DnsConfig {
                block_mode: crate::block::BlockResponseMode::Sinkhole,
                upstreams: vec!["127.0.0.1:1".to_owned()],
                ..DnsConfig::default()
            },
        );

        let response = resolve(&stub, "blocked.example", RecordType::A)
            .await
            .expect("blocked response");
        assert_eq!(response.metadata.response_code, ResponseCode::NoError);
        assert_eq!(response.answers.len(), 1);
    }

    #[test]
    fn try_new_with_default_config_builds_resolver() {
        let settings = antiwire_store::DaemonSetting::default();
        let config = crate::settings::dns_config_from_settings(&settings);
        QueryEngine::try_new(RuleEngine::new(), &config, EngineServices::default())
            .expect("engine");
    }

    #[test]
    fn servfail_preserves_query_id() {
        let query = build_query_message("example.example", RecordType::A).expect("query");
        let response = build_servfail_response(&query);
        assert_eq!(response.metadata.id, query.metadata.id);
        assert_eq!(response.metadata.response_code, ResponseCode::ServFail);
        assert_eq!(response.queries.len(), 1);
    }
}
