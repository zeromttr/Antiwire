//! Tower services that answer DNS queries for the loopback listeners.
//!
//! A query is answered in two steps. [`Resolve`] parses the raw wire and tries
//! to answer without upstream I/O — policy blocks and cache hits — returning
//! either an encoded reply or the state a [`Forward`] needs to finish the miss.
//! The listeners send local replies from the receive task and spawn a task only
//! for a miss, so this split is what keeps cache hits free of task creation.
//! Both services catch a panic in one query and answer it SERVFAIL; see
//! [`crate::query_guard`].
//!
//! Replies are encoded here rather than in the transports, so UDP and TCP share
//! one size limit and truncation rule.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Instant;

use antiwire_policy::PolicyEngine;
use antiwire_tuning::{DNS_DEFAULT_UDP_PAYLOAD_SIZE, DNS_MAX_UDP_DATAGRAM_SIZE};
use futures_util::future::BoxFuture;
use hickory_proto::op::{Edns, MessageType, ResponseCode};
use hickory_proto::rr::Record;
use hickory_proto::serialize::binary::{BinEncodable, BinEncoder};
use hickory_server::net::xfer::Protocol;
use hickory_server::proto::op::{Header, HeaderCounts, Metadata, OpCode};
use hickory_server::server::Request;
use hickory_server::zone_handler::{MessageResponse, MessageResponseBuilder};
use tower::Service;
use tracing::warn;

use crate::ai::{AiCoordinator, PostResponseWork};
use crate::block::DnsQueryContext;
#[cfg(test)]
use crate::query_engine::prepare_uncached_message;
use crate::query_engine::QueryEngine;
use crate::query_engine::{PreparedQuery, PreparedResponse};
use crate::query_guard::{catch_query_panic, catch_sync_query_panic};

/// One query as read off the wire, before parsing.
pub(crate) struct Query {
    pub(crate) wire: Vec<u8>,
    pub(crate) src: SocketAddr,
    pub(crate) protocol: Protocol,
    /// Taken when the bytes arrived, so parsing counts against the client's
    /// query deadline.
    pub(crate) received_at: Instant,
}

/// What [`Resolve`] made of a query.
pub(crate) enum Answer<M> {
    /// Answered without upstream I/O; send it now.
    Local(Reply),
    /// Needs upstream; hand it to a [`Forward`] on its own task.
    Miss(M),
    /// Shorter than a DNS header, or a response rather than a query: no
    /// reply is owed.
    Ignored,
}

/// A query [`Resolve`] could not answer locally, carrying the parse and policy
/// work already done so [`Forward`] never repeats it.
pub(crate) struct Miss {
    request: Request,
    query: PreparedQuery,
    received_at: Instant,
}

/// An encoded reply and the work owed once a transport accepts it.
pub(crate) struct Reply {
    bytes: Vec<u8>,
    receipt: Receipt,
}

impl Reply {
    #[cfg(test)]
    pub(crate) fn new(bytes: Vec<u8>) -> Self {
        Self {
            bytes,
            receipt: Receipt(None),
        }
    }

    pub(crate) fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub(crate) fn into_parts(self) -> (Vec<u8>, Receipt) {
        (self.bytes, self.receipt)
    }

    /// Call once the transport accepted the reply.
    pub(crate) fn delivered(self) {
        self.receipt.delivered();
    }
}

/// Post-response AI work, submitted only once the reply was accepted for
/// sending.
///
/// For UDP, acceptance cannot prove the client received it; it only rules out
/// a send that failed locally. Dropping a receipt without calling
/// [`Self::delivered`] discards the work, and DNS admission is never held for it.
pub(crate) struct Receipt(Option<(Arc<AiCoordinator>, PostResponseWork)>);

impl Receipt {
    pub(crate) fn delivered(self) {
        if let Some((ai, work)) = self.0 {
            ai.submit_post_response(&work);
        }
    }
}

/// Parses a query and answers it from policy or cache when no upstream I/O is
/// needed.
pub(crate) struct Resolve<P> {
    engine: Arc<QueryEngine<P>>,
}

impl<P> Resolve<P> {
    pub(crate) fn new(engine: Arc<QueryEngine<P>>) -> Self {
        Self { engine }
    }
}

impl<P> Resolve<P>
where
    P: PolicyEngine + Send + Sync + Unpin + 'static,
{
    /// Synchronous: nothing here waits on I/O, so the listeners call it on
    /// their receive task.
    pub(crate) fn resolve(&self, query: Query) -> Answer<Miss> {
        resolve_query(&self.engine, query)
    }
}

impl<P> Clone for Resolve<P> {
    fn clone(&self) -> Self {
        Self::new(Arc::clone(&self.engine))
    }
}

/// Parses `query` and answers it locally, or returns what its miss needs.
fn resolve_query<P>(engine: &QueryEngine<P>, query: Query) -> Answer<Miss>
where
    P: PolicyEngine + Send + Sync + Unpin + 'static,
{
    // Kept for a FORMERR: parsing consumes the wire.
    let header = query
        .wire
        .get(..12)
        .and_then(|header| <[u8; 12]>::try_from(header).ok());
    let Ok(request) = Request::from_bytes(query.wire, query.src, query.protocol) else {
        return header.and_then(formerr).map_or(Answer::Ignored, |bytes| {
            Answer::Local(Reply {
                bytes,
                receipt: Receipt(None),
            })
        });
    };
    if request.metadata.message_type == MessageType::Response {
        return Answer::Ignored;
    }
    let received_at = query.received_at;
    #[expect(
        clippy::result_large_err,
        reason = "the miss keeps its PreparedQuery so upstream never re-parses"
    )]
    let local = catch_sync_query_panic(&request, || answer_locally(engine, &request, received_at));
    match local {
        Some(Ok(Some(reply))) => Answer::Local(reply),
        Some(Ok(None)) => Answer::Ignored,
        Some(Err(query)) => Answer::Miss(Miss {
            request,
            query,
            received_at,
        }),
        None => Answer::Local(servfail(&request)),
    }
}

/// Answers `request` from policy or cache, or returns the state its miss needs.
/// `None` means the query is owed no reply.
///
/// `try_handle_parsed_sync` evaluates policy *before* probing the cache, which is what
/// makes a newly added block rule take effect immediately without any cache
/// invalidation. That ordering must stay inside the engine.
#[expect(
    clippy::result_large_err,
    reason = "forwards PreparedQuery so a miss keeps the inline cache key without a second parse"
)]
pub(crate) fn answer_locally<P>(
    engine: &QueryEngine<P>,
    request: &Request,
    received_at: Instant,
) -> Result<Option<Reply>, PreparedQuery>
where
    P: PolicyEngine + Send + Sync + Unpin + 'static,
{
    let prepared = engine.try_handle_parsed_sync(request, Some(context(request, received_at)))?;
    Ok(prepared.map(|prepared| encode_prepared(request, prepared, engine.ai_coordinator())))
}

/// Finishes a [`Miss`] over upstream.
pub(crate) struct Forward<P> {
    engine: Arc<QueryEngine<P>>,
}

impl<P> Forward<P> {
    pub(crate) fn new(engine: Arc<QueryEngine<P>>) -> Self {
        Self { engine }
    }
}

impl<P> Clone for Forward<P> {
    fn clone(&self) -> Self {
        Self::new(Arc::clone(&self.engine))
    }
}

impl<P> Service<Miss> for Forward<P>
where
    P: PolicyEngine + Send + Sync + Unpin + 'static,
{
    type Response = Reply;
    type Error = Infallible;
    type Future = BoxFuture<'static, Result<Reply, Infallible>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Infallible>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, miss: Miss) -> Self::Future {
        let engine = Arc::clone(&self.engine);
        Box::pin(async move { Ok(answer_miss(&engine, miss).await) })
    }
}

/// Finishes `miss` over upstream, answering SERVFAIL if that panics.
async fn answer_miss<P>(engine: &QueryEngine<P>, miss: Miss) -> Reply
where
    P: PolicyEngine + Send + Sync + Unpin + 'static,
{
    let Miss {
        request,
        query,
        received_at,
    } = miss;
    let context = context(&request, received_at);
    let answered = catch_query_panic(&request, async {
        let prepared = engine
            .handle_parsed_miss(&request, Some(context), query, received_at)
            .await;
        encode_prepared(&request, prepared, engine.ai_coordinator())
    })
    .await;
    answered.unwrap_or_else(|| servfail(&request))
}

fn context(request: &Request, received_at: Instant) -> DnsQueryContext {
    DnsQueryContext {
        client_addr: request.src().ip(),
        client_port: request.src().port(),
        protocol: request.protocol(),
        received_at,
    }
}

/// FORMERR for a query whose header can be read but whose body cannot.
///
/// RFC 1035 §4.1.1 defines FORMERR for this, and RFC 6891 §6.1.1 requires it
/// for a query with more than one OPT record. Dropping the query instead
/// leaves the client waiting out its timeout. The reply is a bare header with
/// the transaction ID, opcode and RD bit copied and no sections, since the
/// question could not be read. A message marked as a response gets nothing.
fn formerr(header: [u8; 12]) -> Option<Vec<u8>> {
    const QR: u8 = 0x80;
    const OPCODE_AND_RD: u8 = 0x79;
    const RA: u8 = 0x80;
    if header[2] & QR != 0 {
        return None;
    }
    let mut reply = vec![0; 12];
    reply[..2].copy_from_slice(&header[..2]);
    reply[2] = QR | (header[2] & OPCODE_AND_RD);
    reply[3] = RA | ResponseCode::FormErr.low();
    Some(reply)
}

/// SERVFAIL for a query whose handling panicked.
pub(crate) fn servfail(request: &Request) -> Reply {
    let response = MessageResponseBuilder::from_message_request(request)
        .error_msg(&request.metadata, ResponseCode::ServFail);
    Reply {
        bytes: encode(response, request.protocol(), None),
        receipt: Receipt(None),
    }
}

fn encode_prepared(
    request: &Request,
    mut prepared: PreparedResponse,
    ai: Option<Arc<AiCoordinator>>,
) -> Reply {
    let receipt = Receipt(ai.zip(prepared.take_post_ai()));

    // The OPT record is the one small copy left on a cache hit: the advertised
    // payload size must become the client's, and an OPT with no options clones
    // without touching the heap.
    let mut edns = response_edns(request.edns.as_ref(), prepared.edns());
    if prepared.stale() {
        // RFC 8914 §4.4: say the answer is stale. The cached OPT is shared,
        // so the option goes on this serve's copy.
        if let Some(edns) = edns.as_mut() {
            edns.options_mut().insert(crate::ede::build_ede_option(
                crate::ede::EDE_STALE_ANSWER,
                None,
            ));
        }
    }
    let mut builder = MessageResponseBuilder::from_message_request(request);
    if let Some(edns) = edns.as_ref() {
        builder.edns(edns);
    }

    // The question section comes from the request, so the client's original
    // casing is echoed back without the byte-level fixup the cache path does.
    // Records are borrowed from the cached parse tree when no TTL aging is due.
    let message = builder.build(
        prepared.metadata,
        prepared.answers(),
        prepared.authorities(),
        std::iter::empty(),
        prepared.additionals(),
    );
    Reply {
        bytes: encode(message, request.protocol(), edns.as_ref()),
        receipt,
    }
}

/// Encodes a response, capped at what the client can receive.
///
/// A UDP response is capped at the client's advertised payload size, or at
/// the 512 bytes RFC 1035 §4.2.1 allows a client that sent no OPT record.
/// Hickory's encoder writes the records that fit and sets TC, so the client
/// retries over TCP. A response that cannot be encoded at all becomes a bare
/// SERVFAIL header.
fn encode<'a, A, N, S, D>(
    response: MessageResponse<'_, 'a, A, N, S, D>,
    protocol: Protocol,
    edns: Option<&Edns>,
) -> Vec<u8>
where
    A: Iterator<Item = &'a Record> + Send + 'a,
    N: Iterator<Item = &'a Record> + Send + 'a,
    S: Iterator<Item = &'a Record> + Send + 'a,
    D: Iterator<Item = &'a Record> + Send + 'a,
{
    let id = response.metadata().id;
    let max_size = match protocol {
        Protocol::Udp => edns.map_or_else(min_udp_payload_size, Edns::max_payload),
        _ => u16::MAX,
    };

    let mut bytes = Vec::with_capacity(512);
    let emitted = {
        let mut encoder = BinEncoder::new(&mut bytes);
        encoder.set_max_size(max_size);
        response.destructive_emit(&mut encoder)
    };
    let Err(error) = emitted else {
        return bytes;
    };

    warn!(%error, "error encoding dns response; answering SERVFAIL");
    bytes.clear();
    let mut metadata = Metadata::new(id, MessageType::Response, OpCode::Query);
    metadata.response_code = ResponseCode::ServFail;
    let header = Header {
        metadata,
        counts: HeaderCounts::default(),
    };
    let mut encoder = BinEncoder::new(&mut bytes);
    if header.emit(&mut encoder).is_err() {
        bytes.clear();
    }
    bytes
}

/// Response OPT record, or `None` when the client sent none.
///
/// RFC 6891 forbids returning an OPT record to a client that did not send one —
/// which is also why [`crate::response_cache::QueryFlags`] keys the cache on it.
/// The advertised payload size is the client's, so the encoder truncates at
/// exactly what the client said it can receive.
///
/// When the prepared response carries an OPT of its own — an upstream answer, a
/// cache hit, or a policy block with its EDE option — that record is reused. An
/// error response built without one is given a synthesized OPT whose DO bit is
/// copied from the request, so the client's request for DNSSEC records is not
/// silently dropped.
pub(crate) fn response_edns(
    request_edns: Option<&Edns>,
    response_edns: Option<&Edns>,
) -> Option<Edns> {
    let request_edns = request_edns?;
    let mut edns = response_edns.cloned().unwrap_or_else(|| {
        let mut synthesized = Edns::default();
        synthesized.set_dnssec_ok(request_edns.flags().dnssec_ok);
        synthesized
    });
    edns.set_max_payload(
        request_edns
            .max_payload()
            .clamp(min_udp_payload_size(), max_udp_payload_size()),
    );
    Some(edns)
}

fn min_udp_payload_size() -> u16 {
    u16::try_from(DNS_DEFAULT_UDP_PAYLOAD_SIZE).unwrap_or(512)
}

fn max_udp_payload_size() -> u16 {
    u16::try_from(DNS_MAX_UDP_DATAGRAM_SIZE).unwrap_or(4096)
}

/// Test helpers: stand-in services for the listener loops, and the listener's
/// own query path for tests that drive an engine directly.
#[cfg(test)]
pub(crate) mod testing {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use hickory_proto::op::{Message, OpCode, Query as Question};
    use hickory_proto::rr::{Name, RecordType};
    use tokio::sync::Semaphore;
    use tower::service_fn;

    use super::*;
    use crate::messages::encode_message;

    pub(crate) fn query_wire(id: u16, name: &str) -> Vec<u8> {
        let mut query = Message::new(id, MessageType::Query, OpCode::Query);
        query.add_query(Question::query(
            Name::from_ascii(name).expect("query name"),
            RecordType::A,
        ));
        encode_message(&query).expect("encode query")
    }

    pub(crate) fn reply_to(query: &Message) -> Reply {
        let mut response = Message::response(query.metadata.id, OpCode::Query);
        response.queries.clone_from(&query.queries);
        Reply::new(encode_message(&response).expect("encode reply"))
    }

    /// Answers `cached.test.` locally and sends every other name upstream.
    pub(crate) fn resolve() -> impl Fn(Query) -> Answer<Message> + Clone + Send + 'static {
        |query: Query| {
            let message = Message::from_vec(&query.wire).expect("test query parses");
            let name = message.queries[0].name().to_utf8();
            if name == "cached.test." {
                Answer::Local(reply_to(&message))
            } else {
                Answer::Miss(message)
            }
        }
    }

    /// Upstream stand-in. Each call counts itself in `started`, then waits for
    /// a `release` permit.
    pub(crate) fn forward(
        started: &Arc<AtomicUsize>,
        release: &Arc<Semaphore>,
    ) -> impl Service<Message, Response = Reply, Error = Infallible, Future: Send + 'static> + Clone + Send
    {
        let started = Arc::clone(started);
        let release = Arc::clone(release);
        service_fn(move |message: Message| {
            let started = Arc::clone(&started);
            let release = Arc::clone(&release);
            async move {
                started.fetch_add(1, Ordering::Relaxed);
                release
                    .acquire()
                    .await
                    .expect("test gate remains open")
                    .forget();
                Ok(reply_to(&message))
            }
        })
    }

    const CLIENT: &str = "127.0.0.1:53000";

    pub(crate) fn wire_query(request: &Message, received_at: Instant) -> Query {
        Query {
            wire: encode_message(request).expect("encode query"),
            src: CLIENT.parse().expect("client address"),
            protocol: Protocol::Udp,
            received_at,
        }
    }

    /// The reply's bytes, with its post-response work submitted as a
    /// transport would once the send succeeded.
    fn sent(reply: Reply) -> Vec<u8> {
        let (bytes, receipt) = reply.into_parts();
        receipt.delivered();
        bytes
    }

    /// Answers `request` the way the UDP listener does: the local path, then
    /// upstream on a miss. Empty when no reply is owed.
    pub(crate) async fn respond<P>(
        engine: &QueryEngine<P>,
        request: &Message,
        received_at: Instant,
    ) -> Vec<u8>
    where
        P: PolicyEngine + Send + Sync + Unpin + 'static,
    {
        match resolve_query(engine, wire_query(request, received_at)) {
            Answer::Local(reply) => sent(reply),
            Answer::Miss(miss) => sent(answer_miss(engine, miss).await),
            Answer::Ignored => Vec::new(),
        }
    }

    /// The local path alone: `None` when the query needs upstream or owes no
    /// reply.
    pub(crate) fn respond_locally<P>(engine: &QueryEngine<P>, request: &Message) -> Option<Vec<u8>>
    where
        P: PolicyEngine + Send + Sync + Unpin + 'static,
    {
        match resolve_query(engine, wire_query(request, Instant::now())) {
            Answer::Local(reply) => Some(sent(reply)),
            Answer::Miss(_) | Answer::Ignored => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Duration;

    use antiwire_policy::{DomainDecision, RuleEngine};
    use hickory_proto::op::{Message, Query as Question};
    use hickory_proto::rr::{rdata, Name, RData, RecordType};
    use tower::ServiceExt;

    use super::*;
    use crate::messages::encode_message;
    use crate::response_cache::{CacheKey, QueryFlags, ResponseCache};
    use crate::settings::DnsConfig;

    struct CallFlagClassifier {
        called: Arc<AtomicBool>,
    }

    #[async_trait::async_trait]
    impl crate::ai::Classifier for CallFlagClassifier {
        async fn classify(
            &self,
            domain: &str,
        ) -> Result<antiwire_ai::DomainAssessment, crate::ai::classifier::ClassifierError> {
            self.called.store(true, Ordering::Release);
            Ok(crate::ai::classifier::test_helpers::assessment_for(
                domain, 0.95,
            ))
        }
    }

    fn retroactive_policy() -> crate::ai::AiPolicySnapshot {
        let settings = antiwire_store::DaemonSetting {
            ai_enabled: true,
            ai_decision_mode: "retroactive".to_owned(),
            ..Default::default()
        };
        crate::ai::AiPolicySnapshot::from_settings(&settings, 1)
    }

    use crate::test_support::leaked_store as test_store;

    fn classifying_ai() -> (Arc<AiCoordinator>, Arc<AtomicBool>) {
        let called = Arc::new(AtomicBool::new(false));
        let ai = AiCoordinator::new(
            test_store(),
            Some(Arc::new(CallFlagClassifier {
                called: Arc::clone(&called),
            })),
            &retroactive_policy(),
            None,
        );
        (ai, called)
    }

    use super::testing::wire_query;
    use crate::test_support::a_query as query_message;

    fn request_for(name: &str) -> Request {
        let query = wire_query(&query_message(0x1234, name), Instant::now());
        Request::from_bytes(query.wire, query.src, query.protocol).expect("hickory parses request")
    }

    fn response_with_work(name: &str, answer_count: usize) -> PreparedResponse {
        let mut response = Message::response(0, OpCode::Query);
        response.add_query(Question::query(
            Name::from_ascii(name).expect("response name"),
            RecordType::A,
        ));
        for index in 0..answer_count {
            response.add_answer(Record::from_rdata(
                Name::from_ascii(name).expect("answer name"),
                300,
                RData::A(rdata::A(std::net::Ipv4Addr::new(
                    192,
                    0,
                    2,
                    u8::try_from(index % 250 + 1).expect("bounded address"),
                ))),
            ));
        }
        prepare_uncached_message(
            response,
            Some(PostResponseWork {
                domain: name.trim_end_matches('.').to_owned(),
                was_block: false,
                eligible: true,
            }),
        )
    }

    fn edns_with(dnssec_ok: bool, max_payload: u16) -> Edns {
        let mut edns = Edns::new();
        edns.set_dnssec_ok(dnssec_ok);
        edns.set_max_payload(max_payload);
        edns
    }

    async fn wait_for(flag: &AtomicBool) {
        tokio::time::timeout(Duration::from_secs(1), async {
            while !flag.load(Ordering::Acquire) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("post-response classifier should run");
    }

    #[test]
    fn no_opt_is_returned_to_a_client_that_sent_none() {
        // RFC 6891: never hand an OPT record to a non-EDNS client.
        assert!(response_edns(None, None).is_none());
        assert!(response_edns(None, Some(&edns_with(true, 4096))).is_none());
    }

    /// Block and synthetic-error responses carry no OPT of their own, so the DO
    /// bit has to come from the request or it is silently dropped.
    #[test]
    fn synthetic_responses_echo_the_requested_do_bit() {
        let echoed = response_edns(Some(&edns_with(true, 1232)), None).expect("opt");
        assert!(echoed.flags().dnssec_ok);

        let cleared = response_edns(Some(&edns_with(false, 1232)), None).expect("opt");
        assert!(!cleared.flags().dnssec_ok);
    }

    #[test]
    fn upstream_opt_flags_survive_when_the_response_has_one() {
        let response =
            response_edns(Some(&edns_with(true, 1232)), Some(&edns_with(true, 4096))).expect("opt");
        assert!(response.flags().dnssec_ok);
        // The advertised size is always the client's, so the encoder truncates
        // at exactly what the client said it can receive.
        assert_eq!(response.max_payload(), 1232);
    }

    #[test]
    fn advertised_payload_size_is_clamped_to_the_supported_range() {
        let tiny = response_edns(Some(&edns_with(false, 12)), None).expect("opt");
        assert_eq!(tiny.max_payload(), min_udp_payload_size());

        let huge = response_edns(Some(&edns_with(false, u16::MAX)), None).expect("opt");
        assert_eq!(huge.max_payload(), max_udp_payload_size());
    }

    #[tokio::test]
    async fn cache_hit_uses_hickory_parse_trees_without_wire_round_trips() {
        let stub = Arc::new(QueryEngine::new(
            RuleEngine::new(),
            DnsConfig {
                upstreams: vec!["127.0.0.1:1".to_owned()],
                ..DnsConfig::default()
            },
        ));

        let mut query = query_message(0xCAFE, "ExAmPlE.example.");
        query.metadata.recursion_desired = true;

        let mut response = Message::response(0, OpCode::Query);
        response.metadata.recursion_available = true;
        response.add_query(Question::query(
            Name::from_ascii("example.example.").expect("response name"),
            RecordType::A,
        ));
        response.add_answer(Record::from_rdata(
            Name::from_ascii("example.example.").expect("answer name"),
            300,
            RData::A(rdata::A(std::net::Ipv4Addr::new(192, 0, 2, 1))),
        ));

        let mut cached = ResponseCache::entry_from_message(&response, false).expect("cache entry");
        cached.cached_at = Instant::now()
            .checked_sub(Duration::from_secs(10))
            .expect("instant supports subtraction");
        // A wire-based hit would copy and then fail to parse these bytes. The
        // service must instead use the parsed response retained at insertion.
        stub.response_cache().insert(
            CacheKey::from_query("example.example", RecordType::A, 1)
                .with_flags(QueryFlags::from_request(&query)),
            cached,
        );

        let answer = Resolve::new(stub).resolve(wire_query(&query, Instant::now()));
        let Answer::Local(reply) = answer else {
            panic!("cached response completes on the local fast path");
        };

        let decoded = Message::from_vec(reply.bytes()).expect("decode response");
        assert_eq!(decoded.metadata.id, 0xCAFE);
        assert_eq!(decoded.metadata.response_code, ResponseCode::NoError);
        assert_eq!(decoded.queries[0].name().to_utf8(), "ExAmPlE.example.");
        assert_eq!(decoded.answers.len(), 1);
        assert!(
            (289..=290).contains(&decoded.answers[0].ttl),
            "cached TTL is aged on the parsed response path"
        );
    }

    #[tokio::test]
    async fn forward_uses_the_ingress_deadline() {
        let blackhole = tokio::net::UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("blackhole bind");
        let stub = Arc::new(QueryEngine::new(
            RuleEngine::new(),
            DnsConfig {
                upstreams: vec![blackhole.local_addr().expect("address").to_string()],
                ..DnsConfig::default()
            },
        ));

        let received_at = Instant::now()
            .checked_sub(antiwire_tuning::DNS_QUERY_DEADLINE)
            .expect("instant supports subtraction");
        let answer = Resolve::new(Arc::clone(&stub)).resolve(wire_query(
            &query_message(0xD1E, "deadline.example."),
            received_at,
        ));
        let Answer::Miss(miss) = answer else {
            panic!("an uncached name needs upstream");
        };

        let started = Instant::now();
        let reply = Forward::new(stub).oneshot(miss).await.expect("infallible");
        let decoded = Message::from_vec(reply.bytes()).expect("decode response");
        assert_eq!(decoded.metadata.response_code, ResponseCode::ServFail);
        assert!(
            started.elapsed() < Duration::from_millis(100),
            "an already-expired ingress deadline must not enter upstream I/O"
        );
    }

    #[tokio::test]
    async fn a_panicking_local_path_answers_servfail() {
        struct PanickingPolicy;

        impl PolicyEngine for PanickingPolicy {
            fn evaluate_domain_with_source(&self, _domain: &str) -> Option<DomainDecision> {
                panic!("policy evaluation panicked");
            }
        }

        let stub = Arc::new(QueryEngine::new(
            PanickingPolicy,
            DnsConfig {
                upstreams: vec!["127.0.0.1:1".to_owned()],
                ..DnsConfig::default()
            },
        ));
        let answer = Resolve::new(stub).resolve(wire_query(
            &query_message(0xBAD, "panic.example."),
            Instant::now(),
        ));
        let Answer::Local(reply) = answer else {
            panic!("a panic is answered locally");
        };
        let decoded = Message::from_vec(reply.bytes()).expect("decode response");
        assert_eq!(decoded.metadata.id, 0xBAD);
        assert_eq!(decoded.metadata.response_code, ResponseCode::ServFail);
    }

    #[tokio::test]
    async fn responses_and_garbage_owe_no_reply() {
        let stub = Arc::new(QueryEngine::new(
            RuleEngine::new(),
            DnsConfig {
                upstreams: vec!["127.0.0.1:1".to_owned()],
                ..DnsConfig::default()
            },
        ));
        let resolve = Resolve::new(stub);

        let mut response = query_message(1, "response.example.");
        response.metadata.message_type = MessageType::Response;
        let mut garbage = wire_query(&response, Instant::now());
        garbage.wire.truncate(5);
        for query in [wire_query(&response, Instant::now()), garbage] {
            let answer = resolve.resolve(query);
            assert!(matches!(answer, Answer::Ignored));
        }
    }

    fn local_reply(resolve: &Resolve<RuleEngine>, wire: Vec<u8>) -> Message {
        let answer = resolve.resolve(Query {
            wire,
            src: "127.0.0.1:53000".parse().expect("client address"),
            protocol: Protocol::Udp,
            received_at: Instant::now(),
        });
        let Answer::Local(reply) = answer else {
            panic!("answered locally");
        };
        Message::from_vec(reply.bytes()).expect("decode reply")
    }

    fn offline_resolve() -> Resolve<RuleEngine> {
        Resolve::new(Arc::new(QueryEngine::new(
            RuleEngine::new(),
            DnsConfig {
                upstreams: vec!["127.0.0.1:1".to_owned()],
                ..DnsConfig::default()
            },
        )))
    }

    /// RFC 1035 §4.1.1 and RFC 6891 §6.1.1: a query with a readable header
    /// but a body that does not parse gets FORMERR, not silence.
    #[tokio::test]
    async fn unparseable_queries_get_formerr() {
        let resolve = offline_resolve();
        let mut query = query_message(0x5151, "formerr.example.");
        query.metadata.recursion_desired = true;
        query.set_edns(Edns::new());
        let wire = encode_message(&query).expect("encode query");

        // The question is cut off mid-name.
        let reply = local_reply(&resolve, wire[..16].to_vec());
        assert_eq!(reply.metadata.id, 0x5151);
        assert_eq!(reply.metadata.message_type, MessageType::Response);
        assert_eq!(reply.metadata.response_code, ResponseCode::FormErr);
        assert!(reply.metadata.recursion_desired, "RD is copied");
        assert!(reply.queries.is_empty());

        // A second OPT record: root name, type 41, class 4096, TTL 0, no data.
        let mut two_opts = wire;
        two_opts.extend_from_slice(&[0, 0, 41, 0x10, 0, 0, 0, 0, 0, 0, 0]);
        let additionals = u16::from_be_bytes([two_opts[10], two_opts[11]]) + 1;
        two_opts[10..12].copy_from_slice(&additionals.to_be_bytes());
        let reply = local_reply(&resolve, two_opts);
        assert_eq!(reply.metadata.response_code, ResponseCode::FormErr);
    }

    /// RFC 6891 §6.1.3: an EDNS version this resolver does not speak gets
    /// BADVERS, with a version 0 OPT.
    #[tokio::test]
    async fn an_unsupported_edns_version_gets_badvers() {
        let resolve = offline_resolve();
        let mut query = query_message(7, "badvers.example.");
        let mut edns = Edns::new();
        edns.set_version(1);
        query.set_edns(edns);
        let reply = local_reply(&resolve, encode_message(&query).expect("encode"));
        // RCODE 16 is BADVERS with an OPT and BADSIG with a TSIG, and hickory
        // decodes it as the latter, so compare the number.
        assert_eq!(u16::from(reply.metadata.response_code), 16);
        assert_eq!(reply.edns.as_ref().expect("reply OPT").version(), 0);
    }

    #[tokio::test]
    async fn post_ai_work_waits_for_the_transport_to_accept_the_reply() {
        let (ai, called) = classifying_ai();
        let reply = encode_prepared(
            &request_for("ordered.example."),
            response_with_work("ordered.example.", 1),
            Some(Arc::clone(&ai)),
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(
            !called.load(Ordering::Acquire),
            "nothing is submitted before the transport accepts the reply"
        );

        reply.delivered();
        wait_for(&called).await;
        ai.shutdown().await;
    }

    #[tokio::test]
    async fn an_undelivered_reply_drops_its_post_ai_work() {
        let (ai, called) = classifying_ai();
        let reply = encode_prepared(
            &request_for("send-error.example."),
            response_with_work("send-error.example.", 1),
            Some(Arc::clone(&ai)),
        );
        drop(reply);
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(!called.load(Ordering::Acquire));
        ai.shutdown().await;
    }

    #[tokio::test]
    async fn truncated_udp_reply_still_submits_ai_once_delivered() {
        let (ai, called) = classifying_ai();
        let reply = encode_prepared(
            &request_for("truncated.example."),
            response_with_work("truncated.example.", 40),
            Some(Arc::clone(&ai)),
        );
        assert!(
            reply.bytes().len() <= 512,
            "a non-EDNS client gets at most 512 bytes"
        );
        let response = Message::from_vec(reply.bytes()).expect("decode truncated response");
        assert!(response.metadata.truncation);
        assert!(
            response.answers.len() < 40,
            "only the records that fit are sent"
        );

        reply.delivered();
        wait_for(&called).await;
        ai.shutdown().await;
    }
}
