//! Shared helpers for antiwire-dns integration tests.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::response_cache::{CachedAnswer, ResponseCache};
use crate::service::testing::respond;
use crate::{encode_message, DnsConfig, QueryEngine};
use antiwire_policy::{DomainBlockSource, DomainDecision, PolicyEngine, Verdict};
use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::{rdata, Name, RData, Record, RecordType};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};
use tokio::task::JoinHandle;

/// Policy that allows all domains through.
pub struct AllowAllPolicy;

impl PolicyEngine for AllowAllPolicy {
    fn evaluate_domain_with_source(&self, _: &str) -> Option<DomainDecision> {
        None
    }
}

/// Policy that blocks a single domain.
pub struct BlockOnePolicy {
    pub domain: &'static str,
}

impl PolicyEngine for BlockOnePolicy {
    fn evaluate_domain_with_source(&self, domain: &str) -> Option<DomainDecision> {
        (domain == self.domain).then_some(DomainDecision {
            verdict: Verdict::Block,
            source: Some(DomainBlockSource::DnsRule),
        })
    }
}

/// AI settings that block a name judged malicious, in `mode`.
pub fn ai_policy(mode: &str) -> crate::ai::AiPolicySnapshot {
    let settings = antiwire_store::DaemonSetting {
        ai_enabled: true,
        ai_decision_mode: mode.to_owned(),
        ai_malicious_action: "block".to_owned(),
        ai_confidence_malicious: 80,
        ..Default::default()
    };
    crate::ai::AiPolicySnapshot::from_settings(&settings, 1)
}

/// A malicious score [`ai_policy`] lets through.
pub const BENIGN: f64 = 0.01;
/// A malicious score [`ai_policy`] blocks.
pub const MALICIOUS: f64 = 0.97;
/// A registration age, in days, that no new-domain setting blocks.
pub const OLD_DOMAIN: i64 = 4_000;
/// A registration age, in days, that every new-domain setting blocks.
pub const YOUNG_DOMAIN: i64 = 1;

/// `engine` behind both gates: proactive AI judging every name `malicious`
/// after `classifier`, and a registry that dates `domain` `age_days` old
/// after `lookup`. The coordinator is returned for the test to cancel.
pub fn behind_both_gates<P: PolicyEngine + Send + Sync>(
    engine: QueryEngine<P>,
    domain: &'static str,
    classifier: Duration,
    malicious: f64,
    lookup: Duration,
    age_days: i64,
) -> (QueryEngine<P>, Arc<crate::ai::AiCoordinator>) {
    use crate::new_domain::testing::{days_ago, FixedSource};
    use crate::new_domain::{NewDomainGuard, RegistrationCache};

    let registry = RegistrationCache::new(FixedSource::new([(domain, days_ago(age_days))], lookup));
    let engine = engine.with_new_domain_guard(NewDomainGuard::new(30, registry));
    let ai = crate::ai::AiCoordinator::new(
        crate::test_support::leaked_store(),
        Some(Arc::new(
            crate::ai::classifier::test_helpers::SlowClassifier {
                delay: classifier,
                malicious,
            },
        )),
        &ai_policy("proactive"),
        None,
    );
    engine.set_ai(Some(Arc::clone(&ai)));
    (engine, ai)
}

/// Whether `bytes` is a sinkhole block answer, the default block mode's.
pub fn sinkholed(bytes: &[u8]) -> bool {
    let response = Message::from_vec(bytes).expect("decode");
    response.answers.iter().any(|record| {
        matches!(
            record.data,
            RData::A(rdata::A(ip)) if ip.is_unspecified()
        )
    })
}

/// An answerless upstream reply carrying an authority SOA, as a zone serving
/// NXDOMAIN or NODATA does. `soa_ttl` and `minimum` are the two inputs to the
/// RFC 2308 negative TTL.
#[derive(Debug, Clone, Copy)]
pub struct NegativeAnswer {
    pub rcode: ResponseCode,
    pub soa_ttl: u32,
    pub minimum: u32,
}

/// Configuration for a local mock UDP upstream.
#[derive(Debug, Clone)]
pub struct MockUpstreamConfig {
    pub delay: Duration,
    pub respond: bool,
    pub ttl: u32,
    pub answer_ipv4: std::net::Ipv4Addr,
    /// A records per answer. Raise it past ~40 to push a response over the
    /// 512-byte UDP limit and exercise truncation.
    pub answer_count: u32,
    /// When set, reply with this negative answer instead of A records.
    pub negative: Option<NegativeAnswer>,
    /// Reply SERVFAIL to everything, as a zone that fails to resolve does.
    pub servfail: bool,
    /// Set AD on every reply, as a validating resolver would.
    pub authentic_data: bool,
    /// When set, reply with only a CNAME to this name and no address, as a
    /// resolver does when it will not resolve the target itself.
    pub alias_to: Option<&'static str>,
}

impl Default for MockUpstreamConfig {
    fn default() -> Self {
        Self {
            delay: Duration::ZERO,
            respond: true,
            ttl: 30,
            answer_ipv4: std::net::Ipv4Addr::new(93, 184, 216, 34),
            answer_count: 1,
            negative: None,
            servfail: false,
            authentic_data: false,
            alias_to: None,
        }
    }
}

/// Local DNS server that counts upstream exchanges.
pub struct MockUpstream {
    addr: SocketAddr,
    protocol: crate::DnsProtocol,
    call_count: Arc<AtomicU32>,
    received: Received,
    _task: JoinHandle<()>,
}

/// Every query the mock upstream received, in arrival order.
type Received = Arc<std::sync::Mutex<Vec<Message>>>;

/// The mock upstream's reply to `request`.
fn mock_response(config: &MockUpstreamConfig, request: &Message) -> Message {
    let mut response = match config.negative {
        _ if config.servfail => build_servfail_response(request),
        _ if config.alias_to.is_some() => {
            build_alias_response(request, config.ttl, config.alias_to.unwrap_or_default())
        }
        Some(negative) => build_negative_response(request, negative),
        None => build_a_response(request, config.ttl, config.answer_ipv4, config.answer_count),
    };
    response.metadata.authentic_data = config.authentic_data;
    response
}

impl MockUpstream {
    pub async fn start() -> Self {
        Self::start_with(MockUpstreamConfig::default()).await
    }

    pub async fn start_with(config: MockUpstreamConfig) -> Self {
        let socket = UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("bind mock upstream");
        let addr = socket.local_addr().expect("mock upstream addr");
        let call_count = Arc::new(AtomicU32::new(0));
        let calls = Arc::clone(&call_count);
        let received = Received::default();
        let queries = Arc::clone(&received);
        let config = Arc::new(config);

        let task = tokio::spawn(async move {
            let mut buf = vec![0u8; 512];
            loop {
                let Ok((len, peer)) = socket.recv_from(&mut buf).await else {
                    continue;
                };
                calls.fetch_add(1, Ordering::SeqCst);
                if config.delay > Duration::ZERO {
                    tokio::time::sleep(config.delay).await;
                }
                if !config.respond {
                    continue;
                }
                let Ok(request) = Message::from_vec(&buf[..len]) else {
                    continue;
                };
                queries.lock().expect("received").push(request.clone());
                let response = mock_response(&config, &request);
                if let Ok(wire) = encode_message(&response) {
                    let _ = socket.send_to(&wire, peer).await;
                }
            }
        });

        Self {
            addr,
            protocol: crate::DnsProtocol::Udp,
            call_count,
            received,
            _task: task,
        }
    }

    /// Stream-transport upstream, standing in for DoH/DoT/DoQ in tests.
    ///
    /// A UDP upstream cannot return more than the 512 bytes a non-EDNS query
    /// asks for, so oversized answers can only be produced over a stream.
    pub async fn start_tcp_with(config: MockUpstreamConfig) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind mock tcp upstream");
        let addr = listener.local_addr().expect("mock tcp upstream addr");
        let call_count = Arc::new(AtomicU32::new(0));
        let calls = Arc::clone(&call_count);
        let received = Received::default();
        let queries = Arc::clone(&received);
        let config = Arc::new(config);

        let task = tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    continue;
                };
                let calls = Arc::clone(&calls);
                let queries = Arc::clone(&queries);
                let config = Arc::clone(&config);
                tokio::spawn(async move {
                    loop {
                        let mut prefix = [0u8; 2];
                        if stream.read_exact(&mut prefix).await.is_err() {
                            return;
                        }
                        let mut body = vec![0u8; usize::from(u16::from_be_bytes(prefix))];
                        if stream.read_exact(&mut body).await.is_err() {
                            return;
                        }
                        calls.fetch_add(1, Ordering::SeqCst);
                        if config.delay > Duration::ZERO {
                            tokio::time::sleep(config.delay).await;
                        }
                        if !config.respond {
                            continue;
                        }
                        let Ok(request) = Message::from_vec(&body) else {
                            return;
                        };
                        queries.lock().expect("received").push(request.clone());
                        let response = mock_response(&config, &request);
                        let Ok(wire) = encode_message(&response) else {
                            return;
                        };
                        let Ok(len) = u16::try_from(wire.len()) else {
                            return;
                        };
                        if stream.write_all(&len.to_be_bytes()).await.is_err()
                            || stream.write_all(&wire).await.is_err()
                        {
                            return;
                        }
                    }
                });
            }
        });

        Self {
            addr,
            protocol: crate::DnsProtocol::Tcp,
            call_count,
            received,
            _task: task,
        }
    }

    #[must_use]
    pub fn endpoint(&self) -> String {
        self.addr.to_string()
    }

    #[must_use]
    pub fn protocol(&self) -> crate::DnsProtocol {
        self.protocol
    }

    #[must_use]
    pub fn calls(&self) -> u32 {
        self.call_count.load(Ordering::SeqCst)
    }

    /// Every query received so far.
    #[must_use]
    pub fn received(&self) -> Vec<Message> {
        self.received.lock().expect("received").clone()
    }
}

/// Scriptable loopback upstream used by the DNS hot-path regression suite.
pub struct ControlledUpstream {
    addr: SocketAddr,
    protocol: crate::DnsProtocol,
    inner: Arc<ControlledInner>,
    _task: JoinHandle<()>,
}

struct ControlledInner {
    calls: AtomicU32,
    drop_remaining: AtomicU32,
    respond: AtomicBool,
    arrivals: std::sync::Mutex<Vec<Instant>>,
}

impl ControlledUpstream {
    pub async fn drop_then_answer() -> Self {
        Self::spawn(1, true).await
    }

    pub async fn silent() -> Self {
        Self::spawn(0, false).await
    }

    async fn spawn(drop_remaining: u32, respond: bool) -> Self {
        let socket = UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("bind controlled upstream");
        let addr = socket.local_addr().expect("controlled upstream addr");
        let inner = Arc::new(ControlledInner {
            calls: AtomicU32::new(0),
            drop_remaining: AtomicU32::new(drop_remaining),
            respond: AtomicBool::new(respond),
            arrivals: std::sync::Mutex::new(Vec::new()),
        });
        let state = Arc::clone(&inner);
        let task = tokio::spawn(async move {
            let mut buf = vec![0u8; 512];
            loop {
                let Ok((len, peer)) = socket.recv_from(&mut buf).await else {
                    continue;
                };
                state.calls.fetch_add(1, Ordering::SeqCst);
                state
                    .arrivals
                    .lock()
                    .expect("arrivals")
                    .push(Instant::now());
                if state.drop_remaining.load(Ordering::SeqCst) > 0 {
                    state.drop_remaining.fetch_sub(1, Ordering::SeqCst);
                    continue;
                }
                if !state.respond.load(Ordering::SeqCst) {
                    continue;
                }
                let Ok(request) = Message::from_vec(&buf[..len]) else {
                    continue;
                };
                let response =
                    build_a_response(&request, 30, std::net::Ipv4Addr::new(93, 184, 216, 34), 1);
                if let Ok(wire) = encode_message(&response) {
                    let _ = socket.send_to(&wire, peer).await;
                }
            }
        });
        Self {
            addr,
            protocol: crate::DnsProtocol::Udp,
            inner,
            _task: task,
        }
    }

    pub fn become_responsive(&self) {
        self.inner.drop_remaining.store(0, Ordering::SeqCst);
        self.inner.respond.store(true, Ordering::SeqCst);
    }

    #[must_use]
    pub fn endpoint(&self) -> String {
        self.addr.to_string()
    }

    #[must_use]
    pub fn protocol(&self) -> crate::DnsProtocol {
        self.protocol
    }

    #[must_use]
    pub fn calls(&self) -> u32 {
        self.inner.calls.load(Ordering::SeqCst)
    }

    #[must_use]
    pub fn arrivals(&self) -> Vec<Instant> {
        self.inner.arrivals.lock().expect("arrivals").clone()
    }
}

pub fn stub_config_with_controlled(upstream: &ControlledUpstream) -> DnsConfig {
    DnsConfig {
        protocol: upstream.protocol(),
        upstreams: vec![upstream.endpoint()],
        ..DnsConfig::default()
    }
}

pub fn stub_config_with_upstream(upstream: &MockUpstream) -> DnsConfig {
    DnsConfig {
        protocol: upstream.protocol(),
        upstreams: vec![upstream.endpoint()],
        ..DnsConfig::default()
    }
}

pub fn build_query(name: &str, qtype: RecordType, id: u16) -> Message {
    let fqdn = Name::from_ascii(format!("{name}.")).expect("name");
    let mut query = Message::new(id, MessageType::Query, OpCode::Query);
    query.add_query(Query::query(fqdn, qtype));
    query
}

pub fn encode_query(name: &str, qtype: RecordType, id: u16) -> Vec<u8> {
    encode_message(&build_query(name, qtype, id)).expect("encode query")
}

/// SERVFAIL echoing the question.
fn build_servfail_response(request: &Message) -> Message {
    let mut response = Message::response(request.metadata.id, OpCode::Query);
    response.metadata.response_code = ResponseCode::ServFail;
    response.metadata.recursion_available = true;
    if let Some(question) = request.queries.first() {
        response.add_query(question.clone());
    }
    response
}

/// NXDOMAIN or NODATA with an authority SOA, the shape a real zone returns.
fn build_negative_response(request: &Message, negative: NegativeAnswer) -> Message {
    let question = request
        .queries
        .first()
        .expect("mock upstream query")
        .clone();
    let mut response = Message::response(request.metadata.id, OpCode::Query);
    response.metadata.response_code = negative.rcode;
    response.metadata.recursion_available = true;
    response.add_query(question.clone());

    let zone = question.name().base_name().trim_to(2).to_lowercase();
    response.add_authority(Record::from_rdata(
        zone.clone(),
        negative.soa_ttl,
        RData::SOA(rdata::SOA::new(
            zone.clone(),
            zone,
            20_240_101,
            7200,
            3600,
            1_209_600,
            negative.minimum,
        )),
    ));
    response
}

fn build_a_response(
    request: &Message,
    ttl: u32,
    ipv4: std::net::Ipv4Addr,
    answer_count: u32,
) -> Message {
    let question = request
        .queries
        .first()
        .expect("mock upstream query")
        .clone();
    let mut response = Message::response(request.metadata.id, OpCode::Query);
    response.metadata.response_code = ResponseCode::NoError;
    response.add_query(question.clone());
    for index in 0..answer_count.max(1) {
        // Distinct addresses so a truncated answer is obviously short, rather
        // than plausibly deduplicated.
        let mut octets = ipv4.octets();
        octets[3] = octets[3].wrapping_add(u8::try_from(index % 256).unwrap_or(0));
        response.add_answer(Record::from_rdata(
            question.name().clone(),
            ttl,
            RData::A(rdata::A(std::net::Ipv4Addr::from(octets))),
        ));
    }
    response
}

fn build_alias_response(request: &Message, ttl: u32, target: &str) -> Message {
    let question = request
        .queries
        .first()
        .expect("mock upstream query")
        .clone();
    let mut response = Message::response(request.metadata.id, OpCode::Query);
    response.metadata.response_code = ResponseCode::NoError;
    response.add_query(question.clone());
    response.add_answer(Record::from_rdata(
        question.name().clone(),
        ttl,
        RData::CNAME(rdata::CNAME(
            Name::from_ascii(target).expect("alias target"),
        )),
    ));
    response
}

pub fn allow_policy() -> AllowAllPolicy {
    AllowAllPolicy
}

/// Builds the cache entry a positive A answer for `name` would produce.
///
/// Seeding through the same constructor the resolver uses keeps the parsed
/// message, TTLs, and serve-stale window real instead of hand-assembled.
/// Callers place the entry in its window (`fresh_until`, `stale_until`,
/// `prefetch_at`) and insert it under their own key.
pub fn positive_cache_entry(name: &str, ipv4: Ipv4Addr, ttl: u32) -> CachedAnswer {
    let fqdn = Name::from_ascii(format!("{name}.")).expect("name");
    let mut response = Message::response(0, OpCode::Query);
    response.metadata.recursion_available = true;
    response.add_query(Query::query(fqdn.clone(), RecordType::A));
    response.add_answer(Record::from_rdata(fqdn, ttl, RData::A(rdata::A(ipv4))));
    ResponseCache::entry_from_message(&response, false).expect("cache entry")
}

/// Polls `condition` until it holds, panicking with `what` if `timeout` elapses
/// first. Waiting on the effect beats sleeping a fixed guess at how long an
/// asynchronous worker needs.
pub async fn wait_until(timeout: Duration, what: &str, mut condition: impl FnMut() -> bool) {
    tokio::time::timeout(timeout, async {
        while !condition() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("{what} did not happen within {timeout:?}"));
}

/// Drives `stub`'s async wire path (`QueryEngine::handle_wire`) and parses the
/// response back to a `Message`.
///
/// This is not the production request path: `service::Resolve` hands an
/// already-parsed `Request` to the stub. Tests that need to cover request
/// parsing and policy-before-cache ordering drive the services directly rather
/// than through this helper.
pub async fn forward<P>(stub: &QueryEngine<P>, request: &Message) -> crate::Result<Message>
where
    P: PolicyEngine + Send + Sync + Unpin + 'static,
{
    let bytes = respond(stub, request, std::time::Instant::now()).await;
    Message::from_vec(&bytes).map_err(|error| crate::DnsError::InvalidQuery(error.to_string()))
}
