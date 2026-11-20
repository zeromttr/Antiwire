//! Reply-path cost of naming the process behind a query.
//!
//! The `hot` group measures cache hits with no hint sink, but the daemon
//! always installs one, so every served answer and every block is also
//! attributed to the client socket. Each query here comes from a freshly bound
//! UDP socket, as a stub resolver's would, and only the handler call is timed.

use std::net::{SocketAddr, UdpSocket};
use std::sync::Arc;
use std::time::{Duration, Instant};

use antiwire_policy::{DomainBlockSource, DomainDecision, PolicyEngine, RuleEngine, Verdict};
use hickory_proto::op::{Message, MessageType, OpCode, Query};
use hickory_proto::rr::{rdata, Name, RData, Record, RecordType};

use crate::block::{DnsBlockSink, DnsQueryContext};
use crate::listener::Transport;
use crate::messages::encode_message;
use crate::port_mapper::Scans;
use crate::query_engine::{EngineServices, QueryEngine};
use crate::response_cache::{CacheKey, QueryFlags, ResponseCache};
use crate::service::{answer_locally, parse};
use crate::settings::DnsConfig;
use crate::DnsHintSink;

const QUERIES: usize = 2_000;
const ROUNDS: usize = 5;

/// A hint and block sink that keeps nothing, so the reply path's own work is
/// what is measured.
pub(super) struct NoopSink;

impl DnsHintSink for NoopSink {
    fn record_hint(&self, _: u32, _: &str, _: &[std::net::IpAddr], _: u64, _: u64) {}
    fn record_resolution(&self, _: &str, _: &[std::net::IpAddr]) {}
}

impl DnsBlockSink for NoopSink {
    fn record_blocked_query(&self, _: &str, _: u32, _: &[String]) {}
}

struct BlockAll;

impl PolicyEngine for BlockAll {
    fn evaluate_domain_with_source(&self, _: &str) -> Option<DomainDecision> {
        Some(DomainDecision {
            verdict: Verdict::Block,
            source: Some(DomainBlockSource::DnsRule),
        })
    }
}

/// Where each query's source port comes from.
#[derive(Clone, Copy)]
enum Client {
    /// A socket bound just before its query, as a stub resolver binds one.
    FreshSocket,
    /// One long-lived socket, already in the socket-table snapshot.
    SameSocket,
}

pub(super) fn run() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("bench runtime");
    runtime.block_on(async {
        println!(
            "attribution: recorded owners available={}",
            crate::port_mapper::recorded_owners_available()
        );
        for (label, sink, client) in [
            ("cache_hit no_sink", false, Client::FreshSocket),
            ("cache_hit sink same_socket", true, Client::SameSocket),
            ("cache_hit sink fresh_socket", true, Client::FreshSocket),
        ] {
            let engine = hit_engine(sink);
            report(label, &engine, client);
        }
        for (label, sink, client) in [
            ("block no_sink", false, Client::FreshSocket),
            ("block sink same_socket", true, Client::SameSocket),
            ("block sink fresh_socket", true, Client::FreshSocket),
        ] {
            let engine = block_engine(sink);
            report(label, &engine, client);
        }
    });
}

fn config() -> DnsConfig {
    DnsConfig {
        upstreams: vec!["127.0.0.1:1".to_owned()],
        ..DnsConfig::default()
    }
}

fn hit_engine(sink: bool) -> QueryEngine<RuleEngine> {
    let engine = QueryEngine::try_new(RuleEngine::new(), &config(), EngineServices::default())
        .expect("engine");
    if sink {
        engine.set_hint_sink(Arc::new(NoopSink));
    }
    let query = query_message();
    let mut response = Message::response(0, OpCode::Query);
    response.metadata.recursion_available = true;
    response.queries.clone_from(&query.queries);
    response.add_answer(Record::from_rdata(
        Name::from_ascii("attr.perf.example.").expect("name"),
        300,
        RData::A(rdata::A(std::net::Ipv4Addr::new(192, 0, 2, 1))),
    ));
    engine.response_cache().insert(
        CacheKey::from_query("attr.perf.example", RecordType::A, 1)
            .with_flags(QueryFlags::from_request(&query)),
        ResponseCache::entry_from_message(&response, false).expect("cache entry"),
    );
    engine
}

fn block_engine(sink: bool) -> QueryEngine<BlockAll> {
    let block_sink: Option<Arc<dyn DnsBlockSink>> = sink.then(|| Arc::new(NoopSink) as _);
    QueryEngine::try_new(
        BlockAll,
        &config(),
        EngineServices {
            block_sink,
            ..EngineServices::default()
        },
    )
    .expect("engine")
}

fn query_message() -> Message {
    let mut query = Message::new(0xBEEF, MessageType::Query, OpCode::Query);
    query.metadata.recursion_desired = true;
    query.add_query(Query::query(
        Name::from_ascii("attr.perf.example.").expect("name"),
        RecordType::A,
    ));
    query
}

fn report<P>(label: &str, engine: &QueryEngine<P>, client: Client)
where
    P: PolicyEngine + Send + Sync + Unpin + 'static,
{
    // Parsed from the wire, as the listener would.
    let wire = encode_message(&query_message()).expect("encode");
    let (request, questions) = parse(&wire).expect("parse request");
    let same = UdpSocket::bind("127.0.0.1:0").expect("bind");
    let mut rounds = Vec::with_capacity(ROUNDS);
    for _ in 0..=ROUNDS {
        let mut samples = Vec::with_capacity(QUERIES);
        for _ in 0..QUERIES {
            let fresh = matches!(client, Client::FreshSocket)
                .then(|| UdpSocket::bind("127.0.0.1:0").expect("bind"));
            let src: SocketAddr = fresh
                .as_ref()
                .unwrap_or(&same)
                .local_addr()
                .expect("local addr");
            let start = Instant::now();
            let context = DnsQueryContext {
                client_addr: src.ip(),
                client_port: src.port(),
                transport: Transport::Udp,
                received_at: start,
            };
            let reply = answer_locally(engine, &request, questions, context, Scans::Here);
            samples.push(start.elapsed());
            assert!(matches!(reply, Ok(Some(_))), "{label}: answered locally");
        }
        rounds.push(samples);
    }
    // The first round warms the snapshot and the workers.
    rounds.remove(0);
    let mut all: Vec<Duration> = rounds.into_iter().flatten().collect();
    all.sort_unstable();
    let at = |permille| {
        super::percentile(&all, permille).map_or(f64::NAN, |latency| latency.as_secs_f64() * 1e6)
    };
    let mean = all.iter().sum::<Duration>().as_secs_f64() * 1e6
        / f64::from(u32::try_from(all.len()).expect("sample count"));
    println!(
        "attribution {label}: n={} us mean={mean:.1} p50={:.1} p90={:.1} p99={:.1} max={:.1}",
        all.len(),
        at(500),
        at(900),
        at(990),
        at(1_000)
    );
}
