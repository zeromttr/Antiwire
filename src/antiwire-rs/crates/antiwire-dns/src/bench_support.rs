//! Bench-only entry points.
//!
//! Compiled behind the `bench-internals` feature so the `dns_hot_path` bench
//! can drive the real request handler and the Windows socket-table capture
//! without widening the crate's normal API.

mod attribution;
mod listener;
mod upstream;

use std::sync::Arc;
use std::time::{Duration, Instant};

use antiwire_policy::RuleEngine;
use hickory_proto::op::{Edns, Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::{rdata, Name, RData, Record, RecordType};
use hickory_server::net::xfer::Protocol;
use hickory_server::server::Request;

use crate::messages::encode_message;
use crate::query_engine::{EngineServices, QueryEngine};
use crate::response_cache::{CacheKey, QueryFlags, ResponseCache};
use crate::service::{answer_locally, Reply};
use crate::settings::DnsConfig;

/// Runs the benchmark groups named on the command line, or every default group.
///
/// Groups: `hot` (handler cache hit and socket snapshot), `attribution`
/// (owner lookups on the reply path), `listener`
/// (loopback socket loops), `upstream` (mock-upstream failover), and the
/// opt-in `upstream-live` (real providers; needs network access).
pub fn run() {
    let groups: Vec<String> = std::env::args()
        .skip(1)
        .filter(|arg| !arg.starts_with("--"))
        .collect();
    let wanted = |group: &str| {
        if groups.is_empty() {
            group != "upstream-live"
        } else {
            groups.iter().any(|name| name == group)
        }
    };
    if wanted("hot") {
        measure_production_cache_hit();
        #[cfg(windows)]
        crate::port_mapper::run_snapshot_benchmark();
    }
    if wanted("attribution") {
        attribution::run();
    }
    if wanted("listener") {
        listener::run();
    }
    if wanted("upstream") {
        upstream::run();
    }
    if wanted("upstream-live") {
        upstream::run_live();
    }
}

/// The sample `permille` thousandths of the way through `sorted` (500 is the
/// median, 1000 the maximum), or `None` when there are no samples.
fn percentile(sorted: &[Duration], permille: usize) -> Option<Duration> {
    sorted
        .get(sorted.len().saturating_sub(1) * permille / 1_000)
        .copied()
}

fn edns_with(dnssec_ok: bool, max_payload: u16) -> Edns {
    let mut edns = Edns::new();
    edns.set_dnssec_ok(dnssec_ok);
    edns.set_max_payload(max_payload);
    edns
}

/// Measures the production cache-hit path the listeners take after parsing,
/// including response encoding, for one-answer and many-answer entries.
fn measure_production_cache_hit() {
    const BATCH_SIZE: u32 = 20_000;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("bench runtime");
    runtime.block_on(async {
        for answer_count in [1u8, 100] {
            let stub = Arc::new(
                QueryEngine::try_new(
                    RuleEngine::new(),
                    &DnsConfig {
                        upstreams: vec!["127.0.0.1:1".to_owned()],
                        ..DnsConfig::default()
                    },
                    EngineServices::default(),
                )
                .expect("dns stub"),
            );
            let mut query = Message::new(0xCAFE, MessageType::Query, OpCode::Query);
            query.metadata.recursion_desired = true;
            query.add_query(Query::query(
                Name::from_ascii("CaChE.PeRf.example.").expect("query name"),
                RecordType::A,
            ));
            query.edns = Some(edns_with(false, 4096));
            let request = Request::from_bytes(
                encode_message(&query).expect("encode query"),
                "127.0.0.1:53000".parse().expect("client address"),
                Protocol::Udp,
            )
            .expect("parse request");
            let mut response = Message::response(0, OpCode::Query);
            response.metadata.recursion_available = true;
            response.queries.clone_from(&query.queries);
            response.edns.clone_from(&query.edns);
            for index in 0..answer_count {
                response.add_answer(Record::from_rdata(
                    Name::from_ascii("cache.perf.example.").expect("answer name"),
                    300,
                    RData::A(rdata::A(std::net::Ipv4Addr::new(192, 0, 2, index))),
                ));
            }
            let mut cached =
                ResponseCache::entry_from_message(&response, false).expect("cache entry");
            cached.cached_at = Instant::now()
                .checked_sub(Duration::from_secs(10))
                .expect("cache age");
            let cached_at = cached.cached_at;
            stub.response_cache().insert(
                CacheKey::from_query("cache.perf.example", RecordType::A, 1)
                    .with_flags(QueryFlags::from_request(&query)),
                cached,
            );
            let hit = || -> Reply {
                answer_locally(&stub, &request, Instant::now())
                    .ok()
                    .flatten()
                    .expect("seeded name is a cache hit")
            };
            for _ in 0..100 {
                std::hint::black_box(hit());
            }
            let mut samples = Vec::with_capacity(9);
            for _ in 0..9 {
                let oldest_ttl = 300u32.saturating_sub(
                    u32::try_from(cached_at.elapsed().as_secs()).unwrap_or(u32::MAX),
                );
                let start = Instant::now();
                let mut last = None;
                for _ in 0..BATCH_SIZE {
                    last = Some(std::hint::black_box(hit()));
                }
                samples.push(start.elapsed().as_nanos() / u128::from(BATCH_SIZE));
                // Decode outside the measured region; validate each batch's
                // final response still preserves the production cache contract.
                let reply = last.expect("reply");
                let decoded = Message::from_vec(reply.bytes()).expect("valid response");
                assert_eq!(decoded.metadata.id, query.metadata.id);
                assert_eq!(decoded.queries, query.queries);
                assert_eq!(decoded.metadata.response_code, ResponseCode::NoError);
                assert_eq!(decoded.answers.len(), usize::from(answer_count));
                let newest_ttl = 300u32.saturating_sub(
                    u32::try_from(cached_at.elapsed().as_secs()).unwrap_or(u32::MAX),
                );
                assert!(decoded
                    .answers
                    .iter()
                    .all(|record| (newest_ttl..=oldest_ttl).contains(&record.ttl)));
            }
            samples.sort_unstable();
            println!("production_cache_hit answers={answer_count} batches=9 queries_per_batch={BATCH_SIZE} ns/query median={} min={} max={}",
                samples[4], samples[0], samples[8]);
        }
    });
}
