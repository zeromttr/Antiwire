//! Upstream failover benchmarks, measured from the client side.
//!
//! Each scenario starts the production [`DnsListener`] on loopback in front of
//! two mock UDP upstreams whose behaviour can be switched at runtime — healthy,
//! slow, silent, or dropping a share of queries — and times cache misses as a
//! client sees them. Nothing here touches upstream internals, so the same
//! scenarios measure any replacement of the failover engine.
//!
//! The mocks only speak plain UDP, which cannot express the port-853 primary
//! with a `DoH` fallback. The opt-in `upstream-live` group covers that against
//! real providers instead.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use antiwire_policy::RuleEngine;
use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::{rdata, Name, RData, Record, RecordType};
use tokio::net::UdpSocket;
use tokio::runtime::Runtime;

use crate::listener::DnsListener;
use crate::messages::encode_message;
use crate::query_engine::{EngineServices, QueryEngine};
use crate::response_cache::{CacheKey, QueryFlags, ResponseCache};
use crate::settings::{DnsConfig, DnsProtocol};
use crate::upstream::resolve_upstream_urls;

/// Longer than the 2s query deadline, so a client timeout means the server
/// never answered rather than answered late.
const CLIENT_TIMEOUT: Duration = Duration::from_secs(3);
const ZONE: &str = "upstream-bench.net.";

/// Runs the mock-upstream scenarios.
pub(super) fn run() {
    let server = runtime("dns-bench-server");
    let clients = runtime("dns-bench-client");

    clients.block_on(async {
        println!("upstream scenarios: two mock UDP upstreams, sequential client, unique names");
        steady_state(&server, "healthy", 200, |_, _| {}).await;
        steady_state(&server, "first_slow_300ms", 100, |first, _| {
            first.delay_ms.store(300, Ordering::Relaxed);
        })
        .await;
        steady_state(&server, "second_slow_300ms", 100, |_, second| {
            second.delay_ms.store(300, Ordering::Relaxed);
        })
        .await;
        steady_state(&server, "first_dead", 100, |first, _| {
            first.silent.store(true, Ordering::Relaxed);
        })
        .await;
        steady_state(&server, "second_dead", 100, |_, second| {
            second.silent.store(true, Ordering::Relaxed);
        })
        .await;
        steady_state(&server, "first_drops_30pct", 200, |first, _| {
            first.drop_percent.store(30, Ordering::Relaxed);
        })
        .await;
        outage_and_recovery(&server).await;
    });
}

/// Runs the opt-in scenarios against real public resolvers.
pub(super) fn run_live() {
    let server = runtime("dns-bench-server");
    let clients = runtime("dns-bench-client");
    clients.block_on(async {
        println!("upstream live scenarios: real providers, NXDOMAIN names, sequential client");
        for (protocol, provider) in [
            ("doh", "cloudflare"),
            ("dot", "cloudflare"),
            ("doq", "quad9"),
        ] {
            let parsed = DnsProtocol::from_settings(protocol);
            let upstreams = resolve_upstream_urls(parsed, provider, "");
            let config = DnsConfig::from_settings(parsed, &upstreams, "", "", false, true);
            let mut bench = Bench::start(&server, config).await;
            let label = format!("live_{protocol}_{provider} endpoints={}", upstreams.len());
            let samples = bench.ask_many(30, "example.com.").await;
            report(&label, &samples, None);
            bench.stop(&server).await;
        }
    });
}

fn runtime(name: &str) -> Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .thread_name(name)
        .enable_all()
        .build()
        .expect("bench runtime")
}

/// Switches applied to one mock upstream.
#[derive(Default)]
struct Behavior {
    silent: AtomicBool,
    delay_ms: AtomicU64,
    drop_percent: AtomicU64,
    received: AtomicU64,
}

struct MockUpstream {
    addr: SocketAddr,
    behavior: Arc<Behavior>,
    task: tokio::task::JoinHandle<()>,
}

impl MockUpstream {
    async fn start() -> Self {
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.expect("mock bind"));
        let addr = socket.local_addr().expect("mock address");
        let behavior = Arc::new(Behavior::default());
        let task = tokio::spawn(serve_mock(socket, Arc::clone(&behavior)));
        Self {
            addr,
            behavior,
            task,
        }
    }
}

impl Drop for MockUpstream {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn serve_mock(socket: Arc<UdpSocket>, behavior: Arc<Behavior>) {
    let mut buffer = [0u8; 4096];
    loop {
        let Ok((len, src)) = socket.recv_from(&mut buffer).await else {
            continue;
        };
        let count = behavior.received.fetch_add(1, Ordering::Relaxed) + 1;
        if behavior.silent.load(Ordering::Relaxed)
            || scatter(count) < behavior.drop_percent.load(Ordering::Relaxed)
        {
            continue;
        }
        let Ok(query) = Message::from_vec(&buffer[..len]) else {
            continue;
        };
        let delay = Duration::from_millis(behavior.delay_ms.load(Ordering::Relaxed));
        let socket = Arc::clone(&socket);
        tokio::spawn(async move {
            if !delay.is_zero() {
                tokio::time::sleep(delay).await;
            }
            let _ = socket.send_to(&answer_for(&query), src).await;
        });
    }
}

/// Spreads the query sequence evenly over 0..100 without a random source, so
/// a drop percentage is exact over every 100 queries and repeatable.
fn scatter(count: u64) -> u64 {
    count.wrapping_mul(37) % 100
}

fn answer_for(query: &Message) -> Vec<u8> {
    let mut response = Message::response(query.metadata.id, OpCode::Query);
    response.metadata.recursion_desired = query.metadata.recursion_desired;
    response.metadata.recursion_available = true;
    response.queries.clone_from(&query.queries);
    response.edns.clone_from(&query.edns);
    if let Some(question) = query.queries.first() {
        response.add_answer(Record::from_rdata(
            question.name().clone(),
            300,
            RData::A(rdata::A(std::net::Ipv4Addr::new(192, 0, 2, 7))),
        ));
    }
    encode_message(&response).expect("encode mock answer")
}

/// A listener in front of the configured upstreams, plus one client socket.
struct Bench {
    listener: DnsListener,
    stub: Arc<QueryEngine<RuleEngine>>,
    server_addr: SocketAddr,
    client: UdpSocket,
    next_id: u16,
    next_name: u64,
}

impl Bench {
    async fn start(server: &Runtime, config: DnsConfig) -> Self {
        let stub = Arc::new(
            QueryEngine::try_new(RuleEngine::new(), &config, EngineServices::default())
                .expect("dns stub"),
        );
        let started = Arc::clone(&stub);
        let listener = server
            .spawn(async move {
                DnsListener::start_on(started, "127.0.0.1:0".parse().expect("bench address"))
                    .expect("bench listener")
            })
            .await
            .expect("listener start task");
        let server_addr = listener.udp_addr();
        let client = UdpSocket::bind("127.0.0.1:0").await.expect("client bind");
        Self {
            listener,
            stub,
            server_addr,
            client,
            next_id: 1,
            next_name: 0,
        }
    }

    async fn stop(self, server: &Runtime) {
        let mut listener = self.listener;
        server
            .spawn(async move { listener.shutdown().await })
            .await
            .expect("shutdown task")
            .expect("bench listener shutdown");
    }

    fn fresh_name(&mut self, zone: &str) -> String {
        self.next_name += 1;
        format!("q{}.{zone}", self.next_name)
    }

    async fn ask(&mut self, name: &str) -> Sample {
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1).max(1);
        let wire = encode_message(&query_for(id, name)).expect("encode query");
        let started = Instant::now();
        self.client
            .send_to(&wire, self.server_addr)
            .await
            .expect("send query");
        let mut buffer = [0u8; 4096];
        let deadline = started + CLIENT_TIMEOUT;
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            let Ok(Ok((len, _))) =
                tokio::time::timeout(remaining, self.client.recv_from(&mut buffer)).await
            else {
                return Sample {
                    latency: started.elapsed(),
                    outcome: Outcome::NoReply,
                };
            };
            let Ok(reply) = Message::from_vec(&buffer[..len]) else {
                continue;
            };
            // A late reply to an earlier query is not this one's answer.
            if reply.metadata.id != id {
                continue;
            }
            let outcome = match reply.metadata.response_code {
                ResponseCode::NoError if !reply.answers.is_empty() => {
                    if reply.answers.iter().all(|record| record.ttl <= 1) {
                        Outcome::Stale
                    } else {
                        Outcome::Answer
                    }
                }
                ResponseCode::NoError | ResponseCode::NXDomain => Outcome::Answer,
                ResponseCode::ServFail => Outcome::ServFail,
                _ => Outcome::Other,
            };
            return Sample {
                latency: started.elapsed(),
                outcome,
            };
        }
    }

    async fn ask_many(&mut self, count: usize, zone: &str) -> Vec<Sample> {
        let mut samples = Vec::with_capacity(count);
        for _ in 0..count {
            let name = self.fresh_name(zone);
            samples.push(self.ask(&name).await);
        }
        samples
    }

    /// Caches `name` as an answer already past its TTL but inside the
    /// serve-stale window, as if it had been resolved a while ago.
    fn seed_stale(&self, name: &str) {
        let query = query_for(0, name);
        let mut response = Message::response(0, OpCode::Query);
        response.metadata.recursion_available = true;
        response.queries.clone_from(&query.queries);
        response.add_answer(Record::from_rdata(
            Name::from_ascii(name).expect("stale name"),
            60,
            RData::A(rdata::A(std::net::Ipv4Addr::new(192, 0, 2, 9))),
        ));
        let mut entry = ResponseCache::entry_from_message(&response, false).expect("cache entry");
        let now = Instant::now();
        entry.cached_at = now.checked_sub(Duration::from_secs(120)).expect("instant");
        entry.fresh_until = now.checked_sub(Duration::from_secs(60)).expect("instant");
        entry.prefetch_at = entry.fresh_until;
        entry.stale_until = now + Duration::from_secs(3_600);
        self.stub.response_cache().insert(
            CacheKey::from_query(name.trim_end_matches('.'), RecordType::A, 1)
                .with_flags(QueryFlags::from_request(&query)),
            entry,
        );
    }
}

fn query_for(id: u16, name: &str) -> Message {
    let mut query = Message::new(id, MessageType::Query, OpCode::Query);
    query.metadata.recursion_desired = true;
    query.add_query(Query::query(
        Name::from_ascii(name).expect("query name"),
        RecordType::A,
    ));
    query
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Outcome {
    Answer,
    Stale,
    ServFail,
    Other,
    NoReply,
}

#[derive(Clone, Copy)]
struct Sample {
    latency: Duration,
    outcome: Outcome,
}

fn mock_config(mocks: &[&MockUpstream]) -> DnsConfig {
    DnsConfig {
        protocol: DnsProtocol::Udp,
        upstreams: mocks.iter().map(|mock| mock.addr.to_string()).collect(),
        ..DnsConfig::default()
    }
}

/// Unique-name misses against two mocks after `configure` sets their
/// behaviour, reporting latency and how many upstream queries each miss cost.
async fn steady_state(
    server: &Runtime,
    label: &str,
    count: usize,
    configure: impl FnOnce(&Behavior, &Behavior),
) {
    let first = MockUpstream::start().await;
    let second = MockUpstream::start().await;
    configure(&first.behavior, &second.behavior);
    let mut bench = Bench::start(server, mock_config(&[&first, &second])).await;

    let samples = bench.ask_many(count, ZONE).await;
    let upstream_queries = first.behavior.received.load(Ordering::Relaxed)
        + second.behavior.received.load(Ordering::Relaxed);
    report(label, &samples, Some(upstream_queries));
    // The first misses show how quickly a bad endpoint stops costing time.
    let first_ten: Vec<String> = samples
        .iter()
        .take(10)
        .map(|sample| format!("{:.0}", millis(sample.latency)))
        .collect();
    println!("  {label} first_10_ms=[{}]", first_ten.join(","));
    bench.stop(server).await;
}

/// Both upstreams go silent with stale answers cached, then come back.
async fn outage_and_recovery(server: &Runtime) {
    let first = MockUpstream::start().await;
    let second = MockUpstream::start().await;
    let mut bench = Bench::start(server, mock_config(&[&first, &second])).await;

    // Warm the path, then cache names that are past their TTL.
    let _ = bench.ask_many(5, ZONE).await;
    let stale_names: Vec<String> = (0..40).map(|i| format!("stale{i}.{ZONE}")).collect();
    for name in &stale_names {
        bench.seed_stale(name);
    }

    first.behavior.silent.store(true, Ordering::Relaxed);
    second.behavior.silent.store(true, Ordering::Relaxed);
    let outage_started = Instant::now();

    let mut stale = Vec::with_capacity(stale_names.len());
    for name in &stale_names {
        stale.push(bench.ask(name).await);
    }
    report("outage_cached_names", &stale, None);
    let first_ten: Vec<String> = stale
        .iter()
        .take(10)
        .map(|sample| format!("{:.0}", millis(sample.latency)))
        .collect();
    println!(
        "  outage_cached_names first_10_ms=[{}]",
        first_ten.join(",")
    );
    let uncached = bench.ask_many(10, ZONE).await;
    report("outage_uncached_names", &uncached, None);
    println!(
        "  outage_duration_before_recovery_ms={:.0}",
        millis(outage_started.elapsed())
    );

    first.behavior.silent.store(false, Ordering::Relaxed);
    second.behavior.silent.store(false, Ordering::Relaxed);
    let revived = Instant::now();
    let mut failed_while_recovering = 0;
    let recovered_after = loop {
        let name = bench.fresh_name(ZONE);
        let sample = bench.ask(&name).await;
        if sample.outcome == Outcome::Answer {
            break revived.elapsed();
        }
        failed_while_recovering += 1;
        if revived.elapsed() > Duration::from_secs(120) {
            break revived.elapsed();
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    };
    println!(
        "recovery_after_upstreams_return ms={:.0} failed_queries={failed_while_recovering}",
        millis(recovered_after)
    );
    let after = bench.ask_many(50, ZONE).await;
    report("after_recovery", &after, None);
    bench.stop(server).await;
}

fn millis(duration: Duration) -> f64 {
    duration.as_secs_f64() * 1e3
}

fn report(label: &str, samples: &[Sample], upstream_queries: Option<u64>) {
    let count = |outcome| samples.iter().filter(|s| s.outcome == outcome).count();
    let mut latencies: Vec<Duration> = samples.iter().map(|s| s.latency).collect();
    latencies.sort_unstable();
    let at = |permille| super::percentile(&latencies, permille).map_or(f64::NAN, millis);
    let per_miss = upstream_queries.map_or_else(String::new, |queries| {
        let misses = u32::try_from(samples.len()).unwrap_or(u32::MAX).max(1);
        let queries = u32::try_from(queries).unwrap_or(u32::MAX);
        format!(
            " upstream_queries_per_miss={:.2}",
            f64::from(queries) / f64::from(misses)
        )
    });
    println!(
        "{label} n={} answer={} stale={} servfail={} other={} no_reply={} ms p50={:.1} p90={:.1} p99={:.1} max={:.1}{per_miss}",
        samples.len(),
        count(Outcome::Answer),
        count(Outcome::Stale),
        count(Outcome::ServFail),
        count(Outcome::Other),
        count(Outcome::NoReply),
        at(500),
        at(900),
        at(990),
        at(1_000),
    );
}
