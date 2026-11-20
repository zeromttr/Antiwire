//! Upstream failover benchmarks, measured from the client side.
//!
//! Each scenario starts the production [`DnsListener`] on loopback in front of
//! two mock UDP upstreams whose behaviour can be switched at runtime — healthy,
//! slow, silent, or dropping a share of queries — and times cache misses as a
//! client sees them. Nothing here touches upstream internals, so the same
//! scenarios measure any replacement of the failover engine.
//!
//! The mocks only speak plain UDP, so a working port-853 primary with a `DoH`
//! fallback is left to the opt-in `upstream-live` group and real providers. A
//! blocked one needs no TLS server: a port that accepts and never answers
//! stands in for it, with a mock as the fallback.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use antiwire_policy::RuleEngine;
use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::rdata::opt::EdnsOption;
use hickory_proto::rr::{rdata, Name, RData, Record, RecordType};
use tokio::net::UdpSocket;
use tokio::runtime::Runtime;

use super::edns_with;
use crate::ede::{EDE_STALE_ANSWER, EDNS_OPTION_CODE_EDE};
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

/// Runs the scenarios with a blocked primary tier and a healthy fallback.
pub(super) fn run_failover() {
    let server = runtime("dns-bench-server");
    let clients = runtime("dns-bench-client");
    clients.block_on(async {
        println!("failover scenarios: blocked port-853 primary, mock UDP fallback, unique names");
        // A trickle shows how long a blocked primary costs every miss its head
        // start. A flood shows what its attempts cost the misses behind them.
        blocked_primary(&server, "trickle", 10, Duration::from_secs(40)).await;
        blocked_primary(&server, "flood", 200, Duration::from_secs(10)).await;
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
        let Ok(query) = Message::from_vec(&buffer[..len]) else {
            continue;
        };
        // A reply is ignored, as a real server ignores one. If a query ever
        // reached this mock from its own address, answering replies would
        // have it answer its own answers for as long as it ran.
        if query.metadata.message_type != MessageType::Query {
            continue;
        }
        let count = behavior.received.fetch_add(1, Ordering::Relaxed) + 1;
        if behavior.silent.load(Ordering::Relaxed)
            || scatter(count) < behavior.drop_percent.load(Ordering::Relaxed)
        {
            continue;
        }
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
            return Sample {
                latency: started.elapsed(),
                outcome: outcome_of(&reply),
            };
        }
    }

    /// Asks for a new name `rate` times a second for `duration` without
    /// waiting for the answers, as the applications of a busy host do, and
    /// returns each query's sample with how long after the start it was sent.
    async fn ask_at_rate(
        &mut self,
        rate: u32,
        duration: Duration,
        zone: &str,
    ) -> Vec<(Duration, Sample)> {
        let started = Instant::now();
        let gap = Duration::from_secs(1) / rate;
        let mut pending: HashMap<u16, Instant> = HashMap::new();
        let mut samples = Vec::new();
        let mut next_send = Some(started);
        let mut buffer = [0u8; 4096];
        loop {
            // A late timer sends every query that is due, so the rate holds
            // on a coarse clock.
            while let Some(due) = next_send.filter(|due| *due <= Instant::now()) {
                let id = self.next_id;
                self.next_id = self.next_id.wrapping_add(1).max(1);
                let name = self.fresh_name(zone);
                let wire = encode_message(&query_for(id, &name)).expect("encode query");
                pending.insert(id, Instant::now());
                self.client
                    .send_to(&wire, self.server_addr)
                    .await
                    .expect("send query");
                next_send = Some(due + gap).filter(|next| *next < started + duration);
            }
            let wake = match (next_send, pending.values().min()) {
                (Some(due), _) => due,
                (None, Some(oldest)) => *oldest + CLIENT_TIMEOUT,
                (None, None) => break,
            };
            let wait = wake.saturating_duration_since(Instant::now());
            match tokio::time::timeout(wait, self.client.recv_from(&mut buffer)).await {
                Ok(Ok((len, _))) => {
                    let Ok(reply) = Message::from_vec(&buffer[..len]) else {
                        continue;
                    };
                    if let Some(sent) = pending.remove(&reply.metadata.id) {
                        samples.push((
                            sent.duration_since(started),
                            Sample {
                                latency: sent.elapsed(),
                                outcome: outcome_of(&reply),
                            },
                        ));
                    }
                }
                Ok(Err(_)) => {}
                Err(_) => {
                    // Whatever has waited its limit was never answered.
                    let now = Instant::now();
                    pending.retain(|_, sent| {
                        let lost = now.duration_since(*sent) >= CLIENT_TIMEOUT;
                        if lost {
                            samples.push((
                                sent.duration_since(started),
                                Sample {
                                    latency: CLIENT_TIMEOUT,
                                    outcome: Outcome::NoReply,
                                },
                            ));
                        }
                        !lost
                    });
                }
            }
        }
        samples.sort_unstable_by_key(|(sent, _)| *sent);
        samples
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

/// A query as a stub resolver sends it, with an OPT record: the resolver
/// says an answer is stale in the OPT record's EDE, so a query without one
/// could not tell.
fn query_for(id: u16, name: &str) -> Message {
    let mut query = Message::new(id, MessageType::Query, OpCode::Query);
    query.metadata.recursion_desired = true;
    query.add_query(Query::query(
        Name::from_ascii(name).expect("query name"),
        RecordType::A,
    ));
    query.edns = Some(edns_with(false, 1232));
    query
}

fn outcome_of(reply: &Message) -> Outcome {
    match reply.metadata.response_code {
        ResponseCode::NoError if !reply.answers.is_empty() => {
            if says_stale(reply) {
                Outcome::Stale
            } else {
                Outcome::Answer
            }
        }
        ResponseCode::NoError | ResponseCode::NXDomain => Outcome::Answer,
        ResponseCode::ServFail => Outcome::ServFail,
        _ => Outcome::Other,
    }
}

/// Whether `reply` carries RFC 8914 EDE 3, Stale Answer. Its TTLs cannot say:
/// a stale record is served with the RFC 8767 stale TTL, not one second.
fn says_stale(reply: &Message) -> bool {
    reply.edns.as_ref().is_some_and(|edns| {
        edns.options().as_ref().iter().any(|(_, option)| {
            matches!(
                option,
                EdnsOption::Unknown(EDNS_OPTION_CODE_EDE, data)
                    if data.get(..2) == Some(&EDE_STALE_ANSWER.to_be_bytes()[..])
            )
        })
    })
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

/// A TCP port that accepts every connection and never sends a byte, which is
/// how a firewall that swallows port 853 looks to a TLS client: the handshake
/// never completes.
struct Blackhole {
    addr: SocketAddr,
    connects: Arc<AtomicU64>,
    task: tokio::task::JoinHandle<()>,
}

impl Blackhole {
    async fn start() -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("blackhole bind");
        let addr = listener.local_addr().expect("blackhole address");
        let connects = Arc::new(AtomicU64::new(0));
        let counter = Arc::clone(&connects);
        let task = tokio::spawn(async move {
            let mut held = Vec::new();
            while let Ok((stream, _)) = listener.accept().await {
                counter.fetch_add(1, Ordering::Relaxed);
                held.push(stream);
            }
        });
        Self {
            addr,
            connects,
            task,
        }
    }
}

impl Drop for Blackhole {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// A port-853 primary that never completes a handshake, with a healthy
/// fallback behind it, from a cold start: misses arrive `rate` a second.
///
/// The fallback answers every one of them, so what is measured is what the
/// primary's attempts cost: the head start each miss gives it, and the
/// upstream admission they hold while they wait.
async fn blocked_primary(server: &Runtime, pace: &str, rate: u32, duration: Duration) {
    let primary = Blackhole::start().await;
    let fallback = MockUpstream::start().await;
    let config = DnsConfig {
        protocol: DnsProtocol::Udp,
        upstreams: vec![format!("tls://{}", primary.addr), fallback.addr.to_string()],
        ..DnsConfig::default()
    };
    let mut bench = Bench::start(server, config).await;

    let sent = bench.ask_at_rate(rate, duration, ZONE).await;
    let samples: Vec<Sample> = sent.iter().map(|(_, sample)| *sample).collect();
    let label = format!("blocked_primary_{pace} rate={rate}/s");
    report(&label, &samples, None);
    // A miss the fallback answered at once took about one loopback round trip.
    // One that waited for the primary first took the hedge delay as well.
    let waited = |sample: &Sample| sample.latency >= antiwire_tuning::DOH_HEDGE_DELAY * 9 / 10;
    let last_waited = sent
        .iter()
        .rev()
        .find(|(_, sample)| waited(sample))
        .map_or(0.0, |(at, _)| millis(*at));
    println!(
        "  {label} waited_on_primary={} last_of_them_sent_at_ms={last_waited:.0} \
         primary_connects={} fallback_queries={}",
        samples.iter().filter(|sample| waited(sample)).count(),
        primary.connects.load(Ordering::Relaxed),
        fallback.behavior.received.load(Ordering::Relaxed),
    );
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
