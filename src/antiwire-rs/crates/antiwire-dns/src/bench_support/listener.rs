//! Loopback benchmarks for the DNS listener's UDP and TCP serve loops.
//!
//! These drive the production [`DnsListener`] through real sockets, so they
//! measure receive, admission, dispatch, and send together — the code a
//! transport rewrite replaces. The server runs on its own multi-thread runtime
//! and the clients on another, so client work does not borrow server workers.
//!
//! Every hit scenario queries one cached name; the saturation scenarios add a
//! flood of uncached names forwarded to an upstream that never answers, first
//! while it is still trusted and then after it has been marked down.

use std::net::{SocketAddr, UdpSocket as StdUdpSocket};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use antiwire_policy::RuleEngine;
use antiwire_tuning::DNS_QUERY_DEADLINE;
use hickory_proto::op::{Message, MessageType, OpCode, Query};
use hickory_proto::rr::{rdata, Name, RData, Record, RecordType};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::runtime::Runtime;

use super::edns_with;
use crate::listener::DnsListener;
use crate::messages::encode_message;
use crate::query_engine::{EngineServices, QueryEngine};
use crate::response_cache::{CacheKey, QueryFlags, ResponseCache};
use crate::settings::DnsConfig;

const RUNTIME_THREADS: usize = 4;
const HIT_NAME: &str = "hit.listener.bench.";
/// A UDP reply not back within this long is counted lost and its slot reused.
const UDP_LOSS_TIMEOUT: Duration = Duration::from_millis(250);
const ROUNDS: usize = 3;

/// Runs every listener scenario and prints one line per scenario.
pub(super) fn run() {
    let server = runtime("dns-bench-server");
    let clients = runtime("dns-bench-client");
    println!(
        "listener runtimes: server_threads={RUNTIME_THREADS} client_threads={RUNTIME_THREADS} rounds={ROUNDS}"
    );

    let hits = BenchServer::start(&server, "127.0.0.1:1".to_owned());
    report("listener_udp_hit_sequential", &clients, || {
        udp_clients(hits.udp, 1, 1, 20_000)
    });
    report(
        "listener_udp_hit_pipelined clients=16 window=8",
        &clients,
        || udp_clients(hits.udp, 16, 8, 20_000),
    );
    report("listener_tcp_hit_sequential", &clients, || {
        tcp_clients(hits.tcp, 1, 1, 20_000)
    });
    report(
        "listener_tcp_hit_pipelined clients=16 window=4",
        &clients,
        || tcp_clients(hits.tcp, 16, 4, 10_000),
    );
    hits.stop(&server);

    // Nothing ever reads this socket, so every forwarded miss holds its worker
    // until the upstream deadline. Once those misses expire the upstream is
    // degraded and misses fail fast instead, which turns the flood into a
    // SERVFAIL storm that overflows the socket's receive buffer — a different
    // scenario, where every dropped hit costs the client a loss timeout. So
    // each round gets a fresh server and ends well inside the deadline.
    let silent = StdUdpSocket::bind("127.0.0.1:0").expect("silent upstream bind");
    let silent_addr = silent.local_addr().expect("silent upstream address");
    let flood_round = || {
        let flooded = BenchServer::start(&server, silent_addr.to_string());
        let round = clients.block_on(udp_hits_under_flood(flooded.udp, 4, 5_000));
        flooded.stop(&server);
        round
    };
    flood_round();
    print_rounds(
        "listener_udp_hit_under_miss_flood flooders=4",
        (0..ROUNDS).map(|_| flood_round()).collect(),
    );

    // The degraded case on purpose: one flood lets its misses expire, which
    // takes the upstream down, and the measured rounds then flood a resolver
    // that fails misses fast. Cached answers must keep flowing here too.
    let degraded = BenchServer::start(&server, silent_addr.to_string());
    clients.block_on(udp_hits_under_flood(degraded.udp, 4, 1_000));
    std::thread::sleep(DNS_QUERY_DEADLINE + Duration::from_millis(500));
    report(
        "listener_udp_hit_under_miss_flood_upstream_down flooders=4",
        &clients,
        || udp_hits_under_flood(degraded.udp, 4, 5_000),
    );
    degraded.stop(&server);
    drop(silent);
}

fn runtime(name: &str) -> Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(RUNTIME_THREADS)
        .thread_name(name)
        .enable_all()
        .build()
        .expect("bench runtime")
}

struct BenchServer {
    listener: DnsListener,
    udp: SocketAddr,
    tcp: SocketAddr,
}

impl BenchServer {
    fn start(runtime: &Runtime, upstream: String) -> Self {
        runtime.block_on(async {
            let stub = Arc::new(
                QueryEngine::try_new(
                    RuleEngine::new(),
                    &DnsConfig {
                        upstreams: vec![upstream],
                        ..DnsConfig::default()
                    },
                    EngineServices::default(),
                )
                .expect("dns stub"),
            );
            seed_hit(&stub);
            let listener =
                DnsListener::start_on(stub, "127.0.0.1:0".parse().expect("bench address"))
                    .expect("bench listener");
            let udp = listener.udp_addr();
            let tcp = listener.tcp_addr().expect("bench tcp listener");
            Self { listener, udp, tcp }
        })
    }

    fn stop(mut self, runtime: &Runtime) {
        runtime
            .block_on(self.listener.shutdown())
            .expect("bench listener shutdown");
    }
}

fn hit_query() -> Message {
    let mut query = Message::new(0, MessageType::Query, OpCode::Query);
    query.metadata.recursion_desired = true;
    query.add_query(Query::query(
        Name::from_ascii(HIT_NAME).expect("hit name"),
        RecordType::A,
    ));
    query.edns = Some(edns_with(false, 1232));
    query
}

fn hit_wire() -> Vec<u8> {
    encode_message(&hit_query()).expect("encode hit query")
}

fn seed_hit(stub: &QueryEngine<RuleEngine>) {
    let query = hit_query();
    let mut response = Message::response(0, OpCode::Query);
    response.metadata.recursion_available = true;
    response.queries.clone_from(&query.queries);
    response.edns.clone_from(&query.edns);
    response.add_answer(Record::from_rdata(
        Name::from_ascii(HIT_NAME).expect("answer name"),
        3_600,
        RData::A(rdata::A(std::net::Ipv4Addr::new(192, 0, 2, 1))),
    ));
    let entry = ResponseCache::entry_from_message(&response, false).expect("cache entry");
    stub.response_cache().insert(
        CacheKey::from_query(HIT_NAME.trim_end_matches('.'), RecordType::A, 1)
            .with_flags(QueryFlags::from_request(&query)),
        entry,
    );
}

/// Latency samples and outcome counts from one scenario round.
#[derive(Default)]
struct Round {
    latencies: Vec<Duration>,
    lost: usize,
    elapsed: Duration,
}

impl Round {
    fn merge(&mut self, other: Self) {
        self.latencies.extend(other.latencies);
        self.lost += other.lost;
    }
}

/// Runs `ROUNDS` rounds of a scenario after one warm-up round and prints the
/// median round with its latency percentiles.
fn report<F, Fut>(label: &str, clients: &Runtime, scenario: F)
where
    F: Fn() -> Fut,
    Fut: std::future::Future<Output = Round>,
{
    clients.block_on(scenario());
    print_rounds(
        label,
        (0..ROUNDS).map(|_| clients.block_on(scenario())).collect(),
    );
}

/// Prints the median of `ROUNDS` rounds with its latency percentiles.
fn print_rounds(label: &str, mut rounds: Vec<Round>) {
    for round in &mut rounds {
        round.latencies.sort_unstable();
    }
    let qps = |round: &Round| count(round.latencies.len()) / round.elapsed.as_secs_f64();
    rounds.sort_by(|a, b| qps(a).total_cmp(&qps(b)));
    let (min_qps, max_qps) = (qps(&rounds[0]), qps(&rounds[ROUNDS - 1]));
    let median = &rounds[ROUNDS / 2];
    let micros = |permille| {
        super::percentile(&median.latencies, permille)
            .map_or(f64::NAN, |latency| latency.as_secs_f64() * 1e6)
    };
    let sent = median.latencies.len() + median.lost;
    println!(
        "{label} answered={} lost={} ({:.2}%) qps median={:.0} min={min_qps:.0} max={max_qps:.0} us p50={:.1} p99={:.1} p99.9={:.1}",
        median.latencies.len(),
        median.lost,
        100.0 * count(median.lost) / count(sent.max(1)),
        qps(median),
        micros(500),
        micros(990),
        micros(999),
    );
}

/// Lossless for every count these scenarios produce.
fn count(n: usize) -> f64 {
    f64::from(u32::try_from(n).unwrap_or(u32::MAX))
}

/// `clients` concurrent UDP clients, each keeping up to `window` queries in
/// flight until it has sent `per_client` queries.
async fn udp_clients(
    server: SocketAddr,
    clients: usize,
    window: usize,
    per_client: usize,
) -> Round {
    let started = Instant::now();
    let tasks: Vec<_> = (0..clients)
        .map(|_| tokio::spawn(udp_client(server, window, per_client)))
        .collect();
    let mut round = Round::default();
    for task in tasks {
        round.merge(task.await.expect("udp client task"));
    }
    round.elapsed = started.elapsed();
    round
}

async fn udp_client(server: SocketAddr, window: usize, total: usize) -> Round {
    assert!(u16::try_from(total).is_ok(), "ids must not wrap");
    let socket = UdpSocket::bind("127.0.0.1:0").await.expect("client bind");
    socket.connect(server).await.expect("client connect");
    let mut wire = hit_wire();
    let mut sent_at: Vec<Option<Instant>> = vec![None; total];
    let mut outstanding: Vec<usize> = Vec::with_capacity(window);
    let mut next = 0;
    let mut round = Round {
        latencies: Vec::with_capacity(total),
        ..Round::default()
    };
    let mut buffer = [0u8; 1_500];

    while next < total || !outstanding.is_empty() {
        while next < total && outstanding.len() < window {
            wire[..2].copy_from_slice(&u16::try_from(next).expect("id").to_be_bytes());
            sent_at[next] = Some(Instant::now());
            socket.send(&wire).await.expect("send query");
            outstanding.push(next);
            next += 1;
        }
        match tokio::time::timeout(UDP_LOSS_TIMEOUT, socket.recv(&mut buffer)).await {
            Ok(received) => {
                let len = received.expect("receive reply");
                if len < 2 {
                    continue;
                }
                let id = usize::from(u16::from_be_bytes([buffer[0], buffer[1]]));
                if let Some(at) = sent_at.get_mut(id).and_then(Option::take) {
                    round.latencies.push(at.elapsed());
                    outstanding.retain(|&pending| pending != id);
                }
            }
            Err(_) => {
                // Everything still outstanding is lost; clearing the send
                // times makes a straggler arriving later a no-op.
                for id in outstanding.drain(..) {
                    sent_at[id] = None;
                    round.lost += 1;
                }
            }
        }
    }
    round
}

/// `clients` concurrent TCP connections, each pipelining up to `window`
/// queries until it has sent `per_client`.
async fn tcp_clients(
    server: SocketAddr,
    clients: usize,
    window: usize,
    per_client: usize,
) -> Round {
    let started = Instant::now();
    let tasks: Vec<_> = (0..clients)
        .map(|_| tokio::spawn(tcp_client(server, window, per_client)))
        .collect();
    let mut round = Round::default();
    for task in tasks {
        round.merge(task.await.expect("tcp client task"));
    }
    round.elapsed = started.elapsed();
    round
}

async fn tcp_client(server: SocketAddr, window: usize, total: usize) -> Round {
    assert!(u16::try_from(total).is_ok(), "ids must not wrap");
    let wire = hit_wire();
    let mut frame = Vec::with_capacity(wire.len() + 2);
    frame.extend_from_slice(&u16::try_from(wire.len()).expect("frame").to_be_bytes());
    frame.extend_from_slice(&wire);
    let mut round = Round {
        latencies: Vec::with_capacity(total),
        ..Round::default()
    };
    let mut buffer = vec![0u8; usize::from(u16::MAX)];
    let mut stream = TcpStream::connect(server).await.expect("tcp connect");
    stream.set_nodelay(true).expect("tcp nodelay");
    let mut sent_at: Vec<Instant> = Vec::with_capacity(total);

    while round.latencies.len() < total {
        while sent_at.len() < total && sent_at.len() - round.latencies.len() < window {
            let id = u16::try_from(sent_at.len()).expect("id");
            frame[2..4].copy_from_slice(&id.to_be_bytes());
            sent_at.push(Instant::now());
            stream.write_all(&frame).await.expect("send frame");
        }
        let mut len = [0u8; 2];
        stream.read_exact(&mut len).await.expect("reply length");
        let len = usize::from(u16::from_be_bytes(len));
        stream
            .read_exact(&mut buffer[..len])
            .await
            .expect("reply body");
        // Replies may come back out of order, so match on the echoed id.
        let id = usize::from(u16::from_be_bytes([buffer[0], buffer[1]]));
        round.latencies.push(sent_at[id].elapsed());
    }
    round
}

/// Measures cache hits from one sequential client while `flooders` sockets
/// send uncached names as fast as the loopback accepts them.
async fn udp_hits_under_flood(server: SocketAddr, flooders: usize, hits: usize) -> Round {
    static NEXT_NAME: AtomicU64 = AtomicU64::new(0);
    let stop = Arc::new(AtomicBool::new(false));
    let mut flood = Vec::with_capacity(flooders * 2);
    for _ in 0..flooders {
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.expect("flood bind"));
        socket.connect(server).await.expect("flood connect");
        // Drain replies so the flooder's receive buffer never fills.
        let drain = Arc::clone(&socket);
        let drain_stop = Arc::clone(&stop);
        flood.push(tokio::spawn(async move {
            let mut buffer = [0u8; 1_500];
            while !drain_stop.load(Ordering::Relaxed) {
                let _ =
                    tokio::time::timeout(Duration::from_millis(50), drain.recv(&mut buffer)).await;
            }
        }));
        let send_stop = Arc::clone(&stop);
        flood.push(tokio::spawn(async move {
            while !send_stop.load(Ordering::Relaxed) {
                let n = NEXT_NAME.fetch_add(1, Ordering::Relaxed);
                let mut query = Message::new(0, MessageType::Query, OpCode::Query);
                query.add_query(Query::query(
                    Name::from_ascii(format!("m{n}.flood.listener.bench.")).expect("flood name"),
                    RecordType::A,
                ));
                let wire = encode_message(&query).expect("encode flood query");
                // A full socket buffer is part of a flood; keep going.
                let _ = socket.send(&wire).await;
                tokio::task::yield_now().await;
            }
        }));
    }

    // Let the flood fill the upstream workers before measuring.
    tokio::time::sleep(Duration::from_millis(300)).await;
    let started = Instant::now();
    let mut round = udp_client(server, 1, hits).await;
    round.elapsed = started.elapsed();

    stop.store(true, Ordering::Relaxed);
    for task in flood {
        task.await.expect("flood task");
    }
    round
}
