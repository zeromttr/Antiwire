//! Timing diagnostics for the new-domain guard. They print numbers and assert
//! nothing; run them in release with `--ignored --nocapture`.

use std::sync::Arc;
use std::time::{Duration, Instant};

use hickory_proto::op::Message;
use hickory_proto::rr::RecordType;

use super::support::{
    allow_policy, build_query, stub_config_with_upstream, MockUpstream, MockUpstreamConfig,
};
use crate::new_domain::testing::{days_ago, FixedSource};
use crate::new_domain::{
    NewDomainGuard, RegistrationAnswer, RegistrationCache, MAX_CONCURRENT_LOOKUPS,
};
use crate::query_engine::{EngineServices, QueryEngine};
use crate::service::testing::{respond, respond_locally};

type Engine = QueryEngine<super::support::AllowAllPolicy>;

fn build_engine(upstream: &MockUpstream, guard: Option<NewDomainGuard>) -> Engine {
    let engine = QueryEngine::try_new(
        allow_policy(),
        &stub_config_with_upstream(upstream),
        EngineServices::default(),
    )
    .expect("engine");
    match guard {
        Some(guard) => engine.with_new_domain_guard(guard),
        None => engine,
    }
}

fn sinkholed(bytes: &[u8]) -> bool {
    let response = Message::from_vec(bytes).expect("decode");
    response.answers.iter().any(|record| {
        matches!(
            record.data,
            hickory_proto::rr::RData::A(hickory_proto::rr::rdata::A(ip)) if ip.is_unspecified()
        )
    })
}

fn ms(duration: Duration) -> u128 {
    duration.as_millis()
}

fn summary(label: &str, mut samples: Vec<Duration>) {
    samples.sort_unstable();
    let pick = |percent: usize| ms(samples[(samples.len() - 1) * percent / 100]);
    println!(
        "{label}: n={} p50={}ms p90={}ms max={}ms",
        samples.len(),
        pick(50),
        pick(90),
        pick(100)
    );
}

/// Cost the guard adds to a DNS cache hit whose registration date is cached.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "timing diagnostic"]
async fn probe_sync_path_overhead() {
    const BATCH: u32 = 20_000;
    let upstream = MockUpstream::start().await;
    let names = [
        ("off, short name", "www.example.com", None),
        (
            "off, deep name",
            "a.b.c.d.e.f.cdn.region.example.co.uk",
            None,
        ),
        ("on, short name", "www.example.com", Some("example.com")),
        (
            "on, deep name",
            "a.b.c.d.e.f.cdn.region.example.co.uk",
            Some("example.co.uk"),
        ),
    ];
    for (label, name, registered) in names {
        let guard = registered.map(|registered| {
            let dates = RegistrationCache::new(FixedSource::new([], Duration::ZERO));
            dates.insert_for_test(registered, days_ago(4_000));
            NewDomainGuard::new(30, dates)
        });
        let engine = build_engine(&upstream, guard);
        let query = build_query(name, RecordType::A, 7);
        // Warm the DNS answer cache through the real miss path.
        let _ = respond(&engine, &query, Instant::now()).await;
        assert!(
            respond_locally(&engine, &query).is_some(),
            "{label}: warm hit"
        );
        let mut samples = Vec::new();
        for _ in 0..9 {
            let start = Instant::now();
            for _ in 0..BATCH {
                std::hint::black_box(respond_locally(&engine, &query));
            }
            samples.push(start.elapsed().as_nanos() / u128::from(BATCH));
        }
        samples.sort_unstable();
        println!(
            "sync_hit guard={label}: ns/query median={} min={} max={}",
            samples[4], samples[0], samples[8]
        );
    }
}

/// First query for a registered domain whose date is not cached: the
/// registration lookup and the upstream exchange run one after the other.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "timing diagnostic"]
async fn probe_cold_query_latency() {
    let upstream_delay = Duration::from_millis(50);
    let upstream = MockUpstream::start_with(MockUpstreamConfig {
        delay: upstream_delay,
        ..MockUpstreamConfig::default()
    })
    .await;
    println!("cold query, upstream delay {}ms", ms(upstream_delay));

    let engine_off = build_engine(&upstream, None);
    let start = Instant::now();
    let _ = respond(
        &engine_off,
        &build_query("cold-off.com", RecordType::A, 1),
        start,
    )
    .await;
    println!("  guard off: {}ms", ms(start.elapsed()));

    for lookup_ms in [0u64, 100, 300, 600, 900, 1_200, 3_000] {
        let source = FixedSource::new(
            [("cold.com", days_ago(4_000))],
            Duration::from_millis(lookup_ms),
        );
        let engine = build_engine(
            &upstream,
            Some(NewDomainGuard::new(30, RegistrationCache::new(source))),
        );
        let start = Instant::now();
        let _ = respond(
            &engine,
            &build_query("www.cold.com", RecordType::A, 2),
            start,
        )
        .await;
        println!(
            "  guard on, lookup {lookup_ms}ms: {}ms",
            ms(start.elapsed())
        );
    }
}

/// Many new registered domains at once, as on a cold page load: lookups
/// beyond the concurrency limit queue, and those that miss the wait budget
/// fail open after waiting for it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "timing diagnostic"]
async fn probe_burst_of_new_domains() {
    let upstream = MockUpstream::start().await;
    for (count, lookup_ms) in [(16usize, 250u64), (40, 250), (40, 500), (80, 250)] {
        let domains: Vec<&'static str> = (0..count)
            .map(|index| &*Box::leak(format!("burst{index}.com").into_boxed_str()))
            .collect();
        let source = FixedSource::new(
            domains.iter().map(|domain| (*domain, days_ago(1))),
            Duration::from_millis(lookup_ms),
        );
        let engine = Arc::new(build_engine(
            &upstream,
            Some(NewDomainGuard::new(30, RegistrationCache::new(source))),
        ));
        let tasks: Vec<_> = domains
            .iter()
            .enumerate()
            .map(|(index, domain)| {
                let engine = Arc::clone(&engine);
                let query = build_query(domain, RecordType::A, u16::try_from(index).expect("id"));
                tokio::spawn(async move {
                    let start = Instant::now();
                    let bytes = respond(&engine, &query, start).await;
                    (start.elapsed(), sinkholed(&bytes))
                })
            })
            .collect();
        let mut latencies = Vec::new();
        let mut blocked = 0;
        for task in tasks {
            let (latency, was_blocked) = task.await.expect("query");
            latencies.push(latency);
            blocked += usize::from(was_blocked);
        }
        summary(
            &format!(
                "burst {count} young domains, lookup {lookup_ms}ms: blocked {blocked}/{count}"
            ),
            latencies,
        );
    }
}

/// A registry that does not answer: every query for the name, not only the
/// first, joins the stuck lookup and waits out the full budget.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "timing diagnostic"]
async fn probe_stuck_registry() {
    let upstream = MockUpstream::start().await;
    let source = FixedSource::new(
        [("stuck.com", RegistrationAnswer::Failed)],
        Duration::from_secs(20),
    );
    let engine = build_engine(
        &upstream,
        Some(NewDomainGuard::new(30, RegistrationCache::new(source))),
    );
    let mut latencies = Vec::new();
    for id in 0..5 {
        let start = Instant::now();
        let _ = respond(
            &engine,
            &build_query("www.stuck.com", RecordType::A, id),
            start,
        )
        .await;
        latencies.push(start.elapsed());
    }
    println!(
        "stuck registry, 5 sequential queries for one name: {:?}ms",
        latencies
            .iter()
            .map(|latency| ms(*latency))
            .collect::<Vec<_>>()
    );

    // Stuck lookups hold every permit; a fast registry queues behind them.
    let mut answers: Vec<(&'static str, RegistrationAnswer)> = (0..MAX_CONCURRENT_LOOKUPS)
        .map(|index| {
            (
                &*Box::leak(format!("stuck{index}.com").into_boxed_str()),
                RegistrationAnswer::Failed,
            )
        })
        .collect();
    answers.push(("fast.com", days_ago(1)));
    answers.push(("after.com", days_ago(1)));
    let source = Arc::new(SplitSource {
        slow: FixedSource::new(answers.clone(), Duration::from_secs(20)),
        fast: FixedSource::new(answers, Duration::from_millis(20)),
    });
    let engine = Arc::new(build_engine(
        &upstream,
        Some(NewDomainGuard::new(30, RegistrationCache::new(source))),
    ));
    for index in 0..MAX_CONCURRENT_LOOKUPS {
        let engine = Arc::clone(&engine);
        tokio::spawn(async move {
            let query = build_query(
                &format!("stuck{index}.com"),
                RecordType::A,
                u16::try_from(index).expect("id"),
            );
            respond(&engine, &query, Instant::now()).await
        });
    }
    tokio::time::sleep(Duration::from_millis(50)).await;
    let start = Instant::now();
    let bytes = respond(&engine, &build_query("fast.com", RecordType::A, 99), start).await;
    println!(
        "permits held by {MAX_CONCURRENT_LOOKUPS} stuck lookups; 20ms registry for a young domain: {}ms, blocked={}",
        ms(start.elapsed()),
        sinkholed(&bytes)
    );

    // Once the stuck lookups time out, their permits serve the queue again.
    tokio::time::sleep(Duration::from_secs(5)).await;
    let start = Instant::now();
    let bytes = respond(&engine, &build_query("after.com", RecordType::A, 98), start).await;
    println!(
        "after the stuck lookups time out; 20ms registry for a young domain: {}ms, blocked={}",
        ms(start.elapsed()),
        sinkholed(&bytes)
    );
}

struct SplitSource {
    slow: Arc<FixedSource>,
    fast: Arc<FixedSource>,
}

impl crate::new_domain::RegistrationSource for SplitSource {
    fn lookup<'a>(
        &'a self,
        domain: &'a str,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = RegistrationAnswer> + Send + 'a>> {
        if domain.starts_with("stuck") {
            self.slow.lookup(domain)
        } else {
            self.fast.lookup(domain)
        }
    }
}
