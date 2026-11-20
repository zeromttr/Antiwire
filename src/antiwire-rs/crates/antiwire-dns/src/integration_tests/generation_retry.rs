//! Generation-retry regression tests: after a network reset retires a fetch,
//! the retry must use the newly installed upstream pool, never the pool
//! captured before the reset. Both the foreground miss path and background
//! prefetch re-acquire the pool together with the generation on every attempt.

use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use super::support::{
    allow_policy, build_query, positive_cache_entry, AllowAllPolicy, MockUpstream,
    MockUpstreamConfig,
};
use crate::query_engine::QueryEngine;
use crate::service::testing::respond;
use crate::{CacheKey, CacheProbe, DnsConfig};
use hickory_proto::op::Message;
use hickory_proto::rr::{RData, RecordType};

const OLD_MARKER: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);
const NEW_MARKER: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 1);

fn answer_ip(response: &Message) -> Option<Ipv4Addr> {
    response
        .answers
        .iter()
        .find_map(|record| match &record.data {
            RData::A(addr) => Some(addr.0),
            _ => None,
        })
}

fn engine_pointing_at(old: &MockUpstream) -> Arc<QueryEngine<AllowAllPolicy>> {
    Arc::new(QueryEngine::new(
        allow_policy(),
        DnsConfig {
            protocol: old.protocol(),
            upstreams: vec![old.endpoint()],
            ..DnsConfig::default()
        },
    ))
}

async fn wait_for_calls(upstream: &MockUpstream, expected: u32, what: &str) {
    tokio::time::timeout(Duration::from_secs(5), async {
        while upstream.calls() < expected {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("{what} did not reach the upstream in time"));
}

/// The exact reported sequence: a query captures pool A under generation 0, a
/// reset installs pool B with generation 1, the first result is rejected, and
/// the retry must fetch through pool B so the admitted answer comes from it.
#[tokio::test]
async fn foreground_retry_after_network_reset_uses_the_new_pool() {
    let old = MockUpstream::start_with(MockUpstreamConfig {
        delay: Duration::from_millis(500),
        answer_ipv4: OLD_MARKER,
        ..MockUpstreamConfig::default()
    })
    .await;
    let new = MockUpstream::start_with(MockUpstreamConfig {
        answer_ipv4: NEW_MARKER,
        ..MockUpstreamConfig::default()
    })
    .await;
    let engine = engine_pointing_at(&old);
    let query = build_query("retry-pool.example", RecordType::A, 1);

    let task_engine = Arc::clone(&engine);
    let task = tokio::spawn(async move { respond(&task_engine, &query, Instant::now()).await });

    // The old pool's delay keeps the first attempt in flight while the reset
    // lands beneath it.
    wait_for_calls(&old, 1, "the first foreground fetch").await;
    engine.set_upstream_endpoints_for_test(vec![new.endpoint()]);
    engine
        .reset_after_network_change()
        .await
        .expect("rebuild upstream pool");

    let bytes = tokio::time::timeout(Duration::from_secs(5), task)
        .await
        .expect("retried query completes")
        .expect("join");
    let response = Message::from_vec(&bytes).expect("decode retried response");
    assert_eq!(
        answer_ip(&response),
        Some(NEW_MARKER),
        "the retry must be served by the new pool, not the retired one"
    );
    assert!(new.calls() >= 1, "the retry must reach the new pool");
    // No exact count: a slow endpoint triggers the exchange layer's own
    // hedged attempts, which also land on the old pool but share the first
    // attempt's generation and are discarded with it.
    assert!(
        old.calls() >= 1,
        "the first fetch must start against the old pool"
    );

    let key = CacheKey::from_query("retry-pool.example", RecordType::A, 1);
    let CacheProbe::Fresh(entry) = engine.response_cache().probe(&key) else {
        panic!("the retried answer must be cached under the new generation");
    };
    assert_eq!(
        answer_ip(&entry.parsed_message),
        Some(NEW_MARKER),
        "the cache must hold the new pool's answer"
    );
}

/// The regression this guards: only an answer was checked against the
/// generation. A fetch that failed after a reset, as one does when the network
/// it used goes away, was answered SERVFAIL instead of retried on the new pool.
#[tokio::test]
async fn a_failure_after_a_network_reset_is_retried_on_the_new_pool() {
    // Long enough for the reset to land while the fetch is in flight, short
    // enough to leave the retry the transport attempt admission reserves.
    let old = MockUpstream::start_with(MockUpstreamConfig {
        delay: Duration::from_millis(150),
        servfail: true,
        ..MockUpstreamConfig::default()
    })
    .await;
    let new = MockUpstream::start_with(MockUpstreamConfig {
        answer_ipv4: NEW_MARKER,
        ..MockUpstreamConfig::default()
    })
    .await;
    let engine = engine_pointing_at(&old);
    let query = build_query("fail-after-reset.example", RecordType::A, 1);

    let task_engine = Arc::clone(&engine);
    let task = tokio::spawn(async move { respond(&task_engine, &query, Instant::now()).await });
    wait_for_calls(&old, 1, "the first foreground fetch").await;
    engine.set_upstream_endpoints_for_test(vec![new.endpoint()]);
    engine
        .reset_after_network_change()
        .await
        .expect("rebuild upstream pool");

    let bytes = tokio::time::timeout(Duration::from_secs(5), task)
        .await
        .expect("retried query completes")
        .expect("join");
    let response = Message::from_vec(&bytes).expect("decode retried response");
    assert_eq!(
        answer_ip(&response),
        Some(NEW_MARKER),
        "the old pool's failure must be retried on the new pool, not answered"
    );
}

/// Prefetch captures nothing at spawn time: a reset between the spawn and the
/// refresh must still land the new pool's answer, not discard a retired-pool
/// fetch and exhaust the budget on a second retired-pool fetch.
#[tokio::test]
async fn prefetch_after_network_reset_uses_the_new_pool() {
    let old = MockUpstream::start_with(MockUpstreamConfig {
        delay: Duration::from_millis(500),
        answer_ipv4: OLD_MARKER,
        ..MockUpstreamConfig::default()
    })
    .await;
    let new = MockUpstream::start_with(MockUpstreamConfig {
        answer_ipv4: NEW_MARKER,
        ..MockUpstreamConfig::default()
    })
    .await;
    let engine = engine_pointing_at(&old);

    // Seed a fresh entry whose answer predates the reset and whose prefetch is
    // already due, so the next hit schedules a background refresh.
    let key = CacheKey::from_query("prefetch-pool.example", RecordType::A, 1);
    let mut entry = positive_cache_entry("prefetch-pool.example", OLD_MARKER, 30);
    entry.prefetch_at = Instant::now()
        .checked_sub(Duration::from_secs(1))
        .expect("instant supports subtraction");
    engine.response_cache().insert(key.clone(), entry);

    let hit = build_query("prefetch-pool.example", RecordType::A, 2);
    let bytes = respond(&engine, &hit, Instant::now()).await;
    let response = Message::from_vec(&bytes).expect("decode hit response");
    assert_eq!(
        answer_ip(&response),
        Some(OLD_MARKER),
        "the seeded entry serves the hit"
    );

    // The background refresh is now in flight against the old pool; reset
    // beneath it exactly like the foreground case.
    wait_for_calls(&old, 1, "the prefetch refresh").await;
    engine.set_upstream_endpoints_for_test(vec![new.endpoint()]);
    engine
        .reset_after_network_change()
        .await
        .expect("rebuild upstream pool");

    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if let CacheProbe::Fresh(entry) = engine.response_cache().probe(&key) {
                if answer_ip(&entry.parsed_message) == Some(NEW_MARKER) {
                    return;
                }
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("prefetch must refresh the entry from the new pool");
    assert!(
        new.calls() >= 1,
        "the prefetch retry must reach the new pool"
    );
    // No exact count here either: exchange-level hedging may re-hit the old
    // pool, but those attempts share the retired generation and are discarded.
    assert!(
        old.calls() >= 1,
        "the prefetch must start against the old pool"
    );
}
