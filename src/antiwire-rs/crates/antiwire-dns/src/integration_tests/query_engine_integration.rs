//! Integration tests for query orchestration, caching, and upstream coalescing.

use std::sync::Arc;
use std::time::{Duration, Instant};

use super::support::{
    allow_policy, build_query, forward, positive_cache_entry, stub_config_with_controlled,
    stub_config_with_upstream, BlockOnePolicy, ControlledUpstream, MockUpstream,
    MockUpstreamConfig, NegativeAnswer,
};
use crate::service::testing::{respond, respond_locally};
use crate::{BlockResponseMode, CacheKey, CacheProbe, DnsConfig, QueryEngine, ResponseCache};
use hickory_proto::op::{Message, ResponseCode};
use hickory_proto::rr::{rdata, Name, RData, RecordType};

/// End-to-end negative caching: the upstream's authority SOA has to survive
/// hickory's `NoRecords` error, the synthesized answer, and the cache entry, or
/// the RFC 2308 TTL is silently replaced by the 30s default.
async fn negative_cache_ttl(rcode: ResponseCode, soa_ttl: u32, minimum: u32) -> Duration {
    let upstream = MockUpstream::start_with(MockUpstreamConfig {
        negative: Some(NegativeAnswer {
            rcode,
            soa_ttl,
            minimum,
        }),
        ..MockUpstreamConfig::default()
    })
    .await;
    let stub = QueryEngine::new(allow_policy(), stub_config_with_upstream(&upstream));

    let query = build_query("absent.example.example", RecordType::A, 1);
    let response = forward(&stub, &query).await.expect("negative answer");
    assert_eq!(response.metadata.response_code, rcode);
    assert!(
        response.answers.is_empty(),
        "negative answers carry no answers"
    );

    let key = CacheKey::from_query("absent.example.example", RecordType::A, 1);
    let CacheProbe::Fresh(entry) = stub.response_cache().probe(&key) else {
        panic!("negative answer was cached fresh");
    };
    entry.fresh_until.saturating_duration_since(Instant::now())
}

#[tokio::test]
async fn nxdomain_is_cached_for_the_zone_negative_ttl_not_the_default() {
    // A short negative TTL must not be over-cached to the 30s default.
    let short = negative_cache_ttl(ResponseCode::NXDomain, 3600, 45).await;
    assert!(
        (Duration::from_secs(40)..=Duration::from_secs(45)).contains(&short),
        "expected ~45s from SOA MINIMUM, got {short:?}"
    );

    // A long one must not be under-cached to it either.
    let long = negative_cache_ttl(ResponseCode::NXDomain, 900, 900).await;
    assert!(
        (Duration::from_secs(880)..=Duration::from_secs(900)).contains(&long),
        "expected ~900s from the SOA, got {long:?}"
    );
}

#[tokio::test]
async fn nodata_negative_ttl_takes_the_lesser_of_soa_ttl_and_minimum() {
    let ttl = negative_cache_ttl(ResponseCode::NoError, 120, 3600).await;
    assert!(
        (Duration::from_secs(115)..=Duration::from_secs(120)).contains(&ttl),
        "expected ~120s from the SOA's own TTL, got {ttl:?}"
    );
}

/// A TTL at the clamp floor sits below the prefetch threshold. Those entries
/// must simply expire: scheduling a refresh at insertion made every fresh hit
/// spawn a background upstream fetch, so a popular low-TTL domain re-queried
/// upstream continuously instead of being served from cache.
#[tokio::test]
async fn short_ttl_fresh_hits_do_not_trigger_repeated_upstream_refreshes() {
    let upstream = MockUpstream::start_with(MockUpstreamConfig {
        ttl: 5,
        ..MockUpstreamConfig::default()
    })
    .await;
    let stub = QueryEngine::new(allow_policy(), stub_config_with_upstream(&upstream));

    let query = build_query("short-ttl.example", RecordType::A, 1);
    forward(&stub, &query).await.expect("prime the cache");
    assert_eq!(upstream.calls(), 1, "one call to populate the entry");

    for id in 2..12 {
        let hit = build_query("short-ttl.example", RecordType::A, id);
        assert!(
            respond_locally(&stub, &hit).is_some(),
            "query {id} is a fresh cache hit"
        );
    }

    // Any prefetch these hits scheduled would have completed by now; the entry
    // is still comfortably inside its 5s freshness window either way.
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(
        upstream.calls(),
        1,
        "fresh hits inside the TTL must not refresh upstream"
    );
}

/// The authority SOA is also what lets the client do its own negative caching.
#[tokio::test]
async fn negative_answers_reach_the_client_with_their_authority_soa() {
    let upstream = MockUpstream::start_with(MockUpstreamConfig {
        negative: Some(NegativeAnswer {
            rcode: ResponseCode::NXDomain,
            soa_ttl: 600,
            minimum: 600,
        }),
        ..MockUpstreamConfig::default()
    })
    .await;
    let stub = QueryEngine::new(allow_policy(), stub_config_with_upstream(&upstream));

    let query = build_query("gone.example.example", RecordType::A, 7);
    let response = forward(&stub, &query).await.expect("negative answer");

    assert_eq!(response.metadata.response_code, ResponseCode::NXDomain);
    assert_eq!(response.queries.len(), 1, "question is echoed");
    assert!(
        response
            .authorities
            .iter()
            .any(|record| record.record_type() == RecordType::SOA),
        "authority SOA reaches the client"
    );
}

#[tokio::test]
async fn concurrent_identical_misses_coalesce_upstream_calls() {
    let upstream = MockUpstream::start_with(MockUpstreamConfig {
        delay: Duration::from_millis(200),
        ..MockUpstreamConfig::default()
    })
    .await;
    let stub = Arc::new(QueryEngine::new(
        allow_policy(),
        stub_config_with_upstream(&upstream),
    ));

    let mut handles = Vec::new();
    for id in 0..50_u16 {
        let stub = Arc::clone(&stub);
        handles.push(tokio::spawn(async move {
            let query = build_query("coalesce.example", RecordType::A, id);
            forward(&stub, &query).await
        }));
    }

    for handle in handles {
        let response = handle.await.expect("join").expect("resolve");
        assert_eq!(response.metadata.response_code, ResponseCode::NoError);
        assert_eq!(response.answers.len(), 1);
    }

    assert_eq!(upstream.calls(), 1);
}

#[tokio::test]
async fn cache_hit_avoids_upstream_on_sync_path() {
    let upstream = MockUpstream::start().await;
    let stub = QueryEngine::new(allow_policy(), stub_config_with_upstream(&upstream));

    let first = build_query("cached.example", RecordType::A, 1);
    forward(&stub, &first).await.expect("prime cache");
    assert_eq!(upstream.calls(), 1);

    let second = build_query("cached.example", RecordType::A, 2);
    let bytes = respond_locally(&stub, &second).expect("sync cache hit");
    assert!(!bytes.is_empty());
    assert_eq!(upstream.calls(), 1);
}

#[tokio::test]
async fn stale_cache_entry_refreshes_before_answering_with_healthy_upstream() {
    let upstream = MockUpstream::start().await;
    let stub = QueryEngine::new(allow_policy(), stub_config_with_upstream(&upstream));

    let query = build_query("stale.example", RecordType::A, 1);
    let first = forward(&stub, &query).await.expect("prime cache");
    assert_eq!(upstream.calls(), 1);

    let cache_key = CacheKey::from_query("stale.example", RecordType::A, 1);
    let mut stale_entry = ResponseCache::entry_from_message(&first, false).expect("entry");
    stale_entry.fresh_until = Instant::now()
        .checked_sub(Duration::from_secs(1))
        .expect("test timestamp");
    stale_entry.stale_until = Instant::now() + Duration::from_secs(60);
    stub.response_cache().insert(cache_key.clone(), stale_entry);

    assert!(matches!(
        stub.response_cache().probe(&cache_key),
        CacheProbe::Stale(_)
    ));

    let sync_query = build_query("stale.example", RecordType::A, 2);
    assert!(respond_locally(&stub, &sync_query).is_none());
    assert!(
        !stub.response_cache().prefetch_in_flight(&cache_key),
        "stale misses must use foreground admission, not start a competing prefetch"
    );
    let refreshed = forward(&stub, &sync_query).await.expect("fresh answer");
    assert_eq!(refreshed.metadata.response_code, ResponseCode::NoError);
    assert_eq!(upstream.calls(), 2, "refresh before answering the client");
    assert!(matches!(
        stub.response_cache().probe(&cache_key),
        CacheProbe::Fresh(_)
    ));
}

#[tokio::test]
async fn stale_cache_entry_falls_back_after_foreground_upstream_failure() {
    let upstream = MockUpstream::start_with(MockUpstreamConfig {
        respond: false,
        ..MockUpstreamConfig::default()
    })
    .await;
    let stub = QueryEngine::new(allow_policy(), stub_config_with_upstream(&upstream));
    let key = CacheKey::from_query("stale-failure.example", RecordType::A, 1);
    let mut entry = positive_cache_entry(
        "stale-failure.example",
        std::net::Ipv4Addr::new(1, 2, 3, 4),
        30,
    );
    entry.fresh_until = Instant::now()
        .checked_sub(Duration::from_secs(1))
        .expect("test timestamp");
    entry.stale_until = Instant::now() + Duration::from_secs(60);
    stub.response_cache().insert(key, entry);

    let served = forward(
        &stub,
        &build_query("stale-failure.example", RecordType::A, 2),
    )
    .await
    .expect("stale fallback");
    assert!(
        upstream.calls() > 0,
        "attempt upstream before serving stale"
    );
    assert_eq!(served.metadata.response_code, ResponseCode::NoError);
    assert_eq!(served.answers.len(), 1);
}

#[tokio::test]
async fn expired_stale_window_returns_servfail_on_upstream_failure() {
    let upstream = MockUpstream::start_with(MockUpstreamConfig {
        respond: false,
        ..MockUpstreamConfig::default()
    })
    .await;
    let stub = QueryEngine::new(allow_policy(), stub_config_with_upstream(&upstream));

    let cache_key = CacheKey::from_query("expired.example", RecordType::A, 1);
    let mut entry =
        positive_cache_entry("expired.example", std::net::Ipv4Addr::new(1, 2, 3, 4), 30);
    entry.fresh_until = Instant::now()
        .checked_sub(Duration::from_secs(120))
        .expect("test timestamp");
    entry.stale_until = Instant::now()
        .checked_sub(Duration::from_secs(1))
        .expect("test timestamp");
    stub.response_cache().insert(cache_key, entry);

    let retry = build_query("expired.example", RecordType::A, 2);
    let failed = forward(&stub, &retry).await.expect("servfail");
    assert_eq!(failed.metadata.response_code, ResponseCode::ServFail);
}

#[tokio::test]
async fn degraded_upstreams_serve_stale_immediately() {
    let upstream = MockUpstream::start_with(MockUpstreamConfig {
        respond: false,
        ..MockUpstreamConfig::default()
    })
    .await;
    let stub = QueryEngine::new(allow_policy(), stub_config_with_upstream(&upstream));

    // Prime the cache with a real answer, then age it into the stale window.
    let cache_key = CacheKey::from_query("degraded.example", RecordType::A, 1);
    let mut entry =
        positive_cache_entry("degraded.example", std::net::Ipv4Addr::new(1, 2, 3, 4), 30);
    entry.fresh_until = Instant::now()
        .checked_sub(Duration::from_secs(1))
        .expect("test timestamp");
    entry.stale_until = Instant::now() + Duration::from_secs(60);
    stub.response_cache().insert(cache_key.clone(), entry);

    // Every tier down: an exchange would burn the whole deadline.
    stub.mark_upstream_degraded_for_test();

    let started = Instant::now();
    let served = forward(&stub, &build_query("degraded.example", RecordType::A, 2))
        .await
        .expect("stale answer");
    let elapsed = started.elapsed();

    assert_eq!(served.metadata.response_code, ResponseCode::NoError);
    assert_eq!(served.answers.len(), 1);
    assert!(
        elapsed < Duration::from_millis(500),
        "degraded stale fallback must answer immediately, took {elapsed:?}"
    );
}

#[tokio::test]
async fn degraded_upstreams_fail_fast_without_a_stale_answer_when_recovery_is_busy() {
    let upstream = MockUpstream::start_with(MockUpstreamConfig {
        respond: false,
        ..MockUpstreamConfig::default()
    })
    .await;
    let stub = QueryEngine::new(allow_policy(), stub_config_with_upstream(&upstream));

    stub.mark_upstream_degraded_for_test();
    let _owner = stub.hold_recovery_for_test().expect("recovery owner");
    assert!(stub.recovery_occupied_for_test());

    let started = Instant::now();
    let served = forward(&stub, &build_query("uncached.example", RecordType::A, 3))
        .await
        .expect("servfail");
    let elapsed = started.elapsed();

    assert_eq!(served.metadata.response_code, ResponseCode::ServFail);
    assert!(
        elapsed < Duration::from_millis(500),
        "degraded fail-fast must not wait on upstream I/O, took {elapsed:?}"
    );
}

#[tokio::test]
async fn degraded_fail_fast_is_answered_without_a_miss_task() {
    let upstream = MockUpstream::start_with(MockUpstreamConfig {
        respond: false,
        ..MockUpstreamConfig::default()
    })
    .await;
    let stub = QueryEngine::new(allow_policy(), stub_config_with_upstream(&upstream));
    stub.mark_upstream_degraded_for_test();
    let query = build_query("flood.example", RecordType::A, 7);

    // Down with a recovery attempt free: the miss must go upstream so it can
    // own that attempt.
    assert!(
        respond_locally(&stub, &query).is_none(),
        "a query that can recover the upstream must not be failed locally"
    );

    // Down with the recovery attempt taken: the SERVFAIL the miss path would
    // produce is answered from the receive loop instead.
    let _owner = stub.hold_recovery_for_test().expect("recovery owner");
    let bytes = respond_locally(&stub, &query).expect("answered locally");
    let served = Message::from_vec(&bytes).expect("decode");
    assert_eq!(served.metadata.response_code, ResponseCode::ServFail);
    assert_eq!(served.metadata.id, 7);
    assert_eq!(served.queries, query.queries, "the question is echoed");
    assert_eq!(upstream.calls(), 0);
}

#[tokio::test]
async fn drop_then_answer_recovers_inside_the_query_deadline() {
    let upstream = ControlledUpstream::drop_then_answer().await;
    let stub = QueryEngine::new(allow_policy(), stub_config_with_controlled(&upstream));
    let started = Instant::now();
    let served = forward(
        &stub,
        &build_query("retry-engine.example", RecordType::A, 9),
    )
    .await
    .expect("retry answer");
    assert_eq!(served.metadata.response_code, ResponseCode::NoError);
    assert!(started.elapsed() < Duration::from_secs(2));
    assert!(upstream.calls() >= 2);
    assert!(!upstream.arrivals().is_empty());
}

#[tokio::test]
async fn a_down_udp_upstream_recovers_on_the_next_uncached_name() {
    let upstream = ControlledUpstream::silent().await;
    let stub = QueryEngine::new(allow_policy(), stub_config_with_controlled(&upstream));
    stub.mark_upstream_degraded_for_test();
    upstream.become_responsive();

    let started = Instant::now();
    let served = forward(&stub, &build_query("recovered.example", RecordType::A, 4))
        .await
        .expect("recovery answer");
    let elapsed = started.elapsed();

    assert_eq!(served.metadata.response_code, ResponseCode::NoError);
    assert_eq!(served.answers.len(), 1);
    assert!(
        elapsed < Duration::from_secs(30),
        "the first query after going down owns the recovery attempt, took {elapsed:?}"
    );
    assert!(upstream.calls() >= 1);
}

#[tokio::test]
async fn a_burst_starts_at_most_one_recovery_owner() {
    let upstream = ControlledUpstream::silent().await;
    let stub = QueryEngine::new(allow_policy(), stub_config_with_controlled(&upstream));
    stub.mark_upstream_degraded_for_test();

    let first_query = build_query("burst-a.example", RecordType::A, 5);
    let second_query = build_query("burst-b.example", RecordType::A, 6);
    let first = forward(&stub, &first_query);
    let second = async {
        tokio::time::sleep(Duration::from_millis(30)).await;
        let started = Instant::now();
        let served = forward(&stub, &second_query).await.expect("fail fast");
        (served, started.elapsed())
    };
    let (first_result, (second_served, second_elapsed)) = tokio::join!(first, second);
    assert!(first_result.is_ok());
    assert_eq!(second_served.metadata.response_code, ResponseCode::ServFail);
    assert!(
        second_elapsed < Duration::from_millis(500),
        "non-owners must fail fast, took {second_elapsed:?}"
    );
}

#[tokio::test]
async fn query_deadline_expires_to_servfail() {
    let upstream = MockUpstream::start_with(MockUpstreamConfig {
        delay: Duration::from_secs(5),
        ..MockUpstreamConfig::default()
    })
    .await;
    let stub = QueryEngine::new(allow_policy(), stub_config_with_upstream(&upstream));
    let query = build_query("deadline.example", RecordType::A, 42);
    let enqueued_at = Instant::now()
        .checked_sub(Duration::from_secs(3))
        .expect("test timestamp");
    let bytes = respond(&stub, &query, enqueued_at).await;
    let response = Message::from_vec(&bytes).expect("wire");
    assert_eq!(response.metadata.response_code, ResponseCode::ServFail);
}

#[tokio::test]
async fn invalidate_cache_prevents_sync_hit() {
    let upstream = MockUpstream::start().await;
    let stub = QueryEngine::new(allow_policy(), stub_config_with_upstream(&upstream));

    let query = build_query("invalidate.example", RecordType::A, 1);
    forward(&stub, &query).await.expect("prime");
    assert!(respond_locally(&stub, &query).is_some());

    stub.response_cache().bump_generation();
    assert!(respond_locally(&stub, &query).is_none());
}

#[tokio::test]
async fn txid_is_patched_per_client_on_cache_hit() {
    let upstream = MockUpstream::start().await;
    let stub = QueryEngine::new(allow_policy(), stub_config_with_upstream(&upstream));

    let prime = build_query("txid.example", RecordType::A, 0x1111);
    forward(&stub, &prime).await.expect("prime");

    let client_a = build_query("txid.example", RecordType::A, 0xAAAA);
    let client_b = build_query("txid.example", RecordType::A, 0xBBBB);
    let bytes_a = respond_locally(&stub, &client_a).expect("hit a");
    let bytes_b = respond_locally(&stub, &client_b).expect("hit b");
    assert_eq!(bytes_a[0], 0xAA);
    assert_eq!(bytes_a[1], 0xAA);
    assert_eq!(bytes_b[0], 0xBB);
    assert_eq!(bytes_b[1], 0xBB);
    assert_eq!(&bytes_a[2..], &bytes_b[2..]);
}

#[tokio::test]
async fn prefetch_due_fresh_hit_returns_without_blocking() {
    let upstream = MockUpstream::start().await;
    let stub = QueryEngine::new(allow_policy(), stub_config_with_upstream(&upstream));

    let query = build_query("prefetch.example", RecordType::A, 1);
    let response = forward(&stub, &query).await.expect("prime");
    assert_eq!(upstream.calls(), 1);

    let cache_key = CacheKey::from_query("prefetch.example", RecordType::A, 1);
    let mut entry = ResponseCache::entry_from_message(&response, false).expect("entry");
    entry.prefetch_at = Instant::now()
        .checked_sub(Duration::from_secs(1))
        .expect("test timestamp");
    stub.response_cache().insert(cache_key, entry);

    let prefetch_query = build_query("prefetch.example", RecordType::A, 2);
    let bytes = respond_locally(&stub, &prefetch_query).expect("non-blocking fresh hit");
    assert!(!bytes.is_empty());
    assert_eq!(bytes[0], 0x00);
    assert_eq!(bytes[1], 0x02);
}

#[tokio::test]
async fn edns_client_receives_ede_blocked_on_policy_rejection() {
    let stub = QueryEngine::new(
        BlockOnePolicy {
            domain: "blocked.example",
        },
        DnsConfig {
            block_mode: BlockResponseMode::Sinkhole,
            ..DnsConfig::default()
        },
    );

    let mut query = build_query("blocked.example", RecordType::A, 0x1234);
    let mut edns = hickory_proto::op::Edns::new();
    edns.set_dnssec_ok(true);
    edns.set_max_payload(1232);
    query.set_edns(edns);

    let response = forward(&stub, &query).await.expect("response");
    let resp_edns = response
        .edns
        .as_ref()
        .expect("edns must be present for EDNS client");
    assert!(resp_edns.flags().dnssec_ok);

    let ede_opt = resp_edns.option(hickory_proto::rr::rdata::opt::EdnsCode::from(15));
    assert!(
        ede_opt.is_some(),
        "EDE option must be attached to blocked response"
    );
    if let Some(hickory_proto::rr::rdata::opt::EdnsOption::Unknown(code, data)) = ede_opt {
        assert_eq!(*code, 15);
        assert!(data.len() >= 2);
        let info_code = u16::from_be_bytes([data[0], data[1]]);
        assert_eq!(info_code, 15, "EDE 15 (Blocked)");
    }
}

#[tokio::test]
async fn special_use_domain_resolves_locally_without_upstream_calls() {
    let upstream = MockUpstream::start().await;
    let stub = QueryEngine::new(allow_policy(), stub_config_with_upstream(&upstream));

    // 1. localhost.
    let q_local = build_query("localhost", RecordType::A, 1);
    let resp_local = forward(&stub, &q_local).await.expect("localhost");
    assert_eq!(resp_local.metadata.response_code, ResponseCode::NoError);
    assert_eq!(resp_local.answers.len(), 1);
    assert_eq!(
        resp_local.answers[0].data,
        RData::A(rdata::A(std::net::Ipv4Addr::LOCALHOST))
    );

    // 2. app.localhost. (IPv6)
    let q_v6 = build_query("app.localhost", RecordType::AAAA, 2);
    let resp_v6 = forward(&stub, &q_v6).await.expect("app.localhost");
    assert_eq!(resp_v6.metadata.response_code, ResponseCode::NoError);
    assert_eq!(
        resp_v6.answers[0].data,
        RData::AAAA(rdata::AAAA(std::net::Ipv6Addr::LOCALHOST))
    );

    // 3. Reverse loopback PTR
    let q_ptr = build_query("2.0.0.127.in-addr.arpa", RecordType::PTR, 3);
    let resp_ptr = forward(&stub, &q_ptr).await.expect("ptr");
    assert_eq!(resp_ptr.metadata.response_code, ResponseCode::NoError);
    assert_eq!(
        resp_ptr.answers[0].data,
        RData::PTR(rdata::PTR(Name::from_ascii("localhost.").unwrap()))
    );

    // The address the resolver itself listens on is named for it.
    let q_self = build_query("1.0.0.127.in-addr.arpa", RecordType::PTR, 5);
    let resp_self = forward(&stub, &q_self).await.expect("resolver ptr");
    assert!(matches!(
        &resp_self.answers[0].data,
        RData::PTR(target) if target.0.iter().eq([b"Antiwire Resolver".as_slice()])
    ));

    // 4. Invalid domain (RFC 6761) -> NXDomain
    let q_inv = build_query("something.invalid", RecordType::A, 4);
    let resp_inv = forward(&stub, &q_inv).await.expect("invalid");
    assert_eq!(resp_inv.metadata.response_code, ResponseCode::NXDomain);

    // Upstream was never called for any of these!
    assert_eq!(
        upstream.calls(),
        0,
        "SUDN lookups must never touch upstream resolver"
    );
}

fn stale_entry_for(
    stub: &QueryEngine<impl antiwire_policy::PolicyEngine + Send + Sync>,
    domain: &str,
) {
    let mut entry = positive_cache_entry(domain, std::net::Ipv4Addr::new(1, 2, 3, 4), 30);
    entry.fresh_until = Instant::now()
        .checked_sub(Duration::from_secs(1))
        .expect("test timestamp");
    entry.stale_until = Instant::now() + Duration::from_secs(60);
    stub.response_cache()
        .insert(CacheKey::from_query(domain, RecordType::A, 1), entry);
}

/// Latest a stale answer may arrive in the timer tests: the 1.8 s timer plus
/// slack for a loaded CI runner, whose sleeps have been seen to wake 80 ms
/// late. It stays well under the 2 s query deadline, which is when the stale
/// answer went out before the timer existed, so that regression still fails.
fn stale_served_by() -> Duration {
    let served_by = antiwire_tuning::DNS_STALE_ANSWER_TIMER + Duration::from_millis(150);
    assert!(served_by < antiwire_tuning::DNS_QUERY_DEADLINE);
    served_by
}

/// RFC 8767 §5 client response timer: with a stale answer cached, the client
/// gets it within 1.8 s of asking even when the upstream never replies and
/// the query had already spent part of its deadline before going upstream.
#[tokio::test]
async fn a_stale_answer_is_served_within_the_client_response_timer() {
    let mut waits = Vec::new();
    for already_spent_ms in [0_u64, 200, 400, 600, 1_000] {
        let upstream = MockUpstream::start_with(MockUpstreamConfig {
            respond: false,
            ..MockUpstreamConfig::default()
        })
        .await;
        let stub = QueryEngine::new(allow_policy(), stub_config_with_upstream(&upstream));
        stale_entry_for(&stub, "timer.example");

        let received_at = Instant::now()
            .checked_sub(Duration::from_millis(already_spent_ms))
            .expect("test timestamp");
        let query = build_query("timer.example", RecordType::A, 2);
        let bytes = respond(&stub, &query, received_at).await;
        let wait = received_at.elapsed();
        let served = Message::from_vec(&bytes).expect("reply");
        assert_eq!(served.metadata.response_code, ResponseCode::NoError);
        assert_eq!(served.answers.len(), 1, "stale answer served");
        assert!(
            upstream.calls() > 0,
            "attempt upstream before serving stale"
        );
        waits.push((already_spent_ms, wait));
    }
    println!("stale answer wait (already spent ms, total): {waits:?}");
    for (spent, wait) in waits {
        assert!(
            wait <= stale_served_by(),
            "stale answer after {wait:?} with {spent} ms already spent"
        );
    }
}

/// Serving stale at the timer must not abandon the refresh: a late upstream
/// answer still lands in the cache.
#[tokio::test]
async fn the_refresh_continues_after_the_timer_serves_stale() {
    let upstream = MockUpstream::start_with(MockUpstreamConfig {
        delay: Duration::from_millis(750),
        ..MockUpstreamConfig::default()
    })
    .await;
    let stub = QueryEngine::new(allow_policy(), stub_config_with_upstream(&upstream));
    stale_entry_for(&stub, "late.example");

    // 1.15 s already spent leaves the upstream admission room for one
    // 800 ms transport attempt, but only 650 ms before the timer, less than
    // the upstream's 750 ms.
    let received_at = Instant::now()
        .checked_sub(Duration::from_millis(1_150))
        .expect("test timestamp");
    let bytes = respond(
        &stub,
        &build_query("late.example", RecordType::A, 2),
        received_at,
    )
    .await;
    let wait = received_at.elapsed();
    let served = Message::from_vec(&bytes).expect("reply");
    assert_eq!(served.answers.len(), 1, "stale answer served");
    assert!(wait <= stale_served_by(), "served after {wait:?}");

    let key = CacheKey::from_query("late.example", RecordType::A, 1);
    let refreshed = Instant::now();
    while !matches!(stub.response_cache().probe(&key), CacheProbe::Fresh(_)) {
        assert!(
            refreshed.elapsed() < Duration::from_secs(3),
            "the background refresh never landed"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// `query` with an OPT record, so the reply can carry Extended DNS Errors.
fn with_edns(mut query: Message) -> Message {
    query.set_edns(hickory_proto::op::Edns::new());
    query
}

/// RFC 8914 info codes on `response`.
fn ede_codes(response: &Message) -> Vec<u16> {
    use hickory_proto::rr::rdata::opt::EdnsOption;
    response
        .edns
        .as_ref()
        .map(|edns| {
            edns.options()
                .as_ref()
                .iter()
                .filter_map(|(_, option)| match option {
                    EdnsOption::Unknown(15, data) if data.len() >= 2 => {
                        Some(u16::from_be_bytes([data[0], data[1]]))
                    }
                    _ => None,
                })
                .collect()
        })
        .unwrap_or_default()
}

/// RFC 9520 §3.2: once a name has failed to resolve, a repeat query within
/// the hold is answered from the cached failure without asking upstream, and
/// says so with EDE 13.
#[tokio::test]
async fn a_failed_name_is_not_asked_upstream_again_while_its_failure_is_held() {
    let upstream = MockUpstream::start_with(MockUpstreamConfig {
        servfail: true,
        ..MockUpstreamConfig::default()
    })
    .await;
    let stub = QueryEngine::new(allow_policy(), stub_config_with_upstream(&upstream));

    let query = with_edns(build_query("broken.example", RecordType::A, 1));
    let first = forward(&stub, &query).await.expect("first reply");
    assert_eq!(first.metadata.response_code, ResponseCode::ServFail);
    let asked = upstream.calls();
    assert!(asked > 0, "the first query goes upstream");

    let second = forward(&stub, &query).await.expect("second reply");
    assert_eq!(second.metadata.response_code, ResponseCode::ServFail);
    assert_eq!(upstream.calls(), asked, "a held failure is not re-asked");
    assert_eq!(ede_codes(&second), vec![crate::ede::EDE_CACHED_ERROR]);

    // Other names are unaffected by this one's failure.
    let other = with_edns(build_query("other.example", RecordType::A, 2));
    let _ = forward(&stub, &other).await.expect("other reply");
    assert!(upstream.calls() > asked, "another name still goes upstream");
}

/// RFC 8767: after a refresh fails, the stale answer goes out at once for
/// the failure recheck timer instead of waiting on upstream again, with its
/// expired records at the 30 s stale TTL and EDE 3 saying it is stale.
#[tokio::test]
async fn a_stale_answer_is_served_at_once_after_its_refresh_fails() {
    let upstream = MockUpstream::start_with(MockUpstreamConfig {
        servfail: true,
        ..MockUpstreamConfig::default()
    })
    .await;
    let stub = QueryEngine::new(allow_policy(), stub_config_with_upstream(&upstream));
    let query = with_edns(build_query("flaky.example", RecordType::A, 1));
    // The OPT is part of the cache key, so the stale entry is keyed with it.
    let mut entry = positive_cache_entry("flaky.example", std::net::Ipv4Addr::new(1, 2, 3, 4), 30);
    entry.fresh_until = Instant::now()
        .checked_sub(Duration::from_secs(1))
        .expect("test timestamp");
    entry.stale_until = Instant::now() + Duration::from_secs(60);
    stub.response_cache().insert(
        CacheKey::from_query("flaky.example", RecordType::A, 1)
            .with_flags(crate::response_cache::QueryFlags::from_request(&query)),
        entry,
    );
    stale_entry_for(&stub, "flaky.example");

    let first = forward(&stub, &query).await.expect("first reply");
    assert_eq!(first.metadata.response_code, ResponseCode::NoError);
    assert_eq!(first.answers.len(), 1, "stale answer served");
    assert_eq!(
        first.answers[0].ttl,
        antiwire_tuning::DNS_STALE_ANSWER_TTL_SECONDS
    );
    assert_eq!(ede_codes(&first), vec![crate::ede::EDE_STALE_ANSWER]);
    let asked = upstream.calls();
    assert!(asked > 0, "the refresh was attempted");

    let started = Instant::now();
    let second = forward(&stub, &query).await.expect("second reply");
    assert_eq!(second.answers.len(), 1, "stale answer served again");
    assert_eq!(ede_codes(&second), vec![crate::ede::EDE_STALE_ANSWER]);
    assert_eq!(
        upstream.calls(),
        asked,
        "no refresh within the recheck timer"
    );
    assert!(
        started.elapsed() < Duration::from_millis(200),
        "served from cache, not after an upstream wait: {:?}",
        started.elapsed()
    );

    // A client that sent no OPT gets none back, so no EDE either.
    let plain = forward(&stub, &build_query("flaky.example", RecordType::A, 3))
        .await
        .expect("plain reply");
    assert!(plain.edns.is_none());
    assert_eq!(plain.answers.len(), 1);
}

/// A fresh answer carries no stale marker.
#[tokio::test]
async fn a_fresh_answer_has_no_stale_ede() {
    let upstream = MockUpstream::start().await;
    let stub = QueryEngine::new(allow_policy(), stub_config_with_upstream(&upstream));
    let query = with_edns(build_query("fresh.example", RecordType::A, 1));
    let fetched = forward(&stub, &query).await.expect("fetched");
    let cached = forward(&stub, &query).await.expect("cached");
    assert!(ede_codes(&fetched).is_empty());
    assert!(ede_codes(&cached).is_empty());
    assert_eq!(upstream.calls(), 1);
}

/// RFC 7873 §5: a cookie, like any option about the client's own connection
/// or one this resolver does not know, stays here. With nothing left to
/// change the upstream answer, such a query shares the ordinary cache entry.
#[tokio::test]
async fn hop_by_hop_options_stay_here_and_share_the_cache() {
    use hickory_proto::rr::rdata::opt::{EdnsCode, EdnsOption};
    let upstream = MockUpstream::start().await;
    let stub = QueryEngine::new(allow_policy(), stub_config_with_upstream(&upstream));

    let mut query = with_edns(build_query("cookie.example", RecordType::A, 1));
    let edns = query.edns.as_mut().expect("opt");
    edns.options_mut()
        .insert(EdnsOption::Unknown(10, vec![1, 2, 3, 4, 5, 6, 7, 8]));
    edns.options_mut()
        .insert(EdnsOption::Unknown(65_001, vec![9]));
    let first = forward(&stub, &query).await.expect("first");
    let second = forward(&stub, &query).await.expect("second");
    assert_eq!(first.answers.len(), 1);
    assert_eq!(second.answers.len(), 1);
    assert_eq!(upstream.calls(), 1, "the second query is a cache hit");

    let sent = upstream.received();
    let options = sent[0].edns.as_ref().expect("forwarded OPT").options();
    assert!(options.get(EdnsCode::Cookie).is_none(), "cookie forwarded");
    assert!(
        options.get(EdnsCode::Unknown(65_001)).is_none(),
        "unknown option forwarded"
    );
}

/// RFC 4035 §4.9.3: over plain UDP anyone on the path can set AD, so it does
/// not reach the client even when the client asked for it. The query still
/// asks the upstream to report validation (RFC 6840 §5.7).
#[tokio::test]
async fn ad_from_an_unencrypted_upstream_is_not_passed_on() {
    let upstream = MockUpstream::start_with(MockUpstreamConfig {
        authentic_data: true,
        ..MockUpstreamConfig::default()
    })
    .await;
    let stub = QueryEngine::new(allow_policy(), stub_config_with_upstream(&upstream));

    let mut query = build_query("validated.example", RecordType::A, 1);
    query.metadata.authentic_data = true;
    let response = forward(&stub, &query).await.expect("reply");
    assert_eq!(response.answers.len(), 1);
    assert!(!response.metadata.authentic_data);
    assert!(
        upstream.received()[0].metadata.authentic_data,
        "AD asked upstream"
    );
}

/// RFC 6840 §5.8: a cached answer marked AD shows it only to a client that
/// asked, by setting AD or DO.
#[tokio::test]
async fn ad_reaches_only_clients_that_ask_for_it() {
    let upstream = MockUpstream::start().await;
    let stub = QueryEngine::new(allow_policy(), stub_config_with_upstream(&upstream));
    let domain = "signed.example";
    let fqdn = Name::from_ascii(format!("{domain}.")).expect("name");
    let mut message = Message::response(0, hickory_proto::op::OpCode::Query);
    message.metadata.authentic_data = true;
    message.add_query(hickory_proto::op::Query::query(fqdn.clone(), RecordType::A));
    message.add_answer(hickory_proto::rr::Record::from_rdata(
        fqdn,
        300,
        RData::A(rdata::A::new(192, 0, 2, 7)),
    ));
    stub.response_cache().insert(
        CacheKey::from_query(domain, RecordType::A, 1),
        ResponseCache::entry_from_message(&message, false).expect("entry"),
    );

    let plain = forward(&stub, &build_query(domain, RecordType::A, 1))
        .await
        .expect("plain");
    assert!(!plain.metadata.authentic_data, "client did not ask");

    let mut asking = build_query(domain, RecordType::A, 2);
    asking.metadata.authentic_data = true;
    let asked = forward(&stub, &asking).await.expect("asking");
    assert!(asked.metadata.authentic_data, "client set AD");
    assert_eq!(upstream.calls(), 0, "both served from cache");
}

/// A classifier that never answers, so the proactive gate runs out its budget.
struct HungClassifier;

#[async_trait::async_trait]
impl crate::ai::Classifier for HungClassifier {
    async fn classify(
        &self,
        _domain: &str,
    ) -> Result<antiwire_ai::DomainAssessment, crate::ai::classifier::ClassifierError> {
        std::future::pending().await
    }
}

/// The regression this guards: the proactive AI gate and the new-domain lookup
/// each left less of the query deadline than upstream admission accepts. A
/// name both of them timed out on was refused admission and answered SERVFAIL
/// without upstream being asked, instead of failing open.
#[tokio::test]
async fn a_name_both_gates_time_out_on_still_resolves() {
    use crate::new_domain::testing::FixedSource;
    use crate::new_domain::{NewDomainGuard, RegistrationCache};

    let upstream = MockUpstream::start().await;
    let slow_registry = RegistrationCache::new(FixedSource::new([], Duration::from_secs(5)));
    let engine = QueryEngine::new(allow_policy(), stub_config_with_upstream(&upstream))
        .with_new_domain_guard(NewDomainGuard::new(30, slow_registry));
    let settings = antiwire_store::DaemonSetting {
        ai_enabled: true,
        ai_decision_mode: "proactive".to_owned(),
        ..Default::default()
    };
    let ai = crate::ai::AiCoordinator::new(
        crate::test_support::leaked_store(),
        Some(Arc::new(HungClassifier)),
        &crate::ai::AiPolicySnapshot::from_settings(&settings, 1),
        None,
    );
    engine.set_ai(Some(Arc::clone(&ai)));

    let query = build_query("unseen.example.com", RecordType::A, 7);
    let started = Instant::now();
    let response = forward(&engine, &query).await.expect("response");
    let waited = started.elapsed();

    assert_eq!(response.metadata.response_code, ResponseCode::NoError);
    assert_eq!(response.answers.len(), 1, "the upstream answer is served");
    assert_eq!(upstream.calls(), 1);
    assert!(
        waited >= antiwire_tuning::DNS_AI_FOREGROUND_BUDGET,
        "both gates waited ({waited:?})"
    );
    // Not `shutdown`, which would wait out its timeout on the hung classifier.
    ai.shutdown_cancel();
}

const CACHED_ANSWER: std::net::Ipv4Addr = std::net::Ipv4Addr::new(192, 0, 2, 44);

/// AI settings that block a name judged malicious.
fn ai_policy(mode: &str) -> crate::ai::AiPolicySnapshot {
    let settings = antiwire_store::DaemonSetting {
        ai_enabled: true,
        ai_decision_mode: mode.to_owned(),
        ai_malicious_action: "block".to_owned(),
        ai_confidence_malicious: 80,
        ..Default::default()
    };
    crate::ai::AiPolicySnapshot::from_settings(&settings, 1)
}

/// An engine that cannot reach upstream, with `name` already cached.
fn engine_with_cached(name: &str) -> QueryEngine<super::support::AllowAllPolicy> {
    let engine = QueryEngine::new(
        allow_policy(),
        DnsConfig {
            upstreams: vec!["127.0.0.1:1".to_owned()],
            ..DnsConfig::default()
        },
    );
    engine.response_cache().insert(
        CacheKey::from_query(name, RecordType::A, 1),
        positive_cache_entry(name, CACHED_ANSWER, 300),
    );
    engine
}

fn serves_cached_answer(bytes: &[u8]) -> bool {
    let response = Message::from_vec(bytes).expect("decode");
    matches!(
        response.answers.as_slice(),
        [record] if matches!(&record.data, RData::A(addr) if addr.0 == CACHED_ANSWER)
    )
}

/// The regression this guards: with AI enabled, every query for a name AI
/// applies to took the miss path, cached or not. Each cached answer then cost
/// a task and needed an upstream worker, so cached names stopped resolving
/// whenever the workers were busy.
#[tokio::test]
async fn a_cached_answer_is_served_locally_once_ai_knows_the_name() {
    for mode in ["retroactive", "proactive"] {
        let engine = engine_with_cached("cached.example.com");
        let ai = crate::ai::AiCoordinator::new(
            crate::test_support::leaked_store(),
            None,
            &ai_policy(mode),
            None,
        );
        engine.set_ai(Some(Arc::clone(&ai)));
        let query = build_query("cached.example.com", RecordType::A, 1);

        assert!(
            respond_locally(&engine, &query).is_none(),
            "{mode}: a saved block may exist, and only the store can tell"
        );
        let first = respond(&engine, &query, Instant::now()).await;
        assert!(serves_cached_answer(&first), "{mode}: no decision is saved");

        let local = respond_locally(&engine, &query);
        assert!(
            local.is_some_and(|bytes| serves_cached_answer(&bytes)),
            "{mode}: the store has been read, so nothing is left to wait for"
        );
        ai.shutdown().await;
    }
}

#[tokio::test]
async fn a_saved_decision_in_memory_is_applied_without_the_miss_path() {
    use crate::ai::classifier::test_helpers::{assessment_for, MockBehavior, MockClassifier};

    let store = crate::test_support::leaked_store();
    let classifier =
        MockClassifier::with_assessment("bad.example.com", assessment_for("bad.example.com", 0.99));
    classifier.set(
        "good.example.com",
        MockBehavior::Assess(assessment_for("good.example.com", 0.01)),
    );
    let seed = crate::ai::AiCoordinator::new(
        Arc::clone(&store),
        Some(classifier),
        &ai_policy("proactive"),
        None,
    );
    for name in ["bad.example.com", "good.example.com"] {
        let _ = seed.proactive_gate(name, Duration::from_secs(2)).await;
        assert!(store.cached_domain_decision(name).is_some(), "{name}");
    }
    seed.shutdown().await;

    for mode in ["retroactive", "proactive"] {
        let ai = crate::ai::AiCoordinator::new(Arc::clone(&store), None, &ai_policy(mode), None);

        let engine = engine_with_cached("good.example.com");
        engine.set_ai(Some(Arc::clone(&ai)));
        let allowed = respond_locally(&engine, &build_query("good.example.com", RecordType::A, 2));
        assert!(
            allowed.is_some_and(|bytes| serves_cached_answer(&bytes)),
            "{mode}: a saved decision that allows the name"
        );

        let engine = engine_with_cached("bad.example.com");
        engine.set_ai(Some(Arc::clone(&ai)));
        let blocked = respond_locally(&engine, &build_query("bad.example.com", RecordType::A, 3))
            .expect("a saved block is answered locally");
        assert!(
            !serves_cached_answer(&blocked),
            "{mode}: the cached answer must not get past a saved block"
        );
        ai.shutdown().await;
    }
}

/// Proactive mode classifies an unknown name before it answers, so a name
/// that still has no decision keeps going through the gate.
#[tokio::test]
async fn proactive_ai_still_gates_a_name_it_has_not_classified() {
    use crate::ai::classifier::test_helpers::MockClassifier;

    let engine = engine_with_cached("unjudged.example.com");
    let ai = crate::ai::AiCoordinator::new(
        crate::test_support::leaked_store(),
        Some(MockClassifier::failing("provider down")),
        &ai_policy("proactive"),
        None,
    );
    engine.set_ai(Some(Arc::clone(&ai)));
    let query = build_query("unjudged.example.com", RecordType::A, 4);

    let first = respond(&engine, &query, Instant::now()).await;
    assert!(serves_cached_answer(&first), "the gate fails open");
    assert!(
        respond_locally(&engine, &query).is_none(),
        "the next query must give the classifier another chance"
    );
    ai.shutdown().await;
}
