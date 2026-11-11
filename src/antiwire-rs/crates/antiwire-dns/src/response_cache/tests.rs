//! Tests for the response cache module tree.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use antiwire_tuning::{
    DNS_DEFAULT_TTL_SECONDS, DNS_MAX_UPSTREAM_TTL_SECONDS, DNS_MIN_UPSTREAM_TTL_SECONDS,
    DNS_PREFETCH_FRACTION, DNS_RESPONSE_CACHE_BYTE_CAP, DNS_RESPONSE_CACHE_HARD_CAP,
    DNS_RESPONSE_CACHE_MAX_ENTRY_BYTES, DNS_STALE_ANSWER_TTL_SECONDS,
};

use hickory_proto::op::Message;
use hickory_proto::rr::{RData, RecordType};

use crate::messages::encode_message;
use crate::{DnsError, Result};

use super::coalesce::InflightState;
use super::entry::{cache_entry_weight, AnswerExpiry};
use super::prefetch::PrefetchBackoff;
use super::*;
use hickory_proto::op::{MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::{rdata, Name, Record};
use tokio::sync::Semaphore;

fn sample_response() -> Message {
    let mut response = Message::new(0, MessageType::Response, OpCode::Query);
    response.metadata.response_code = ResponseCode::NoError;
    response.add_query(Query::query(
        Name::from_ascii("example.test.").expect("name"),
        RecordType::A,
    ));
    response.add_answer(Record::from_rdata(
        Name::from_ascii("example.test.").expect("name"),
        30,
        RData::A(rdata::A(std::net::Ipv4Addr::new(1, 2, 3, 4))),
    ));
    response
}

/// Test-local mirror of the query engine's generation-retry loop, built on
/// [`ResponseCache::resolve_once`]. Production owns this loop (and its
/// per-attempt upstream re-acquisition) in the query engine.
async fn resolve_with_retry<F, Fut>(
    cache: &ResponseCache,
    key: &CacheKey,
    generation_at_start: u64,
    init: F,
) -> Result<CachedAnswer>
where
    F: Fn() -> Fut,
    Fut: std::future::Future<Output = Result<CachedAnswer>>,
{
    let mut generation = generation_at_start;
    let mut attempts_remaining = FETCH_GENERATION_ATTEMPTS;
    while attempts_remaining > 0 {
        attempts_remaining -= 1;
        match cache.resolve_once(key, generation, &init).await {
            SharedOutcome::Ready(Ok(entry)) => return Ok(entry),
            SharedOutcome::Ready(Err(error)) => return Err((*error).clone()),
            SharedOutcome::GenerationRetired => generation = cache.current_generation(),
        }
    }
    Err(DnsError::Config("cache generation changed".to_owned()))
}

#[tokio::test]
async fn oversized_answers_are_served_but_not_retained() {
    let cache = ResponseCache::new();
    let key = CacheKey::from_query("huge.test", RecordType::A, 1);
    let generation = cache.current_generation();
    let oversized = vec![0u8; DNS_RESPONSE_CACHE_MAX_ENTRY_BYTES as usize + 1];

    let entry = resolve_with_retry(&cache, &key, generation, || async {
        Ok(ResponseCache::entry_from_wire(&oversized, 300, false))
    })
    .await
    .expect("oversized answer is still returned to the client");

    assert!(!entry.cacheable);
    assert_eq!(entry.encoded_len, oversized.len());
    assert!(
        matches!(cache.probe(&key), CacheProbe::Miss),
        "oversized answer must not be retained"
    );
}

#[test]
fn answers_within_the_entry_limit_stay_cacheable() {
    let entry = ResponseCache::entry_from_message(&sample_response(), false).expect("entry");
    assert!(entry.cacheable);
}

#[test]
fn cache_weight_enforces_byte_and_entry_bounds() {
    let entry = ResponseCache::entry_from_message(&sample_response(), false).expect("entry");
    let key = CacheKey::from_query("example.test", RecordType::A, 1);
    let byte_cap = usize::try_from(DNS_RESPONSE_CACHE_BYTE_CAP).expect("positive byte cap");
    let hard_cap = usize::try_from(DNS_RESPONSE_CACHE_HARD_CAP).expect("positive hard cap");
    let minimum_weight = byte_cap.div_ceil(hard_cap);

    assert!(usize::try_from(cache_entry_weight(&key, &entry)).unwrap() >= minimum_weight);
    assert!(minimum_weight.saturating_mul(hard_cap) <= byte_cap);
    assert!(minimum_weight.saturating_mul(hard_cap + 1) > byte_cap);

    let long_key = CacheKey::from_query(&"x".repeat(4_096), RecordType::A, 1);
    assert!(cache_entry_weight(&long_key, &entry) > cache_entry_weight(&key, &entry));
}

#[tokio::test]
async fn coalesces_concurrent_misses() {
    let cache = Arc::new(ResponseCache::new());
    let key = CacheKey::from_query("example.test", RecordType::A, 1);
    let generation = cache.current_generation();
    let calls = Arc::new(AtomicU64::new(0));

    let mut handles = Vec::new();
    for _ in 0..10 {
        let cache = Arc::clone(&cache);
        let key = key.clone();
        let calls = Arc::clone(&calls);
        handles.push(tokio::spawn(async move {
            resolve_with_retry(&cache, &key, generation, || {
                let calls = Arc::clone(&calls);
                async move {
                    calls.fetch_add(1, Ordering::SeqCst);
                    tokio::time::sleep(Duration::from_millis(10)).await;
                    let message = sample_response();
                    ResponseCache::entry_from_message(&message, false)
                }
            })
            .await
        }));
    }

    for handle in handles {
        handle.await.expect("join").expect("resolve");
    }

    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert!(cache.inflight.is_empty());
}

#[tokio::test]
async fn completed_failure_is_not_reused() {
    let cache = ResponseCache::new();
    let key = CacheKey::from_query("retry.test", RecordType::A, 1);
    let generation = cache.current_generation();

    let first = resolve_with_retry(&cache, &key, generation, || async {
        Err(DnsError::Upstream("transient failure".to_owned()))
    })
    .await;
    assert!(first.is_err());
    assert!(cache.inflight.is_empty());

    let second = resolve_with_retry(&cache, &key, generation, || async {
        ResponseCache::entry_from_message(&sample_response(), false)
    })
    .await;
    assert!(second.is_ok());
    assert!(cache.inflight.is_empty());
}

#[tokio::test]
async fn bump_during_fetch_refetches_under_new_generation() {
    let cache = Arc::new(ResponseCache::new());
    let key = CacheKey::from_query("generation.test", RecordType::A, 1);
    let generation = cache.current_generation();
    let started = Arc::new(Semaphore::new(0));
    let release = Arc::new(Semaphore::new(0));
    let calls = Arc::new(AtomicU64::new(0));
    let task_cache = Arc::clone(&cache);
    let task_key = key.clone();
    let task_started = Arc::clone(&started);
    let task_release = Arc::clone(&release);
    let task_calls = Arc::clone(&calls);

    let task = tokio::spawn(async move {
        resolve_with_retry(&task_cache, &task_key, generation, move || {
            let started = Arc::clone(&task_started);
            let release = Arc::clone(&task_release);
            let calls = Arc::clone(&task_calls);
            async move {
                calls.fetch_add(1, Ordering::SeqCst);
                started.add_permits(1);
                let _permit = release.acquire().await.expect("gate remains open");
                ResponseCache::entry_from_message(&sample_response(), false)
            }
        })
        .await
    });

    // Hold the first fetch open while the generation is retired beneath it.
    started.acquire().await.expect("fetch starts").forget();
    cache.bump_generation();
    // Both the discarded first attempt and the retry must pass the gate.
    release.add_permits(2);

    let entry = tokio::time::timeout(Duration::from_secs(1), task)
        .await
        .expect("recovery completes")
        .expect("join")
        .expect("refetch under the new generation succeeds");

    assert_eq!(
        calls.load(Ordering::SeqCst),
        2,
        "the retired attempt must be rerun exactly once"
    );
    assert_eq!(
        entry.encoded_len,
        encode_message(&sample_response())
            .expect("encode sample")
            .len(),
        "served answer comes from the post-bump fetch"
    );
    assert!(
        matches!(cache.probe(&key), CacheProbe::Fresh(_)),
        "the recovered answer must be cached under the new generation"
    );
    assert!(cache.inflight.is_empty());
}

#[tokio::test]
async fn concurrent_waiters_recover_after_generation_bump() {
    let cache = Arc::new(ResponseCache::new());
    let key = CacheKey::from_query("waiters.test", RecordType::A, 1);
    let generation = cache.current_generation();
    let started = Arc::new(Semaphore::new(0));
    let release = Arc::new(Semaphore::new(0));
    let calls = Arc::new(AtomicU64::new(0));

    let mut tasks = Vec::new();
    for _ in 0..3 {
        let cache = Arc::clone(&cache);
        let key = key.clone();
        let started = Arc::clone(&started);
        let release = Arc::clone(&release);
        let calls = Arc::clone(&calls);
        tasks.push(tokio::spawn(async move {
            resolve_with_retry(&cache, &key, generation, move || {
                let started = Arc::clone(&started);
                let release = Arc::clone(&release);
                let calls = Arc::clone(&calls);
                async move {
                    calls.fetch_add(1, Ordering::SeqCst);
                    started.add_permits(1);
                    let _permit = release.acquire().await.expect("gate remains open");
                    ResponseCache::entry_from_message(&sample_response(), false)
                }
            })
            .await
        }));
    }

    // One permit per coalesced fetch: only each cell's initiator runs init.
    started
        .acquire()
        .await
        .expect("first fetch starts")
        .forget();
    cache.bump_generation();
    release.add_permits(4);
    started.acquire().await.expect("retry starts").forget();

    let callers = tasks.len();
    for task in tasks {
        tokio::time::timeout(Duration::from_secs(1), task)
            .await
            .expect("waiters recover")
            .expect("join")
            .expect("every waiter resolves under the new generation");
    }

    // Exactly how many fetches run depends on scheduler timing: a caller
    // polled only after the bump never sees the retired cell and spends
    // its first attempt on the stale-generation check. What matters is
    // that every caller recovers, the retired answer was rerun rather
    // than adopted, and no caller exceeds its retry budget.
    let attempts = usize::try_from(calls.load(Ordering::SeqCst)).expect("call count fits");
    assert!(
        attempts >= 2,
        "the retired fetch must be rerun under the new generation"
    );
    assert!(
        attempts <= callers * FETCH_GENERATION_ATTEMPTS,
        "each caller must respect the bounded retry budget"
    );
    assert!(matches!(cache.probe(&key), CacheProbe::Fresh(_)));
    assert!(cache.inflight.is_empty());
}

#[tokio::test]
async fn generation_flapping_exhausts_retry_budget() {
    let cache = Arc::new(ResponseCache::new());
    let key = CacheKey::from_query("flap.test", RecordType::A, 1);
    let generation = cache.current_generation();
    let calls = Arc::new(AtomicU64::new(0));
    let bump_cache = Arc::clone(&cache);
    let task_calls = Arc::clone(&calls);

    // Every attempt retires itself by bumping the generation mid-fetch,
    // simulating a pathologically flapping network.
    let result = resolve_with_retry(&cache, &key, generation, move || {
        let bump_cache = Arc::clone(&bump_cache);
        let calls = Arc::clone(&task_calls);
        async move {
            calls.fetch_add(1, Ordering::SeqCst);
            bump_cache.bump_generation();
            ResponseCache::entry_from_message(&sample_response(), false)
        }
    })
    .await;

    assert!(
        matches!(result, Err(DnsError::Config(_))),
        "the exhausted budget must surface the historical sentinel error"
    );
    assert_eq!(
        usize::try_from(calls.load(Ordering::SeqCst)).expect("call count fits"),
        FETCH_GENERATION_ATTEMPTS,
        "the retry budget must bound refetches"
    );
    assert!(cache.inflight.is_empty(), "no cell may leak");
    assert!(
        matches!(cache.probe(&key), CacheProbe::Miss),
        "discarded attempts must never be cached"
    );
}

#[tokio::test]
async fn a_new_generation_never_adopts_a_stale_inflight_answer() {
    // Reproduces the window inside `bump_generation`: the counter has moved
    // but the in-flight map still holds the retired generation's cell, whose
    // fetch already completed. A caller arriving on the new generation must
    // re-fetch, not inherit the answer resolved over the old network.
    let cache = ResponseCache::new();
    let key = CacheKey::from_query("stale-cell.test", RecordType::A, 1);
    let stale = ResponseCache::entry_from_wire(&[0xAA; 12], 300, false);

    let retired = Arc::new(InflightState::first_waiter(cache.current_generation()));
    assert!(retired.result.set(SharedOutcome::Ready(Ok(stale))).is_ok());
    cache.generation.fetch_add(1, Ordering::AcqRel);
    cache.inflight.insert(key.clone(), retired);

    let fetched = Arc::new(AtomicU64::new(0));
    let entry = resolve_with_retry(&cache, &key, cache.current_generation(), || {
        let fetched = Arc::clone(&fetched);
        async move {
            fetched.fetch_add(1, Ordering::SeqCst);
            Ok(ResponseCache::entry_from_wire(&[0xBB; 13], 300, false))
        }
    })
    .await
    .expect("new generation resolves");

    assert_eq!(fetched.load(Ordering::SeqCst), 1, "stale cell was adopted");
    assert_eq!(entry.encoded_len, 13);
    assert!(cache.inflight.is_empty());
}

#[tokio::test]
async fn cancelled_fetch_releases_inflight_cell() {
    let cache = Arc::new(ResponseCache::new());
    let key = CacheKey::from_query("cancel.test", RecordType::A, 1);
    let generation = cache.current_generation();
    let started = Arc::new(Semaphore::new(0));
    let task_cache = Arc::clone(&cache);
    let task_started = Arc::clone(&started);

    let task = tokio::spawn(async move {
        resolve_with_retry(&task_cache, &key, generation, move || {
            let started = Arc::clone(&task_started);
            async move {
                started.add_permits(1);
                std::future::pending::<Result<CachedAnswer>>().await
            }
        })
        .await
    });

    started.acquire().await.expect("fetch starts").forget();
    task.abort();
    let _ = task.await;
    tokio::task::yield_now().await;
    assert!(cache.inflight.is_empty());
}

#[test]
fn bump_generation_invalidates_probe() {
    let cache = ResponseCache::new();
    let key = CacheKey::from_query("example.test", RecordType::A, 1);
    let message = sample_response();
    let entry = ResponseCache::entry_from_message(&message, false).expect("entry");
    cache.insert(key.clone(), entry);
    assert!(matches!(cache.probe(&key), CacheProbe::Fresh(_)));
    cache.bump_generation();
    assert!(matches!(cache.probe(&key), CacheProbe::Miss));
}

#[test]
fn probe_reports_stale_after_fresh_window() {
    let cache = ResponseCache::new();
    let key = CacheKey::from_query("stale.test", RecordType::A, 1);
    let message = sample_response();
    let mut entry = ResponseCache::entry_from_message(&message, false).expect("entry");
    entry.fresh_until = Instant::now()
        .checked_sub(Duration::from_secs(1))
        .expect("instant supports one second subtraction");
    entry.stale_until = Instant::now() + Duration::from_secs(60);
    cache.insert(key.clone(), entry);
    assert!(matches!(cache.probe(&key), CacheProbe::Stale(_)));
}

#[test]
fn negative_answers_do_not_serve_stale_after_failure() {
    let cache = ResponseCache::new();
    let key = CacheKey::from_query("nx.test", RecordType::A, 1);
    let mut response = sample_response();
    response.metadata.response_code = ResponseCode::NXDomain;
    let entry = ResponseCache::entry_from_message(&response, true).expect("entry");
    cache.insert(key.clone(), entry);
    assert!(cache.stale_after_failure(&key).is_none());
}

#[test]
fn stale_after_failure_returns_entry_within_grace() {
    let cache = ResponseCache::new();
    let key = CacheKey::from_query("grace.test", RecordType::A, 1);
    let message = sample_response();
    let mut entry = ResponseCache::entry_from_message(&message, false).expect("entry");
    entry.fresh_until = Instant::now()
        .checked_sub(Duration::from_secs(1))
        .expect("instant supports one second subtraction");
    entry.stale_until = Instant::now() + Duration::from_secs(60);
    cache.insert(key.clone(), entry);
    assert!(cache.stale_after_failure(&key).is_some());
}

#[test]
fn failed_prefetch_is_backed_off_and_success_clears_state() {
    let cache = ResponseCache::new();
    let key = CacheKey::from_query("prefetch.test", RecordType::A, 1);

    cache
        .try_reserve_prefetch(&key)
        .expect("first reservation")
        .complete(false);
    assert!(
        cache.try_reserve_prefetch(&key).is_none(),
        "failure must suppress an immediate retry"
    );
    {
        let state = cache.prefetch_backoff.get(&key).expect("backoff state");
        assert_eq!(state.failures, 1);
        cache.prefetch_backoff.insert(
            key.clone(),
            PrefetchBackoff {
                failures: state.failures,
                retry_after: Instant::now()
                    .checked_sub(Duration::from_millis(1))
                    .expect("instant supports subtraction"),
            },
        );
    }

    cache
        .try_reserve_prefetch(&key)
        .expect("retry after backoff")
        .complete(true);
    assert!(cache.prefetching.get(&key).is_none());
    assert!(cache.prefetch_backoff.get(&key).is_none());
}

/// RFC 2308 ┬º5: the negative TTL is `min(SOA.ttl, SOA.MINIMUM)`.
fn negative_response(soa_ttl: u32, minimum: u32) -> Message {
    let name = Name::from_ascii("example.test.").expect("name");
    let mut response = Message::new(0, MessageType::Response, OpCode::Query);
    response.metadata.response_code = ResponseCode::NXDomain;
    response.add_query(Query::query(name.clone(), RecordType::A));
    response.add_authority(Record::from_rdata(
        name.clone(),
        soa_ttl,
        RData::SOA(rdata::SOA::new(
            name.clone(),
            name,
            1,
            7200,
            3600,
            1_209_600,
            minimum,
        )),
    ));
    response
}

#[test]
fn negative_answers_use_the_soa_derived_ttl() {
    // MINIMUM below the SOA's own TTL wins, and vice versa.
    assert_eq!(
        ResponseCache::message_ttl_seconds(&negative_response(3600, 120)),
        120
    );
    assert_eq!(
        ResponseCache::message_ttl_seconds(&negative_response(90, 3600)),
        90
    );
}

#[test]
fn nxdomain_cname_chain_is_bounded_by_negative_ttl() {
    let mut response = negative_response(60, 60);
    response.add_answer(Record::from_rdata(
        Name::from_ascii("alias.example.test.").expect("alias"),
        300,
        RData::CNAME(rdata::CNAME(
            Name::from_ascii("missing.example.test.").expect("target"),
        )),
    ));

    assert_eq!(ResponseCache::message_ttl_seconds(&response), 60);
}

#[test]
fn fresh_response_drops_expired_auxiliary_records() {
    let mut response = sample_response();
    response.add_additional(Record::from_rdata(
        Name::from_ascii("glue.example.test.").expect("name"),
        5,
        RData::A(rdata::A(std::net::Ipv4Addr::new(10, 0, 0, 1))),
    ));
    let mut entry = ResponseCache::entry_from_message(&response, false).expect("entry");
    entry.cached_at = Instant::now()
        .checked_sub(Duration::from_secs(10))
        .expect("instant supports subtraction");

    let aged = age(&entry).expect("ten seconds of age");
    assert_eq!(aged.answers[0].ttl, 20);
    assert!(aged.additionals.is_empty());
}

fn age(entry: &CachedAnswer) -> Option<Arc<AgedSections>> {
    let message = entry.parsed_message.as_deref().expect("parsed message");
    ResponseCache::age_sections(entry, message)
}

#[test]
fn record_ttls_are_capped_at_the_cache_lifetime() {
    let max = DNS_MAX_UPSTREAM_TTL_SECONDS as u32;
    let mut response = sample_response();
    response.answers[0].ttl = 86_400;
    response.add_additional(Record::from_rdata(
        Name::from_ascii("glue.example.test.").expect("name"),
        86_400,
        RData::A(rdata::A(std::net::Ipv4Addr::new(10, 0, 0, 1))),
    ));

    for entry in [
        ResponseCache::entry_from_message(&response, false).expect("entry"),
        ResponseCache::entry_from_upstream(crate::upstream::UpstreamAnswer {
            message: response.clone(),
            encoded_len: None,
        })
        .expect("entry"),
    ] {
        let stored = entry.parsed_message.as_deref().expect("parsed message");
        assert_eq!(stored.answers[0].ttl, max, "served within the first second");
        assert_eq!(stored.additionals[0].ttl, max);

        let mut aged_entry = entry.clone();
        aged_entry.cached_at = Instant::now()
            .checked_sub(Duration::from_secs(10))
            .expect("instant supports subtraction");
        let aged = age(&aged_entry).expect("ten seconds of age");
        assert_eq!(aged.answers[0].ttl, max - 10);
    }
}

#[test]
fn records_are_served_as_stored_within_the_first_second() {
    let entry = ResponseCache::entry_from_message(&sample_response(), false).expect("entry");
    assert!(
        age(&entry).is_none(),
        "nothing to count down yet, so nothing is copied"
    );
}

#[test]
fn ttl_snapshot_is_reused_within_the_same_elapsed_second() {
    let mut entry = ResponseCache::entry_from_message(&sample_response(), false).expect("entry");
    entry.cached_at = Instant::now()
        .checked_sub(Duration::from_secs(2))
        .expect("instant supports subtraction");
    let first = age(&entry).expect("aged");
    let second = age(&entry).expect("aged again");
    assert!(
        Arc::ptr_eq(&first, &second),
        "the same elapsed-second bucket must share one aged snapshot"
    );
    assert_eq!(first.answers[0].ttl, second.answers[0].ttl);
}

#[test]
fn ttl_snapshot_is_rebuilt_when_the_elapsed_second_changes() {
    let mut entry = ResponseCache::entry_from_message(&sample_response(), false).expect("entry");
    entry.cached_at = Instant::now()
        .checked_sub(Duration::from_secs(2))
        .expect("instant supports subtraction");
    let first = age(&entry).expect("two seconds of age");
    entry.cached_at = Instant::now()
        .checked_sub(Duration::from_secs(3))
        .expect("instant supports subtraction");
    let second = age(&entry).expect("three seconds of age");
    assert!(
        !Arc::ptr_eq(&first, &second),
        "a later elapsed second must not reuse the previous snapshot"
    );
    assert_eq!(first.answers[0].ttl, 28);
    assert_eq!(second.answers[0].ttl, 27);
}

#[test]
fn ttl_snapshot_distinguishes_fresh_and_stale_buckets() {
    let mut entry = ResponseCache::entry_from_message(&sample_response(), false).expect("entry");
    entry.cached_at = Instant::now()
        .checked_sub(Duration::from_secs(10))
        .expect("instant supports subtraction");
    entry.fresh_until = Instant::now() + Duration::from_secs(20);
    let fresh = age(&entry).expect("fresh aged");
    entry.fresh_until = Instant::now()
        .checked_sub(Duration::from_secs(1))
        .expect("instant supports subtraction");
    let stale = age(&entry).expect("stale aged");
    assert!(
        !Arc::ptr_eq(&fresh, &stale),
        "fresh and stale serves in the same elapsed second must not share a snapshot"
    );
}

#[test]
#[ignore = "allocation and timing diagnostic; run with --ignored --nocapture on an optimized build"]
fn ttl_snapshot_reuse_allocation_diagnostic() {
    let mut entry = ResponseCache::entry_from_message(&sample_response(), false).expect("entry");
    entry.cached_at = Instant::now()
        .checked_sub(Duration::from_secs(2))
        .expect("instant supports subtraction");
    let warmup = age(&entry).expect("warmup");
    let iterations = 20_000_u32;

    let started = Instant::now();
    for _ in 0..iterations {
        std::hint::black_box(age(&entry));
    }
    let reused = started.elapsed();

    let started = Instant::now();
    for _ in 0..iterations {
        std::hint::black_box(Arc::new(AgedSections {
            answers: warmup.answers.clone(),
            authorities: warmup.authorities.clone(),
            additionals: warmup.additionals.clone(),
        }));
    }
    let recopy = started.elapsed();

    eprintln!(
        "ttl snapshot diagnostic: {iterations} reused hits {reused:?}; recopying sections {recopy:?}"
    );
    eprintln!(
        "this is a timing diagnostic, not an allocation proof; do not treat it as a measured gain"
    );
}

#[test]
fn minimum_cache_ttl_does_not_turn_a_positive_answer_into_nodata() {
    let mut response = sample_response();
    response.answers[0].ttl = 1;
    let mut entry = ResponseCache::entry_from_message(&response, false).expect("entry");
    entry.cached_at = Instant::now()
        .checked_sub(Duration::from_secs(2))
        .expect("instant supports subtraction");

    let aged = age(&entry).expect("two seconds of age");
    assert_eq!(aged.answers.len(), 1);
    assert_eq!(aged.answers[0].ttl, 1);
}

/// RFC 8767 §4: each expired record of a stale answer goes out at the
/// recommended 30 s, not 1 s, so the client does not re-ask every second.
/// Records still within their TTL keep what is left of it.
#[test]
fn stale_response_serves_expired_records_at_the_stale_ttl() {
    let mut response = sample_response();
    response.add_additional(Record::from_rdata(
        Name::from_ascii("glue.example.test.").expect("name"),
        5,
        RData::A(rdata::A(std::net::Ipv4Addr::new(10, 0, 0, 1))),
    ));
    response.add_additional(Record::from_rdata(
        Name::from_ascii("long.example.test.").expect("name"),
        100,
        RData::A(rdata::A(std::net::Ipv4Addr::new(10, 0, 0, 2))),
    ));
    let mut entry = ResponseCache::entry_from_message(&response, false).expect("entry");
    entry.cached_at = Instant::now()
        .checked_sub(Duration::from_secs(40))
        .expect("instant supports subtraction");
    entry.fresh_until = Instant::now()
        .checked_sub(Duration::from_secs(1))
        .expect("instant supports subtraction");

    let aged = age(&entry).expect("forty seconds of age");
    assert_eq!(aged.answers[0].ttl, DNS_STALE_ANSWER_TTL_SECONDS);
    assert_eq!(aged.additionals[0].ttl, DNS_STALE_ANSWER_TTL_SECONDS);
    assert_eq!(aged.additionals[1].ttl, 60);
}

#[test]
fn soa_derived_negative_ttl_is_clamped_like_any_other() {
    // Still bounded by the upstream TTL clamp, so a zone cannot pin an entry
    // for a day or force a sub-second re-query storm.
    assert_eq!(
        ResponseCache::message_ttl_seconds(&negative_response(1, 1)),
        DNS_MIN_UPSTREAM_TTL_SECONDS as u32
    );
    assert_eq!(
        ResponseCache::message_ttl_seconds(&negative_response(86_400, 86_400)),
        DNS_MAX_UPSTREAM_TTL_SECONDS as u32
    );
}

#[test]
fn answerless_response_without_soa_falls_back_to_the_default_ttl() {
    let mut response = negative_response(600, 600);
    response.authorities.clear();
    assert_eq!(
        ResponseCache::message_ttl_seconds(&response),
        DNS_DEFAULT_TTL_SECONDS as u32
    );
}

#[test]
fn answer_ttl_still_wins_over_any_authority_soa() {
    let mut response = sample_response();
    let name = Name::from_ascii("example.test.").expect("name");
    response.add_authority(Record::from_rdata(
        name.clone(),
        900,
        RData::SOA(rdata::SOA::new(
            name.clone(),
            name,
            1,
            7200,
            3600,
            1_209_600,
            900,
        )),
    ));
    // The 30s answer TTL, not the 900s SOA.
    assert_eq!(ResponseCache::message_ttl_seconds(&response), 30);
}

#[test]
fn short_ttl_entries_never_schedule_a_prefetch_while_fresh() {
    // A TTL under the prefetch floor must not collapse `prefetch_at` onto the
    // insertion instant ΓÇö that made every fresh hit spawn a background
    // refresh, so a popular low-TTL domain re-queried upstream continuously.
    let ttl = u32::try_from(DNS_MIN_UPSTREAM_TTL_SECONDS).expect("positive floor");
    let entry = ResponseCache::entry_from_wire(b"\0\0\0\0\0\0\0\0\0\0\0\0", ttl, false);

    assert!(
        entry.prefetch_at >= entry.fresh_until,
        "short-TTL entry must expire rather than prefetch"
    );
    assert!(!entry.should_prefetch());
}

#[test]
fn long_ttl_entries_still_prefetch_shortly_before_expiry() {
    let entry = ResponseCache::entry_from_wire(b"\0\0\0\0\0\0\0\0\0\0\0\0", 600, false);

    assert!(entry.prefetch_at < entry.fresh_until, "lead time exists");
    assert!(!entry.should_prefetch(), "not yet due at insertion");

    let lead = entry.fresh_until - entry.prefetch_at;
    let expected = Duration::from_secs_f64(600.0 * DNS_PREFETCH_FRACTION);
    assert!(
        lead.abs_diff(expected) < Duration::from_millis(50),
        "lead {lead:?} tracks the configured fraction ({expected:?})"
    );
}

#[test]
fn should_prefetch_entries_near_expiry() {
    let message = sample_response();
    let mut entry = ResponseCache::entry_from_message(&message, false).expect("entry");
    entry.prefetch_at = Instant::now()
        .checked_sub(Duration::from_secs(1))
        .expect("instant supports one second subtraction");
    assert!(entry.should_prefetch());

    let fresh = ResponseCache::entry_from_message(&message, false).expect("entry");
    assert!(!fresh.should_prefetch());
}

#[test]
fn prefetch_reservation_coalesces_until_released() {
    let cache = ResponseCache::new();
    let key = CacheKey::from_query("prefetch.test", RecordType::A, 1);

    let reservation = cache.try_reserve_prefetch(&key).expect("first reservation");
    assert!(cache.try_reserve_prefetch(&key).is_none());

    reservation.complete(true);
    assert!(cache.try_reserve_prefetch(&key).is_some());
}

#[test]
fn old_prefetch_reservation_cannot_release_a_new_generation() {
    let cache = ResponseCache::new();
    let key = CacheKey::from_query("prefetch-generation.test", RecordType::A, 1);
    let old_reservation = cache.try_reserve_prefetch(&key).expect("old reservation");

    cache.bump_generation();
    let new_reservation = cache.try_reserve_prefetch(&key).expect("new reservation");
    drop(old_reservation);

    assert!(cache.try_reserve_prefetch(&key).is_none());
    new_reservation.complete(true);
    assert!(cache.try_reserve_prefetch(&key).is_some());
}

#[test]
fn failure_hold_doubles_up_to_its_ceiling() {
    use antiwire_tuning::{DNS_RESOLUTION_FAILURE_HOLD, DNS_RESOLUTION_FAILURE_MAX_HOLD};
    assert!(
        DNS_RESOLUTION_FAILURE_HOLD >= Duration::from_secs(1),
        "RFC 9520 floor"
    );
    assert!(
        DNS_RESOLUTION_FAILURE_MAX_HOLD <= Duration::from_secs(300),
        "RFC 9520 ceiling"
    );
    assert_eq!(super::failure::failure_hold(1), DNS_RESOLUTION_FAILURE_HOLD);
    assert_eq!(
        super::failure::failure_hold(2),
        DNS_RESOLUTION_FAILURE_HOLD * 2
    );
    assert_eq!(
        super::failure::failure_hold(40),
        DNS_RESOLUTION_FAILURE_MAX_HOLD
    );
}

#[tokio::test]
async fn a_held_failure_blocks_prefetch_and_clears_on_success() {
    let cache = ResponseCache::new();
    let key = CacheKey::from_query("held.test", RecordType::A, 1);
    assert!(!cache.failure_held(&key));

    cache.record_failure(&key, cache.current_generation());
    assert!(cache.failure_held(&key));
    assert!(
        cache.try_reserve_prefetch(&key).is_none(),
        "no outgoing query while a failure is held"
    );

    let outcome = cache
        .resolve_once(&key, cache.current_generation(), &|| async {
            ResponseCache::entry_from_message(&sample_response(), false)
        })
        .await;
    assert!(matches!(outcome, SharedOutcome::Ready(Ok(_))));
    assert!(
        !cache.failure_held(&key),
        "a successful fetch clears the hold"
    );
}

#[test]
fn failures_are_forgotten_with_their_network() {
    let cache = ResponseCache::new();
    let key = CacheKey::from_query("moved.test", RecordType::A, 1);
    let old = cache.current_generation();
    cache.record_failure(&key, old);
    cache.bump_generation();
    assert!(!cache.failure_held(&key), "a network change clears holds");

    cache.record_failure(&key, old);
    assert!(
        !cache.failure_held(&key),
        "a fetch over the retired network records nothing"
    );
}

#[test]
fn a_failure_with_a_stale_answer_holds_for_the_recheck_timer() {
    let cache = ResponseCache::new();
    let key = CacheKey::from_query("recheck.test", RecordType::A, 1);
    let mut entry = ResponseCache::entry_from_message(&sample_response(), false).expect("entry");
    entry.fresh_until = Instant::now()
        .checked_sub(Duration::from_secs(1))
        .expect("instant supports subtraction");
    entry.stale_until = Instant::now() + Duration::from_secs(600);
    cache.insert(key.clone(), entry);

    cache.record_failure(&key, cache.current_generation());
    let hold = cache
        .failures
        .get(&key)
        .expect("failure recorded")
        .held_until
        .saturating_duration_since(Instant::now());
    assert!(
        hold > antiwire_tuning::DNS_RESOLUTION_FAILURE_HOLD
            && hold <= antiwire_tuning::DNS_STALE_FAILURE_RECHECK,
        "expected the RFC 8767 recheck timer, got {hold:?}"
    );
}

/// Moka reads `None` from an expiry callback as "never expire", so a past-due
/// entry must get zero, not `None`.
#[test]
fn a_past_due_entry_expires_at_once() {
    use moka::Expiry;

    let mut entry = ResponseCache::entry_from_message(&sample_response(), false).expect("entry");
    let now = Instant::now();
    entry.stale_until = now
        .checked_sub(Duration::from_secs(1))
        .expect("instant supports subtraction");
    let key = CacheKey::from_query("example.test", RecordType::A, 1);

    assert_eq!(
        AnswerExpiry.expire_after_create(&key, &entry, now),
        Some(Duration::ZERO)
    );
    assert_eq!(
        AnswerExpiry.expire_after_read(&key, &entry, now, None, now),
        Some(Duration::ZERO)
    );
    assert_eq!(
        AnswerExpiry.expire_after_update(&key, &entry, now, None),
        Some(Duration::ZERO)
    );
}
