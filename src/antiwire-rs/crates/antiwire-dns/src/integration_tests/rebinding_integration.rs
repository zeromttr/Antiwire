//! Integration tests for DNS rebinding protection.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use super::support::{
    allow_policy, build_query, forward, positive_cache_entry, stub_config_with_upstream,
    wait_until, MockUpstream, MockUpstreamConfig,
};
use crate::query_engine::EngineServices;
use crate::service::testing::respond_locally;
use crate::{BlockResponseMode, CacheKey, CacheProbe, DnsBlockSink, QueryEngine};
use hickory_proto::op::ResponseCode;
use hickory_proto::rr::{RData, RecordType};

#[derive(Default)]
struct RecordingBlockSink {
    domains: Mutex<Vec<String>>,
}

impl DnsBlockSink for RecordingBlockSink {
    fn record_blocked_query(&self, domain: &str, _pid: u32, _blocklist_names: &[String]) {
        self.domains.lock().expect("lock").push(domain.to_owned());
    }
}

#[tokio::test]
async fn rebinding_protection_blocks_private_upstream_answers() {
    let upstream = MockUpstream::start_with(MockUpstreamConfig {
        answer_ipv4: std::net::Ipv4Addr::new(192, 168, 1, 50),
        ..MockUpstreamConfig::default()
    })
    .await;

    let mut config = stub_config_with_upstream(&upstream);
    config.rebinding_protection_enabled = true;

    let stub = QueryEngine::new(allow_policy(), config);
    let query = build_query("rebind.example", RecordType::A, 1);
    let response = forward(&stub, &query).await.expect("response");

    assert_eq!(response.metadata.response_code, ResponseCode::NoError);
    assert!(response.answers.is_empty());
}

#[tokio::test]
async fn rebinding_protection_records_blocked_domain() {
    let upstream = MockUpstream::start_with(MockUpstreamConfig {
        answer_ipv4: std::net::Ipv4Addr::new(10, 0, 0, 5),
        ..MockUpstreamConfig::default()
    })
    .await;

    let sink = Arc::new(RecordingBlockSink::default());
    let mut config = stub_config_with_upstream(&upstream);
    config.rebinding_protection_enabled = true;
    config.block_mode = BlockResponseMode::Sinkhole;

    let stub = QueryEngine::try_new(
        allow_policy(),
        &config,
        EngineServices {
            block_sink: Some(sink.clone()),
            ..EngineServices::default()
        },
    )
    .expect("stub");

    let query = build_query("evil.rebind", RecordType::A, 7);
    let response = forward(&stub, &query).await.expect("response");
    assert_eq!(response.metadata.response_code, ResponseCode::NoError);
    assert!(response.answers.is_empty());

    wait_until(Duration::from_secs(1), "blocked domain recorded", || {
        sink.domains
            .lock()
            .expect("lock")
            .iter()
            .any(|domain| domain == "evil.rebind")
    })
    .await;
}

/// The regression this guards: an upstream that will not resolve `localhost`
/// returns the alias alone. It used to pass, and the client's follow-up query
/// for the target was answered locally with 127.0.0.1.
#[tokio::test]
async fn an_alias_only_answer_to_localhost_is_filtered() {
    let upstream = MockUpstream::start_with(MockUpstreamConfig {
        alias_to: Some("app.localhost."),
        ..MockUpstreamConfig::default()
    })
    .await;
    let mut config = stub_config_with_upstream(&upstream);
    config.rebinding_protection_enabled = true;
    let stub = QueryEngine::new(allow_policy(), config);

    let query = build_query("rebind.example", RecordType::A, 9);
    let response = forward(&stub, &query).await.expect("response");

    assert_eq!(response.metadata.response_code, ResponseCode::NoError);
    assert!(
        response.answers.is_empty(),
        "the alias must not reach the client: {:?}",
        response.answers
    );
}

#[tokio::test]
async fn an_alias_only_answer_to_a_public_name_passes() {
    let upstream = MockUpstream::start_with(MockUpstreamConfig {
        alias_to: Some("cdn.example.net."),
        ..MockUpstreamConfig::default()
    })
    .await;
    let mut config = stub_config_with_upstream(&upstream);
    config.rebinding_protection_enabled = true;
    let stub = QueryEngine::new(allow_policy(), config);

    let query = build_query("www.example", RecordType::A, 10);
    let response = forward(&stub, &query).await.expect("response");

    assert!(matches!(
        response.answers.as_slice(),
        [record] if matches!(&record.data, RData::CNAME(target) if target.0.to_ascii() == "cdn.example.net.")
    ));
}

#[tokio::test]
async fn an_alias_to_localhost_passes_when_rebinding_disabled() {
    let upstream = MockUpstream::start_with(MockUpstreamConfig {
        alias_to: Some("localhost."),
        ..MockUpstreamConfig::default()
    })
    .await;
    let stub = QueryEngine::new(allow_policy(), stub_config_with_upstream(&upstream));

    let query = build_query("dev.example", RecordType::A, 11);
    let response = forward(&stub, &query).await.expect("response");

    assert_eq!(response.answers.len(), 1);
}

#[tokio::test]
async fn public_upstream_answers_pass_when_rebinding_enabled() {
    let upstream = MockUpstream::start().await;
    let mut config = stub_config_with_upstream(&upstream);
    config.rebinding_protection_enabled = true;

    let stub = QueryEngine::new(allow_policy(), config);
    let query = build_query("public.example", RecordType::A, 3);
    let response = forward(&stub, &query).await.expect("response");

    assert_eq!(response.metadata.response_code, ResponseCode::NoError);
    assert_eq!(response.answers.len(), 1);
}

#[tokio::test]
async fn private_upstream_answers_allowed_when_rebinding_disabled() {
    let upstream = MockUpstream::start_with(MockUpstreamConfig {
        answer_ipv4: std::net::Ipv4Addr::LOCALHOST,
        ..MockUpstreamConfig::default()
    })
    .await;

    let config = stub_config_with_upstream(&upstream);
    let stub = QueryEngine::new(allow_policy(), config);
    let query = build_query("local.example", RecordType::A, 4);
    let response = forward(&stub, &query).await.expect("response");

    assert_eq!(response.answers.len(), 1);
}

/// A still-fresh public answer must survive a background refresh that sees a
/// private address. Prefetch used to cache that as NODATA and wipe the entry.
#[tokio::test]
async fn prefetch_rebinding_refresh_does_not_replace_a_fresh_positive_entry() {
    let upstream = MockUpstream::start_with(MockUpstreamConfig {
        answer_ipv4: std::net::Ipv4Addr::new(192, 168, 1, 50),
        ..MockUpstreamConfig::default()
    })
    .await;

    let mut config = stub_config_with_upstream(&upstream);
    config.rebinding_protection_enabled = true;
    let stub = QueryEngine::new(allow_policy(), config);

    let public = std::net::Ipv4Addr::new(93, 184, 216, 34);
    let cache_key = CacheKey::from_query("prefetch-rebind.example", RecordType::A, 1);
    let mut entry = positive_cache_entry("prefetch-rebind.example", public, 300);
    entry.prefetch_at = Instant::now()
        .checked_sub(Duration::from_secs(1))
        .expect("test timestamp");
    stub.response_cache().insert(cache_key.clone(), entry);

    let hit = build_query("prefetch-rebind.example", RecordType::A, 2);
    assert!(
        respond_locally(&stub, &hit).is_some(),
        "fresh hit schedules prefetch without blocking"
    );

    wait_until(
        Duration::from_secs(1),
        "prefetch to reach the private upstream",
        || upstream.calls() >= 1,
    )
    .await;
    wait_until(Duration::from_secs(1), "prefetch to finish", || {
        !stub.response_cache().prefetch_in_flight(&cache_key)
    })
    .await;

    let CacheProbe::Fresh(entry) = stub.response_cache().probe(&cache_key) else {
        panic!("positive entry must remain fresh");
    };
    let message = entry.parsed_message.as_deref().expect("parsed");
    assert_eq!(
        message.answers.len(),
        1,
        "must not be overwritten with NODATA"
    );
    assert!(
        matches!(&message.answers[0].data, RData::A(addr) if addr.0 == public),
        "must keep the public address"
    );
}

/// The filtered NODATA is cached and replayed to other clients, so it must not
/// carry the first client's EDNS options, such as its ECS subnet.
#[tokio::test]
async fn cached_rebinding_nodata_does_not_replay_another_clients_edns_options() {
    use hickory_proto::op::Edns;
    use hickory_proto::rr::rdata::opt::{EdnsCode, EdnsOption};

    let upstream = MockUpstream::start_with(MockUpstreamConfig {
        answer_ipv4: std::net::Ipv4Addr::new(192, 168, 1, 50),
        ..MockUpstreamConfig::default()
    })
    .await;
    let mut config = stub_config_with_upstream(&upstream);
    config.rebinding_protection_enabled = true;
    let stub = QueryEngine::new(allow_policy(), config);

    let with_edns = |id, subnet: Option<&str>| {
        let mut query = build_query("rebind.example", RecordType::A, id);
        let mut edns = Edns::new();
        edns.set_max_payload(1232);
        if let Some(subnet) = subnet {
            edns.options_mut()
                .insert(EdnsOption::Subnet(subnet.parse().expect("subnet")));
        }
        query.set_edns(edns);
        query
    };

    let first = forward(&stub, &with_edns(1, Some("198.51.100.0/24")))
        .await
        .expect("first");
    assert!(first.answers.is_empty());

    let second = forward(&stub, &with_edns(2, None)).await.expect("second");
    assert!(second.answers.is_empty());
    assert_eq!(upstream.calls(), 1, "the second answer came from the cache");
    let edns = second.edns.as_ref().expect("opt");
    assert!(
        edns.option(EdnsCode::Subnet).is_none(),
        "replayed another client's subnet: {edns:?}"
    );
    assert!(
        edns.option(EdnsCode::Unknown(15)).is_some(),
        "filtered EDE kept"
    );
}

/// A filtering resolver that answers a blocked name with `0.0.0.0`.
const ZERO_ADDRESS_PROVIDER: &str = "https://security.cloudflare-dns.com/dns-query";

/// Every blocked query with the lists it was attributed to.
#[derive(Default)]
struct AttributionSink {
    blocks: Mutex<Vec<(String, Vec<String>)>>,
}

impl DnsBlockSink for AttributionSink {
    fn record_blocked_query(&self, domain: &str, _pid: u32, blocklist_names: &[String]) {
        self.blocks
            .lock()
            .expect("lock")
            .push((domain.to_owned(), blocklist_names.to_vec()));
    }
}

/// An engine with rebinding protection on, whose upstream answers `0.0.0.0`
/// as `ZERO_ADDRESS_PROVIDER` does for a name it blocks.
async fn provider_blocking_engine() -> (
    MockUpstream,
    Arc<AttributionSink>,
    QueryEngine<super::support::AllowAllPolicy>,
) {
    let upstream = MockUpstream::start_with(MockUpstreamConfig {
        answer_ipv4: std::net::Ipv4Addr::UNSPECIFIED,
        ..MockUpstreamConfig::default()
    })
    .await;
    let sink = Arc::new(AttributionSink::default());
    let mut config = stub_config_with_upstream(&upstream);
    config.rebinding_protection_enabled = true;
    let engine = QueryEngine::try_new(
        allow_policy(),
        &config,
        EngineServices {
            block_sink: Some(sink.clone()),
            ..EngineServices::default()
        },
    )
    .expect("engine");
    engine.set_upstream_endpoints_for_test(vec![ZERO_ADDRESS_PROVIDER.to_owned()]);
    (upstream, sink, engine)
}

/// The EDE info code on a cached answer.
fn cached_ede(entry: &crate::response_cache::CachedAnswer) -> Option<u16> {
    use hickory_proto::rr::rdata::opt::{EdnsCode, EdnsOption};

    let edns = entry.parsed_message.as_deref()?.edns.as_ref()?;
    match edns.option(EdnsCode::from(crate::ede::EDNS_OPTION_CODE_EDE))? {
        EdnsOption::Unknown(_, data) => Some(u16::from_be_bytes([*data.first()?, *data.get(1)?])),
        _ => None,
    }
}

/// The regression this guards: rebinding protection ran before the provider
/// check and its ranges include `0.0.0.0`, so a filtering resolver's block was
/// logged and recorded as a rebinding attempt.
#[tokio::test]
async fn a_provider_block_is_withheld_but_reported_as_the_providers() {
    let (_upstream, sink, engine) = provider_blocking_engine().await;

    let query = build_query("ads.example", RecordType::A, 3);
    let response = forward(&engine, &query).await.expect("response");
    assert_eq!(response.metadata.response_code, ResponseCode::NoError);
    assert!(
        response.answers.is_empty(),
        "0.0.0.0 is still withheld: an attacker's looks the same"
    );

    wait_until(Duration::from_secs(1), "block recorded", || {
        !sink.blocks.lock().expect("lock").is_empty()
    })
    .await;
    assert_eq!(
        *sink.blocks.lock().expect("lock"),
        vec![(
            "ads.example".to_owned(),
            vec![crate::provider_block::DNS_PROVIDER_BLOCK_LABEL.to_owned()]
        )]
    );

    let key = CacheKey::from_query("ads.example", RecordType::A, 1);
    let CacheProbe::Fresh(entry) = engine.response_cache().probe(&key) else {
        panic!("the withheld answer is cached");
    };
    assert_eq!(cached_ede(&entry), Some(crate::ede::EDE_BLOCKED));
}

/// A private address is a rebinding attempt whichever resolver passed it on.
#[tokio::test]
async fn a_private_answer_from_a_filtering_resolver_is_still_rebinding() {
    let upstream = MockUpstream::start_with(MockUpstreamConfig {
        answer_ipv4: std::net::Ipv4Addr::new(10, 0, 0, 5),
        ..MockUpstreamConfig::default()
    })
    .await;
    let sink = Arc::new(AttributionSink::default());
    let mut config = stub_config_with_upstream(&upstream);
    config.rebinding_protection_enabled = true;
    let engine = QueryEngine::try_new(
        allow_policy(),
        &config,
        EngineServices {
            block_sink: Some(sink.clone()),
            ..EngineServices::default()
        },
    )
    .expect("engine");
    engine.set_upstream_endpoints_for_test(vec![ZERO_ADDRESS_PROVIDER.to_owned()]);

    let query = build_query("evil.example", RecordType::A, 4);
    let response = forward(&engine, &query).await.expect("response");
    assert!(response.answers.is_empty());

    wait_until(Duration::from_secs(1), "block recorded", || {
        !sink.blocks.lock().expect("lock").is_empty()
    })
    .await;
    assert_eq!(
        *sink.blocks.lock().expect("lock"),
        vec![("evil.example".to_owned(), Vec::new())]
    );
    let key = CacheKey::from_query("evil.example", RecordType::A, 1);
    let CacheProbe::Fresh(entry) = engine.response_cache().probe(&key) else {
        panic!("the withheld answer is cached");
    };
    assert_eq!(cached_ede(&entry), Some(crate::ede::EDE_FILTERED));
}

/// The withheld block has a short TTL. Its refresh used to be thrown away as a
/// rebinding answer, so a blocked name that kept being asked for was fetched
/// again in the foreground every time the entry ran out.
#[tokio::test]
async fn a_withheld_provider_block_is_refreshed_in_the_background() {
    let (upstream, _sink, engine) = provider_blocking_engine().await;
    let query = build_query("tracker.example", RecordType::A, 5);
    forward(&engine, &query).await.expect("response");
    assert_eq!(upstream.calls(), 1);

    let key = CacheKey::from_query("tracker.example", RecordType::A, 1);
    let CacheProbe::Fresh(mut entry) = engine.response_cache().probe(&key) else {
        panic!("the withheld answer is cached");
    };
    let first_cached_at = entry.cached_at;
    entry.prefetch_at = Instant::now()
        .checked_sub(Duration::from_secs(1))
        .expect("test timestamp");
    engine.response_cache().insert(key.clone(), entry);

    assert!(
        respond_locally(&engine, &query).is_some(),
        "the hit is answered from cache and schedules the refresh"
    );
    wait_until(Duration::from_secs(1), "refresh to reach upstream", || {
        upstream.calls() >= 2
    })
    .await;
    wait_until(Duration::from_secs(1), "refresh to finish", || {
        !engine.response_cache().prefetch_in_flight(&key)
    })
    .await;

    let CacheProbe::Fresh(refreshed) = engine.response_cache().probe(&key) else {
        panic!("the refreshed answer is cached");
    };
    assert!(
        refreshed.cached_at > first_cached_at,
        "the refresh replaced the entry"
    );
    assert_eq!(cached_ede(&refreshed), Some(crate::ede::EDE_BLOCKED));
    assert!(refreshed
        .parsed_message
        .as_deref()
        .is_some_and(|message| message.answers.is_empty()));
}
