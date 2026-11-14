//! Tests for query orchestration.

#[tokio::test]
async fn dropping_encrypted_engines_releases_upstream_pools() {
    for _ in 0..8 {
        let engine = QueryEngine::new(
            AllowAll,
            DnsConfig {
                protocol: crate::settings::DnsProtocol::Https,
                upstreams: vec!["https://127.0.0.1/dns-query".to_owned()],
                ..DnsConfig::default()
            },
        );
        let upstream = Arc::downgrade(engine.upstream.read().inner());
        tokio::task::yield_now().await;
        drop(engine);
        tokio::time::timeout(Duration::from_secs(1), async {
            while upstream.strong_count() != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("retired engine must release its upstream pool");
    }
}

#[tokio::test]
async fn network_reset_replaces_and_releases_the_upstream_pool() {
    let engine = QueryEngine::new(
        AllowAll,
        DnsConfig {
            protocol: crate::settings::DnsProtocol::Https,
            upstreams: vec!["https://127.0.0.1/dns-query".to_owned()],
            ..DnsConfig::default()
        },
    );
    let generation = engine.response_cache.current_generation();
    let retired = Arc::downgrade(engine.upstream.read().inner());

    engine
        .reset_after_network_change()
        .await
        .expect("rebuild upstream resolver");

    assert_eq!(engine.response_cache.current_generation(), generation + 1);
    tokio::time::timeout(Duration::from_secs(1), async {
        while retired.strong_count() != 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("retired upstream pool must be released");
}

use std::cell::Cell;

use parking_lot::Mutex;

use super::ai::*;
use super::local::*;
use super::prefetch::*;
use super::request::*;
use super::*;
use crate::block::DnsQueryContext;
use crate::domain_key;
use crate::response_cache::{CacheKey, QueryFlags};
use crate::service::testing::{respond, respond_locally};
use antiwire_policy::DomainDecision;
use antiwire_policy::{DomainBlockSource, Verdict};
use antiwire_tuning::{DNS_FAIL_FAST_REPLY_BUDGET, DNS_FAIL_FAST_REPLY_WINDOW, DNS_QUERY_DEADLINE};
use hickory_proto::op::{Edns, Message, Metadata, ResponseCode};
use hickory_proto::op::{MessageType, OpCode, Query};
use hickory_proto::rr::{rdata::opt::EdnsOption, Name};
use hickory_proto::rr::{DNSClass, Record, RecordType};
use std::time::{Duration, Instant};

#[test]
fn fail_fast_budget_refills_each_window() {
    let budget = FailFastBudget::new();
    let window = DNS_FAIL_FAST_REPLY_WINDOW;
    let answered = (0..DNS_FAIL_FAST_REPLY_BUDGET + 50)
        .filter(|_| budget.try_take_at(window / 2))
        .count();
    assert_eq!(answered, DNS_FAIL_FAST_REPLY_BUDGET as usize);
    assert!(!budget.try_take_at(window / 2), "the window is spent");
    assert!(
        budget.try_take_at(window * 3 / 2),
        "the next window refills"
    );
}

#[test]
fn fail_fast_drops_are_counted_for_the_engine_lifetime() {
    let budget = FailFastBudget::new();
    assert_eq!(budget.note_drop(), 1);
    assert_eq!(budget.note_drop(), 2);
    assert_eq!(budget.note_drop(), 3);
}

#[test]
fn ai_eligibility_accepts_single_character_labels() {
    let eligible = |name: &str| {
        ai_domain_eligible(&domain_key::from_name(
            &Name::from_ascii(name).expect("name"),
            true,
        ))
    };
    assert!(eligible("x.com."));
    assert!(eligible("t.co."));
    assert!(eligible("a.b.example."));
    assert!(eligible("my-site.example."));
    assert!(!eligible("x-.example."));
    assert!(!eligible("_dmarc.example."));
}

#[tokio::test]
async fn blocked_domain_returns_without_upstream() {
    struct BlockPolicy;

    impl PolicyEngine for BlockPolicy {
        fn evaluate_domain_with_source(&self, domain: &str) -> Option<DomainDecision> {
            (domain == "blocked.example").then_some(DomainDecision {
                verdict: Verdict::Block,
                source: Some(DomainBlockSource::DnsRule),
            })
        }
    }

    let engine = QueryEngine::new(
        BlockPolicy,
        DnsConfig {
            block_mode: BlockResponseMode::Sinkhole,
            upstreams: vec!["127.0.0.1:1".to_owned()],
            ..DnsConfig::default()
        },
    );

    let mut query = Message::new(0, MessageType::Query, OpCode::Query);
    query.add_query(Query::query(
        Name::from_ascii("blocked.example.").expect("name"),
        RecordType::A,
    ));

    let bytes = respond_locally(&engine, &query).expect("blocked sync response");
    assert_ne!(bytes, [] as [u8; 0]);
}

#[test]
fn repeated_blocked_queries_resolve_attribution_once_per_throttle_window() {
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct AttributedPolicy(Arc<AtomicUsize>);

    impl PolicyEngine for AttributedPolicy {
        fn evaluate_domain_with_source(&self, _: &str) -> Option<DomainDecision> {
            Some(DomainDecision {
                verdict: Verdict::Block,
                source: Some(DomainBlockSource::Blocklist),
            })
        }

        fn matching_blocklists(&self, _: &str) -> Vec<String> {
            self.0.fetch_add(1, Ordering::Relaxed);
            vec!["catalog-one".to_owned()]
        }

        fn matching_normalized_blocklists(&self, _: &str) -> Vec<String> {
            self.0.fetch_add(1, Ordering::Relaxed);
            vec!["catalog-one".to_owned()]
        }
    }

    let resolutions = Arc::new(AtomicUsize::new(0));
    let engine = QueryEngine::new(
        AttributedPolicy(Arc::clone(&resolutions)),
        DnsConfig {
            block_mode: BlockResponseMode::Sinkhole,
            upstreams: vec!["127.0.0.1:1".to_owned()],
            ..DnsConfig::default()
        },
    );
    let mut query = Message::new(0, MessageType::Query, OpCode::Query);
    query.add_query(Query::query(
        Name::from_ascii("blocked.example.").expect("name"),
        RecordType::A,
    ));

    assert!(respond_locally(&engine, &query).is_some());
    assert!(respond_locally(&engine, &query).is_some());
    assert_eq!(resolutions.load(Ordering::Relaxed), 1);
}

#[tokio::test]
async fn punycode_blocklist_entry_blocks_punycode_query() {
    let mut policy = antiwire_policy::RuleEngine::new();
    let mut builder = antiwire_policy::BlocklistBuilder::new(1);
    builder.add_domain("xn--e1afmkfd.xn--p1ai");
    policy.publish_blocklist(builder.prepare().expect("prepare blocklist"));

    let engine = QueryEngine::new(
        policy,
        DnsConfig {
            block_mode: BlockResponseMode::Sinkhole,
            upstreams: vec!["127.0.0.1:1".to_owned()],
            ..DnsConfig::default()
        },
    );

    let mut query = Message::new(0, MessageType::Query, OpCode::Query);
    query.add_query(Query::query(
        Name::from_ascii("xn--e1afmkfd.xn--p1ai.").expect("punycode name"),
        RecordType::A,
    ));

    assert!(
        respond_locally(&engine, &query).is_some(),
        "the blocklist match should return without consulting upstream"
    );
}

#[tokio::test]
async fn miss_path_evaluates_policy_exactly_once() {
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct CountingPolicy(Arc<AtomicUsize>);

    impl PolicyEngine for CountingPolicy {
        fn evaluate_domain_with_source(&self, _: &str) -> Option<DomainDecision> {
            self.0.fetch_add(1, Ordering::Relaxed);
            None
        }
    }

    let evaluations = Arc::new(AtomicUsize::new(0));
    let engine = QueryEngine::new(
        CountingPolicy(Arc::clone(&evaluations)),
        DnsConfig {
            upstreams: vec!["127.0.0.1:1".to_owned()],
            ..DnsConfig::default()
        },
    );

    let mut query = Message::new(0, MessageType::Query, OpCode::Query);
    query.add_query(Query::query(
        Name::from_ascii("allowed.example.").expect("name"),
        RecordType::A,
    ));

    let _ = respond(&engine, &query, Instant::now()).await;
    assert_eq!(evaluations.load(Ordering::Relaxed), 1);
}

#[test]
fn rejects_multi_question_and_non_query_messages_and_ignores_responses() {
    struct AllowAll;

    impl PolicyEngine for AllowAll {
        fn evaluate_domain_with_source(&self, _: &str) -> Option<DomainDecision> {
            None
        }
    }

    let engine = QueryEngine::new(
        AllowAll,
        DnsConfig {
            upstreams: vec!["127.0.0.1:1".to_owned()],
            ..DnsConfig::default()
        },
    );

    let question = |name: &str| Query::query(Name::from_ascii(name).expect("name"), RecordType::A);

    let mut multi = Message::new(0, MessageType::Query, OpCode::Query);
    multi.add_query(question("allowed.example."));
    multi.add_query(question("smuggled.example."));
    let bytes = respond_locally(&engine, &multi).expect("rejected");
    let decoded = Message::from_vec(&bytes).expect("decode");
    assert_eq!(decoded.metadata.response_code, ResponseCode::FormErr);

    let mut response = Message::new(0, MessageType::Response, OpCode::Query);
    response.add_query(question("allowed.example."));
    assert!(
        respond_locally(&engine, &response).is_none(),
        "a response owes no reply"
    );

    let mut status = Message::new(0, MessageType::Query, OpCode::Status);
    status.add_query(question("allowed.example."));
    let bytes = respond_locally(&engine, &status).expect("rejected");
    let decoded = Message::from_vec(&bytes).expect("decode");
    assert_eq!(decoded.metadata.response_code, ResponseCode::NotImp);
}

#[test]
fn cache_key_separates_edns_dnssec_and_checking_disabled_variants() {
    let plain = CacheKey::from_query("example.example", RecordType::A, 1);
    let variants = [
        QueryFlags {
            recursion_desired: true,
            ..QueryFlags::default()
        },
        QueryFlags {
            edns: true,
            ..QueryFlags::default()
        },
        QueryFlags {
            edns: true,
            dnssec_ok: true,
            ..QueryFlags::default()
        },
        QueryFlags {
            checking_disabled: true,
            ..QueryFlags::default()
        },
    ];
    for flags in variants {
        assert_ne!(plain, plain.clone().with_flags(flags), "{flags:?}");
    }
    assert_eq!(plain, plain.clone().with_flags(QueryFlags::default()));
}

#[test]
fn parsed_flags_follow_the_client_query() {
    let mut request = Message::new(0, MessageType::Query, OpCode::Query);
    request.metadata.checking_disabled = true;
    let mut edns = Edns::new();
    edns.set_dnssec_ok(true);
    request.set_edns(edns);
    let mut question = Query::query(
        Name::from_ascii("Example.example.").expect("name"),
        RecordType::A,
    );
    question.set_query_class(DNSClass::CH);
    request.add_query(question);

    let prepared = parse_query(&request).expect("parse");
    let key = prepared.cache_key;
    assert_eq!(key.domain, "example.example");
    assert_eq!(
        key.flags,
        QueryFlags {
            recursion_desired: false,
            edns: true,
            dnssec_ok: true,
            checking_disabled: true,
        }
    );

    // A reconstructed prefetch query must carry the same terms.
    let refreshed = build_query_from_key(&key).expect("prefetch query");
    assert_eq!(QueryFlags::from_request(&refreshed), key.flags);
    assert_eq!(refreshed.queries[0].query_class(), DNSClass::CH);
}

#[test]
fn edns_options_and_nonstandard_fields_bypass_the_cache() {
    let request_with = |edns: Edns| {
        let mut request = Message::new(0, MessageType::Query, OpCode::Query);
        request.set_edns(edns);
        request.add_query(Query::query(
            Name::from_ascii("example.example.").expect("name"),
            RecordType::A,
        ));
        parse_query(&request).expect("parse").cache_eligible
    };

    let standard = Edns::new();
    assert!(request_with(standard));

    for code in [8, 11, 12] {
        let mut harmless = Edns::new();
        harmless
            .options_mut()
            .insert(EdnsOption::Unknown(code, Vec::new()));
        assert!(request_with(harmless));
    }
    // A cookie and an unrecognised option are never forwarded, so they
    // cannot change the upstream answer either.
    let mut cookie = Edns::new();
    cookie
        .options_mut()
        .insert(EdnsOption::Unknown(10, vec![0; 8]));
    assert!(request_with(cookie));

    let mut unknown = Edns::new();
    unknown
        .options_mut()
        .insert(EdnsOption::Unknown(65_001, vec![1]));
    assert!(request_with(unknown));

    // NSID is forwarded and changes the answer's OPT.
    let mut nsid = Edns::new();
    nsid.options_mut()
        .insert(EdnsOption::Unknown(3, Vec::new()));
    assert!(!request_with(nsid));

    let mut with_version = Edns::new();
    with_version.set_version(1);
    assert!(!request_with(with_version));

    let mut with_z_flag = Edns::new();
    with_z_flag.flags_mut().z = 1;
    assert!(!request_with(with_z_flag));
}

#[test]
fn cache_key_domain_is_built_inline_from_both_request_views() {
    let mut request = Message::new(0, MessageType::Query, OpCode::Query);
    request.add_query(Query::query(
        Name::from_ascii("Long-Ish.SubDomain.ExAmPlE.example.").expect("name"),
        RecordType::A,
    ));
    let from_message = parse_query(&request).expect("parse").cache_key;
    assert!(!from_message.domain.spilled(), "no heap for the key");
    assert_eq!(from_message.domain, "long-ish.subdomain.example.example");

    let parsed = hickory_server::server::Request::from_bytes(
        crate::messages::encode_message(&request).expect("encode"),
        "127.0.0.1:53000".parse().expect("client address"),
        hickory_server::net::xfer::Protocol::Udp,
    )
    .expect("hickory parses request");
    let from_request = parse_query(&*parsed).expect("parse").cache_key;
    assert!(!from_request.domain.spilled(), "no heap for the key");
    assert_eq!(from_request, from_message, "both views produce one key");
}

struct AllowAll;

impl PolicyEngine for AllowAll {
    fn evaluate_domain_with_source(&self, _: &str) -> Option<DomainDecision> {
        None
    }
}

struct SpyRequest {
    metadata: Metadata,
    query: Query,
    to_message_calls: Cell<usize>,
    first_query_calls: Cell<usize>,
}

impl RequestView for SpyRequest {
    fn metadata(&self) -> &Metadata {
        &self.metadata
    }

    fn query_count(&self) -> usize {
        1
    }

    fn question(&self) -> Option<QuestionParts> {
        Some(QuestionParts {
            normalized: domain_key::from_name(self.query.name(), true),
            qtype: self.query.query_type(),
            qclass: u16::from(self.query.query_class()),
        })
    }

    fn edns(&self) -> Option<&Edns> {
        None
    }

    fn to_message(&self) -> Message {
        self.to_message_calls.set(self.to_message_calls.get() + 1);
        panic!("ordinary lookups must not clone the full message before cache");
    }

    fn first_query(&self) -> Option<Query> {
        self.first_query_calls.set(self.first_query_calls.get() + 1);
        Some(self.query.clone())
    }
}

fn spy_engine() -> QueryEngine<AllowAll> {
    QueryEngine::new(
        AllowAll,
        DnsConfig {
            upstreams: vec!["127.0.0.1:1".to_owned()],
            ..DnsConfig::default()
        },
    )
}

fn spy_request(name: &str) -> SpyRequest {
    SpyRequest {
        metadata: Metadata::new(1, MessageType::Query, OpCode::Query),
        query: Query::query(Name::from_ascii(name).expect("name"), RecordType::A),
        to_message_calls: Cell::new(0),
        first_query_calls: Cell::new(0),
    }
}

/// Hints as `(pid, query, ttl_ms)`, and separately when each was answered.
#[derive(Default)]
struct RecordingHints(Mutex<Vec<(u32, String, u64)>>, Mutex<Vec<u64>>);

impl crate::DnsHintSink for RecordingHints {
    fn record_hint(
        &self,
        pid: u32,
        query: &str,
        _answers: &[std::net::IpAddr],
        ttl_ms: u64,
        answered_at_ms: u64,
    ) {
        self.0.lock().push((pid, query.to_owned(), ttl_ms));
        self.1.lock().push(answered_at_ms);
    }

    fn record_resolution(&self, _query: &str, _answers: &[std::net::IpAddr]) {}
}

fn hint_context() -> DnsQueryContext {
    DnsQueryContext {
        client_addr: std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
        client_port: 0,
        protocol: hickory_server::net::xfer::Protocol::Udp,
        received_at: Instant::now(),
    }
}

fn hint_answer(address: std::net::Ipv4Addr, ttl: u32) -> Message {
    use hickory_proto::rr::{rdata, RData};

    let name = Name::from_ascii("hint.example.").expect("name");
    let mut message = Message::new(1, MessageType::Response, OpCode::Query);
    message.add_query(Query::query(name.clone(), RecordType::A));
    message.add_answer(Record::from_rdata(name, ttl, RData::A(rdata::A(address))));
    message
}

#[test]
fn cached_hint_uses_the_ttl_sent_to_the_client() {
    let engine = spy_engine();
    let hints = Arc::new(RecordingHints::default());
    engine.set_hint_sink(hints.clone());
    let message = hint_answer(std::net::Ipv4Addr::new(192, 0, 2, 1), 60);
    let mut answer = ResponseCache::entry_from_message(&message, false).expect("entry");
    answer.cached_at = Instant::now().checked_sub(Duration::from_secs(59)).unwrap();
    answer.fresh_until = Instant::now() + Duration::from_secs(1);

    let unix_ms = || {
        u64::try_from(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("after the epoch")
                .as_millis(),
        )
        .expect("fits")
    };
    let before = unix_ms();
    engine.note_client_hint(Some(hint_context()), "hint.example", &answer);
    let after = unix_ms();

    assert_eq!(&*hints.0.lock(), &[(0, "hint.example".to_owned(), 1_000)]);
    let answered_at = hints.1.lock()[0];
    assert!(
        (before..=after).contains(&answered_at),
        "the hint is stamped when the answer was served: {before} <= {answered_at} <= {after}"
    );
}

#[test]
fn cached_provider_block_does_not_create_a_hint() {
    let engine = spy_engine();
    engine.set_upstream_endpoints_for_test(vec![
        "https://security.cloudflare-dns.com/dns-query".to_owned()
    ]);
    let hints = Arc::new(RecordingHints::default());
    engine.set_hint_sink(hints.clone());
    let message = hint_answer(std::net::Ipv4Addr::UNSPECIFIED, 60);
    let answer = ResponseCache::entry_from_message(&message, false).expect("entry");

    engine.note_client_hint(Some(hint_context()), "hint.example", &answer);

    assert!(hints.0.lock().is_empty());
}

#[tokio::test]
async fn async_miss_credits_the_client_when_another_request_filled_the_cache() {
    let engine = spy_engine();
    let hints = Arc::new(RecordingHints::default());
    engine.set_hint_sink(hints.clone());
    let message = hint_answer(std::net::Ipv4Addr::new(192, 0, 2, 1), 60);
    let mut request = Message::new(1, MessageType::Query, OpCode::Query);
    request.add_query(message.queries[0].clone());
    let prepared = parse_query(&request).expect("prepared");
    engine.response_cache.insert(
        prepared.cache_key.clone(),
        ResponseCache::entry_from_message(&message, false).expect("entry"),
    );

    let _ = engine
        .resolve_miss_message(&request, Some(hint_context()), prepared, Instant::now())
        .await;

    assert_eq!(hints.0.lock().len(), 1);
}

#[test]
fn policy_block_clones_only_the_question() {
    struct BlockAll;

    impl PolicyEngine for BlockAll {
        fn evaluate_domain_with_source(&self, _: &str) -> Option<DomainDecision> {
            Some(DomainDecision {
                verdict: Verdict::Block,
                source: Some(DomainBlockSource::DnsRule),
            })
        }
    }

    let engine = QueryEngine::new(
        BlockAll,
        DnsConfig {
            upstreams: vec!["127.0.0.1:1".to_owned()],
            ..DnsConfig::default()
        },
    );
    let request = spy_request("blocked.example.");
    match engine.process_core(&request, None) {
        CoreSyncOutcome::Response(message, _) => {
            assert_eq!(message.metadata.id, 1);
            assert_eq!(message.queries, vec![request.query.clone()]);
            assert_eq!(message.metadata.response_code, ResponseCode::NoError);
            assert_eq!(message.answers.len(), 1, "sinkhole answer");
            assert!(message.edns.is_some(), "EDE option is attached");
        }
        CoreSyncOutcome::Cached(_, _) | CoreSyncOutcome::Miss(_) | CoreSyncOutcome::Dropped => {
            panic!("expected block response")
        }
    }
    assert_eq!(request.to_message_calls.get(), 0);
    assert_eq!(request.first_query_calls.get(), 1);
}

#[test]
fn cache_miss_does_not_clone_the_request_message() {
    let engine = spy_engine();
    let request = spy_request("example.example.");
    assert!(matches!(
        engine.process_core(&request, None),
        CoreSyncOutcome::Miss(_)
    ));
    assert_eq!(request.to_message_calls.get(), 0);
    assert_eq!(request.first_query_calls.get(), 0);
}

#[test]
fn special_use_clones_only_the_question() {
    let engine = spy_engine();
    let request = spy_request("localhost.");
    match engine.process_core(&request, None) {
        CoreSyncOutcome::Response(message, _) => {
            assert_eq!(message.metadata.response_code, ResponseCode::NoError);
            assert_eq!(message.answers.len(), 1);
        }
        CoreSyncOutcome::Cached(_, _) | CoreSyncOutcome::Miss(_) | CoreSyncOutcome::Dropped => {
            panic!("expected special-use response")
        }
    }
    assert_eq!(request.to_message_calls.get(), 0);
    assert_eq!(request.first_query_calls.get(), 1);
}

#[tokio::test]
async fn expired_query_deadline_records_a_timeout() {
    let engine = spy_engine();
    let mut query = Message::new(1, MessageType::Query, OpCode::Query);
    query.add_query(Query::query(
        Name::from_ascii("expired-deadline.example.").expect("name"),
        RecordType::A,
    ));
    let received_at = Instant::now()
        .checked_sub(DNS_QUERY_DEADLINE)
        .expect("instant supports subtraction");

    let started = Instant::now();
    let _ = respond(&engine, &query, received_at).await;
    assert!(
        started.elapsed() < Duration::from_millis(100),
        "an already-expired deadline must not enter upstream I/O"
    );
}

mod ai_gate {
    use super::*;
    use crate::ai::classifier::test_helpers::{assessment_for, MockClassifier};
    use crate::ai::decision::{AiCategorySetting, AiDecisionMode, AiEvaluation, CategoryScores};
    use crate::ai::{AiCoordinator, AiPolicySnapshot};

    fn proactive_block_policy() -> AiPolicySnapshot {
        let mk = |id: &'static str, order: usize, block: bool| AiCategorySetting {
            id,
            enabled: true,
            threshold_percent: 80,
            block,
            order,
        };
        AiPolicySnapshot {
            enabled: true,
            mode: AiDecisionMode::Proactive,
            categories: [
                mk("advertising", 0, false),
                mk("tracking", 1, false),
                mk("telemetry", 2, false),
                mk("analytics", 3, false),
                mk("malicious", 4, true),
                mk("security_fraud", 5, false),
                mk("cryptomining", 6, false),
                mk("tunnel", 7, false),
            ],
            generation: 1,
        }
    }

    use crate::test_support::leaked_store as test_store;

    fn query_for(name: &str) -> Message {
        crate::test_support::a_query(7, name)
    }

    #[tokio::test]
    async fn retroactive_learning_excludes_failed_dns_rcodes() {
        let engine = spy_engine();
        let mut policy = proactive_block_policy();
        policy.mode = AiDecisionMode::Retroactive;
        let ai = AiCoordinator::new(test_store(), None, &policy, None);
        engine.set_ai(Some(ai));
        let domain = parse_query(&query_for("rcode.example."))
            .expect("query")
            .cache_key
            .domain;
        for (rcode, expected) in [
            (ResponseCode::NoError, true),
            (ResponseCode::NXDomain, true),
            (ResponseCode::ServFail, false),
            (ResponseCode::Refused, false),
            (ResponseCode::Unknown(999), false),
        ] {
            let mut response = Message::new(7, MessageType::Response, OpCode::Query);
            response.metadata.response_code = rcode;
            let answer = ResponseCache::entry_from_message(&response, true).expect("answer");
            assert_eq!(
                engine.post_work_for_answer(&domain, &answer).is_some(),
                expected,
                "{rcode:?} eligibility"
            );
        }
    }

    #[tokio::test]
    async fn proactive_sync_defers_to_async_when_ai_pending() {
        let engine = spy_engine();
        let store = test_store();
        let classifier = MockClassifier::failing("unused");
        let ai = AiCoordinator::new(store, Some(classifier), &proactive_block_policy(), None);
        engine.set_ai(Some(ai));
        let request = spy_request("deferred.example.");
        assert!(matches!(
            engine.process_core(&request, None),
            CoreSyncOutcome::Miss(_)
        ));
    }

    #[tokio::test]
    async fn unknown_proactive_malicious_blocks_before_upstream() {
        let store = test_store();
        let assessment = assessment_for("evil.example", 0.97);
        let classifier = MockClassifier::with_assessment("evil.example", assessment);
        let ai = AiCoordinator::new(
            Arc::clone(&store),
            Some(classifier.clone()),
            &proactive_block_policy(),
            None,
        );
        let recorded = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
        let sink = Arc::clone(&recorded);
        let engine = QueryEngine::try_new(
            AllowAll,
            &DnsConfig {
                upstreams: vec!["127.0.0.1:1".to_owned()],
                ..DnsConfig::default()
            },
            EngineServices {
                block_sink: Some(Arc::new(RecordingSink { names: sink })),
                ..EngineServices::default()
            },
        )
        .expect("engine");
        engine.set_ai(Some(Arc::clone(&ai)));
        let query = query_for("evil.example.");
        let started = Instant::now();
        let bytes = respond(&engine, &query, started).await;
        let response = Message::from_vec(&bytes).expect("decode");
        // Sinkhole block: NOERROR with one answer, no upstream needed.
        assert_eq!(response.answers.len(), 1);
        assert_eq!(classifier.call_count(), 1);
        assert!(store
            .get_domain_decision("EVIL.EXAMPLE.")
            .expect("read")
            .is_some());
        let names = wait_for_recorded(&recorded);
        assert_eq!(names, vec![antiwire_policy::AI_BLOCK_LABEL.to_owned()]);
        ai.shutdown().await;
    }

    struct RecordingSink {
        names: Arc<std::sync::Mutex<Vec<String>>>,
    }

    impl DnsBlockSink for RecordingSink {
        fn record_blocked_query(&self, _domain: &str, _pid: u32, blocklist_names: &[String]) {
            *self.names.lock().expect("names") = blocklist_names.to_vec();
        }
    }

    fn wait_for_recorded(names: &std::sync::Mutex<Vec<String>>) -> Vec<String> {
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            let recorded = names.lock().expect("names").clone();
            if !recorded.is_empty() || Instant::now() >= deadline {
                return recorded;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    #[tokio::test]
    async fn saved_decision_reuses_without_new_ai_call_after_restart() {
        let store = test_store();
        let assessment = assessment_for("saved.example", 0.97);
        let classifier = MockClassifier::with_assessment("saved.example", assessment);
        let first = AiCoordinator::new(
            Arc::clone(&store),
            Some(classifier.clone()),
            &proactive_block_policy(),
            None,
        );
        let engine = QueryEngine::new(
            AllowAll,
            DnsConfig {
                upstreams: vec!["127.0.0.1:1".to_owned()],
                ..DnsConfig::default()
            },
        );
        engine.set_ai(Some(Arc::clone(&first)));
        let query = query_for("saved.example.");
        let _ = respond(&engine, &query, Instant::now()).await;
        assert_eq!(classifier.call_count(), 1);
        first.shutdown().await;

        // Restart: new coordinator, failing classifier, same store.
        let failing = MockClassifier::failing("must not classify saved domains");
        let second = AiCoordinator::new(
            Arc::clone(&store),
            Some(failing.clone()),
            &proactive_block_policy(),
            None,
        );
        engine.set_ai(Some(Arc::clone(&second)));
        let bytes = respond(&engine, &query, Instant::now()).await;
        let response = Message::from_vec(&bytes).expect("decode");
        assert_eq!(response.answers.len(), 1, "saved block still enforced");
        assert_eq!(failing.call_count(), 0);
        second.shutdown().await;
    }

    struct Hang;
    #[async_trait::async_trait]
    impl crate::ai::Classifier for Hang {
        async fn classify(
            &self,
            _: &str,
        ) -> std::result::Result<
            antiwire_ai::DomainAssessment,
            crate::ai::classifier::ClassifierError,
        > {
            futures_util::future::pending::<()>().await;
            Err(crate::ai::classifier::ClassifierError::Transient(
                "hung".to_owned(),
            ))
        }
    }

    #[allow(clippy::items_after_statements)]
    #[tokio::test]
    async fn ai_timeout_fails_open_within_foreground_budget() {
        let store = test_store();
        // Hang behavior via a classifier that never resolves.
        let ai = AiCoordinator::new(store, Some(Arc::new(Hang)), &proactive_block_policy(), None);
        let started = Instant::now();
        let outcome = ai
            .proactive_gate("slow.example", Duration::from_secs(2))
            .await;
        assert!(matches!(
            outcome,
            crate::ai::coordinator::ProactiveOutcome::Proceed
        ));
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "foreground budget must expire well before the DNS deadline"
        );
        ai.shutdown().await;
    }

    #[tokio::test]
    async fn cached_answer_cannot_bypass_proactive_block() {
        let store = test_store();
        let assessment = assessment_for("cached.example", 0.97);
        let classifier = MockClassifier::with_assessment("cached.example", assessment);
        let ai = AiCoordinator::new(
            Arc::clone(&store),
            Some(classifier),
            &proactive_block_policy(),
            None,
        );
        let engine = QueryEngine::new(
            AllowAll,
            DnsConfig {
                upstreams: vec!["127.0.0.1:1".to_owned()],
                ..DnsConfig::default()
            },
        );
        engine.set_ai(Some(Arc::clone(&ai)));
        // Seed a cached upstream answer for the same name.
        let mut answer = Message::response(0, OpCode::Query);
        answer.add_query(Query::query(
            Name::from_ascii("cached.example.").expect("name"),
            RecordType::A,
        ));
        answer.add_answer(hickory_proto::rr::Record::from_rdata(
            Name::from_ascii("cached.example.").expect("name"),
            300,
            hickory_proto::rr::RData::A(hickory_proto::rr::rdata::A(std::net::Ipv4Addr::new(
                192, 0, 2, 9,
            ))),
        ));
        let entry = ResponseCache::entry_from_message(&answer, false).expect("entry");
        engine.response_cache().insert(
            CacheKey::from_query("cached.example", RecordType::A, 1)
                .with_flags(QueryFlags::from_request(&query_for("cached.example."))),
            entry,
        );
        let bytes = respond(&engine, &query_for("cached.example."), Instant::now()).await;
        let response = Message::from_vec(&bytes).expect("decode");
        // AI block wins over the cached answer (sinkhole, not 192.0.2.9).
        let blocked = response.answers.iter().all(|record| {
            !matches!(
                record.data,
                hickory_proto::rr::RData::A(hickory_proto::rr::rdata::A(ip))
                if ip == std::net::Ipv4Addr::new(192, 0, 2, 9)
            )
        });
        assert!(blocked, "proactive AI must precede cache access");
        ai.shutdown().await;
    }

    #[tokio::test]
    async fn expired_deadline_cannot_serve_a_cached_answer_for_a_saved_block() {
        let store = test_store();
        let mut policy = proactive_block_policy();
        policy.mode = AiDecisionMode::Retroactive;
        let scores = CategoryScores::new([0.0, 0.0, 0.0, 0.0, 0.95, 0.0, 0.0, 0.0]);
        store
            .upsert_domain_decision(&AiEvaluation::evaluate(&scores, &policy).to_stored(
                "late.example",
                "test",
                &scores,
                time::OffsetDateTime::now_utc(),
                None,
            ))
            .expect("saved decision");
        let ai = AiCoordinator::new(Arc::clone(&store), None, &policy, None);
        let engine = QueryEngine::new(
            AllowAll,
            DnsConfig {
                upstreams: vec!["127.0.0.1:1".to_owned()],
                ..DnsConfig::default()
            },
        );
        engine.set_ai(Some(Arc::clone(&ai)));
        // Retroactive mode caches the real answer before the verdict exists.
        let resolved = std::net::Ipv4Addr::new(192, 0, 2, 10);
        let mut answer = Message::response(0, OpCode::Query);
        answer.add_query(Query::query(
            Name::from_ascii("late.example.").expect("name"),
            RecordType::A,
        ));
        answer.add_answer(hickory_proto::rr::Record::from_rdata(
            Name::from_ascii("late.example.").expect("name"),
            300,
            hickory_proto::rr::RData::A(hickory_proto::rr::rdata::A(resolved)),
        ));
        engine.response_cache().insert(
            CacheKey::from_query("late.example", RecordType::A, 1)
                .with_flags(QueryFlags::from_request(&query_for("late.example."))),
            ResponseCache::entry_from_message(&answer, false).expect("entry"),
        );
        let received_at = Instant::now()
            .checked_sub(DNS_QUERY_DEADLINE)
            .expect("instant supports subtraction");

        let bytes = respond(&engine, &query_for("late.example."), received_at).await;
        let response = Message::from_vec(&bytes).expect("decode");
        assert!(
            response.answers.iter().all(|record| !matches!(
                record.data,
                hickory_proto::rr::RData::A(hickory_proto::rr::rdata::A(ip)) if ip == resolved
            )),
            "an expired deadline must not bypass a saved AI block"
        );
        ai.shutdown().await;
    }

    /// Custom block mode holds one address, so it has no answer for the other
    /// family or for non-address types. Such a query must still be blocked,
    /// with NODATA as sinkhole gives, not resolved upstream.
    #[tokio::test]
    async fn custom_mode_ai_block_does_not_fall_through_to_upstream() {
        use crate::integration_tests::support::{stub_config_with_upstream, MockUpstream};
        let upstream = MockUpstream::start().await;
        let assessment = assessment_for("evil.example", 0.97);
        let classifier = MockClassifier::with_assessment("evil.example", assessment);
        let ai = AiCoordinator::new(
            test_store(),
            Some(classifier),
            &proactive_block_policy(),
            None,
        );
        let engine = QueryEngine::new(
            AllowAll,
            DnsConfig {
                block_mode: crate::BlockResponseMode::Custom,
                custom_block_ip: Some("10.0.0.9".parse().expect("ip")),
                ..stub_config_with_upstream(&upstream)
            },
        );
        engine.set_ai(Some(Arc::clone(&ai)));
        for qtype in [RecordType::AAAA, RecordType::HTTPS] {
            let mut query = query_for("evil.example.");
            query.queries[0].set_query_type(qtype);
            let bytes = respond(&engine, &query, Instant::now()).await;
            let response = Message::from_vec(&bytes).expect("decode");
            assert_eq!(
                response.metadata.response_code,
                ResponseCode::NoError,
                "{qtype}"
            );
            assert!(
                response.answers.is_empty(),
                "{qtype}: {:?}",
                response.answers
            );
        }
        assert_eq!(
            upstream.calls(),
            0,
            "a blocked name must not reach upstream"
        );
        ai.shutdown().await;
    }

    #[tokio::test]
    async fn retroactive_post_response_saves_without_delaying_answer() {
        use crate::ai::decision::AiDecisionMode as Mode;
        let mk = |id: &'static str, order: usize| AiCategorySetting {
            id,
            enabled: true,
            threshold_percent: 80,
            block: false,
            order,
        };
        let policy = AiPolicySnapshot {
            enabled: true,
            mode: Mode::Retroactive,
            categories: [
                mk("advertising", 0),
                mk("tracking", 1),
                mk("telemetry", 2),
                mk("analytics", 3),
                mk("malicious", 4),
                mk("security_fraud", 5),
                mk("cryptomining", 6),
                mk("tunnel", 7),
            ],
            generation: 1,
        };
        let store = test_store();
        let assessment = assessment_for("retro.example", 0.95);
        let classifier = MockClassifier::with_assessment("retro.example", assessment);
        let ai = AiCoordinator::new(Arc::clone(&store), Some(classifier), &policy, None);
        // Simulate handler ordering: response already sent, then submit.
        ai.submit_post_response(&crate::ai::PostResponseWork {
            domain: "retro.example".to_owned(),
            was_block: false,
            eligible: true,
        });
        let saved = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if let Ok(Some(row)) = store.get_domain_decision("retro.example") {
                    break row;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("retroactive save");
        assert_eq!(saved.domain, "retro.example");
        ai.shutdown().await;
    }

    struct PendingClassifier {
        started: Arc<tokio::sync::Notify>,
        release: Arc<tokio::sync::Notify>,
    }

    #[async_trait::async_trait]
    impl crate::ai::Classifier for PendingClassifier {
        async fn classify(
            &self,
            domain: &str,
        ) -> std::result::Result<
            antiwire_ai::DomainAssessment,
            crate::ai::classifier::ClassifierError,
        > {
            self.started.notify_one();
            self.release.notified().await;
            Ok(assessment_for(domain, 0.97))
        }
    }

    struct MutablePolicy {
        decision: Arc<parking_lot::RwLock<Option<DomainDecision>>>,
    }

    impl PolicyEngine for MutablePolicy {
        fn evaluate_domain_with_source(&self, _: &str) -> Option<DomainDecision> {
            *self.decision.read()
        }
    }

    #[tokio::test]
    async fn policy_allow_added_while_classifier_pending_overrides_ai_block() {
        let started = Arc::new(tokio::sync::Notify::new());
        let release = Arc::new(tokio::sync::Notify::new());
        let decision = Arc::new(parking_lot::RwLock::new(None));
        let ai = AiCoordinator::new(
            test_store(),
            Some(Arc::new(PendingClassifier {
                started: Arc::clone(&started),
                release: Arc::clone(&release),
            })),
            &proactive_block_policy(),
            None,
        );
        let engine = QueryEngine::new(
            MutablePolicy {
                decision: Arc::clone(&decision),
            },
            DnsConfig {
                upstreams: vec!["127.0.0.1:1".to_owned()],
                ..DnsConfig::default()
            },
        );
        engine.set_ai(Some(Arc::clone(&ai)));
        let query = query_for("pending-policy.example.");
        let response_future = respond(&engine, &query, Instant::now());
        tokio::pin!(response_future);

        tokio::select! {
            () = started.notified() => {}
            response = &mut response_future => panic!("query completed before classifier gate: {response:?}"),
        }
        *decision.write() = Some(DomainDecision {
            verdict: Verdict::Allow,
            source: None,
        });
        release.notify_one();

        let response = Message::from_vec(&response_future.await).expect("decode");
        assert_eq!(response.metadata.response_code, ResponseCode::ServFail);
        assert!(
            response.answers.is_empty(),
            "the newly added allow must suppress the AI sinkhole"
        );
        ai.shutdown().await;
    }

    /// A block that lands while a gate waits carries the post-response work
    /// the same block gets on the synchronous path: classification for a
    /// blocklist match, none for the user's own rule or the gate's own block.
    #[tokio::test]
    async fn a_block_added_during_a_gate_carries_its_usual_post_work() {
        let decision = Arc::new(parking_lot::RwLock::new(None));
        let ai = AiCoordinator::new(
            test_store(),
            Some(Arc::new(PendingClassifier {
                started: Arc::new(tokio::sync::Notify::new()),
                release: Arc::new(tokio::sync::Notify::new()),
            })),
            &proactive_block_policy(),
            None,
        );
        let engine = QueryEngine::new(
            MutablePolicy {
                decision: Arc::clone(&decision),
            },
            DnsConfig {
                upstreams: vec!["127.0.0.1:1".to_owned()],
                ..DnsConfig::default()
            },
        );
        engine.set_ai(Some(Arc::clone(&ai)));
        let request = query_for("gated.example.");
        let prepared = parse_query(&request).expect("prepared");
        let gate_block = || Some(crate::messages::build_servfail_response(&request));

        let post_work = |source| {
            *decision.write() = Some(DomainDecision {
                verdict: Verdict::Block,
                source: Some(source),
            });
            engine
                .recheck_policy_after_gate(&request, &prepared, None, gate_block)
                .expect("a policy block")
                .1
        };
        let blocklist = post_work(DomainBlockSource::Blocklist).expect("blocklist classification");
        assert!(blocklist.was_block);
        assert!(post_work(DomainBlockSource::DnsRule).is_none());

        *decision.write() = None;
        let (_, gate_post_work) = engine
            .recheck_policy_after_gate(&request, &prepared, None, gate_block)
            .expect("the gate's own block");
        assert!(gate_post_work.is_none());
        ai.shutdown().await;
    }

    #[tokio::test]
    async fn boot_gate_special_use_and_unsupported_names_skip_background_ai() {
        struct BootGatePolicy;
        impl PolicyEngine for BootGatePolicy {
            fn evaluate_domain_with_source(&self, domain: &str) -> Option<DomainDecision> {
                (domain == "boot-gated.example").then_some(DomainDecision {
                    verdict: Verdict::Block,
                    source: Some(DomainBlockSource::BlocklistPending),
                })
            }
        }

        let engine = QueryEngine::new(
            BootGatePolicy,
            DnsConfig {
                block_mode: BlockResponseMode::Sinkhole,
                upstreams: vec!["127.0.0.1:1".to_owned()],
                ..DnsConfig::default()
            },
        );
        let store = test_store();
        let classifier = MockClassifier::failing("background work must not be scheduled");
        let ai = AiCoordinator::new(
            store,
            Some(classifier.clone()),
            &proactive_block_policy(),
            None,
        );
        engine.set_ai(Some(ai.clone()));

        let boot = spy_request("boot-gated.example.");
        match engine.process_core(&boot, None) {
            CoreSyncOutcome::Response(_, post_ai) => assert!(post_ai.is_none()),
            CoreSyncOutcome::Cached(_, _) | CoreSyncOutcome::Miss(_) | CoreSyncOutcome::Dropped => {
                panic!("boot gate must be answered synchronously")
            }
        }

        let special = spy_request("localhost.");
        match engine.process_core(&special, None) {
            CoreSyncOutcome::Response(_, post_ai) => assert!(post_ai.is_none()),
            CoreSyncOutcome::Cached(_, _) | CoreSyncOutcome::Miss(_) | CoreSyncOutcome::Dropped => {
                panic!("special-use must be synthesized synchronously")
            }
        }

        assert!(!ai_domain_eligible(&domain_key::from_name(
            &Name::from_ascii("_dmarc.example.").expect("name"),
            true,
        )));
        let _ = respond(&engine, &query_for("_dmarc.example."), Instant::now()).await;
        assert_eq!(classifier.call_count(), 0);
        ai.shutdown().await;
    }
}

#[tokio::test]
async fn hung_miss_records_a_timeout_instead_of_success() {
    let blackhole = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("blackhole bind");
    let engine = QueryEngine::new(
        AllowAll,
        DnsConfig {
            upstreams: vec![blackhole.local_addr().expect("address").to_string()],
            ..DnsConfig::default()
        },
    );
    let mut query = Message::new(1, MessageType::Query, OpCode::Query);
    query.add_query(Query::query(
        Name::from_ascii("hung-miss.example.").expect("name"),
        RecordType::A,
    ));

    let started = Instant::now();
    let _ = respond(&engine, &query, started).await;
    assert!(
        started.elapsed() < DNS_QUERY_DEADLINE + Duration::from_millis(500),
        "the query deadline must fire instead of waiting on Hickory"
    );
}

mod new_domain_gate {
    use super::*;
    use crate::new_domain::testing::{days_ago, FixedSource};
    use crate::new_domain::{
        NewDomainGuard, RegistrationAnswer, RegistrationCache, NEW_DOMAIN_BLOCK_LABEL,
    };

    struct RecordingSink {
        names: Arc<std::sync::Mutex<Vec<String>>>,
    }

    impl DnsBlockSink for RecordingSink {
        fn record_blocked_query(&self, _domain: &str, _pid: u32, blocklist_names: &[String]) {
            *self.names.lock().expect("names") = blocklist_names.to_vec();
        }
    }

    fn engine_with<P: PolicyEngine + Send + Sync>(
        policy: P,
        dates: Arc<RegistrationCache>,
        sink: Option<Arc<dyn DnsBlockSink>>,
    ) -> QueryEngine<P> {
        QueryEngine::try_new(
            policy,
            &DnsConfig {
                upstreams: vec!["127.0.0.1:1".to_owned()],
                ..DnsConfig::default()
            },
            EngineServices {
                block_sink: sink,
                ..EngineServices::default()
            },
        )
        .expect("engine")
        .with_new_domain_guard(NewDomainGuard::new(30, dates))
    }

    fn query_for(name: &str) -> Message {
        crate::test_support::a_query(9, name)
    }

    fn is_sinkholed(bytes: &[u8]) -> bool {
        let response = Message::from_vec(bytes).expect("decode");
        response.answers.len() == 1
            && matches!(
                response.answers[0].data,
                hickory_proto::rr::RData::A(hickory_proto::rr::rdata::A(ip)) if ip.is_unspecified()
            )
    }

    #[tokio::test]
    async fn a_cached_young_domain_is_blocked_on_the_sync_path() {
        let dates = RegistrationCache::new(FixedSource::new([], Duration::ZERO));
        dates.insert_for_test("fresh.com", days_ago(2));
        let recorded = Arc::new(std::sync::Mutex::new(Vec::new()));
        let engine = engine_with(
            AllowAll,
            dates,
            Some(Arc::new(RecordingSink {
                names: Arc::clone(&recorded),
            })),
        );
        let bytes = respond_locally(&engine, &query_for("www.fresh.com.")).expect("local block");
        assert!(is_sinkholed(&bytes));

        let deadline = Instant::now() + Duration::from_secs(2);
        while recorded.lock().expect("names").is_empty() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(
            *recorded.lock().expect("names"),
            vec![NEW_DOMAIN_BLOCK_LABEL.to_owned()]
        );
    }

    #[tokio::test]
    async fn an_uncached_young_domain_waits_for_its_date_and_is_blocked() {
        let source = FixedSource::new([("brandnew.com", days_ago(1))], Duration::from_millis(50));
        let engine = engine_with(
            AllowAll,
            RegistrationCache::new(Arc::<FixedSource>::clone(&source)),
            None,
        );
        assert!(respond_locally(&engine, &query_for("brandnew.com.")).is_none());

        let bytes = respond(&engine, &query_for("brandnew.com."), Instant::now()).await;
        assert!(is_sinkholed(&bytes));
        assert_eq!(source.calls(), 1);
    }

    #[tokio::test]
    async fn an_old_domain_is_not_blocked() {
        let dates = RegistrationCache::new(FixedSource::new([], Duration::ZERO));
        dates.insert_for_test("old.com", days_ago(400));
        dates.insert_for_test("unknown.com", RegistrationAnswer::Unknown);
        let engine = engine_with(AllowAll, dates, None);
        for name in ["old.com.", "unknown.com."] {
            let local = respond_locally(&engine, &query_for(name));
            assert!(
                local.is_none_or(|bytes| !is_sinkholed(&bytes)),
                "{name} must go on to resolve"
            );
        }
    }

    #[tokio::test]
    async fn an_allow_rule_overrides_the_age_block() {
        struct AllowFresh;

        impl PolicyEngine for AllowFresh {
            fn evaluate_domain_with_source(&self, domain: &str) -> Option<DomainDecision> {
                (domain == "fresh.com").then_some(DomainDecision {
                    verdict: Verdict::Allow,
                    source: None,
                })
            }
        }

        let dates = RegistrationCache::new(FixedSource::new([], Duration::ZERO));
        dates.insert_for_test("fresh.com", days_ago(2));
        let engine = engine_with(AllowFresh, dates, None);
        let local = respond_locally(&engine, &query_for("fresh.com."));
        assert!(local.is_none_or(|bytes| !is_sinkholed(&bytes)));
    }
}
