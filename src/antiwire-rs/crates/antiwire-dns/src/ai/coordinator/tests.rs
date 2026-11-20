use super::*;
use crate::ai::classifier::test_helpers::{assessment_for, MockClassifier};
use crate::ai::decision::{AiCategorySetting, AiDecisionMode};
use std::sync::atomic::AtomicUsize;

struct ControlledClassifier {
    calls: AtomicUsize,
    entered: Semaphore,
    release: Semaphore,
}

impl ControlledClassifier {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            calls: AtomicUsize::new(0),
            entered: Semaphore::new(0),
            release: Semaphore::new(0),
        })
    }
}

#[async_trait::async_trait]
impl crate::ai::classifier::Classifier for ControlledClassifier {
    async fn classify(
        &self,
        domain: &str,
    ) -> Result<antiwire_ai::DomainAssessment, ClassifierError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.entered.add_permits(1);
        self.release
            .acquire()
            .await
            .expect("release permit")
            .forget();
        Ok(assessment_for(domain, 0.99))
    }
}

fn test_policy(mode: AiDecisionMode, block_malicious: bool) -> AiPolicySnapshot {
    let mk = |id: &'static str, order: usize, block: bool| AiCategorySetting {
        id,
        enabled: true,
        threshold_percent: 80,
        block,
        order,
    };
    AiPolicySnapshot {
        enabled: true,
        mode,
        categories: [
            mk("advertising", 0, false),
            mk("tracking", 1, false),
            mk("telemetry", 2, false),
            mk("analytics", 3, false),
            mk("malicious", 4, block_malicious),
            mk("security_fraud", 5, false),
            mk("cryptomining", 6, false),
            mk("tunnel", 7, false),
        ],
        generation: 1,
    }
}

use crate::test_support::leaked_store as test_store;

struct PanickingClassifier;

#[async_trait::async_trait]
impl crate::ai::classifier::Classifier for PanickingClassifier {
    async fn classify(
        &self,
        _domain: &str,
    ) -> Result<antiwire_ai::DomainAssessment, ClassifierError> {
        panic!("classifier bug");
    }
}

#[tokio::test]
async fn a_panicking_classification_releases_its_domain() {
    let policy = test_policy(AiDecisionMode::Proactive, true);
    let coordinator = AiCoordinator::new(
        test_store(),
        Some(Arc::new(PanickingClassifier)),
        &policy,
        None,
    );

    let result = coordinator
        .classify_shared("panic.example", Duration::from_secs(2))
        .await;

    assert!(
        matches!(result, Err(ClassifierError::Transient(_))),
        "{result:?}"
    );
    assert!(
        coordinator.inflight.is_empty(),
        "a later query must start a new classification, not join a dead one"
    );
    coordinator.shutdown().await;
}

#[tokio::test]
async fn concurrent_queries_share_one_classification() {
    let store = test_store();
    let assessment = assessment_for("shared.example", 0.95);
    let classifier = MockClassifier::with_assessment("shared.example", assessment);
    let policy = test_policy(AiDecisionMode::Proactive, true);
    let coordinator = AiCoordinator::new(store, Some(classifier.clone()), &policy, None);

    let (first, second) = tokio::join!(
        coordinator.classify_shared("shared.example", Duration::from_secs(5)),
        coordinator.classify_shared("shared.example", Duration::from_secs(5)),
    );
    assert!(first.is_ok());
    assert!(second.is_ok());
    assert_eq!(classifier.call_count(), 1);
    coordinator.shutdown().await;
}

#[tokio::test]
async fn cancelled_waiter_does_not_strand_the_domain() {
    let classifier = ControlledClassifier::new();
    let policy = test_policy(AiDecisionMode::Proactive, true);
    let coordinator = AiCoordinator::new(test_store(), Some(classifier.clone()), &policy, None);
    let first = tokio::spawn({
        let coordinator = Arc::clone(&coordinator);
        async move {
            coordinator
                .proactive_gate("cancel.example", Duration::from_secs(2))
                .await
        }
    });
    classifier
        .entered
        .acquire()
        .await
        .expect("entered")
        .forget();
    first.abort();
    let _ = first.await;
    classifier.release.add_permits(1);
    let next = coordinator
        .proactive_gate("cancel.example", Duration::from_secs(2))
        .await;
    assert!(matches!(next, ProactiveOutcome::Block(_)));
    assert_eq!(classifier.calls.load(Ordering::SeqCst), 1);
    coordinator.shutdown().await;
}

#[tokio::test]
async fn previous_provider_cannot_block_after_reconfiguration() {
    let old = ControlledClassifier::new();
    let policy = test_policy(AiDecisionMode::Proactive, true);
    let coordinator = AiCoordinator::new(test_store(), Some(old.clone()), &policy, None);
    let query = tokio::spawn({
        let coordinator = Arc::clone(&coordinator);
        async move {
            coordinator
                .proactive_gate("provider.example", Duration::from_secs(2))
                .await
        }
    });
    old.entered.acquire().await.expect("entered").forget();
    coordinator.update_config(&policy, None, None);
    old.release.add_permits(1);
    assert!(matches!(
        query.await.expect("query"),
        ProactiveOutcome::Proceed
    ));
    coordinator.shutdown().await;
}

#[test]
fn saved_decision_wait_respects_remaining_dns_budget() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .max_blocking_threads(1)
        .enable_all()
        .build()
        .expect("runtime");
    runtime.block_on(async {
        let policy = test_policy(AiDecisionMode::Proactive, true);
        let coordinator = AiCoordinator::new(test_store(), None, &policy, None);
        let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
        let blocker = tokio::task::spawn_blocking(move || {
            let _ = ready_tx.send(());
            std::thread::sleep(Duration::from_millis(750));
        });
        ready_rx.await.expect("blocking worker started");
        let outcome = tokio::time::timeout(
            Duration::from_millis(300),
            coordinator.proactive_gate(
                "db.example",
                antiwire_tuning::DNS_GATE_UPSTREAM_RESERVE + Duration::from_millis(100),
            ),
        )
        .await
        .expect("foreground budget must expire while the store is waiting");
        assert!(matches!(outcome, ProactiveOutcome::Proceed));
        blocker.await.expect("blocking worker");
        coordinator.shutdown().await;
    });
}

#[tokio::test]
async fn saved_decision_survives_and_suppresses_new_calls() {
    let store = test_store();
    let assessment = assessment_for("saved.example", 0.01);
    let classifier = MockClassifier::with_assessment("saved.example", assessment);
    let policy = test_policy(AiDecisionMode::Proactive, true);
    let coordinator =
        AiCoordinator::new(Arc::clone(&store), Some(classifier.clone()), &policy, None);

    coordinator
        .classify_shared("saved.example", Duration::from_secs(5))
        .await
        .expect("classify");
    let calls_after_first = classifier.call_count();
    assert!(store
        .get_domain_decision("saved.example")
        .expect("read")
        .is_some());

    // Second lookup hits the saved row; waiter path rechecks the DB.
    coordinator
        .classify_shared("saved.example", Duration::from_secs(5))
        .await
        .expect("reuse");
    assert_eq!(classifier.call_count(), calls_after_first);
    coordinator.shutdown().await;
}

#[test]
fn resident_decision_bypasses_blocking_worker_and_uses_current_policy() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .max_blocking_threads(1)
        .enable_all()
        .build()
        .expect("runtime");
    runtime.block_on(async {
        let store = test_store();
        let classifier = MockClassifier::with_assessment(
            "resident.example",
            assessment_for("resident.example", 0.99),
        );
        let policy = test_policy(AiDecisionMode::Proactive, true);
        let coordinator =
            AiCoordinator::new(Arc::clone(&store), Some(classifier.clone()), &policy, None);
        coordinator
            .classify_shared("resident.example", Duration::from_secs(5))
            .await
            .expect("seed saved decision");
        let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
        let blocker = tokio::task::spawn_blocking(move || {
            let _ = ready_tx.send(());
            std::thread::sleep(Duration::from_millis(500));
        });
        ready_rx.await.expect("blocking worker started");
        assert!(matches!(
            coordinator
                .proactive_gate("RESIDENT.example.", Duration::from_millis(100))
                .await,
            ProactiveOutcome::Block(_)
        ));
        let allow_policy = test_policy(AiDecisionMode::Proactive, false);
        coordinator.update_config(&allow_policy, None, None);
        assert!(matches!(
            coordinator
                .proactive_gate("resident.example", Duration::from_millis(100))
                .await,
            ProactiveOutcome::Proceed
        ));
        assert_eq!(classifier.call_count(), 1);
        blocker.await.expect("blocking worker");
        coordinator.shutdown().await;
    });
}

#[tokio::test]
async fn raising_the_malicious_threshold_unblocks_a_saved_domain() {
    let store = test_store();
    let mut policy = test_policy(AiDecisionMode::Proactive, true);
    let scores = CategoryScores::new([0.1, 0.1, 0.1, 0.1, 0.82, 0.1, 0.1, 0.1]);
    let now = time::OffsetDateTime::now_utc();
    store
        .upsert_domain_decision(&AiEvaluation::evaluate(&scores, &policy).to_stored(
            "edge.example",
            "test",
            &scores,
            now,
            None,
        ))
        .expect("save decision");
    let classifier = MockClassifier::failing("must reuse stored scores");
    let coordinator =
        AiCoordinator::new(Arc::clone(&store), Some(classifier.clone()), &policy, None);

    let blocked = coordinator
        .proactive_gate("edge.example", Duration::from_secs(2))
        .await;
    assert!(matches!(blocked, ProactiveOutcome::Block(_)));

    policy.categories[4].threshold_percent = 85;
    coordinator.update_config(&policy, Some(classifier.clone()), None);
    let allowed = coordinator
        .proactive_gate("edge.example", Duration::from_secs(2))
        .await;
    assert!(
        matches!(allowed, ProactiveOutcome::Proceed),
        "82% no longer meets an 85% block threshold"
    );

    policy.categories[4].threshold_percent = 80;
    coordinator.update_config(&policy, Some(classifier.clone()), None);
    let blocked_again = coordinator
        .proactive_gate("edge.example", Duration::from_secs(2))
        .await;
    assert!(matches!(blocked_again, ProactiveOutcome::Block(_)));
    assert_eq!(classifier.call_count(), 0);
    coordinator.shutdown().await;
}

#[tokio::test]
async fn retroactive_saved_decision_skips_background_job() {
    let store = test_store();
    let classifier = MockClassifier::failing("saved decision must skip AI");
    let policy = test_policy(AiDecisionMode::Retroactive, true);
    let coordinator =
        AiCoordinator::new(Arc::clone(&store), Some(classifier.clone()), &policy, None);
    let now = time::OffsetDateTime::now_utc();
    store
        .upsert_domain_decision(
            &AiEvaluation::evaluate(&CategoryScores::new([0.0; 8]), &policy).to_stored(
                "retro-saved.example",
                "test",
                &CategoryScores::new([0.0; 8]),
                now,
                None,
            ),
        )
        .expect("saved decision");
    coordinator.submit_post_response(&PostResponseWork {
        domain: "RETRO-SAVED.example.".to_owned(),
        was_block: false,
        eligible: true,
    });
    assert!(coordinator.inflight.is_empty());
    assert_eq!(classifier.call_count(), 0);
    coordinator.shutdown().await;
}

#[tokio::test]
async fn retroactive_blocks_the_next_query_from_a_saved_score() {
    let store = test_store();
    let classifier = MockClassifier::failing("retroactive must not classify in the gate");
    let policy = test_policy(AiDecisionMode::Retroactive, true);
    let coordinator =
        AiCoordinator::new(Arc::clone(&store), Some(classifier.clone()), &policy, None);
    let first = coordinator
        .proactive_gate("later.example", Duration::from_secs(2))
        .await;
    assert!(matches!(first, ProactiveOutcome::Proceed));
    assert_eq!(classifier.call_count(), 0);

    let scores = CategoryScores::new([0.0, 0.0, 0.0, 0.0, 0.95, 0.0, 0.0, 0.0]);
    let now = time::OffsetDateTime::now_utc();
    store
        .upsert_domain_decision(&AiEvaluation::evaluate(&scores, &policy).to_stored(
            "later.example",
            "test",
            &scores,
            now,
            None,
        ))
        .expect("saved decision");
    let second = coordinator
        .proactive_gate("later.example", Duration::from_secs(2))
        .await;
    assert!(matches!(second, ProactiveOutcome::Block(_)));
    assert_eq!(classifier.call_count(), 0);
    coordinator.shutdown().await;
}

#[tokio::test]
async fn retroactive_enforces_a_saved_block_missing_from_the_decision_cache() {
    let dir = tempfile::tempdir().expect("tempdir");
    let keystore = antiwire_secrets::UnixSecureFileKeyProvider::new(dir.path().join("key"));
    let path = dir.path().join("db.sqlite");
    let store = Arc::new(Store::open_with_keystore(&path, &keystore).expect("store"));
    // Another handle writes the row, as after a restart or a cache expiry: the
    // coordinator's own store has never cached it.
    let writer = Store::open_with_keystore(&path, &keystore).expect("writer");
    let policy = test_policy(AiDecisionMode::Retroactive, true);
    let scores = CategoryScores::new([0.0, 0.0, 0.0, 0.0, 0.95, 0.0, 0.0, 0.0]);
    writer
        .upsert_domain_decision(&AiEvaluation::evaluate(&scores, &policy).to_stored(
            "cold.example",
            "test",
            &scores,
            time::OffsetDateTime::now_utc(),
            None,
        ))
        .expect("saved decision");
    assert!(store.cached_domain_decision("cold.example").is_none());

    let classifier = MockClassifier::failing("retroactive must not classify in the gate");
    let coordinator = AiCoordinator::new(store, Some(classifier.clone()), &policy, None);
    let outcome = coordinator
        .proactive_gate("cold.example", Duration::from_secs(2))
        .await;
    assert!(matches!(outcome, ProactiveOutcome::Block(_)));
    assert_eq!(classifier.call_count(), 0);
    coordinator.shutdown().await;
}

#[tokio::test]
async fn unavailable_client_does_not_retry_until_reconfigured() {
    let store = test_store();
    let policy = test_policy(AiDecisionMode::Proactive, true);
    let coordinator = AiCoordinator::new(store, None, &policy, None);
    let result = coordinator
        .classify_shared("unavailable.example", Duration::from_secs(2))
        .await;
    assert!(matches!(result, Err(ClassifierError::Unavailable(_))));
    assert!(coordinator.retry_tasks.is_empty());
    assert!(coordinator.retries.is_empty());

    let classifier = MockClassifier::with_assessment(
        "unavailable.example",
        assessment_for("unavailable.example", 0.95),
    );
    coordinator.update_config(&policy, Some(classifier.clone()), None);
    assert!(matches!(
        coordinator
            .proactive_gate("unavailable.example", Duration::from_secs(2))
            .await,
        ProactiveOutcome::Block(_)
    ));
    assert_eq!(classifier.call_count(), 1);
    coordinator.shutdown().await;
}

#[tokio::test]
async fn bootstrap_domain_skips_ai() {
    let store = test_store();
    let classifier = MockClassifier::failing("must not call");
    let policy = test_policy(AiDecisionMode::Proactive, true);
    let coordinator = AiCoordinator::new(
        store,
        Some(classifier.clone()),
        &policy,
        Some("ai-provider.example".to_owned()),
    );
    let outcome = coordinator
        .proactive_gate("AI-Provider.Example.", Duration::from_secs(2))
        .await;
    assert!(matches!(outcome, ProactiveOutcome::Proceed));
    assert_eq!(classifier.call_count(), 0);
    coordinator.shutdown().await;
}

#[tokio::test]
async fn the_resident_gate_applies_a_saved_decision_from_memory() {
    use crate::ai::classifier::test_helpers::MockBehavior;

    let store = test_store();
    let classifier =
        MockClassifier::with_assessment("bad.example", assessment_for("bad.example", 0.99));
    classifier.set(
        "good.example",
        MockBehavior::Assess(assessment_for("good.example", 0.01)),
    );
    let coordinator = AiCoordinator::new(
        Arc::clone(&store),
        Some(classifier),
        &test_policy(AiDecisionMode::Proactive, true),
        None,
    );
    assert!(
        matches!(
            coordinator.resident_gate("bad.example"),
            ResidentOutcome::Deferred
        ),
        "nothing has read the store for the name yet"
    );

    for domain in ["bad.example", "good.example"] {
        coordinator
            .classify_shared(domain, Duration::from_secs(5))
            .await
            .expect("saved decision");
    }
    assert!(matches!(
        coordinator.resident_gate("BAD.example."),
        ResidentOutcome::Block(_)
    ));
    assert!(matches!(
        coordinator.resident_gate("good.example"),
        ResidentOutcome::Proceed { saved: true }
    ));

    // The policy in force decides, over the same saved scores.
    coordinator.update_config(&test_policy(AiDecisionMode::Proactive, false), None, None);
    assert!(matches!(
        coordinator.resident_gate("bad.example"),
        ResidentOutcome::Proceed { saved: true }
    ));
    coordinator.shutdown().await;
}

#[tokio::test]
async fn an_unsaved_name_proceeds_unless_a_classification_must_come_first() {
    let store = test_store();
    assert!(store
        .get_domain_decision("new.example")
        .expect("store read")
        .is_none());
    for (mode, can_classify, deferred) in [
        (AiDecisionMode::Retroactive, true, false),
        (AiDecisionMode::Retroactive, false, false),
        // Nothing can classify the name, so the gate would fail open.
        (AiDecisionMode::Proactive, false, false),
        (AiDecisionMode::Proactive, true, true),
    ] {
        let classifier: Option<SharedClassifier> =
            can_classify.then(|| MockClassifier::failing("unused") as SharedClassifier);
        let coordinator = AiCoordinator::new(
            Arc::clone(&store),
            classifier,
            &test_policy(mode, true),
            None,
        );
        let outcome = coordinator.resident_gate("new.example");
        assert_eq!(
            matches!(outcome, ResidentOutcome::Deferred),
            deferred,
            "{mode:?} can_classify={can_classify}: {outcome:?}"
        );
        if !deferred {
            assert!(matches!(outcome, ResidentOutcome::Proceed { saved: false }));
        }
    }
}

#[tokio::test]
async fn the_resident_gate_leaves_disabled_ai_and_the_providers_host_alone() {
    let store = test_store();
    let mut disabled = test_policy(AiDecisionMode::Proactive, true);
    disabled.enabled = false;
    let coordinator = AiCoordinator::new(Arc::clone(&store), None, &disabled, None);
    assert!(matches!(
        coordinator.resident_gate("never-read.example"),
        ResidentOutcome::Proceed { saved: false }
    ));

    let coordinator = AiCoordinator::new(
        store,
        Some(MockClassifier::failing("unused")),
        &test_policy(AiDecisionMode::Proactive, true),
        Some("AI-Provider.Example.".to_owned()),
    );
    assert!(matches!(
        coordinator.resident_gate("ai-provider.example"),
        ResidentOutcome::Proceed { saved: false }
    ));
    assert!(matches!(
        coordinator.resident_gate("other.example"),
        ResidentOutcome::Deferred
    ));
}

/// Without this, what memory holds expires once a minute and the next query
/// for the name has to leave the receive loop to read the store again.
#[tokio::test]
async fn a_decision_about_to_leave_memory_is_reread_in_the_background() {
    let ttl = antiwire_tuning::DNS_AI_DECISION_CACHE_TTL;
    let store = test_store();
    assert!(store
        .get_domain_decision("steady.example")
        .expect("store read")
        .is_none());
    let coordinator = AiCoordinator::new(
        Arc::clone(&store),
        None,
        &test_policy(AiDecisionMode::Retroactive, true),
        None,
    );
    assert!(matches!(
        coordinator.resident_gate("steady.example"),
        ResidentOutcome::Proceed { saved: false }
    ));
    assert!(
        coordinator.refreshing.is_empty(),
        "a fresh entry is not re-read"
    );

    store.age_resident_decision("steady.example", ttl.saturating_sub(Duration::from_secs(1)));
    assert!(store.resident_domain_decision("steady.example").refresh_due);
    assert!(
        matches!(
            coordinator.resident_gate("steady.example"),
            ResidentOutcome::Proceed { saved: false }
        ),
        "still decided from memory while the re-read runs"
    );
    tokio::time::timeout(Duration::from_secs(5), async {
        while store.resident_domain_decision("steady.example").refresh_due
            || !coordinator.refreshing.is_empty()
        {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("the entry starts a new residency");
    coordinator.shutdown().await;
}

/// An answer sent while no classifier is available used to start a job that
/// read the store and failed, once for every such answer.
#[tokio::test]
async fn post_response_work_starts_nothing_without_a_classifier() {
    let coordinator = AiCoordinator::new(
        test_store(),
        None,
        &test_policy(AiDecisionMode::Retroactive, true),
        None,
    );
    coordinator.submit_post_response(&PostResponseWork {
        domain: "answered.example".to_owned(),
        was_block: false,
        eligible: true,
    });
    assert!(coordinator.inflight.is_empty());

    coordinator.update_config(
        &test_policy(AiDecisionMode::Retroactive, true),
        Some(MockClassifier::failing("unused")),
        None,
    );
    coordinator.submit_post_response(&PostResponseWork {
        domain: "answered.example".to_owned(),
        was_block: false,
        eligible: true,
    });
    assert!(
        coordinator.inflight.contains_key("answered.example"),
        "a classifier that came back is used"
    );
    coordinator.shutdown().await;
}

/// Lets paused time run until `condition` holds, for at most `limit`.
async fn settle(limit: Duration, condition: impl Fn() -> bool) -> bool {
    let started = tokio::time::Instant::now();
    while !condition() {
        if started.elapsed() >= limit {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    true
}

/// The regression this guards: a retry that found the AI queue full asked for
/// a second retry slot while it still held its own. With every other slot
/// taken it got none, so the domain's retries ended there, and its attempt
/// count stayed behind for as long as the daemon ran: one entry for each
/// domain that went this way, and nothing left to remove it.
#[tokio::test(start_paused = true)]
async fn a_retry_that_cannot_start_goes_on_in_its_own_slot() {
    let policy = test_policy(AiDecisionMode::Proactive, true);
    let coordinator = AiCoordinator::new(
        test_store(),
        Some(MockClassifier::failing("unused")),
        &policy,
        None,
    );
    let queue_size = antiwire_tuning::DNS_AI_MAX_QUEUED;
    let _queue_full = Arc::clone(&coordinator.queued)
        .try_acquire_many_owned(u32::try_from(queue_size).expect("queue size"))
        .expect("the whole AI queue");
    let _other_retries = Arc::clone(&coordinator.retry_slots)
        .try_acquire_many_owned(u32::try_from(queue_size - 1).expect("queue size"))
        .expect("every retry slot but one");

    let domains = 50;
    for id in 0..domains {
        let domain = format!("overloaded{id}.example");
        coordinator.schedule_retry(&domain);
        assert!(coordinator.retry_tasks.contains_key(&domain));
        let last_attempt = antiwire_tuning::DNS_AI_RETRY_MAX_ATTEMPTS;
        let retried = settle(Duration::from_secs(120), || {
            coordinator
                .retries
                .get(&domain)
                .is_some_and(|attempts| *attempts == last_attempt)
        })
        .await;
        assert!(retried, "{domain} is retried {last_attempt} times");
        let ended = settle(Duration::from_secs(120), || {
            !coordinator.retry_tasks.contains_key(&domain)
                && coordinator.retry_slots.available_permits() == 1
        })
        .await;
        assert!(ended, "the retries of {domain} end");
    }
    assert!(
        coordinator.retries.is_empty(),
        "{} of {domains} domains keep an attempt count with no retry left",
        coordinator.retries.len()
    );
    coordinator.shutdown().await;
}

/// The regression this guards: a failed classification that a retry had
/// started, shed because no retry slot was free, kept its attempt count.
#[tokio::test]
async fn a_retry_shed_for_want_of_a_slot_forgets_its_count() {
    let policy = test_policy(AiDecisionMode::Proactive, true);
    let coordinator = AiCoordinator::new(
        test_store(),
        Some(MockClassifier::failing("unused")),
        &policy,
        None,
    );
    let _every_retry = Arc::clone(&coordinator.retry_slots)
        .try_acquire_many_owned(
            u32::try_from(antiwire_tuning::DNS_AI_MAX_QUEUED).expect("queue size"),
        )
        .expect("every retry slot");

    let domains = 50;
    for id in 0..domains {
        let domain = format!("shed{id}.example");
        // A classification its first retry started has just failed.
        coordinator.retries.insert(domain.clone(), 1);
        coordinator.schedule_retry(&domain);
    }
    assert!(coordinator.retry_tasks.is_empty());
    assert!(
        coordinator.retries.is_empty(),
        "{} of {domains} shed domains keep an attempt count",
        coordinator.retries.len()
    );
    coordinator.shutdown().await;
}
