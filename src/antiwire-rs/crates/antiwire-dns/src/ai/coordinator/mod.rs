//! Shared AI decision coordinator: dedup, budgets, retries, persistence.
//!
//! One in-flight classification per normalized domain is shared across both
//! modes and query types. Foreground proactive work has priority over
//! background classification; everything fails open within bounded budgets.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use std::time::Instant;

use antiwire_store::{ResidentDecision, Store};
use dashmap::DashMap;
use parking_lot::RwLock;
use tokio::sync::Semaphore;
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;
use tracing::debug;

use super::classifier::{ClassifierError, SharedClassifier};
use super::decision::{canonical_ai_key, AiEvaluation, AiPolicySnapshot, CategoryScores};

mod inflight;
mod jobs;
mod retry;

use inflight::Inflight;

/// Post-response work carried alongside the prepared DNS response.
///
/// The handler submits it to the coordinator only after the response-send
/// operation succeeds.
#[derive(Debug, Clone)]
pub struct PostResponseWork {
    /// Canonical domain key (lowercase, no trailing dot).
    pub domain: String,
    /// True when the response was an immediate policy block.
    pub was_block: bool,
    /// True when the answer came from a provider/cache path eligible for
    /// retroactive learning (provider answers, cached answers, NXDOMAIN).
    /// False for malformed, special-use, transport failures, SERVFAIL.
    pub eligible: bool,
}

/// Outcome of the proactive foreground gate.
#[derive(Debug, Clone)]
pub enum ProactiveOutcome {
    /// Continue normal DNS resolution.
    Proceed,
    /// Block now with the evaluated decision.
    Block(AiEvaluation),
}

/// What the gate decides for a query from memory alone, without waiting on
/// the store or a classification.
#[derive(Debug, Clone)]
pub enum ResidentOutcome {
    /// Continue normal DNS resolution. `saved` says a saved decision allowed
    /// it, so nothing is left to classify once the answer is sent.
    Proceed { saved: bool },
    /// Block now with the evaluated decision.
    Block(AiEvaluation),
    /// Memory cannot tell. [`AiCoordinator::proactive_gate`] has to run.
    Deferred,
}

#[derive(Clone)]
struct ConfigSnapshot {
    policy: AiPolicySnapshot,
    classifier: Option<SharedClassifier>,
    bootstrap_host: Option<String>,
    provider_epoch: u64,
}

/// Shared AI coordinator used by both DNS modes.
pub struct AiCoordinator {
    store: Arc<Store>,
    config: Arc<RwLock<ConfigSnapshot>>,
    generation: AtomicU64,
    persist_gate: Arc<parking_lot::Mutex<()>>,
    active: Arc<Semaphore>,
    queued: Arc<Semaphore>,
    inflight_slots: Arc<Semaphore>,
    retry_slots: Arc<Semaphore>,
    inflight: DashMap<String, Arc<Inflight>>,
    retries: DashMap<String, u32>,
    retry_tasks: DashMap<String, ()>,
    persist_tasks: DashMap<String, ()>,
    /// Domains whose saved decision is being re-read; see
    /// `refresh_resident`.
    refreshing: DashMap<String, ()>,
    shutdown: CancellationToken,
    tasks: TaskTracker,
    foreground_budget: Duration,
    background_timeout: Duration,
}

impl AiCoordinator {
    /// Creates a coordinator. `policy.generation` seeds the generation counter.
    pub fn new(
        store: Arc<Store>,
        classifier: Option<SharedClassifier>,
        policy: &AiPolicySnapshot,
        bootstrap_host: Option<String>,
    ) -> Arc<Self> {
        let generation = policy.generation;
        Arc::new(Self {
            store,
            config: Arc::new(RwLock::new(ConfigSnapshot {
                policy: *policy,
                classifier,
                bootstrap_host: bootstrap_host.and_then(|host| canonical_ai_key(&host)),
                provider_epoch: 0,
            })),
            generation: AtomicU64::new(generation),
            persist_gate: Arc::new(parking_lot::Mutex::new(())),
            active: Arc::new(Semaphore::new(
                antiwire_tuning::DNS_AI_MAX_CONCURRENT.max(1),
            )),
            queued: Arc::new(Semaphore::new(antiwire_tuning::DNS_AI_MAX_QUEUED.max(1))),
            inflight_slots: Arc::new(Semaphore::new(antiwire_tuning::DNS_AI_MAX_INFLIGHT.max(1))),
            retry_slots: Arc::new(Semaphore::new(antiwire_tuning::DNS_AI_MAX_QUEUED.max(1))),
            inflight: DashMap::new(),
            retries: DashMap::new(),
            retry_tasks: DashMap::new(),
            persist_tasks: DashMap::new(),
            refreshing: DashMap::new(),
            shutdown: CancellationToken::new(),
            tasks: TaskTracker::new(),
            foreground_budget: antiwire_tuning::DNS_AI_FOREGROUND_BUDGET,
            background_timeout: antiwire_tuning::DNS_AI_BACKGROUND_TIMEOUT,
        })
    }

    /// Current policy snapshot (cloned).
    pub fn policy_snapshot(&self) -> AiPolicySnapshot {
        self.config.read().policy
    }

    /// Current configuration generation.
    pub fn generation(&self) -> u64 {
        self.generation.load(Ordering::SeqCst)
    }

    /// Applies new settings live: enablement, mode, thresholds, actions,
    /// endpoint, and credentials. Bumps the generation so stale jobs cannot
    /// enforce outdated decisions.
    pub fn update_config(
        &self,
        policy: &AiPolicySnapshot,
        classifier: Option<SharedClassifier>,
        bootstrap_host: Option<String>,
    ) {
        let _persist_gate = self.persist_gate.lock();
        let generation = self.generation.fetch_add(1, Ordering::SeqCst) + 1;
        let next_policy = AiPolicySnapshot {
            generation,
            ..*policy
        };
        let mut config = self.config.write();
        config.policy = next_policy;
        // `None` deliberately clears the old client. The settings layer passes
        // `None` when the endpoint or credentials cannot produce a valid client.
        config.classifier = classifier;
        config.bootstrap_host = bootstrap_host.and_then(|host| canonical_ai_key(&host));
        config.provider_epoch = config.provider_epoch.wrapping_add(1);
        let enabled = config.policy.enabled;
        let client_available = config.classifier.is_some();
        drop(config);
        if !enabled || !client_available {
            // Stop admitting new AI work when disabled; in-flight foreground
            // work fails open via generation checks. An unavailable client
            // cannot recover without another settings update.
            self.retries.clear();
        }
    }

    /// Whether `domain` must skip AI (bootstrap endpoint resolution).
    ///
    /// The AI provider's own hostname resolves through the narrow bootstrap
    /// path: normal policy enforcement still applies, but no AI
    /// classification is started or waited on, so resolution cannot wait on
    /// itself.
    pub fn is_bootstrap_domain(&self, canonical: &str) -> bool {
        self.config
            .read()
            .bootstrap_host
            .as_deref()
            .is_some_and(|host| host == canonical)
    }

    /// Proactive foreground gate: saved decision or bounded new classification.
    ///
    /// `remaining` is the DNS deadline left; the AI budget is capped by it so
    /// DNS resolution time is preserved. On any timeout, outage, or overload
    /// the gate fails open (`Proceed`) and lets a shared background
    /// classification finish within its own bounded timeout. A zero
    /// `remaining` never waits, but still enforces a decision already cached.
    pub async fn proactive_gate(
        self: &Arc<Self>,
        domain: &str,
        remaining: Duration,
    ) -> ProactiveOutcome {
        let Some(canonical) = canonical_ai_key(domain) else {
            return ProactiveOutcome::Proceed;
        };
        let policy = self.policy_snapshot();
        if !policy.enabled {
            return ProactiveOutcome::Proceed;
        }
        if self.is_bootstrap_domain(&canonical) {
            return ProactiveOutcome::Proceed;
        }
        let reserve = antiwire_tuning::DNS_GATE_UPSTREAM_RESERVE.min(remaining);
        let budget = self
            .foreground_budget
            .min(remaining.saturating_sub(reserve));
        let saved = match self.store.cached_domain_decision(&canonical) {
            Some(stored) => Some(stored),
            // Retroactive mode never waits on a classification, but a saved
            // verdict is enforced in both modes, including one that has left
            // the in-memory cache. Proactive jobs read it before classifying.
            None if !policy.mode.enforces() => self.saved_decision_within(&canonical, budget).await,
            None => None,
        };
        if let Some(stored) = saved {
            let current = self.policy_snapshot();
            if !current.enabled {
                return ProactiveOutcome::Proceed;
            }
            let evaluation =
                AiEvaluation::evaluate(&CategoryScores::from_stored(&stored), &current);
            return if evaluation.should_block() {
                ProactiveOutcome::Block(evaluation)
            } else {
                ProactiveOutcome::Proceed
            };
        }
        // Retroactive learns after the answer. A saved score blocks above;
        // this query must not wait on a new classification.
        if !policy.mode.enforces() {
            return ProactiveOutcome::Proceed;
        }
        if budget.is_zero() {
            return ProactiveOutcome::Proceed;
        }

        let deadline = Instant::now() + budget;
        let shared = match self.start_or_join(&canonical) {
            Ok(shared) => shared,
            Err(error) => {
                if error.is_retryable() {
                    self.schedule_retry(&canonical);
                }
                return ProactiveOutcome::Proceed;
            }
        };
        if let Ok(completed) = self.wait_shared(shared, deadline).await {
            // Recheck current mode and policy after the await: stale work
            // must not enforce an outdated decision.
            let current = self.policy_snapshot();
            if !current.enabled {
                return ProactiveOutcome::Proceed;
            }
            if completed.policy_generation != current.generation {
                let scores = CategoryScores::from_stored(&completed.stored);
                let reevaluated = AiEvaluation::evaluate(&scores, &current);
                if reevaluated.should_block() {
                    return ProactiveOutcome::Block(reevaluated);
                }
                return ProactiveOutcome::Proceed;
            }
            if completed.evaluation.should_block() {
                ProactiveOutcome::Block(completed.evaluation)
            } else {
                ProactiveOutcome::Proceed
            }
        } else {
            ProactiveOutcome::Proceed
        }
    }

    /// What [`Self::proactive_gate`] would decide for `domain`, when memory
    /// alone can tell.
    ///
    /// The synchronous path asks this so an answer that needs no I/O is not
    /// moved to a task only to learn what is already known: a saved decision
    /// in memory is enforced here, and a name the store recently had no
    /// decision for proceeds unless a classification must come first. Reads no
    /// database itself. What it reads from memory is re-read in the background
    /// shortly before it would expire, so a name in steady use never has to
    /// wait on the store again.
    pub fn resident_gate(self: &Arc<Self>, domain: &str) -> ResidentOutcome {
        const UNDECIDED: ResidentOutcome = ResidentOutcome::Proceed { saved: false };
        let Some(canonical) = canonical_ai_key(domain) else {
            return UNDECIDED;
        };
        let (policy, can_classify) = {
            let config = self.config.read();
            if !config.policy.enabled || config.bootstrap_host.as_deref() == Some(&*canonical) {
                return UNDECIDED;
            }
            (config.policy, config.classifier.is_some())
        };
        let resident = self.store.resident_domain_decision(&canonical);
        if resident.refresh_due {
            self.refresh_resident(canonical);
        }
        match resident.decision {
            ResidentDecision::Saved(stored) => {
                let evaluation =
                    AiEvaluation::evaluate(&CategoryScores::from_stored(&stored), &policy);
                if evaluation.should_block() {
                    ResidentOutcome::Block(evaluation)
                } else {
                    ResidentOutcome::Proceed { saved: true }
                }
            }
            // Proactive mode classifies an unknown name before answering.
            // With no classifier that cannot happen, and the gate fails open.
            ResidentDecision::NotSaved if policy.mode.enforces() && can_classify => {
                ResidentOutcome::Deferred
            }
            ResidentDecision::NotSaved => UNDECIDED,
            ResidentDecision::Unknown => ResidentOutcome::Deferred,
        }
    }

    /// Submits post-response work; only call after the send succeeded.
    pub fn submit_post_response(self: &Arc<Self>, work: &PostResponseWork) {
        let Some(canonical) = canonical_ai_key(&work.domain) else {
            return;
        };
        if !work.eligible {
            return;
        }
        debug!(
            domain = %canonical,
            was_block = work.was_block,
            "ai post-response work submitted"
        );
        if !self.policy_snapshot().enabled
            || self.is_bootstrap_domain(&canonical)
            || self.shutdown.is_cancelled()
            || self.tasks.is_closed()
        {
            return;
        }
        if self.store.cached_domain_decision(&canonical).is_some() {
            return;
        }
        // With no classifier a job could only read the store and fail, once
        // for every answer sent. A saved decision does not need it: the gate
        // reads the store itself before the next answer.
        if self.config.read().classifier.is_none() {
            return;
        }
        if let Err(error) = self.start_or_join(&canonical) {
            if error.is_retryable() {
                self.schedule_retry(&canonical);
            }
        }
    }

    /// Cancels remaining work; bounds shutdown time.
    pub async fn shutdown(&self) {
        self.shutdown_cancel();
        tokio::time::timeout(antiwire_tuning::DNS_AI_SHUTDOWN_TIMEOUT, self.tasks.wait())
            .await
            .ok();
    }

    /// Synchronous cancel for blocking teardown paths.
    ///
    /// DNS admission capacity is released when the response is sent, never
    /// held for background AI work, so this only stops AI tasks.
    pub fn shutdown_cancel(&self) {
        self.shutdown.cancel();
        self.tasks.close();
        for entry in &self.inflight {
            *entry.result.lock() =
                Some(Err(ClassifierError::Transient("shutting down".to_owned())));
            entry.notify.notify_waiters();
        }
        self.inflight.clear();
        self.retries.clear();
        self.retry_tasks.clear();
        self.persist_tasks.clear();
        self.refreshing.clear();
    }
}

#[cfg(test)]
mod tests;
