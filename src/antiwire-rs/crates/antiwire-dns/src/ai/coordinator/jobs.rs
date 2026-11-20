//! Running one classification: checking for a saved decision, asking the
//! classifier within the deadline, and saving the result.

use std::sync::Arc;
use std::time::Duration;
use std::time::Instant;

use antiwire_store::{DeletionFence, DomainDecision as StoredDecision};
use tracing::{debug, warn};

use super::AiCoordinator;
use crate::ai::classifier::ClassifierError;
use crate::ai::decision::{AiEvaluation, CategoryScores};

pub(super) struct Admission {
    queued: Option<tokio::sync::OwnedSemaphorePermit>,
    inflight: Option<tokio::sync::OwnedSemaphorePermit>,
    active: Option<tokio::sync::OwnedSemaphorePermit>,
}

impl Admission {
    pub(super) fn new(
        queued: tokio::sync::OwnedSemaphorePermit,
        inflight: Option<tokio::sync::OwnedSemaphorePermit>,
    ) -> Self {
        Self {
            queued: Some(queued),
            inflight,
            active: None,
        }
    }

    fn take_all(&mut self) -> Self {
        Self {
            queued: self.queued.take(),
            inflight: self.inflight.take(),
            active: self.active.take(),
        }
    }
}

#[derive(Debug)]
pub(super) enum PersistError {
    StaleProvider,
    /// The domain was deleted, or a row already exists, after this job started.
    Superseded,
    Failed(String),
}

/// Finished classification shared with waiters.
#[derive(Debug, Clone)]
pub(super) struct CompletedClassification {
    pub(super) evaluation: AiEvaluation,
    pub(super) stored: StoredDecision,
    pub(super) policy_generation: u64,
}

impl AiCoordinator {
    pub(super) async fn run_owned_job(
        self: &Arc<Self>,
        canonical: &str,
        deadline: Instant,
        admission: &mut Admission,
        fence: DeletionFence,
    ) -> Result<CompletedClassification, ClassifierError> {
        let stored = self
            .lookup_saved_until(canonical, deadline, admission)
            .await
            .map_err(ClassifierError::Transient)?;
        if let Some(stored) = stored {
            let policy = self.policy_snapshot();
            return Ok(CompletedClassification {
                evaluation: AiEvaluation::evaluate(&CategoryScores::from_stored(&stored), &policy),
                stored,
                policy_generation: policy.generation,
            });
        }
        self.run_classification_owned(canonical, deadline, admission, fence)
            .await
    }

    async fn run_classification_owned(
        self: &Arc<Self>,
        canonical: &str,
        deadline: Instant,
        admission: &mut Admission,
        fence: DeletionFence,
    ) -> Result<CompletedClassification, ClassifierError> {
        let permit = tokio::time::timeout_at(
            tokio::time::Instant::from_std(deadline),
            self.active.clone().acquire_owned(),
        )
        .await
        .map_err(|_| ClassifierError::Transient("ai budget expired".to_owned()))?
        .map_err(|_| ClassifierError::Transient("ai overloaded".to_owned()))?;
        admission.active = Some(permit);
        let config = self.config.read().clone();
        if !config.policy.enabled {
            return Err(ClassifierError::Transient("ai disabled".to_owned()));
        }
        let classifier = config
            .classifier
            .ok_or_else(|| ClassifierError::Unavailable("ai client unavailable".to_owned()))?;
        let generation = config.policy.generation;
        let domain = canonical.to_owned();
        let assessment = tokio::time::timeout_at(
            tokio::time::Instant::from_std(deadline),
            classifier.classify(&domain),
        )
        .await
        .map_err(|_| ClassifierError::Transient("ai timed out".to_owned()))??;

        let current = self.config.read().clone();
        if current.policy.generation != generation {
            return Err(ClassifierError::Transient(
                "ai provider changed during classification".to_owned(),
            ));
        }
        let scores = CategoryScores::from_assessment(&assessment);
        let evaluation = AiEvaluation::evaluate(&scores, &current.policy);
        let now = time::OffsetDateTime::now_utc();
        let stored = evaluation.to_stored(&domain, &assessment.model, &scores, now, None);
        // Preserve first_seen and avoid overwriting a row that appeared while
        // this owner was classifying. A read error is retryable, never absence.
        match self
            .lookup_saved_until(canonical, deadline, admission)
            .await
        {
            Ok(Some(existing)) => {
                return Ok(CompletedClassification {
                    evaluation: AiEvaluation::evaluate(
                        &CategoryScores::from_stored(&existing),
                        &current.policy,
                    ),
                    stored: existing,
                    policy_generation: current.policy.generation,
                });
            }
            Ok(None) => {}
            Err(error) => return Err(ClassifierError::Transient(error)),
        }
        if remaining_until(deadline).is_err() {
            return Err(ClassifierError::Transient("ai budget expired".to_owned()));
        }
        match self
            .persist_stored_until(&stored, generation, deadline, admission, fence)
            .await
        {
            Ok(()) | Err(PersistError::Superseded) => {}
            Err(PersistError::StaleProvider) => {
                return Err(ClassifierError::Transient(
                    "ai provider changed before persistence".to_owned(),
                ));
            }
            Err(PersistError::Failed(error)) => {
                self.schedule_persist_retry(stored.clone(), generation, fence);
                warn!(%error, "ai decision persistence failed; retry scheduled");
            }
        }
        Ok(CompletedClassification {
            evaluation,
            stored,
            policy_generation: current.policy.generation,
        })
    }

    /// The saved decision for `canonical`, read within `budget`, for a gate
    /// that will not classify. Fails open: `None` when the read is shed,
    /// times out, or fails. A read that outlives `budget` keeps its admission
    /// until it finishes, so stalled reads stay bounded.
    pub(super) async fn saved_decision_within(
        &self,
        canonical: &str,
        budget: Duration,
    ) -> Option<StoredDecision> {
        if budget.is_zero() {
            return None;
        }
        let queued = self.queued.clone().try_acquire_owned().ok()?;
        let mut admission = Admission::new(queued, None);
        match self
            .lookup_saved_until(canonical, Instant::now() + budget, &mut admission)
            .await
        {
            Ok(saved) => saved,
            Err(error) => {
                debug!(domain = %canonical, %error, "saved ai decision unavailable; failing open");
                None
            }
        }
    }

    /// Re-reads `canonical`'s saved decision off the caller's path, once per
    /// domain at a time, so what memory holds starts a new residency.
    ///
    /// Shed without a trace when the store is busy or work is ending: the
    /// entry then expires and the next query runs the gate, as it did before.
    pub(super) fn refresh_resident(self: &Arc<Self>, canonical: String) {
        /// Lets the domain be refreshed again however its read ends.
        struct Refreshing {
            coordinator: Arc<AiCoordinator>,
            domain: String,
        }

        impl Drop for Refreshing {
            fn drop(&mut self) {
                self.coordinator.refreshing.remove(&self.domain);
            }
        }

        if self.shutdown.is_cancelled()
            || self.tasks.is_closed()
            || tokio::runtime::Handle::try_current().is_err()
        {
            return;
        }
        let Ok(queued) = self.queued.clone().try_acquire_owned() else {
            return;
        };
        if self.refreshing.insert(canonical.clone(), ()).is_some() {
            return;
        }
        let refreshing = Refreshing {
            coordinator: Arc::clone(self),
            domain: canonical,
        };
        self.tasks.spawn(async move {
            let _queued = queued;
            let store = Arc::clone(&refreshing.coordinator.store);
            let domain = refreshing.domain.clone();
            let read = tokio::task::spawn_blocking(move || {
                store
                    .reload_domain_decision(&domain)
                    .map_err(|error| error.to_string())
            })
            .await;
            match read {
                Ok(Ok(_)) => {}
                Ok(Err(error)) => {
                    debug!(domain = %refreshing.domain, %error, "saved ai decision refresh failed");
                }
                Err(error) => {
                    debug!(domain = %refreshing.domain, %error, "saved ai decision refresh failed");
                }
            }
        });
    }

    async fn lookup_saved_until(
        &self,
        canonical: &str,
        deadline: Instant,
        admission: &mut Admission,
    ) -> Result<Option<StoredDecision>, String> {
        let store = Arc::clone(&self.store);
        let key = canonical.to_owned();
        let mut handle = tokio::task::spawn_blocking(move || {
            store
                .get_domain_decision(&key)
                .map_err(|error| error.to_string())
        });
        if let Ok(result) =
            tokio::time::timeout_at(tokio::time::Instant::from_std(deadline), &mut handle).await
        {
            result.map_err(|error| error.to_string())?
        } else {
            self.detach_blocking(handle, admission.take_all());
            Err("saved decision lookup timed out".to_owned())
        }
    }

    pub(super) async fn persist_stored_until(
        &self,
        stored: &StoredDecision,
        generation: u64,
        deadline: Instant,
        admission: &mut Admission,
        fence: DeletionFence,
    ) -> Result<(), PersistError> {
        let store = Arc::clone(&self.store);
        let stored = stored.clone();
        let config = Arc::clone(&self.config);
        let persist_gate = Arc::clone(&self.persist_gate);
        let mut handle = tokio::task::spawn_blocking(move || {
            let _gate = persist_gate.lock();
            if config.read().policy.generation != generation {
                return Err(PersistError::StaleProvider);
            }
            match store.insert_domain_decision_if_absent(&stored, fence) {
                Ok(true) => Ok(()),
                Ok(false) => Err(PersistError::Superseded),
                Err(error) => Err(PersistError::Failed(error.to_string())),
            }
        });
        match tokio::time::timeout_at(tokio::time::Instant::from_std(deadline), &mut handle).await {
            Ok(Ok(result)) => result,
            Ok(Err(error)) => Err(PersistError::Failed(error.to_string())),
            Err(_) => {
                self.detach_blocking(handle, admission.take_all());
                Err(PersistError::Failed(
                    "decision persistence timed out".to_owned(),
                ))
            }
        }
    }

    fn detach_blocking<T>(&self, handle: tokio::task::JoinHandle<T>, admission: Admission)
    where
        T: Send + 'static,
    {
        let tasks = self.tasks.clone();
        tasks.spawn(async move {
            let _ = handle.await;
            drop(admission);
        });
    }
}

fn remaining_until(deadline: Instant) -> Result<Duration, ClassifierError> {
    deadline
        .checked_duration_since(Instant::now())
        .ok_or_else(|| ClassifierError::Transient("ai budget expired".to_owned()))
}
