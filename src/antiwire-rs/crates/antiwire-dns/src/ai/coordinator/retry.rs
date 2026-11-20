//! Background retries: classifying a domain again after a transient
//! failure, and saving a finished classification whose write failed.

use std::sync::Arc;
use std::time::Instant;

use antiwire_store::{DeletionFence, DomainDecision as StoredDecision};
use tokio::sync::OwnedSemaphorePermit;

use super::jobs::{Admission, PersistError};
use super::AiCoordinator;

impl AiCoordinator {
    /// Bounded background retry with backoff for failed classifications.
    pub(super) fn schedule_retry(self: &Arc<Self>, canonical: &str) {
        self.retry_in(canonical, None);
    }

    /// Schedules the next retry of `canonical` in `slot`, or in a retry slot
    /// of its own when `slot` is `None`.
    ///
    /// The attempt count lives only as long as the domain's retries: a domain
    /// they end for, here or in [`Self::retry_now`], is forgotten, or every
    /// domain shed under load would stay in memory.
    fn retry_in(self: &Arc<Self>, canonical: &str, slot: Option<OwnedSemaphorePermit>) {
        // Shutting down clears every count.
        if self.shutdown.is_cancelled() || self.tasks.is_closed() {
            return;
        }
        if !self.can_classify() {
            self.retries.remove(canonical);
            return;
        }
        if self.retry_tasks.insert(canonical.to_owned(), ()).is_some() {
            return;
        }
        let Some(slot) = slot.or_else(|| self.retry_slots.clone().try_acquire_owned().ok()) else {
            self.retry_tasks.remove(canonical);
            self.retries.remove(canonical);
            return;
        };
        let attempts = self
            .retries
            .entry(canonical.to_owned())
            .and_modify(|count| *count = count.saturating_add(1))
            .or_insert(1)
            .to_owned();
        if attempts > antiwire_tuning::DNS_AI_RETRY_MAX_ATTEMPTS {
            self.retry_tasks.remove(canonical);
            self.retries.remove(canonical);
            return;
        }
        let this = Arc::clone(self);
        let domain = canonical.to_owned();
        self.tasks.spawn(async move {
            let delay = antiwire_tuning::DNS_AI_RETRY_BACKOFF.delay(attempts);
            tokio::select! {
                () = this.shutdown.cancelled() => {},
                () = tokio::time::sleep(delay) => this.retry_now(&domain, slot),
            }
        });
    }

    /// Classifies `domain` again, its backoff over. A classification that
    /// starts settles the attempt count when it ends. One that cannot start
    /// yet is retried in the same `slot`: the slot is free to take, and asking
    /// for another while holding it fails whenever the others are taken.
    fn retry_now(self: &Arc<Self>, domain: &str, slot: OwnedSemaphorePermit) {
        self.retry_tasks.remove(domain);
        if !self.can_classify() {
            self.retries.remove(domain);
            return;
        }
        match self.start_or_join(domain) {
            Ok(_) => {}
            Err(error) if error.is_retryable() => self.retry_in(domain, Some(slot)),
            Err(_) => {
                self.retries.remove(domain);
            }
        }
    }

    /// Whether a classification could run now: AI is on, with a client.
    fn can_classify(&self) -> bool {
        let config = self.config.read();
        config.policy.enabled && config.classifier.is_some()
    }

    /// Persistence-only retry: saves an already-classified result without a
    /// new AI request. There is at most one persistence chain per domain.
    pub(super) fn schedule_persist_retry(
        self: &Arc<Self>,
        stored: StoredDecision,
        provider_epoch: u64,
        fence: DeletionFence,
    ) {
        let domain = stored.domain.clone();
        if self.shutdown.is_cancelled()
            || self.tasks.is_closed()
            || self.persist_tasks.insert(domain.clone(), ()).is_some()
        {
            return;
        }
        let Ok(slot) = self.retry_slots.clone().try_acquire_owned() else {
            self.persist_tasks.remove(&domain);
            return;
        };
        let this = Arc::clone(self);
        self.tasks.spawn(async move {
            let backoff = antiwire_tuning::DNS_AI_RETRY_BACKOFF;
            let mut delay = backoff.base;
            for _ in 0..antiwire_tuning::DNS_AI_PERSIST_RETRY_MAX_ATTEMPTS {
                tokio::select! {
                    () = this.shutdown.cancelled() => break,
                    () = tokio::time::sleep(delay) => {},
                }
                let Ok(queued) = this.queued.clone().try_acquire_owned() else {
                    delay = backoff.after(delay);
                    continue;
                };
                let mut admission = Admission::new(queued, None);
                let deadline = Instant::now() + this.background_timeout;
                match this
                    .persist_stored_until(&stored, provider_epoch, deadline, &mut admission, fence)
                    .await
                {
                    Ok(()) | Err(PersistError::StaleProvider | PersistError::Superseded) => break,
                    Err(PersistError::Failed(_)) => {
                        delay = backoff.after(delay);
                    }
                }
            }
            this.persist_tasks.remove(&domain);
            drop(slot);
        });
    }
}
