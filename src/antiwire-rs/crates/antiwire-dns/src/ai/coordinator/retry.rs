//! Background retries: classifying a domain again after a transient
//! failure, and saving a finished classification whose write failed.

use std::sync::Arc;
use std::time::Instant;

use antiwire_store::{DeletionFence, DomainDecision as StoredDecision};

use super::jobs::{Admission, PersistError};
use super::AiCoordinator;

impl AiCoordinator {
    /// Bounded background retry with backoff for failed classifications.
    pub(super) fn schedule_retry(self: &Arc<Self>, canonical: &str) {
        if self.shutdown.is_cancelled() || self.tasks.is_closed() {
            return;
        }
        let config = self.config.read();
        if !config.policy.enabled || config.classifier.is_none() {
            return;
        }
        drop(config);
        if self.retry_tasks.insert(canonical.to_owned(), ()).is_some() {
            return;
        }
        let Ok(slot) = self.retry_slots.clone().try_acquire_owned() else {
            self.retry_tasks.remove(canonical);
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
                () = tokio::time::sleep(delay) => {
                    this.retry_tasks.remove(&domain);
                    let config = this.config.read();
                    let can_retry = config.policy.enabled && config.classifier.is_some();
                    drop(config);
                    if can_retry {
                        if let Err(error) = this.start_or_join(&domain) {
                            if error.is_retryable() {
                                this.schedule_retry(&domain);
                            }
                        }
                    } else {
                        this.retries.remove(&domain);
                    }
                }
            }
            drop(slot);
        });
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
