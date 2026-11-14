//! One classification per domain at a time: later queries for a domain
//! already being classified wait for that answer instead of asking again.

use std::sync::Arc;
#[cfg(test)]
use std::time::Duration;
use std::time::Instant;

use antiwire_store::DeletionFence;
use tokio::sync::Notify;

use super::jobs::{Admission, CompletedClassification};
use super::AiCoordinator;
use crate::ai::classifier::ClassifierError;

/// One in-flight classification shared by all waiters for a domain.
pub(super) struct Inflight {
    pub(super) notify: Notify,
    pub(super) result: parking_lot::Mutex<Option<Result<CompletedClassification, ClassifierError>>>,
}

/// The owning task's claim on a domain's [`Inflight`] entry.
///
/// A task that ends without finishing (it panicked, or was dropped) still
/// releases the entry: otherwise every later query would join a classification
/// that never completes, and the domain would never be classified again.
struct OwnedInflight {
    coordinator: Arc<AiCoordinator>,
    domain: Option<String>,
}

impl OwnedInflight {
    fn finish(mut self, result: Result<CompletedClassification, ClassifierError>) {
        if let Some(domain) = self.domain.take() {
            self.coordinator.finish_inflight(&domain, result);
        }
    }
}

impl Drop for OwnedInflight {
    fn drop(&mut self) {
        if let Some(domain) = self.domain.take() {
            self.coordinator.finish_inflight(
                &domain,
                Err(ClassifierError::Transient(
                    "ai classification ended without a result".to_owned(),
                )),
            );
        }
    }
}

impl AiCoordinator {
    #[cfg(test)]
    pub(super) async fn classify_shared(
        self: &Arc<Self>,
        canonical: &str,
        timeout: Duration,
    ) -> Result<CompletedClassification, ClassifierError> {
        let shared = self.start_or_join(canonical)?;
        self.wait_shared(shared, Instant::now() + timeout).await
    }

    /// Starts one background-owned job or joins an existing job.
    pub(super) fn start_or_join(
        self: &Arc<Self>,
        canonical: &str,
    ) -> Result<Arc<Inflight>, ClassifierError> {
        if self.shutdown.is_cancelled() {
            return Err(ClassifierError::Transient("shutting down".to_owned()));
        }
        if !self.policy_snapshot().enabled {
            return Err(ClassifierError::Transient("ai disabled".to_owned()));
        }
        if let Some(shared) = self.inflight.get(canonical) {
            return Ok(shared.clone());
        }
        let queued = self
            .queued
            .clone()
            .try_acquire_owned()
            .map_err(|_| ClassifierError::Transient("ai overloaded".to_owned()))?;
        let inflight = self
            .inflight_slots
            .clone()
            .try_acquire_owned()
            .map_err(|_| ClassifierError::Transient("ai overloaded".to_owned()))?;
        let entry = Arc::new(Inflight {
            notify: Notify::new(),
            result: parking_lot::Mutex::new(None),
        });
        match self.inflight.entry(canonical.to_owned()) {
            dashmap::mapref::entry::Entry::Occupied(occupied) => {
                let shared = occupied.get().clone();
                drop(occupied);
                drop(queued);
                drop(inflight);
                Ok(shared)
            }
            dashmap::mapref::entry::Entry::Vacant(vacant) => {
                vacant.insert(Arc::clone(&entry));
                if self.tasks.is_closed() {
                    self.finish_inflight(
                        canonical,
                        Err(ClassifierError::Transient("shutting down".to_owned())),
                    );
                    return Err(ClassifierError::Transient("shutting down".to_owned()));
                }
                let this = Arc::clone(self);
                let domain = canonical.to_owned();
                let fence = DeletionFence::now();
                self.tasks.spawn(async move {
                    let owned = OwnedInflight {
                        coordinator: Arc::clone(&this),
                        domain: Some(domain.clone()),
                    };
                    let mut admission = Admission::new(queued, Some(inflight));
                    let deadline = Instant::now() + this.background_timeout;
                    let result = this
                        .run_owned_job(&domain, deadline, &mut admission, fence)
                        .await;
                    let retryable = result.as_ref().is_err_and(ClassifierError::is_retryable);
                    owned.finish(result.clone());
                    if retryable {
                        this.schedule_retry(&domain);
                    } else {
                        this.retries.remove(&domain);
                    }
                });
                Ok(entry)
            }
        }
    }

    pub(super) async fn wait_shared(
        &self,
        shared: Arc<Inflight>,
        deadline: Instant,
    ) -> Result<CompletedClassification, ClassifierError> {
        let notified = shared.notify.notified();
        tokio::pin!(notified);
        notified.as_mut().enable();
        if let Some(result) = shared.result.lock().clone() {
            return result;
        }
        let _ = tokio::time::timeout_at(deadline.into(), &mut notified).await;
        match shared.result.lock().clone() {
            Some(Ok(completed)) => Ok(completed),
            Some(Err(error)) => Err(error),
            None => Err(ClassifierError::Transient("ai budget expired".to_owned())),
        }
    }

    fn finish_inflight(
        &self,
        canonical: &str,
        result: Result<CompletedClassification, ClassifierError>,
    ) {
        if let Some((_, entry)) = self.inflight.remove(canonical) {
            *entry.result.lock() = Some(result);
            entry.notify.notify_waiters();
        }
    }
}
