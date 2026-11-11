//! The saved `TypeSafe` domain classifications: listing them, deleting them,
//! and classifying a saved domain again on request.

use std::sync::Arc;

use antiwire_ai::RegistrationEvidence;
use antiwire_lookup::Registration;
use antiwire_store::{
    DeletionFence, DomainDecision, DomainDecisionPage, DomainDecisionQuery, Store, StoreError,
};
use time::OffsetDateTime;

use crate::context::ServiceContext;
use crate::domain_lookup::registration_row;
use crate::lookup_clients::{ClassifierSource, LookupClients, RegistryClient};
use crate::settings_feed::SettingsFeed;

#[cfg(test)]
mod tests;

/// How thoroughly to classify a domain again.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scan {
    /// The eight category questions.
    Basic,
    /// The category questions plus the domain's official registration record.
    Advanced,
}

/// Why a decision could not be read, deleted, or classified again. Nothing
/// saved changed.
#[derive(Debug, thiserror::Error)]
pub enum AiDecisionError {
    #[error("domain is empty")]
    EmptyDomain,
    /// No decision is saved for the domain, or it was deleted meanwhile.
    #[error("decision not found")]
    NotFound,
    #[error("AI API key is not configured")]
    NoApiKey,
    /// No classifier could be built for the saved key.
    #[error("{0}")]
    ClassifierUnavailable(antiwire_ai::Error),
    #[error("registry lookup failed: {0}")]
    Registry(antiwire_lookup::Error),
    #[error("classification failed: {0}")]
    Classification(antiwire_ai::Error),
    #[error(transparent)]
    Store(StoreError),
    #[error("the decision update did not finish: {0}")]
    Interrupted(String),
}

/// Reviews the saved AI decisions.
pub struct AiDecisionService {
    store: Arc<Store>,
    settings: SettingsFeed,
    registry: Arc<dyn RegistryClient>,
    classifiers: Arc<dyn ClassifierSource>,
}

impl AiDecisionService {
    #[must_use]
    pub fn new(context: &ServiceContext, clients: &LookupClients) -> Self {
        Self {
            store: Arc::clone(&context.store),
            settings: context.settings.clone(),
            registry: Arc::clone(&clients.registry),
            classifiers: Arc::clone(&clients.classifiers),
        }
    }

    /// One page of saved decisions.
    ///
    /// # Errors
    ///
    /// A store failure.
    pub async fn page(
        &self,
        query: DomainDecisionQuery,
    ) -> Result<DomainDecisionPage, AiDecisionError> {
        let store = Arc::clone(&self.store);
        blocking(move || store.query_domain_decisions(&query)).await
    }

    /// Deletes the saved decision for `domain`, returning whether one existed.
    ///
    /// A block that stops applying flushes the OS resolver cache, which
    /// would otherwise keep answering with the block until its TTL expired.
    ///
    /// # Errors
    ///
    /// [`AiDecisionError::EmptyDomain`], or a store failure.
    pub async fn delete(&self, domain: &str) -> Result<bool, AiDecisionError> {
        let key = decision_key(domain)?;
        let store = Arc::clone(&self.store);
        let deleted = blocking(move || store.delete_domain_decision(&key)).await?;
        if let Some(previous) = &deleted {
            antiwire_dns::apply_verdict_change(&previous.verdict, "");
        }
        Ok(deleted.is_some())
    }

    /// Classifies one saved domain again and replaces its scores and verdict.
    ///
    /// `first_seen` is kept. The API key is checked before any registry
    /// request, and a lookup or classification failure leaves the saved
    /// decision in place. An advanced scan's registration record is saved
    /// only when `save_domain_lookups` is on.
    ///
    /// # Errors
    ///
    /// See [`AiDecisionError`]; [`AiDecisionError::NotFound`] also when the
    /// user deleted the domain while it was being classified.
    pub async fn reclassify(
        &self,
        domain: &str,
        scan: Scan,
    ) -> Result<DomainDecision, AiDecisionError> {
        let fence = DeletionFence::now();
        let key = decision_key(domain)?;
        let existing = {
            let store = Arc::clone(&self.store);
            let key = key.clone();
            blocking(move || store.get_domain_decision(&key)).await?
        }
        .ok_or(AiDecisionError::NotFound)?;
        let settings = self.settings.current();
        let api_key = settings.ai_api_key.as_str().unwrap_or_default();
        if api_key.trim().is_empty() {
            return Err(AiDecisionError::NoApiKey);
        }
        let classifier = self
            .classifiers
            .connect(api_key)
            .map_err(AiDecisionError::ClassifierUnavailable)?;
        let now = OffsetDateTime::now_utc();

        let (stored, lookup) = match scan {
            Scan::Basic => {
                let assessment = classifier
                    .classify(&key)
                    .await
                    .map_err(AiDecisionError::Classification)?;
                let stored =
                    antiwire_dns::refreshed_decision(&existing, &assessment, &settings, now);
                (stored, None)
            }
            Scan::Advanced => {
                let record = self
                    .registry
                    .lookup(&key)
                    .await
                    .map_err(AiDecisionError::Registry)?;
                let advanced = classifier
                    .classify_advanced(&registration_evidence(&record))
                    .await
                    .map_err(AiDecisionError::Classification)?;
                let stored = antiwire_dns::advanced_decision(&existing, &advanced, &settings, now);
                let lookup = settings
                    .save_domain_lookups
                    .then(|| registration_row(&record, stored.updated_at));
                (stored, lookup)
            }
        };

        let store = Arc::clone(&self.store);
        let saved = stored.clone();
        let written = blocking(move || match scan {
            Scan::Basic => store.upsert_domain_decision_unless_deleted(&saved, Some(fence)),
            Scan::Advanced => store.save_advanced_check(&saved, fence, lookup.as_ref()),
        })
        .await?;
        if !written {
            return Err(AiDecisionError::NotFound);
        }
        antiwire_dns::apply_verdict_change(&existing.verdict, &stored.verdict);
        Ok(stored)
    }
}

fn decision_key(domain: &str) -> Result<String, AiDecisionError> {
    antiwire_dns::canonical_ai_key(domain).ok_or(AiDecisionError::EmptyDomain)
}

/// Runs store work on a blocking thread.
async fn blocking<T: Send + 'static>(
    work: impl FnOnce() -> Result<T, StoreError> + Send + 'static,
) -> Result<T, AiDecisionError> {
    tokio::task::spawn_blocking(work)
        .await
        .map_err(|error| AiDecisionError::Interrupted(error.to_string()))?
        .map_err(AiDecisionError::Store)
}

/// The registration facts the classifier is asked about.
fn registration_evidence(record: &Registration) -> RegistrationEvidence {
    RegistrationEvidence {
        domain: record.domain.clone(),
        source: record.source.as_str().to_owned(),
        registrar: record.registrar.clone(),
        registrar_id: record.registrar_id.clone(),
        statuses: record.statuses.clone(),
        registered_at: record.registered_at,
        expires_at: record.expires_at,
        redacted: record.redacted,
        dnssec: record.dnssec,
    }
}
