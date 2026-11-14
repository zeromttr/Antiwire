//! The outside services the domain inspector and the AI review ask: the
//! registries, the Certificate Transparency index, and the classifier.

use std::sync::Arc;

use antiwire_ai::{AdvancedAssessment, AiBackend, DomainAssessment, RegistrationEvidence};
use antiwire_dns::RegistrationDates;
use antiwire_lookup::{CertificateSearch, CertificateSearchResult, Lookup, Registration};

/// Reads a domain's official registration record.
#[async_trait::async_trait]
pub trait RegistryClient: Send + Sync {
    /// # Errors
    ///
    /// Why no record came back: not found, rate limited, no authority for the
    /// TLD, or the registry could not be reached or read.
    async fn lookup(&self, domain: &str) -> Result<Registration, antiwire_lookup::Error>;
}

#[async_trait::async_trait]
impl RegistryClient for Lookup {
    async fn lookup(&self, domain: &str) -> Result<Registration, antiwire_lookup::Error> {
        Lookup::lookup(self, domain).await
    }
}

/// Lists the hostnames on a domain's logged TLS certificates.
#[async_trait::async_trait]
pub trait CertificateLog: Send + Sync {
    /// # Errors
    ///
    /// As [`CertificateSearch::search`].
    async fn search(&self, domain: &str)
        -> Result<CertificateSearchResult, antiwire_lookup::Error>;
}

#[async_trait::async_trait]
impl CertificateLog for CertificateSearch {
    async fn search(
        &self,
        domain: &str,
    ) -> Result<CertificateSearchResult, antiwire_lookup::Error> {
        CertificateSearch::search(self, domain).await
    }
}

/// Scores a domain against the AI categories.
#[async_trait::async_trait]
pub trait DomainClassifier: Send + Sync {
    /// # Errors
    ///
    /// As [`AiBackend::classify_domain`].
    async fn classify(&self, domain: &str) -> Result<DomainAssessment, antiwire_ai::Error>;

    /// The category scores plus the registration signals.
    ///
    /// # Errors
    ///
    /// As [`AiBackend::classify_domain_advanced`].
    async fn classify_advanced(
        &self,
        evidence: &RegistrationEvidence,
    ) -> Result<AdvancedAssessment, antiwire_ai::Error>;
}

#[async_trait::async_trait]
impl DomainClassifier for AiBackend {
    async fn classify(&self, domain: &str) -> Result<DomainAssessment, antiwire_ai::Error> {
        self.classify_domain(domain).await
    }

    async fn classify_advanced(
        &self,
        evidence: &RegistrationEvidence,
    ) -> Result<AdvancedAssessment, antiwire_ai::Error> {
        self.classify_domain_advanced(evidence).await
    }
}

/// Builds a classifier for the saved API key, which the user can change at
/// any time.
pub trait ClassifierSource: Send + Sync {
    /// # Errors
    ///
    /// When no client can be built for `api_key`.
    fn connect(&self, api_key: &str) -> Result<Box<dyn DomainClassifier>, antiwire_ai::Error>;
}

/// Classifies with the `TypeSafe` backend, bounded like background
/// classification and never retried.
pub struct TypeSafeClassifiers;

impl ClassifierSource for TypeSafeClassifiers {
    fn connect(&self, api_key: &str) -> Result<Box<dyn DomainClassifier>, antiwire_ai::Error> {
        let backend = AiBackend::with_api_key(api_key, antiwire_tuning::DNS_AI_BACKGROUND_TIMEOUT)?;
        Ok(Box::new(backend))
    }
}

/// Every outside service, built once so their caches (the IANA bootstrap
/// among them) last for the daemon's lifetime.
#[derive(Clone)]
pub struct LookupClients {
    pub registry: Arc<dyn RegistryClient>,
    pub certificates: Arc<dyn CertificateLog>,
    pub classifiers: Arc<dyn ClassifierSource>,
    /// Registration dates for the resolver's new-domain block.
    pub registration_dates: RegistrationDates,
}

impl LookupClients {
    /// The real services.
    ///
    /// # Errors
    ///
    /// When an HTTP client cannot be built.
    pub fn online() -> Result<Self, antiwire_lookup::Error> {
        // One registry client, so the record inspector and the resolver
        // share its cached IANA bootstrap.
        let registry = Arc::new(Lookup::new()?);
        Ok(Self {
            registration_dates: RegistrationDates::official(Arc::clone(&registry)),
            registry,
            certificates: Arc::new(CertificateSearch::new()?),
            classifiers: Arc::new(TypeSafeClassifiers),
        })
    }
}
