//! Domain-use classification on top of [`antiwire_aibackend`].
//!
//! [`AiBackend::with_api_key`] builds the `TypeSafe` client from a saved API
//! key (base URL from the environment). [`AiBackend::classify_domain`]
//! asks Jev eight noul questions in one call: advertising, tracking,
//! telemetry, analytics, malicious activity, lookalike fraud,
//! cryptomining, and reverse-proxy or tunnel endpoints.
//!
//! A noul answer is the probability that the answer is yes. Compare it with
//! [`YES_THRESHOLD`] or your own cutoff. Values near 0.5 are uncertain.

mod classify;
mod evidence;

use std::time::Duration;

use antiwire_aibackend::{RetryPolicy, TypeSafeClient};

pub use antiwire_aibackend::Error as BackendError;
pub use classify::{
    AdvancedAssessment, DomainAssessment, DomainUse, NoulPrompt, ADVANCED_NOULS, DOMAIN_NOULS,
};
pub use evidence::RegistrationEvidence;

/// Probability at or above which a noul is treated as a yes.
///
/// `TypeSafe` documents 0.8 as a starting yes cutoff when a false yes is costly.
pub const YES_THRESHOLD: f64 = 0.8;

/// API root classification requests are sent to.
///
/// The endpoint is owned by `antiwire-aibackend` (`TYPESAFE_BASE_URL`, else
/// its default). Callers that need the provider's hostname use this rather
/// than storing a URL of their own.
#[must_use]
pub fn endpoint() -> String {
    antiwire_aibackend::resolved_base_url()
}

/// Configured `TypeSafe` client used to classify domains with Jev.
#[derive(Clone, Debug)]
pub struct AiBackend {
    client: TypeSafeClient,
}

impl AiBackend {
    /// Build the backend from a saved API key instead of the environment.
    ///
    /// Each request is bounded by `timeout` and is not retried by the client,
    /// so callers with their own retry schedule are not delayed by backoff.
    ///
    /// # Errors
    ///
    /// Returns [`Error::MissingApiKey`] when `api_key` is blank, and
    /// [`Error::Backend`] when the client cannot be built.
    pub fn with_api_key(api_key: &str, timeout: Duration) -> Result<Self, Error> {
        let api_key = api_key.trim();
        if api_key.is_empty() {
            return Err(Error::MissingApiKey);
        }
        let client = TypeSafeClient::builder()
            .api_key(api_key)
            .timeout(timeout)
            .retry(RetryPolicy {
                max_retries: 0,
                ..RetryPolicy::default()
            })
            .build()?;
        Ok(Self { client })
    }

    /// Use a client that was already built. Classification still sends `jev-latest`.
    #[must_use]
    pub fn from_client(client: TypeSafeClient) -> Self {
        Self { client }
    }

    /// The underlying client, for model listing or a custom call.
    #[must_use]
    pub fn client(&self) -> &TypeSafeClient {
        &self.client
    }

    /// Ask Jev whether `domain` is used for each [`DomainUse`].
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidDomain`] when `domain` is not a hostname.
    /// Returns [`Error::Backend`] when the request fails, and
    /// [`Error::Incomplete`] when a category answer is missing or not a noul.
    pub async fn classify_domain(&self, domain: &str) -> Result<DomainAssessment, Error> {
        classify::classify(&self.client, domain).await
    }

    /// Ask the eight category questions and the four registration questions.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidDomain`] when the evidence domain is not a hostname.
    /// Returns [`Error::Backend`] when the request fails, and
    /// [`Error::Incomplete`] when a category or signal answer is missing.
    pub async fn classify_domain_advanced(
        &self,
        evidence: &RegistrationEvidence,
    ) -> Result<AdvancedAssessment, Error> {
        classify::classify_advanced(&self.client, evidence).await
    }
}

/// Failure while setting up the backend or classifying a domain.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The `TypeSafe` client or the HTTP call failed.
    #[error(transparent)]
    Backend(#[from] BackendError),

    /// No API key was supplied.
    #[error("AI API key is empty")]
    MissingApiKey,

    /// The input was empty or not a hostname.
    #[error("domain must be a hostname without a scheme or path")]
    InvalidDomain,

    /// Jev did not return a noul for one of the domain-use questions.
    #[error("Jev did not return a noul answer for {category}")]
    Incomplete {
        /// Question id that was missing or the wrong answer type.
        category: &'static str,
    },
}
