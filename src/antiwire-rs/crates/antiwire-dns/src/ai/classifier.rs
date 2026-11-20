//! Injectable classifier interface so tests control AI without network.
//!
//! Production classifies through [`antiwire_ai::AiBackend`], built from the
//! saved API key with [`antiwire_ai::AiBackend::with_api_key`] rather than the
//! environment-based `connect()`.

use std::sync::Arc;
use std::time::Duration;

/// Classification failure, distinguishing retryable outages from permanent input errors.
#[derive(Debug, Clone)]
pub(crate) enum ClassifierError {
    /// Timeout, overload, or provider error: fail open, retry in background.
    Transient(String),
    /// Invalid domain: do not retry as-is. An incomplete provider answer is
    /// `Transient`, since asking again can succeed.
    Permanent(String),
    /// No configured client: retry only after settings change, not on a timer.
    Unavailable(String),
}

impl ClassifierError {
    #[must_use]
    pub(crate) const fn is_retryable(&self) -> bool {
        matches!(self, Self::Transient(_))
    }
}

impl std::fmt::Display for ClassifierError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Transient(message) | Self::Permanent(message) | Self::Unavailable(message) => {
                write!(f, "{message}")
            }
        }
    }
}

/// Narrow classifier interface shared by proactive and retroactive paths.
#[async_trait::async_trait]
pub(crate) trait Classifier: Send + Sync {
    async fn classify(
        &self,
        domain: &str,
    ) -> Result<antiwire_ai::DomainAssessment, ClassifierError>;
}

/// Production classifier backed by [`antiwire_ai::AiBackend`].
pub(crate) struct AiBackendClassifier {
    backend: antiwire_ai::AiBackend,
}

impl AiBackendClassifier {
    /// Builds the backend from the saved API key.
    ///
    /// # Errors
    ///
    /// Returns a description when the backend cannot be built (missing key,
    /// bad timeout, ...).
    pub(crate) fn from_settings(
        api_key: &str,
        background_timeout: Duration,
    ) -> Result<Self, String> {
        antiwire_ai::AiBackend::with_api_key(api_key, background_timeout)
            .map(|backend| Self { backend })
            .map_err(|error| error.to_string())
    }
}

#[async_trait::async_trait]
impl Classifier for AiBackendClassifier {
    async fn classify(
        &self,
        domain: &str,
    ) -> Result<antiwire_ai::DomainAssessment, ClassifierError> {
        self.backend.classify_domain(domain).await.map_err(|error| {
            // Timeouts, transport failures, and incomplete answers are all
            // transient for DNS purposes: fail open now, retry in background.
            // Only invalid input is permanent.
            match &error {
                antiwire_ai::Error::InvalidDomain => ClassifierError::Permanent(error.to_string()),
                _ => ClassifierError::Transient(error.to_string()),
            }
        })
    }
}

/// Shared classifier handle used by the coordinator.
pub(crate) type SharedClassifier = Arc<dyn Classifier>;

#[cfg(test)]
pub(crate) mod test_helpers {
    use super::*;
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// Controllable mock classifier with event recording and barriers.
    pub(crate) struct MockClassifier {
        calls: AtomicUsize,
        handler: parking_lot::Mutex<HashMap<String, MockBehavior>>,
        default: MockBehavior,
    }

    #[derive(Debug, Clone)]
    pub(crate) enum MockBehavior {
        Assess(antiwire_ai::DomainAssessment),
        Transient(String),
    }

    impl MockClassifier {
        pub(crate) fn with_assessment(
            domain: &str,
            assessment: antiwire_ai::DomainAssessment,
        ) -> Arc<Self> {
            let mock = Arc::new(Self {
                calls: AtomicUsize::new(0),
                handler: parking_lot::Mutex::new(HashMap::new()),
                default: MockBehavior::Transient("no behavior".to_owned()),
            });
            mock.set(domain, MockBehavior::Assess(assessment));
            mock
        }

        pub(crate) fn failing(message: &str) -> Arc<Self> {
            Arc::new(Self {
                calls: AtomicUsize::new(0),
                handler: parking_lot::Mutex::new(HashMap::new()),
                default: MockBehavior::Transient(message.to_owned()),
            })
        }

        pub(crate) fn set(&self, domain: &str, behavior: MockBehavior) {
            if let Some(key) = crate::ai::decision::canonical_ai_key(domain) {
                self.handler.lock().insert(key, behavior);
            }
        }

        pub(crate) fn call_count(&self) -> usize {
            self.calls.load(Ordering::SeqCst)
        }
    }

    /// Judges every name after `delay`, as a classifier behind a slow link
    /// does, with `malicious` as its malicious score.
    pub(crate) struct SlowClassifier {
        pub delay: std::time::Duration,
        pub malicious: f64,
    }

    #[async_trait::async_trait]
    impl Classifier for SlowClassifier {
        async fn classify(
            &self,
            domain: &str,
        ) -> Result<antiwire_ai::DomainAssessment, ClassifierError> {
            tokio::time::sleep(self.delay).await;
            Ok(assessment_for(domain, self.malicious))
        }
    }

    pub(crate) fn assessment_for(domain: &str, malicious: f64) -> antiwire_ai::DomainAssessment {
        antiwire_ai::DomainAssessment {
            domain: domain.to_owned(),
            model: "mock".to_owned(),
            advertising: 0.01,
            tracking: 0.01,
            telemetry: 0.01,
            analytics: 0.01,
            malicious,
            security_fraud: 0.01,
            cryptomining: 0.01,
            tunnel: 0.01,
        }
    }

    #[async_trait::async_trait]
    impl Classifier for MockClassifier {
        async fn classify(
            &self,
            domain: &str,
        ) -> Result<antiwire_ai::DomainAssessment, ClassifierError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let key = crate::ai::decision::canonical_ai_key(domain).unwrap_or_default();
            let behavior = self
                .handler
                .lock()
                .get(&key)
                .cloned()
                .unwrap_or_else(|| self.default.clone());
            match behavior {
                MockBehavior::Assess(assessment) => Ok(assessment),
                MockBehavior::Transient(message) => Err(ClassifierError::Transient(message)),
            }
        }
    }
}
