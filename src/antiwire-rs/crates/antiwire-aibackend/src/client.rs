//! Async `TypeSafe` client.

use std::sync::Arc;
use std::time::Duration;

use antiwire_http::{header, Destinations, HttpClient, Method};
use serde::de::DeserializeOwned;
use serde_json::{Map, Value};

use crate::config::{self, Settings};
use crate::error::Error;
use crate::questions::{self, JsonContent, Questions};
use crate::response::{self, ListModelsResponse, SystemOneResponse};
use crate::retry::RetryPolicy;
use crate::transport::{self, HttpState, RequestParts};
use crate::Result;

/// Per-call replacements for the client defaults.
///
/// `headers` cannot replace `authorization`, `accept`, `user-agent`,
/// `x-typesafe-sdk`, `x-typesafe-runtime`, or `x-typesafe-retry-count`.
/// `extra_body` is only used by system-one calls. Keys `state`, `model`, and
/// `questions` replace those fields; other keys are appended. Objects are not
/// deep-merged.
#[derive(Debug, Clone, Default)]
pub struct CallOverrides<'a> {
    /// Model for this call. `None` uses the client default.
    pub model: Option<&'a str>,
    /// Timeout for this call. `None` uses the client default.
    pub timeout: Option<Duration>,
    /// Retry policy for this call. `None` uses the client default.
    pub retry: Option<RetryPolicy>,
    /// Extra request headers.
    pub headers: Vec<(String, String)>,
    /// Extra top-level JSON fields for a system-one body.
    pub extra_body: Option<&'a Map<String, Value>>,
}

impl CallOverrides<'_> {
    /// Append one extra header.
    #[must_use]
    pub fn header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.push((name.into(), value.into()));
        self
    }
}

/// Builder for [`TypeSafeClient`].
#[derive(Clone, Default)]
pub struct ClientBuilder {
    api_key: Option<String>,
    base_url: Option<String>,
    model: Option<String>,
    timeout: Option<Duration>,
    headers: Vec<(String, String)>,
    retry: RetryPolicy,
}

/// Leaves out the API key and header values, which may hold credentials.
impl std::fmt::Debug for ClientBuilder {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ClientBuilder")
            .field("api_key", &self.api_key.as_ref().map(|_| "<redacted>"))
            .field("base_url", &self.base_url)
            .field("model", &self.model)
            .field("timeout", &self.timeout)
            .field(
                "headers",
                &self
                    .headers
                    .iter()
                    .map(|(name, _)| name)
                    .collect::<Vec<_>>(),
            )
            .field("retry", &self.retry)
            .finish()
    }
}

impl ClientBuilder {
    /// Start a builder. The API key is read from `TYPESAFE_API_KEY` when unset.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the API key. An explicit value wins over the environment, even when empty.
    #[must_use]
    pub fn api_key(mut self, api_key: impl Into<String>) -> Self {
        self.api_key = Some(api_key.into());
        self
    }

    /// Set the API root. Trailing slashes are removed.
    #[must_use]
    pub fn base_url(mut self, base_url: impl Into<String>) -> Self {
        self.base_url = Some(base_url.into());
        self
    }

    /// Set the default model.
    #[must_use]
    pub fn model(mut self, model: impl Into<String>) -> Self {
        self.model = Some(model.into());
        self
    }

    /// Set the default per-request timeout.
    #[must_use]
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    /// Set the default retry policy.
    #[must_use]
    pub fn retry(mut self, retry: RetryPolicy) -> Self {
        self.retry = retry;
        self
    }

    /// Add a default header. Protected headers are ignored at build time.
    #[must_use]
    pub fn header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.push((name.into(), value.into()));
        self
    }

    /// Build a client that shares one connection pool across [`Clone`]s.
    ///
    /// # Errors
    ///
    /// Returns an error when the API key is missing, the timeout or retry
    /// policy is invalid, the base URL cannot be parsed, or a header is invalid.
    pub fn build(self) -> Result<TypeSafeClient> {
        let Settings {
            api_key,
            base_url,
            model,
            timeout,
        } = config::resolve_settings(
            self.api_key,
            self.base_url,
            self.model,
            self.timeout,
            &config::process_env,
        )?;
        self.retry.validate()?;
        let (base_headers, protected) = transport::static_headers(&api_key, &self.headers)?;
        // The API is on the internet. Only a local mock, which the base URL
        // check allows to use plain HTTP, may be reached on this machine.
        let local_mock = config::is_loopback_base(&base_url);
        let destinations = if local_mock {
            Destinations::PublicPrivateAndLoopback
        } else {
            Destinations::Public
        };
        let http = HttpClient::builder(transport::USER_AGENT_VALUE)
            .destinations(destinations)
            .https_only(!local_mock)
            .max_redirects(0)
            .timeout(timeout)
            .default_headers(base_headers.clone())
            .build()
            .map_err(|error| Error::client(format!("failed to build HTTP client: {error}")))?;
        Ok(TypeSafeClient {
            inner: Arc::new(Inner {
                http,
                base_headers,
                protected,
                base_url,
                model,
                timeout,
                retry: self.retry,
            }),
        })
    }
}

struct Inner {
    http: HttpClient,
    base_headers: header::HeaderMap,
    protected: header::HeaderMap,
    base_url: String,
    model: String,
    timeout: Duration,
    retry: RetryPolicy,
}

/// Async client for the `TypeSafe` AI API.
///
/// Cloning is cheap. Clones share the HTTP connection pool, including HTTP/2
/// connections negotiated by rustls.
#[derive(Clone)]
pub struct TypeSafeClient {
    inner: Arc<Inner>,
}

impl std::fmt::Debug for TypeSafeClient {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("TypeSafeClient")
            .field("base_url", &self.inner.base_url)
            .field("model", &self.inner.model)
            .field("timeout", &self.inner.timeout)
            .finish_non_exhaustive()
    }
}

impl TypeSafeClient {
    /// Start a builder.
    #[must_use]
    pub fn builder() -> ClientBuilder {
        ClientBuilder::new()
    }

    /// Configured API root, without a trailing slash.
    #[must_use]
    pub fn base_url(&self) -> &str {
        &self.inner.base_url
    }

    /// Default model.
    #[must_use]
    pub fn model(&self) -> &str {
        &self.inner.model
    }

    /// Accessor for `GET /v1/models`.
    #[must_use]
    pub fn models(&self) -> Models<'_> {
        Models { client: self }
    }

    /// Answer `questions` about `state` with the client defaults.
    ///
    /// # Errors
    ///
    /// Returns an error when questions fail validation, the server returns a
    /// non-success status, the response body does not match the system-one
    /// shape, or the request times out or cannot connect.
    pub async fn system_one(
        &self,
        state: &JsonContent<'_>,
        questions: &Questions<'_>,
    ) -> Result<SystemOneResponse> {
        let overrides = CallOverrides::default();
        self.system_one_with(state, questions, &overrides).await
    }

    /// [`Self::system_one`] with per-call overrides.
    ///
    /// # Errors
    ///
    /// See [`Self::system_one`]. An override with a zero timeout or an invalid
    /// retry policy also fails before the request is sent.
    pub async fn system_one_with(
        &self,
        state: &JsonContent<'_>,
        questions: &Questions<'_>,
        overrides: &CallOverrides<'_>,
    ) -> Result<SystemOneResponse> {
        let success = self.post_system_one(state, questions, overrides).await?;
        response::parse_system_one(
            success.status,
            success.body,
            success.request_id,
            &success.endpoint,
        )
    }

    /// Decode a system-one response into `T` instead of [`SystemOneResponse`].
    ///
    /// Unknown answer types are not filtered on this path. `T` must accept the
    /// JSON the server returns.
    ///
    /// # Errors
    ///
    /// See [`Self::system_one`]. A body that does not match `T` is an
    /// [`ApiErrorKind::InvalidResponse`](crate::ApiErrorKind::InvalidResponse).
    pub async fn system_one_into<T: DeserializeOwned>(
        &self,
        state: &JsonContent<'_>,
        questions: &Questions<'_>,
    ) -> Result<T> {
        let overrides = CallOverrides::default();
        self.system_one_into_with(state, questions, &overrides)
            .await
    }

    /// [`Self::system_one_into`] with per-call overrides.
    ///
    /// # Errors
    ///
    /// See [`Self::system_one_into`].
    pub async fn system_one_into_with<T: DeserializeOwned>(
        &self,
        state: &JsonContent<'_>,
        questions: &Questions<'_>,
        overrides: &CallOverrides<'_>,
    ) -> Result<T> {
        let success = self.post_system_one(state, questions, overrides).await?;
        response::parse_json(&success.body).map_err(|path| {
            Error::Api(Box::new(crate::error::invalid_response(
                success.status,
                &success.body,
                success.request_id.clone(),
                &success.endpoint,
                &path,
            )))
        })
    }

    async fn post_system_one(
        &self,
        state: &JsonContent<'_>,
        questions: &Questions<'_>,
        overrides: &CallOverrides<'_>,
    ) -> Result<transport::Success> {
        let timeout = self.timeout_of(overrides)?;
        let model = overrides.model.unwrap_or(self.inner.model.as_str());
        let body = questions::encode_system_one(state, model, questions, overrides.extra_body)?;
        let policy = overrides.retry.as_ref().unwrap_or(&self.inner.retry);
        transport::execute(
            &self.http_state(),
            RequestParts {
                method: Method::POST,
                path: transport::SYSTEM_ONE_PATH,
                body: Some(body),
                timeout,
                extra_headers: &overrides.headers,
            },
            policy,
        )
        .await
    }

    fn timeout_of(&self, overrides: &CallOverrides<'_>) -> Result<Duration> {
        let timeout = overrides.timeout.unwrap_or(self.inner.timeout);
        if timeout.is_zero() {
            return Err(Error::client(
                "timeout must be a positive, finite number of seconds.",
            ));
        }
        Ok(timeout)
    }

    fn http_state(&self) -> HttpState<'_> {
        HttpState {
            http: &self.inner.http,
            base_url: &self.inner.base_url,
            base_headers: &self.inner.base_headers,
            protected: &self.inner.protected,
        }
    }
}

/// `GET /v1/models`, reached through [`TypeSafeClient::models`].
pub struct Models<'a> {
    client: &'a TypeSafeClient,
}

impl Models<'_> {
    /// List the models available to the account.
    ///
    /// # Errors
    ///
    /// Returns an error when the server responds unsuccessfully, the body is
    /// not a model list, or the request times out or cannot connect.
    pub async fn list(&self) -> Result<ListModelsResponse> {
        let overrides = CallOverrides::default();
        self.list_with(&overrides).await
    }

    /// [`Self::list`] with per-call timeout, retry, and header overrides.
    ///
    /// `model` and `extra_body` are ignored.
    ///
    /// # Errors
    ///
    /// See [`Self::list`].
    pub async fn list_with(&self, overrides: &CallOverrides<'_>) -> Result<ListModelsResponse> {
        let timeout = self.client.timeout_of(overrides)?;
        let policy = overrides.retry.as_ref().unwrap_or(&self.client.inner.retry);
        let success = transport::execute(
            &self.client.http_state(),
            RequestParts {
                method: Method::GET,
                path: transport::MODELS_PATH,
                body: None,
                timeout,
                extra_headers: &overrides.headers,
            },
            policy,
        )
        .await?;
        response::parse_models(
            success.status,
            success.body,
            success.request_id,
            &success.endpoint,
        )
    }
}

#[cfg(test)]
mod debug_tests {
    use super::ClientBuilder;

    #[test]
    fn debug_output_leaves_out_the_api_key_and_header_values() {
        let builder = ClientBuilder::new()
            .api_key("sk-secret-key")
            .header("X-Org-Token", "org-secret");
        let shown = format!("{builder:?}");
        assert!(!shown.contains("sk-secret-key"), "{shown}");
        assert!(!shown.contains("org-secret"), "{shown}");
        assert!(shown.contains("X-Org-Token"), "{shown}");
    }
}
