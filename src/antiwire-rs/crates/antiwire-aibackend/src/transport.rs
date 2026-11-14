//! HTTP request preparation, secret-header redaction, and the retry loop.

use antiwire_http::reqwest;
use std::time::{Duration, Instant};

use bytes::Bytes;
use reqwest::header::{
    HeaderMap, HeaderName, HeaderValue, ACCEPT, AUTHORIZATION, CONTENT_TYPE, USER_AGENT,
};

use crate::error::{self, Error};
use crate::retry::RetryPolicy;

pub(crate) const SYSTEM_ONE_PATH: &str = "/v1/systemone";
pub(crate) const MODELS_PATH: &str = "/v1/models";

pub(crate) const USER_AGENT_VALUE: &str = concat!("antiwire-aibackend/", env!("CARGO_PKG_VERSION"));

/// Far above any classification or model listing. A larger answer is refused
/// rather than buffered.
const MAX_RESPONSE_BYTES: u64 = 16 * 1024 * 1024;

pub(crate) struct HttpState<'a> {
    pub(crate) http: &'a antiwire_http::HttpClient,
    pub(crate) base_url: &'a str,
    pub(crate) base_headers: &'a HeaderMap,
    pub(crate) protected: &'a HeaderMap,
}

pub(crate) struct RequestParts<'a> {
    pub(crate) method: reqwest::Method,
    pub(crate) path: &'a str,
    pub(crate) body: Option<Vec<u8>>,
    pub(crate) timeout: Duration,
    pub(crate) extra_headers: &'a [(String, String)],
}

pub(crate) struct Success {
    pub(crate) status: u16,
    pub(crate) body: Bytes,
    pub(crate) request_id: Option<String>,
    pub(crate) endpoint: String,
}

pub(crate) fn static_headers(
    api_key: &str,
    user_headers: &[(String, String)],
) -> Result<(HeaderMap, HeaderMap), Error> {
    let mut protected = HeaderMap::new();
    let user_agent = HeaderValue::from_static(USER_AGENT_VALUE);
    protected.insert(AUTHORIZATION, bearer(api_key)?);
    protected.insert(ACCEPT, HeaderValue::from_static("application/json"));
    protected.insert(USER_AGENT, user_agent.clone());
    protected.insert(HeaderName::from_static("x-typesafe-sdk"), user_agent);
    protected.insert(
        HeaderName::from_static("x-typesafe-runtime"),
        HeaderValue::from_str(&runtime_header())
            .map_err(|_| Error::client("invalid runtime header"))?,
    );

    let mut base = HeaderMap::new();
    for (name, value) in user_headers {
        if is_protected_name(name) || is_retry_count_name(name) {
            continue;
        }
        insert_header(&mut base, name, value)?;
    }
    // Protected names are applied last so caller defaults cannot replace them.
    overlay(&mut base, &protected);
    Ok((base, protected))
}

pub(crate) async fn execute(
    state: &HttpState<'_>,
    request: RequestParts<'_>,
    policy: &RetryPolicy,
) -> Result<Success, Error> {
    policy.validate()?;
    let url = join_url(state.base_url, request.path)?;
    let endpoint = endpoint_of(&request.method, &url);
    let started = Instant::now();
    let mut attempt = 0u32;
    loop {
        match send_once(state, &request, &url, &endpoint, attempt).await {
            Ok(success) => return Ok(success),
            Err(error) => {
                if !policy.is_retryable(&error) || attempt >= policy.max_retries {
                    return Err(error);
                }
                let delay = policy.delay_after(&error, attempt.saturating_add(1));
                if policy.budget_exhausted(started.elapsed(), delay) {
                    return Err(error);
                }
                tokio::time::sleep(delay).await;
                attempt = attempt.saturating_add(1);
            }
        }
    }
}

async fn send_once(
    state: &HttpState<'_>,
    request: &RequestParts<'_>,
    url: &reqwest::Url,
    endpoint: &str,
    attempt: u32,
) -> Result<Success, Error> {
    if attempt > 0 {
        tracing::info!(
            method = %request.method,
            %url,
            retry = attempt,
            "retrying request"
        );
    }
    let headers = request_headers(
        state.base_headers,
        state.protected,
        request.extra_headers,
        attempt,
        request.body.is_some(),
    )?;
    log_wire(
        &request.method,
        url,
        &headers,
        request.body.as_deref().unwrap_or_default(),
        "http request",
    );
    let attempt_started = Instant::now();
    let mut builder = state
        .http
        .request(request.method.clone(), url.clone())
        .map_err(|error| Error::client(error.to_string()))?
        .headers(headers.clone())
        .timeout(request.timeout);
    if let Some(body) = &request.body {
        builder = builder.body(body.clone());
    }
    let response = builder
        .send()
        .await
        .map_err(|error| map_transport(&error, request.timeout))?;
    let status = response.status().as_u16();
    let response_headers = response.headers().clone();
    let body = antiwire_http::read_limited(response, MAX_RESPONSE_BYTES)
        .await
        .map_err(|error| match error {
            antiwire_http::HttpError::Request(error) => map_transport(&error, request.timeout),
            other => Error::Connection {
                message: other.to_string(),
            },
        })?;
    let request_id = error::header_text(&response_headers, "x-typesafe-request-id");
    let elapsed_ms = u64::try_from(attempt_started.elapsed().as_millis()).unwrap_or(u64::MAX);
    tracing::info!(
        method = %request.method,
        %url,
        status,
        elapsed_ms,
        request_id = request_id.as_deref().unwrap_or("-"),
        "received response"
    );
    log_wire(
        &request.method,
        url,
        &response_headers,
        &body,
        "http response",
    );
    if !(200..300).contains(&status) {
        return Err(Error::Api(Box::new(error::http_error(
            status,
            &body,
            &response_headers,
            endpoint,
        ))));
    }
    Ok(Success {
        status,
        body,
        request_id,
        endpoint: endpoint.to_owned(),
    })
}

fn request_headers(
    base: &HeaderMap,
    protected: &HeaderMap,
    extra: &[(String, String)],
    attempt: u32,
    has_body: bool,
) -> Result<HeaderMap, Error> {
    let mut headers = base.clone();
    for (name, value) in extra {
        if is_protected_name(name) || is_retry_count_name(name) {
            continue;
        }
        insert_header(&mut headers, name, value)?;
    }
    if attempt > 0 {
        insert_header(&mut headers, "x-typesafe-retry-count", &attempt.to_string())?;
    } else {
        headers.remove(HeaderName::from_static("x-typesafe-retry-count"));
    }
    if has_body {
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    }
    // Re-stamp protected headers. reqwest would otherwise let a per-call header replace a client default.
    overlay(&mut headers, protected);
    Ok(headers)
}

fn overlay(destination: &mut HeaderMap, source: &HeaderMap) {
    for (name, value) in source {
        destination.insert(name.clone(), value.clone());
    }
}

fn bearer(api_key: &str) -> Result<HeaderValue, Error> {
    HeaderValue::from_str(&format!("Bearer {api_key}")).map_err(|_| {
        Error::client(
            "API key contains characters that are not allowed in an Authorization header.",
        )
    })
}

fn insert_header(headers: &mut HeaderMap, name: &str, value: &str) -> Result<(), Error> {
    let name = HeaderName::from_bytes(name.as_bytes())
        .map_err(|_| Error::client(format!("invalid header name: {name}")))?;
    let value = HeaderValue::from_str(value)
        .map_err(|_| Error::client(format!("invalid header value for {name}")))?;
    headers.insert(name, value);
    Ok(())
}

fn is_protected_name(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "authorization"
            | "proxy-authorization"
            | "accept"
            | "user-agent"
            | "x-typesafe-sdk"
            | "x-typesafe-runtime"
    )
}

fn is_retry_count_name(name: &str) -> bool {
    name.eq_ignore_ascii_case("x-typesafe-retry-count")
}

fn runtime_header() -> String {
    format!(
        "rust ({}; {})",
        std::env::consts::OS,
        std::env::consts::ARCH
    )
}

fn join_url(base: &str, path: &str) -> Result<reqwest::Url, Error> {
    reqwest::Url::parse(&format!("{base}{path}"))
        .map_err(|_| Error::client(format!("invalid request URL for {base}{path}")))
}

pub(crate) fn endpoint_of(method: &reqwest::Method, url: &reqwest::Url) -> String {
    let mut clean = url.clone();
    clean.set_query(None);
    clean.set_fragment(None);
    let _ = clean.set_password(None);
    let _ = clean.set_username("");
    format!("{method} {clean}")
}

fn map_transport(error: &reqwest::Error, timeout: Duration) -> Error {
    if error.is_timeout() {
        Error::Timeout {
            seconds: timeout.as_secs_f64(),
        }
    } else {
        Error::Connection {
            message: error.to_string(),
        }
    }
}

fn log_wire(
    method: &reqwest::Method,
    url: &reqwest::Url,
    headers: &HeaderMap,
    body: &[u8],
    message: &'static str,
) {
    if tracing::enabled!(tracing::Level::DEBUG) {
        tracing::debug!(
            %method,
            %url,
            headers = %redact_headers(headers),
            body = %String::from_utf8_lossy(body),
            direction = message,
            "http wire"
        );
    }
}

pub(crate) fn redact_headers(headers: &HeaderMap) -> String {
    let mut parts = Vec::new();
    for (name, value) in headers {
        let shown = if is_secret(name.as_str()) {
            "***"
        } else {
            value.to_str().unwrap_or("***")
        };
        parts.push(format!("{name}={shown}"));
    }
    parts.join(", ")
}

fn is_secret(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    matches!(
        lower.as_str(),
        "authorization" | "proxy-authorization" | "x-api-key" | "api-key" | "cookie" | "set-cookie"
    ) || lower.contains("token")
        || lower.contains("secret")
}

#[cfg(test)]
mod tests {
    use super::{endpoint_of, redact_headers, static_headers};
    use antiwire_http::reqwest;
    use reqwest::header::{HeaderMap, HeaderValue, AUTHORIZATION};

    #[test]
    fn redacts_secret_headers_only() {
        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, HeaderValue::from_static("Bearer secret-key"));
        headers.insert("x-team", HeaderValue::from_static("call"));
        headers.insert("x-api-key", HeaderValue::from_static("k"));
        headers.insert("x-access-token", HeaderValue::from_static("session-value"));
        headers.insert("set-cookie", HeaderValue::from_static("sid=1"));
        let redacted = redact_headers(&headers);
        assert!(!redacted.contains("secret-key"));
        assert!(!redacted.contains("session-value"));
        assert!(!redacted.contains("sid=1"));
        assert!(redacted.contains("authorization=***"));
        assert!(redacted.contains("x-team=call"));
        assert!(redacted.contains("x-api-key=***"));
        assert!(redacted.contains("x-access-token=***"));
        assert!(redacted.contains("set-cookie=***"));
    }

    #[test]
    fn caller_cannot_override_protected_headers() {
        let (base, protected) = static_headers(
            "test-key",
            &[
                ("Authorization".to_owned(), "injected".to_owned()),
                ("X-Team".to_owned(), "default".to_owned()),
                ("X-TypeSafe-Retry-Count".to_owned(), "99".to_owned()),
            ],
        )
        .expect("headers");
        assert_eq!(
            base.get(AUTHORIZATION)
                .and_then(|value| value.to_str().ok()),
            Some("Bearer test-key")
        );
        assert_eq!(
            base.get("x-team").and_then(|value| value.to_str().ok()),
            Some("default")
        );
        assert!(base.get("x-typesafe-retry-count").is_none());
        assert_eq!(
            protected
                .get("x-typesafe-sdk")
                .and_then(|value| value.to_str().ok()),
            Some(concat!("antiwire-aibackend/", env!("CARGO_PKG_VERSION")))
        );
        let runtime = protected
            .get("x-typesafe-runtime")
            .and_then(|value| value.to_str().ok())
            .expect("runtime");
        assert!(runtime.starts_with("rust ("));
    }

    #[test]
    fn endpoint_drops_userinfo_query_and_fragment() {
        let url = reqwest::Url::parse(
            "https://user:password@example.test/v1/models?token=secret#fragment",
        )
        .expect("url");
        assert_eq!(
            endpoint_of(&reqwest::Method::GET, &url),
            "GET https://example.test/v1/models"
        );
    }
}
