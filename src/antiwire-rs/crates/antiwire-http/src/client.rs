//! The hardened client, its builder, and wrapped request/response types.

use std::fmt::Display;
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use futures_util::{Stream, StreamExt};
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use reqwest::{Method, StatusCode, Url};

use crate::destination::Destinations;
use crate::error::HttpError;
use crate::redirect::{RedirectState, UrlRules};
use crate::resolver::PolicyResolver;

const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);
const DEFAULT_MAX_REDIRECTS: usize = 5;

/// Policy and transport defaults shared by an [`HttpClient`] or
/// [`BlockingHttpClient`] across clones.
#[derive(Debug)]
struct ClientConfig {
    destinations: Destinations,
    https_only: bool,
    max_redirects: usize,
    timeout: Duration,
    default_headers: HeaderMap,
}

impl ClientConfig {
    const fn rules(&self) -> UrlRules {
        UrlRules {
            destinations: self.destinations,
            https_only: self.https_only,
        }
    }
}

/// Underlying `reqwest` clients indexed by how wide a destination policy they
/// permit.
///
/// Redirects only ever narrow the active policy (`PublicPrivateAndLoopback` ->
/// `PublicAndPrivate` -> `Public`), so a redirect-following client keeps
/// narrower clients ready for post-redirect DNS resolution and isolates their
/// connection pools. When `max_redirects == 0` or the policy is already
/// `Public`, only one client is built.
#[derive(Debug, Clone)]
enum ZoneClients<C> {
    Single(C),
    PublicAndPrivate { public: C, private: C },
    All { public: C, private: C, loopback: C },
}

impl<C> ZoneClients<C> {
    fn build(
        destinations: Destinations,
        max_redirects: usize,
        mut build_one: impl FnMut(Destinations) -> Result<C, HttpError>,
    ) -> Result<Self, HttpError> {
        if max_redirects == 0 || destinations == Destinations::Public {
            return Ok(Self::Single(build_one(destinations)?));
        }
        match destinations {
            Destinations::Public => unreachable!("handled above"),
            Destinations::PublicAndPrivate => Ok(Self::PublicAndPrivate {
                public: build_one(Destinations::Public)?,
                private: build_one(Destinations::PublicAndPrivate)?,
            }),
            Destinations::PublicPrivateAndLoopback => Ok(Self::All {
                public: build_one(Destinations::Public)?,
                private: build_one(Destinations::PublicAndPrivate)?,
                loopback: build_one(Destinations::PublicPrivateAndLoopback)?,
            }),
        }
    }

    fn for_destinations(&self, destinations: Destinations) -> &C {
        match self {
            Self::Single(client) => client,
            Self::PublicAndPrivate { public, private } => match destinations {
                Destinations::Public => public,
                Destinations::PublicAndPrivate | Destinations::PublicPrivateAndLoopback => private,
            },
            Self::All {
                public,
                private,
                loopback,
            } => match destinations {
                Destinations::Public => public,
                Destinations::PublicAndPrivate => private,
                Destinations::PublicPrivateAndLoopback => loopback,
            },
        }
    }
}

/// Shared request fields accumulated by [`HttpRequestBuilder`] and
/// [`BlockingRequestBuilder`].
#[derive(Debug)]
struct RequestParts {
    method: Method,
    url: Url,
    headers: HeaderMap,
    body: Option<Bytes>,
    timeout: Option<Duration>,
    invalid_header: Option<String>,
}

impl RequestParts {
    fn new(method: Method, url: Url) -> Self {
        Self {
            method,
            url,
            headers: HeaderMap::new(),
            body: None,
            timeout: None,
            invalid_header: None,
        }
    }

    fn push_header<K, V>(&mut self, key: K, value: V)
    where
        K: TryInto<HeaderName>,
        K::Error: Display,
        V: TryInto<HeaderValue>,
        V::Error: Display,
    {
        if self.invalid_header.is_some() {
            return;
        }
        match (key.try_into(), value.try_into()) {
            (Ok(name), Ok(value)) => {
                self.headers.append(name, value);
            }
            (Err(error), _) => {
                self.invalid_header = Some(format!("invalid header name: {error}"));
            }
            (_, Err(error)) => {
                self.invalid_header = Some(format!("invalid header value: {error}"));
            }
        }
    }

    fn extend_headers(&mut self, headers: &HeaderMap) {
        for name in headers.keys() {
            self.headers.remove(name);
            for value in headers.get_all(name) {
                self.headers.append(name.clone(), value.clone());
            }
        }
    }

    fn append_query<K, V>(&mut self, pairs: &[(K, V)])
    where
        K: AsRef<str>,
        V: AsRef<str>,
    {
        self.url.query_pairs_mut().extend_pairs(pairs);
    }

    fn into_redirect_state(
        self,
        config: &ClientConfig,
    ) -> Result<(RedirectState, Duration), HttpError> {
        if let Some(reason) = self.invalid_header {
            return Err(HttpError::refused(&self.url, reason));
        }
        let headers = merge_default_headers(&config.default_headers, self.headers);
        let timeout = self.timeout.unwrap_or(config.timeout);
        let state = RedirectState::new(
            self.method,
            self.url,
            headers,
            self.body,
            config.destinations,
            config.https_only,
            config.max_redirects,
        );
        Ok((state, timeout))
    }
}

fn merge_default_headers(defaults: &HeaderMap, mut request: HeaderMap) -> HeaderMap {
    for name in defaults.keys() {
        if !request.contains_key(name) {
            for value in defaults.get_all(name) {
                request.append(name.clone(), value.clone());
            }
        }
    }
    request
}

fn remaining_timeout(
    deadline: Option<Instant>,
    fallback: Duration,
    url: &Url,
) -> Result<Duration, HttpError> {
    let Some(deadline) = deadline else {
        return Ok(fallback);
    };
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return Err(HttpError::timeout(url));
    }
    Ok(remaining)
}

/// Builder for [`HttpClient`] and [`BlockingHttpClient`].
///
/// Every client it builds refuses link-local and cloud metadata addresses, uses
/// TLS 1.2 or later, ignores proxy settings (a proxy would resolve names where
/// the destination policy cannot see them), never downgrades from HTTPS to
/// HTTP on a redirect, narrows destination scope monotonically across
/// redirects, strips non-safe headers and refuses `307`/`308` body replay
/// across origins, and sends no `Referer`.
#[derive(Debug, Clone)]
#[must_use]
pub struct HttpClientBuilder {
    user_agent: String,
    destinations: Destinations,
    https_only: bool,
    max_redirects: usize,
    connect_timeout: Duration,
    timeout: Duration,
    default_headers: HeaderMap,
}

impl HttpClientBuilder {
    /// Starts a builder for a client identifying itself as `user_agent`.
    ///
    /// Defaults: public destinations only, HTTPS only, at most five redirects,
    /// a 10 s connect timeout and a 30 s overall timeout.
    pub fn new(user_agent: impl Into<String>) -> Self {
        Self {
            user_agent: user_agent.into(),
            destinations: Destinations::Public,
            https_only: true,
            max_redirects: DEFAULT_MAX_REDIRECTS,
            connect_timeout: DEFAULT_CONNECT_TIMEOUT,
            timeout: DEFAULT_TIMEOUT,
            default_headers: HeaderMap::new(),
        }
    }

    /// Which addresses requests and redirects may reach.
    pub const fn destinations(mut self, destinations: Destinations) -> Self {
        self.destinations = destinations;
        self
    }

    /// Whether plain HTTP is refused. On by default.
    pub const fn https_only(mut self, https_only: bool) -> Self {
        self.https_only = https_only;
        self
    }

    /// The most redirects one request follows; `0` follows none.
    pub const fn max_redirects(mut self, max_redirects: usize) -> Self {
        self.max_redirects = max_redirects;
        self
    }

    /// Time allowed to establish a connection.
    pub const fn connect_timeout(mut self, timeout: Duration) -> Self {
        self.connect_timeout = timeout;
        self
    }

    /// Deadline for a whole request, from sending it to reading the last byte.
    pub const fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Headers sent with the initial request (and same-origin redirects).
    ///
    /// Stripped on cross-origin redirects unless in the safe content-negotiation
    /// allowlist (`Accept`, `Accept-Encoding`, `Accept-Language`).
    pub fn default_headers(mut self, headers: HeaderMap) -> Self {
        self.default_headers = headers;
        self
    }

    fn build_config(&self) -> Arc<ClientConfig> {
        Arc::new(ClientConfig {
            destinations: self.destinations,
            https_only: self.https_only,
            max_redirects: self.max_redirects,
            timeout: self.timeout,
            default_headers: self.default_headers.clone(),
        })
    }

    /// Builds an async client.
    ///
    /// # Errors
    ///
    /// Returns an error when the TLS backend or the headers cannot be set up.
    pub fn build(self) -> Result<HttpClient, HttpError> {
        let config = self.build_config();
        let clients = ZoneClients::build(self.destinations, self.max_redirects, |zone| {
            reqwest::Client::builder()
                .user_agent(self.user_agent.clone())
                .redirect(reqwest::redirect::Policy::none())
                .referer(false)
                .dns_resolver(Arc::new(PolicyResolver::new(zone)))
                .https_only(self.https_only)
                .min_tls_version(reqwest::tls::Version::TLS_1_2)
                .no_proxy()
                .connect_timeout(self.connect_timeout)
                .timeout(self.timeout)
                .build()
                .map_err(|error| HttpError::from_reqwest(error, None))
        })?;
        Ok(HttpClient { clients, config })
    }

    /// Builds a blocking client, for code that runs on its own thread.
    ///
    /// # Errors
    ///
    /// Returns an error when the TLS backend or the headers cannot be set up.
    #[cfg(feature = "blocking")]
    pub fn build_blocking(self) -> Result<BlockingHttpClient, HttpError> {
        let config = self.build_config();
        let clients = ZoneClients::build(self.destinations, self.max_redirects, |zone| {
            reqwest::blocking::Client::builder()
                .user_agent(self.user_agent.clone())
                .redirect(reqwest::redirect::Policy::none())
                .referer(false)
                .dns_resolver(Arc::new(PolicyResolver::new(zone)))
                .https_only(self.https_only)
                .min_tls_version(reqwest::tls::Version::TLS_1_2)
                .no_proxy()
                .connect_timeout(self.connect_timeout)
                .timeout(self.timeout)
                .build()
                .map_err(|error| HttpError::from_reqwest(error, None))
        })?;
        Ok(BlockingHttpClient { clients, config })
    }
}

/// An async HTTP client that only reaches the destinations it was built for.
///
/// Requests are started through [`Self::get`] or [`Self::request`], which
/// refuse a URL the client's rules do not allow before anything is sent.
/// Cloning is cheap and shares the connection pool.
#[derive(Debug, Clone)]
pub struct HttpClient {
    clients: ZoneClients<reqwest::Client>,
    config: Arc<ClientConfig>,
}

impl HttpClient {
    /// Starts a builder for a client identifying itself as `user_agent`.
    pub fn builder(user_agent: impl Into<String>) -> HttpClientBuilder {
        HttpClientBuilder::new(user_agent)
    }

    /// Starts a GET request.
    ///
    /// # Errors
    ///
    /// Returns [`HttpError::Refused`] when the URL is invalid or not allowed.
    pub fn get(&self, url: &str) -> Result<HttpRequestBuilder, HttpError> {
        self.request(Method::GET, parse(url)?)
    }

    /// Starts a request with any method.
    ///
    /// # Errors
    ///
    /// Returns [`HttpError::Refused`] when the URL is not allowed.
    pub fn request(&self, method: Method, url: Url) -> Result<HttpRequestBuilder, HttpError> {
        self.config
            .rules()
            .check(&url)
            .map_err(|reason| HttpError::refused(&url, reason))?;
        Ok(HttpRequestBuilder {
            client: self.clone(),
            parts: RequestParts::new(method, url),
        })
    }
}

/// Builder for a single async request created by [`HttpClient`].
#[derive(Debug)]
#[must_use]
pub struct HttpRequestBuilder {
    client: HttpClient,
    parts: RequestParts,
}

impl HttpRequestBuilder {
    /// Adds a header to the request.
    pub fn header<K, V>(mut self, key: K, value: V) -> Self
    where
        K: TryInto<HeaderName>,
        K::Error: Display,
        V: TryInto<HeaderValue>,
        V::Error: Display,
    {
        self.parts.push_header(key, value);
        self
    }

    /// Adds every header from `headers` to the request.
    pub fn headers(mut self, headers: &HeaderMap) -> Self {
        self.parts.extend_headers(headers);
        self
    }

    /// Appends query key-value pairs to the request URL.
    pub fn query<K, V>(mut self, pairs: &[(K, V)]) -> Self
    where
        K: AsRef<str>,
        V: AsRef<str>,
    {
        self.parts.append_query(pairs);
        self
    }

    /// Sets the request body.
    pub fn body(mut self, body: impl Into<Bytes>) -> Self {
        self.parts.body = Some(body.into());
        self
    }

    /// Overrides the overall timeout for this request.
    pub const fn timeout(mut self, timeout: Duration) -> Self {
        self.parts.timeout = Some(timeout);
        self
    }

    /// Sends the request, following allowed redirects within the deadline.
    ///
    /// # Errors
    ///
    /// Returns [`HttpError::Refused`] when a header, resolved address, or
    /// redirect violates policy, [`HttpError::Timeout`] when the deadline
    /// expires, or [`HttpError::Request`] on transport failure.
    pub async fn send(self) -> Result<HttpResponse, HttpError> {
        let (mut state, timeout) = self.parts.into_redirect_state(&self.client.config)?;
        let deadline = Instant::now().checked_add(timeout);
        loop {
            let remaining = remaining_timeout(deadline, timeout, &state.url)?;
            let inner = self.client.clients.for_destinations(state.destinations);
            let mut req = inner
                .request(state.method.clone(), state.url.clone())
                .headers(state.headers.clone())
                .timeout(remaining);
            if let Some(body) = &state.body {
                req = req.body(body.clone());
            }
            let response = req
                .send()
                .await
                .map_err(|error| HttpError::from_reqwest(error, Some(&state.url)))?;
            let remote_ip = response.remote_addr().map(|address| address.ip());
            if !state.advance(response.status(), response.headers(), remote_ip)? {
                return Ok(HttpResponse { inner: response });
            }
        }
    }
}

/// An async HTTP response returned by [`HttpRequestBuilder::send`].
///
/// Unbounded `bytes()` / `text()` / `json()` helpers are deliberately omitted:
/// read bodies via [`crate::read_limited`], [`crate::read_text_limited`],
/// [`Self::chunk`], or [`Self::bytes_stream`].
#[derive(Debug)]
pub struct HttpResponse {
    inner: reqwest::Response,
}

impl HttpResponse {
    /// The HTTP status code.
    #[must_use]
    pub fn status(&self) -> StatusCode {
        self.inner.status()
    }

    /// The response headers.
    #[must_use]
    pub fn headers(&self) -> &HeaderMap {
        self.inner.headers()
    }

    /// The declared `Content-Length`, if known and not stripped by gzip
    /// decoding.
    #[must_use]
    pub fn content_length(&self) -> Option<u64> {
        self.inner.content_length()
    }

    /// Turns a 4xx/5xx response into a redacted [`HttpError::Request`].
    ///
    /// # Errors
    ///
    /// Returns [`HttpError::Request`] when the status is a client or server
    /// error.
    pub fn error_for_status(self) -> Result<Self, HttpError> {
        let url = self.inner.url().clone();
        self.inner
            .error_for_status()
            .map(|inner| Self { inner })
            .map_err(|error| HttpError::from_reqwest(error, Some(&url)))
    }

    /// Streams the next chunk of the response body.
    ///
    /// # Errors
    ///
    /// Returns [`HttpError::Request`] when reading or decoding the body fails.
    pub async fn chunk(&mut self) -> Result<Option<Bytes>, HttpError> {
        let url = self.inner.url().clone();
        self.inner
            .chunk()
            .await
            .map_err(|error| HttpError::from_reqwest(error, Some(&url)))
    }

    /// Converts the response body into a stream of chunks with redacted errors.
    pub fn bytes_stream(self) -> impl Stream<Item = Result<Bytes, HttpError>> + Send + 'static {
        let url = self.inner.url().clone();
        self.inner
            .bytes_stream()
            .map(move |chunk| chunk.map_err(|error| HttpError::from_reqwest(error, Some(&url))))
    }
}

/// A blocking HTTP client that only reaches the destinations it was built for.
///
/// The blocking counterpart of [`HttpClient`], with the same checks. It must not
/// be used from inside an async runtime.
#[cfg(feature = "blocking")]
#[derive(Debug, Clone)]
pub struct BlockingHttpClient {
    clients: ZoneClients<reqwest::blocking::Client>,
    config: Arc<ClientConfig>,
}

#[cfg(feature = "blocking")]
impl BlockingHttpClient {
    /// Starts a POST request.
    ///
    /// # Errors
    ///
    /// Returns [`HttpError::Refused`] when the URL is invalid or not allowed.
    pub fn post(&self, url: &str) -> Result<BlockingRequestBuilder, HttpError> {
        let url = parse(url)?;
        self.config
            .rules()
            .check(&url)
            .map_err(|reason| HttpError::refused(&url, reason))?;
        Ok(BlockingRequestBuilder {
            client: self.clone(),
            parts: RequestParts::new(Method::POST, url),
        })
    }
}

/// Builder for a single blocking request created by [`BlockingHttpClient`].
#[cfg(feature = "blocking")]
#[derive(Debug)]
#[must_use]
pub struct BlockingRequestBuilder {
    client: BlockingHttpClient,
    parts: RequestParts,
}

#[cfg(feature = "blocking")]
impl BlockingRequestBuilder {
    /// Adds a header to the request.
    pub fn header<K, V>(mut self, key: K, value: V) -> Self
    where
        K: TryInto<HeaderName>,
        K::Error: Display,
        V: TryInto<HeaderValue>,
        V::Error: Display,
    {
        self.parts.push_header(key, value);
        self
    }

    /// Sets the request body.
    pub fn body(mut self, body: impl Into<Bytes>) -> Self {
        self.parts.body = Some(body.into());
        self
    }

    /// Sends the request, following allowed redirects within the deadline.
    ///
    /// # Errors
    ///
    /// Returns [`HttpError::Refused`] when a header, resolved address, or
    /// redirect violates policy, [`HttpError::Timeout`] when the deadline
    /// expires, or [`HttpError::Request`] on transport failure.
    pub fn send(self) -> Result<BlockingResponse, HttpError> {
        let (mut state, timeout) = self.parts.into_redirect_state(&self.client.config)?;
        let deadline = Instant::now().checked_add(timeout);
        loop {
            let remaining = remaining_timeout(deadline, timeout, &state.url)?;
            let inner = self.client.clients.for_destinations(state.destinations);
            let mut req = inner
                .request(state.method.clone(), state.url.clone())
                .headers(state.headers.clone())
                .timeout(remaining);
            if let Some(body) = &state.body {
                req = req.body(body.clone());
            }
            let response = req
                .send()
                .map_err(|error| HttpError::from_reqwest(error, Some(&state.url)))?;
            let remote_ip = response.remote_addr().map(|address| address.ip());
            if !state.advance(response.status(), response.headers(), remote_ip)? {
                return Ok(BlockingResponse { inner: response });
            }
        }
    }
}

/// A blocking HTTP response returned by [`BlockingRequestBuilder::send`].
#[cfg(feature = "blocking")]
#[derive(Debug)]
pub struct BlockingResponse {
    inner: reqwest::blocking::Response,
}

#[cfg(feature = "blocking")]
impl BlockingResponse {
    /// The HTTP status code.
    #[must_use]
    pub fn status(&self) -> StatusCode {
        self.inner.status()
    }
}

fn parse(url: &str) -> Result<Url, HttpError> {
    Url::parse(url).map_err(|error| HttpError::unparseable(&error))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rules(destinations: Destinations, https_only: bool) -> UrlRules {
        UrlRules {
            destinations,
            https_only,
        }
    }

    fn url(text: &str) -> Url {
        Url::parse(text).expect("url")
    }

    #[test]
    fn https_only_refuses_plain_http() {
        let strict = rules(Destinations::Public, true);
        assert!(strict.check(&url("https://example.com/list.txt")).is_ok());
        assert!(strict.check(&url("http://example.com/list.txt")).is_err());
        assert!(strict.check(&url("ftp://example.com/list.txt")).is_err());
        assert!(rules(Destinations::Public, false)
            .check(&url("http://example.com/list.txt"))
            .is_ok());
    }

    /// An IP-address host is connected to without a DNS lookup, so the resolver
    /// never sees it; the URL check has to.
    #[test]
    fn literal_addresses_are_checked_against_the_policy() {
        let public = rules(Destinations::Public, false);
        for refused in [
            "http://127.0.0.1/",
            "http://10.0.0.1/",
            "http://169.254.169.254/latest/meta-data/",
            "http://168.63.129.16/machine/?comp=goalstate",
            "http://[::1]/",
            "http://[::ffff:127.0.0.1]/",
            "http://[fe80::1]/",
            "http://[64:ff9b:1::7f:0:100:0]/",
            "http://[64:ff9b:1:a9fe:a9:fe00:808:808]/",
            "http://[2001:0:a9fe:a9fe::f7f7:f7f7]/",
            "http://[5f00::1]/",
        ] {
            assert!(public.check(&url(refused)).is_err(), "{refused}");
        }
        assert!(public.check(&url("http://93.184.216.34/")).is_ok());

        let lan = rules(Destinations::PublicAndPrivate, false);
        assert!(lan.check(&url("http://192.168.1.20/hosts")).is_ok());
        assert!(lan.check(&url("http://127.0.0.1/")).is_err());
        assert!(lan.check(&url("http://169.254.169.254/")).is_err());
        assert!(lan.check(&url("http://168.63.129.16/")).is_err());
        assert!(lan.check(&url("http://[64:ff9b:1::7f:0:100:0]/")).is_err());
        assert!(lan.check(&url("http://[fd20:ce::254]/")).is_err());
    }

    /// URL parsing turns every spelling of an IPv4 address into the dotted form
    /// the check sees, so none of these slip through as a hostname.
    #[test]
    fn unusual_spellings_of_loopback_are_still_loopback() {
        let public = rules(Destinations::Public, false);
        for spelling in [
            "http://2130706433/",
            "http://0177.0.0.1/",
            "http://0x7f.0.0.1/",
            "http://0x7f000001/",
            "http://127.1/",
            "http://[::ffff:7f00:1]/",
            "http://[0:0:0:0:0:ffff:127.0.0.1]/",
        ] {
            assert!(public.check(&url(spelling)).is_err(), "{spelling}");
        }
    }

    #[test]
    fn local_only_hostnames_are_refused_before_lookup() {
        let public = rules(Destinations::Public, false);
        for refused in [
            "http://localhost/",
            "http://api.localhost/",
            "http://wpad/wpad.dat",
            "http://printer.local/",
        ] {
            assert!(public.check(&url(refused)).is_err(), "{refused}");
        }
        assert!(public.check(&url("http://example.com/")).is_ok());

        let lan = rules(Destinations::PublicAndPrivate, false);
        assert!(lan.check(&url("http://localhost/")).is_err());
        assert!(lan.check(&url("http://pihole.local/hosts")).is_ok());
        assert!(lan.check(&url("http://pihole/hosts")).is_ok());
    }

    #[test]
    fn requests_are_refused_before_anything_is_sent() {
        let client = HttpClient::builder("antiwire-test")
            .build()
            .expect("client");
        let error = client
            .get("http://169.254.169.254/latest/meta-data/")
            .expect_err("refused");
        assert!(matches!(error, HttpError::Refused { .. }), "{error}");
        assert!(client.get("not a url").is_err());
    }
}
