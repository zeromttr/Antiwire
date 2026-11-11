//! The hardened client and its builder.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use reqwest::header::HeaderMap;
use reqwest::{Method, Url};

use crate::destination::Destinations;
use crate::error::HttpError;
use crate::resolver::PolicyResolver;

const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);
const DEFAULT_MAX_REDIRECTS: usize = 5;

/// What a client's requests and redirects must satisfy.
#[derive(Debug, Clone, Copy)]
struct UrlRules {
    destinations: Destinations,
    https_only: bool,
}

impl UrlRules {
    /// Checks the parts of a URL the resolver never sees: its scheme, and a
    /// host that is an IP address, which is connected to without a DNS lookup.
    fn check(self, url: &Url) -> Result<(), String> {
        match url.scheme() {
            "https" => {}
            "http" if !self.https_only => {}
            "http" => return Err("plain HTTP is not allowed; use HTTPS".to_owned()),
            other => return Err(format!("unsupported scheme {other}")),
        }
        let host = url
            .host_str()
            .ok_or_else(|| "the URL has no host".to_owned())?;
        let literal = host.trim_start_matches('[').trim_end_matches(']');
        if let Ok(ip) = literal.parse::<IpAddr>() {
            if !self.destinations.allows(ip) {
                return Err(format!("{ip} is not an address this client may reach"));
            }
        }
        Ok(())
    }
}

/// Builder for [`HttpClient`] and [`BlockingHttpClient`].
///
/// Every client it builds refuses link-local and cloud metadata addresses, uses
/// TLS 1.2 or later, ignores proxy settings (a proxy would resolve names where
/// the destination policy cannot see them), never downgrades from HTTPS to
/// HTTP on a redirect, checks every redirect hop like the first request, and
/// sends no `Referer`, so a redirect target does not learn the URL, query
/// tokens included, that pointed to it.
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

    /// Headers sent with every request.
    pub fn default_headers(mut self, headers: HeaderMap) -> Self {
        self.default_headers = headers;
        self
    }

    fn rules(&self) -> UrlRules {
        UrlRules {
            destinations: self.destinations,
            https_only: self.https_only,
        }
    }

    fn redirect_policy(&self) -> reqwest::redirect::Policy {
        if self.max_redirects == 0 {
            return reqwest::redirect::Policy::none();
        }
        let max_redirects = self.max_redirects;
        let rules = self.rules();
        reqwest::redirect::Policy::custom(move |attempt| {
            if attempt.previous().len() > max_redirects {
                return attempt.error(format!("more than {max_redirects} redirects"));
            }
            let downgrade = attempt.url().scheme() == "http"
                && attempt
                    .previous()
                    .iter()
                    .any(|previous| previous.scheme() == "https");
            if downgrade {
                return attempt.error("redirect from HTTPS to HTTP refused");
            }
            if let Err(reason) = rules.check(attempt.url()) {
                return attempt.error(format!("redirect refused: {reason}"));
            }
            attempt.follow()
        })
    }

    /// Builds an async client.
    ///
    /// # Errors
    ///
    /// Returns an error when the TLS backend or the headers cannot be set up.
    pub fn build(self) -> Result<HttpClient, HttpError> {
        let inner = reqwest::Client::builder()
            .user_agent(self.user_agent.clone())
            .default_headers(self.default_headers.clone())
            .redirect(self.redirect_policy())
            .referer(false)
            .dns_resolver(Arc::new(PolicyResolver::new(self.destinations)))
            .https_only(self.https_only)
            .min_tls_version(reqwest::tls::Version::TLS_1_2)
            .no_proxy()
            .connect_timeout(self.connect_timeout)
            .timeout(self.timeout)
            .build()?;
        Ok(HttpClient {
            inner,
            rules: self.rules(),
        })
    }

    /// Builds a blocking client, for code that runs on its own thread.
    ///
    /// # Errors
    ///
    /// Returns an error when the TLS backend or the headers cannot be set up.
    #[cfg(feature = "blocking")]
    pub fn build_blocking(self) -> Result<BlockingHttpClient, HttpError> {
        let inner = reqwest::blocking::Client::builder()
            .user_agent(self.user_agent.clone())
            .default_headers(self.default_headers.clone())
            .redirect(self.redirect_policy())
            .referer(false)
            .dns_resolver(Arc::new(PolicyResolver::new(self.destinations)))
            .https_only(self.https_only)
            .min_tls_version(reqwest::tls::Version::TLS_1_2)
            .no_proxy()
            .connect_timeout(self.connect_timeout)
            .timeout(self.timeout)
            .build()?;
        Ok(BlockingHttpClient {
            inner,
            rules: self.rules(),
        })
    }
}

/// An async HTTP client that only reaches the destinations it was built for.
///
/// Requests are started through [`Self::get`] or [`Self::request`], which
/// refuse a URL the client's rules do not allow before anything is sent.
/// Cloning is cheap and shares the connection pool.
#[derive(Debug, Clone)]
pub struct HttpClient {
    inner: reqwest::Client,
    rules: UrlRules,
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
    pub fn get(&self, url: &str) -> Result<reqwest::RequestBuilder, HttpError> {
        self.request(Method::GET, parse(url)?)
    }

    /// Starts a request with any method.
    ///
    /// # Errors
    ///
    /// Returns [`HttpError::Refused`] when the URL is not allowed.
    pub fn request(&self, method: Method, url: Url) -> Result<reqwest::RequestBuilder, HttpError> {
        self.rules
            .check(&url)
            .map_err(|reason| HttpError::refused(&url, reason))?;
        Ok(self.inner.request(method, url))
    }
}

/// A blocking HTTP client that only reaches the destinations it was built for.
///
/// The blocking counterpart of [`HttpClient`], with the same checks. It must not
/// be used from inside an async runtime.
#[cfg(feature = "blocking")]
#[derive(Debug, Clone)]
pub struct BlockingHttpClient {
    inner: reqwest::blocking::Client,
    rules: UrlRules,
}

#[cfg(feature = "blocking")]
impl BlockingHttpClient {
    /// Starts a POST request.
    ///
    /// # Errors
    ///
    /// Returns [`HttpError::Refused`] when the URL is invalid or not allowed.
    pub fn post(&self, url: &str) -> Result<reqwest::blocking::RequestBuilder, HttpError> {
        let url = parse(url)?;
        self.rules
            .check(&url)
            .map_err(|reason| HttpError::refused(&url, reason))?;
        Ok(self.inner.post(url))
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
            "http://[::1]/",
            "http://[::ffff:127.0.0.1]/",
            "http://[fe80::1]/",
        ] {
            assert!(public.check(&url(refused)).is_err(), "{refused}");
        }
        assert!(public.check(&url("http://93.184.216.34/")).is_ok());

        let lan = rules(Destinations::PublicAndPrivate, false);
        assert!(lan.check(&url("http://192.168.1.20/hosts")).is_ok());
        assert!(lan.check(&url("http://127.0.0.1/")).is_err());
        assert!(lan.check(&url("http://169.254.169.254/")).is_err());
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
