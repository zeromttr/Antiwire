//! URL validation and hop-by-hop redirect enforcement.
//!
//! Redirects are handled inside `antiwire-http` rather than by `reqwest` so
//! every hop enforces:
//! - monotonic destination narrowing (`Public` cannot pivot to `Private` or
//!   `Loopback`, and `Private` cannot pivot to `Loopback`);
//! - HTTPS non-downgrade (`https` -> `http` is refused even when `https_only`
//!   is `false`);
//! - strict cross-origin header allowlisting (only `Accept`,
//!   `Accept-Encoding`, and `Accept-Language` cross an origin boundary, so
//!   `Authorization`, cookies, and custom auth headers never leak);
//! - no cross-origin `307`/`308` request body replay;
//! - no `Referer` header.

use std::net::IpAddr;

use bytes::Bytes;
use reqwest::header::{self, HeaderMap, HeaderName};
use reqwest::{Method, StatusCode, Url};

use crate::destination::{classify, AddressClass, Destinations};
use crate::error::HttpError;
use crate::resolver::is_refused_hostname;

/// Headers allowed to survive a cross-origin redirect. Everything else
/// (including `Authorization`, `Cookie`, `Referer`, and any custom API-key or
/// default headers) is stripped.
const CROSS_ORIGIN_SAFE_HEADERS: [HeaderName; 3] = [
    header::ACCEPT,
    header::ACCEPT_ENCODING,
    header::ACCEPT_LANGUAGE,
];

/// Body-framing headers removed whenever a `301`/`302`/`303` redirect drops the
/// request body.
const BODY_HEADERS: [HeaderName; 4] = [
    header::CONTENT_LENGTH,
    header::CONTENT_TYPE,
    header::CONTENT_ENCODING,
    header::TRANSFER_ENCODING,
];

/// What a client's requests and redirects must satisfy before any socket is
/// opened.
#[derive(Debug, Clone, Copy)]
pub(crate) struct UrlRules {
    pub(crate) destinations: Destinations,
    pub(crate) https_only: bool,
}

impl UrlRules {
    /// Checks the parts of a URL the resolver never sees (scheme and literal IP
    /// host) and refuses local-only hostnames that the policy forbids before
    /// any DNS, mDNS, or LLMNR lookup is issued.
    pub(crate) fn check(self, url: &Url) -> Result<(), String> {
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
        } else if is_refused_hostname(host, self.destinations) {
            return Err(format!("{host} is not a host this client may reach"));
        }
        Ok(())
    }
}

/// Mutable state carried across redirect hops for a single logical request.
#[derive(Debug, Clone)]
pub(crate) struct RedirectState {
    pub(crate) method: Method,
    pub(crate) url: Url,
    pub(crate) headers: HeaderMap,
    pub(crate) body: Option<Bytes>,
    pub(crate) destinations: Destinations,
    pub(crate) https_only: bool,
    pub(crate) saw_https: bool,
    pub(crate) hops: usize,
    pub(crate) max_redirects: usize,
}

impl RedirectState {
    pub(crate) fn new(
        method: Method,
        url: Url,
        headers: HeaderMap,
        body: Option<Bytes>,
        destinations: Destinations,
        https_only: bool,
        max_redirects: usize,
    ) -> Self {
        let saw_https = url.scheme() == "https";
        Self {
            method,
            url,
            headers,
            body,
            destinations,
            https_only,
            saw_https,
            hops: 0,
            max_redirects,
        }
    }

    /// Inspects `status` and `response_headers`. Returns `Ok(false)` when this
    /// response is final, or updates `self` for the next hop and returns
    /// `Ok(true)`, enforcing destination narrowing, scheme non-downgrade,
    /// redirect limits, and cross-origin header/body stripping.
    pub(crate) fn advance(
        &mut self,
        status: StatusCode,
        response_headers: &HeaderMap,
        remote_ip: Option<IpAddr>,
    ) -> Result<bool, HttpError> {
        if self.max_redirects == 0 || !is_redirect_status(status) {
            return Ok(false);
        }
        let Some(raw_location) = response_headers.get(header::LOCATION) else {
            return Ok(false);
        };
        let location = raw_location.to_str().map_err(|_| {
            HttpError::refused(&self.url, "redirect Location header is not valid ASCII")
        })?;
        let next_url = self
            .url
            .join(location)
            .map_err(|error| HttpError::unparseable(&error))?;

        if self.hops >= self.max_redirects {
            return Err(HttpError::refused(
                &next_url,
                format!("more than {} redirects", self.max_redirects),
            ));
        }

        // Narrow destination scope based on the IP actually reached. If the
        // remote address is unavailable, fail closed to Public.
        let reached = remote_ip.map_or(AddressClass::Public, classify);
        let next_destinations = self.destinations.narrow(reached);

        let saw_https = self.saw_https || self.url.scheme() == "https";
        if saw_https && next_url.scheme() == "http" {
            return Err(HttpError::refused(
                &next_url,
                "redirect from HTTPS to HTTP refused",
            ));
        }

        let rules = UrlRules {
            destinations: next_destinations,
            https_only: self.https_only || saw_https,
        };
        if let Err(reason) = rules.check(&next_url) {
            return Err(HttpError::refused(
                &next_url,
                format!("redirect refused: {reason}"),
            ));
        }

        let same_origin = is_same_origin(&self.url, &next_url);
        let prev_method = std::mem::replace(&mut self.method, Method::GET);
        let prev_body = self.body.take();
        let (method, body, body_dropped) =
            next_method_and_body(status, prev_method, prev_body, same_origin, &next_url)?;
        let prev_headers = std::mem::take(&mut self.headers);
        let headers = filter_headers(prev_headers, same_origin, body_dropped);

        self.method = method;
        self.saw_https = saw_https || next_url.scheme() == "https";
        self.url = next_url;
        self.headers = headers;
        self.body = body;
        self.destinations = next_destinations;
        self.hops += 1;
        Ok(true)
    }
}

const fn is_redirect_status(status: StatusCode) -> bool {
    matches!(
        status,
        StatusCode::MOVED_PERMANENTLY
            | StatusCode::FOUND
            | StatusCode::SEE_OTHER
            | StatusCode::TEMPORARY_REDIRECT
            | StatusCode::PERMANENT_REDIRECT
    )
}

fn is_same_origin(current: &Url, next: &Url) -> bool {
    current.scheme() == next.scheme()
        && current.host_str() == next.host_str()
        && current.port_or_known_default() == next.port_or_known_default()
}

fn next_method_and_body(
    status: StatusCode,
    method: Method,
    body: Option<Bytes>,
    same_origin: bool,
    next_url: &Url,
) -> Result<(Method, Option<Bytes>, bool), HttpError> {
    match status {
        StatusCode::TEMPORARY_REDIRECT | StatusCode::PERMANENT_REDIRECT => {
            if !same_origin && body.is_some() {
                return Err(HttpError::refused(
                    next_url,
                    "cross-origin redirect with request body refused",
                ));
            }
            Ok((method, body, false))
        }
        _ => {
            let next_method = if method == Method::GET || method == Method::HEAD {
                method
            } else {
                Method::GET
            };
            let dropped = body.is_some() || next_method == Method::GET;
            Ok((next_method, None, dropped))
        }
    }
}

fn filter_headers(mut headers: HeaderMap, same_origin: bool, body_dropped: bool) -> HeaderMap {
    if !same_origin {
        let mut kept = HeaderMap::new();
        for name in &CROSS_ORIGIN_SAFE_HEADERS {
            for value in headers.get_all(name) {
                kept.append(name.clone(), value.clone());
            }
        }
        return kept;
    }
    headers.remove(header::REFERER);
    if body_dropped {
        for name in &BODY_HEADERS {
            headers.remove(name);
        }
    }
    headers
}

#[cfg(test)]
mod tests {
    use super::*;
    use reqwest::header::HeaderValue;

    fn url(text: &str) -> Url {
        Url::parse(text).expect("url")
    }

    fn location(target: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::LOCATION,
            HeaderValue::from_str(target).expect("loc"),
        );
        headers
    }

    #[test]
    fn public_hop_cannot_redirect_to_private_or_loopback() {
        let public_ip: IpAddr = "93.184.216.34".parse().expect("ip");
        for (policy, target) in [
            (Destinations::PublicAndPrivate, "http://192.168.1.1/admin"),
            (Destinations::PublicAndPrivate, "http://10.0.0.1/internal"),
            (Destinations::PublicAndPrivate, "http://nas.local/hosts"),
            (Destinations::PublicAndPrivate, "http://wpad/wpad.dat"),
            (
                Destinations::PublicPrivateAndLoopback,
                "http://127.0.0.1:50051/",
            ),
            (
                Destinations::PublicPrivateAndLoopback,
                "http://localhost:8080/",
            ),
        ] {
            let mut state = RedirectState::new(
                Method::GET,
                url("http://example.com/start"),
                HeaderMap::new(),
                None,
                policy,
                false,
                5,
            );
            let error = state
                .advance(StatusCode::FOUND, &location(target), Some(public_ip))
                .expect_err("cross-zone redirect must be refused");
            assert!(
                matches!(error, HttpError::Refused { .. }),
                "{target}: {error}"
            );
        }
    }

    #[test]
    fn private_hop_cannot_redirect_to_loopback_or_pivot_via_public() {
        let private_ip: IpAddr = "192.168.1.10".parse().expect("ip");
        let public_ip: IpAddr = "93.184.216.34".parse().expect("ip");

        // Private -> Loopback refused on PublicPrivateAndLoopback.
        let mut state = RedirectState::new(
            Method::GET,
            url("http://192.168.1.10/start"),
            HeaderMap::new(),
            None,
            Destinations::PublicPrivateAndLoopback,
            false,
            5,
        );
        let error = state
            .advance(
                StatusCode::FOUND,
                &location("http://127.0.0.1/"),
                Some(private_ip),
            )
            .expect_err("private -> loopback refused");
        assert!(matches!(error, HttpError::Refused { .. }), "{error}");

        // Private -> Public narrows to Public, so Public -> Private is refused.
        let mut state = RedirectState::new(
            Method::GET,
            url("http://192.168.1.10/start"),
            HeaderMap::new(),
            None,
            Destinations::PublicAndPrivate,
            false,
            5,
        );
        assert!(state
            .advance(
                StatusCode::FOUND,
                &location("https://cdn.example.com/list"),
                Some(private_ip),
            )
            .expect("private -> public allowed"));
        assert_eq!(state.destinations, Destinations::PublicAndPrivate);

        let error = state
            .advance(
                StatusCode::FOUND,
                &location("https://192.168.1.1/admin"),
                Some(public_ip),
            )
            .expect_err("public hop cannot pivot back to private");
        assert!(matches!(error, HttpError::Refused { .. }), "{error}");
    }

    #[test]
    fn https_to_http_downgrade_is_refused_even_after_http_upgrade() {
        let public_ip: IpAddr = "93.184.216.34".parse().expect("ip");
        let mut state = RedirectState::new(
            Method::GET,
            url("http://example.com/start"),
            HeaderMap::new(),
            None,
            Destinations::Public,
            false,
            5,
        );
        assert!(state
            .advance(
                StatusCode::FOUND,
                &location("https://example.com/secure"),
                Some(public_ip),
            )
            .expect("http -> https upgrade allowed"));
        let error = state
            .advance(
                StatusCode::FOUND,
                &location("http://example.com/downgrade"),
                Some(public_ip),
            )
            .expect_err("https -> http downgrade refused");
        assert!(matches!(error, HttpError::Refused { .. }), "{error}");
        assert!(error.to_string().contains("HTTPS to HTTP"), "{error}");
    }

    #[test]
    fn cross_origin_redirect_strips_custom_auth_headers_and_keeps_safe_ones() {
        let public_ip: IpAddr = "93.184.216.34".parse().expect("ip");
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer secret"),
        );
        headers.insert("x-api-key", HeaderValue::from_static("api-secret"));
        headers.insert(header::COOKIE, HeaderValue::from_static("sid=1"));
        headers.insert(header::ACCEPT, HeaderValue::from_static("application/json"));
        headers.insert(
            header::ACCEPT_ENCODING,
            HeaderValue::from_static("identity"),
        );

        let mut state = RedirectState::new(
            Method::GET,
            url("https://a.example.com/start"),
            headers,
            None,
            Destinations::Public,
            true,
            5,
        );
        assert!(state
            .advance(
                StatusCode::FOUND,
                &location("https://b.example.com/next"),
                Some(public_ip),
            )
            .expect("follow"));
        assert!(state.headers.get(header::AUTHORIZATION).is_none());
        assert!(state.headers.get("x-api-key").is_none());
        assert!(state.headers.get(header::COOKIE).is_none());
        assert_eq!(
            state
                .headers
                .get(header::ACCEPT)
                .and_then(|v| v.to_str().ok()),
            Some("application/json")
        );
        assert_eq!(
            state
                .headers
                .get(header::ACCEPT_ENCODING)
                .and_then(|v| v.to_str().ok()),
            Some("identity")
        );
    }

    #[test]
    fn cross_origin_307_with_body_is_refused() {
        let public_ip: IpAddr = "93.184.216.34".parse().expect("ip");
        let mut state = RedirectState::new(
            Method::POST,
            url("https://a.example.com/hook"),
            HeaderMap::new(),
            Some(Bytes::from_static(b"{\"secret\":true}")),
            Destinations::Public,
            true,
            5,
        );
        let error = state
            .advance(
                StatusCode::TEMPORARY_REDIRECT,
                &location("https://b.example.com/steal"),
                Some(public_ip),
            )
            .expect_err("cross-origin 307 with body refused");
        assert!(matches!(error, HttpError::Refused { .. }), "{error}");
    }
}
