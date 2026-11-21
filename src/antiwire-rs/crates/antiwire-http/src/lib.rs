//! The one HTTP client the daemon uses for outbound requests.
//!
//! The daemon runs privileged, and several of its requests go to URLs that come
//! from settings or from other servers' answers: custom blocklists, the SIEM
//! webhook, RDAP referrals, redirects. Every client built here enforces the same
//! rules, so a URL cannot be used to reach something on this machine or the
//! local network that the request was never meant for:
//!
//! - **Destinations.** Every address a request connects to, whether from DNS or
//!   an IP-address URL, on the first request and on every redirect, must be
//!   allowed by the client's [`Destinations`] policy. Link-local addresses,
//!   cloud metadata endpoints (including Azure `WireServer`), local-use NAT64
//!   (`64:ff9b:1::/48`), and non-global IPv6 space outside `2000::/3` are
//!   always refused. Redirects only narrow the active destination zone, so a
//!   public host cannot pivot into private or loopback addresses.
//! - **Transport.** TLS 1.2 or later, no proxies, no HTTPS-to-HTTP redirects,
//!   bounded redirects, no `Referer`, strict cross-origin header allowlisting,
//!   and no cross-origin `307`/`308` body replay.
//! - **Time.** Connect and overall timeouts on every client, shared across
//!   redirect hops.
//! - **Size.** [`read_limited`] and [`read_text_limited`] cap response bodies
//!   without trusting the server.
//! - **Secrets.** [`HttpError`] reduces URLs to `scheme://host[:port]` and
//!   strips unredacted URLs from underlying transport errors.

mod body;
mod client;
mod destination;
mod error;
mod redirect;
mod resolver;

pub use body::{read_limited, read_text_limited};
#[cfg(feature = "blocking")]
pub use client::{BlockingHttpClient, BlockingRequestBuilder, BlockingResponse};
pub use client::{HttpClient, HttpClientBuilder, HttpRequestBuilder, HttpResponse};
pub use destination::Destinations;
pub use error::HttpError;
pub use reqwest::{header, Method, StatusCode, Url};
