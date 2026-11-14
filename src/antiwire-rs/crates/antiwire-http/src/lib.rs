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
//!   which include every cloud metadata service, are always refused.
//! - **Transport.** TLS 1.2 or later, no proxies, no HTTPS-to-HTTP redirects,
//!   and a bounded number of redirects.
//! - **Time.** Connect and overall timeouts on every client.
//! - **Size.** [`read_limited`] and [`read_text_limited`] read a body with a
//!   cap, rather than trusting the server about its size.

mod body;
mod client;
mod destination;
mod error;
mod resolver;

pub use body::{read_limited, read_text_limited};
#[cfg(feature = "blocking")]
pub use client::BlockingHttpClient;
pub use client::{HttpClient, HttpClientBuilder};
pub use destination::Destinations;
pub use error::HttpError;

/// Re-exported so callers can name request and response types without their
/// own `reqwest` dependency drifting from this one.
pub use reqwest;
