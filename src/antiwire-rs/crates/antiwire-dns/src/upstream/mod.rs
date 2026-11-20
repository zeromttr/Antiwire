//! Upstream resolver construction, provider tables, and admission.

mod admission;
mod doh_block;
mod providers;
mod resolver;

pub(crate) use admission::{AdmissionClass, SharedUpstreamAdmission, UpstreamAdmission};
pub use doh_block::{doh_block_targets, DOH_PORT};
#[cfg(any(test, feature = "bench-internals"))]
pub(crate) use providers::resolve_upstream_urls;
pub(crate) use providers::upstreams_for_settings;
pub(crate) use providers::{withhold_shape, WithholdShape};
#[cfg(test)]
pub(crate) use resolver::RecoveryHold;
pub(crate) use resolver::{
    build_upstream_dns, check_upstream_endpoints, dialled_addresses, UpstreamAnswer, UpstreamDns,
};

use hickory_proto::rr::rdata::opt::EdnsCode;
use hickory_resolver::net::NetError;

/// The lowercase host of a configured upstream: a URL, a bare host or IP
/// address, `host:port`, or a bracketed `[IPv6]:port`, each optionally
/// followed by a path as in `dns.example/dns-query`.
pub(crate) fn upstream_host(upstream: &str) -> Option<String> {
    let upstream = upstream.trim();
    let url;
    let host = if upstream.contains("://") {
        url = url::Url::parse(upstream).ok()?;
        url.host_str()?
    } else {
        let authority = upstream.split('/').next().unwrap_or(upstream);
        if let Some(rest) = authority.strip_prefix('[') {
            rest.split_once(']')?.0
        } else if authority.matches(':').count() == 1 {
            authority.split_once(':')?.0
        } else {
            authority
        }
    };
    // `url` keeps the brackets around an IPv6 host.
    let host = host.trim_start_matches('[').trim_end_matches(']');
    (!host.is_empty()).then(|| host.to_ascii_lowercase())
}

/// Whether a client's EDNS option goes upstream with its query.
///
/// Options about the client's own connection to this resolver stay here:
/// keepalive (RFC 7828; RFC 9250 forbids it on QUIC), padding, which each
/// transport adds for itself, and cookies, which RFC 7873 §5 ties to one
/// client-server pair. The client's subnet is not disclosed upstream. Options
/// this resolver does not recognise are dropped too, as it cannot tell what
/// they would reveal or change. A query whose options are all dropped asks
/// upstream the same thing as one without them, so it shares their cache.
pub(crate) fn forwards_edns_option(code: EdnsCode) -> bool {
    !matches!(
        code,
        EdnsCode::Keepalive
            | EdnsCode::Padding
            | EdnsCode::Cookie
            | EdnsCode::Subnet
            | EdnsCode::Unknown(_)
    )
}

/// Whether an option in an upstream answer describes the upstream's
/// connection to this resolver. Cached, it would reach every client.
pub(crate) fn is_upstream_transport_option(code: EdnsCode) -> bool {
    matches!(
        code,
        EdnsCode::Cookie | EdnsCode::Keepalive | EdnsCode::Padding
    )
}

/// No admission permit was free for the query.
const ADMISSION_DENIED: &str = "upstream admission denied";
/// This tier could not admit the query to its pooled connections in time.
const TIER_BUSY: &str = "upstream tier busy";
/// This tier went down while the query waited its turn on it.
const TIER_WENT_DOWN: &str = "upstream tier went down";
/// Every tier is down and its one recovery attempt is already running.
const EVERY_TIER_DOWN: &str = "every upstream tier is down";

/// True for errors raised before the query left this host.
///
/// They say nothing about the name, so they are not resolution failures in
/// the RFC 9520 §2 sense and must not hold the name.
pub(crate) fn query_never_sent(error: &NetError) -> bool {
    matches!(
        error,
        NetError::Msg(message)
            if [ADMISSION_DENIED, TIER_BUSY, TIER_WENT_DOWN, EVERY_TIER_DOWN]
                .contains(&message.as_str())
    )
}
