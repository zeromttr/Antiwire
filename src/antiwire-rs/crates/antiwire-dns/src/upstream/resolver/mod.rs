//! Upstream resolver construction and the failover handle.
//!
//! Configured endpoints are grouped into transport tiers in their configured
//! order: a port-853 primary and the `DoH` fallback appended to it are two
//! tiers, while a plain `DoH` list is one. Each tier is a single Hickory
//! `NameServerPool`, which races its servers and orders them by observed
//! round-trip time. [`exchange`] tries the tiers in order, [`tier`] tracks
//! which of them are down, [`endpoint`] parses the configuration, and
//! [`error_kind`] labels transport failures for logs.

mod endpoint;
mod error_kind;
mod exchange;
mod runtime;
#[cfg(test)]
mod tests;
mod tier;
mod tls;

use std::net::IpAddr;
use std::sync::atomic::AtomicU64;
use std::sync::Arc;

use hickory_proto::op::DnsRequestOptions;
use hickory_resolver::config::ResolverOpts;
use hickory_resolver::PoolContext;
use tracing::{info, warn};

use antiwire_tuning::{DNS_TRANSPORT_RETRY_ATTEMPTS, DNS_TRANSPORT_TIMEOUT};

use crate::settings::DnsProtocol;
use crate::Result;

use self::endpoint::{collect_upstream_endpoints, UpstreamEndpoint};
use self::runtime::UpstreamRuntime;
use self::tier::Tier;

pub(crate) use self::exchange::UpstreamAnswer;
#[cfg(test)]
pub(crate) use self::tier::RecoveryHold;

/// Servers a tier's pool queries in parallel for each request; the first
/// answer wins. Two covers the paired endpoints every multi-endpoint provider
/// publishes, and replaces a delayed hedge with no delay at all.
const CONCURRENT_REQUESTS_PER_TIER: usize = 2;

/// Hickory 0.26's exchange request queue holds 32 messages. TCP/TLS also
/// limit active requests to 32; HTTP/2 uses its own stream limits. Bound work
/// before either queue can return `Busy`, which the pool can lose as
/// `NoConnections` (also used for genuine connection failures).
const MAX_IN_FLIGHT_PER_TIER: usize = 32;

/// Hickory transport options for the upstream pools.
#[must_use]
pub(crate) fn resolver_opts_from_tuning() -> ResolverOpts {
    let mut opts = ResolverOpts::default();
    // Hickory applies `timeout` to UDP receive, TCP/TLS connect, and every
    // request wait, including DoH, DoQ, and H3 since 0.26.2. HTTPS/QUIC
    // connection setup uses Hickory's own connect timeout, not this value.
    opts.timeout = DNS_TRANSPORT_TIMEOUT;
    // `RetryDnsHandle::new(handle, attempts)` stores `attempts` as remaining
    // retries after the initial send. `1` therefore permits two ordinary
    // sends. `Busy` does not decrement the counter. UDP may still retransmit
    // inside one attempt at Hickory's 333ms floor until `timeout` fires.
    opts.attempts = DNS_TRANSPORT_RETRY_ATTEMPTS;
    opts.num_concurrent_reqs = CONCURRENT_REQUESTS_PER_TIER;
    opts.max_active_requests = MAX_IN_FLIGHT_PER_TIER;
    opts
}

fn request_options_from_resolver_opts(opts: &ResolverOpts) -> DnsRequestOptions {
    let mut request_opts = DnsRequestOptions::default();
    request_opts.recursion_desired = opts.recursion_desired;
    request_opts.use_edns = opts.edns0;
    request_opts.case_randomization = opts.case_randomization;
    request_opts
}

/// Upstream exchange handle: the configured tiers, tried in order.
pub(crate) struct UpstreamDns {
    tiers: Vec<Arc<Tier>>,
    protocol: &'static str,
    next_exchange_id: AtomicU64,
    config_warnings: Vec<String>,
}

impl UpstreamDns {
    /// True when every tier is down, so an exchange cannot be attempted and a
    /// stale answer should be served at once.
    #[must_use]
    pub(crate) fn endpoints_degraded(&self) -> bool {
        self.tiers.iter().all(|tier| tier.health.is_down())
    }

    /// True when an exchange started now would fail at once: every tier is
    /// down and none can start a recovery attempt. A snapshot; a recovery
    /// slot that frees a moment later goes to the next query.
    #[must_use]
    pub(crate) fn fails_fast(&self) -> bool {
        self.tiers.iter().all(|tier| tier.health.skips_now())
    }

    /// True when the tier an exchange started now would wait on first has
    /// failed since it last answered. When every tier is skipped an exchange
    /// waits on none of them, which is [`Self::fails_fast`] instead.
    #[must_use]
    pub(crate) fn failing(&self) -> bool {
        self.tiers
            .iter()
            .find(|tier| !tier.health.skips_now())
            .is_some_and(|tier| tier.health.has_failed())
    }

    /// Parse failures for configured upstreams that were skipped because at
    /// least one other endpoint remained dialable. Empty in the normal case.
    #[must_use]
    pub(crate) fn config_warnings(&self) -> &[String] {
        &self.config_warnings
    }

    /// Test hook: mark every tier down so degraded-mode paths can be exercised
    /// without real network failures. The next exchange may recover a tier.
    #[cfg(test)]
    pub(crate) fn mark_all_endpoints_failed(&self) {
        for tier in &self.tiers {
            tier.health.force_down();
        }
    }

    /// Test hook: claim every tier's recovery attempt, as a query recovering
    /// the upstreams would.
    #[cfg(test)]
    pub(crate) fn hold_recovery_for_test(&self) -> Option<RecoveryHold> {
        RecoveryHold::claim_all(&self.tiers)
    }

    #[cfg(test)]
    pub(crate) fn recovery_occupied_for_test(&self) -> bool {
        self.tiers.iter().all(|tier| tier.health.is_recovering())
    }
}

/// Checks that `upstreams` give [`build_upstream_dns`] at least one endpoint it
/// can dial, without building anything.
pub(crate) fn check_upstream_endpoints(protocol: DnsProtocol, upstreams: &[String]) -> Result<()> {
    collect_upstream_endpoints(protocol, upstreams).map(|_| ())
}

/// The addresses [`build_upstream_dns`] would dial for `upstreams`.
pub(crate) fn dialled_addresses(protocol: DnsProtocol, upstreams: &[String]) -> Vec<IpAddr> {
    collect_upstream_endpoints(protocol, upstreams)
        .map(|(endpoints, _)| {
            endpoints
                .iter()
                .map(|endpoint| endpoint.socket_addr.ip())
                .collect()
        })
        .unwrap_or_default()
}

/// Builds an upstream exchange handle with failover across configured endpoints.
pub(crate) fn build_upstream_dns(
    protocol: DnsProtocol,
    upstreams: &[String],
) -> Result<UpstreamDns> {
    let (configured, config_warnings) = collect_upstream_endpoints(protocol, upstreams)?;
    let groups: Vec<&[UpstreamEndpoint]> = configured
        .chunk_by(|left, right| left.protocol == right.protocol)
        .collect();
    build_from_tiers(protocol, &groups, config_warnings)
}

/// Builds the handle from endpoint groups that are already split into tiers.
fn build_from_tiers(
    protocol: DnsProtocol,
    groups: &[&[UpstreamEndpoint]],
    config_warnings: Vec<String>,
) -> Result<UpstreamDns> {
    let opts = resolver_opts_from_tuning();
    let request_options = request_options_from_resolver_opts(&opts);
    let retry_attempts = opts.attempts;
    // Nothing in the context is mutated at runtime — opportunistic encryption
    // stays disabled — so one context backs every tier. That also shares one
    // rustls `ClientConfig`, and with it one session-resumption cache.
    let pool_context = Arc::new(PoolContext::new(opts, tls::upstream_tls_config()?));
    let provider = UpstreamRuntime::new();
    let tiers: Vec<Arc<Tier>> = groups
        .iter()
        .map(|endpoints| {
            Arc::new(Tier::new(
                endpoints,
                &pool_context,
                &provider,
                retry_attempts,
                request_options,
            ))
        })
        .collect();

    let protocol_tag = transport_tag(protocol);
    for warning in &config_warnings {
        warn!(
            protocol = protocol_tag,
            detail = %warning,
            "configured dns upstream was skipped; the remaining endpoints will serve"
        );
    }
    info!(
        protocol = protocol_tag,
        tiers = ?tiers.iter().map(|tier| tier.label.as_ref()).collect::<Vec<_>>(),
        retry_attempts,
        "DNS upstream tiers configured"
    );

    Ok(UpstreamDns {
        tiers,
        protocol: protocol_tag,
        next_exchange_id: AtomicU64::new(1),
        config_warnings,
    })
}

/// Exact wire transport tag used in logs.
fn transport_tag(protocol: DnsProtocol) -> &'static str {
    match protocol {
        DnsProtocol::Https => "DoH",
        DnsProtocol::H3 => "H3",
        DnsProtocol::Quic => "DoQ",
        DnsProtocol::Tls => "DoT",
        DnsProtocol::Tcp => "TCP",
        DnsProtocol::Udp => "UDP",
    }
}

pub(super) fn resolve_error_msg(message: impl Into<String>) -> hickory_resolver::net::NetError {
    hickory_resolver::net::NetError::Msg(message.into())
}
