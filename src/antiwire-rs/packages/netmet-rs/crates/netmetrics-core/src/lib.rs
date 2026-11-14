//! Platform-independent state and event types for `netmetrics`.
//!
//! The core contains no OS APIs, async runtime, or packet-capture dependency.

mod clock_lag;
mod coalescer;
mod dns;
mod dns_caller;
mod dns_divert;
mod dns_parse;
mod dns_stream;
mod dns_transaction;
/// Native endpoint ownership history shared by all backends.
#[doc(hidden)]
pub mod endpoint_owner;
mod error;
mod etw_names;
#[doc(hidden)]
#[allow(missing_docs)]
pub mod expiring_map;
mod flow;
mod ip_cache;
mod ip_packet;
mod process;
mod socket;
mod tcp_state;
#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub mod test_support;
mod time;
mod types;

pub use clock_lag::{ClockLag, ClockLagGauge};
pub use coalescer::IngressCoalescer;
pub use dns::{
    DnsHint, DnsHintAt, DnsHintMap, DnsHintProvenance, NearestHint, ResolvedDnsHint,
    normalize_dns_name,
};

pub use dns_caller::{
    DnsCallerObservation, DnsCallerRecovery, DnsCallerRecoveryStats, DnsCallerResolution,
    DnsEventKind,
};
pub use dns_divert::{
    DivertEvent, DivertReport, LINUX_NFT_PATHS, MACOS_DNS_DIVERT_ANCHOR, MacosPfctlCommand,
    linux_dns_divert_disable_args, linux_dns_divert_install_args, linux_dns_divert_list_args,
    linux_dns_divert_ruleset, macos_dns_divert_rules,
};
pub use dns_parse::{
    canonicalize_ip, ip_aliases, parse_dns_result_addresses, parse_dns_result_addresses_with_ttl,
    parse_dns_result_text,
};
#[doc(hidden)]
pub use dns_stream::DnsStreamReassembler;
#[doc(hidden)]
pub use dns_transaction::{
    CorrelatedDnsResponse, DnsMessageObservation, DnsPacket, DnsTransactionTracker,
    parse_dns_packet,
};
pub use error::MetricsError;
pub use etw_names::{ETW_LOGGER_LIMIT, ETW_LOGGER_PREFIX, EtwLoggerNames, has_owned_prefix};
#[doc(hidden)]
pub use flow::FlowSnapshotSeed;
pub use flow::{FlowTable, FlowTableStats, UpsertOutcome};
pub use ip_cache::IpCache;
#[doc(hidden)]
pub use ip_packet::{IpTransport, locate_transport};
pub use process::{ProcessTable, StopOutcome};
pub use socket::{
    EndpointOwner, LocalEndpoint, Ownership, SocketCount, SocketOwnerSnapshot, unspecified_address,
};
pub use tcp_state::TcpState;
pub use time::unix_now_ms;
pub use types::{
    ByteDelta, CookieSource, DegradeReason, DnsCallerIdentity, DnsCorrelationId, DnsFlushStats,
    DnsQueryEvent, DnsResolutionAttribution, FlowEvent, FlowKey, FlowMeta, FlowRecord,
    FlowSnapshot, FlowState, InterfaceStats, OwnerDisagreement, OwnerEvidenceStats,
    ProcessIdentity, ProcessInfo, Protocol, SocketCookie, TcpPidAttributionSample,
};
