//! Cross-platform, synchronous network flow telemetry.
//!
//! Native callbacks enqueue into a bounded channel and never call user code.
//! A single collector worker owns accounting state, coalesces byte deltas, and
//! publishes fixed-size batches.

mod active;
mod attribution;
mod collector;
mod config;
pub mod dns_divert;
pub mod endpoint_owner;
pub mod owner_cache;
mod sockets;

pub use active::{SocketCount, active_connection_count};
pub use attribution::{
    dns_event_flush_stats, event_clock_lag, owner_evidence_stats, request_dns_event_flush,
    take_owner_disagreements, tcp_pid_attribution_stats,
};
pub use collector::{Collector, CollectorStats, FlowConsumer};
pub use config::{CollectorBuilder, CollectorConfig};
pub use netmetrics_core::{
    ByteDelta, ClockLag, CookieSource, DegradeReason, DnsFlushStats, FlowEvent, FlowKey, FlowMeta,
    FlowRecord, FlowSnapshot, FlowState, InterfaceStats, LocalEndpoint, MetricsError,
    OwnerEvidenceStats, Ownership, ProcessIdentity, ProcessInfo, Protocol, SocketCookie,
    SocketOwnerSnapshot, TcpPidAttributionSample, canonicalize_ip, parse_dns_result_addresses,
    parse_dns_result_text,
};
pub use owner_cache::SocketOwnerCache;
pub use sockets::{socket_owner_snapshot, socket_owner_snapshot_for};
