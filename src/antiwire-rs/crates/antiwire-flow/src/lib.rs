//! Bridges netmetrics flow events into batched connection-log writes.
//!
//! The crate covers the collection-side half of the daemon's traffic audit:
//!
//! - [`NetmetBridge`] and [`FlowTracker`] consume netmetrics flow events and
//!   aggregate byte deltas into batched `connection_logs` writes.
//! - [`FlowProcessor`] enriches each flow with policy verdicts, geo/ISP data,
//!   DNS names, and SIEM/notification fan-out.
//! - [`DnsQueryCorrelator`] and [`DnsBlockRecorder`] match blocked DNS queries
//!   back to the requesting process using ETW DNS-Client evidence.
//! - [`AppIdResolver`] maps PIDs to executable identities, including processes
//!   that pre-date the collector once [`FlowTracker::bootstrap_running_processes`]
//!   has run.

mod active_connections;
mod app_resolver;
mod bridge;
mod correlator;
mod dns_block_recorder;
mod domain_stats;
mod error;
mod port_pid_cache;
mod process_resolver;
mod processor;
mod sanitize;
mod store;
mod system_services;
mod timestamps;
mod tracker;

#[cfg(test)]
mod test_support;

#[cfg(test)]
mod unicode_display_tests;

pub use active_connections::TrackerActiveConnectionCounter;
pub use app_resolver::{AppIdResolver, AppRuleRetargeter};
pub use bridge::NetmetBridge;
pub use correlator::DnsQueryCorrelator;
pub use dns_block_recorder::DnsBlockRecorder;
pub use error::{FlowError, Result};
pub use process_resolver::BootstrapStats;
pub use processor::FlowProcessor;
pub use store::{DomainStore, FlowStore, StoreFlowAdapter};
pub use system_services::SystemAttributionStats;
pub use tracker::{ActiveApplication, FlowTracker};
