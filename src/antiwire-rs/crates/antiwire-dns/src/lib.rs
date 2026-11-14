//! DNS resolver stub with policy-aware blocking and upstream caching.

pub(crate) mod ai;
pub(crate) mod ai_support;
mod answers;
mod block;
mod dns_name;
mod domain_key;
mod ede;
mod error;
mod interceptor;
mod lifecycle;
mod listener;
mod messages;
mod network_watch;
mod new_domain;
mod owner_worker;
mod policy_adapter;
mod port_mapper;
mod provider_block;
mod query_engine;
mod query_guard;
mod rebinding;
mod records;
mod response_cache;
mod service;
mod settings;
mod special_use;
mod tcp_server;
mod udp_server;
#[cfg(windows)]
mod udp_socket;
mod upstream;

#[cfg(feature = "bench-internals")]
#[doc(hidden)]
pub mod bench_support;

#[cfg(test)]
mod integration_tests;
#[cfg(test)]
mod test_support;

pub use ai::decision::canonical_ai_key;
pub use ai_support::{advanced_decision, apply_verdict_change, refreshed_decision};
pub use block::forget_cached_answers;
pub use block::DnsBlockSink;
pub use block::DnsHintSink;
pub use error::{DnsError, Result};
pub use interceptor::DnsInterceptor;
pub use lifecycle::{
    apply_dns_settings_change, attach_dns_hint_sink, bootstrap_dns_interceptor,
    shutdown_dns_interceptor, DnsDependencies, DnsInterceptorSlot,
};
pub use new_domain::{is_supported_new_domain_max_age, RegistrationDates, NEW_DOMAIN_MAX_AGE_DAYS};
pub use records::{
    find_domain, lookup_records, reverse_name, RecordAnswer, RecordLookup, RecordPurpose, RecordSet,
};
pub use settings::{check_upstream_settings, is_known_dns_protocol};

/// Removes a port-53 divert left behind by a process that did not shut down.
pub fn clear_port53_divert() {
    netmetrics::dns_divert::clear_leftover();
}

pub use upstream::{doh_block_targets, DOH_PORT};

#[cfg(test)]
pub(crate) use block::BlockResponseMode;
#[cfg(test)]
pub(crate) use listener::DnsListener;
#[cfg(test)]
pub(crate) use messages::encode_message;
#[cfg(test)]
pub(crate) use query_engine::QueryEngine;
#[cfg(test)]
pub(crate) use response_cache::{CacheKey, CacheProbe, ResponseCache};
#[cfg(test)]
pub(crate) use settings::{DnsConfig, DnsProtocol};
