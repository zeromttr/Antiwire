//! Callback surface for persisting DNS-layer blocks outside the DNS crate.

use netmetrics::Ownership;

/// Receives blocked-query notifications after policy evaluation.
pub trait DnsBlockSink: Send + Sync {
    /// Records a blocked query of `domain` made at `timestamp`.
    ///
    /// `ownership` is the owner of the client's socket. `blocklist_names` are
    /// the catalog ids that matched; empty for DNS rules and the fail-closed
    /// boot window.
    fn record_blocked_query(
        &self,
        domain: &str,
        ownership: Ownership,
        blocklist_names: &[String],
        timestamp: time::OffsetDateTime,
    );

    /// Applies daemon settings that affect block recording side effects.
    fn update_runtime_settings(
        &self,
        _log_daemon_connections: bool,
        _notify_threat_detected: bool,
    ) {
    }
}

/// Receives stub answers so flow accounting can name connections.
pub trait DnsHintSink: Send + Sync {
    /// An answer served to a client. `pid` is zero when the client socket has
    /// no owner. `ttl_ms` is how long the addresses should stay attributed to
    /// `query`, counted from `answered_at_ms`, the Unix epoch milliseconds at
    /// which the answer was served. The client can connect as soon as it has
    /// the answer, and this call can come some time later, once the client's
    /// owner has been found.
    fn record_hint(
        &self,
        pid: u32,
        query: &str,
        answers: &[std::net::IpAddr],
        ttl_ms: u64,
        answered_at_ms: u64,
    );

    /// A block answer's sinkhole addresses, recorded so a later connection to
    /// them is named after `query`. Unlike a hint, this attributes nothing to
    /// the querying process: every blocked name shares the same sinkhole.
    fn record_resolution(&self, query: &str, answers: &[std::net::IpAddr]);
}
