//! Callback surface for persisting DNS-layer blocks outside the DNS crate.

use netmetrics::Ownership;

/// Receives blocked-query notifications after policy evaluation.
pub trait DnsBlockSink: Send + Sync {
    /// `pid` is zero when the querying process could not be resolved.
    /// `blocklist_names` are catalog ids that matched; empty for DNS rules
    /// and the fail-closed boot window.
    fn record_blocked_query(&self, domain: &str, pid: u32, blocklist_names: &[String]);

    /// Detailed record carrying the event timestamp and the full
    /// [`Ownership`]. This is the method the resolver calls.
    ///
    /// The default forwards only a pid to [`Self::record_blocked_query`]:
    /// `Resolved(pid)` becomes `pid`, while `Ambiguous` and `NotFound` both
    /// collapse to `0`, and the timestamp is dropped. A sink that needs either
    /// must override this method.
    fn record_blocked_query_with_ownership(
        &self,
        domain: &str,
        ownership: Ownership,
        blocklist_names: &[String],
        _timestamp: Option<time::OffsetDateTime>,
    ) {
        self.record_blocked_query(
            domain,
            ownership.resolved_pid().unwrap_or(0),
            blocklist_names,
        );
    }

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
