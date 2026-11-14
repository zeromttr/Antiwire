//! Centralized tuning parameters for daemon caches, timeouts, and queues.
//! Consolidated here for easy adjustment.

use std::time::Duration;

/// Exponential backoff: `base` before the first retry, doubling with each
/// one after it, never more than `cap`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Backoff {
    pub base: Duration,
    pub cap: Duration,
}

impl Backoff {
    #[must_use]
    pub const fn new(base: Duration, cap: Duration) -> Self {
        Self { base, cap }
    }

    /// The wait before retry `attempt`, counting from 1. Attempt 0 waits as
    /// long as attempt 1.
    #[must_use]
    pub fn delay(self, attempt: u32) -> Duration {
        let doublings = attempt.saturating_sub(1).min(31);
        self.base.saturating_mul(1 << doublings).min(self.cap)
    }

    /// The wait after one of `current`: twice as long, at most `cap`.
    #[must_use]
    pub fn after(self, current: Duration) -> Duration {
        current.saturating_mul(2).min(self.cap)
    }
}

// ---- ProcessResolver ----
mod process_resolver {
    pub const PROCESS_STOP_RETENTION_MS: u64 = 60 * 60_000;
    pub const PROCESS_SWEEP_EVERY_N_STOPS: i32 = 512;
    pub const PROCESS_SWEEP_WHEN_COUNT_EXCEEDS: i32 = 50_000;
    /// Successful PID lookups are retained this long (live and ETW-fed).
    pub const PROCESS_CACHE_TTL_MS: u64 = 60 * 60_000;
    /// Entries retained for successful PID lookups. Kept well above the active
    /// flow hard cap (`FLOW_ACTIVE_FLOWS_HARD_CAP`) so a busy host does not
    /// evict live flows' identities and fall back to repeated `OpenProcess` /
    /// `QueryFullProcessImageNameW` calls.
    pub const PROCESS_CACHE_CAP: u64 = 65_536;
    pub const PROCESS_DEVICE_MAP_REBUILD_MS: u64 = 60_000;
}

// ---- FlowTracker ----
mod flow_tracker {
    use super::Duration;

    pub const FLOW_EVENT_QUEUE_CAPACITY: usize = 8192;
    /// Recent closed records eligible for verified, same-instance path repair.
    pub const FLOW_CLOSED_IDENTITY_CAPACITY: usize = 4096;
    pub const FLOW_CLOSED_IDENTITY_RETENTION: Duration = Duration::from_secs(60);
    pub const FLOW_IDLE_TIMEOUT_MS: i64 = 30 * 60_000;
    pub const FLOW_ACTIVE_FLOWS_HARD_CAP: usize = 32_768;
    /// Cadence for persisting active-flow byte deltas to SQLite. This bounds how
    /// stale the records table's live byte counters can look, so it trades write
    /// rate for latency; 100 ms matches the write coalescing window below.
    pub const FLOW_FLUSH_INTERVAL: Duration = Duration::from_millis(100);
    pub const FLOW_MAINTENANCE_INTERVAL: Duration = Duration::from_secs(10);
    pub const FLOW_WRITE_BATCH_SIZE: i32 = 250;
    pub const FLOW_WRITE_COALESCE_WINDOW: Duration = Duration::from_millis(100);
    /// Consecutive store-flush failures tolerated before the collector is reported
    /// degraded to the UI. A single failure is usually a transient busy database.
    pub const FLOW_FLUSH_FAILURES_BEFORE_DEGRADED: u32 = 3;
    /// Ceiling on connection logs held in memory while the store is unwritable.
    ///
    /// A failing flush keeps its batch for the next attempt, so the backlog only
    /// grows. Shedding the newest records beats exhausting memory on a machine whose
    /// disk is already in trouble.
    pub const FLOW_PENDING_WRITE_HARD_CAP: usize = 50_000;
    /// Ceiling on queued re-attributions held in memory, for the same reason.
    pub const FLOW_PENDING_ATTRIBUTION_HARD_CAP: i32 = 10_000;
    /// Grace period before persisting unknown flows; socket tables are queried after this.
    pub const UNKNOWN_SOCKET_ATTRIBUTION_DELAY: Duration = Duration::from_secs(5);
}

// ---- Log retention: shared by the IPC service and LogRetentionScheduler.
// UNLIMITED_LOG_RETENTION_DAYS is the persisted sentinel meaning "keep forever". ----
mod log_retention {
    use super::Duration;

    pub const DEFAULT_LOG_RETENTION_DAYS: i32 = 30;
    pub const UNLIMITED_LOG_RETENTION_DAYS: i32 = 666;
    pub const LOG_RETENTION_PURGE_INTERVAL: Duration = Duration::from_secs(2 * 3600);
    /// Most rows one retention pass deletes from each table. A pass that
    /// removes fewer is the last one; the scheduler yields between passes so
    /// a large backlog never holds up shutdown.
    pub const LOG_RETENTION_PURGE_BATCH_SIZE: u32 = 1_000;
}

// ---- ConnectionLogQueryService ----
mod connection_log_query {
    pub const DEFAULT_LOG_PAGE_SIZE: i32 = 1000;
    pub const MAX_LOG_PAGE_SIZE: i32 = 50_000;
}

// ---- NotificationManager / TrafficStreamingHub subscriber queues ----
mod notification {
    pub const NOTIFICATION_QUEUE_CAPACITY: i32 = 512;
    pub const TRAFFIC_STREAM_QUEUE_CAPACITY: i32 = 4096;
}

// ---- DnsInterceptor ----
mod dns_interceptor {
    use super::Duration;

    pub const RECENT_BLOCK_SIGNALS_CAP: i32 = 100_000;
    pub const BLOCK_SIGNAL_THROTTLE_MS: i64 = 30_000;
    pub const DNS_BLOCK_SIGNAL_QUEUE_CAPACITY: i32 = 4096;
    // Desktop scale. A single machine's working set of names is small; the
    // byte cap is the operative bound because the response cache is weighed
    // in bytes, and the entry caps are advisory alongside it.
    pub const DNS_RESPONSE_CACHE_HARD_CAP: i32 = 4_096;
    pub const DNS_RESPONSE_CACHE_BYTE_CAP: i64 = 4 * 1024 * 1024;
    pub const DNS_RESPONSE_CACHE_MAX_ENTRY_BYTES: i32 = 16 * 1024;
    pub const DNS_DEFAULT_TTL_SECONDS: i32 = 30;
    pub const DNS_MIN_UPSTREAM_TTL_SECONDS: i32 = 5;
    pub const DNS_MAX_UPSTREAM_TTL_SECONDS: i32 = 3600;
    /// RFC 8767 serve-stale window: how long an expired positive answer may
    /// still be served when refresh fails or upstreams are down. The RFC's
    /// recommended range is 1–3 days; 24h keeps recently visited domains
    /// resolving through provider outages and network flaps instead of
    /// turning them into SERVFAILs after only a minute.
    pub const DNS_SERVE_STALE_GRACE: Duration = Duration::from_secs(60 * 60 * 24);
    pub const DNS_QUERY_DEADLINE: Duration = Duration::from_secs(2);
    /// RFC 8767 §5 client response timer: once a query has waited this long
    /// and a stale answer is cached, serve it and keep refreshing in the
    /// background. The RFC recommends 1.8 s, just under common 2 s client
    /// timeouts.
    pub const DNS_STALE_ANSWER_TIMER: Duration = Duration::from_millis(1_800);
    /// RFC 8767 §4: TTL given to each expired record in a stale answer. The
    /// RFC recommends 30 s, so a client does not re-ask every second while
    /// the upstream is failing.
    pub const DNS_STALE_ANSWER_TTL_SECONDS: u32 = 30;
    /// RFC 8767 §5 failure recheck timer: after a refresh of a name with a
    /// stale answer fails, the stale answer is served without asking
    /// upstream again for this long. The RFC recommends 30 s.
    pub const DNS_STALE_FAILURE_RECHECK: Duration = Duration::from_secs(30);
    /// RFC 9520 §3.2: how long the first failed resolution of a name with no
    /// stale answer is answered SERVFAIL without asking upstream. The RFC's
    /// floor is 1 s.
    pub const DNS_RESOLUTION_FAILURE_HOLD: Duration = Duration::from_secs(5);
    /// Ceiling for the doubling hold on repeated failures of one name. The
    /// RFC 9520 limit is 5 minutes; a desktop resolver keeps it short so a
    /// name recovers soon after its upstream does.
    pub const DNS_RESOLUTION_FAILURE_MAX_HOLD: Duration = Duration::from_secs(30);
    /// Per-transport Hickory timeout. Bounds UDP wait, TCP/TLS connect, and
    /// multiplexed request wait. One attempt plus one `RetryDnsHandle` retry
    /// (see `DNS_TRANSPORT_RETRY_ATTEMPTS`) fits inside `DNS_QUERY_DEADLINE`.
    pub const DNS_TRANSPORT_TIMEOUT: Duration = Duration::from_millis(800);
    /// Passed to Hickory `RetryDnsHandle` as remaining retries after the
    /// initial send. `1` permits the initial send plus one retry — two
    /// ordinary sends. Hickory's default of `2` is three ordinary sends.
    pub const DNS_TRANSPORT_RETRY_ATTEMPTS: usize = 1;
    /// Spacing between recovery attempts on a down upstream tier.
    pub const DNS_UPSTREAM_RECOVERY_INTERVAL: Duration = Duration::from_secs(1);
    pub const DNS_MAX_CONCURRENT_UPSTREAM: i32 = 256;
    pub const DNS_MAX_CONCURRENT_BACKGROUND_UPSTREAM: i32 = 16;
    pub const DNS_REFRESH_RETRY_BASE_DELAY_MS: i32 = 1_000;
    pub const DNS_REFRESH_RETRY_MAX_DELAY_MS: i32 = 30_000;
    pub const DNS_UPSTREAM_ADMISSION_TIMEOUT: Duration = Duration::from_millis(150);
    /// Foreground AI budget for proactive classification before DNS resolution.
    /// Must leave time for DNS within [`DNS_QUERY_DEADLINE`]; 500 ms is the
    /// initial proposal, validated by timing tests.
    pub const DNS_AI_FOREGROUND_BUDGET: Duration = Duration::from_millis(500);
    /// Time every gate that runs before the upstream request (proactive AI,
    /// the new-domain lookup) leaves of [`DNS_QUERY_DEADLINE`]. Upstream
    /// admission refuses a query with no more than [`DNS_TRANSPORT_TIMEOUT`]
    /// left, so a gate that leaves less turns a fail-open into SERVFAIL. The
    /// margin on top covers the wait for an admission permit. The gates run
    /// one after the other and each leaves this much, so together they do too.
    pub const DNS_GATE_UPSTREAM_RESERVE: Duration =
        DNS_TRANSPORT_TIMEOUT.saturating_add(DNS_UPSTREAM_ADMISSION_TIMEOUT);
    /// Bounded timeout for a background AI classification once started.
    pub const DNS_AI_BACKGROUND_TIMEOUT: Duration = Duration::from_secs(10);
    /// Maximum concurrent active AI classification requests.
    pub const DNS_AI_MAX_CONCURRENT: usize = 8;
    /// Maximum in-flight domains (active + queued + retry) before overload fails open.
    pub const DNS_AI_MAX_INFLIGHT: usize = 256;
    /// Maximum queued background jobs before rejection.
    pub const DNS_AI_MAX_QUEUED: usize = 512;
    /// Bounded background retry attempts for failed classifications.
    pub const DNS_AI_RETRY_MAX_ATTEMPTS: u32 = 3;
    /// Backoff between AI retries, and between persistence retries.
    pub const DNS_AI_RETRY_BACKOFF: super::Backoff =
        super::Backoff::new(Duration::from_secs(1), Duration::from_secs(30));
    /// Bounded persistence retry attempts for a successful classification
    /// whose store write failed (does not repeat the AI request).
    pub const DNS_AI_PERSIST_RETRY_MAX_ATTEMPTS: u32 = 3;
    /// Budget for coordinator shutdown draining background AI work.
    pub const DNS_AI_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(3);
    /// Maximum saved AI decisions held in memory per Store instance.
    pub const DNS_AI_DECISION_CACHE_CAP: usize = 4_096;
    /// Recheck SQLite after this residency period for out-of-process edits.
    pub const DNS_AI_DECISION_CACHE_TTL: Duration = Duration::from_secs(60);
    /// A saved decision read from memory this close to the end of its
    /// residency is re-read from SQLite in the background. A name in steady
    /// use is then always decided from memory, and only one that went unasked
    /// for the whole lead waits on SQLite again.
    pub const DNS_AI_DECISION_REFRESH_LEAD: Duration = Duration::from_secs(10);
    pub const DNS_DEFAULT_UDP_PAYLOAD_SIZE: i32 = 512;
    /// How often adapter state is sampled to detect a network transition.
    pub const DNS_NETWORK_WATCH_INTERVAL: Duration = Duration::from_secs(5);
}

// ---- HostsParser ----
mod hosts_parser {
    use super::Duration;

    pub const HOSTS_MAX_DOWNLOAD_BYTES: i64 = 128 * 1024 * 1024;
    pub const HOSTS_PER_LIST_SIZE_ESTIMATE: i32 = 300_000;
    pub const HOSTS_PER_CUSTOM_LIST_SIZE_ESTIMATE: i32 = 100_000;
    pub const HOSTS_DOWNLOAD_IDLE_TIMEOUT: Duration = Duration::from_secs(120);
    pub const HOSTS_MAX_PARALLEL_DOWNLOADS: usize = 3;
    pub const HOSTS_SCHEDULER_INTERVAL: Duration = Duration::from_secs(30 * 60);
    pub const HOSTS_SYNC_BACKOFF_BASE_MINUTES: f64 = 30.0;
    pub const HOSTS_SYNC_BACKOFF_CAP_MINUTES: f64 = 24.0 * 60.0;
}

// ---- GeoIP database download (antiwire-ipc::GeoDatabaseService) ----
mod geoip_database {
    use super::Duration;

    /// Headroom over the ~30-35MB compressed GeoLite2-City.mmdb.gz. Kept
    /// independent of `HOSTS_MAX_DOWNLOAD_BYTES` since this bounds a single
    /// binary database download, not a hosts list.
    pub const GEOIP_MAX_COMPRESSED_DOWNLOAD_BYTES: u64 = 128 * 1024 * 1024;
    /// Headroom over the ~70MB decompressed .mmdb; also the decompression-bomb guard.
    pub const GEOIP_MAX_DECOMPRESSED_BYTES: u64 = 256 * 1024 * 1024;
    pub const GEOIP_DOWNLOAD_IDLE_TIMEOUT: Duration = Duration::from_secs(120);
    /// MaxMind/CDN publish a fresh GeoLite2-City build roughly every 3 months.
    pub const GEOIP_DATABASE_REFRESH_INTERVAL: Duration = Duration::from_secs(90 * 24 * 3600);
    /// Scheduler tick cadence. Coarse, since the refresh interval is quarterly.
    pub const GEOIP_SCHEDULER_INTERVAL: Duration = Duration::from_secs(6 * 3600);
    pub const GEOIP_SYNC_BACKOFF_BASE_MINUTES: f64 = 30.0;
    pub const GEOIP_SYNC_BACKOFF_CAP_MINUTES: f64 = 24.0 * 60.0;
    /// jsDelivr data API for the npm package that republishes GeoLite2-City.
    /// `/resolved` names the latest version; `@<version>?structure=flat`
    /// lists each file in that version with its SHA-256 and size.
    pub const GEOLITE2_CITY_PACKAGE_API: &str =
        "https://data.jsdelivr.com/v1/packages/npm/geolite2-city";
    /// CDN root for that package; the database is fetched at a pinned version
    /// so it is the exact file whose digest was published.
    pub const GEOLITE2_CITY_CDN: &str = "https://cdn.jsdelivr.net/npm/geolite2-city";
    /// Bound on the release metadata responses, which are well under 2 KiB.
    pub const GEOIP_MAX_METADATA_BYTES: u64 = 64 * 1024;
}

// ---- Persistent DNS inference (antiwire-store front cache + flow fallback) ----
mod dns_inference {
    use super::Duration;

    /// Maximum age for a persistent IP→domain mapping to back flow inference.
    /// The front cache never extends this: residency only avoids re-reading
    /// SQLite, while eligibility is always recomputed from the mapping's
    /// original observation timestamp.
    pub const DNS_INFERENCE_MAX_AGE: Duration = Duration::from_secs(24 * 60 * 60);
    /// Front-cache capacity in entries. Age-based retention bounds history;
    /// no strict row-count bound is imposed for bursts of unique addresses.
    pub const DNS_INFERENCE_FRONT_CACHE_CAP: i32 = 32_768;
    /// How long a positive front entry avoids a SQLite re-read. An experiment
    /// setting, not a correctness bound — eligibility still uses `MAX_AGE`.
    pub const DNS_INFERENCE_FRONT_POSITIVE_TTL: Duration = Duration::from_secs(5 * 60);
    /// Genuinely absent mappings are cached briefly to absorb the repeated
    /// lookups unresolved flows incur during flushes. Database errors are
    /// never cached as misses.
    pub const DNS_INFERENCE_FRONT_NEGATIVE_TTL: Duration = Duration::from_secs(60);
    /// Observations further than this in the future are treated as clock skew
    /// and ineligible for inference, rather than clamped to fresh.
    pub const DNS_INFERENCE_CLOCK_SKEW_TOLERANCE: Duration = Duration::from_secs(5 * 60);
    /// Minimum interval between opportunistic write-path retention passes.
    pub const DNS_INFERENCE_PURGE_INTERVAL: Duration = Duration::from_secs(60 * 60);
    /// Idle polling interval for the independent DNS retention worker.
    /// Full batches trigger another pass immediately after yielding.
    pub const DNS_INFERENCE_PURGE_WORK_INTERVAL: Duration = Duration::from_secs(5 * 60);
    /// Maximum rows removed per indexed purge pass. The worker releases the
    /// connection between passes and drains until fewer rows are removed.
    pub const DNS_INFERENCE_PURGE_BATCH_SIZE: i32 = 1_000;
}

// ---- EtwDnsCollector ----
mod etw_dns_collector {
    use super::Duration;

    pub const DNS_PERSISTENT_LAST_SEEN_INTERVAL: Duration = Duration::from_secs(5 * 60);
}

// ---- Flow/DnsBlockRecorder ----
mod dns_block_recorder {
    pub const RECENT_DNS_BLOCKS_CAP: i32 = 100_000;
    pub const DNS_BLOCK_DEDUP_MS: u64 = 30_000;
    pub const DNS_BLOCK_RECONCILIATION_MS: u64 = 2_000;
}

// ---- Flow/FlowEventProcessor ----
mod flow_event_processor {
    pub const SEEN_DOMAINS_CAP: usize = 100_000;
}

// ---- Flow/AppIdResolver ----
mod app_id_resolver {
    pub const KNOWN_APP_IDS_CACHE_CAP: u64 = 50_000;
}

// ---- RuleEngine ----
mod rule_engine {
    pub const MAX_DNS_RULE_TARGET_LENGTH: i32 = 253;
    pub const MAX_APP_RULE_TARGET_LENGTH: i32 = 4096;
}

// ---- Dns/DnsServer ----
mod dns_server {
    use super::Duration;

    pub const DNS_MAX_UDP_DATAGRAM_SIZE: i32 = 4096;
    pub const DNS_MAX_TCP_CONNECTIONS: i32 = 128;
    /// Concurrent UDP queries waiting on upstream. Local answers need no slot.
    pub const DNS_MAX_UDP_WORKERS: i32 = 512;
    /// UDP SERVFAILs answered per [`DNS_FAIL_FAST_REPLY_WINDOW`] while every
    /// upstream is down; queries past it are dropped, as when workers are full.
    pub const DNS_FAIL_FAST_REPLY_BUDGET: u32 = 100;
    pub const DNS_FAIL_FAST_REPLY_WINDOW: Duration = Duration::from_millis(100);
    pub const DNS_TCP_IO_TIMEOUT: Duration = Duration::from_secs(5);
    /// Longest a DNS TCP connection is kept, however active, so a client
    /// trickling queries cannot hold a connection slot for good.
    pub const DNS_TCP_MAX_CONNECTION_LIFETIME: Duration = Duration::from_secs(30);
    /// Pause after a failed accept that is not about one connection, such as
    /// running out of file descriptors, so the loop does not spin.
    pub const DNS_TCP_ACCEPT_ERROR_BACKOFF: Duration = Duration::from_millis(100);
    /// Pause after a UDP receive error that is neither about one datagram nor
    /// known to break the socket, so an unexpected repeating error cannot spin
    /// the receive loop.
    pub const DNS_UDP_RECEIVE_ERROR_BACKOFF: Duration = Duration::from_millis(100);
    pub const DNS_TCP_LISTEN_BACKLOG: i32 = 100;
    pub const DNS_SERVER_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(3);
    /// Retry a failed adapter DNS restore after a listener could not start.
    pub const DNS_RESTORE_RETRY_INITIAL_DELAY: Duration = Duration::from_secs(1);
    /// Cap on the doubling restore delay while adapters still need recovery.
    pub const DNS_RESTORE_RETRY_MAX_DELAY: Duration = Duration::from_secs(5);
    /// First wait before retrying a resolver that failed to start at boot.
    pub const DNS_START_RETRY_INITIAL_DELAY: Duration = Duration::from_secs(2);
    /// Cap on the doubling delay between those retries.
    pub const DNS_START_RETRY_MAX_DELAY: Duration = Duration::from_secs(60);
    /// Wait before rebinding a listener socket that stopped unexpectedly.
    pub const DNS_LISTENER_REBIND_INITIAL_DELAY: Duration = Duration::from_millis(50);
    /// Cap on the doubling rebind delay for a listener that keeps failing.
    pub const DNS_LISTENER_REBIND_MAX_DELAY: Duration = Duration::from_secs(5);
    /// Uptime after which a rebound listener counts as healthy again.
    pub const DNS_LISTENER_STABLE_UPTIME: Duration = Duration::from_secs(30);
}

// ---- Dns/Clients/DohClient ----
mod doh_client {
    use super::Duration;
    use crate::dns_interceptor::DNS_QUERY_DEADLINE;

    pub const DOH_FORWARD_TIMEOUT: Duration = DNS_QUERY_DEADLINE;
    /// Head start each upstream tier gets before the next is tried as well.
    pub const DOH_HEDGE_DELAY: Duration = Duration::from_millis(100);
    /// Consecutive transport failures that take an upstream tier down.
    pub const DOH_ENDPOINT_FAILURE_THRESHOLD: i32 = 3;
}

// ---- Dns/NetworkWatch ----
mod dns_network_watch {
    use super::Duration;

    /// A watch tick this much later than scheduled means the host slept.
    pub const DNS_SUSPEND_GAP_THRESHOLD: Duration = Duration::from_secs(10);
    /// Retries of a redirect extension that could not capture, persist, or
    /// apply the originals of new adapters. The first waits one watch tick;
    /// the cap keeps a host where it keeps failing from spawning resolver
    /// tools every few seconds.
    pub const DNS_REDIRECT_EXTENSION_RETRY: super::Backoff =
        super::Backoff::new(Duration::from_secs(5), Duration::from_secs(300));
}

// ---- Dns/Types/CacheTypes ----
mod dns_cache_types {
    use super::Duration;

    pub const DNS_MIN_PREFETCH_TTL: Duration = Duration::from_secs(6);
    pub const DNS_PREFETCH_FRACTION: f64 = 0.10;
}

// ---- Misc shutdown/wait timeouts ----
mod misc_shutdown {
    use super::Duration;

    pub const SIEM_TCP_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

    /// Budget for restoring adapter DNS and removing installed firewall rules.
    ///
    /// Interactive session-end holds a `ShutdownBlockReason` so this can exceed
    /// the bare console `WaitToKillAppTimeout` (5s). The revert starts the
    /// moment shutdown is signalled, beside the IPC drain and the buffer
    /// drain; overrunning still leaves the dirty flag for a next-start heal
    /// when possible.
    pub const SHUTDOWN_REVERT_TIMEOUT: Duration = Duration::from_secs(12);

    /// Deadline for the whole runtime stop, counted from the shutdown signal.
    ///
    /// The buffer drain runs beside the reverts, and the blocked queries and
    /// alerts saved last must be done by it too. Longer than
    /// [`SHUTDOWN_REVERT_TIMEOUT`], so the revert always fits inside it.
    /// Deliberately longer than the OS shutdown grace period: on a `Stop` or a
    /// Ctrl-C there is time to flush, and on a machine shutdown the drain is
    /// expected to be cut short by the OS with nothing lost but telemetry.
    pub const SHUTDOWN_DRAIN_TIMEOUT: Duration = Duration::from_secs(15);

    /// How long the process waits, after teardown, for blocking work still
    /// running to finish before it exits regardless.
    ///
    /// Timing out a revert does not stop the OS call behind it, and the async
    /// runtime would otherwise wait for that call without limit, keeping the
    /// process, and the service, alive. Exiting hands what is left to the
    /// host-state reaper, which starts once this process is gone.
    pub const PROCESS_EXIT_BLOCKING_TIMEOUT: Duration = Duration::from_secs(5);

    /// First wait before the host-state reaper retries a DNS restore that
    /// was not confirmed.
    pub const REAPER_RETRY_INITIAL_DELAY: Duration = Duration::from_secs(5);
    /// Cap on the reaper's doubling retry delay.
    pub const REAPER_RETRY_MAX_DELAY: Duration = Duration::from_secs(300);

    /// How long a settings update waits before replying: for an earlier
    /// update that is still being applied, then for its own changes to take
    /// effect. What is still running carries on in the background, ahead of
    /// later updates, so the order of changes holds. The client's deadline
    /// for the call has to be longer.
    pub const SETTINGS_APPLY_DEADLINE: Duration = Duration::from_secs(30);
}

// ---- Packet capture (CaptureSession) ----
mod packet_capture {
    pub const CAPTURE_TYPICAL_FRAME_BYTES: usize = 2048;
    pub const CAPTURE_LIVE_QUEUE_MEMORY_BUDGET: usize = 16 * 1024 * 1024;
    pub const CAPTURE_LIVE_QUEUE_MIN_CAPACITY: usize = 128;
    pub const CAPTURE_LIVE_QUEUE_MAX_CAPACITY: usize = 2048;
    pub const CAPTURE_LIVE_PAYLOAD_MAX_BYTES: usize = 2048;
    pub const CAPTURE_STATS_SAMPLE_MIN_INTERVAL_MS: i64 = 500;
    /// How long an application capture holds a packet whose flow has no known owner yet.
    pub const CAPTURE_APP_FLOW_HOLD: std::time::Duration = std::time::Duration::from_secs(3);
    /// How often an application capture rereads the application's flows.
    pub const CAPTURE_APP_FLOW_REFRESH: std::time::Duration = std::time::Duration::from_millis(200);
    /// Captured bytes an application capture may hold while owners are resolved.
    pub const CAPTURE_APP_HOLD_MEMORY_BUDGET: usize = 32 * 1024 * 1024;
}

// ---- IPC server (antiwire-ipc) ----
mod ipc_server {
    use super::Duration;

    /// Status messages queued per status stream. Each is a full snapshot,
    /// so a client that falls behind loses nothing by the queue being short.
    pub const IPC_STATUS_STREAM_CAPACITY: usize = 8;
    /// Traffic events or notifications queued per stream before the stream
    /// waits for its client.
    pub const IPC_EVENT_STREAM_CAPACITY: usize = 32;
    /// Captured packets queued per packet stream.
    pub const IPC_PACKET_STREAM_CAPACITY: usize = 128;
    /// Capture file chunks queued per download.
    pub const IPC_DOWNLOAD_STREAM_CAPACITY: usize = 8;
    /// How long the server gets to finish in-flight requests once it stops
    /// accepting new ones. Shutdown does not wait for it: the runtime stops
    /// beside it, and a request still running finds DNS and the firewall
    /// closed.
    pub const IPC_SERVER_DRAIN_TIMEOUT: Duration = Duration::from_secs(5);
}

// ---- System-service attribution (antiwire-flow system_services) ----
mod system_attribution {
    /// Master switch for System-bucket folding. When false, signatures are only
    /// counted (audit mode): attribution stays byte-for-byte identical and no
    /// impersonation alert is published.
    pub const SYSTEM_ATTRIBUTION_ENABLED: bool = true;
    /// Distinct (app, service) impersonation alerts remembered for suppression.
    pub const IMPERSONATION_ALERT_CACHE_CAP: i32 = 1_024;
    /// How long one (app, service) pair stays suppressed after alerting.
    pub const IMPERSONATION_ALERT_TTL_SECS: i64 = 3_600;
}

pub use app_id_resolver::*;
pub use connection_log_query::*;
pub use dns_block_recorder::*;
pub use dns_cache_types::*;
pub use dns_inference::*;
pub use dns_interceptor::*;
pub use dns_network_watch::*;
pub use dns_server::*;
pub use doh_client::*;
pub use etw_dns_collector::*;
pub use flow_event_processor::*;
pub use flow_tracker::*;
pub use geoip_database::*;
pub use hosts_parser::*;
pub use ipc_server::*;
pub use log_retention::*;
pub use misc_shutdown::*;
pub use notification::*;
pub use packet_capture::*;
pub use process_resolver::*;
pub use rule_engine::*;
pub use system_attribution::*;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_doubles_from_the_base_up_to_the_cap() {
        let backoff = Backoff::new(Duration::from_millis(200), Duration::from_secs(1));
        let delays: Vec<_> = (0..=5).map(|attempt| backoff.delay(attempt)).collect();
        assert_eq!(
            delays,
            [200, 200, 400, 800, 1_000, 1_000].map(Duration::from_millis)
        );
        assert_eq!(backoff.delay(u32::MAX), Duration::from_secs(1));
        assert_eq!(
            backoff.after(Duration::from_millis(400)),
            Duration::from_millis(800)
        );
        assert_eq!(
            backoff.after(Duration::from_millis(800)),
            Duration::from_secs(1)
        );
    }
}
