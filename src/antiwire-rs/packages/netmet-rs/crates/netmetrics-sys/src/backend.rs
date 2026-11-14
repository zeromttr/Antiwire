use crate::{EventSink, StopFlag};
use netmetrics_core::{
    ByteDelta, DegradeReason, DnsQueryEvent, FlowKey, InterfaceStats, ProcessIdentity, ProcessInfo,
    Protocol, SocketCookie, canonicalize_ip,
};
use std::error::Error;
use std::fmt::{Display, Formatter};
use std::net::IpAddr;

/// Platform-neutral subset of collector configuration consumed by backends.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BackendConfig {
    /// Native session or pin-path name.
    pub session_name: String,
    /// Native buffer sizing hint.
    pub buffer_mb: u32,
    /// Interface/fallback polling interval.
    pub poll_interval_ms: u64,
    /// Whether the backend should start its DNS side channel.
    pub dns_hints: bool,
}

/// Internal, minimally processed event produced by a native backend.
///
/// [`EventSink::emit`] puts its flow addresses in canonical form
/// ([`FlowKey::canonical`]), so the collector sees one form whichever backend reports it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BackendEvent {
    /// Flow lifecycle start.
    Opened {
        /// Flow key.
        key: FlowKey,
        /// Owning PID, or zero when unknown.
        pid: u32,
        /// Per-socket identity, or `None` when this backend cannot resolve one.
        cookie: Option<SocketCookie>,
        /// Unix epoch milliseconds.
        timestamp: u64,
        /// Host interface index, when the backend observed one.
        if_index: Option<u32>,
    },
    /// Socket identity learned for a flow that some other source reports the lifecycle of.
    ///
    /// Enrichment only: it never creates a flow. Backends where identity arrives from a
    /// side channel (the Windows owner-module poller) use this so that polling the whole
    /// system socket table does not start tracking flows the lifecycle source never saw.
    CookieResolved {
        /// Flow key.
        key: FlowKey,
        /// Owning PID reported alongside the identity, or zero when unknown.
        pid: u32,
        /// Resolved per-socket identity.
        cookie: SocketCookie,
        /// Unix epoch milliseconds.
        timestamp: u64,
    },
    /// Flow lifecycle end.
    Closed {
        /// Flow key.
        key: FlowKey,
        /// Owning PID observed on this close, or zero when unknown.
        ///
        /// Applied only when this flow is already tracked. A close must not
        /// create a row for a connection the collector never saw.
        pid: u32,
        /// Unix epoch milliseconds.
        timestamp: u64,
    },
    /// A flow's TCP connection is no longer established, and its socket is still open:
    /// this end has sent its FIN. The flow keeps taking bytes until its `Closed`.
    ///
    /// Applied only to a flow already tracked, and published once for it. An `Opened` for
    /// the same key afterwards is a new connection on those addresses.
    Finishing {
        /// Flow key.
        key: FlowKey,
        /// Unix epoch milliseconds.
        timestamp: u64,
    },
    /// Every flow sharing this local bind ended because the socket itself disappeared.
    LocalEndpointClosed {
        /// Transport protocol.
        protocol: Protocol,
        /// Local address from the platform table; unspecified matches every address that
        /// wildcard receives for (see `FlowTable::close_local_endpoint`).
        local_addr: IpAddr,
        /// Local port.
        local_port: u16,
        /// Cookie of the vanished bind, when known.
        ///
        /// A delayed close must not drain a newer bind generation: the collector skips
        /// flows whose cookie contradicts this value.
        cookie: Option<SocketCookie>,
        /// Unix epoch milliseconds.
        timestamp: u64,
    },
    /// Incremental byte delta.
    Bytes {
        /// Flow key.
        key: FlowKey,
        /// Owning PID observed with this byte event, or zero when unavailable.
        pid: u32,
        /// Incremental accounting.
        delta: ByteDelta,
        /// Unix epoch milliseconds.
        timestamp: u64,
        /// Host interface index, when the backend observed one.
        if_index: Option<u32>,
        /// Per-socket identity observed with this byte event, when available.
        ///
        /// The collector reconciles this cookie before applying the delta so a bind
        /// recycle splits the previous identity instead of charging the new bytes to it.
        cookie: Option<SocketCookie>,
    },
    /// Asynchronous interface lookup for a previously created flow.
    ///
    /// `bound` is true when `if_index` is the interface that owns the flow's local
    /// address. A route estimate (`bound == false`) may be replaced later by a bound
    /// answer. The collector applies the hint only when `generation` still matches
    /// the live flow at `key`.
    InterfaceHint {
        /// Flow that requested the lookup.
        key: FlowKey,
        /// Host interface index.
        if_index: u32,
        /// True when the index owns the local address, false for a route estimate.
        bound: bool,
        /// Flow identity generation captured when the lookup was requested.
        generation: u64,
    },
    /// Process lifecycle start.
    ProcessStarted(ProcessInfo),
    /// Process lifecycle end.
    ProcessStopped {
        /// Process identifier.
        pid: u32,
        /// Unix epoch milliseconds.
        timestamp: u64,
        /// Identity from the stop event when start/rundown was missed.
        identity: Option<ProcessIdentity>,
    },
    /// Process-level DNS query attempt (from ETW or platform probe).
    DnsQuery(DnsQueryEvent),
    /// Best-effort DNS result.
    DnsResolved {
        /// Querying process.
        pid: u32,
        /// Domain query.
        query: String,
        /// Canonical IP answers.
        answers: Vec<IpAddr>,
        /// Cache lifetime. Zero asks the collector to apply its configured default.
        ttl_ms: u64,
        /// Unix epoch milliseconds.
        timestamp: u64,
    },
    /// Interface cumulative counters.
    Interface(InterfaceStats),
    /// Backend-specific degradation that does not stop the stream.
    Degraded(DegradeReason),
    /// The native source started, ending any [`DegradeReason::SnapshotOnly`] fallback reported
    /// for `source`.
    ///
    /// Sent every time the native source starts, including the first: a backend the collector
    /// restarted cannot know whether its previous run left a fallback unended. The collector
    /// outlives its backend runs, so it publishes this only when it ends a fallback it
    /// published.
    Restored {
        /// The fallback this ends, as its `SnapshotOnly` named it.
        source: String,
    },
}

impl BackendEvent {
    /// Puts every flow key and local endpoint in canonical form.
    ///
    /// DNS answers are canonical already: their producers deduplicate on that form.
    pub(crate) fn canonicalize(&mut self) {
        match self {
            Self::Opened { key, .. }
            | Self::CookieResolved { key, .. }
            | Self::Closed { key, .. }
            | Self::Finishing { key, .. }
            | Self::Bytes { key, .. }
            | Self::InterfaceHint { key, .. } => *key = key.canonical(),
            Self::LocalEndpointClosed { local_addr, .. } => {
                *local_addr = canonicalize_ip(*local_addr);
            }
            Self::ProcessStarted(_)
            | Self::ProcessStopped { .. }
            | Self::DnsQuery(_)
            | Self::DnsResolved { .. }
            | Self::Interface(_)
            | Self::Degraded(_)
            | Self::Restored { .. } => {}
        }
    }
}

/// Broad category of backend failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BackendErrorKind {
    /// Insufficient native privileges.
    PermissionDenied,
    /// Preferred source is not present.
    Unavailable,
    /// An established session was lost.
    SessionLost,
    /// Target is unsupported.
    Unsupported,
    /// Native data could not be decoded.
    Decode,
    /// Other I/O error.
    Io,
}

/// Failure returned by a backend run.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BackendError {
    /// Error category.
    pub kind: BackendErrorKind,
    /// Native source name.
    pub source: String,
    /// Human-readable diagnostic.
    pub detail: String,
}

impl BackendError {
    /// Creates a new backend error.
    pub fn new(
        kind: BackendErrorKind,
        source: impl Into<String>,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            kind,
            source: source.into(),
            detail: detail.into(),
        }
    }

    /// Converts the terminal error into the normalized event contract.
    pub fn degrade_reason(&self, backend: &str) -> DegradeReason {
        match self.kind {
            BackendErrorKind::PermissionDenied => DegradeReason::PermissionDenied {
                source: self.source.clone(),
            },
            BackendErrorKind::Unavailable => DegradeReason::SourceUnavailable {
                source: self.source.clone(),
                detail: self.detail.clone(),
            },
            BackendErrorKind::SessionLost | BackendErrorKind::Io => DegradeReason::SessionLost {
                backend: backend.to_owned(),
                detail: self.detail.clone(),
            },
            BackendErrorKind::Unsupported => DegradeReason::UnsupportedPlatform,
            BackendErrorKind::Decode => DegradeReason::DecodeError {
                source: self.source.clone(),
            },
        }
    }
}

impl Display for BackendError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}: {}", self.source, self.detail)
    }
}

impl Error for BackendError {}

/// Blocking native collector run. Implementations return when stopped or failed.
pub trait Backend: Send + 'static {
    /// Stable backend name used in diagnostics.
    fn name(&self) -> &'static str;

    /// Runs the backend until `stop` is requested or a terminal native error occurs.
    ///
    /// # Errors
    ///
    /// Returns a categorized error when the native source cannot start, loses
    /// its session, or produces an unrecoverable record.
    fn run(
        &mut self,
        config: &BackendConfig,
        sink: EventSink,
        stop: StopFlag,
    ) -> Result<(), BackendError>;
}
