use crate::{canonicalize_ip, unspecified_address};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

/// Transport protocol represented by a flow.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    /// Transmission Control Protocol.
    Tcp,
    /// User Datagram Protocol.
    Udp,
}

/// Direction-independent identity of a network flow from the local host's view.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct FlowKey {
    /// TCP or UDP.
    pub protocol: Protocol,
    /// Address on the monitored host.
    pub local_addr: IpAddr,
    /// Port on the monitored host.
    pub local_port: u16,
    /// Peer address.
    pub remote_addr: IpAddr,
    /// Peer port.
    pub remote_port: u16,
}

impl FlowKey {
    /// Returns true when either endpoint is an IP loopback address.
    pub fn is_loopback(self) -> bool {
        self.local_addr.is_loopback() || self.remote_addr.is_loopback()
    }

    /// The same flow in canonical form, the one form every backend reports.
    ///
    /// An IPv4-mapped IPv6 address (`::ffff:a.b.c.d`) becomes the IPv4 address it maps.
    /// Linux keeps the addresses of an `AF_INET6` socket that carries IPv4 in that form
    /// (`ipv6(7)`: "When you get an IPv4 connection or packet to an IPv6 socket, its source
    /// address will be mapped to v6"), while the packets themselves, and the Windows and
    /// macOS sources, carry plain IPv4. An unspecified address then takes the
    /// family of the other endpoint: a socket bound to `::` that exchanges IPv4 datagrams
    /// is bound to the IPv4 wildcard for that flow. Any other IPv6 address, `::1` and
    /// `::a.b.c.d` included, is left alone.
    #[must_use]
    pub fn canonical(self) -> Self {
        let local_addr = canonicalize_ip(self.local_addr);
        let remote_addr = canonicalize_ip(self.remote_addr);
        Self {
            local_addr: in_family_of(local_addr, remote_addr),
            remote_addr: in_family_of(remote_addr, local_addr),
            ..self
        }
    }

    /// Swaps local and remote endpoints (packet vs connection orientation).
    #[must_use]
    pub fn reverse(self) -> Self {
        Self {
            protocol: self.protocol,
            local_addr: self.remote_addr,
            local_port: self.remote_port,
            remote_addr: self.local_addr,
            remote_port: self.local_port,
        }
    }
}

/// `address`, or the unspecified address of `peer`'s family when `address` is unspecified
/// and `peer` is not.
fn in_family_of(address: IpAddr, peer: IpAddr) -> IpAddr {
    if address.is_unspecified() && !peer.is_unspecified() {
        unspecified_address(peer)
    } else {
        address
    }
}

/// Origin of a [`SocketCookie`], recorded so consumers know how far to trust it.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CookieSource {
    /// The kernel's socket cookie (`sk_cookie`, what `bpf_get_socket_cookie` returns). Unique
    /// for the boot lifetime and never reused. The kernel assigns it only when asked. The
    /// backend asks when a TCP socket first changes state and at a UDP socket's first
    /// send, where the kernel lets a tracing program; elsewhere a socket can carry none at
    /// first and this one later.
    LinuxSockCookie,
    /// `/proc/net/*` socket inode. Unique among open sockets; recycled after close.
    LinuxInode,
    /// `MIB_TCPROW_OWNER_MODULE.liCreateTimestamp` folded with the flow tuple.
    WindowsCreateTimestamp,
    /// The flow ID macOS reports with a socket's packets (`pth_flowid` in a PKTAP header):
    /// a random number the kernel gives each socket, unique among open sockets and
    /// released when the socket closes. Packets the host receives through the kernel's
    /// own network stack do not carry it, so a flow can have none at first.
    MacosFlowId,
    /// Derived from tuple, PID and first observation. Unique, but not OS-backed.
    Synthetic,
}

/// Per-socket identity used to tell a recycled tuple from a continuing socket.
///
/// A [`FlowKey`] alone cannot distinguish a long-lived connection from a new socket that
/// reused the same ephemeral port after `TIME_WAIT`. Comparing cookies makes that boundary
/// observable wherever the platform exposes a socket token.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub struct SocketCookie {
    /// Opaque identifier. Only meaningful when compared against the same [`CookieSource`].
    pub value: u64,
    /// How the value was obtained.
    pub source: CookieSource,
}

const FNV_OFFSET_BASIS: u64 = 0xcbf2_9ce4_8422_2325;
const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;

fn fnv1a(mut hash: u64, bytes: &[u8]) -> u64 {
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    hash
}

fn fold_addr(hash: u64, addr: IpAddr) -> u64 {
    match addr {
        IpAddr::V4(address) => fnv1a(hash, &address.octets()),
        IpAddr::V6(address) => fnv1a(hash, &address.octets()),
    }
}

impl SocketCookie {
    /// Derives a cookie from observation context when the platform exposes no socket token.
    ///
    /// The value is a deterministic digest of the flow tuple, owning PID and first-observation
    /// timestamp, so two sockets that reuse one tuple at different times receive different
    /// cookies. It cannot detect a close and reopen that the collector never observed.
    #[must_use]
    pub fn synthetic(key: FlowKey, pid: u32, first_seen_ts: u64) -> Self {
        let protocol = match key.protocol {
            Protocol::Tcp => 6u8,
            Protocol::Udp => 17u8,
        };
        let mut hash = fnv1a(FNV_OFFSET_BASIS, &[protocol]);
        hash = fold_addr(hash, key.local_addr);
        hash = fnv1a(hash, &key.local_port.to_be_bytes());
        hash = fold_addr(hash, key.remote_addr);
        hash = fnv1a(hash, &key.remote_port.to_be_bytes());
        hash = fnv1a(hash, &pid.to_le_bytes());
        hash = fnv1a(hash, &first_seen_ts.to_le_bytes());
        Self {
            value: hash,
            source: CookieSource::Synthetic,
        }
    }

    /// Returns true when both cookies came from the same source and disagree.
    ///
    /// Cookies from differing sources carry no comparable information, so they never report
    /// a mismatch. This is the single predicate that decides whether a tuple has been
    /// recycled onto a new socket.
    #[must_use]
    pub fn contradicts(self, other: Self) -> bool {
        self.source == other.source && self.value != other.value
    }
}

/// Stable process identity across PID reuse.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ProcessIdentity {
    /// Best available executable path.
    pub executable: String,
    /// Short display name.
    pub name: String,
    /// Process creation timestamp, in Unix epoch milliseconds.
    pub start_ts: u64,
}

impl ProcessIdentity {
    /// Whether the identity names the process by path or name, not just its start time.
    #[must_use]
    pub fn is_usable(&self) -> bool {
        !self.executable.is_empty() || !self.name.is_empty()
    }
}

/// Process identity together with its current PID.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ProcessInfo {
    /// Operating-system process identifier.
    pub pid: u32,
    /// Stable identity fields.
    pub identity: ProcessIdentity,
}

/// Attribution attached to flow lifecycle events.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct FlowMeta {
    /// Owning PID, or zero when the backend could not attribute it.
    pub pid: u32,
    /// Resolved process identity, retained briefly after process exit.
    pub process: Option<ProcessIdentity>,
    /// Flow-open timestamp, in Unix epoch milliseconds.
    pub open_ts: u64,
    /// Per-socket identity, when the platform exposed one for this observation.
    ///
    /// Absent is common and never means "different socket": UDP on Windows, inferred opens,
    /// and any flow seen before its backend could resolve a token all report `None`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cookie: Option<SocketCookie>,
    /// First inferred host interface index for this flow, when known.
    ///
    /// This is the interface that owns the local address when that address is
    /// known, and otherwise a routing estimate captured when the flow was created.
    /// A later bound answer may replace an estimate. An estimate does not replace
    /// a bound answer, and a second estimate does not replace the first.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub if_index: Option<u32>,
}

/// Incremental byte counts. Values are never absolute counters.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct ByteDelta {
    /// Bytes sent by the local host.
    pub sent: u64,
    /// Bytes received by the local host.
    pub received: u64,
}

impl ByteDelta {
    /// Returns the sum of both directions, saturating on overflow.
    pub fn total(self) -> u64 {
        self.sent.saturating_add(self.received)
    }

    /// Returns true when neither direction contains bytes.
    pub fn is_zero(self) -> bool {
        self.sent == 0 && self.received == 0
    }

    /// Adds another delta without wrapping counters.
    pub fn saturating_add_assign(&mut self, other: Self) {
        self.sent = self.sent.saturating_add(other.sent);
        self.received = self.received.saturating_add(other.received);
    }
}

/// Current lifecycle state of a flow.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FlowState {
    /// The backend considers the flow active.
    Open,
    /// The flow's TCP connection is no longer established and its socket is still open
    /// (see [`FlowEvent::Finishing`]).
    Finishing,
    /// A terminal close was observed.
    Closed,
}

/// One row in a point-in-time flow snapshot.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct FlowRecord {
    /// Flow identity.
    pub key: FlowKey,
    /// Process and open-time attribution.
    pub meta: FlowMeta,
    /// Cumulative local send bytes seen by this collector session.
    pub bytes_sent: u64,
    /// Cumulative local receive bytes seen by this collector session.
    pub bytes_received: u64,
    /// Most recent activity timestamp, in Unix epoch milliseconds.
    pub last_seen_ts: u64,
    /// Lifecycle state.
    pub state: FlowState,
}

/// Immutable copy of the collector's flow table.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct FlowSnapshot {
    /// Time the snapshot was published, in Unix epoch milliseconds.
    pub captured_at: u64,
    /// Active flows, sorted by [`FlowKey`] for stable output.
    pub flows: Vec<FlowRecord>,
    /// Number of flow entries evicted since collector start.
    pub evicted_flows: u64,
}

/// Interface-level cumulative counters.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct InterfaceStats {
    /// Platform interface index.
    pub index: u32,
    /// Human-readable interface name.
    pub name: String,
    /// Cumulative received bytes.
    pub rx_bytes: u64,
    /// Cumulative transmitted bytes.
    pub tx_bytes: u64,
    /// Cumulative receive errors.
    pub rx_errors: u64,
    /// Cumulative transmit errors.
    pub tx_errors: u64,
    /// Cumulative receive drops.
    pub rx_drops: u64,
    /// Cumulative transmit drops.
    pub tx_drops: u64,
    /// Sample timestamp, in Unix epoch milliseconds.
    pub timestamp: u64,
}

/// A normalized reason why collection is incomplete.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum DegradeReason {
    /// Native telemetry could not be opened with current privileges.
    PermissionDenied {
        /// Native source that rejected access.
        source: String,
    },
    /// A running native session exited and will be restarted.
    SessionLost {
        /// Backend name.
        backend: String,
        /// Diagnostic detail.
        detail: String,
    },
    /// A bounded buffer between the native source and the collector discarded what it
    /// could not hold: events in the collector's ingress queue, records in the eBPF ring on
    /// Linux, events in an ETW session's buffers on Windows, or packets in the kernel's
    /// capture buffer on macOS. Byte totals fall short by what was discarded, and a flow
    /// whose close was discarded stays open.
    BufferOverflow {
        /// Events or packets discarded since the preceding report. On Windows this is the
        /// least that was lost: a buffer of events ETW could not deliver counts as one.
        dropped: u64,
    },
    /// Flow capacity was exceeded and least-recently-used rows were evicted.
    CapacityExceeded {
        /// Rows evicted since the preceding report.
        evicted: u64,
    },
    /// A preferred native source is unavailable.
    SourceUnavailable {
        /// Source name.
        source: String,
        /// Diagnostic detail.
        detail: String,
    },
    /// Only periodic snapshots are available; short-lived flows may be missed.
    SnapshotOnly {
        /// Fallback source name.
        source: String,
    },
    /// A native record did not match its documented schema.
    DecodeError {
        /// Decoder or provider name.
        source: String,
    },
    /// No backend exists for the current target.
    UnsupportedPlatform,
}

/// Process identities observed around a DNS operation, with roles kept explicit.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct DnsCallerIdentity {
    /// Process that generated/logged the ETW event. Its DNS role is event-schema dependent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub logging_pid: Option<u32>,
    /// Original requesting application PID (from `ClientPID` payload or in-process caller).
    pub requesting_pid: Option<u32>,
    /// Resolver process PID, only when the event schema establishes that role.
    pub resolver_pid: Option<u32>,
}

/// Correlation identifiers for tracing a DNS query across ETW events.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct DnsCorrelationId {
    /// Activity GUID from the event header (16 bytes).
    pub activity_id: Option<[u8; 16]>,
    /// Query pointer or identifier from payload (e.g. `QueryBlob`).
    pub query_blob: Option<u64>,
}

/// DNS query event carrying query details, status, and caller attribution.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DnsQueryEvent {
    /// Native source event identifier, when supplied by the backend.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event_id: Option<u16>,
    /// Native source event schema version, when supplied by the backend.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event_version: Option<u8>,
    /// Query name.
    pub name: String,
    /// DNS query record type (e.g. 1 = A, 28 = AAAA).
    pub query_type: u16,
    /// Resolution or response status code (0 = success): a Win32 error from the Windows
    /// DNS client, and the DNS response code where the backend reads packets. A query
    /// reported before its answer carries zero.
    pub status: u32,
    /// Requesting and resolver caller identity.
    pub caller: DnsCallerIdentity,
    /// Correlation identifiers (`ActivityId`, `QueryBlob`).
    pub correlation: DnsCorrelationId,
    /// Original event timestamp (Unix epoch milliseconds).
    pub timestamp: u64,
}

/// TCP payload-PID attribution counters for one native event ID/version.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct TcpPidAttributionSample {
    /// TCP/IP ETW event type (the classic provider opcode).
    pub event_id: u8,
    /// Native event schema version.
    pub event_version: u8,
    /// Events observed after resolving this native schema.
    pub observed: u64,
    /// Events whose payload PID was absent or zero.
    pub missing: u64,
    /// Missing-PID events recovered from connection identity or ownership evidence.
    pub recovered: u64,
}

/// Where the owner of each kernel network event came from, and how the
/// sources compared.
///
/// An event can carry a PID of its own, and the flow it belongs to can have an
/// owner recorded when it was established. Where both are present the event's
/// PID is the one used, so the two disagreeing is a flow that one of the
/// sources would attribute to another process.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct OwnerEvidenceStats {
    /// Events whose own PID is the owner recorded at establishment.
    pub agree: u64,
    /// Events whose own PID is not the owner recorded at establishment.
    pub disagree: u64,
    /// Of those, events whose own PID is the kernel's.
    pub disagree_event_system: u64,
    /// Events with a PID of their own and no recorded owner.
    pub event_only: u64,
    /// Events with no PID of their own, given the recorded owner.
    pub recorded_only: u64,
    /// Events with neither, left to the socket tables and to what the
    /// connection's earlier events said.
    pub neither: u64,
    /// Events that ended with no owner at all.
    pub unowned: u64,
}

/// A flow whose kernel events carried a PID other than the owner recorded
/// when it was established: one case of [`OwnerEvidenceStats::disagree`], with
/// what is needed to tell why.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OwnerDisagreement {
    /// The flow, as the disagreeing event described it.
    pub key: FlowKey,
    /// The PID the event carried, which is the one used.
    pub event_pid: u32,
    /// The owner recorded at establishment.
    pub recorded_pid: u32,
    /// The recorded owner's executable, empty when it could not be read.
    pub recorded_executable: String,
    /// The recorded owner was found under the flow's addresses swapped, so
    /// it is the process at the other end of a connection between two local
    /// endpoints and not another claim to this end.
    pub reversed: bool,
    /// How long before the first disagreeing event the owner was recorded,
    /// in milliseconds.
    pub record_age_ms: u64,
    /// Kernel event type of the first disagreeing event.
    pub opcode: u8,
    /// Disagreeing events seen for this flow and pair of PIDs.
    pub events: u64,
}

/// Requests to deliver DNS events ahead of the event source's own timer, and
/// how the flushes went.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct DnsFlushStats {
    /// Requests a running DNS event source accepted.
    pub requests: u64,
    /// Flushes that succeeded. Requests close together share one.
    pub flushes: u64,
    /// Flushes the event source refused.
    pub failures: u64,
}

/// Attribution scope attached to a DNS resolution hint.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "scope", content = "pid", rename_all = "snake_case")]
pub enum DnsResolutionAttribution {
    /// The native source identified the querying process.
    Process(u32),
    /// The resolution is only safe as a system-wide hint.
    Shared,
}

/// Unified event stream emitted on every supported operating system.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "event", content = "data", rename_all = "snake_case")]
pub enum FlowEvent {
    /// A flow became visible to the native source.
    Opened(FlowKey, FlowMeta),
    /// A flow's TCP connection is no longer established, and its socket is still open.
    ///
    /// This end has sent its FIN: the application shut down its sending side and may still
    /// be receiving, or it closed the socket and the system is finishing the connection.
    /// From here on the connection is not an active one
    /// ([`TcpState::is_established`](crate::TcpState::is_established)), so it is no longer
    /// counted as one. The flow stays open for the bytes that still follow, and
    /// [`FlowEvent::Closed`] ends it. Sent at most once for a flow, and only by a source
    /// that sees a connection change state: Linux eBPF and macOS packet capture. Windows
    /// and the socket-table fallbacks report only `Closed`.
    Finishing(FlowKey),
    /// A flow terminated or aged out.
    Closed(FlowKey, FlowMeta),
    /// Incremental byte accounting for a flow.
    Bytes(FlowKey, ByteDelta),
    /// A process began.
    ProcessStarted(ProcessInfo),
    /// A process ended.
    ProcessStopped {
        /// Process identifier.
        pid: u32,
        /// Stop timestamp, in Unix epoch milliseconds.
        stop_ts: u64,
    },
    /// Optional, best-effort DNS side-channel information.
    DnsResolved {
        /// Process that issued the query, when available.
        pid: u32,
        /// Normalized queried domain.
        query: String,
        /// Textual IP answers.
        answers: Vec<String>,
    },
    /// DNS side-channel information with native TTL and attribution provenance.
    DnsResolvedWithMetadata {
        /// Scope of the native attribution evidence.
        attribution: DnsResolutionAttribution,
        /// Normalized queried domain.
        query: String,
        /// Textual IP answers.
        answers: Vec<String>,
        /// Cache lifetime supplied by the native source or collector fallback.
        ttl_ms: u64,
        /// Observation timestamp in Unix epoch milliseconds.
        observed_at: u64,
    },
    /// Process-level DNS query attempt.
    DnsQuery(DnsQueryEvent),
    /// Cumulative interface counters.
    Interface(InterfaceStats),
    /// Collection continues with reduced fidelity.
    Degraded {
        /// Normalized degradation reason.
        reason: DegradeReason,
    },
    /// The native source is back, and collection is at full fidelity again.
    ///
    /// Ends the [`DegradeReason::SnapshotOnly`] fallback reported with the same `source`.
    /// It follows that report, at most once for each time it was made.
    Restored {
        /// The fallback that ended, as its `SnapshotOnly` named it.
        source: String,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    #[test]
    fn byte_delta_saturates() {
        let mut delta = ByteDelta {
            sent: u64::MAX,
            received: 4,
        };
        delta.saturating_add_assign(ByteDelta {
            sent: 1,
            received: u64::MAX,
        });
        assert_eq!(delta.sent, u64::MAX);
        assert_eq!(delta.received, u64::MAX);
        assert_eq!(delta.total(), u64::MAX);
    }

    #[test]
    fn loopback_checks_both_endpoints() {
        let key = FlowKey {
            protocol: Protocol::Tcp,
            local_addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
            local_port: 1,
            remote_addr: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)),
            remote_port: 2,
        };
        assert!(key.is_loopback());
    }

    fn mapped(address: Ipv4Addr) -> IpAddr {
        IpAddr::V6(address.to_ipv6_mapped())
    }

    /// Linux reports a dual-stack socket's IPv4 connection with IPv4-mapped addresses.
    #[test]
    fn a_mapped_key_becomes_its_ipv4_key() {
        let plain = sample_key();
        let reported = FlowKey {
            local_addr: mapped(Ipv4Addr::new(192, 0, 2, 10)),
            remote_addr: mapped(Ipv4Addr::new(198, 51, 100, 20)),
            ..plain
        };
        assert_eq!(reported.canonical(), plain);
        assert_eq!(plain.canonical(), plain);
    }

    #[test]
    fn a_mapped_loopback_flow_is_loopback_once_canonical() {
        let reported = FlowKey {
            local_addr: mapped(Ipv4Addr::LOCALHOST),
            remote_addr: mapped(Ipv4Addr::LOCALHOST),
            ..sample_key()
        };
        assert!(!reported.is_loopback(), "the mapped form is not loopback");
        assert!(reported.canonical().is_loopback());
    }

    #[test]
    fn real_ipv6_addresses_are_left_alone() {
        for (local, remote) in [
            ("2001:db8::1", "2606:4700:4700::1111"),
            ("::1", "::1"),
            // IPv4-compatible (`::a.b.c.d`) is a real, if deprecated, IPv6 address.
            ("::c000:20a", "::c633:6414"),
        ] {
            let key = FlowKey {
                local_addr: local.parse().expect("local address"),
                remote_addr: remote.parse().expect("remote address"),
                ..sample_key()
            };
            assert_eq!(key.canonical(), key, "{local} -> {remote}");
        }
    }

    /// A UDP socket bound to `::` that talks IPv4 reports its local address as `::` on the
    /// receive path and as `0.0.0.0` on the send path; both are one flow.
    #[test]
    fn an_unspecified_address_takes_the_family_of_its_peer() {
        let plain = FlowKey {
            protocol: Protocol::Udp,
            local_addr: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            local_port: 50_000,
            remote_addr: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 20)),
            remote_port: 53,
        };
        let received = FlowKey {
            local_addr: IpAddr::V6(Ipv6Addr::UNSPECIFIED),
            remote_addr: mapped(Ipv4Addr::new(198, 51, 100, 20)),
            ..plain
        };
        assert_eq!(received.canonical(), plain);
        let ipv6 = FlowKey {
            local_addr: IpAddr::V6(Ipv6Addr::UNSPECIFIED),
            remote_addr: "2001:db8::53".parse().expect("remote address"),
            ..plain
        };
        assert_eq!(ipv6.canonical(), ipv6, "an IPv6 flow keeps `::`");
        let unbound = FlowKey {
            remote_addr: IpAddr::V6(Ipv6Addr::UNSPECIFIED),
            remote_port: 0,
            ..received
        };
        assert_eq!(unbound.canonical(), unbound, "two unspecified ends stay");
    }

    fn sample_key() -> FlowKey {
        FlowKey {
            protocol: Protocol::Tcp,
            local_addr: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
            local_port: 50_000,
            remote_addr: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 20)),
            remote_port: 443,
        }
    }

    #[test]
    fn synthetic_cookies_separate_sockets_that_reuse_a_tuple() {
        let key = sample_key();
        let first = SocketCookie::synthetic(key, 42, 1_000);
        let repeat = SocketCookie::synthetic(key, 42, 1_000);
        let reopened = SocketCookie::synthetic(key, 42, 2_000);
        let other_owner = SocketCookie::synthetic(key, 43, 1_000);

        assert_eq!(first, repeat, "derivation must be deterministic");
        assert!(!first.contradicts(repeat));
        assert!(first.contradicts(reopened));
        assert!(first.contradicts(other_owner));
    }

    #[test]
    fn synthetic_cookies_separate_distinct_tuples() {
        let mut other = sample_key();
        other.remote_port = 8443;
        assert!(
            SocketCookie::synthetic(sample_key(), 42, 1_000)
                .contradicts(SocketCookie::synthetic(other, 42, 1_000))
        );
    }

    #[test]
    fn cookies_from_differing_sources_never_contradict() {
        let bpf = SocketCookie {
            value: 1,
            source: CookieSource::LinuxSockCookie,
        };
        let inode = SocketCookie {
            value: 2,
            source: CookieSource::LinuxInode,
        };
        assert!(!bpf.contradicts(inode));
        assert!(!inode.contradicts(bpf));
    }
}
