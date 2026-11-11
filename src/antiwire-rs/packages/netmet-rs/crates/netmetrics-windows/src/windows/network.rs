//! Kernel network event decoding, owner attribution, and diagnostic counters.

use crate::filetime::filetime_to_unix_ms;
use crate::owner_module::{OwnedSocket, OwnedUdpEndpoint, TcpOwnerSnapshot, UdpOwnerSnapshot};
use arc_swap::ArcSwap;
use ferrisetw::EventRecord;
use ferrisetw::parser::Parser;
use ferrisetw::schema_locator::SchemaLocator;
use netmetrics_core::{
    ByteDelta, ClockLag, ClockLagGauge, FlowKey, OwnerDisagreement, OwnerEvidenceStats,
    ProcessIdentity, ProcessInfo, Protocol, TcpPidAttributionSample, expiring_map::ExpiringMap,
    unix_now_ms,
};
use netmetrics_sys::{BackendEvent, EventSink};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{LazyLock, Mutex};
use std::time::{Duration, Instant};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum NetworkClass {
    Open {
        protocol: Protocol,
        ipv6: bool,
        reverse: bool,
    },
    Close {
        protocol: Protocol,
        ipv6: bool,
    },
    Bytes {
        protocol: Protocol,
        ipv6: bool,
        received: bool,
    },
}

pub(super) fn classify_network_opcode(protocol: Protocol, opcode: u8) -> Option<NetworkClass> {
    match (protocol, opcode) {
        (Protocol::Tcp, 10 | 14) => Some(NetworkClass::Bytes {
            protocol: Protocol::Tcp,
            ipv6: false,
            received: false,
        }),
        (Protocol::Tcp, 11) => Some(NetworkClass::Bytes {
            protocol: Protocol::Tcp,
            ipv6: false,
            received: true,
        }),
        // Accept (15) and Copy (18) report saddr as the local endpoint. Copy is
        // receive-side attribution, not additional wire bytes, so it opens rather
        // than adding a delta.
        (Protocol::Tcp, 12 | 15 | 16 | 18) => Some(NetworkClass::Open {
            protocol: Protocol::Tcp,
            ipv6: false,
            reverse: false,
        }),
        (Protocol::Tcp, 13) => Some(NetworkClass::Close {
            protocol: Protocol::Tcp,
            ipv6: false,
        }),
        (Protocol::Tcp, 26 | 30) => Some(NetworkClass::Bytes {
            protocol: Protocol::Tcp,
            ipv6: true,
            received: false,
        }),
        (Protocol::Tcp, 27) => Some(NetworkClass::Bytes {
            protocol: Protocol::Tcp,
            ipv6: true,
            received: true,
        }),
        (Protocol::Tcp, 28 | 31 | 32 | 34) => Some(NetworkClass::Open {
            protocol: Protocol::Tcp,
            ipv6: true,
            reverse: false,
        }),
        (Protocol::Tcp, 29) => Some(NetworkClass::Close {
            protocol: Protocol::Tcp,
            ipv6: true,
        }),
        (Protocol::Udp, 10) => Some(NetworkClass::Bytes {
            protocol: Protocol::Udp,
            ipv6: false,
            received: false,
        }),
        (Protocol::Udp, 11) => Some(NetworkClass::Bytes {
            protocol: Protocol::Udp,
            ipv6: false,
            received: true,
        }),
        (Protocol::Udp, 26) => Some(NetworkClass::Bytes {
            protocol: Protocol::Udp,
            ipv6: true,
            received: false,
        }),
        (Protocol::Udp, 27) => Some(NetworkClass::Bytes {
            protocol: Protocol::Udp,
            ipv6: true,
            received: true,
        }),
        _ => None,
    }
}

static ADDRESS_STRING_FALLBACKS: AtomicU64 = AtomicU64::new(0);

/// The kernel's own PID, which an event carries when it was logged for work
/// the kernel did and not for the process that owns the socket.
const SYSTEM_PID: u32 = 4;

/// Which of an event's two owner sources were present, and whether they agreed.
#[derive(Clone, Copy)]
enum OwnerEvidence {
    Agree,
    Disagree,
    DisagreeEventSystem,
    EventOnly,
    RecordedOnly,
    Neither,
    Unowned,
}

static OWNER_EVIDENCE: [AtomicU64; 7] = [const { AtomicU64::new(0) }; 7];

fn count_owner_evidence(evidence: OwnerEvidence) {
    OWNER_EVIDENCE[evidence as usize].fetch_add(1, Ordering::Relaxed);
}

/// Flows whose owner sources disagreed, kept until they are taken. Past
/// this, further flows are counted in [`OwnerEvidenceStats`] only.
const DISAGREEMENT_CAP: usize = 128;

static DISAGREEMENTS: Mutex<Vec<OwnerDisagreement>> = Mutex::new(Vec::new());

/// Takes the flows whose kernel events carried a PID other than the owner
/// recorded at establishment, seen since the last call.
#[must_use]
pub fn take_owner_disagreements() -> Vec<OwnerDisagreement> {
    std::mem::take(
        &mut *DISAGREEMENTS
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner),
    )
}

fn note_disagreement(
    key: &FlowKey,
    event_pid: u32,
    found: &crate::flow_owner::FoundOwner,
    opcode: u8,
) {
    let mut seen = DISAGREEMENTS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let same = |noted: &&mut OwnerDisagreement| {
        noted.key == *key && noted.event_pid == event_pid && noted.recorded_pid == found.owner.pid
    };
    if let Some(noted) = seen.iter_mut().find(same) {
        noted.events += 1;
    } else if seen.len() < DISAGREEMENT_CAP {
        seen.push(OwnerDisagreement {
            key: *key,
            event_pid,
            recorded_pid: found.owner.pid,
            recorded_executable: found.owner.executable.clone(),
            reversed: found.reversed,
            record_age_ms: u64::try_from(found.age.as_millis()).unwrap_or(u64::MAX),
            opcode,
            events: 1,
        });
    }
}

/// Where the owner of each kernel network event came from since the process
/// started, and how the sources compared.
#[must_use]
pub fn owner_evidence_stats() -> OwnerEvidenceStats {
    let load = |evidence: OwnerEvidence| OWNER_EVIDENCE[evidence as usize].load(Ordering::Relaxed);
    OwnerEvidenceStats {
        agree: load(OwnerEvidence::Agree),
        disagree: load(OwnerEvidence::Disagree),
        disagree_event_system: load(OwnerEvidence::DisagreeEventSystem),
        event_only: load(OwnerEvidence::EventOnly),
        recorded_only: load(OwnerEvidence::RecordedOnly),
        neither: load(OwnerEvidence::Neither),
        unowned: load(OwnerEvidence::Unowned),
    }
}

// https://learn.microsoft.com/en-us/windows/win32/etw/tcpip
pub(super) const TCP_EVENT_IDS: [u8; 16] = [
    10, 11, 12, 13, 14, 15, 16, 18, 26, 27, 28, 29, 30, 31, 32, 34,
];
static TCP_OWNER_COOKIE_HITS: AtomicU64 = AtomicU64::new(0);

/// Owner cookies attached to open/byte events whose payload already supplied a PID.
#[must_use]
pub fn tcp_owner_cookie_hit_count() -> u64 {
    TCP_OWNER_COOKIE_HITS.load(Ordering::Relaxed)
}

const TCP_EVENT_VERSIONS: usize = 256;
const TCP_PID_COUNTERS: usize = TCP_EVENT_IDS.len() * TCP_EVENT_VERSIONS;

#[derive(Debug)]
struct TcpPidCounter {
    observed: AtomicU64,
    missing: AtomicU64,
    recovered: AtomicU64,
}

impl TcpPidCounter {
    const fn new() -> Self {
        Self {
            observed: AtomicU64::new(0),
            missing: AtomicU64::new(0),
            recovered: AtomicU64::new(0),
        }
    }
}

pub(super) struct TcpPidMetrics {
    counters: Box<[TcpPidCounter]>,
}

impl TcpPidMetrics {
    pub(super) fn new() -> Self {
        Self {
            counters: (0..TCP_PID_COUNTERS)
                .map(|_| TcpPidCounter::new())
                .collect(),
        }
    }

    fn counter(&self, event_id: u8, event_version: u8) -> Option<&TcpPidCounter> {
        let event_slot = TCP_EVENT_IDS
            .iter()
            .position(|candidate| *candidate == event_id)?;
        Some(&self.counters[event_slot * TCP_EVENT_VERSIONS + usize::from(event_version)])
    }

    pub(super) fn observe(&self, event_id: u8, event_version: u8, payload_pid: u32) {
        let Some(counter) = self.counter(event_id, event_version) else {
            return;
        };
        counter.observed.fetch_add(1, Ordering::Relaxed);
        if payload_pid == 0 {
            counter.missing.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub(super) fn recover(&self, event_id: u8, event_version: u8) {
        if let Some(counter) = self.counter(event_id, event_version) {
            counter.recovered.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub(super) fn snapshot(&self) -> Vec<TcpPidAttributionSample> {
        let mut samples = Vec::new();
        for (event_slot, event_id) in TCP_EVENT_IDS.into_iter().enumerate() {
            for version in 0_u8..=u8::MAX {
                let counter =
                    &self.counters[event_slot * TCP_EVENT_VERSIONS + usize::from(version)];
                let observed = counter.observed.load(Ordering::Relaxed);
                if observed == 0 {
                    continue;
                }
                samples.push(TcpPidAttributionSample {
                    event_id,
                    event_version: version,
                    observed,
                    missing: counter.missing.load(Ordering::Relaxed),
                    recovered: counter.recovered.load(Ordering::Relaxed),
                });
            }
        }
        samples
    }
}

pub(super) static TCP_PID_METRICS: LazyLock<TcpPidMetrics> = LazyLock::new(TcpPidMetrics::new);
static UDP_PID_METRICS: LazyLock<TcpPidMetrics> = LazyLock::new(TcpPidMetrics::new);

/// UDP payload attribution sample, partitioned by opcode and version.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UdpPidAttributionSample {
    /// Kernel UDP opcode.
    pub event_id: u8,
    /// Event schema version.
    pub event_version: u8,
    /// Parsed events observed.
    pub observed: u64,
    /// Events without a payload PID.
    pub missing: u64,
    /// Missing payload PIDs recovered from connection id or owner snapshots.
    pub recovered: u64,
}

/// Returns cumulative UDP payload attribution counters.
#[must_use]
pub fn udp_pid_attribution_stats() -> Vec<UdpPidAttributionSample> {
    UDP_PID_METRICS
        .snapshot()
        .into_iter()
        .map(|sample| UdpPidAttributionSample {
            event_id: sample.event_id,
            event_version: sample.event_version,
            observed: sample.observed,
            missing: sample.missing,
            recovered: sample.recovered,
        })
        .collect()
}

/// Returns TCP payload-PID attribution counters partitioned by event ID and version.
#[must_use]
pub fn tcp_pid_attribution_stats() -> Vec<TcpPidAttributionSample> {
    TCP_PID_METRICS.snapshot()
}

/// Number of times ETW address fields were parsed from a display string.
#[must_use]
pub fn address_string_fallback_count() -> u64 {
    ADDRESS_STRING_FALLBACKS.load(Ordering::Relaxed)
}

/// How long a connection-id mapping stays usable after its last observation.
///
/// Every event of a connection refreshes its mapping, so the window only has to
/// bridge the gaps between an event that carried a PID and the next one that
/// did not. When it lapses, the owner-module snapshot is the remaining fallback.
pub(super) const CONNID_RETENTION: Duration = Duration::from_secs(30);

/// Bound on retained connection-id mappings per transport.
pub(super) const CONNID_CACHE_CAPACITY: usize = 8_192;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct ConnIdEntry {
    pid: u32,
    key: FlowKey,
    cookie: Option<netmetrics_core::SocketCookie>,
}

/// Bounded `connid -> owner` memory for one transport.
///
/// Kernel network events carry a connection identifier that is stable across
/// every event of a connection, independent of address orientation and of the
/// owner-module poll window. A PID (and cookie) learned from any event of the
/// connection is applied to later events that miss their payload PID, so a
/// delayed or reordered byte event does not fall back to an unknown owner.
#[derive(Debug, Default)]
pub(super) struct ConnIdCache {
    pub(super) entries: ExpiringMap<u64, ConnIdEntry, CONNID_CACHE_CAPACITY>,
}

/// Owner evidence resolved for one network event.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct NetworkAttribution {
    pub(super) pid: u32,
    pub(super) cookie: Option<netmetrics_core::SocketCookie>,
    /// True when the payload PID was missing and another source supplied one.
    pub(super) recovered: bool,
}

impl ConnIdCache {
    /// Resolves one event's owner and refreshes the connection's mapping.
    ///
    /// Payload identity stays authoritative; a per-event owner lookup is next,
    /// and the connection's remembered owner is the last resort. A cookie is
    /// attached even when the PID came from the payload, so a missed owner
    /// lookup cannot drop the socket identity of a known connection, but only
    /// from evidence about the selected owner: a cookie names one process's
    /// socket, and pairing it with another PID would read as a replaced socket.
    pub(super) fn observe(
        &mut self,
        connid: Option<u64>,
        key: &FlowKey,
        payload_pid: u32,
        owner: Option<(u32, Option<netmetrics_core::SocketCookie>)>,
        now: Instant,
    ) -> NetworkAttribution {
        self.entries.expire(now);
        let cached = connid.and_then(|connid| self.entries.get(&connid).copied());
        // A connid can be reused by a new socket after close. TCP must be the
        // same 5-tuple. One UDP socket keeps its connid across remotes, so the
        // local endpoint is enough.
        let same_flow = cached.is_some_and(|entry| same_connid_flow(&entry.key, key));
        let mut pid = payload_pid;
        let mut recovered = false;
        if pid == 0 {
            match owner {
                Some((owner_pid, _)) if owner_pid > 0 => {
                    pid = owner_pid;
                    recovered = true;
                }
                _ => {
                    if let Some(entry) = cached.filter(|_| same_flow) {
                        pid = entry.pid;
                        recovered = true;
                    }
                }
            }
        }
        let mut cookie = owner
            .filter(|&(owner_pid, _)| owner_pid == pid)
            .and_then(|(_, cookie)| cookie);
        if cookie.is_none() {
            cookie = cached
                .filter(|entry| same_flow && entry.pid == pid)
                .and_then(|entry| entry.cookie);
        }
        if let Some(connid) = connid
            && pid > 0
        {
            self.insert(connid, *key, pid, cookie, now);
        }
        if pid == 0 {
            count_owner_evidence(OwnerEvidence::Unowned);
        }
        NetworkAttribution {
            pid,
            cookie,
            recovered,
        }
    }

    fn insert(
        &mut self,
        connid: u64,
        key: FlowKey,
        pid: u32,
        cookie: Option<netmetrics_core::SocketCookie>,
        now: Instant,
    ) {
        let expires_at = now.checked_add(CONNID_RETENTION).unwrap_or(now);
        self.entries
            .insert(connid, ConnIdEntry { pid, key, cookie }, expires_at);
    }
}

/// Connection identifier carried by kernel TCP/IP and UDP/IP events.
///
/// Classic MOF and manifest events both expose `connid` as a per-connection
/// value; zero is treated as absent so an unmapped event cannot collide with a
/// real connection.
fn same_connid_flow(stored: &FlowKey, current: &FlowKey) -> bool {
    if stored.protocol != current.protocol {
        return false;
    }
    if stored.protocol == Protocol::Udp {
        let stored_local = (stored.local_addr, stored.local_port);
        let current_local = (current.local_addr, current.local_port);
        let current_remote = (current.remote_addr, current.remote_port);
        return stored_local == current_local || stored_local == current_remote;
    }
    stored == current || stored == &current.reverse()
}

fn parse_connid(parser: &Parser<'_, '_>) -> Option<u64> {
    parser
        .try_parse::<u64>("connid")
        .or_else(|_| parser.try_parse::<u32>("connid").map(u64::from))
        .ok()
        .filter(|connid| *connid != 0)
}

pub(super) struct DecodedNetwork {
    pub(super) event: BackendEvent,
    pub(super) process: Option<ProcessInfo>,
}

#[cfg(test)]
pub(super) fn prefer_flow_owner(
    payload_pid: u32,
    key: &FlowKey,
    snapshot: Option<(u32, Option<netmetrics_core::SocketCookie>)>,
    flow_owners: &Mutex<crate::flow_owner::FlowOwnerCache>,
    now: Instant,
) -> (
    Option<(u32, Option<netmetrics_core::SocketCookie>)>,
    Option<ProcessInfo>,
) {
    prefer_flow_owner_for(0, payload_pid, key, snapshot, flow_owners, now)
}

/// [`prefer_flow_owner`] for an event of kernel type `opcode`, which is noted
/// when the event's PID and the recorded owner disagree.
fn prefer_flow_owner_for(
    opcode: u8,
    payload_pid: u32,
    key: &FlowKey,
    snapshot: Option<(u32, Option<netmetrics_core::SocketCookie>)>,
    flow_owners: &Mutex<crate::flow_owner::FlowOwnerCache>,
    now: Instant,
) -> (
    Option<(u32, Option<netmetrics_core::SocketCookie>)>,
    Option<ProcessInfo>,
) {
    let found = flow_owners
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .find(key, now)
        // Between two endpoints on this host, a record under the addresses
        // swapped is the process at the other end. It is no evidence of who
        // owns this end, and no rival to the event's own PID.
        .filter(|found| !(found.reversed && both_ends_local(key)));
    match (payload_pid, found.as_ref().map(|found| found.owner.pid)) {
        (0, Some(_)) => count_owner_evidence(OwnerEvidence::RecordedOnly),
        (0, None) => count_owner_evidence(OwnerEvidence::Neither),
        (_, None) => count_owner_evidence(OwnerEvidence::EventOnly),
        (event, Some(recorded)) if event == recorded => count_owner_evidence(OwnerEvidence::Agree),
        (event, Some(_)) => {
            count_owner_evidence(OwnerEvidence::Disagree);
            if event == SYSTEM_PID {
                count_owner_evidence(OwnerEvidence::DisagreeEventSystem);
            }
            if let Some(found) = &found {
                note_disagreement(key, event, found, opcode);
            }
        }
    }
    let flow = found.map(|found| found.owner);
    if payload_pid != 0 {
        // The payload remains the owner. Retain a connect-time image only
        // when both sources agree; its creation time follows it through the
        // collector's generation checks instead of being queried after exit.
        let process = flow
            .filter(|owner| {
                owner.pid == payload_pid
                    && owner.start_ts > 0
                    && snapshot.is_none_or(|(pid, _)| pid == payload_pid)
            })
            .and_then(|owner| owner.process_info());
        return (snapshot, process);
    }
    match flow {
        // The snapshot's cookie belongs to the snapshot's owner; keep it only
        // when that is the owner FLOW recorded.
        Some(owner) if owner.pid > 0 => (
            Some((
                owner.pid,
                snapshot
                    .filter(|&(pid, _)| pid == owner.pid)
                    .and_then(|(_, cookie)| cookie),
            )),
            owner.process_info(),
        ),
        _ => (snapshot, None),
    }
}

pub(super) fn decode_network_event(
    record: &EventRecord,
    locator: &SchemaLocator,
    protocol: Protocol,
    tcp_owners: Option<&ArcSwap<TcpOwnerSnapshot>>,
    udp_owners: Option<&ArcSwap<UdpOwnerSnapshot>>,
    flow_owners: &Mutex<crate::flow_owner::FlowOwnerCache>,
    connids: &mut ConnIdCache,
) -> Result<Option<DecodedNetwork>, ()> {
    let Some(class) = classify_network_opcode(protocol, record.opcode()) else {
        return Ok(None);
    };
    let schema = locator.event_schema(record).map_err(|_| ())?;
    let parser = Parser::create(record, &schema);
    let payload_pid = network_payload_pid(&parser);
    payload_pid_metrics(protocol).observe(record.opcode(), record.version(), payload_pid);
    let reverse = tuple_is_reversed(class);
    let (protocol, ipv6) = match class {
        NetworkClass::Open { protocol, ipv6, .. }
        | NetworkClass::Close { protocol, ipv6 }
        | NetworkClass::Bytes { protocol, ipv6, .. } => (protocol, ipv6),
    };
    let source_addr = parse_address(&parser, "saddr", ipv6)?;
    let destination_addr = parse_address(&parser, "daddr", ipv6)?;
    let source_port = parse_port(&parser, "sport")?;
    let destination_port = parse_port(&parser, "dport")?;
    let key = orient_network_key(
        FlowKey {
            protocol,
            local_addr: source_addr,
            local_port: source_port,
            remote_addr: destination_addr,
            remote_port: destination_port,
        },
        reverse,
    );
    let local_addr = key.local_addr;
    let local_port = key.local_port;
    let (raw_timestamp, timestamp) = network_event_time(record);
    // When network payload PID parsing fails, do NOT fall back to record.process_id() (the ETW
    // event header PID). Microsoft explicitly warns that network events may be logged by other
    // threads (e.g. DPC/interrupt or worker threads). Resolve the owner from the event's
    // connection instead: the per-event socket table, then the connection id learned from an
    // earlier event of the same connection.
    let snapshot = match protocol {
        Protocol::Tcp => tcp_snapshot_owner(tcp_owners, &key, raw_timestamp),
        Protocol::Udp => lookup_udp_owner(udp_owners, local_addr, local_port, raw_timestamp)
            .map(|owner| (owner.pid, Some(owner.cookie()))),
    };
    let now = Instant::now();
    let (owner, process) = prefer_flow_owner_for(
        record.opcode(),
        payload_pid,
        &key,
        snapshot,
        flow_owners,
        now,
    );
    let attribution = connids.observe(parse_connid(&parser), &key, payload_pid, owner, now);
    let pid = attribution.pid;
    if attribution.recovered {
        payload_pid_metrics(protocol).recover(record.opcode(), record.version());
    }
    if protocol == Protocol::Tcp
        && payload_pid > 0
        && snapshot.is_some()
        && !matches!(class, NetworkClass::Close { .. })
    {
        TCP_OWNER_COOKIE_HITS.fetch_add(1, Ordering::Relaxed);
    }

    let event = match class {
        NetworkClass::Open { .. } => BackendEvent::Opened {
            key,
            pid,
            cookie: attribution.cookie,
            timestamp,
            if_index: None,
        },
        NetworkClass::Close { .. } => BackendEvent::Closed {
            key,
            pid,
            timestamp,
        },
        NetworkClass::Bytes { received, .. } => {
            let size = parser
                .try_parse::<u32>("size")
                .or_else(|_| parser.try_parse::<u32>("Size"))
                .map(u64::from)
                .map_err(|_| ())?;
            let delta = if received {
                ByteDelta {
                    sent: 0,
                    received: size,
                }
            } else {
                ByteDelta {
                    sent: size,
                    received: 0,
                }
            };
            BackendEvent::Bytes {
                key,
                pid,
                delta,
                timestamp,
                if_index: None,
                cookie: attribution.cookie,
            }
        }
    };
    Ok(Some(DecodedNetwork { event, process }))
}

fn payload_pid_metrics(protocol: Protocol) -> &'static TcpPidMetrics {
    match protocol {
        Protocol::Tcp => &TCP_PID_METRICS,
        Protocol::Udp => &UDP_PID_METRICS,
    }
}

pub(super) fn orient_network_key(key: FlowKey, reverse: bool) -> FlowKey {
    if reverse { key.reverse() } else { key }
}

/// Whether `saddr`/`sport` are the packet source rather than the local endpoint.
///
/// Kernel TCP events report `saddr` as local. UDP Recv reports the packet
/// source, so only that path flips the tuple.
pub(super) const fn tuple_is_reversed(class: NetworkClass) -> bool {
    match class {
        NetworkClass::Open { reverse, .. } => reverse,
        NetworkClass::Bytes {
            protocol: Protocol::Udp,
            received: true,
            ..
        } => true,
        NetworkClass::Close { .. } | NetworkClass::Bytes { .. } => false,
    }
}

/// How far kernel ETW event times run behind the system clock (see
/// [`netmetrics_core::ClockLagGauge`]).
pub(super) static ETW_CLOCK_LAG: ClockLagGauge = ClockLagGauge::new(60_000);

/// How far kernel ETW network event times run behind the system clock, measured
/// over one-minute windows since the kernel session started.
#[must_use]
pub fn etw_clock_lag() -> ClockLag {
    ETW_CLOCK_LAG.snapshot()
}

fn network_event_time(record: &EventRecord) -> (i64, u64) {
    let raw = record.raw_timestamp();
    let now = unix_now_ms();
    let Some(unix_ms) = u64::try_from(raw).ok().and_then(filetime_to_unix_ms) else {
        return (raw, now);
    };
    ETW_CLOCK_LAG.observe(unix_ms, now);
    (raw, unix_ms)
}

fn network_payload_pid(parser: &Parser<'_, '_>) -> u32 {
    parser
        .try_parse::<u32>("PID")
        .or_else(|_| parser.try_parse::<u32>("ProcessId"))
        .unwrap_or(0)
}

/// Whether both ends of `key` are on this host, as far as its addresses
/// alone can say: the same address at each end, or two loopback addresses.
fn both_ends_local(key: &FlowKey) -> bool {
    key.local_addr == key.remote_addr
        || (key.local_addr.is_loopback() && key.remote_addr.is_loopback())
}

/// The socket table's owner of the TCP flow `key`, with its cookie.
fn tcp_snapshot_owner(
    owners: Option<&ArcSwap<TcpOwnerSnapshot>>,
    key: &FlowKey,
    event_time: i64,
) -> Option<(u32, Option<netmetrics_core::SocketCookie>)> {
    lookup_tcp_owner(owners, key, event_time).map(|owner| {
        // A listener-derived owner has no per-connection creation timestamp,
        // so it must not contribute a cookie that could split a flow.
        let cookie = (owner.created > 0).then(|| owner.cookie());
        (owner.pid, cookie)
    })
}

fn lookup_tcp_owner(
    owners: Option<&ArcSwap<TcpOwnerSnapshot>>,
    key: &FlowKey,
    event_time: i64,
) -> Option<OwnedSocket> {
    owners?.load().lookup(key, event_time)
}

fn lookup_udp_owner(
    owners: Option<&ArcSwap<UdpOwnerSnapshot>>,
    local_addr: IpAddr,
    local_port: u16,
    event_time: i64,
) -> Option<OwnedUdpEndpoint> {
    owners?.load().lookup(local_addr, local_port, event_time)
}

fn parse_address(parser: &Parser<'_, '_>, name: &str, ipv6: bool) -> Result<IpAddr, ()> {
    match parser.try_parse::<IpAddr>(name) {
        Ok(address) if address.is_ipv6() == ipv6 => return Ok(address),
        _ => {}
    }
    if ipv6 {
        return parser
            .try_parse::<String>(name)
            .ok()
            .and_then(|value| value.trim_matches(['[', ']']).parse::<Ipv6Addr>().ok())
            .map(|address| {
                ADDRESS_STRING_FALLBACKS.fetch_add(1, Ordering::Relaxed);
                IpAddr::V6(address)
            })
            .ok_or(());
    }
    if let Ok(raw) = parser.try_parse::<u32>(name) {
        return Ok(IpAddr::V4(Ipv4Addr::from(raw.to_ne_bytes())));
    }
    if let Some(address) = parser
        .try_parse::<String>(name)
        .ok()
        .and_then(|value| value.parse::<Ipv4Addr>().ok())
    {
        ADDRESS_STRING_FALLBACKS.fetch_add(1, Ordering::Relaxed);
        return Ok(IpAddr::V4(address));
    }
    Err(())
}

fn parse_port(parser: &Parser<'_, '_>, name: &str) -> Result<u16, ()> {
    if let Ok(port) = parser.try_parse::<u16>(name) {
        return Ok(u16::from_be(port));
    }
    let port = parser.try_parse::<u32>(name).map_err(|_| ())?;
    u16::try_from(port).map_err(|_| ())
}

pub(super) fn emit_decoded(
    sink: &EventSink,
    decoded: DecodedNetwork,
    announced: &mut ProcessAnnouncements,
) {
    if let Some(process) = decoded.process
        && announced.is_due(&process, Instant::now())
        && sink.emit(BackendEvent::ProcessStarted(process.clone()))
    {
        announced.record(process, Instant::now());
    }
    sink.emit(decoded.event);
}

/// How long a network callback waits before repeating an announced identity.
/// The repeat lets the collector relearn one it has evicted.
pub(super) const PROCESS_REANNOUNCE: Duration = Duration::from_secs(30);
/// Bound on identities a network callback remembers announcing.
const PROCESS_ANNOUNCEMENT_CAPACITY: usize = 4_096;

/// Identities a network callback has announced from the FLOW owner cache.
///
/// Without this every packet of an attributed flow repeats `ProcessStarted`.
/// Each repeat makes the collector scan every active flow, and repeats take
/// the queue capacity reserved for opens and closes.
#[derive(Debug, Default)]
pub(super) struct ProcessAnnouncements {
    entries: HashMap<u32, (ProcessIdentity, Instant)>,
}

impl ProcessAnnouncements {
    pub(super) fn is_due(&self, process: &ProcessInfo, now: Instant) -> bool {
        self.entries.get(&process.pid).is_none_or(|(identity, at)| {
            *identity != process.identity
                || now.saturating_duration_since(*at) >= PROCESS_REANNOUNCE
        })
    }

    pub(super) fn record(&mut self, process: ProcessInfo, now: Instant) {
        if self.entries.len() >= PROCESS_ANNOUNCEMENT_CAPACITY
            && !self.entries.contains_key(&process.pid)
        {
            // Forgetting only costs a repeated announcement.
            self.entries.clear();
        }
        self.entries.insert(process.pid, (process.identity, now));
    }
}
