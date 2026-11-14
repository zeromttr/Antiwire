//! Socket creation timestamps read from the IP Helper owner-module TCP tables.
//!
//! Kernel TCP/IP ETW payloads carry no socket handle, so this is the only Windows source
//! that can tell two sockets sharing one 5-tuple apart. `liCreateTimestamp` is stable for
//! the life of a socket, so re-reading a live connection yields the same cookie and no
//! spurious flow split.
//!
//! UDP owner-module rows describe only a local bind. They still supply PID and a creation
//! timestamp, which is enough to enrich ETW byte events and to close flows when the bind
//! disappears.
//!
//! Timestamp resolution is coarse, so two sockets created on one tuple within a single tick
//! are indistinguishable. That produces a *missed* split rather than a false one.

use netmetrics_core::{
    CookieSource, FlowKey, SocketCookie, SocketCount, unix_now_ms, unspecified_address,
};
use std::collections::HashMap;
use std::hash::Hash;
use std::net::IpAddr;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

mod poller;
mod tables;
#[cfg(test)]
mod tests;

pub(crate) use poller::CookiePoller;
#[cfg(target_arch = "x86_64")]
pub(crate) use tables::owns_local_endpoint;
pub(crate) use tables::snapshot;
pub use tables::{count_owner_pid_tables, socket_owner_snapshot, socket_owner_snapshot_for};

/// How long a disappeared owner may still pin a delayed ETW event after process/socket exit.
const CLOSED_OWNER_GRACE: Duration = Duration::from_secs(10);
/// Memory bound on recently closed TCP or UDP owners.
const MAX_CLOSED_OWNERS: usize = 8_192;

static TCP_ACCEPTED_BEYOND_VALID_THROUGH: AtomicU64 = AtomicU64::new(0);
static TCP_LISTENER_FALLBACKS: AtomicU64 = AtomicU64::new(0);

/// Live TCP owner matches accepted within one poll interval after observation.
#[must_use]
pub fn tcp_owner_relaxed_match_count() -> u64 {
    TCP_ACCEPTED_BEYOND_VALID_THROUGH.load(Ordering::Relaxed)
}

/// Inbound connections attributed from their local listening endpoint.
#[must_use]
pub fn tcp_listener_fallback_count() -> u64 {
    TCP_LISTENER_FALLBACKS.load(Ordering::Relaxed)
}

/// An established TCP socket paired with the token that identifies it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct OwnedSocket {
    /// Connection tuple.
    pub key: FlowKey,
    /// Owning process.
    pub pid: u32,
    /// Raw `liCreateTimestamp`, used as the cookie value.
    pub created: i64,
}

impl OwnedSocket {
    /// Returns the cookie for this socket.
    ///
    /// The raw timestamp is the value: cookies are only ever compared between observations
    /// of the same [`FlowKey`], so folding the tuple in would add nothing.
    pub fn cookie(self) -> SocketCookie {
        SocketCookie {
            #[allow(clippy::cast_sign_loss)]
            value: self.created as u64,
            source: CookieSource::WindowsCreateTimestamp,
        }
    }
}

/// Immutable full-tuple TCP owners published for delayed ETW delivery.
///
/// Live matches require creation before the event and allow at most one poll interval
/// beyond the latest observation. Recently closed owners are retained for
/// [`CLOSED_OWNER_GRACE`] but remain strictly bounded by the close observation, so a
/// delayed ETW payload with PID 0 can still be pinned. A later live owner of a reused
/// tuple is tried first.
#[derive(Clone, Debug, Default)]
pub(crate) struct TcpOwnerSnapshot {
    sockets: HashMap<FlowKey, TcpSeen>,
    closed: HashMap<FlowKey, ClosedTcpSeen>,
    /// Listener owners keyed by local bind, used for inbound connections whose
    /// established 5-tuple is no longer in the platform table.
    listeners: HashMap<(IpAddr, u16), Option<TcpSeen>>,
    valid_through: i64,
    valid_until: i64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ClosedTcpSeen {
    pid: u32,
    created: i64,
    valid_through: i64,
    keep_until: Instant,
}

impl TcpOwnerSnapshot {
    pub fn lookup(&self, key: &FlowKey, event_time: i64) -> Option<OwnedSocket> {
        if let Some(owner) = self.find_live(key)
            && owner.created > 0
            && owner.created <= event_time
            && event_time <= self.valid_until
        {
            if event_time > self.valid_through {
                TCP_ACCEPTED_BEYOND_VALID_THROUGH.fetch_add(1, Ordering::Relaxed);
            }
            return Some(OwnedSocket {
                key: *key,
                pid: owner.pid,
                created: owner.created,
            });
        }
        if let Some(closed) = self.find_closed(key)
            && closed.created > 0
            && closed.created <= event_time
            && event_time <= closed.valid_through
            && Instant::now() <= closed.keep_until
        {
            return Some(OwnedSocket {
                key: *key,
                pid: closed.pid,
                created: closed.created,
            });
        }
        self.lookup_listener(key, event_time)
    }

    /// Attributes an inbound flow from the process that owns its local port.
    ///
    /// A listener is weaker evidence than an exact 5-tuple and has no
    /// per-connection identity, so the returned owner carries `created == 0`
    /// and must never contribute a cookie.
    fn lookup_listener(&self, key: &FlowKey, event_time: i64) -> Option<OwnedSocket> {
        let owner = lookup_listener_owner(&self.listeners, key.local_addr, key.local_port)?;
        if owner.created <= 0 || event_time < owner.created || event_time > self.valid_until {
            return None;
        }
        TCP_LISTENER_FALLBACKS.fetch_add(1, Ordering::Relaxed);
        Some(OwnedSocket {
            key: *key,
            pid: owner.pid,
            created: 0,
        })
    }

    fn find_live(&self, key: &FlowKey) -> Option<&TcpSeen> {
        self.sockets
            .get(key)
            .or_else(|| self.sockets.get(&key.reverse()))
    }

    fn find_closed(&self, key: &FlowKey) -> Option<&ClosedTcpSeen> {
        self.closed
            .get(key)
            .or_else(|| self.closed.get(&key.reverse()))
    }

    fn clear(&mut self) {
        self.sockets.clear();
        self.closed.clear();
        self.listeners.clear();
        self.valid_through = 0;
        self.valid_until = 0;
    }

    fn fill_from(
        &mut self,
        live: &HashMap<FlowKey, TcpSeen>,
        valid_through: i64,
        poll_interval: Duration,
    ) {
        self.fill_from_at(
            live,
            valid_through,
            Instant::now(),
            CLOSED_OWNER_GRACE,
            poll_interval,
        );
    }

    fn fill_from_at(
        &mut self,
        live: &HashMap<FlowKey, TcpSeen>,
        valid_through: i64,
        now: Instant,
        grace: Duration,
        poll_interval: Duration,
    ) {
        self.closed.retain(|key, entry| {
            now < entry.keep_until && !same_tcp_socket(live.get(key), entry.pid, entry.created)
        });
        let keep_until = now.checked_add(grace).unwrap_or(now);
        for (key, seen) in &self.sockets {
            if seen.created > 0 && !same_tcp_socket(live.get(key), seen.pid, seen.created) {
                self.closed.insert(
                    *key,
                    ClosedTcpSeen {
                        pid: seen.pid,
                        created: seen.created,
                        valid_through,
                        keep_until,
                    },
                );
            }
        }
        trim_closed_tcp(&mut self.closed);
        self.sockets.clear();
        self.sockets
            .extend(live.iter().map(|(key, owner)| (*key, *owner)));
        self.valid_through = valid_through;
        // FILETIME uses 100 ns ticks. A close/reuse within this interval is corrected
        // by the next poll's changed cookie and the consumer's cookie split.
        let ticks = i64::try_from(poll_interval.as_nanos() / 100).unwrap_or(i64::MAX);
        self.valid_until = valid_through.saturating_add(ticks);
    }
}

/// A UDP bind paired with the token that identifies it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct OwnedUdpEndpoint {
    /// Bound address, which may be unspecified.
    pub local_addr: IpAddr,
    /// Bound port.
    pub local_port: u16,
    /// Owning process.
    pub pid: u32,
    /// Raw `liCreateTimestamp`.
    pub created: i64,
}

impl OwnedUdpEndpoint {
    pub fn cookie(self) -> SocketCookie {
        SocketCookie {
            #[allow(clippy::cast_sign_loss)]
            value: self.created as u64,
            source: CookieSource::WindowsCreateTimestamp,
        }
    }

    pub fn key(self) -> (IpAddr, u16) {
        (self.local_addr, self.local_port)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum UdpBind {
    Unique(OwnedUdpEndpoint),
    Ambiguous,
}

/// Immutable UDP bind owners published for ETW byte observations.
#[derive(Clone, Debug, Default)]
pub(crate) struct UdpOwnerSnapshot {
    binds: HashMap<(IpAddr, u16), UdpBind>,
    closed: HashMap<(IpAddr, u16), ClosedUdpBind>,
    valid_through: i64,
    valid_until: i64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ClosedUdpBind {
    endpoint: OwnedUdpEndpoint,
    valid_through: i64,
    keep_until: Instant,
}

/// UDP owner join outcomes, including rejected evidence.
#[derive(Clone, Copy, Debug, Default)]
pub struct UdpOwnerLookupStats {
    /// Successful live or retained-owner joins.
    pub matched: u64,
    /// Live joins beyond the last observation, within one poll interval.
    pub relaxed: u64,
    /// Rejections caused by a shared local bind.
    pub ambiguous: u64,
    /// A candidate existed but its lifetime or retention did not match.
    pub temporal_miss: u64,
    /// No exact or wildcard candidate existed.
    pub absent: u64,
}
static UDP_LOOKUP_COUNTS: [AtomicU64; 5] = [const { AtomicU64::new(0) }; 5];

/// Returns cumulative UDP owner lookup diagnostics.
#[must_use]
pub fn udp_owner_lookup_stats() -> UdpOwnerLookupStats {
    let counts = UDP_LOOKUP_COUNTS
        .each_ref()
        .map(|counter| counter.load(Ordering::Relaxed));
    UdpOwnerLookupStats {
        matched: counts[0],
        relaxed: counts[1],
        ambiguous: counts[2],
        temporal_miss: counts[3],
        absent: counts[4],
    }
}

impl UdpOwnerSnapshot {
    pub fn lookup(&self, addr: IpAddr, port: u16, event_time: i64) -> Option<OwnedUdpEndpoint> {
        let result = self.lookup_inner(addr, port, event_time);
        let exact = (addr, port);
        let wildcard = (unspecified_address(addr), port);
        let count = if let Some(owner) = result {
            if event_time > self.valid_through
                && self.binds.get(&owner.key()) == Some(&UdpBind::Unique(owner))
            {
                UDP_LOOKUP_COUNTS[1].fetch_add(1, Ordering::Relaxed);
            }
            0
        } else if matches!(self.binds.get(&exact), Some(UdpBind::Ambiguous))
            || matches!(self.binds.get(&wildcard), Some(UdpBind::Ambiguous))
        {
            2
        } else if self.binds.contains_key(&exact)
            || self.binds.contains_key(&wildcard)
            || self.closed.contains_key(&exact)
            || self.closed.contains_key(&wildcard)
        {
            3
        } else {
            4
        };
        UDP_LOOKUP_COUNTS[count].fetch_add(1, Ordering::Relaxed);
        result
    }

    fn lookup_inner(&self, addr: IpAddr, port: u16, event_time: i64) -> Option<OwnedUdpEndpoint> {
        match self.binds.get(&(addr, port)) {
            Some(UdpBind::Unique(endpoint))
                if endpoint.created > 0
                    && endpoint.created <= event_time
                    && event_time <= self.valid_until =>
            {
                Some(*endpoint)
            }
            Some(UdpBind::Ambiguous) => None,
            Some(UdpBind::Unique(_)) | None => self
                .lookup_closed(addr, port, event_time)
                .or_else(|| self.lookup_wildcard(addr, port, event_time)),
        }
    }

    fn lookup_wildcard(
        &self,
        addr: IpAddr,
        port: u16,
        event_time: i64,
    ) -> Option<OwnedUdpEndpoint> {
        let wildcard = unspecified_address(addr);
        match self.binds.get(&(wildcard, port)) {
            Some(UdpBind::Unique(endpoint))
                if endpoint.created > 0
                    && endpoint.created <= event_time
                    && event_time <= self.valid_until =>
            {
                Some(*endpoint)
            }
            Some(UdpBind::Ambiguous) => None,
            Some(UdpBind::Unique(_)) | None => self.lookup_closed(wildcard, port, event_time),
        }
    }

    fn lookup_closed(&self, addr: IpAddr, port: u16, event_time: i64) -> Option<OwnedUdpEndpoint> {
        let closed = self.closed.get(&(addr, port))?;
        (closed.endpoint.created > 0
            && closed.endpoint.created <= event_time
            && event_time <= closed.valid_through
            && Instant::now() <= closed.keep_until)
            .then_some(closed.endpoint)
    }

    fn clear(&mut self) {
        self.binds.clear();
        self.closed.clear();
        self.valid_through = 0;
        self.valid_until = 0;
    }

    fn fill_from(
        &mut self,
        live: &HashMap<(IpAddr, u16), UdpBind>,
        valid_through: i64,
        poll_interval: Duration,
    ) {
        self.fill_from_at(
            live,
            valid_through,
            Instant::now(),
            CLOSED_OWNER_GRACE,
            poll_interval,
        );
    }

    fn fill_from_at(
        &mut self,
        live: &HashMap<(IpAddr, u16), UdpBind>,
        valid_through: i64,
        now: Instant,
        grace: Duration,
        poll_interval: Duration,
    ) {
        self.closed.retain(|key, entry| {
            now < entry.keep_until && !same_udp_bind(live.get(key), entry.endpoint)
        });
        let keep_until = now.checked_add(grace).unwrap_or(now);
        for (key, bind) in &self.binds {
            if let UdpBind::Unique(endpoint) = bind
                && !same_udp_bind(live.get(key), *endpoint)
            {
                self.closed.insert(
                    *key,
                    ClosedUdpBind {
                        endpoint: *endpoint,
                        valid_through,
                        keep_until,
                    },
                );
            }
        }
        trim_closed_udp(&mut self.closed);
        self.binds.clear();
        self.binds
            .extend(live.iter().map(|(key, bind)| (*key, *bind)));
        self.valid_through = valid_through;
        let ticks = i64::try_from(poll_interval.as_nanos() / 100).unwrap_or(i64::MAX);
        self.valid_until = valid_through.saturating_add(ticks);
    }
}

/// Count plus sample time from a successful TCP owner-table poll.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SocketCountSample {
    /// Established TCP connections: owned rows with both ports whose state is established
    /// (`TcpState::is_established`).
    pub count: u32,
    /// Unix epoch milliseconds when the table was read.
    pub sampled_at_ms: u64,
}

/// How long a published TCP count may be reused before RPC walks `OWNER_PID`.
const TCP_COUNT_TTL: Duration = Duration::from_secs(5);

#[derive(Clone, Copy, Debug)]
struct CachedTcpCount {
    sample: SocketCountSample,
    sampled_at: Instant,
}

static LAST_TCP_COUNT: Mutex<Option<CachedTcpCount>> = Mutex::new(None);

fn cached_tcp_count() -> Option<CachedTcpCount> {
    LAST_TCP_COUNT
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .as_ref()
        .copied()
}

fn store_tcp_socket_count(sample: SocketCountSample) {
    *LAST_TCP_COUNT
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(CachedTcpCount {
        sample,
        sampled_at: Instant::now(),
    });
}

/// Fresh cache → that count. Stale or missing cache → `OWNER_PID` walker.
/// Walker failure keeps last-known and marks it stale; never sampled and walker
/// failure is unavailable.
pub fn active_tcp_socket_count() -> SocketCount {
    let (count, refresh) = resolve_tcp_socket_count(
        cached_tcp_count(),
        Instant::now(),
        TCP_COUNT_TTL,
        count_owner_pid_tables,
    );
    if let Some(count) = refresh {
        store_tcp_socket_count(SocketCountSample {
            count,
            sampled_at_ms: unix_now_ms(),
        });
    }
    count
}

/// Returns `(report, Some(count))` when the cache should be overwritten with a new sample.
fn resolve_tcp_socket_count(
    cached: Option<CachedTcpCount>,
    now: Instant,
    ttl: Duration,
    fresh_read: impl FnOnce() -> Result<u32, String>,
) -> (SocketCount, Option<u32>) {
    if let Some(cached) = cached {
        if now.saturating_duration_since(cached.sampled_at) < ttl {
            return (SocketCount::fresh(cached.sample.count), None);
        }
        return match fresh_read() {
            Ok(count) => (SocketCount::fresh(count), Some(count)),
            Err(_) => (SocketCount::stale(cached.sample.count), None),
        };
    }
    match fresh_read() {
        Ok(count) => (SocketCount::fresh(count), Some(count)),
        Err(_) => (SocketCount::UNAVAILABLE, None),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct TcpSeen {
    pid: u32,
    created: i64,
    /// Whether the connection's state is established (`TcpState::is_established`). Such a
    /// row is opened as a flow by the first poll, and is counted as an active connection.
    established: bool,
}

impl TcpSeen {
    fn cookie(self) -> SocketCookie {
        SocketCookie {
            #[allow(clippy::cast_sign_loss)]
            value: self.created as u64,
            source: CookieSource::WindowsCreateTimestamp,
        }
    }
}

/// A local TCP bind paired with its owning PID.
type ListenerOwner = ((IpAddr, u16), TcpSeen);

fn insert_tcp_listener(
    map: &mut HashMap<(IpAddr, u16), Option<TcpSeen>>,
    endpoint: (IpAddr, u16),
    owner: TcpSeen,
) {
    if owner.pid == 0 {
        return;
    }
    match map.get_mut(&endpoint) {
        Some(existing) => {
            if *existing != Some(owner) {
                *existing = None;
            }
        }
        None => {
            map.insert(endpoint, Some(owner));
        }
    }
}

fn lookup_listener_owner(
    listeners: &HashMap<(IpAddr, u16), Option<TcpSeen>>,
    addr: IpAddr,
    port: u16,
) -> Option<TcpSeen> {
    let exact = (addr, port);
    if let Some(owner) = listeners.get(&exact) {
        return *owner;
    }
    let wildcard = (unspecified_address(addr), port);
    if wildcard != exact
        && let Some(owner) = listeners.get(&wildcard)
    {
        return *owner;
    }
    None
}

fn same_tcp_socket(live: Option<&TcpSeen>, pid: u32, created: i64) -> bool {
    live.is_some_and(|live| live.pid == pid && live.created == created)
}

fn same_udp_bind(live: Option<&UdpBind>, endpoint: OwnedUdpEndpoint) -> bool {
    matches!(live, Some(UdpBind::Unique(current)) if *current == endpoint)
}

fn trim_closed_tcp(closed: &mut HashMap<FlowKey, ClosedTcpSeen>) {
    trim_closed(closed, |entry| entry.keep_until);
}

fn trim_closed_udp(closed: &mut HashMap<(IpAddr, u16), ClosedUdpBind>) {
    trim_closed(closed, |entry| entry.keep_until);
}

fn trim_closed<K, V>(closed: &mut HashMap<K, V>, keep_until: impl Fn(&V) -> Instant)
where
    K: Copy + Eq + Hash,
{
    if closed.len() <= MAX_CLOSED_OWNERS {
        return;
    }
    let mut deadlines: Vec<(Instant, K)> = closed
        .iter()
        .map(|(key, entry)| (keep_until(entry), *key))
        .collect();
    deadlines.sort_unstable_by_key(|(deadline, _)| *deadline);
    let drop_count = closed.len() - MAX_CLOSED_OWNERS;
    for (_, key) in deadlines.into_iter().take(drop_count) {
        closed.remove(&key);
    }
}

fn insert_udp_bind(map: &mut HashMap<(IpAddr, u16), UdpBind>, endpoint: OwnedUdpEndpoint) {
    match map.entry(endpoint.key()) {
        std::collections::hash_map::Entry::Vacant(entry) => {
            entry.insert(UdpBind::Unique(endpoint));
        }
        std::collections::hash_map::Entry::Occupied(mut entry) => match entry.get() {
            UdpBind::Ambiguous => {}
            UdpBind::Unique(existing)
                if existing.created == endpoint.created && existing.pid == endpoint.pid => {}
            UdpBind::Unique(_) => {
                entry.insert(UdpBind::Ambiguous);
            }
        },
    }
}
