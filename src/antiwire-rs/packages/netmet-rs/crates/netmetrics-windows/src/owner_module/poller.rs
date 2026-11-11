//! Reusable owner-table polling buffers, snapshot publication, and lifecycle events.

use super::tables::{AlignedBuffer, fetch_rows, ingest_tcp, ingest_tcp_listeners, ingest_udp};
use super::{
    SocketCountSample, TcpOwnerSnapshot, TcpSeen, UdpBind, UdpOwnerSnapshot, store_tcp_socket_count,
};
use crate::filetime::filetime_now;
use arc_swap::ArcSwap;
use netmetrics_core::{FlowKey, Protocol, SocketCookie};
use netmetrics_sys::{BackendEvent, EventSink};
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;
use windows::Win32::NetworkManagement::IpHelper::{
    MIB_TCP6ROW_OWNER_MODULE, MIB_TCPROW_OWNER_MODULE, MIB_UDP6ROW_OWNER_MODULE,
    MIB_UDPROW_OWNER_MODULE,
};

/// First poll opens the row. Later polls only attach a cookie to a flow ETW already tracks.
pub(crate) fn tcp_table_event(
    seed: bool,
    key: FlowKey,
    pid: u32,
    cookie: SocketCookie,
    timestamp: u64,
) -> BackendEvent {
    if seed {
        BackendEvent::Opened {
            key,
            pid,
            cookie: Some(cookie),
            timestamp,
            if_index: None,
        }
    } else {
        BackendEvent::CookieResolved {
            key,
            pid,
            cookie,
            timestamp,
        }
    }
}

pub(super) fn emit_tcp_table_row(
    sink: &EventSink,
    pending_seed: &mut HashSet<FlowKey>,
    seed: bool,
    key: FlowKey,
    row: TcpSeen,
    timestamp: u64,
) {
    if sink.emit(tcp_table_event(seed, key, row.pid, row.cookie(), timestamp)) {
        pending_seed.remove(&key);
    } else if seed {
        pending_seed.insert(key);
    }
}

/// Supplies socket identity alongside the callback-driven ETW stream.
///
/// ETW owns flow lifecycle; this only reports identity. Steady state is silent, because an
/// unchanged connection re-reports the same timestamp, so the cost is one extra `Opened`
/// per TCP socket over its lifetime.
#[derive(Debug)]
pub(crate) struct CookiePoller {
    poll_interval: Duration,
    tcp4: AlignedBuffer,
    tcp6: AlignedBuffer,
    udp4: AlignedBuffer,
    udp6: AlignedBuffer,
    seen_tcp: HashMap<FlowKey, TcpSeen>,
    working_tcp: HashMap<FlowKey, TcpSeen>,
    working_listeners: HashMap<(IpAddr, u16), Option<TcpSeen>>,
    seen_udp: HashMap<(IpAddr, u16), UdpBind>,
    pub(super) working_udp: HashMap<(IpAddr, u16), UdpBind>,
    tcp_owners: Arc<ArcSwap<TcpOwnerSnapshot>>,
    udp_owners: Arc<ArcSwap<UdpOwnerSnapshot>>,
    spare_tcp: Option<Arc<TcpOwnerSnapshot>>,
    spare_udp: Option<Arc<UdpOwnerSnapshot>>,
    /// False until the first successful TCP poll has seeded existing connections.
    tcp_seeded: bool,
    /// First-poll opens rejected by the bounded control channel are retried.
    pending_tcp_seed: HashSet<FlowKey>,
    /// UDP closes the channel rejected, oldest first, retried on later polls.
    /// In ETW mode this poller is the only source of UDP closes, so a lost one
    /// would leave its flows open until the idle timeout.
    pub(super) pending_udp_closes: Vec<PendingUdpClose>,
}

/// Bound on [`CookiePoller::pending_udp_closes`]; the oldest are dropped first.
const PENDING_UDP_CLOSE_CAPACITY: usize = 4_096;

#[derive(Clone, Copy, Debug)]
pub(super) struct PendingUdpClose {
    pub(super) key: (IpAddr, u16),
    pub(super) cookie: Option<SocketCookie>,
    pub(super) timestamp: u64,
}

impl PendingUdpClose {
    fn event(self) -> BackendEvent {
        BackendEvent::LocalEndpointClosed {
            protocol: Protocol::Udp,
            local_addr: self.key.0,
            local_port: self.key.1,
            cookie: self.cookie,
            timestamp: self.timestamp,
        }
    }
}

impl CookiePoller {
    pub fn new(
        tcp_owners: Arc<ArcSwap<TcpOwnerSnapshot>>,
        udp_owners: Arc<ArcSwap<UdpOwnerSnapshot>>,
        poll_interval: Duration,
    ) -> Self {
        Self {
            poll_interval,
            tcp4: AlignedBuffer::new(),
            tcp6: AlignedBuffer::new(),
            udp4: AlignedBuffer::new(),
            udp6: AlignedBuffer::new(),
            seen_tcp: HashMap::new(),
            working_tcp: HashMap::new(),
            working_listeners: HashMap::new(),
            seen_udp: HashMap::new(),
            working_udp: HashMap::new(),
            tcp_owners,
            udp_owners,
            spare_tcp: None,
            spare_udp: None,
            tcp_seeded: false,
            pending_tcp_seed: HashSet::new(),
            pending_udp_closes: Vec::new(),
        }
    }

    /// Reports identity for every socket whose timestamp differs from the last reported.
    ///
    /// A tuple that disappears is forgotten, so its reappearance is reported again.
    /// The first successful poll emits `Opened` for established and close-wait rows
    /// so a connection the process still holds is tracked before its next byte.
    /// Other states stay in the owner map and emit `CookieResolved`, which never
    /// creates a flow. Later polls only attach a cookie.
    ///
    /// TCP and UDP tables are polled independently: a UDP failure does not imply every bind
    /// disappeared, and does not roll back a successful TCP poll.
    pub fn poll(&mut self, sink: &EventSink, timestamp: u64) -> Result<(), String> {
        let tcp = self.poll_tcp(sink, timestamp);
        let udp = self.poll_udp(sink, timestamp);
        match (tcp, udp) {
            (Ok(()), Ok(())) => Ok(()),
            (Err(error), Ok(())) | (Ok(()), Err(error)) => Err(error),
            (Err(tcp_error), Err(udp_error)) => Err(format!("tcp: {tcp_error}; udp: {udp_error}")),
        }
    }

    fn poll_tcp(&mut self, sink: &EventSink, timestamp: u64) -> Result<(), String> {
        // Every row returned below was observed no earlier than this point. An event at or
        // before this boundary therefore occurred while a returned socket was still alive.
        let valid_through = filetime_now();
        let rows4 = fetch_rows::<MIB_TCPROW_OWNER_MODULE>(&mut self.tcp4)?;
        let rows6 = fetch_rows::<MIB_TCP6ROW_OWNER_MODULE>(&mut self.tcp6)?;
        self.working_tcp.clear();
        self.working_listeners.clear();
        ingest_tcp(rows4, &mut self.working_tcp);
        ingest_tcp(rows6, &mut self.working_tcp);
        ingest_tcp_listeners(rows4, &mut self.working_listeners);
        ingest_tcp_listeners(rows6, &mut self.working_listeners);
        let seed = !self.tcp_seeded;
        for (key, seen) in &self.working_tcp {
            let needs_seed = seen.seeds_flow && (seed || self.pending_tcp_seed.contains(key));
            if !needs_seed
                && self
                    .seen_tcp
                    .get(key)
                    .is_some_and(|previous| previous.created == seen.created)
            {
                continue;
            }
            emit_tcp_table_row(
                sink,
                &mut self.pending_tcp_seed,
                needs_seed,
                *key,
                *seen,
                timestamp,
            );
        }
        self.tcp_seeded = true;
        self.pending_tcp_seed
            .retain(|key| self.working_tcp.contains_key(key));
        let count = u32::try_from(self.working_tcp.len()).unwrap_or(u32::MAX);
        store_tcp_socket_count(SocketCountSample {
            count,
            sampled_at_ms: timestamp,
        });
        self.publish_tcp_snapshot(valid_through);
        std::mem::swap(&mut self.seen_tcp, &mut self.working_tcp);
        self.working_tcp.clear();
        Ok(())
    }

    fn publish_tcp_snapshot(&mut self, valid_through: i64) {
        let previous = self.tcp_owners.load();
        let mut snapshot = self.take_exclusive_tcp_snapshot();
        snapshot.sockets.clone_from(&self.seen_tcp);
        snapshot.closed.clone_from(&previous.closed);
        snapshot.listeners.clone_from(&self.working_listeners);
        snapshot.fill_from(&self.working_tcp, valid_through, self.poll_interval);
        let published = Arc::new(snapshot);
        let old = self.tcp_owners.swap(published);
        self.spare_tcp = None;
        if Arc::strong_count(&old) == 1 {
            let mut old = old;
            if let Some(inner) = Arc::get_mut(&mut old) {
                inner.clear();
                self.spare_tcp = Some(old);
            }
        }
    }

    fn take_exclusive_tcp_snapshot(&mut self) -> TcpOwnerSnapshot {
        if let Some(mut spare) = self.spare_tcp.take()
            && let Some(inner) = Arc::get_mut(&mut spare)
        {
            return std::mem::take(inner);
        }
        TcpOwnerSnapshot::default()
    }

    fn poll_udp(&mut self, sink: &EventSink, timestamp: u64) -> Result<(), String> {
        let valid_through = filetime_now();
        let rows4 = fetch_rows::<MIB_UDPROW_OWNER_MODULE>(&mut self.udp4)?;
        let rows6 = fetch_rows::<MIB_UDP6ROW_OWNER_MODULE>(&mut self.udp6)?;
        self.working_udp.clear();
        ingest_udp(rows4, &mut self.working_udp);
        ingest_udp(rows6, &mut self.working_udp);
        for (key, previous) in &self.seen_udp {
            if self.working_udp.contains_key(key) {
                continue;
            }
            let cookie = match previous {
                UdpBind::Unique(endpoint) => Some(endpoint.cookie()),
                UdpBind::Ambiguous => None,
            };
            self.pending_udp_closes.push(PendingUdpClose {
                key: *key,
                cookie,
                timestamp,
            });
        }
        self.emit_udp_closes(sink);
        self.publish_udp_snapshot(valid_through);
        std::mem::swap(&mut self.seen_udp, &mut self.working_udp);
        self.working_udp.clear();
        Ok(())
    }

    /// Emits pending UDP closes in order, keeping those the channel rejects.
    pub(super) fn emit_udp_closes(&mut self, sink: &EventSink) {
        let working = &self.working_udp;
        // Once a new socket binds the endpoint, a late close would also end
        // its flows that carry no cookie yet.
        self.pending_udp_closes
            .retain(|close| !working.contains_key(&close.key));
        let mut accepting = true;
        self.pending_udp_closes.retain(|close| {
            accepting = accepting && sink.emit(close.event());
            !accepting
        });
        let excess = self
            .pending_udp_closes
            .len()
            .saturating_sub(PENDING_UDP_CLOSE_CAPACITY);
        self.pending_udp_closes.drain(..excess);
    }

    fn publish_udp_snapshot(&mut self, valid_through: i64) {
        let previous = self.udp_owners.load();
        let mut snapshot = self.take_exclusive_snapshot();
        snapshot.binds.clone_from(&self.seen_udp);
        snapshot.closed.clone_from(&previous.closed);
        snapshot.fill_from(&self.working_udp, valid_through, self.poll_interval);
        let published = Arc::new(snapshot);
        let old = self.udp_owners.swap(Arc::clone(&published));
        self.spare_udp = None;
        if Arc::strong_count(&old) == 1 {
            let mut old = old;
            if let Some(inner) = Arc::get_mut(&mut old) {
                inner.clear();
                self.spare_udp = Some(old);
            }
        }
        let _ = published;
    }

    fn take_exclusive_snapshot(&mut self) -> UdpOwnerSnapshot {
        if let Some(mut spare) = self.spare_udp.take()
            && let Some(inner) = Arc::get_mut(&mut spare)
        {
            let snapshot = std::mem::take(inner);
            return snapshot;
        }
        UdpOwnerSnapshot::default()
    }
}
