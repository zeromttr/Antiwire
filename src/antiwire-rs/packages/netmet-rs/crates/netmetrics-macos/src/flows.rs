//! The flows the macOS backend has announced and not yet closed.
//!
//! PKTAP capture and the socket-table fallback keep one table, and it passes from one to the
//! other when the backend switches between them. A flow either one announced is not
//! announced again by the other, and every flow stays with one that closes it when its socket
//! goes, so a switch neither repeats nor strands a flow.

use crate::pktap::TcpFlags;
use netmetrics_core::{ByteDelta, FlowKey, Protocol, SocketCookie, TcpState, unspecified_address};
use netmetrics_sys::{BackendEvent, EventSink};
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;

/// How long a captured UDP flow may go without a packet before it is closed, bound or not.
const FLOW_IDLE_MS: u64 = 300_000;
/// How long after its last packet a captured flow whose socket the table no longer lists
/// stays open.
const SOCKET_GONE_GRACE_MS: u64 = 2_000;

/// The local address and port of each bound UDP socket on the host.
#[derive(Debug, Default)]
pub(crate) struct UdpBinds(HashSet<(IpAddr, u16)>);

impl UdpBinds {
    /// Records a bound socket.
    pub(crate) fn insert(&mut self, address: IpAddr, port: u16) {
        self.0.insert((address, port));
    }

    /// Whether the socket a UDP flow uses is still bound, to its own address or to the
    /// wildcard.
    fn hold(&self, key: &FlowKey) -> bool {
        self.0.contains(&(key.local_addr, key.local_port))
            || self
                .0
                .contains(&(unspecified_address(key.local_addr), key.local_port))
    }
}

/// The sockets the table lists, as capture checks its flows against them.
#[derive(Debug, Default)]
pub(crate) struct SocketCoverage {
    /// Connected TCP sockets, listeners left out.
    pub(crate) tcp: HashSet<FlowKey>,
    /// Bound UDP sockets.
    pub(crate) udp_binds: UdpBinds,
}

/// The socket table as the fallback reads it. Its connections are the flows the fallback
/// lists, and their number is the count of active connections.
#[derive(Debug, Default)]
pub(crate) struct SocketTable {
    /// Established TCP connections ([`TcpState::is_established`]), each with a process
    /// that holds it.
    pub(crate) connections: HashMap<FlowKey, u32>,
    /// Bound UDP sockets.
    pub(crate) udp_binds: UdpBinds,
}

impl SocketTable {
    /// Lists the TCP socket of one table row when it is an established connection: `key`
    /// is its addresses, `state` its state when the row names one, and `pid` the process
    /// whose descriptor the row was read through.
    ///
    /// The table has a row for each descriptor of each process, so a socket that several
    /// descriptors refer to, in one process or in several, has several rows. It is listed
    /// once, under the process of the row read last.
    pub(crate) fn list_tcp(&mut self, key: FlowKey, state: Option<TcpState>, pid: u32) {
        if state.is_some_and(TcpState::is_established)
            && key.local_port != 0
            && key.remote_port != 0
            && pid != 0
        {
            self.connections.insert(key, pid);
        }
    }
}

/// Where a flow is in its life.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Phase {
    /// A TCP connection whose handshake has not been seen to complete. It is not announced,
    /// and `held` is what its packets have carried so far.
    Handshake { held: ByteDelta },
    /// Announced. A TCP connection is established.
    Open,
    /// Announced, and reported finishing: this host has sent its FIN.
    Finishing,
}

#[derive(Clone, Copy, Debug)]
struct KnownFlow {
    /// The process that owns it, zero when unknown.
    pid: u32,
    /// The identity of its socket, once a packet or the fallback has given one.
    cookie: Option<SocketCookie>,
    /// When it was last seen, in Unix epoch milliseconds.
    last_seen: u64,
    phase: Phase,
}

impl KnownFlow {
    /// Whether the flow was reported open, and so has to be reported closed.
    fn announced(&self) -> bool {
        !matches!(self.phase, Phase::Handshake { .. })
    }
}

/// What capture read from one packet.
#[derive(Clone, Copy, Debug)]
pub(crate) struct SeenPacket {
    pub(crate) key: FlowKey,
    /// The process the packet is attributed to, zero when unknown.
    pub(crate) pid: u32,
    /// The identity of the packet's socket, when the packet names it.
    pub(crate) cookie: Option<SocketCookie>,
    pub(crate) if_index: Option<u32>,
    /// The bytes the packet carried.
    pub(crate) delta: ByteDelta,
    /// Whether this host sent the packet.
    pub(crate) outbound: bool,
    /// The control bits of a TCP segment. A UDP datagram has none.
    pub(crate) tcp_flags: Option<TcpFlags>,
}

/// Flows capture or the fallback has seen and not yet closed.
///
/// A UDP flow is announced at its first packet. A TCP flow follows its connection, as the
/// other platforms' flows do, so that a flow is open exactly while its connection is one
/// the active count takes (`TcpState::is_established`):
///
/// - It is announced when a segment shows the handshake is over
///   ([`TcpFlags::past_handshake`]). What the handshake's own segments carried is held
///   until then and reported with it. A connection that is never established is never
///   announced, and what its segments carried is dropped: a refused or unanswered
///   connection attempt is no flow on Linux or Windows either.
/// - It is reported finishing when this host sends a FIN, which it does only once it has
///   left `ESTABLISHED` or `CLOSE_WAIT` (`tcp_usrclosed` in XNU's
///   `bsd/netinet/tcp_usrreq.c` moves them to `FIN_WAIT_1` and `LAST_ACK`). The peer's FIN
///   does not finish it: this host is then in `CLOSE_WAIT` and can still send.
/// - It is closed when its socket leaves the socket table.
#[derive(Debug)]
pub(crate) struct KnownFlows {
    flows: HashMap<FlowKey, KnownFlow>,
    /// Flows capture keeps before it drops the one seen least recently.
    capacity: usize,
}

impl KnownFlows {
    /// An empty table for at most `capacity` captured flows.
    pub(crate) fn new(capacity: usize) -> Self {
        Self {
            flows: HashMap::new(),
            capacity,
        }
    }

    /// Capture saw `packet`. Announces its flow, or reports it finishing, when the packet
    /// shows that, and returns the bytes to report for the flow now: the packet's, with
    /// what was held for the flow, or nothing while the flow is not announced.
    pub(crate) fn saw_packet(
        &mut self,
        packet: &SeenPacket,
        timestamp: u64,
        sink: &EventSink,
    ) -> ByteDelta {
        let key = packet.key;
        // This host begins a connection here, so an announced flow on the same addresses
        // belonged to an earlier one, whose socket has gone.
        if packet.outbound
            && packet.tcp_flags.is_some_and(TcpFlags::begins_connection)
            && self.flows.get(&key).is_some_and(KnownFlow::announced)
        {
            self.flows.remove(&key);
            sink.emit(BackendEvent::Closed {
                pid: 0,
                key,
                timestamp,
            });
        }
        if !self.flows.contains_key(&key) {
            self.make_room(timestamp, sink);
        }
        let flow = self.flows.entry(key).or_insert(KnownFlow {
            pid: packet.pid,
            cookie: packet.cookie,
            last_seen: timestamp,
            phase: Phase::Handshake {
                held: ByteDelta::default(),
            },
        });
        flow.last_seen = timestamp;
        if flow.pid == 0 {
            flow.pid = packet.pid;
        }
        // The socket's flow ID is its identity. A flow whose first packet arrived from
        // outside has none yet and learns it from the first packet it sends.
        if flow.cookie.is_none() {
            flow.cookie = packet.cookie;
        }
        let mut report = packet.delta;
        if let Phase::Handshake { mut held } = flow.phase {
            held.saturating_add_assign(packet.delta);
            if packet
                .tcp_flags
                .is_some_and(|flags| !flags.past_handshake())
            {
                flow.phase = Phase::Handshake { held };
                return ByteDelta::default();
            }
            flow.phase = Phase::Open;
            report = held;
            sink.emit(BackendEvent::Opened {
                key,
                pid: flow.pid,
                cookie: flow.cookie,
                timestamp,
                if_index: packet.if_index,
            });
        }
        if flow.phase == Phase::Open
            && packet.outbound
            && packet.tcp_flags.is_some_and(TcpFlags::fin)
        {
            flow.phase = Phase::Finishing;
            sink.emit(BackendEvent::Finishing { key, timestamp });
        }
        report
    }

    /// Drops the flow seen least recently when the table is full, closing it if it was
    /// announced.
    fn make_room(&mut self, timestamp: u64, sink: &EventSink) {
        if self.flows.len() < self.capacity {
            return;
        }
        let Some(evicted) = self
            .flows
            .iter()
            .min_by_key(|(key, flow)| (flow.last_seen, **key))
            .map(|(key, _)| *key)
        else {
            return;
        };
        if self
            .flows
            .remove(&evicted)
            .is_some_and(|flow| flow.announced())
        {
            sink.emit(BackendEvent::Closed {
                pid: 0,
                key: evicted,
                timestamp,
            });
        }
    }

    /// Closes the flows whose socket `coverage` no longer lists, once
    /// [`SOCKET_GONE_GRACE_MS`] has passed since their last packet, and UDP flows that have
    /// gone [`FLOW_IDLE_MS`] without one.
    ///
    /// `timestamp` is when `coverage` was read, which may be a while before it is applied.
    /// A flow is judged by how long before that reading its last packet came, so one that
    /// began, or sent a packet, after the reading is never closed by it.
    pub(crate) fn close_missing(
        &mut self,
        coverage: &SocketCoverage,
        timestamp: u64,
        sink: &EventSink,
    ) {
        self.close_where(timestamp, sink, |key, flow| {
            let age = timestamp.saturating_sub(flow.last_seen);
            match key.protocol {
                Protocol::Tcp => {
                    !coverage.tcp.contains(key)
                        && !coverage.tcp.contains(&key.reverse())
                        && age >= SOCKET_GONE_GRACE_MS
                }
                Protocol::Udp => {
                    (!coverage.udp_binds.hold(key) && age >= SOCKET_GONE_GRACE_MS)
                        || age >= FLOW_IDLE_MS
                }
            }
        });
    }

    /// Closes UDP flows that have gone [`FLOW_IDLE_MS`] without a packet, for when capture
    /// cannot read the socket table.
    pub(crate) fn expire_idle_udp(&mut self, timestamp: u64, sink: &EventSink) {
        self.close_where(timestamp, sink, |key, flow| {
            key.protocol == Protocol::Udp
                && timestamp.saturating_sub(flow.last_seen) >= FLOW_IDLE_MS
        });
    }

    /// Brings the table in line with the socket table while capture is down.
    ///
    /// A connection the table lists is established. One not announced yet, or announced
    /// under another process, or already reported finishing, is announced: the last is a new
    /// connection on the addresses of one whose end was not seen. The table has no socket
    /// token, so its cookie is derived from the tuple, the owner and this first sight. A TCP
    /// flow the table no longer lists is closed. UDP flows come only from
    /// capture, and without packets nothing shows one has gone idle, so each stays open while
    /// its socket is bound. A flow the table still shows counts as seen now, so capture, once
    /// back, measures its idleness from then.
    pub(crate) fn apply_snapshot(&mut self, table: &SocketTable, timestamp: u64, sink: &EventSink) {
        for (key, pid) in &table.connections {
            if self
                .flows
                .get(key)
                .is_some_and(|flow| flow.pid == *pid && flow.phase == Phase::Open)
            {
                continue;
            }
            let cookie = Some(SocketCookie::synthetic(*key, *pid, timestamp));
            self.flows.insert(
                *key,
                KnownFlow {
                    pid: *pid,
                    cookie,
                    last_seen: timestamp,
                    phase: Phase::Open,
                },
            );
            sink.emit(BackendEvent::Opened {
                key: *key,
                pid: *pid,
                cookie,
                timestamp,
                if_index: None,
            });
        }
        self.close_where(timestamp, sink, |key, flow| {
            let listed = match key.protocol {
                Protocol::Tcp => table.connections.contains_key(key),
                Protocol::Udp => table.udp_binds.hold(key),
            };
            if listed {
                flow.last_seen = timestamp;
            }
            !listed
        });
    }

    /// Closes every flow, for when the backend stops.
    pub(crate) fn close_all(&mut self, timestamp: u64, sink: &EventSink) {
        self.close_where(timestamp, sink, |_, _| true);
    }

    /// Removes each flow `gone` picks, and reports it closed if it was announced. `gone`
    /// may update the flows it keeps.
    fn close_where(
        &mut self,
        timestamp: u64,
        sink: &EventSink,
        mut gone: impl FnMut(&FlowKey, &mut KnownFlow) -> bool,
    ) {
        self.flows.retain(|key, flow| {
            let closed = gone(key, flow);
            if closed && flow.announced() {
                sink.emit(BackendEvent::Closed {
                    key: *key,
                    pid: 0,
                    timestamp,
                });
            }
            !closed
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use netmetrics_core::CookieSource;
    use std::net::Ipv4Addr;
    use std::sync::Arc;
    use std::sync::atomic::AtomicU64;
    use std::sync::mpsc::{Receiver, sync_channel};

    /// The process every fixture flow belongs to.
    const PID: u32 = 7;
    const START: u64 = 1_000_000;

    /// A sink whose events the test reads back.
    fn sink() -> (EventSink, Receiver<BackendEvent>) {
        let (sender, receiver) = sync_channel(1_024);
        (
            EventSink::new(sender, Arc::new(AtomicU64::new(0))),
            receiver,
        )
    }

    /// A flow from one fixed local address, told apart by `local_port`.
    fn key(protocol: Protocol, local_port: u16) -> FlowKey {
        FlowKey {
            protocol,
            local_addr: Ipv4Addr::new(192, 0, 2, 10).into(),
            local_port,
            remote_addr: Ipv4Addr::new(198, 51, 100, 20).into(),
            remote_port: 443,
        }
    }

    const ACK: u8 = 0x10;
    const SYN: u8 = 0x02;
    const FIN: u8 = 0x01;
    const RST: u8 = 0x04;

    /// A packet of `key`'s flow that this host sent, carrying 100 bytes. A TCP one has
    /// the control bits `flags`.
    fn segment(key: FlowKey, flags: u8, cookie: Option<SocketCookie>) -> SeenPacket {
        SeenPacket {
            key,
            pid: PID,
            cookie,
            if_index: None,
            delta: ByteDelta {
                sent: 100,
                received: 0,
            },
            outbound: true,
            tcp_flags: (key.protocol == Protocol::Tcp).then(|| TcpFlags::new(flags)),
        }
    }

    /// The same packet as this host received it.
    fn inbound(packet: SeenPacket) -> SeenPacket {
        SeenPacket {
            outbound: false,
            delta: ByteDelta {
                sent: packet.delta.received,
                received: packet.delta.sent,
            },
            ..packet
        }
    }

    /// A packet of an established connection, or a datagram.
    fn data(key: FlowKey, cookie: Option<SocketCookie>) -> SeenPacket {
        segment(key, ACK, cookie)
    }

    fn finishing(events: &[BackendEvent]) -> Vec<FlowKey> {
        events
            .iter()
            .filter_map(|event| match event {
                BackendEvent::Finishing { key, .. } => Some(*key),
                _ => None,
            })
            .collect()
    }

    /// The segments of a handshake this host begins are held, and the connection is
    /// announced with what they carried once the third one shows it established.
    #[test]
    fn a_connection_is_announced_when_its_handshake_completes() {
        let (sink, events) = sink();
        let tcp = key(Protocol::Tcp, 50_000);
        let mut flows = KnownFlows::new(8);
        let syn = flows.saw_packet(&segment(tcp, SYN, Some(flow_id(tcp))), START, &sink);
        let syn_ack = flows.saw_packet(&inbound(segment(tcp, SYN | ACK, None)), START + 1, &sink);
        assert_eq!((syn, syn_ack), (ByteDelta::default(), ByteDelta::default()));
        assert!(
            events.try_iter().next().is_none(),
            "nothing is announced yet"
        );

        let ack = flows.saw_packet(&segment(tcp, ACK, Some(flow_id(tcp))), START + 2, &sink);
        assert_eq!(
            ack,
            ByteDelta {
                sent: 200,
                received: 100
            },
            "the handshake's bytes are reported with the announcement"
        );
        let announced: Vec<_> = events.try_iter().collect();
        assert!(matches!(
            announced.as_slice(),
            [BackendEvent::Opened { key, pid: PID, cookie, .. }]
                if *key == tcp && *cookie == Some(flow_id(tcp))
        ));
    }

    /// The handshake of a connection this host accepts ends with a segment it receives.
    #[test]
    fn an_accepted_connection_is_announced_when_the_third_segment_arrives() {
        let (sink, events) = sink();
        let tcp = key(Protocol::Tcp, 443);
        let mut flows = KnownFlows::new(8);
        flows.saw_packet(&inbound(segment(tcp, SYN, None)), START, &sink);
        flows.saw_packet(
            &segment(tcp, SYN | ACK, Some(flow_id(tcp))),
            START + 1,
            &sink,
        );
        assert!(events.try_iter().next().is_none());
        flows.saw_packet(&inbound(segment(tcp, ACK, None)), START + 2, &sink);
        assert_eq!(opened(&events.try_iter().collect::<Vec<_>>()), [tcp]);
    }

    /// A refused attempt is answered with a reset and one that times out with nothing.
    /// Neither is a flow: nothing is announced, nothing closed, and no bytes reported.
    #[test]
    fn a_connection_that_is_never_established_is_never_a_flow() {
        let (sink, events) = sink();
        let refused = key(Protocol::Tcp, 50_000);
        let unanswered = key(Protocol::Tcp, 50_001);
        let mut flows = KnownFlows::new(8);
        let mut reported = ByteDelta::default();
        for packet in [
            segment(refused, SYN, Some(flow_id(refused))),
            inbound(segment(refused, RST | ACK, None)),
            segment(unanswered, SYN, Some(flow_id(unanswered))),
            segment(unanswered, SYN, Some(flow_id(unanswered))),
        ] {
            reported.saturating_add_assign(flows.saw_packet(&packet, START, &sink));
        }
        flows.close_missing(
            &SocketCoverage::default(),
            START + SOCKET_GONE_GRACE_MS,
            &sink,
        );
        assert_eq!(reported, ByteDelta::default());
        assert!(events.try_iter().next().is_none());
        assert!(flows.flows.is_empty(), "the attempts are forgotten");
    }

    /// This host's FIN reports the flow finishing, once, and the flow stays known for the
    /// bytes that follow until its socket goes.
    #[test]
    fn a_fin_this_host_sends_reports_the_flow_finishing_once() {
        let (sink, events) = sink();
        let tcp = key(Protocol::Tcp, 50_000);
        let mut flows = KnownFlows::new(8);
        flows.saw_packet(&data(tcp, Some(flow_id(tcp))), START, &sink);
        let _ = events.try_iter().count();

        flows.saw_packet(&segment(tcp, FIN | ACK, None), START + 1, &sink);
        flows.saw_packet(&segment(tcp, FIN | ACK, None), START + 2, &sink);
        let after = flows.saw_packet(&inbound(data(tcp, None)), START + 3, &sink);
        assert_eq!(
            after,
            ByteDelta {
                sent: 0,
                received: 100
            },
            "what a finishing flow receives is still its own"
        );
        let reported: Vec<_> = events.try_iter().collect();
        assert_eq!(finishing(&reported), [tcp]);
        assert!(opened(&reported).is_empty() && closed(&reported).is_empty());

        flows.close_missing(
            &SocketCoverage::default(),
            START + 3 + SOCKET_GONE_GRACE_MS,
            &sink,
        );
        assert_eq!(closed(&events.try_iter().collect::<Vec<_>>()), [tcp]);
    }

    /// The peer's FIN leaves this host able to send, so its flow is not finishing.
    #[test]
    fn a_fin_the_peer_sends_does_not_finish_the_flow() {
        let (sink, events) = sink();
        let tcp = key(Protocol::Tcp, 50_000);
        let mut flows = KnownFlows::new(8);
        flows.saw_packet(&data(tcp, None), START, &sink);
        flows.saw_packet(&inbound(segment(tcp, FIN | ACK, None)), START + 1, &sink);
        assert!(finishing(&events.try_iter().collect::<Vec<_>>()).is_empty());
    }

    /// A connection first seen as this host closes it is announced and finishing at once.
    #[test]
    fn a_flow_first_seen_at_its_fin_is_announced_and_finishing() {
        let (sink, events) = sink();
        let tcp = key(Protocol::Tcp, 50_000);
        let mut flows = KnownFlows::new(8);
        flows.saw_packet(&segment(tcp, FIN | ACK, None), START, &sink);
        let reported: Vec<_> = events.try_iter().collect();
        assert_eq!(opened(&reported), [tcp]);
        assert_eq!(finishing(&reported), [tcp]);
    }

    /// A first SYN this host sends on the addresses of an announced flow starts a new
    /// connection, so the old flow is closed and the new one waits for its handshake. A
    /// SYN that acknowledges may be a repeat of this connection's own, and closes nothing.
    #[test]
    fn a_new_connection_on_a_known_flows_addresses_closes_the_old_flow() {
        let (sink, events) = sink();
        let tcp = key(Protocol::Tcp, 50_000);
        let mut flows = KnownFlows::new(8);
        flows.saw_packet(&data(tcp, Some(flow_id(tcp))), START, &sink);
        let _ = events.try_iter().count();

        flows.saw_packet(&segment(tcp, SYN | ACK, None), START + 1, &sink);
        assert!(events.try_iter().next().is_none());

        flows.saw_packet(&segment(tcp, SYN, None), START + 1, &sink);
        let reported: Vec<_> = events.try_iter().collect();
        assert_eq!(closed(&reported), [tcp]);
        assert!(opened(&reported).is_empty());

        flows.saw_packet(&segment(tcp, ACK, None), START + 2, &sink);
        assert_eq!(opened(&events.try_iter().collect::<Vec<_>>()), [tcp]);
    }

    /// The fallback lists established connections. A flow still in its handshake when
    /// capture went down is announced by it, and a finishing one it lists is a new
    /// connection.
    #[test]
    fn the_snapshot_announces_a_connection_capture_had_not_announced() {
        let (sink, events) = sink();
        let pending = key(Protocol::Tcp, 50_000);
        let ending = key(Protocol::Tcp, 50_001);
        let mut flows = KnownFlows::new(8);
        flows.saw_packet(&segment(pending, SYN, None), START, &sink);
        flows.saw_packet(&segment(ending, FIN | ACK, None), START, &sink);
        let _ = events.try_iter().count();

        flows.apply_snapshot(&table(&[pending, ending], &[]), START + 1_000, &sink);
        let mut announced = opened(&events.try_iter().collect::<Vec<_>>());
        announced.sort();
        assert_eq!(announced, [pending, ending]);
    }

    /// The flow ID capture reports for `key`'s socket.
    fn flow_id(key: FlowKey) -> SocketCookie {
        SocketCookie {
            value: u64::from(key.local_port),
            source: CookieSource::MacosFlowId,
        }
    }

    /// A socket table listing `connections`, each owned by [`PID`], and the binds of `udp`.
    fn table(connections: &[FlowKey], udp: &[FlowKey]) -> SocketTable {
        let mut table = SocketTable {
            connections: connections.iter().map(|key| (*key, PID)).collect(),
            udp_binds: UdpBinds::default(),
        };
        for key in udp {
            table.udp_binds.insert(key.local_addr, key.local_port);
        }
        table
    }

    fn opened(events: &[BackendEvent]) -> Vec<FlowKey> {
        events
            .iter()
            .filter_map(|event| match event {
                BackendEvent::Opened { key, .. } => Some(*key),
                _ => None,
            })
            .collect()
    }

    fn closed(events: &[BackendEvent]) -> Vec<FlowKey> {
        let mut keys: Vec<_> = events
            .iter()
            .filter_map(|event| match event {
                BackendEvent::Closed { key, .. } => Some(*key),
                _ => None,
            })
            .collect();
        keys.sort();
        keys
    }

    /// Of a row in every state, only the established and the close-wait one are listed.
    #[test]
    fn the_table_lists_only_established_connections() {
        let states = [
            (TcpState::Closed, false),
            (TcpState::Listen, false),
            (TcpState::SynSent, false),
            (TcpState::SynReceived, false),
            (TcpState::Established, true),
            (TcpState::FinWait1, false),
            (TcpState::FinWait2, false),
            (TcpState::CloseWait, true),
            (TcpState::Closing, false),
            (TcpState::LastAck, false),
            (TcpState::TimeWait, false),
        ];
        let mut table = SocketTable::default();
        let mut expected = HashMap::new();
        for (local_port, (state, listed)) in (50_000..).zip(states) {
            let key = key(Protocol::Tcp, local_port);
            table.list_tcp(key, Some(state), PID);
            if listed {
                expected.insert(key, PID);
            }
        }
        table.list_tcp(key(Protocol::Tcp, 51_000), None, PID);
        assert_eq!(table.connections, expected);
    }

    /// A row without a port or a process is no connection, whatever state it names.
    #[test]
    fn the_table_lists_no_row_without_both_ports_and_a_process() {
        let established = Some(TcpState::Established);
        let mut table = SocketTable::default();
        table.list_tcp(key(Protocol::Tcp, 0), established, PID);
        table.list_tcp(
            FlowKey {
                remote_port: 0,
                ..key(Protocol::Tcp, 50_000)
            },
            established,
            PID,
        );
        table.list_tcp(key(Protocol::Tcp, 50_001), established, 0);
        assert!(table.connections.is_empty(), "{:?}", table.connections);
    }

    /// A socket two descriptors refer to has two rows and is one connection.
    #[test]
    fn a_socket_with_several_descriptors_is_listed_once() {
        let shared = key(Protocol::Tcp, 50_000);
        let mut table = SocketTable::default();
        table.list_tcp(shared, Some(TcpState::Established), PID);
        table.list_tcp(shared, Some(TcpState::Established), PID);
        table.list_tcp(shared, Some(TcpState::Established), PID + 1);
        table.list_tcp(key(Protocol::Tcp, 50_001), Some(TcpState::Established), PID);
        assert_eq!(table.connections.len(), 2);
        assert_eq!(table.connections.get(&shared), Some(&(PID + 1)));
    }

    #[test]
    fn the_snapshot_takes_over_captured_flows_without_announcing_them_again() {
        let (sink, events) = sink();
        let tcp = key(Protocol::Tcp, 50_000);
        let udp = key(Protocol::Udp, 50_001);
        let mut flows = KnownFlows::new(8);
        flows.saw_packet(&data(tcp, Some(flow_id(tcp))), START, &sink);
        flows.saw_packet(&data(udp, Some(flow_id(udp))), START, &sink);
        assert_eq!(opened(&events.try_iter().collect::<Vec<_>>()), [tcp, udp]);

        flows.apply_snapshot(&table(&[tcp], &[udp]), START + 1_000, &sink);
        assert!(
            events.try_iter().next().is_none(),
            "flows capture announced are neither announced again nor closed"
        );
    }

    #[test]
    fn the_snapshot_closes_captured_flows_whose_socket_is_gone() {
        let (sink, events) = sink();
        let tcp = key(Protocol::Tcp, 50_000);
        let udp = key(Protocol::Udp, 50_001);
        let mut flows = KnownFlows::new(8);
        flows.saw_packet(&data(tcp, Some(flow_id(tcp))), START, &sink);
        flows.saw_packet(&data(udp, Some(flow_id(udp))), START, &sink);
        let _ = events.try_iter().count();

        flows.apply_snapshot(&table(&[], &[]), START + 1_000, &sink);
        let mut expected = vec![tcp, udp];
        expected.sort();
        assert_eq!(closed(&events.try_iter().collect::<Vec<_>>()), expected);
    }

    /// Without packets nothing shows a UDP flow has gone idle, so it stays open while its
    /// socket is bound, and capture, once back, gives it the full idle time again.
    #[test]
    fn a_bound_udp_flow_outlasts_a_fallback_longer_than_its_idle_time() {
        let (sink, events) = sink();
        let udp = key(Protocol::Udp, 50_001);
        let mut flows = KnownFlows::new(8);
        flows.saw_packet(&data(udp, Some(flow_id(udp))), START, &sink);
        let _ = events.try_iter().count();

        let back = START + 2 * FLOW_IDLE_MS;
        flows.apply_snapshot(&table(&[], &[udp]), back, &sink);
        let mut coverage = SocketCoverage::default();
        coverage.udp_binds.insert(udp.local_addr, udp.local_port);
        flows.close_missing(&coverage, back + 1_000, &sink);
        assert!(events.try_iter().next().is_none(), "the flow is still open");

        flows.close_missing(&coverage, back + FLOW_IDLE_MS, &sink);
        assert_eq!(closed(&events.try_iter().collect::<Vec<_>>()), [udp]);
    }

    #[test]
    fn capture_takes_over_snapshot_flows_without_announcing_them_again() {
        let (sink, events) = sink();
        let tcp = key(Protocol::Tcp, 50_000);
        let mut flows = KnownFlows::new(8);
        flows.apply_snapshot(&table(&[tcp], &[]), START, &sink);
        let announced: Vec<_> = events.try_iter().collect();
        assert!(matches!(
            announced.as_slice(),
            [BackendEvent::Opened {
                cookie: Some(SocketCookie {
                    source: CookieSource::Synthetic,
                    ..
                }),
                ..
            }]
        ));

        flows.saw_packet(&data(tcp, Some(flow_id(tcp))), START + 1_000, &sink);
        assert!(events.try_iter().next().is_none());
    }

    /// Capture closes a flow the fallback announced once the socket table stops listing it,
    /// as it does its own.
    #[test]
    fn capture_closes_a_snapshot_flow_whose_socket_is_gone() {
        let (sink, events) = sink();
        let tcp = key(Protocol::Tcp, 50_000);
        let mut flows = KnownFlows::new(8);
        flows.apply_snapshot(&table(&[tcp], &[]), START, &sink);
        let _ = events.try_iter().count();

        let mut coverage = SocketCoverage::default();
        coverage.tcp.insert(tcp);
        flows.close_missing(&coverage, START + SOCKET_GONE_GRACE_MS, &sink);
        assert!(events.try_iter().next().is_none(), "its socket is listed");

        flows.close_missing(&SocketCoverage::default(), START + 1, &sink);
        assert!(events.try_iter().next().is_none(), "within the grace");
        flows.close_missing(
            &SocketCoverage::default(),
            START + SOCKET_GONE_GRACE_MS,
            &sink,
        );
        assert_eq!(closed(&events.try_iter().collect::<Vec<_>>()), [tcp]);
    }

    /// The synthetic cookie names the owner, so the collector splits the old socket's flow
    /// from the new one.
    #[test]
    fn the_snapshot_announces_a_connection_another_process_now_owns() {
        let (sink, events) = sink();
        let tcp = key(Protocol::Tcp, 50_000);
        let mut flows = KnownFlows::new(8);
        flows.apply_snapshot(&table(&[tcp], &[]), START, &sink);
        let mut moved = table(&[], &[]);
        moved.connections.insert(tcp, PID + 1);
        flows.apply_snapshot(&moved, START + 1_000, &sink);
        let cookies: Vec<_> = events
            .try_iter()
            .filter_map(|event| match event {
                BackendEvent::Opened { cookie, .. } => cookie,
                _ => None,
            })
            .collect();
        let [first, second] = cookies.as_slice() else {
            panic!("expected two announcements, got {cookies:?}");
        };
        assert!(first.contradicts(*second));
    }

    /// The socket table is read on another thread and applied when it arrives. A flow
    /// whose packets came after the reading may belong to a socket the reading missed.
    #[test]
    fn a_listing_does_not_close_a_flow_seen_after_it_was_read() {
        let (sink, events) = sink();
        let before = key(Protocol::Tcp, 50_000);
        let after = key(Protocol::Tcp, 50_001);
        let mut flows = KnownFlows::new(8);
        let read_at = START + SOCKET_GONE_GRACE_MS;
        flows.saw_packet(&data(before, None), START, &sink);
        flows.saw_packet(&data(after, None), read_at + 1, &sink);
        let _ = events.try_iter().count();

        flows.close_missing(&SocketCoverage::default(), read_at, &sink);
        assert_eq!(closed(&events.try_iter().collect::<Vec<_>>()), [before]);
    }

    #[test]
    fn a_full_table_closes_the_flow_seen_least_recently() {
        let (sink, events) = sink();
        let older = key(Protocol::Tcp, 50_000);
        let newer = key(Protocol::Tcp, 50_001);
        let arriving = key(Protocol::Tcp, 50_002);
        let mut flows = KnownFlows::new(2);
        flows.saw_packet(&data(older, None), START, &sink);
        flows.saw_packet(&data(newer, None), START + 1, &sink);
        let _ = events.try_iter().count();

        flows.saw_packet(&data(arriving, None), START + 2, &sink);
        let events: Vec<_> = events.try_iter().collect();
        assert_eq!(closed(&events), [older]);
        assert_eq!(opened(&events), [arriving]);
    }

    #[test]
    fn an_unreadable_table_still_ends_idle_udp_flows() {
        let (sink, events) = sink();
        let tcp = key(Protocol::Tcp, 50_000);
        let udp = key(Protocol::Udp, 50_001);
        let mut flows = KnownFlows::new(8);
        flows.saw_packet(&data(tcp, None), START, &sink);
        flows.saw_packet(&data(udp, None), START, &sink);
        let _ = events.try_iter().count();

        flows.expire_idle_udp(START + FLOW_IDLE_MS, &sink);
        assert_eq!(closed(&events.try_iter().collect::<Vec<_>>()), [udp]);
    }

    #[test]
    fn stopping_closes_every_flow() {
        let (sink, events) = sink();
        let tcp = key(Protocol::Tcp, 50_000);
        let mut flows = KnownFlows::new(8);
        flows.apply_snapshot(&table(&[tcp], &[]), START, &sink);
        let _ = events.try_iter().count();

        flows.close_all(START + 1, &sink);
        assert_eq!(closed(&events.try_iter().collect::<Vec<_>>()), [tcp]);
    }
}
