//! Restricts a capture to the TCP and UDP flows one application owns.
//!
//! Packets carry no owner, so each one is matched against the flows the
//! daemon's connection tracker attributes to the application. A flow can be
//! captured before the tracker reports it (a TCP handshake usually is), so a
//! packet whose flow is not known yet waits in [`HoldQueue`] for up to
//! [`AppFilter::hold`] before it is dropped. Packets leave the queue in
//! arrival order, so the archive stays in capture order.

use std::collections::{HashSet, VecDeque};
use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::session::CaptureFrame;

/// Transport protocol of a [`FlowTuple`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Transport {
    Tcp,
    Udp,
}

/// One TCP or UDP flow as seen from this host.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct FlowTuple {
    pub transport: Transport,
    pub local: SocketAddr,
    pub remote: SocketAddr,
}

/// Live flows owned by the application a capture is restricted to.
pub trait AppFlowSource: Send + Sync {
    /// Flows the application owns now. `None` means ownership cannot be
    /// determined at the moment, not that the application has no flows.
    fn flows(&self) -> Option<Vec<FlowTuple>>;
}

/// Keeps only the packets of one application's flows.
#[derive(Clone)]
pub struct AppFilter {
    /// Shown in status messages.
    pub app_name: String,
    pub source: Arc<dyn AppFlowSource>,
    /// How long a packet of an unknown flow waits for the tracker to report it.
    pub hold: Duration,
    /// How often the owned flows are read from [`Self::source`].
    pub refresh: Duration,
    /// Captured bytes the hold queue may keep before it decides early.
    pub hold_budget_bytes: usize,
}

impl fmt::Debug for AppFilter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AppFilter")
            .field("app_name", &self.app_name)
            .field("hold", &self.hold)
            .field("refresh", &self.refresh)
            .field("hold_budget_bytes", &self.hold_budget_bytes)
            .finish_non_exhaustive()
    }
}

/// Owned flows are matched on local port and remote endpoint only: sockets
/// bound to a wildcard address report it as their local address, while the
/// packets carry the interface address.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct FlowKey {
    transport: Transport,
    local_port: u16,
    remote: SocketAddr,
}

impl FlowKey {
    fn of(tuple: &FlowTuple) -> Self {
        Self {
            transport: tuple.transport,
            local_port: tuple.local.port(),
            remote: canonical(tuple.remote),
        }
    }
}

/// Folds IPv4-mapped IPv6 addresses, which dual-stack sockets report, into IPv4.
fn canonical(address: SocketAddr) -> SocketAddr {
    SocketAddr::new(address.ip().to_canonical(), address.port())
}

/// Most owned flows remembered at once; the set is rebuilt from the source past this.
const MAX_OWNED_FLOWS: usize = 65_536;

/// Flows the application has owned during the capture.
///
/// A flow stays matched after the tracker forgets it, so the packets that
/// close a connection are kept.
struct OwnedFlows {
    source: Arc<dyn AppFlowSource>,
    refresh: Duration,
    owned: HashSet<FlowKey>,
    refreshed_at: Option<Instant>,
}

impl OwnedFlows {
    fn new(source: Arc<dyn AppFlowSource>, refresh: Duration) -> Self {
        Self {
            source,
            refresh,
            owned: HashSet::new(),
            refreshed_at: None,
        }
    }

    fn refresh_if_due(&mut self, now: Instant) {
        if self
            .refreshed_at
            .is_some_and(|at| now.saturating_duration_since(at) < self.refresh)
        {
            return;
        }
        self.refresh_now(now);
    }

    fn refresh_now(&mut self, now: Instant) {
        self.refreshed_at = Some(now);
        // Keep what is known when ownership is briefly unavailable.
        let Some(flows) = self.source.flows() else {
            return;
        };
        if self.owned.len().saturating_add(flows.len()) > MAX_OWNED_FLOWS {
            self.owned.clear();
        }
        self.owned.extend(flows.iter().map(FlowKey::of));
    }

    /// Whether the packet between `source` and `destination` belongs to an owned
    /// flow, in either direction. Loopback packets match whichever end is owned.
    fn contains(&self, transport: Transport, source: SocketAddr, destination: SocketAddr) -> bool {
        let source = canonical(source);
        let destination = canonical(destination);
        let outbound = FlowKey {
            transport,
            local_port: source.port(),
            remote: destination,
        };
        let inbound = FlowKey {
            transport,
            local_port: destination.port(),
            remote: source,
        };
        self.owned.contains(&outbound) || self.owned.contains(&inbound)
    }
}

/// The TCP or UDP endpoints of a decoded frame, when it has them.
///
/// Fragments after the first, ICMP, and non-IP frames have no ports, and
/// truncated transport headers decode with port zero; none can be matched.
fn frame_endpoints(frame: &CaptureFrame) -> Option<(Transport, SocketAddr, SocketAddr)> {
    let transport = match frame.protocol.as_str() {
        "TCP" => Transport::Tcp,
        "UDP" => Transport::Udp,
        _ => return None,
    };
    let source_port = u16::try_from(frame.source_port).ok().filter(|&p| p != 0)?;
    let destination_port = u16::try_from(frame.destination_port)
        .ok()
        .filter(|&p| p != 0)?;
    let source: IpAddr = frame.source.parse().ok()?;
    let destination: IpAddr = frame.destination.parse().ok()?;
    Some((
        transport,
        SocketAddr::new(source, source_port),
        SocketAddr::new(destination, destination_port),
    ))
}

struct Held {
    arrived: Instant,
    frame: CaptureFrame,
    endpoints: (Transport, SocketAddr, SocketAddr),
}

/// What [`HoldQueue::release`] decided about a frame.
pub(crate) enum Released {
    Keep(CaptureFrame),
    /// Not the application's; counted, not stored.
    Filtered,
}

/// Frames waiting for their flow's owner, in arrival order.
pub(crate) struct HoldQueue {
    flows: OwnedFlows,
    hold: Duration,
    budget_bytes: usize,
    held: VecDeque<Held>,
    held_bytes: usize,
}

impl HoldQueue {
    pub(crate) fn new(filter: &AppFilter, now: Instant) -> Self {
        let mut flows = OwnedFlows::new(Arc::clone(&filter.source), filter.refresh);
        // Flows already open when the capture starts.
        flows.refresh_now(now);
        Self {
            flows,
            hold: filter.hold,
            budget_bytes: filter.hold_budget_bytes,
            held: VecDeque::new(),
            held_bytes: 0,
        }
    }

    /// Queues a frame; one that can never match is filtered at once.
    pub(crate) fn push(&mut self, frame: CaptureFrame, now: Instant) -> Option<Released> {
        let Some(endpoints) = frame_endpoints(&frame) else {
            return Some(Released::Filtered);
        };
        self.held_bytes = self.held_bytes.saturating_add(frame.payload.len());
        self.held.push_back(Held {
            arrived: now,
            frame,
            endpoints,
        });
        None
    }

    /// Frames whose fate is settled, oldest first. With `finish`, every
    /// frame is settled after one last look at the owned flows.
    pub(crate) fn release(&mut self, now: Instant, finish: bool, out: &mut Vec<Released>) {
        if finish {
            self.flows.refresh_now(now);
        } else {
            self.flows.refresh_if_due(now);
        }
        while let Some(front) = self.held.front() {
            let (transport, source, destination) = front.endpoints;
            let owned = self.flows.contains(transport, source, destination);
            let expired = finish
                || now.saturating_duration_since(front.arrived) >= self.hold
                || self.held_bytes > self.budget_bytes;
            if !owned && !expired {
                break;
            }
            let Some(held) = self.held.pop_front() else {
                break;
            };
            self.held_bytes = self.held_bytes.saturating_sub(held.frame.payload.len());
            out.push(if owned {
                Released::Keep(held.frame)
            } else {
                Released::Filtered
            });
        }
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.held.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use parking_lot::Mutex;

    #[derive(Default)]
    struct FakeSource {
        flows: Mutex<Option<Vec<FlowTuple>>>,
        reads: Mutex<u32>,
    }

    impl FakeSource {
        fn set(&self, flows: Option<Vec<FlowTuple>>) {
            *self.flows.lock() = flows;
        }
    }

    impl AppFlowSource for FakeSource {
        fn flows(&self) -> Option<Vec<FlowTuple>> {
            *self.reads.lock() += 1;
            self.flows.lock().clone()
        }
    }

    const APP: &str = "10.0.0.2:50000";
    const PEER: &str = "93.184.216.34:443";
    const OTHER: &str = "10.0.0.2:50001";

    fn tcp(local: &str, remote: &str) -> FlowTuple {
        FlowTuple {
            transport: Transport::Tcp,
            local: local.parse().unwrap(),
            remote: remote.parse().unwrap(),
        }
    }

    fn frame(protocol: &str, source: &str, destination: &str) -> CaptureFrame {
        let source: SocketAddr = source.parse().unwrap();
        let destination: SocketAddr = destination.parse().unwrap();
        CaptureFrame {
            sequence: 0,
            timestamp_us: 0,
            captured_length: 4,
            original_length: 4,
            link_layer: 1,
            protocol: protocol.to_owned(),
            source: source.ip().to_string(),
            destination: destination.ip().to_string(),
            source_port: u32::from(source.port()),
            destination_port: u32::from(destination.port()),
            info: String::new(),
            payload: vec![0; 4],
        }
    }

    fn filter(source: &Arc<FakeSource>) -> AppFilter {
        AppFilter {
            app_name: "app".to_owned(),
            source: Arc::clone(source) as Arc<dyn AppFlowSource>,
            hold: Duration::from_secs(2),
            refresh: Duration::from_millis(200),
            hold_budget_bytes: 1024,
        }
    }

    fn kept(released: &[Released]) -> usize {
        released
            .iter()
            .filter(|r| matches!(r, Released::Keep(_)))
            .count()
    }

    fn filtered(released: &[Released]) -> usize {
        released
            .iter()
            .filter(|r| matches!(r, Released::Filtered))
            .count()
    }

    #[test]
    fn flows_open_at_start_match_in_both_directions() {
        let source = Arc::new(FakeSource::default());
        source.set(Some(vec![tcp(APP, PEER)]));
        let now = Instant::now();
        let mut queue = HoldQueue::new(&filter(&source), now);

        assert!(queue.push(frame("TCP", APP, PEER), now).is_none());
        assert!(queue.push(frame("TCP", PEER, APP), now).is_none());
        let mut out = Vec::new();
        queue.release(now, false, &mut out);

        assert_eq!(kept(&out), 2);
        assert_eq!(queue.len(), 0);
    }

    #[test]
    fn frames_without_ports_are_filtered_at_once() {
        let source = Arc::new(FakeSource::default());
        let now = Instant::now();
        let mut queue = HoldQueue::new(&filter(&source), now);

        assert!(matches!(
            queue.push(frame("ICMP", APP, PEER), now),
            Some(Released::Filtered)
        ));
        let mut truncated = frame("TCP", APP, PEER);
        truncated.source_port = 0;
        assert!(matches!(
            queue.push(truncated, now),
            Some(Released::Filtered)
        ));
        assert_eq!(queue.len(), 0);
    }

    #[test]
    fn an_unknown_flow_waits_for_the_tracker() {
        let source = Arc::new(FakeSource::default());
        source.set(Some(Vec::new()));
        let start = Instant::now();
        let mut queue = HoldQueue::new(&filter(&source), start);
        queue.push(frame("TCP", APP, PEER), start);

        let mut out = Vec::new();
        queue.release(start + Duration::from_millis(100), false, &mut out);
        assert!(
            out.is_empty(),
            "the handshake waits while the owner is unknown"
        );

        source.set(Some(vec![tcp(APP, PEER)]));
        queue.release(start + Duration::from_millis(300), false, &mut out);
        assert_eq!(kept(&out), 1);
    }

    #[test]
    fn frames_of_other_applications_are_dropped_after_the_hold() {
        let source = Arc::new(FakeSource::default());
        source.set(Some(vec![tcp(APP, PEER)]));
        let start = Instant::now();
        let mut queue = HoldQueue::new(&filter(&source), start);
        queue.push(frame("TCP", OTHER, PEER), start);
        queue.push(frame("TCP", APP, PEER), start);

        let mut out = Vec::new();
        queue.release(start + Duration::from_secs(1), false, &mut out);
        assert!(
            out.is_empty(),
            "release keeps arrival order behind the unknown frame"
        );

        queue.release(start + Duration::from_secs(2), false, &mut out);
        assert_eq!(filtered(&out), 1);
        assert_eq!(kept(&out), 1);
        assert!(matches!(out[0], Released::Filtered));
    }

    #[test]
    fn flows_stay_matched_after_the_tracker_forgets_them() {
        let source = Arc::new(FakeSource::default());
        source.set(Some(vec![tcp(APP, PEER)]));
        let start = Instant::now();
        let mut queue = HoldQueue::new(&filter(&source), start);

        source.set(Some(Vec::new()));
        let later = start + Duration::from_secs(1);
        queue.push(frame("TCP", PEER, APP), later);
        let mut out = Vec::new();
        queue.release(later, false, &mut out);
        assert_eq!(kept(&out), 1);
    }

    #[test]
    fn unavailable_ownership_keeps_known_flows() {
        let source = Arc::new(FakeSource::default());
        source.set(Some(vec![tcp(APP, PEER)]));
        let start = Instant::now();
        let mut queue = HoldQueue::new(&filter(&source), start);

        source.set(None);
        let later = start + Duration::from_secs(1);
        queue.push(frame("TCP", APP, PEER), later);
        let mut out = Vec::new();
        queue.release(later, false, &mut out);
        assert_eq!(kept(&out), 1);
    }

    #[test]
    fn wildcard_and_mapped_addresses_match_the_packets() {
        let source = Arc::new(FakeSource::default());
        source.set(Some(vec![
            tcp("0.0.0.0:50000", "[::ffff:93.184.216.34]:443"),
            FlowTuple {
                transport: Transport::Udp,
                local: "[::]:5353".parse().unwrap(),
                remote: "[fe80::1]:5353".parse().unwrap(),
            },
        ]));
        let now = Instant::now();
        let mut queue = HoldQueue::new(&filter(&source), now);
        queue.push(frame("TCP", APP, PEER), now);
        queue.push(frame("UDP", "[fe80::2]:5353", "[fe80::1]:5353"), now);
        // Same ports, other transport.
        queue.push(frame("UDP", APP, PEER), now);

        let mut out = Vec::new();
        queue.release(now, true, &mut out);
        assert_eq!(kept(&out), 2);
        assert_eq!(filtered(&out), 1);
    }

    #[test]
    fn finishing_settles_every_frame_after_a_last_refresh() {
        let source = Arc::new(FakeSource::default());
        source.set(Some(Vec::new()));
        let start = Instant::now();
        let mut queue = HoldQueue::new(&filter(&source), start);
        queue.push(frame("TCP", APP, PEER), start);
        queue.push(frame("TCP", OTHER, PEER), start);

        source.set(Some(vec![tcp(APP, PEER)]));
        let mut out = Vec::new();
        queue.release(start, true, &mut out);
        assert_eq!(kept(&out), 1);
        assert_eq!(filtered(&out), 1);
        assert_eq!(queue.len(), 0);
    }

    #[test]
    fn a_full_queue_decides_early() {
        let source = Arc::new(FakeSource::default());
        source.set(Some(Vec::new()));
        let start = Instant::now();
        let mut queue = HoldQueue::new(&filter(&source), start);
        // 300 frames of 4 bytes exceed the 1024-byte budget.
        for _ in 0..300 {
            queue.push(frame("TCP", OTHER, PEER), start);
        }

        let mut out = Vec::new();
        queue.release(start, false, &mut out);
        assert!(!out.is_empty());
        assert!(queue.held_bytes <= 1024);
    }

    #[test]
    fn the_source_is_read_at_most_once_per_refresh_interval() {
        let source = Arc::new(FakeSource::default());
        source.set(Some(Vec::new()));
        let start = Instant::now();
        let mut queue = HoldQueue::new(&filter(&source), start);
        let mut out = Vec::new();
        for step in 0..10 {
            queue.release(start + Duration::from_millis(step * 10), false, &mut out);
        }
        assert_eq!(*source.reads.lock(), 1);
        queue.release(start + Duration::from_millis(250), false, &mut out);
        assert_eq!(*source.reads.lock(), 2);
    }
}
