use crate::BackendEvent;
use crossbeam_queue::ArrayQueue;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering, fence};
use std::sync::mpsc::{SyncSender, TrySendError};

/// Shared producer/consumer notification flag for the collector wake channel.
///
/// Producers enqueue first, then try to move this from unnotified to notified.
/// Only that transition sends a wake token. The consumer clears it and rechecks
/// work before sleeping.
///
/// The queue is lock-free, so nothing else orders a producer's enqueue against
/// the consumer's recheck. Both sides fence with `SeqCst`: either the consumer's
/// recheck sees the event, or the producer sees the cleared flag and sends a
/// wake token. Without the fences both could miss, and the event would wait
/// for the consumer's next timeout.
#[derive(Clone, Debug)]
pub struct WakeState {
    notified: Arc<AtomicBool>,
}

impl WakeState {
    /// Creates an unnotified state.
    #[must_use]
    pub fn new() -> Self {
        Self {
            notified: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Marks notified. Returns true when this caller performed the unnotified→notified transition.
    ///
    /// Call after the event is enqueued.
    pub fn notify(&self) -> bool {
        fence(Ordering::SeqCst);
        !self.notified.swap(true, Ordering::AcqRel)
    }

    /// Clears the notified flag. The caller must recheck queued work before sleeping.
    pub fn clear(&self) {
        self.notified.store(false, Ordering::Release);
        fence(Ordering::SeqCst);
    }
}

impl Default for WakeState {
    fn default() -> Self {
        Self::new()
    }
}

/// Non-blocking ingress handle used inside native callbacks.
#[derive(Clone, Debug)]
pub struct EventSink {
    channels: SinkChannels,
    dropped: Arc<AtomicU64>,
    enabled: Option<Arc<AtomicBool>>,
    native_capacity: usize,
}

const DEFAULT_NATIVE_CAPACITY: usize = 65_536;

/// Revokes every clone of a backend-run event producer.
#[doc(hidden)]
#[derive(Clone, Debug)]
pub struct EventGate(Arc<AtomicBool>);

impl EventGate {
    /// Prevents further admissions from this backend run.
    pub fn revoke(&self) {
        self.0.store(false, Ordering::Release);
    }
}

#[derive(Clone, Debug)]
enum SinkChannels {
    /// A plain channel, for backend tests that read events directly.
    Shared(SyncSender<BackendEvent>),
    /// The collector's queue.
    Ordered {
        queue: Arc<OrderedQueue>,
        wake: SyncSender<()>,
        wake_state: WakeState,
    },
}

/// A bounded FIFO shared by native callbacks and the collector.
///
/// Events leave in the order they were admitted, across both classes. Each
/// class has its own bound, tracked by an atomic counter, so a data burst cannot
/// take the room lifecycle events need to keep flow and process state correct.
///
/// The queue is lock-free: an event is dropped only when its class is full,
/// never because another producer or the consumer is using the queue at the
/// same moment.
#[derive(Debug)]
struct OrderedQueue {
    events: ArrayQueue<(BackendEvent, bool)>,
    data: ClassBound,
    control: ClassBound,
}

/// Admission bound for one class of events.
#[derive(Debug)]
struct ClassBound {
    len: AtomicUsize,
    capacity: usize,
}

impl ClassBound {
    fn new(capacity: usize) -> Self {
        Self {
            len: AtomicUsize::new(0),
            capacity,
        }
    }

    /// Takes a slot, or returns false when the class is full.
    fn try_reserve(&self) -> bool {
        // `AtomicUsize::try_update` does this, but needs Rust 1.95.
        let mut len = self.len.load(Ordering::Acquire);
        while len < self.capacity {
            match self
                .len
                .compare_exchange_weak(len, len + 1, Ordering::AcqRel, Ordering::Acquire)
            {
                Ok(_) => return true,
                Err(current) => len = current,
            }
        }
        false
    }

    fn release(&self) {
        self.len.fetch_sub(1, Ordering::AcqRel);
    }
}

impl OrderedQueue {
    fn new(data_capacity: usize, control_capacity: usize) -> Self {
        Self {
            // Room for both bounds, so a reserved slot always fits.
            events: ArrayQueue::new(data_capacity.saturating_add(control_capacity)),
            data: ClassBound::new(data_capacity),
            control: ClassBound::new(control_capacity),
        }
    }

    fn class(&self, control: bool) -> &ClassBound {
        if control { &self.control } else { &self.data }
    }

    fn push(&self, event: BackendEvent) -> Result<(), BackendEvent> {
        let control = is_control_event(&event);
        let class = self.class(control);
        if !class.try_reserve() {
            return Err(event);
        }
        self.events.push((event, control)).map_err(|(event, _)| {
            class.release();
            event
        })
    }

    fn pop(&self) -> Option<BackendEvent> {
        let (event, control) = self.events.pop()?;
        self.class(control).release();
        Some(event)
    }
}

/// Consumer half of a bounded admission-order ingress queue.
#[doc(hidden)]
#[derive(Clone, Debug)]
pub struct OrderedIngress {
    queue: Arc<OrderedQueue>,
}

impl OrderedIngress {
    /// Returns whether an event is currently queued.
    pub fn has_pending(&self) -> bool {
        !self.queue.events.is_empty()
    }

    /// Removes the earliest successfully admitted event.
    pub fn try_recv(&self) -> Option<BackendEvent> {
        self.queue.pop()
    }
}

impl EventSink {
    /// Wraps a bounded channel and shared drop counter.
    ///
    /// Backend tests use this to read emitted events directly; the collector
    /// uses [`EventSink::ordered`].
    pub fn new(sender: SyncSender<BackendEvent>, dropped: Arc<AtomicU64>) -> Self {
        Self {
            channels: SinkChannels::Shared(sender),
            dropped,
            enabled: None,
            native_capacity: DEFAULT_NATIVE_CAPACITY,
        }
    }

    /// Creates one bounded lock-free queue whose admission order is event order.
    ///
    /// Data and lifecycle events have separate bounds, so the lifecycle reserve does not
    /// reduce the configured data capacity. Native callbacks drop an event only when its
    /// class is full.
    #[doc(hidden)]
    pub fn ordered(
        data_capacity: usize,
        control_capacity: usize,
        wake: SyncSender<()>,
        wake_state: WakeState,
        dropped: Arc<AtomicU64>,
    ) -> (Self, OrderedIngress) {
        assert!(data_capacity > 0);
        assert!(control_capacity > 0);
        let queue = Arc::new(OrderedQueue::new(data_capacity, control_capacity));
        (
            Self {
                channels: SinkChannels::Ordered {
                    queue: Arc::clone(&queue),
                    wake,
                    wake_state,
                },
                dropped,
                enabled: None,
                native_capacity: DEFAULT_NATIVE_CAPACITY,
            },
            OrderedIngress { queue },
        )
    }

    /// Creates a producer scoped to one revocable backend run.
    #[doc(hidden)]
    pub fn revocable(&self) -> (Self, EventGate) {
        let enabled = Arc::new(AtomicBool::new(true));
        (
            Self {
                channels: self.channels.clone(),
                dropped: Arc::clone(&self.dropped),
                enabled: Some(Arc::clone(&enabled)),
                native_capacity: self.native_capacity,
            },
            EventGate(enabled),
        )
    }

    /// Associates the collector's native staging bound with this sink.
    #[doc(hidden)]
    #[must_use]
    pub fn with_native_capacity(mut self, capacity: usize) -> Self {
        assert!(capacity > 0);
        self.native_capacity = capacity;
        self
    }

    /// Returns the native staging bound associated with this sink.
    #[doc(hidden)]
    pub fn native_capacity(&self) -> usize {
        self.native_capacity
    }

    /// Attempts to enqueue without ever blocking a native callback.
    ///
    /// Every backend's events leave it here, so this is where their flow addresses are
    /// made canonical ([`netmetrics_core::FlowKey::canonical`]): one connection is one
    /// flow, and a dual-stack socket's loopback traffic is loopback, whichever form the
    /// native source used.
    ///
    /// Returns `false` when the queue is full or disconnected.
    pub fn emit(&self, mut event: BackendEvent) -> bool {
        if self
            .enabled
            .as_ref()
            .is_some_and(|enabled| !enabled.load(Ordering::Acquire))
        {
            self.dropped.fetch_add(1, Ordering::Relaxed);
            return false;
        }
        event.canonicalize();
        let result = match &self.channels {
            SinkChannels::Shared(sender) => sender.try_send(event),
            SinkChannels::Ordered {
                queue,
                wake,
                wake_state,
            } => {
                let result = queue.push(event).map_err(TrySendError::Full);
                if result.is_ok() && wake_state.notify() {
                    let _ = wake.try_send(());
                }
                result
            }
        };
        match result {
            Ok(()) => true,
            Err(TrySendError::Full(_) | TrySendError::Disconnected(_)) => {
                self.dropped.fetch_add(1, Ordering::Relaxed);
                false
            }
        }
    }

    /// Returns the shared cumulative drop counter.
    #[cfg(test)]
    pub fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }
}

fn is_control_event(event: &BackendEvent) -> bool {
    matches!(
        event,
        BackendEvent::Opened { .. }
            | BackendEvent::CookieResolved { .. }
            | BackendEvent::Closed { .. }
            | BackendEvent::Finishing { .. }
            | BackendEvent::LocalEndpointClosed { .. }
            | BackendEvent::ProcessStarted(_)
            | BackendEvent::ProcessStopped { .. }
            | BackendEvent::InterfaceHint { .. }
            | BackendEvent::Degraded(_)
            | BackendEvent::Restored { .. }
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use netmetrics_core::{ByteDelta, FlowKey, Protocol};
    use netmetrics_core::{DegradeReason, FlowEvent};
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::Barrier;
    use std::sync::mpsc::{Receiver, sync_channel};
    use std::thread;
    use std::time::Duration;

    fn sample_key() -> FlowKey {
        FlowKey {
            protocol: Protocol::Tcp,
            local_addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
            local_port: 1,
            remote_addr: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)),
            remote_port: 443,
        }
    }

    fn sample_bytes(timestamp: u64) -> BackendEvent {
        BackendEvent::Bytes {
            key: sample_key(),
            pid: 1,
            delta: ByteDelta {
                sent: 1,
                received: 0,
            },
            timestamp,
            if_index: None,
            cookie: None,
        }
    }

    fn sample_closed(timestamp: u64) -> BackendEvent {
        BackendEvent::Closed {
            key: sample_key(),
            pid: 42,
            timestamp,
        }
    }

    fn ordered(
        data_capacity: usize,
        control_capacity: usize,
    ) -> (EventSink, OrderedIngress, WakeState, Receiver<()>) {
        let (wake_sender, wake_receiver) = sync_channel(1);
        let wake_state = WakeState::new();
        let (sink, ingress) = EventSink::ordered(
            data_capacity,
            control_capacity,
            wake_sender,
            wake_state.clone(),
            Arc::new(AtomicU64::new(0)),
        );
        (sink, ingress, wake_state, wake_receiver)
    }

    #[test]
    fn full_queue_is_counted_without_blocking() {
        let (sender, _receiver) = sync_channel(1);
        let dropped = Arc::new(AtomicU64::new(0));
        let sink = EventSink::new(sender, dropped);
        let event = BackendEvent::Degraded(DegradeReason::UnsupportedPlatform);
        assert!(sink.emit(event.clone()));
        assert!(!sink.emit(event));
        assert_eq!(sink.dropped(), 1);

        // Keep the public type imported here to ensure backend and facade
        // degradation variants remain intentionally distinct.
        let _ = std::mem::size_of::<FlowEvent>();
    }

    /// Linux reports a dual-stack socket's IPv4 traffic with IPv4-mapped addresses; the
    /// collector must see the plain IPv4 form every other source uses.
    #[test]
    fn emitted_flow_addresses_are_canonical() {
        let (sender, receiver) = sync_channel(4);
        let sink = EventSink::new(sender, Arc::new(AtomicU64::new(0)));
        let plain = sample_key();
        let mapped = |address: IpAddr| match address {
            IpAddr::V4(address) => IpAddr::V6(address.to_ipv6_mapped()),
            IpAddr::V6(_) => address,
        };
        assert!(sink.emit(BackendEvent::Bytes {
            key: FlowKey {
                local_addr: mapped(plain.local_addr),
                remote_addr: mapped(plain.remote_addr),
                ..plain
            },
            pid: 1,
            delta: ByteDelta {
                sent: 1,
                received: 0,
            },
            timestamp: 1,
            if_index: None,
            cookie: None,
        }));
        assert!(sink.emit(BackendEvent::LocalEndpointClosed {
            protocol: Protocol::Udp,
            local_addr: mapped(plain.local_addr),
            local_port: 53,
            cookie: None,
            timestamp: 2,
        }));
        assert_eq!(receiver.try_recv(), Ok(sample_bytes(1)));
        assert!(matches!(
            receiver.try_recv(),
            Ok(BackendEvent::LocalEndpointClosed { local_addr, .. }) if local_addr == plain.local_addr
        ));
    }

    #[test]
    fn saturated_data_class_preserves_lifecycle_capacity() {
        let (sink, ingress, _wake_state, _wake) = ordered(1, 1);
        assert!(sink.emit(sample_bytes(1)));
        assert!(!sink.emit(sample_bytes(2)), "the data class is full");
        assert!(sink.emit(sample_closed(3)), "lifecycle keeps its own room");
        assert!(!sink.emit(sample_closed(4)), "the lifecycle class is full");
        assert_eq!(sink.dropped(), 2);

        assert!(matches!(
            ingress.try_recv(),
            Some(BackendEvent::Bytes { timestamp: 1, .. })
        ));
        assert!(matches!(
            ingress.try_recv(),
            Some(BackendEvent::Closed { timestamp: 3, .. })
        ));
        assert!(ingress.try_recv().is_none());
    }

    #[test]
    fn a_received_event_frees_its_class_slot() {
        let (sink, ingress, _wake_state, _wake) = ordered(1, 1);
        assert!(sink.emit(sample_bytes(1)));
        assert!(!sink.emit(sample_bytes(2)));
        assert!(ingress.try_recv().is_some());
        assert!(sink.emit(sample_bytes(3)), "the slot is free again");
    }

    #[test]
    fn ordered_ingress_preserves_cross_class_admission_order() {
        let (sink, ingress, _wake_state, _wake) = ordered(2, 1);
        assert!(sink.emit(sample_bytes(1)));
        assert!(sink.emit(sample_closed(2)));
        assert!(sink.emit(sample_bytes(3)));

        assert!(matches!(
            ingress.try_recv(),
            Some(BackendEvent::Bytes { timestamp: 1, .. })
        ));
        assert!(matches!(
            ingress.try_recv(),
            Some(BackendEvent::Closed { timestamp: 2, .. })
        ));
        assert!(matches!(
            ingress.try_recv(),
            Some(BackendEvent::Bytes { timestamp: 3, .. })
        ));
    }

    /// The queue used to take a lock and drop the event whenever the lock was
    /// busy, so producers racing each other or a draining consumer lost events
    /// with room to spare: up to 70% of a two-producer burst.
    #[test]
    fn concurrent_producers_and_a_draining_consumer_lose_nothing() {
        const PRODUCERS: u64 = 4;
        const PER_PRODUCER: u64 = 20_000;
        let capacity = usize::try_from(PRODUCERS * PER_PRODUCER).expect("capacity");
        let (sink, ingress, _wake_state, _wake) = ordered(capacity, 1);
        let start = Arc::new(Barrier::new(usize::try_from(PRODUCERS).expect("count") + 1));
        let producers: Vec<_> = (0..PRODUCERS)
            .map(|producer| {
                let sink = sink.clone();
                let start = Arc::clone(&start);
                thread::spawn(move || {
                    start.wait();
                    for offset in 0..PER_PRODUCER {
                        sink.emit(sample_bytes(producer * PER_PRODUCER + offset));
                    }
                })
            })
            .collect();
        start.wait();
        let mut received = 0_u64;
        let mut producers = producers;
        while !producers.is_empty() || ingress.has_pending() {
            while ingress.try_recv().is_some() {
                received += 1;
            }
            producers.retain(|producer| !producer.is_finished());
        }
        assert_eq!(sink.dropped(), 0, "no event may be lost to contention");
        assert_eq!(received, PRODUCERS * PER_PRODUCER);
    }

    #[test]
    fn burst_producers_send_one_wake_until_the_consumer_clears() {
        let (sink, ingress, wake_state, wake_receiver) = ordered(64, 8);
        for timestamp in 0..16 {
            assert!(sink.emit(sample_bytes(timestamp)));
        }
        assert!(wake_receiver.try_recv().is_ok());
        assert!(
            wake_receiver.try_recv().is_err(),
            "a burst must not enqueue a second wake token"
        );
        let mut drained = 0;
        while ingress.try_recv().is_some() {
            drained += 1;
        }
        assert_eq!(drained, 16);

        wake_state.clear();
        assert!(sink.emit(sample_bytes(99)));
        assert!(wake_receiver.try_recv().is_ok());
    }

    #[test]
    fn clear_then_recheck_observes_a_racing_enqueue() {
        let (sink, ingress, wake_state, wake_receiver) = ordered(8, 8);
        let cleared = Arc::new(Barrier::new(2));
        let producer = {
            let sink = sink.clone();
            let cleared = Arc::clone(&cleared);
            thread::spawn(move || {
                cleared.wait();
                assert!(sink.emit(sample_bytes(7)));
            })
        };

        wake_state.clear();
        cleared.wait();
        let queued = ingress.has_pending();
        let woke = wake_receiver.try_recv().is_ok()
            || wake_receiver
                .recv_timeout(Duration::from_millis(200))
                .is_ok();
        let queued = queued || ingress.has_pending();
        assert!(
            queued || woke,
            "after clear, a recheck of the queue or the wake token must see the enqueue"
        );
        producer.join().expect("producer");
    }

    #[test]
    fn concurrent_producers_do_not_lose_the_wake_handshake() {
        let (sink, ingress, _wake_state, wake_receiver) = ordered(256, 8);
        let start = Arc::new(Barrier::new(5));
        let workers: Vec<_> = (0_u32..4)
            .map(|worker| {
                let sink = sink.clone();
                let start = Arc::clone(&start);
                thread::spawn(move || {
                    start.wait();
                    for offset in 0_u32..32 {
                        assert!(
                            sink.emit(sample_bytes(u64::from(worker) * 32 + u64::from(offset)))
                        );
                    }
                })
            })
            .collect();
        start.wait();
        for worker in workers {
            worker.join().expect("producer");
        }

        let mut seen = 0_usize;
        while ingress.try_recv().is_some() {
            seen += 1;
        }
        assert_eq!(seen, 128);
        assert!(
            wake_receiver.try_recv().is_ok(),
            "at least one producer must have sent the wake token"
        );
    }

    #[test]
    fn revocation_rejects_every_clone_from_an_old_backend_run() {
        let (sender, receiver) = sync_channel(2);
        let dropped = Arc::new(AtomicU64::new(0));
        let base = EventSink::new(sender, Arc::clone(&dropped)).with_native_capacity(7);
        let (scoped, gate) = base.revocable();
        let late = scoped.clone();
        assert_eq!(scoped.native_capacity(), 7);
        assert!(scoped.emit(sample_bytes(1)));
        gate.revoke();
        assert!(!late.emit(sample_bytes(2)));
        assert!(base.emit(sample_bytes(3)));
        assert_eq!(receiver.try_iter().count(), 2);
        assert_eq!(dropped.load(Ordering::Relaxed), 1);
    }
}
