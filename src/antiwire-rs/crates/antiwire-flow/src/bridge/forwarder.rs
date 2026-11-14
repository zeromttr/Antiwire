//! Buffered collector admission; only the forwarding thread waits on Tokio capacity.
//!
//! The collector hands events to a large in-memory queue and returns at once,
//! so a slow tracker does not stall native collection. This queue drops no
//! event: byte deltas for a flow already queued merge into its pending entry,
//! and anything else that finds the queue full makes the collector wait for
//! room, as it did before the queue existed. Lifecycle events are never
//! discarded, because a lost open or close leaves the tracker with a flow it
//! cannot account for. Downstream, [`BridgeConsumer`] can still shed byte
//! deltas when the tracker's channel stays full past its key cap; it reports
//! that to collector health.

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::thread::JoinHandle;

use antiwire_events::CollectorHealth;
use netmetrics::FlowConsumer;
use netmetrics_core::{ByteDelta, FlowEvent, FlowKey};
use parking_lot::{Condvar, Mutex, MutexGuard};
use tokio::sync::mpsc;

use super::BridgeConsumer;

enum Queued {
    Control(FlowEvent),
    Bytes(u64),
}

struct Queue {
    order: VecDeque<Queued>,
    bytes: HashMap<u64, (FlowKey, ByteDelta)>,
    merge: HashMap<FlowKey, u64>,
    next_id: u64,
    capacity: usize,
    /// Times the collector has had to wait for room, for throttled warnings.
    full_waits: u64,
    closed: bool,
}

impl Queue {
    fn new(capacity: usize) -> Self {
        Self {
            order: VecDeque::new(),
            bytes: HashMap::new(),
            merge: HashMap::new(),
            next_id: 0,
            capacity,
            full_waits: 0,
            closed: false,
        }
    }

    /// Queues `event`, or hands it back when the queue is full and it needs a
    /// slot of its own. Once the queue is closed, events are discarded.
    fn push(&mut self, event: FlowEvent) -> Option<FlowEvent> {
        if self.closed || matches!(event, FlowEvent::Interface(..)) {
            return None;
        }
        match &event {
            FlowEvent::Bytes(key, delta) => {
                if delta.is_zero() {
                    return None;
                }
                if let Some(id) = self.merge.get(key) {
                    self.bytes
                        .get_mut(id)
                        .expect("queued merge token")
                        .1
                        .saturating_add_assign(*delta);
                    return None;
                }
            }
            FlowEvent::Opened(key, _) | FlowEvent::Closed(key, _) => {
                self.merge.remove(key);
            }
            FlowEvent::ProcessStarted(_) | FlowEvent::ProcessStopped { .. } => self.merge.clear(),
            _ => {}
        }
        if self.order.len() >= self.capacity {
            return Some(event);
        }
        match event {
            FlowEvent::Bytes(key, delta) => {
                let id = self.next_id;
                self.next_id = self.next_id.wrapping_add(1);
                self.bytes.insert(id, (key, delta));
                self.merge.insert(key, id);
                self.order.push_back(Queued::Bytes(id));
            }
            event => self.order.push_back(Queued::Control(event)),
        }
        None
    }

    fn take_batch(&mut self) -> Vec<FlowEvent> {
        let mut batch = Vec::with_capacity(256);
        while batch.len() < 256 {
            match self.order.pop_front() {
                Some(Queued::Control(event)) => batch.push(event),
                Some(Queued::Bytes(id)) => {
                    let (key, delta) = self.bytes.remove(&id).expect("queued byte token");
                    if self.merge.get(&key) == Some(&id) {
                        self.merge.remove(&key);
                    }
                    batch.push(FlowEvent::Bytes(key, delta));
                }
                None => break,
            }
        }
        batch
    }
}

struct Shared {
    queue: Mutex<Queue>,
    /// Signalled when events are queued or the queue closes.
    ready: Condvar,
    /// Signalled when the forwarding thread frees room or stops.
    space: Condvar,
}

impl Shared {
    /// Queues `event`, waiting while the queue is full.
    fn admit(&self, queue: &mut MutexGuard<'_, Queue>, mut event: FlowEvent) {
        while let Some(waiting) = queue.push(event) {
            event = waiting;
            queue.full_waits = queue.full_waits.saturating_add(1);
            if queue.full_waits.is_power_of_two() {
                tracing::warn!(
                    waits = queue.full_waits,
                    "flow forwarding queue full; collector waiting for the tracker"
                );
            }
            self.ready.notify_one();
            self.space.wait(queue);
        }
    }
}

/// Closes the queue when the forwarding thread exits by any path, panics
/// included. A collector waiting for room would otherwise wait forever, and
/// `Collector::stop` joins that collector thread.
struct CloseOnExit(Arc<Shared>);

impl Drop for CloseOnExit {
    fn drop(&mut self) {
        self.0.queue.lock().closed = true;
        self.0.space.notify_all();
    }
}

pub(super) struct CollectorForwarder {
    shared: Arc<Shared>,
    _worker: JoinHandle<()>,
}

impl CollectorForwarder {
    pub(super) fn new(
        tx: mpsc::Sender<FlowEvent>,
        collector_health: Option<Arc<CollectorHealth>>,
    ) -> std::io::Result<Self> {
        let capacity = antiwire_tuning::FLOW_ACTIVE_FLOWS_HARD_CAP
            .saturating_mul(2)
            .max(1024);
        Self::with_capacity(tx, capacity, collector_health)
    }

    fn with_capacity(
        tx: mpsc::Sender<FlowEvent>,
        capacity: usize,
        collector_health: Option<Arc<CollectorHealth>>,
    ) -> std::io::Result<Self> {
        let shared = Arc::new(Shared {
            queue: Mutex::new(Queue::new(capacity)),
            ready: Condvar::new(),
            space: Condvar::new(),
        });
        let worker_shared = Arc::clone(&shared);
        let worker = std::thread::Builder::new()
            .name("antiwire-flow-forward".into())
            .spawn(move || {
                let _close = CloseOnExit(Arc::clone(&worker_shared));
                let mut consumer = BridgeConsumer::new(tx).reporting_to(collector_health);
                loop {
                    let mut batch = {
                        let mut queue = worker_shared.queue.lock();
                        while queue.order.is_empty() && !queue.closed {
                            worker_shared.ready.wait(&mut queue);
                        }
                        if consumer.tx.is_closed() || (queue.closed && queue.order.is_empty()) {
                            break;
                        }
                        let batch = queue.take_batch();
                        worker_shared.space.notify_all();
                        batch
                    };
                    consumer.on_batch_buffer(&mut batch);
                }
            })?;
        Ok(Self {
            shared,
            _worker: worker,
        })
    }
}

impl FlowConsumer for CollectorForwarder {
    fn on_event(&mut self, event: FlowEvent) {
        let mut queue = self.shared.queue.lock();
        self.shared.admit(&mut queue, event);
        drop(queue);
        self.shared.ready.notify_one();
    }

    fn on_batch(&mut self, events: &[FlowEvent]) {
        let mut queue = self.shared.queue.lock();
        for event in events {
            self.shared.admit(&mut queue, event.clone());
        }
        drop(queue);
        self.shared.ready.notify_one();
    }

    fn on_batch_buffer(&mut self, events: &mut Vec<FlowEvent>) {
        let mut queue = self.shared.queue.lock();
        for event in events.drain(..) {
            self.shared.admit(&mut queue, event);
        }
        drop(queue);
        self.shared.ready.notify_one();
    }
}

impl Drop for CollectorForwarder {
    fn drop(&mut self) {
        self.shared.queue.lock().closed = true;
        self.shared.ready.notify_one();
        // Do not join on the collector thread: the worker may be waiting for
        // the tracker to drain its final window. It owns the sender until then.
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use netmetrics_core::{FlowMeta, Protocol};
    use std::time::{Duration, Instant};

    fn key() -> FlowKey {
        FlowKey {
            protocol: Protocol::Tcp,
            local_addr: "127.0.0.1".parse().unwrap(),
            local_port: 50_000,
            remote_addr: "1.1.1.1".parse().unwrap(),
            remote_port: 443,
        }
    }

    #[test]
    fn collector_stays_nonblocking_and_final_bytes_precede_close() {
        let (tx, mut rx) = mpsc::channel(1);
        let mut forwarder = CollectorForwarder::with_capacity(tx, 16, None).unwrap();
        let started = Instant::now();
        for _ in 0..1000 {
            forwarder.on_event(FlowEvent::Bytes(
                key(),
                ByteDelta {
                    sent: 1,
                    received: 2,
                },
            ));
        }
        forwarder.on_event(FlowEvent::Closed(
            key(),
            FlowMeta {
                pid: 42,
                process: None,
                open_ts: 0,
                cookie: None,
                if_index: None,
            },
        ));
        drop(forwarder);
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "collector must not wait for a full Tokio channel"
        );
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let mut totals = (0, 0);
            let mut closed = false;
            tokio::time::timeout(Duration::from_secs(3), async {
                while let Some(event) = rx.recv().await {
                    match event {
                        FlowEvent::Bytes(_, delta) => {
                            assert!(!closed);
                            totals.0 += delta.sent;
                            totals.1 += delta.received;
                        }
                        FlowEvent::Closed(..) => closed = true,
                        _ => panic!("unexpected event"),
                    }
                }
            })
            .await
            .unwrap();
            assert!(closed);
            assert_eq!(totals, (1000, 2000));
        });
    }

    #[test]
    fn a_full_queue_hands_events_back_but_still_merges_queued_bytes() {
        let bytes = |sent| FlowEvent::Bytes(key(), ByteDelta { sent, received: 0 });
        let mut queue = Queue::new(2);
        assert!(queue.push(bytes(1)).is_none());
        assert!(queue
            .push(FlowEvent::ProcessStopped {
                pid: 42,
                stop_ts: 1,
            })
            .is_none());
        // A lifecycle barrier ends merging, so these bytes need a slot.
        assert!(matches!(queue.push(bytes(2)), Some(FlowEvent::Bytes(..))));
        assert!(matches!(
            queue.push(FlowEvent::ProcessStopped {
                pid: 43,
                stop_ts: 2,
            }),
            Some(FlowEvent::ProcessStopped { pid: 43, .. })
        ));

        let mut queue = Queue::new(1);
        assert!(queue.push(bytes(1)).is_none());
        assert!(
            queue.push(bytes(2)).is_none(),
            "queued bytes merge when full"
        );
        let batch = queue.take_batch();
        assert!(matches!(
            batch[..],
            [FlowEvent::Bytes(_, ByteDelta { sent: 3, .. })]
        ));
    }

    /// A forwarding thread that dies must release a collector waiting for room.
    #[test]
    fn a_panicking_worker_releases_a_collector_waiting_for_room() {
        let shared = Arc::new(Shared {
            queue: Mutex::new(Queue::new(1)),
            ready: Condvar::new(),
            space: Condvar::new(),
        });
        let opened = |port| {
            FlowEvent::Opened(
                FlowKey {
                    local_port: port,
                    ..key()
                },
                FlowMeta {
                    pid: 42,
                    process: None,
                    open_ts: 0,
                    cookie: None,
                    if_index: None,
                },
            )
        };
        assert!(shared.queue.lock().push(opened(1)).is_none());

        let collector_shared = Arc::clone(&shared);
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        let collector = std::thread::spawn(move || {
            let mut queue = collector_shared.queue.lock();
            collector_shared.admit(&mut queue, opened(2));
            done_tx.send(()).unwrap();
        });
        // Let the collector park on the full queue before the worker dies.
        while shared.queue.lock().full_waits == 0 {
            std::thread::yield_now();
        }

        let worker_shared = Arc::clone(&shared);
        let worker = std::thread::spawn(move || {
            let _close = CloseOnExit(worker_shared);
            panic!("forwarding failed");
        });
        assert!(worker.join().is_err());

        done_rx
            .recv_timeout(Duration::from_secs(3))
            .expect("the collector must not stay parked after the worker dies");
        collector.join().unwrap();
    }

    /// The regression this guards: once the queue filled, opens and closes
    /// were shed, and the tracker kept flows it could never close.
    #[test]
    fn a_burst_larger_than_the_queue_loses_no_lifecycle_event() {
        let (tx, mut rx) = mpsc::channel(1);
        let mut forwarder = CollectorForwarder::with_capacity(tx, 4, None).unwrap();
        let receiver = std::thread::spawn(move || {
            let mut ports = Vec::new();
            while let Some(event) = rx.blocking_recv() {
                if let FlowEvent::Opened(key, _) = event {
                    ports.push(key.local_port);
                }
            }
            ports
        });
        for port in 0..200 {
            let key = FlowKey {
                local_port: port,
                ..key()
            };
            forwarder.on_event(FlowEvent::Opened(
                key,
                FlowMeta {
                    pid: 42,
                    process: None,
                    open_ts: 0,
                    cookie: None,
                    if_index: None,
                },
            ));
        }
        drop(forwarder);
        assert_eq!(receiver.join().unwrap(), (0..200).collect::<Vec<_>>());
    }
}
