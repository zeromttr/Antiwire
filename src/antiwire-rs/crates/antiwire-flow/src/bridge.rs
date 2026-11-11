use std::collections::HashMap;
use std::sync::Arc;

use antiwire_events::CollectorHealth;
use antiwire_tuning::{FLOW_ACTIVE_FLOWS_HARD_CAP, PROCESS_STOP_RETENTION_MS};
use netmetrics::{Collector, FlowConsumer};
use netmetrics_core::{ByteDelta, FlowEvent, FlowKey};
use tokio::sync::mpsc::{self, error::TrySendError};

use crate::{FlowError, Result};

mod forwarder;
use forwarder::CollectorForwarder;

/// Spawns a [`Collector`] worker thread and forwards events into a Tokio channel.
pub struct NetmetBridge {
    collector: Option<Collector>,
    /// Told when byte deltas are shed, so undercounted totals are explained.
    collector_health: Option<Arc<CollectorHealth>>,
}

impl Default for NetmetBridge {
    fn default() -> Self {
        Self::new()
    }
}

impl NetmetBridge {
    #[must_use]
    pub fn new() -> Self {
        Self {
            collector: None,
            collector_health: None,
        }
    }

    /// Reports shed byte deltas to `collector_health`.
    #[must_use]
    pub fn with_collector_health(mut self, collector_health: Arc<CollectorHealth>) -> Self {
        self.collector_health = Some(collector_health);
        self
    }

    /// Starts collection and returns the Tokio receiver side of the bridge.
    ///
    /// # Errors
    ///
    /// Returns [`FlowError::InvalidConfig`] when `capacity` is zero,
    /// [`FlowError::WorkerSpawn`] when the forwarding thread cannot start,
    /// [`FlowError::AlreadyRunning`] when a live collector is already attached, and
    /// [`FlowError::Metrics`] when the backend fails to build or start its collection
    /// session.
    pub fn start(&mut self, capacity: usize) -> Result<mpsc::Receiver<FlowEvent>> {
        if capacity == 0 {
            return Err(FlowError::InvalidConfig(
                "event queue capacity must be at least 1".to_owned(),
            ));
        }
        if self.collector.as_ref().is_some_and(Collector::is_running) {
            return Err(FlowError::AlreadyRunning);
        }
        // A worker that died is reaped by `Collector::start`; clear it so the restart is
        // allowed rather than reporting a running collector that no longer exists.
        self.collector = None;

        let (tx, rx) = mpsc::channel(capacity);
        let mut collector = Collector::builder()
            .dns_hints(true)
            .process_grace_ms(PROCESS_STOP_RETENTION_MS)
            .build()
            .map_err(FlowError::Metrics)?;
        let forwarder = CollectorForwarder::new(tx, self.collector_health.clone())
            .map_err(FlowError::WorkerSpawn)?;
        collector
            .start(Box::new(forwarder))
            .map_err(FlowError::Metrics)?;

        self.collector = Some(collector);
        Ok(rx)
    }

    /// Stops collection. Idempotent: stopping an already-stopped bridge succeeds.
    /// Queued events continue draining until the returned receiver reaches EOF.
    ///
    /// # Errors
    ///
    /// Returns [`FlowError::Metrics`] when the backend reports a failure other than
    /// "not running", which is treated as success.
    pub fn stop(&mut self) -> Result<()> {
        let Some(mut collector) = self.collector.take() else {
            return Ok(());
        };
        match collector.stop() {
            Ok(()) | Err(netmetrics_core::MetricsError::NotRunning) => Ok(()),
            Err(error) => Err(FlowError::Metrics(error)),
        }
    }
}

struct BridgeConsumer {
    tx: mpsc::Sender<FlowEvent>,
    /// Byte deltas held back while the channel is full. Merged per flow key so totals survive
    /// backpressure, up to `pending_cap` distinct keys.
    pending_bytes: HashMap<FlowKey, ByteDelta>,
    /// Ceiling on distinct flow keys retained while the channel is full.
    ///
    /// A stalled receiver plus a process opening fresh UDP tuples must not grow this
    /// without bound; byte events for keys beyond the cap are shed, and the first shed
    /// is reported to `collector_health` because the totals are now low.
    pending_cap: usize,
    /// Byte events shed because `pending_bytes` was already at its cap.
    shed_byte_events: u64,
    collector_health: Option<Arc<CollectorHealth>>,
}

impl BridgeConsumer {
    fn new(tx: mpsc::Sender<FlowEvent>) -> Self {
        Self {
            tx,
            pending_bytes: HashMap::new(),
            pending_cap: FLOW_ACTIVE_FLOWS_HARD_CAP,
            shed_byte_events: 0,
            collector_health: None,
        }
    }

    fn reporting_to(mut self, collector_health: Option<Arc<CollectorHealth>>) -> Self {
        self.collector_health = collector_health;
        self
    }

    fn forward(&mut self, event: FlowEvent) {
        if let FlowEvent::Bytes(key, delta) = event {
            self.forward_bytes(key, delta);
            return;
        }

        // `FlowEvent::Interface` has no consumer anywhere in the workspace, so forwarding
        // it only spent channel capacity and shed counts. Drop it at the source until a
        // consumer exists.
        if matches!(event, FlowEvent::Interface(..)) {
            return;
        }

        match &event {
            FlowEvent::Opened(key, _) | FlowEvent::Closed(key, _) => self.flush_key_blocking(*key),
            FlowEvent::ProcessStarted(_) | FlowEvent::ProcessStopped { .. } => {
                self.flush_pending_bytes_blocking();
            }
            _ => {}
        }
        if self.tx.blocking_send(event).is_err() {
            tracing::debug!("flow bridge receiver closed");
        }
    }

    /// Sends byte deltas straight through while the channel has room.
    ///
    /// Only a full channel enters the merge map, so the common path never touches it.
    fn forward_bytes(&mut self, key: FlowKey, delta: ByteDelta) {
        match self.tx.try_send(FlowEvent::Bytes(key, delta)) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) => self.accumulate_bytes(key, delta),
            Err(TrySendError::Closed(_)) => {
                self.pending_bytes.clear();
                tracing::debug!("flow bridge receiver closed");
            }
        }
    }

    fn accumulate_bytes(&mut self, key: FlowKey, delta: ByteDelta) {
        if let Some(pending) = self.pending_bytes.get_mut(&key) {
            pending.saturating_add_assign(delta);
        } else {
            if self.pending_bytes.len() >= self.pending_cap {
                self.shed_byte_events = self.shed_byte_events.saturating_add(1);
                if self.shed_byte_events == 1 {
                    if let Some(health) = &self.collector_health {
                        health.mark_byte_accounting_lost(
                            "Traffic arrived faster than Antiwire could record it, so some sent \
                             and received bytes were not counted. Traffic totals are lower than \
                             the real volume.",
                        );
                    }
                }
                if self.shed_byte_events.is_power_of_two() {
                    tracing::warn!(
                        shed = self.shed_byte_events,
                        "flow bridge pending byte map is at capacity; shedding byte deltas"
                    );
                }
                return;
            }
            self.pending_bytes.insert(key, delta);
        }
        self.try_flush_bytes(key);
    }

    fn try_flush_bytes(&mut self, key: FlowKey) {
        let Some(delta) = self.pending_bytes.get(&key).copied() else {
            return;
        };
        if delta.is_zero() {
            return;
        }

        match self.tx.try_send(FlowEvent::Bytes(key, delta)) {
            Ok(()) => {
                self.pending_bytes.remove(&key);
            }
            Err(TrySendError::Full(_)) => {}
            Err(TrySendError::Closed(_)) => {
                self.pending_bytes.clear();
                tracing::debug!("flow bridge receiver closed");
            }
        }
    }

    fn flush_pending_bytes_blocking(&mut self) {
        let keys: Vec<FlowKey> = self.pending_bytes.keys().copied().collect();
        for key in keys {
            let Some(delta) = self.pending_bytes.get(&key).copied() else {
                continue;
            };
            if delta.is_zero() {
                self.pending_bytes.remove(&key);
                continue;
            }
            if self.tx.blocking_send(FlowEvent::Bytes(key, delta)).is_err() {
                self.pending_bytes.clear();
                tracing::debug!("flow bridge receiver closed");
                return;
            }
            self.pending_bytes.remove(&key);
        }
    }

    fn flush_key_blocking(&mut self, key: FlowKey) {
        if let Some(delta) = self.pending_bytes.remove(&key) {
            if !delta.is_zero() && self.tx.blocking_send(FlowEvent::Bytes(key, delta)).is_err() {
                self.pending_bytes.clear();
            }
        }
    }
}

impl FlowConsumer for BridgeConsumer {
    fn on_event(&mut self, event: FlowEvent) {
        self.forward(event);
    }

    fn on_batch(&mut self, events: &[FlowEvent]) {
        for event in events {
            self.forward(event.clone());
        }
        // A batch is the collector's unit of delivery, and its final flush is a batch too.
        // Pushing the merged bytes here guarantees the last window reaches the channel even
        // when it was full at shutdown, instead of being dropped with the consumer.
        self.flush_pending_bytes_blocking();
    }

    fn on_batch_buffer(&mut self, events: &mut Vec<FlowEvent>) {
        for event in events.drain(..) {
            self.forward(event);
        }
        self.flush_pending_bytes_blocking();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use netmetrics_core::{ByteDelta, FlowKey, FlowMeta, InterfaceStats, Protocol};
    use std::net::{IpAddr, Ipv4Addr};

    /// `Interface` has no consumer, so it must be dropped at the source rather
    /// than occupying channel capacity ahead of real flow events.
    #[test]
    fn interface_events_are_dropped_before_they_consume_capacity() {
        let (tx, mut rx) = mpsc::channel(1);
        let mut consumer = BridgeConsumer::new(tx);
        let key = byte_key(50_030);

        consumer.on_event(FlowEvent::Interface(InterfaceStats {
            index: 7,
            name: "eth0".to_owned(),
            rx_bytes: 1,
            tx_bytes: 2,
            rx_errors: 0,
            tx_errors: 0,
            rx_drops: 0,
            tx_drops: 0,
            timestamp: 1,
        }));
        consumer.on_event(FlowEvent::Opened(
            key,
            FlowMeta {
                pid: 7,
                process: None,
                open_ts: 1,
                cookie: None,
                if_index: None,
            },
        ));

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        runtime.block_on(async {
            assert!(
                matches!(rx.recv().await, Some(FlowEvent::Opened(..))),
                "the dropped interface event must not occupy the channel"
            );
        });
    }

    #[test]
    fn coalesces_byte_deltas_when_channel_is_full() {
        let (tx, _rx) = mpsc::channel(1);
        let mut consumer = BridgeConsumer::new(tx);
        let key = FlowKey {
            protocol: Protocol::Udp,
            local_addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
            local_port: 50_000,
            remote_addr: IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
            remote_port: 53,
        };
        let bytes = FlowEvent::Bytes(
            key,
            ByteDelta {
                sent: 1,
                received: 2,
            },
        );

        consumer.on_event(bytes.clone());
        consumer.on_event(bytes);

        assert_eq!(
            consumer.pending_bytes.get(&key),
            Some(&ByteDelta {
                sent: 1,
                received: 2
            })
        );
    }

    fn byte_key(local_port: u16) -> FlowKey {
        FlowKey {
            protocol: Protocol::Udp,
            local_addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
            local_port,
            remote_addr: IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
            remote_port: 53,
        }
    }

    #[test]
    fn dns_keeps_pending_bytes_and_open_flushes_only_its_own_key() {
        let (tx, mut rx) = mpsc::channel(8);
        let mut consumer = BridgeConsumer::new(tx);
        let key = byte_key(50_000);
        let other = byte_key(50_001);
        let delta = ByteDelta {
            sent: 3,
            received: 4,
        };
        consumer.pending_bytes.insert(key, delta);
        consumer.pending_bytes.insert(other, delta);
        consumer.on_event(FlowEvent::DnsResolved {
            pid: 42,
            query: "example.test".to_owned(),
            answers: vec!["1.1.1.1".to_owned()],
        });
        assert_eq!(consumer.pending_bytes.len(), 2);
        assert!(matches!(rx.try_recv(), Ok(FlowEvent::DnsResolved { .. })));
        consumer.on_event(FlowEvent::Opened(
            key,
            FlowMeta {
                pid: 42,
                process: None,
                open_ts: 0,
                cookie: None,
                if_index: None,
            },
        ));
        assert_eq!(consumer.pending_bytes.len(), 1);
        assert_eq!(consumer.pending_bytes.get(&other), Some(&delta));
        assert!(matches!(rx.try_recv(), Ok(FlowEvent::Bytes(found, _)) if found == key));
        assert!(matches!(rx.try_recv(), Ok(FlowEvent::Opened(found, _)) if found == key));
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn bounds_pending_byte_map_when_channel_is_full() {
        let (tx, _rx) = mpsc::channel(1);
        let mut consumer = BridgeConsumer::new(tx);
        consumer.pending_cap = 2;

        // The first delta reaches the channel; the rest would fill the map, and the
        // one past the cap is shed instead of growing it.
        for port in 50_000..50_004 {
            consumer.on_event(FlowEvent::Bytes(
                byte_key(port),
                ByteDelta {
                    sent: 1,
                    received: 0,
                },
            ));
        }

        assert_eq!(consumer.pending_bytes.len(), 2);
        assert_eq!(consumer.shed_byte_events, 1);
    }

    /// Shedding used to leave only a throttled warning, so low totals had no
    /// explanation the user could see.
    #[test]
    fn shed_byte_deltas_are_reported_to_collector_health() {
        let (tx, _rx) = mpsc::channel(1);
        let health = Arc::new(CollectorHealth::default());
        let mut consumer = BridgeConsumer::new(tx).reporting_to(Some(Arc::clone(&health)));
        consumer.pending_cap = 1;

        // 50_001 fills the channel and 50_002 the map, so 50_003 is shed.
        for port in [50_001, 50_002] {
            consumer.on_event(FlowEvent::Bytes(
                byte_key(port),
                ByteDelta {
                    sent: 1,
                    received: 0,
                },
            ));
        }
        assert!(health.byte_accounting_available());

        consumer.on_event(FlowEvent::Bytes(
            byte_key(50_003),
            ByteDelta {
                sent: 1,
                received: 0,
            },
        ));
        assert_eq!(consumer.shed_byte_events, 1);
        assert!(!health.byte_accounting_available());
        assert!(health.detail().contains("not counted"));
    }

    #[test]
    fn pending_byte_map_merges_known_flows_at_capacity() {
        let (tx, _rx) = mpsc::channel(1);
        let mut consumer = BridgeConsumer::new(tx);
        consumer.pending_cap = 1;
        let key = byte_key(50_002);

        // 50_001 goes to the channel; 50_002 fills the map; 50_003 is a different
        // key and is shed; the second 50_002 still merges into the retained key.
        for port in [50_001, 50_002, 50_003, 50_002] {
            consumer.on_event(FlowEvent::Bytes(
                byte_key(port),
                ByteDelta {
                    sent: 1,
                    received: 0,
                },
            ));
        }

        assert_eq!(consumer.pending_bytes.len(), 1);
        assert_eq!(consumer.shed_byte_events, 1);
        assert_eq!(
            consumer.pending_bytes.get(&key),
            Some(&ByteDelta {
                sent: 2,
                received: 0
            })
        );
    }

    #[test]
    fn lifecycle_event_waits_for_channel_capacity() {
        let (tx, mut rx) = mpsc::channel(1);
        let mut consumer = BridgeConsumer::new(tx);
        let key = FlowKey {
            protocol: Protocol::Tcp,
            local_addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
            local_port: 50_000,
            remote_addr: IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
            remote_port: 443,
        };
        consumer.on_event(FlowEvent::Bytes(
            key,
            ByteDelta {
                sent: 1,
                received: 0,
            },
        ));
        let sender = std::thread::spawn(move || {
            consumer.on_event(FlowEvent::Opened(
                key,
                FlowMeta {
                    pid: 4242,
                    process: None,
                    open_ts: 1,
                    cookie: None,
                    if_index: None,
                },
            ));
        });

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        runtime.block_on(async {
            assert!(matches!(rx.recv().await, Some(FlowEvent::Bytes(..))));
            assert!(matches!(rx.recv().await, Some(FlowEvent::Opened(..))));
        });
        sender.join().expect("sender thread");
    }

    #[test]
    fn lifecycle_event_flushes_pending_bytes_before_open() {
        let (tx, mut rx) = mpsc::channel(1);
        let mut consumer = BridgeConsumer::new(tx);
        let key = FlowKey {
            protocol: Protocol::Tcp,
            local_addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
            local_port: 50_001,
            remote_addr: IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
            remote_port: 443,
        };

        consumer.on_event(FlowEvent::Bytes(
            key,
            ByteDelta {
                sent: 10,
                received: 0,
            },
        ));
        consumer.on_event(FlowEvent::Bytes(
            key,
            ByteDelta {
                sent: 5,
                received: 3,
            },
        ));
        assert_eq!(
            consumer.pending_bytes.get(&key),
            Some(&ByteDelta {
                sent: 5,
                received: 3
            })
        );

        let sender = std::thread::spawn(move || {
            consumer.on_event(FlowEvent::Opened(
                key,
                FlowMeta {
                    pid: 4242,
                    process: None,
                    open_ts: 1,
                    cookie: None,
                    if_index: None,
                },
            ));
        });

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        runtime.block_on(async {
            let FlowEvent::Bytes(_, first) = rx.recv().await.expect("first bytes") else {
                panic!("expected first byte event");
            };
            assert_eq!(first.sent, 10);
            assert_eq!(first.received, 0);

            let FlowEvent::Bytes(_, second) = rx.recv().await.expect("flushed bytes") else {
                panic!("expected flushed byte event before lifecycle event");
            };
            assert_eq!(second.sent, 5);
            assert_eq!(second.received, 3);
            assert!(matches!(rx.recv().await, Some(FlowEvent::Opened(..))));
        });
        sender.join().expect("sender thread");
    }

    #[test]
    fn batch_buffer_forwards_owned_events_without_retaining_them() {
        let (tx, mut rx) = mpsc::channel(8);
        let mut consumer = BridgeConsumer::new(tx);
        let key = FlowKey {
            protocol: Protocol::Tcp,
            local_addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
            local_port: 50_002,
            remote_addr: IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
            remote_port: 443,
        };
        let meta = FlowMeta {
            pid: 7,
            process: None,
            open_ts: 1,
            cookie: None,
            if_index: None,
        };
        let mut events = vec![
            FlowEvent::Opened(key, meta.clone()),
            FlowEvent::Bytes(
                key,
                ByteDelta {
                    sent: 3,
                    received: 1,
                },
            ),
            FlowEvent::Closed(key, meta),
        ];
        consumer.on_batch_buffer(&mut events);
        assert!(events.is_empty());

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        runtime.block_on(async {
            assert!(matches!(rx.recv().await, Some(FlowEvent::Opened(..))));
            assert!(matches!(rx.recv().await, Some(FlowEvent::Bytes(..))));
            assert!(matches!(rx.recv().await, Some(FlowEvent::Closed(..))));
        });
    }

    #[test]
    fn start_with_zero_capacity_is_rejected() {
        let mut bridge = NetmetBridge::new();
        assert!(matches!(bridge.start(0), Err(FlowError::InvalidConfig(_))));
        bridge.stop().expect("stop after a rejected start");
    }

    #[test]
    fn stop_is_idempotent() {
        let mut bridge = NetmetBridge::new();
        bridge.stop().expect("stop without a start");
        bridge.stop().expect("second stop without a start");
    }

    /// The final flush is delivered as a batch; merged bytes must reach the channel there
    /// rather than being dropped with the consumer at shutdown.
    #[test]
    fn final_batch_flushes_merged_bytes() {
        let (tx, mut rx) = mpsc::channel(1);
        let mut consumer = BridgeConsumer::new(tx);
        let key = byte_key(50_010);
        consumer.on_event(FlowEvent::Bytes(
            key,
            ByteDelta {
                sent: 1,
                received: 0,
            },
        ));
        consumer.on_event(FlowEvent::Bytes(
            key,
            ByteDelta {
                sent: 2,
                received: 0,
            },
        ));
        assert_eq!(
            consumer.pending_bytes.get(&key),
            Some(&ByteDelta {
                sent: 2,
                received: 0
            })
        );

        let reader = std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("runtime");
            runtime.block_on(async {
                let mut total = 0_u64;
                while let Some(event) = rx.recv().await {
                    if let FlowEvent::Bytes(_, delta) = event {
                        total += delta.sent;
                    }
                }
                total
            })
        });

        let mut empty = Vec::new();
        consumer.on_batch_buffer(&mut empty);
        drop(consumer);

        assert_eq!(reader.join().expect("reader thread"), 3);
    }
}
