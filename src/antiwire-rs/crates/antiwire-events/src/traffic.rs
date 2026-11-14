//! Live traffic events and their fan-out to subscribers.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

use antiwire_tuning::TRAFFIC_STREAM_QUEUE_CAPACITY;
use tokio::sync::broadcast;

/// What a [`TrafficEvent`]'s byte counts mean.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum TrafficEventKind {
    /// A connection record as written: the byte counts are the flow's totals.
    #[default]
    FlowRecord,
    /// Bytes moved since the previous delta for the same live flow.
    ByteDelta,
    /// The subscriber fell behind and missed events; only `timestamp` is set.
    /// Totals from a later [`TrafficEventKind::FlowRecord`] are still correct,
    /// but missed deltas are gone.
    Lagged,
}

/// One live traffic observation.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TrafficEvent {
    pub kind: TrafficEventKind,
    /// Unix seconds.
    pub timestamp: u64,
    pub app_name: String,
    pub app_path: String,
    pub protocol: String,
    pub src_ip: String,
    pub src_port: u32,
    pub dst_ip: String,
    pub dst_port: u32,
    pub dst_domain: String,
    /// Totals or a delta, according to `kind`.
    pub bytes_sent: u64,
    /// Totals or a delta, according to `kind`.
    pub bytes_received: u64,
    /// `ALLOWED` or `BLOCKED` for a record; `UPDATE` for a delta.
    pub action: String,
    /// Unix seconds.
    pub last_seen: u64,
    pub country_code: String,
    pub isp: String,
    /// Blocklists that produced a hosts-blocklist block.
    pub blocklist_names: Vec<String>,
    /// Database row id, or 0 for an event not yet saved.
    pub id: i32,
    /// Unix seconds when the connection ended, or 0 when no close was seen.
    pub closed_at: u64,
    /// Confirmed open in this session. False means unknown, not closed.
    pub is_active: bool,
}

struct TrafficStreamingHubInner {
    publish_enabled: AtomicBool,
    total_bytes_sent: AtomicU64,
    total_bytes_received: AtomicU64,
    sender: broadcast::Sender<TrafficPublication>,
}

#[derive(Clone)]
#[allow(clippy::large_enum_variant)]
enum TrafficPublication {
    Full(TrafficEvent),
    Delta {
        template: Arc<TrafficEvent>,
        sent: u64,
        received: u64,
        timestamp: u64,
    },
}

/// Fans live traffic events out to subscribers, each with a bounded queue,
/// and keeps the daemon's running byte totals.
#[derive(Clone)]
pub struct TrafficStreamingHub {
    inner: Arc<TrafficStreamingHubInner>,
}

impl TrafficStreamingHub {
    #[must_use]
    pub fn new() -> Self {
        Self::with_capacity(TRAFFIC_STREAM_QUEUE_CAPACITY as usize)
    }

    #[must_use]
    pub fn with_capacity(capacity: usize) -> Self {
        let (sender, _) = broadcast::channel(capacity);
        Self {
            inner: Arc::new(TrafficStreamingHubInner {
                publish_enabled: AtomicBool::new(true),
                total_bytes_sent: AtomicU64::new(0),
                total_bytes_received: AtomicU64::new(0),
                sender,
            }),
        }
    }

    pub fn total_bytes_sent(&self) -> u64 {
        self.inner.total_bytes_sent.load(Ordering::Relaxed)
    }

    pub fn total_bytes_received(&self) -> u64 {
        self.inner.total_bytes_received.load(Ordering::Relaxed)
    }

    pub fn record_bytes(&self, sent: u64, received: u64) {
        if sent > 0 {
            self.inner
                .total_bytes_sent
                .fetch_add(sent, Ordering::Relaxed);
        }
        if received > 0 {
            self.inner
                .total_bytes_received
                .fetch_add(received, Ordering::Relaxed);
        }
    }

    pub fn subscribe(&self) -> TrafficSubscription {
        TrafficSubscription {
            receiver: self.inner.sender.subscribe(),
        }
    }

    /// Whether [`Self::publish`] would deliver to at least one live subscriber.
    ///
    /// Callers on hot paths use this to avoid building an event that would be
    /// dropped on arrival. It can race a subscriber joining or leaving, so it is
    /// an optimization hint only; [`Self::publish`] still re-checks.
    pub fn has_subscribers(&self) -> bool {
        self.inner.publish_enabled.load(Ordering::Relaxed) && self.inner.sender.receiver_count() > 0
    }

    /// Publishes a connection record, whose byte counts are the flow's totals.
    pub fn publish(&self, mut event: TrafficEvent) {
        if self.has_subscribers() {
            event.kind = TrafficEventKind::FlowRecord;
            let _ = self.inner.sender.send(TrafficPublication::Full(event));
        }
    }

    /// Publishes a byte delta for a live flow without cloning the flow's
    /// strings on the producer: subscribers fill in `template` themselves.
    pub fn publish_byte_delta(
        &self,
        template: Arc<TrafficEvent>,
        sent: u64,
        received: u64,
        timestamp: u64,
    ) {
        if self.has_subscribers() {
            let _ = self.inner.sender.send(TrafficPublication::Delta {
                template,
                sent,
                received,
                timestamp,
            });
        }
    }

    /// Stops publishing new events during daemon shutdown.
    pub fn cancel_all(&self) {
        self.inner.publish_enabled.store(false, Ordering::Relaxed);
    }
}

impl Default for TrafficStreamingHub {
    fn default() -> Self {
        Self::new()
    }
}

/// One subscriber's view of the hub; dropping it unsubscribes.
pub struct TrafficSubscription {
    receiver: broadcast::Receiver<TrafficPublication>,
}

impl TrafficSubscription {
    /// The next event, or `None` once the hub is gone. A subscriber that fell
    /// behind gets one [`TrafficEventKind::Lagged`] event for the gap.
    pub async fn recv(&mut self) -> Option<TrafficEvent> {
        match self.receiver.recv().await {
            Ok(TrafficPublication::Full(event)) => Some(event),
            Ok(TrafficPublication::Delta {
                template,
                sent,
                received,
                timestamp,
            }) => {
                let mut event = (*template).clone();
                event.kind = TrafficEventKind::ByteDelta;
                event.timestamp = timestamp;
                event.last_seen = timestamp;
                event.bytes_sent = sent;
                event.bytes_received = received;
                Some(event)
            }
            Err(broadcast::error::RecvError::Lagged(_)) => Some(TrafficEvent {
                kind: TrafficEventKind::Lagged,
                timestamp: crate::unix_now(),
                ..TrafficEvent::default()
            }),
            Err(broadcast::error::RecvError::Closed) => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test]
    async fn shared_delta_templates_keep_each_delta_and_the_template_immutable() {
        let hub = TrafficStreamingHub::with_capacity(4);
        let mut subscription = hub.subscribe();
        let template = Arc::new(TrafficEvent {
            app_name: "app.exe".into(),
            action: "UPDATE".into(),
            is_active: true,
            ..Default::default()
        });
        hub.publish_byte_delta(Arc::clone(&template), 1, 2, 10);
        hub.publish_byte_delta(Arc::clone(&template), 3, 4, 20);
        assert_eq!(Arc::strong_count(&template), 3);
        let first = subscription.recv().await.unwrap();
        let second = subscription.recv().await.unwrap();
        assert_eq!(first.kind, TrafficEventKind::ByteDelta);
        assert_eq!(
            (first.bytes_sent, first.bytes_received, first.last_seen),
            (1, 2, 10)
        );
        assert_eq!(
            (second.bytes_sent, second.bytes_received, second.last_seen),
            (3, 4, 20)
        );
        assert_eq!((template.bytes_sent, template.timestamp), (0, 0));
    }

    #[tokio::test]
    async fn a_record_reaches_subscribers_as_a_record() {
        let hub = TrafficStreamingHub::with_capacity(4);
        let mut subscription = hub.subscribe();

        hub.publish(TrafficEvent {
            kind: TrafficEventKind::ByteDelta,
            app_name: "test.exe".to_owned(),
            ..Default::default()
        });

        let event = subscription.recv().await.expect("event");
        assert_eq!(event.app_name, "test.exe");
        assert_eq!(event.kind, TrafficEventKind::FlowRecord);
    }

    #[tokio::test]
    async fn a_lagged_subscriber_is_told_about_the_gap() {
        let hub = TrafficStreamingHub::with_capacity(1);
        let mut subscription = hub.subscribe();
        for name in ["first", "second", "third"] {
            hub.publish(TrafficEvent {
                app_name: name.to_owned(),
                ..Default::default()
            });
        }

        let marker = subscription.recv().await.expect("lag marker");
        assert_eq!(marker.kind, TrafficEventKind::Lagged);
        assert_eq!(subscription.recv().await.expect("latest").app_name, "third");
    }

    #[test]
    fn has_subscribers_tracks_live_receivers_and_cancellation() {
        let hub = TrafficStreamingHub::with_capacity(4);
        assert!(!hub.has_subscribers());

        let subscription = hub.subscribe();
        assert!(hub.has_subscribers());

        hub.cancel_all();
        assert!(!hub.has_subscribers());
        drop(subscription);
    }

    #[tokio::test]
    async fn cancel_all_stops_publishing() {
        let hub = TrafficStreamingHub::with_capacity(4);
        let mut subscription = hub.subscribe();

        hub.publish(TrafficEvent {
            app_name: "before-cancel".to_owned(),
            ..Default::default()
        });
        let first = subscription.recv().await.expect("first event");
        assert_eq!(first.app_name, "before-cancel");

        hub.cancel_all();
        hub.publish(TrafficEvent {
            app_name: "after-cancel".to_owned(),
            ..Default::default()
        });

        let result = tokio::time::timeout(Duration::from_millis(50), subscription.recv()).await;
        assert!(
            result.is_err(),
            "cancelled hub must not deliver further events"
        );
    }
}
