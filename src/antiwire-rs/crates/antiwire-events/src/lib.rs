//! Domain events and status shared by the daemon's producers and its IPC layer.
//!
//! Producers such as the flow tracker, the DNS block recorder, and the
//! background services publish here, and the IPC layer subscribes and converts
//! to wire types. Nothing in this crate depends on the transport, so neither
//! do the producers.

mod active_connections;
mod alert;
mod collector_health;
mod notification;
mod traffic;

#[cfg(any(test, feature = "test-support"))]
pub use active_connections::ZeroActiveConnectionCounter;
pub use active_connections::{
    ActiveApplicationSample, ActiveConnectionCounter, ActiveConnectionSample,
};
pub use alert::{Alert, AlertKind, Notification, Severity};
pub use collector_health::CollectorHealth;
pub use notification::{AlertPublisher, NotificationHub, NotificationSubscription};
pub use traffic::{TrafficEvent, TrafficEventKind, TrafficStreamingHub, TrafficSubscription};

/// Seconds since the Unix epoch, clamped to zero for a clock before it.
pub(crate) fn unix_now() -> u64 {
    u64::try_from(time::OffsetDateTime::now_utc().unix_timestamp()).unwrap_or(0)
}
