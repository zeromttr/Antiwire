//! Alert publication: saving, SIEM forwarding, and fan-out to subscribers.
//!
//! Producers hold an [`AlertPublisher`]. It saves each alert before anyone sees
//! it, because clients key and dismiss notifications by database id, then
//! forwards it to SIEM and hands it to the [`NotificationHub`], which only fans
//! it out. Saving runs on a writer thread, so a producer never waits for
//! `SQLite`; when the writer falls behind, alerts are counted and reported as
//! dropped rather than stalling the producer.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender, TrySendError};
use std::sync::Arc;
use std::thread::JoinHandle;

use antiwire_platform::SiemExporter;
use antiwire_policy::display_text;
use antiwire_store::{NewAlert, Store};
use antiwire_tuning::NOTIFICATION_QUEUE_CAPACITY;
use time::OffsetDateTime;
use tokio::sync::broadcast;

use crate::{Alert, AlertKind, Notification, Severity};

const DEFAULT_QUEUE_CAPACITY: usize = NOTIFICATION_QUEUE_CAPACITY as usize;

/// Longest title retained for a saved or streamed notification.
const MAX_TITLE_CHARS: usize = 256;
/// Longest message retained for a saved or streamed notification.
const MAX_MESSAGE_CHARS: usize = 1024;
/// Most alerts the writer saves in one transaction.
const WRITER_BATCH: usize = 64;

/// Fans notifications out to every subscriber, each with a bounded queue.
#[derive(Clone)]
pub struct NotificationHub {
    sender: broadcast::Sender<Notification>,
}

impl NotificationHub {
    #[must_use]
    pub fn new() -> Self {
        Self::with_capacity(DEFAULT_QUEUE_CAPACITY)
    }

    #[must_use]
    pub fn with_capacity(capacity: usize) -> Self {
        let (sender, _) = broadcast::channel(capacity);
        Self { sender }
    }

    pub fn subscribe(&self) -> NotificationSubscription {
        NotificationSubscription {
            receiver: self.sender.subscribe(),
        }
    }

    fn deliver(&self, notification: Notification) {
        if self.sender.receiver_count() > 0 {
            let _ = self.sender.send(notification);
        }
    }
}

impl Default for NotificationHub {
    fn default() -> Self {
        Self::new()
    }
}

/// One subscriber's view of the hub; dropping it unsubscribes.
pub struct NotificationSubscription {
    receiver: broadcast::Receiver<Notification>,
}

impl NotificationSubscription {
    /// The next notification, or `None` once the hub is gone.
    ///
    /// A subscriber that fell behind gets a [`AlertKind::NotificationsLagged`]
    /// marker in place of what it missed, so a slow client sees the gap
    /// instead of silently losing alerts.
    pub async fn recv(&mut self) -> Option<Notification> {
        match self.receiver.recv().await {
            Ok(notification) => Some(notification),
            Err(broadcast::error::RecvError::Lagged(skipped)) => Some(Notification::from_alert(
                Alert::new(
                    AlertKind::NotificationsLagged,
                    Severity::Warning,
                    "Some notifications were missed",
                    format!(
                        "{skipped} notification(s) were dropped because this stream fell behind."
                    ),
                ),
                0,
            )),
            Err(broadcast::error::RecvError::Closed) => None,
        }
    }
}

/// Publishes alerts: saves them, forwards them to SIEM, then notifies subscribers.
#[derive(Clone)]
pub struct AlertPublisher {
    inner: Arc<PublisherInner>,
}

struct PublisherInner {
    sinks: Arc<Sinks>,
    writer: Option<Writer>,
}

/// Where a published alert goes after it is saved.
struct Sinks {
    hub: NotificationHub,
    siem: Option<SiemExporter>,
}

struct Writer {
    queue: Option<SyncSender<WriterMessage>>,
    thread: Option<JoinHandle<()>>,
    /// Alerts refused because the queue was full, not yet reported.
    dropped: Arc<AtomicU64>,
}

enum WriterMessage {
    Alert(Alert),
    /// Answered once every alert queued before it is saved and delivered.
    Flush(mpsc::Sender<()>),
}

impl AlertPublisher {
    /// A publisher that delivers alerts without saving them.
    #[must_use]
    pub fn unsaved(hub: NotificationHub, siem: Option<SiemExporter>) -> Self {
        Self {
            inner: Arc::new(PublisherInner {
                sinks: Arc::new(Sinks { hub, siem }),
                writer: None,
            }),
        }
    }

    /// A publisher that saves every alert to `store` before delivering it.
    ///
    /// # Panics
    ///
    /// Panics if the writer thread cannot be spawned.
    #[must_use]
    pub fn saved(hub: NotificationHub, store: Arc<Store>, siem: Option<SiemExporter>) -> Self {
        let sinks = Arc::new(Sinks { hub, siem });
        let (queue, messages) = mpsc::sync_channel(DEFAULT_QUEUE_CAPACITY);
        let dropped = Arc::new(AtomicU64::new(0));
        let thread = std::thread::Builder::new()
            .name("antiwire-alerts".to_owned())
            .spawn({
                let sinks = Arc::clone(&sinks);
                let dropped = Arc::clone(&dropped);
                move || run_writer(&messages, &store, &sinks, &dropped)
            })
            .expect("spawn alert writer");
        Self {
            inner: Arc::new(PublisherInner {
                sinks,
                writer: Some(Writer {
                    queue: Some(queue),
                    thread: Some(thread),
                    dropped,
                }),
            }),
        }
    }

    /// Publishes `alert`. Never blocks: an alert the writer has no room for
    /// is counted and later reported as an [`AlertKind::AlertsDropped`] alert.
    pub fn publish(&self, alert: Alert) {
        let alert = sanitized(alert);
        let Some((queue, dropped)) = self.writer() else {
            self.inner.sinks.deliver(Notification::from_alert(alert, 0));
            return;
        };
        match queue.try_send(WriterMessage::Alert(alert)) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) => {
                if dropped.fetch_add(1, Ordering::Relaxed) == 0 {
                    tracing::warn!("alert writer is behind; dropping alerts until it catches up");
                }
            }
            Err(TrySendError::Disconnected(message)) => {
                tracing::error!("alert writer is gone; delivering the alert unsaved");
                if let WriterMessage::Alert(alert) = message {
                    self.inner.sinks.deliver(Notification::from_alert(alert, 0));
                }
            }
        }
    }

    /// Waits until every alert published before this call is saved and
    /// delivered. Blocking; returns at once for a publisher that does not save.
    pub fn flush(&self) {
        let Some((queue, _)) = self.writer() else {
            return;
        };
        let (done, wait) = mpsc::channel();
        if queue.send(WriterMessage::Flush(done)).is_ok() {
            let _ = wait.recv();
        }
    }

    /// Subscribes to the notifications this publisher delivers.
    pub fn subscribe(&self) -> NotificationSubscription {
        self.inner.sinks.hub.subscribe()
    }

    fn writer(&self) -> Option<(&SyncSender<WriterMessage>, &AtomicU64)> {
        let writer = self.inner.writer.as_ref()?;
        Some((writer.queue.as_ref()?, &writer.dropped))
    }
}

impl Drop for PublisherInner {
    fn drop(&mut self) {
        // Closing the queue lets the writer save what is queued and exit.
        if let Some(writer) = &mut self.writer {
            writer.queue.take();
            if let Some(thread) = writer.thread.take() {
                let _ = thread.join();
            }
        }
    }
}

impl Sinks {
    fn deliver(&self, notification: Notification) {
        if let Some(siem) = &self.siem {
            siem.queue_threat_event(
                notification.kind.as_str(),
                &notification.title,
                &notification.message,
                notification.severity.as_str(),
            );
        }
        self.hub.deliver(notification);
    }
}

/// Formats producer-chosen text for display. This is the one place alert text
/// is made safe to save, forward, and show, so producers need not repeat it.
fn sanitized(mut alert: Alert) -> Alert {
    alert.title = display_text(&alert.title, MAX_TITLE_CHARS);
    alert.message = display_text(&alert.message, MAX_MESSAGE_CHARS);
    alert
}

/// Saves queued alerts in batches, delivering each after its batch commits.
fn run_writer(
    messages: &Receiver<WriterMessage>,
    store: &Store,
    sinks: &Sinks,
    dropped: &AtomicU64,
) {
    while let Ok(first) = messages.recv() {
        let mut batch = vec![first];
        while batch.len() < WRITER_BATCH {
            match messages.try_recv() {
                Ok(message) => batch.push(message),
                Err(_) => break,
            }
        }
        let mut pending = Vec::new();
        for message in batch {
            match message {
                WriterMessage::Alert(alert) => pending.push(alert),
                WriterMessage::Flush(done) => {
                    save_and_deliver(store, sinks, std::mem::take(&mut pending));
                    let _ = done.send(());
                }
            }
        }
        save_and_deliver(store, sinks, pending);
        report_dropped(store, sinks, dropped);
    }
}

fn save_and_deliver(store: &Store, sinks: &Sinks, alerts: Vec<Alert>) {
    if alerts.is_empty() {
        return;
    }
    let rows: Vec<NewAlert> = alerts.iter().map(new_alert_row).collect();
    let ids = match store.insert_alerts(&rows) {
        Ok(ids) => ids,
        Err(error) => {
            tracing::error!(%error, count = alerts.len(), "failed to save alerts");
            vec![0; alerts.len()]
        }
    };
    for (alert, id) in alerts.into_iter().zip(ids) {
        sinks.deliver(Notification::from_alert(
            alert,
            u64::try_from(id).unwrap_or(0),
        ));
    }
}

fn report_dropped(store: &Store, sinks: &Sinks, dropped: &AtomicU64) {
    let count = dropped.swap(0, Ordering::Relaxed);
    if count == 0 {
        return;
    }
    let alert = Alert::new(
        AlertKind::AlertsDropped,
        Severity::Warning,
        "Some alerts were not saved",
        format!("{count} alert(s) were dropped because they were raised faster than they could be saved."),
    );
    save_and_deliver(store, sinks, vec![alert]);
}

fn new_alert_row(alert: &Alert) -> NewAlert {
    NewAlert {
        alert_type: alert.kind.as_str().to_owned(),
        title: alert.title.clone(),
        message: alert.message.clone(),
        timestamp: OffsetDateTime::from_unix_timestamp(i64::try_from(alert.timestamp).unwrap_or(0))
            .unwrap_or(OffsetDateTime::UNIX_EPOCH),
        severity: alert.severity.as_str().to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    fn alert(title: &str) -> Alert {
        Alert::new(AlertKind::MaliciousFlow, Severity::Warning, title, "").at(1)
    }

    fn saved_publisher() -> (NamedTempFile, Arc<Store>, AlertPublisher) {
        let file = NamedTempFile::with_suffix(".libsql").expect("temp file");
        let store = Arc::new(Store::open(file.path()).expect("open store"));
        let publisher = AlertPublisher::saved(NotificationHub::new(), Arc::clone(&store), None);
        (file, store, publisher)
    }

    #[tokio::test]
    async fn an_unsaved_alert_reaches_subscribers() {
        let publisher = AlertPublisher::unsaved(NotificationHub::with_capacity(4), None);
        let mut subscription = publisher.subscribe();

        publisher.publish(alert("hello"));

        let notification = subscription.recv().await.expect("notification");
        assert_eq!(notification.title, "hello");
        assert_eq!(notification.id, 0);
    }

    #[tokio::test]
    async fn a_saved_alert_carries_its_database_id() {
        let (_file, store, publisher) = saved_publisher();
        let mut subscription = publisher.subscribe();

        publisher.publish(alert("Blocked connection"));

        let notification = subscription.recv().await.expect("notification");
        let saved = store.list_alerts().expect("saved alerts");
        assert_eq!(saved.len(), 1);
        assert_eq!(notification.id, u64::try_from(saved[0].id).expect("id"));
        assert_eq!(saved[0].alert_type, "MALICIOUS_FLOW");
    }

    #[test]
    fn flush_waits_for_every_earlier_alert() {
        let (_file, store, publisher) = saved_publisher();
        for title in ["first", "second", "third"] {
            publisher.publish(alert(title));
        }

        publisher.flush();

        assert_eq!(store.list_alerts().expect("saved alerts").len(), 3);
    }

    #[test]
    fn dropping_the_publisher_saves_what_was_queued() {
        let (_file, store, publisher) = saved_publisher();
        publisher.publish(alert("queued"));

        drop(publisher);

        let saved = store.list_alerts().expect("saved alerts");
        assert_eq!(saved.len(), 1);
        assert_eq!(saved[0].title, "queued");
    }

    #[test]
    fn alerts_beyond_the_queue_are_reported_instead_of_blocking() {
        let file = NamedTempFile::with_suffix(".libsql").expect("temp file");
        let store = Store::open(file.path()).expect("open store");
        let sinks = Sinks {
            hub: NotificationHub::new(),
            siem: None,
        };
        let dropped = AtomicU64::new(3);

        report_dropped(&store, &sinks, &dropped);

        let saved = store.list_alerts().expect("saved alerts");
        assert_eq!(saved.len(), 1);
        assert_eq!(saved[0].alert_type, "ALERTS_DROPPED");
        assert!(saved[0].message.starts_with("3 alert(s)"));
        assert_eq!(dropped.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn a_lagged_subscriber_gets_a_marker_then_resumes() {
        let publisher = AlertPublisher::unsaved(NotificationHub::with_capacity(1), None);
        let mut subscription = publisher.subscribe();

        for title in ["first", "second", "third"] {
            publisher.publish(alert(title));
        }

        let marker = subscription.recv().await.expect("lag marker");
        assert_eq!(marker.kind, AlertKind::NotificationsLagged);
        assert!(
            marker.message.contains('2'),
            "two notifications were dropped"
        );
        assert_eq!(subscription.recv().await.expect("latest").title, "third");
    }

    #[tokio::test]
    async fn alert_text_is_made_safe_to_display() {
        let publisher = AlertPublisher::unsaved(NotificationHub::with_capacity(4), None);
        let mut subscription = publisher.subscribe();

        publisher.publish(Alert::new(
            AlertKind::MaliciousFlow,
            Severity::Warning,
            "evil\ntitle\u{202E}",
            format!("line\ninjected{}", "x".repeat(2_000)),
        ));

        let notification = subscription.recv().await.expect("notification");
        assert_eq!(notification.title, r"eviltitle\u{202E}");
        assert!(!notification.message.contains('\n'));
        assert!(notification.message.chars().count() <= MAX_MESSAGE_CHARS);
    }
}
