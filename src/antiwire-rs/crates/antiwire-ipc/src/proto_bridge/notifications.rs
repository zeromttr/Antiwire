//! Saved alerts and live notifications to notification events.

use super::timestamps::datetime_to_unix_secs;

use antiwire_events::Notification;
use antiwire_proto::NotificationEvent;
use antiwire_store::Alert;

pub(crate) fn alert_to_proto(alert: &Alert) -> NotificationEvent {
    NotificationEvent {
        r#type: alert.alert_type.clone(),
        title: alert.title.clone(),
        message: alert.message.clone(),
        timestamp: datetime_to_unix_secs(alert.timestamp),
        severity: alert.severity.clone(),
        id: u64::try_from(alert.id).unwrap_or(0),
    }
}

pub(crate) fn notification_to_proto(notification: Notification) -> NotificationEvent {
    NotificationEvent {
        r#type: notification.kind.as_str().to_owned(),
        title: notification.title,
        message: notification.message,
        timestamp: notification.timestamp,
        severity: notification.severity.as_str().to_owned(),
        id: notification.id,
    }
}
