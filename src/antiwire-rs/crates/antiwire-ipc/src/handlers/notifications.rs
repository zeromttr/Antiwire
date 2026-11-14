//! Notification streaming and persisted alerts.

use crate::proto_bridge::{alert_to_proto, notification_to_proto};
use crate::reply::{blocking, done, query, refused};
use crate::stream::spawn_stream;
use antiwire_events::AlertPublisher;
use antiwire_store::Store;
use antiwire_tuning::IPC_EVENT_STREAM_CAPACITY;
use std::sync::Arc;
use tokio_util::sync::CancellationToken;
use tonic::{Request, Response, Status};

/// Alerts and the notification stream.
pub(crate) struct AlertsApi {
    pub(crate) store: Arc<Store>,
    pub(crate) alerts: AlertPublisher,
    pub(crate) shutdown: CancellationToken,
}

#[allow(clippy::result_large_err)] // `tonic::Status` is required by the gRPC surface.
impl AlertsApi {
    pub(super) fn handle_stream_notifications(
        &self,
        _request: Request<antiwire_proto::Empty>,
    ) -> Response<super::StreamNotificationsStream> {
        let mut subscription = self.alerts.subscribe();
        Response::new(spawn_stream(
            IPC_EVENT_STREAM_CAPACITY,
            &self.shutdown,
            |sink| async move {
                while let Some(event) = subscription.recv().await {
                    if sink.send(notification_to_proto(event)).await.is_err() {
                        return;
                    }
                }
            },
        ))
    }

    pub(super) async fn handle_get_alerts(
        &self,
        _request: Request<antiwire_proto::Empty>,
    ) -> Result<Response<antiwire_proto::AlertsResponse>, Status> {
        const MAX_ALERTS: usize = 100;
        let store = Arc::clone(&self.store);
        let alerts = query("alert query", move || store.list_recent_alerts(MAX_ALERTS)).await?;
        Ok(Response::new(antiwire_proto::AlertsResponse {
            alerts: alerts.iter().map(alert_to_proto).collect(),
        }))
    }

    pub(super) async fn handle_dismiss_alert(
        &self,
        request: Request<antiwire_proto::AlertRequest>,
    ) -> Result<Response<antiwire_proto::ActionResponse>, Status> {
        let Ok(id) = i64::try_from(request.into_inner().id) else {
            return Ok(Response::new(refused("Alert id is out of range.")));
        };
        let store = Arc::clone(&self.store);
        // Dismissing is idempotent: an alert another window already dismissed
        // is gone, which is what was asked for.
        Ok(Response::new(
            match blocking("alert dismissal", move || store.delete_alert(id)).await? {
                Ok(true) => done("Alert dismissed"),
                Ok(false) => done("Alert was already dismissed"),
                Err(error) => refused(format!("The alert could not be dismissed: {error}")),
            },
        ))
    }

    pub(super) async fn handle_clear_alerts(
        &self,
        _request: Request<antiwire_proto::Empty>,
    ) -> Result<Response<antiwire_proto::ActionResponse>, Status> {
        let store = Arc::clone(&self.store);
        Ok(Response::new(
            match blocking("alert clearing", move || store.clear_alerts()).await? {
                Ok(_) => done("Alerts cleared"),
                Err(error) => refused(format!("The alerts could not be cleared: {error}")),
            },
        ))
    }
}
