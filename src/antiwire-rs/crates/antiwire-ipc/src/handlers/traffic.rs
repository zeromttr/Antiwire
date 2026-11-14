//! Traffic statistics, streaming, and connection-log queries.

use crate::proto_bridge::{
    activity_bucket_to_proto, activity_bucket_window, app_summary_request_to_query,
    app_summary_to_proto, history_deletion_start, log_page_to_response, log_request_to_query,
    traffic_event_to_proto,
};
use crate::reply::{blocking, query};
use crate::stream::spawn_stream;
use antiwire_events::{ActiveConnectionCounter, CollectorHealth, TrafficStreamingHub};
use antiwire_store::Store;
use antiwire_tuning::IPC_EVENT_STREAM_CAPACITY;
use std::collections::HashMap;
use std::sync::Arc;
use tokio_util::sync::CancellationToken;
use tonic::{Request, Response, Status};

/// Traffic statistics, history, and the live stream.
pub(crate) struct TrafficApi {
    pub(crate) store: Arc<Store>,
    pub(crate) traffic_hub: TrafficStreamingHub,
    pub(crate) active_connections: Arc<dyn ActiveConnectionCounter>,
    pub(crate) collector_health: Arc<CollectorHealth>,
    pub(crate) shutdown: CancellationToken,
}

#[allow(clippy::result_large_err)] // `tonic::Status` is required by the gRPC surface.
impl TrafficApi {
    pub(super) async fn handle_get_stats(
        &self,
        _request: Request<antiwire_proto::Empty>,
    ) -> Result<Response<antiwire_proto::StatsResponse>, Status> {
        const SECONDS_PER_DAY: u32 = 86_400;
        let active_connections = Arc::clone(&self.active_connections);
        let store = Arc::clone(&self.store);
        let (
            active_connections,
            active_applications_count,
            blocked_connections_count,
            database_size_bytes,
        ) = blocking("stats query", move || {
            // The dashboard still shows the live counts when the history
            // cannot be read; the blocked count then reads as none.
            let blocked = store
                .count_blocked_connections(SECONDS_PER_DAY)
                .inspect_err(|error| tracing::warn!(%error, "blocked connection count failed"))
                .map_or(0, |count| u32::try_from(count).unwrap_or(u32::MAX));
            (
                active_connections.active_connections_count(),
                active_connections.active_application_count(),
                blocked,
                store.disk_size_bytes(),
            )
        })
        .await?;
        Ok(Response::new(antiwire_proto::StatsResponse {
            total_bytes_sent: self.traffic_hub.total_bytes_sent(),
            total_bytes_received: self.traffic_hub.total_bytes_received(),
            active_connections_count: active_connections.count.unwrap_or(0),
            blocked_connections_count,
            byte_accounting_available: self.collector_health.byte_accounting_available(),
            collector_status_detail: self.collector_health.detail(),
            active_connections_available: Some(active_connections.count.is_some()),
            active_connections_stale: active_connections.stale,
            active_applications_count,
            daemon_version: antiwire_update::PRODUCT_VERSION.to_owned(),
            database_size_bytes,
        }))
    }

    pub(super) async fn handle_get_active_applications(
        &self,
        _request: Request<antiwire_proto::Empty>,
    ) -> Result<Response<antiwire_proto::ActiveApplicationsResponse>, Status> {
        let active_connections = Arc::clone(&self.active_connections);
        let applications = blocking("active applications query", move || {
            active_connections.active_applications()
        })
        .await?;
        let available = applications.is_some();
        let mut applications = applications.unwrap_or_default();
        // Busiest right now first; connection count breaks ties between idle apps.
        applications.sort_by(|a, b| {
            (b.download_rate + b.upload_rate)
                .cmp(&(a.download_rate + a.upload_rate))
                .then_with(|| b.connection_count.cmp(&a.connection_count))
                .then_with(|| a.app_name.cmp(&b.app_name))
        });
        Ok(Response::new(antiwire_proto::ActiveApplicationsResponse {
            applications: applications
                .into_iter()
                .map(|app| antiwire_proto::ActiveApplication {
                    app_name: app.app_name,
                    app_path: app.app_path,
                    connection_count: app.connection_count,
                    download_rate: app.download_rate,
                    upload_rate: app.upload_rate,
                    top_destinations: app.top_destinations,
                    destination_count: app.destination_count,
                    newest_opened_at: app.newest_opened_at,
                })
                .collect(),
            available,
        }))
    }

    pub(super) fn handle_stream_realtime_traffic(
        &self,
        _request: Request<antiwire_proto::Empty>,
    ) -> Response<super::StreamRealtimeTrafficStream> {
        let mut subscription = self.traffic_hub.subscribe();
        Response::new(spawn_stream(
            IPC_EVENT_STREAM_CAPACITY,
            &self.shutdown,
            |sink| async move {
                while let Some(event) = subscription.recv().await {
                    if sink.send(traffic_event_to_proto(event)).await.is_err() {
                        return;
                    }
                }
            },
        ))
    }

    pub(super) async fn handle_get_connection_logs(
        &self,
        request: Request<antiwire_proto::LogRequest>,
    ) -> Result<Response<antiwire_proto::LogResponse>, Status> {
        let log_query = log_request_to_query(request.into_inner());
        // SQLite is synchronous; a slow or locked database must not stall the
        // runtime that serves traffic streaming.
        let store = Arc::clone(&self.store);
        let (page, apps) = query("log query", move || {
            let page = store.query_connection_logs(&log_query)?;
            // Only the ids the page references: loading the whole applications
            // table per request grew with the lifetime of the daemon, the page
            // does not.
            let app_ids: Vec<i32> = page.logs.iter().map(|log| log.app_id).collect();
            let apps: HashMap<i32, (String, String)> = store
                .find_applications_by_ids(&app_ids)?
                .into_iter()
                .map(|app| (app.id, (app.app_name, app.app_path)))
                .collect();
            Ok::<_, antiwire_store::StoreError>((page, apps))
        })
        .await?;
        Ok(Response::new(log_page_to_response(&page, &apps)))
    }

    pub(super) async fn handle_get_application_log_summaries(
        &self,
        request: Request<antiwire_proto::ApplicationLogSummaryRequest>,
    ) -> Result<Response<antiwire_proto::ApplicationLogSummaryResponse>, Status> {
        let summary_query = app_summary_request_to_query(request.into_inner());
        let store = Arc::clone(&self.store);
        let summaries = query("summary query", move || {
            store.query_application_log_summaries(&summary_query)
        })
        .await?;

        let applications: Vec<_> = summaries.iter().map(app_summary_to_proto).collect();
        let total_count = applications
            .iter()
            .map(|summary| u64::from(summary.total_count))
            .sum::<u64>();
        let blocked_count = applications
            .iter()
            .map(|summary| u64::from(summary.blocked_count))
            .sum::<u64>();

        Ok(Response::new(
            antiwire_proto::ApplicationLogSummaryResponse {
                applications,
                total_count: u32::try_from(total_count).unwrap_or(u32::MAX),
                blocked_count: u32::try_from(blocked_count).unwrap_or(u32::MAX),
            },
        ))
    }

    pub(super) async fn handle_get_activity_buckets(
        &self,
        request: Request<antiwire_proto::ActivityBucketsRequest>,
    ) -> Result<Response<antiwire_proto::ActivityBucketsResponse>, Status> {
        let request = request.into_inner();
        let (since, until) = activity_bucket_window(request.days, request.since, request.until)
            .map_err(Status::invalid_argument)?;
        let store = Arc::clone(&self.store);
        let buckets = query("activity query", move || {
            store.query_activity_buckets(since, until)
        })
        .await?;
        Ok(Response::new(antiwire_proto::ActivityBucketsResponse {
            buckets: buckets.iter().map(activity_bucket_to_proto).collect(),
        }))
    }

    pub(super) async fn handle_delete_history(
        &self,
        request: Request<antiwire_proto::DeleteHistoryRequest>,
    ) -> Result<Response<antiwire_proto::DeleteHistoryResponse>, Status> {
        let since =
            history_deletion_start(&request.into_inner()).map_err(Status::invalid_argument)?;
        let store = Arc::clone(&self.store);
        let deleted = query("history delete", move || store.delete_history(since)).await?;
        tracing::info!(deleted, ?since, "history deleted on request");
        Ok(Response::new(antiwire_proto::DeleteHistoryResponse {
            success: true,
            message: "History deleted".to_owned(),
            deleted_count: deleted,
        }))
    }

    pub(super) async fn handle_get_country_statistics(
        &self,
        _request: Request<antiwire_proto::Empty>,
    ) -> Result<Response<antiwire_proto::CountryStatisticsResponse>, Status> {
        let store = Arc::clone(&self.store);
        let statistics = query("country query", move || store.query_country_statistics()).await?;
        Ok(Response::new(antiwire_proto::CountryStatisticsResponse {
            country_counts: statistics.country_counts.into_iter().collect(),
            total_count: statistics.total_count,
            unknown_count: statistics.unknown_count,
        }))
    }
}
