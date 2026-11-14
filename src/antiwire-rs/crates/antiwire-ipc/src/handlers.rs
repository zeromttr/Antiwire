//! gRPC routing for the domain-specific handler modules.
//! Keep request handling in the owning domain; this trait implementation only dispatches.

mod ai_decisions;
mod capture;
mod domain_lookup;
mod network_mapping;
mod notifications;
mod rules;
mod settings;
mod traffic;
mod updates;

pub(crate) use ai_decisions::AiDecisionsApi;
pub(crate) use capture::CaptureApi;
pub(crate) use domain_lookup::DomainLookupApi;
pub(crate) use network_mapping::NetworkMappingApi;
pub(crate) use notifications::AlertsApi;
pub(crate) use rules::RulesApi;
pub(crate) use settings::SettingsApi;
pub(crate) use traffic::TrafficApi;
pub(crate) use updates::UpdatesApi;

use crate::service::ServiceImpl;
use antiwire_proto::antiwire_service_server::AntiwireService;
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status};

/// Every server stream: items queued by a task, see [`crate::stream`].
pub(super) type ServerStream<T> = ReceiverStream<Result<T, Status>>;

pub(super) type StreamRealtimeTrafficStream = ServerStream<antiwire_proto::TrafficEvent>;
pub(super) type StreamNotificationsStream = ServerStream<antiwire_proto::NotificationEvent>;
pub(super) type StreamCaptureStatusStream = ServerStream<antiwire_proto::CaptureStatus>;
pub(super) type StreamCapturedPacketsStream = ServerStream<antiwire_proto::CapturedPacket>;
pub(super) type DownloadCaptureStream = ServerStream<antiwire_proto::CaptureChunk>;

#[tonic::async_trait]
impl AntiwireService for ServiceImpl {
    async fn get_stats(
        &self,
        request: Request<antiwire_proto::Empty>,
    ) -> Result<Response<antiwire_proto::StatsResponse>, Status> {
        self.traffic.handle_get_stats(request).await
    }

    async fn get_active_applications(
        &self,
        request: Request<antiwire_proto::Empty>,
    ) -> Result<Response<antiwire_proto::ActiveApplicationsResponse>, Status> {
        self.traffic.handle_get_active_applications(request).await
    }

    type StreamRealtimeTrafficStream = StreamRealtimeTrafficStream;

    async fn stream_realtime_traffic(
        &self,
        request: Request<antiwire_proto::Empty>,
    ) -> Result<Response<Self::StreamRealtimeTrafficStream>, Status> {
        Ok(self.traffic.handle_stream_realtime_traffic(request))
    }

    async fn get_connection_logs(
        &self,
        request: Request<antiwire_proto::LogRequest>,
    ) -> Result<Response<antiwire_proto::LogResponse>, Status> {
        self.traffic.handle_get_connection_logs(request).await
    }

    async fn get_application_log_summaries(
        &self,
        request: Request<antiwire_proto::ApplicationLogSummaryRequest>,
    ) -> Result<Response<antiwire_proto::ApplicationLogSummaryResponse>, Status> {
        self.traffic
            .handle_get_application_log_summaries(request)
            .await
    }

    async fn get_country_statistics(
        &self,
        request: Request<antiwire_proto::Empty>,
    ) -> Result<Response<antiwire_proto::CountryStatisticsResponse>, Status> {
        self.traffic.handle_get_country_statistics(request).await
    }

    async fn get_activity_buckets(
        &self,
        request: Request<antiwire_proto::ActivityBucketsRequest>,
    ) -> Result<Response<antiwire_proto::ActivityBucketsResponse>, Status> {
        self.traffic.handle_get_activity_buckets(request).await
    }

    async fn delete_history(
        &self,
        request: Request<antiwire_proto::DeleteHistoryRequest>,
    ) -> Result<Response<antiwire_proto::DeleteHistoryResponse>, Status> {
        self.traffic.handle_delete_history(request).await
    }

    async fn get_rules(
        &self,
        request: Request<antiwire_proto::Empty>,
    ) -> Result<Response<antiwire_proto::RulesResponse>, Status> {
        self.rules.handle_get_rules(request).await
    }

    async fn add_rule(
        &self,
        request: Request<antiwire_proto::Rule>,
    ) -> Result<Response<antiwire_proto::ActionResponse>, Status> {
        self.rules.handle_add_rule(request).await
    }

    async fn remove_rule(
        &self,
        request: Request<antiwire_proto::Rule>,
    ) -> Result<Response<antiwire_proto::ActionResponse>, Status> {
        self.rules.handle_remove_rule(request).await
    }

    async fn add_country_rule(
        &self,
        request: Request<antiwire_proto::CountryRule>,
    ) -> Result<Response<antiwire_proto::ActionResponse>, Status> {
        self.rules.handle_add_country_rule(request).await
    }

    async fn remove_country_rule(
        &self,
        request: Request<antiwire_proto::CountryRule>,
    ) -> Result<Response<antiwire_proto::ActionResponse>, Status> {
        self.rules.handle_remove_country_rule(request).await
    }

    async fn get_ai_decisions(
        &self,
        request: Request<antiwire_proto::AiDecisionsRequest>,
    ) -> Result<Response<antiwire_proto::AiDecisionsResponse>, Status> {
        self.ai_decisions.handle_get_ai_decisions(request).await
    }

    async fn delete_ai_decision(
        &self,
        request: Request<antiwire_proto::DeleteAiDecisionRequest>,
    ) -> Result<Response<antiwire_proto::ActionResponse>, Status> {
        self.ai_decisions.handle_delete_ai_decision(request).await
    }

    async fn refresh_ai_decision(
        &self,
        request: Request<antiwire_proto::RefreshAiDecisionRequest>,
    ) -> Result<Response<antiwire_proto::AiDecision>, Status> {
        self.ai_decisions.handle_refresh_ai_decision(request).await
    }

    async fn advanced_ai_decision(
        &self,
        request: Request<antiwire_proto::AdvancedAiDecisionRequest>,
    ) -> Result<Response<antiwire_proto::AiDecision>, Status> {
        self.ai_decisions.handle_advanced_ai_decision(request).await
    }

    async fn lookup_domain(
        &self,
        request: Request<antiwire_proto::LookupDomainRequest>,
    ) -> Result<Response<antiwire_proto::LookupDomainResponse>, Status> {
        self.domain_lookup.handle_lookup_domain(request).await
    }

    async fn lookup_dns_records(
        &self,
        request: Request<antiwire_proto::DnsRecordsRequest>,
    ) -> Result<Response<antiwire_proto::DnsRecordsResponse>, Status> {
        self.domain_lookup.handle_lookup_dns_records(request).await
    }

    async fn get_seen_subdomains(
        &self,
        request: Request<antiwire_proto::SeenSubdomainsRequest>,
    ) -> Result<Response<antiwire_proto::SeenSubdomainsResponse>, Status> {
        self.domain_lookup.handle_get_seen_subdomains(request).await
    }

    async fn search_certificates(
        &self,
        request: Request<antiwire_proto::CertificateSearchRequest>,
    ) -> Result<Response<antiwire_proto::CertificateSearchResponse>, Status> {
        self.domain_lookup.handle_search_certificates(request).await
    }

    async fn get_settings(
        &self,
        request: Request<antiwire_proto::Empty>,
    ) -> Result<Response<antiwire_proto::SettingsResponse>, Status> {
        Ok(self.settings.handle_get_settings(request))
    }

    async fn update_settings(
        &self,
        request: Request<antiwire_proto::SettingsRequest>,
    ) -> Result<Response<antiwire_proto::UpdateSettingsResponse>, Status> {
        self.settings.handle_update_settings(request).await
    }

    async fn sync_hosts_blocklist(
        &self,
        request: Request<antiwire_proto::Empty>,
    ) -> Result<Response<antiwire_proto::ActionResponse>, Status> {
        Ok(self.settings.handle_sync_hosts_blocklist(request).await)
    }

    async fn refresh_geo_database(
        &self,
        request: Request<antiwire_proto::Empty>,
    ) -> Result<Response<antiwire_proto::ActionResponse>, Status> {
        Ok(self.settings.handle_refresh_geo_database(request).await)
    }

    type StreamNotificationsStream = StreamNotificationsStream;

    async fn stream_notifications(
        &self,
        request: Request<antiwire_proto::Empty>,
    ) -> Result<Response<Self::StreamNotificationsStream>, Status> {
        Ok(self.alerts.handle_stream_notifications(request))
    }

    async fn get_alerts(
        &self,
        request: Request<antiwire_proto::Empty>,
    ) -> Result<Response<antiwire_proto::AlertsResponse>, Status> {
        self.alerts.handle_get_alerts(request).await
    }

    async fn dismiss_alert(
        &self,
        request: Request<antiwire_proto::AlertRequest>,
    ) -> Result<Response<antiwire_proto::ActionResponse>, Status> {
        self.alerts.handle_dismiss_alert(request).await
    }

    async fn clear_alerts(
        &self,
        request: Request<antiwire_proto::Empty>,
    ) -> Result<Response<antiwire_proto::ActionResponse>, Status> {
        self.alerts.handle_clear_alerts(request).await
    }

    async fn list_capture_devices(
        &self,
        request: Request<antiwire_proto::Empty>,
    ) -> Result<Response<antiwire_proto::CaptureDevicesResponse>, Status> {
        self.capture.handle_list_capture_devices(request).await
    }

    async fn start_capture(
        &self,
        request: Request<antiwire_proto::StartCaptureRequest>,
    ) -> Result<Response<antiwire_proto::CaptureSessionResponse>, Status> {
        self.capture.handle_start_capture(request).await
    }

    async fn stop_capture(
        &self,
        request: Request<antiwire_proto::CaptureControl>,
    ) -> Result<Response<antiwire_proto::ActionResponse>, Status> {
        Ok(self.capture.handle_stop_capture(request))
    }

    async fn get_capture_status(
        &self,
        request: Request<antiwire_proto::CaptureControl>,
    ) -> Result<Response<antiwire_proto::CaptureStatus>, Status> {
        self.capture.handle_get_capture_status(request)
    }

    type StreamCaptureStatusStream = StreamCaptureStatusStream;

    async fn stream_capture_status(
        &self,
        request: Request<antiwire_proto::CaptureControl>,
    ) -> Result<Response<Self::StreamCaptureStatusStream>, Status> {
        self.capture.handle_stream_capture_status(request)
    }

    type StreamCapturedPacketsStream = StreamCapturedPacketsStream;

    async fn stream_captured_packets(
        &self,
        request: Request<antiwire_proto::CaptureControl>,
    ) -> Result<Response<Self::StreamCapturedPacketsStream>, Status> {
        self.capture.handle_stream_captured_packets(request)
    }

    type DownloadCaptureStream = DownloadCaptureStream;

    async fn download_capture(
        &self,
        request: Request<antiwire_proto::CaptureControl>,
    ) -> Result<Response<Self::DownloadCaptureStream>, Status> {
        self.capture.handle_download_capture(request).await
    }

    async fn get_network_mapping_state(
        &self,
        request: Request<antiwire_proto::Empty>,
    ) -> Result<Response<antiwire_proto::NetworkMappingState>, Status> {
        self.network_mapping
            .handle_get_network_mapping_state(request)
            .await
    }

    async fn scan_network(
        &self,
        request: Request<antiwire_proto::NetworkMapRequest>,
    ) -> Result<Response<antiwire_proto::NetworkMapResponse>, Status> {
        self.network_mapping.handle_scan_network(request).await
    }

    async fn stop_network_scan(
        &self,
        request: Request<antiwire_proto::Empty>,
    ) -> Result<Response<antiwire_proto::ActionResponse>, Status> {
        self.network_mapping.handle_stop_network_scan(request).await
    }

    async fn clear_network_devices(
        &self,
        request: Request<antiwire_proto::Empty>,
    ) -> Result<Response<antiwire_proto::ActionResponse>, Status> {
        self.network_mapping
            .handle_clear_network_devices(request)
            .await
    }

    async fn save_network_scan_range(
        &self,
        request: Request<antiwire_proto::NetworkScanRange>,
    ) -> Result<Response<antiwire_proto::ActionResponse>, Status> {
        self.network_mapping
            .handle_save_network_scan_range(request)
            .await
    }

    async fn remove_network_scan_range(
        &self,
        request: Request<antiwire_proto::NetworkScanRange>,
    ) -> Result<Response<antiwire_proto::ActionResponse>, Status> {
        self.network_mapping
            .handle_remove_network_scan_range(request)
            .await
    }

    async fn save_network_device_watch(
        &self,
        request: Request<antiwire_proto::NetworkDeviceWatch>,
    ) -> Result<Response<antiwire_proto::ActionResponse>, Status> {
        self.network_mapping
            .handle_save_network_device_watch(request)
            .await
    }

    async fn remove_network_device_watch(
        &self,
        request: Request<antiwire_proto::NetworkDeviceWatch>,
    ) -> Result<Response<antiwire_proto::ActionResponse>, Status> {
        self.network_mapping
            .handle_remove_network_device_watch(request)
            .await
    }

    async fn update_oui_database(
        &self,
        request: Request<antiwire_proto::Empty>,
    ) -> Result<Response<antiwire_proto::ActionResponse>, Status> {
        Ok(NetworkMappingApi::handle_update_oui_database(request))
    }

    async fn get_update_status(
        &self,
        request: Request<antiwire_proto::Empty>,
    ) -> Result<Response<antiwire_proto::UpdateStatus>, Status> {
        Ok(self.updates.handle_get_update_status(request))
    }

    async fn install_update(
        &self,
        request: Request<antiwire_proto::InstallUpdateRequest>,
    ) -> Result<Response<antiwire_proto::ActionResponse>, Status> {
        Ok(self.updates.handle_install_update(request))
    }

    async fn check_for_updates(
        &self,
        request: Request<antiwire_proto::Empty>,
    ) -> Result<Response<antiwire_proto::UpdateStatus>, Status> {
        Ok(self.updates.handle_check_for_updates(request).await)
    }

    async fn explain_domain_block(
        &self,
        request: Request<antiwire_proto::ExplainDomainBlockRequest>,
    ) -> Result<Response<antiwire_proto::ExplainDomainBlockResponse>, Status> {
        Ok(self.rules.handle_explain_domain_block(request))
    }
}
