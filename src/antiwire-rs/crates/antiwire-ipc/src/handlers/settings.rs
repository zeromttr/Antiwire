//! Daemon settings and on-demand database syncs.

use std::sync::Arc;

use antiwire_services::{
    GeoDatabaseService, HostsBlocklistService, SettingsError, SettingsService,
};
use tonic::{Request, Response, Status};

use crate::proto_bridge::{settings_merge_request, settings_to_proto};
use crate::reply::{done, refused};

/// Settings and on-demand database syncs.
pub(crate) struct SettingsApi {
    pub(crate) settings: Arc<SettingsService>,
    pub(crate) hosts_blocklist: Arc<HostsBlocklistService>,
    pub(crate) geo_database: Arc<GeoDatabaseService>,
}

#[allow(clippy::result_large_err)] // `tonic::Status` is required by the gRPC surface.
impl SettingsApi {
    pub(super) fn handle_get_settings(
        &self,
        _request: Request<antiwire_proto::Empty>,
    ) -> Response<antiwire_proto::SettingsResponse> {
        Response::new(settings_to_proto(&self.settings.current()))
    }

    pub(super) async fn handle_update_settings(
        &self,
        request: Request<antiwire_proto::SettingsRequest>,
    ) -> Result<Response<antiwire_proto::UpdateSettingsResponse>, Status> {
        let request = request.into_inner();
        // Merged onto the saved row, not built from a default: daemon-owned
        // columns such as `geoip_database_last_updated` have no field in the
        // request.
        let outcome = self
            .settings
            .update(move |saved| settings_merge_request(saved, request))
            .await;
        Ok(Response::new(match outcome {
            // The settings are saved either way. What could not be put into
            // effect is reported, so the client can say so instead of
            // claiming everything took.
            Ok(update) => antiwire_proto::UpdateSettingsResponse {
                success: true,
                message: if update.not_applied.is_empty() {
                    "Settings updated".to_owned()
                } else {
                    "Settings saved, but some could not be applied".to_owned()
                },
                not_applied: update.not_applied,
            },
            // Not a refusal of these settings: the same request can succeed
            // once the earlier change is through, so the client is told why.
            Err(error @ SettingsError::Busy) => return Err(Status::aborted(error.to_string())),
            Err(error) => antiwire_proto::UpdateSettingsResponse {
                success: false,
                message: error.to_string(),
                not_applied: Vec::new(),
            },
        }))
    }

    pub(super) async fn handle_sync_hosts_blocklist(
        &self,
        _request: Request<antiwire_proto::Empty>,
    ) -> Response<antiwire_proto::ActionResponse> {
        Response::new(match self.hosts_blocklist.sync_now().await {
            Ok(()) => done("Successfully synced hosts blocklists."),
            Err(error) => refused(error),
        })
    }

    pub(super) async fn handle_refresh_geo_database(
        &self,
        _request: Request<antiwire_proto::Empty>,
    ) -> Response<antiwire_proto::ActionResponse> {
        Response::new(match self.geo_database.sync_now().await {
            Ok(()) => done("Successfully refreshed the GeoIP database."),
            Err(error) => refused(error),
        })
    }
}
