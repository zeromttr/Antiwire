//! Network discovery, scan ranges, and device watches.

use std::sync::Arc;

use tonic::{Request, Response, Status};

use crate::proto_bridge::{device_watch_request, netmap_overview_to_proto, scan_range_to_store};
use crate::reply::{done, internal, refused};
use antiwire_services::{NetworkMappingWorker, NetworkMappingWorkerError};

/// Network discovery.
pub(crate) struct NetworkMappingApi {
    pub(crate) worker: Arc<NetworkMappingWorker>,
}

#[allow(clippy::result_large_err)] // `tonic::Status` is required by the gRPC surface.
impl NetworkMappingApi {
    pub(super) async fn handle_get_network_mapping_state(
        &self,
        _request: Request<antiwire_proto::Empty>,
    ) -> Result<Response<antiwire_proto::NetworkMappingState>, Status> {
        let overview = self.worker.overview().await.map_err(internal)?;
        Ok(Response::new(netmap_overview_to_proto(&overview)))
    }

    pub(super) async fn handle_scan_network(
        &self,
        request: Request<antiwire_proto::NetworkMapRequest>,
    ) -> Result<Response<antiwire_proto::NetworkMapResponse>, Status> {
        self.worker
            .start_scan(request.into_inner().cidr_ranges)
            .await
            .map_err(|error| scan_status(&error))?;
        Ok(Response::new(antiwire_proto::NetworkMapResponse {
            success: true,
            message: "Network scan started".to_owned(),
            devices: Vec::new(),
            scanned_at: String::new(),
        }))
    }

    pub(super) async fn handle_stop_network_scan(
        &self,
        _request: Request<antiwire_proto::Empty>,
    ) -> Result<Response<antiwire_proto::ActionResponse>, Status> {
        Ok(Response::new(if self.worker.stop_scan().await {
            done("Network scan stop requested")
        } else {
            refused("No network scan is running")
        }))
    }

    pub(super) async fn handle_clear_network_devices(
        &self,
        _request: Request<antiwire_proto::Empty>,
    ) -> Result<Response<antiwire_proto::ActionResponse>, Status> {
        Ok(Response::new(match self.worker.clear_devices().await {
            Ok(true) => done("Network devices cleared"),
            Ok(false) => refused("Stop the active scan before clearing devices"),
            Err(error) => refused(error),
        }))
    }

    pub(super) async fn handle_save_network_scan_range(
        &self,
        request: Request<antiwire_proto::NetworkScanRange>,
    ) -> Result<Response<antiwire_proto::ActionResponse>, Status> {
        let range = scan_range_to_store(&request.into_inner());
        Ok(Response::new(
            match self.worker.save_scan_range(range).await {
                Ok(id) => done(format!("Scan range saved with id {id}")),
                Err(error) => refused(error),
            },
        ))
    }

    pub(super) async fn handle_remove_network_scan_range(
        &self,
        request: Request<antiwire_proto::NetworkScanRange>,
    ) -> Result<Response<antiwire_proto::ActionResponse>, Status> {
        let id = request.into_inner().id;
        Ok(Response::new(
            match self.worker.remove_scan_range(id).await {
                Ok(()) => done("Scan range removed"),
                Err(error) => refused(error),
            },
        ))
    }

    pub(super) async fn handle_save_network_device_watch(
        &self,
        request: Request<antiwire_proto::NetworkDeviceWatch>,
    ) -> Result<Response<antiwire_proto::ActionResponse>, Status> {
        let watch = device_watch_request(request.into_inner());
        Ok(Response::new(
            match self.worker.save_device_watch(watch).await {
                Ok(id) => done(format!("Device watch saved with id {id}")),
                Err(error) => refused(error),
            },
        ))
    }

    pub(super) async fn handle_remove_network_device_watch(
        &self,
        request: Request<antiwire_proto::NetworkDeviceWatch>,
    ) -> Result<Response<antiwire_proto::ActionResponse>, Status> {
        let id = request.into_inner().id;
        Ok(Response::new(
            match self.worker.remove_device_watch(id).await {
                Ok(()) => done("Device watch removed"),
                Err(error) => refused(error),
            },
        ))
    }

    pub(super) fn handle_update_oui_database(
        _request: Request<antiwire_proto::Empty>,
    ) -> Response<antiwire_proto::ActionResponse> {
        Response::new(done(
            "OUI vendor data is embedded in antiwire-geo; no manual update required.",
        ))
    }
}

/// `ScanNetwork` replies with data, so a refusal is a status.
fn scan_status(error: &NetworkMappingWorkerError) -> Status {
    match error {
        NetworkMappingWorkerError::Busy | NetworkMappingWorkerError::ShuttingDown => {
            Status::failed_precondition(error.to_string())
        }
        NetworkMappingWorkerError::Invalid(_)
        | NetworkMappingWorkerError::AlreadyWatched
        | NetworkMappingWorkerError::Scan(_) => Status::invalid_argument(error.to_string()),
        NetworkMappingWorkerError::Store(_) => Status::internal(error.to_string()),
    }
}
