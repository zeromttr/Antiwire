//! Packet capture control, streaming, and downloads.

use crate::proto_bridge::{
    capture_device_to_proto, capture_frame_to_proto, capture_status_to_proto, CaptureId,
};
use crate::reply::{blocking, done, refused};
use crate::stream::spawn_stream;
use antiwire_capture::{
    AppFilter, AppFlowSource, CaptureError, CaptureOptions, CaptureSession, CaptureStartup,
    FlowTuple,
};
use antiwire_events::ActiveConnectionCounter;
use antiwire_tuning::{
    CAPTURE_APP_FLOW_HOLD, CAPTURE_APP_FLOW_REFRESH, CAPTURE_APP_HOLD_MEMORY_BUDGET,
    CAPTURE_STATS_SAMPLE_MIN_INTERVAL_MS, IPC_DOWNLOAD_STREAM_CAPACITY, IPC_PACKET_STREAM_CAPACITY,
    IPC_STATUS_STREAM_CAPACITY,
};
use std::io::Read;
use std::sync::Arc;
use std::time::Duration;
use tokio_stream::wrappers::ReceiverStream;
use tokio_util::sync::CancellationToken;
use tonic::{Request, Response, Status};

/// Packet capture.
pub(crate) struct CaptureApi {
    pub(crate) capture: Arc<CaptureSession>,
    pub(crate) active_connections: Arc<dyn ActiveConnectionCounter>,
    pub(crate) shutdown: CancellationToken,
}

#[allow(clippy::result_large_err)] // `tonic::Status` is required by the gRPC surface.
impl CaptureApi {
    pub(super) async fn handle_list_capture_devices(
        &self,
        _request: Request<antiwire_proto::Empty>,
    ) -> Result<Response<antiwire_proto::CaptureDevicesResponse>, Status> {
        let capture = Arc::clone(&self.capture);
        let devices = blocking("capture discovery", move || capture.discover_devices()).await?;
        let available = !devices.is_empty();
        let message = if available {
            String::new()
        } else {
            "Npcap is unavailable on Windows, or libpcap is unavailable on macOS/Linux.".to_owned()
        };
        Ok(Response::new(antiwire_proto::CaptureDevicesResponse {
            devices: devices.iter().map(capture_device_to_proto).collect(),
            available,
            message,
        }))
    }

    pub(super) async fn handle_start_capture(
        &self,
        request: Request<antiwire_proto::StartCaptureRequest>,
    ) -> Result<Response<antiwire_proto::CaptureSessionResponse>, Status> {
        let request = request.into_inner();
        let mut options = CaptureOptions {
            device_name: request.device_name,
            capture_filter: request.capture_filter,
            snap_length: request.snap_length,
            promiscuous: request.promiscuous,
            read_timeout_ms: request.read_timeout_ms,
            max_seconds: request.max_seconds,
            max_bytes: request.max_bytes,
            app_filter: None,
        };
        let app_path = request.app_path.trim().to_owned();
        let app_name = application_name(&request.app_name, &app_path);
        let counter = Arc::clone(&self.active_connections);
        let capture = Arc::clone(&self.capture);
        // Blocking: the tracker is asked for flows, and a start may discover
        // interfaces and wait for the interface to open. Status and stop
        // requests do not wait behind it.
        blocking("capture start", move || -> Result<(), Status> {
            if !app_path.is_empty() {
                let source = Arc::new(TrackedApplication { counter, app_path });
                if source.flows().is_none() {
                    return Err(Status::failed_precondition(
                        "Application capture needs connection attribution, which is not available.",
                    ));
                }
                options.app_filter = Some(AppFilter {
                    app_name,
                    source,
                    hold: CAPTURE_APP_FLOW_HOLD,
                    refresh: CAPTURE_APP_FLOW_REFRESH,
                    hold_budget_bytes: CAPTURE_APP_HOLD_MEMORY_BUDGET,
                });
            }
            capture
                .start(options)
                .and_then(CaptureStartup::wait)
                .map_err(|error| capture_error_status(&error))
        })
        .await??;
        Ok(Response::new(antiwire_proto::CaptureSessionResponse {
            capture_id: CaptureId.to_string(),
            started: true,
            message: "Capture started.".to_owned(),
        }))
    }

    pub(super) fn handle_stop_capture(
        &self,
        request: Request<antiwire_proto::CaptureControl>,
    ) -> Response<antiwire_proto::ActionResponse> {
        if let Err(missing) = CaptureId::from_proto(&request.into_inner().capture_id) {
            return Response::new(refused(missing.message()));
        }
        Response::new(match self.capture.stop() {
            Ok(()) => done("Capture is stopping."),
            Err(error) => refused(error),
        })
    }

    pub(super) fn handle_get_capture_status(
        &self,
        request: Request<antiwire_proto::CaptureControl>,
    ) -> Result<Response<antiwire_proto::CaptureStatus>, Status> {
        let id = CaptureId::from_proto(&request.into_inner().capture_id)?;
        Ok(Response::new(capture_status_to_proto(
            id,
            &self.capture.snapshot(),
        )))
    }

    /// Sends the status now, again at each change, and at the sampling
    /// interval for the counters while the capture runs; ends with the
    /// capture.
    pub(super) fn handle_stream_capture_status(
        &self,
        request: Request<antiwire_proto::CaptureControl>,
    ) -> Result<Response<super::StreamCaptureStatusStream>, Status> {
        let id = CaptureId::from_proto(&request.into_inner().capture_id)?;
        let capture = Arc::clone(&self.capture);
        let mut changes = capture.status_changes();
        let interval = Duration::from_millis(
            u64::try_from(CAPTURE_STATS_SAMPLE_MIN_INTERVAL_MS).unwrap_or(500),
        );
        Ok(Response::new(spawn_stream(
            IPC_STATUS_STREAM_CAPACITY,
            &self.shutdown,
            |sink| async move {
                loop {
                    changes.mark_unchanged();
                    let mut active = false;
                    let sent = sink
                        .send_with(|| {
                            let status = capture_status_to_proto(id, &capture.snapshot());
                            active = status.active;
                            status
                        })
                        .await;
                    if sent.is_err() || !active {
                        return;
                    }
                    tokio::select! {
                        () = tokio::time::sleep(interval) => {}
                        sender = changes.changed() => if sender.is_err() { return },
                    }
                }
            },
        )))
    }

    /// Streams the live frames of the capture current when it opens. Only
    /// the newest stream receives them; an older one ends.
    pub(super) fn handle_stream_captured_packets(
        &self,
        request: Request<antiwire_proto::CaptureControl>,
    ) -> Result<Response<super::StreamCapturedPacketsStream>, Status> {
        CaptureId::from_proto(&request.into_inner().capture_id)?;
        let reader = self.capture.frame_reader();
        Ok(Response::new(spawn_stream(
            IPC_PACKET_STREAM_CAPACITY,
            &self.shutdown,
            |sink| async move {
                while let Some(frames) = reader.next_frames().await {
                    let mut frames = frames.into_iter();
                    while let Some(frame) = frames.next() {
                        if sink.send(capture_frame_to_proto(&frame)).await.is_err() {
                            // The client went away, often to reopen the stream.
                            // What it never received goes to the next reader.
                            reader.give_back(std::iter::once(frame).chain(frames).collect());
                            return;
                        }
                    }
                }
            },
        )))
    }

    pub(super) async fn handle_download_capture(
        &self,
        request: Request<antiwire_proto::CaptureControl>,
    ) -> Result<Response<super::DownloadCaptureStream>, Status> {
        CaptureId::from_proto(&request.into_inner().capture_id)?;
        let capture = Arc::clone(&self.capture);
        let mut reader = blocking("capture reader", move || capture.capture_reader())
            .await?
            .map_err(|error| capture_error_status(&error))?;
        let (tx, rx) = tokio::sync::mpsc::channel(IPC_DOWNLOAD_STREAM_CAPACITY);
        tokio::task::spawn_blocking(move || {
            const CHUNK_SIZE: usize = 64 * 1024;
            let length = match reader.metadata() {
                Ok(metadata) => metadata.len(),
                Err(error) => {
                    let _ = tx.blocking_send(Err(Status::internal(error.to_string())));
                    return;
                }
            };
            if length == 0 {
                let _ = tx.blocking_send(Ok(antiwire_proto::CaptureChunk {
                    data: Vec::new(),
                    last: true,
                }));
                return;
            }
            let mut offset = 0_u64;
            while offset < length {
                let requested =
                    usize::try_from((length - offset).min(CHUNK_SIZE as u64)).unwrap_or(CHUNK_SIZE);
                let mut data = vec![0_u8; requested];
                if let Err(error) = reader.read_exact(&mut data) {
                    let _ = tx.blocking_send(Err(Status::internal(error.to_string())));
                    break;
                }
                offset = offset.saturating_add(requested as u64);
                if tx
                    .blocking_send(Ok(antiwire_proto::CaptureChunk {
                        data,
                        last: offset >= length,
                    }))
                    .is_err()
                {
                    break;
                }
            }
        });
        Ok(Response::new(ReceiverStream::new(rx)))
    }
}

/// An application whose live flows are read from the connection tracker.
struct TrackedApplication {
    counter: Arc<dyn ActiveConnectionCounter>,
    app_path: String,
}

impl AppFlowSource for TrackedApplication {
    fn flows(&self) -> Option<Vec<FlowTuple>> {
        self.counter.application_flows(&self.app_path)
    }
}

/// The name shown for a capture restricted to `app_path`: the trimmed
/// `app_name` when given, else the file name of the path.
fn application_name(app_name: &str, app_path: &str) -> String {
    let app_name = app_name.trim();
    if !app_name.is_empty() {
        return app_name.to_owned();
    }
    // Windows paths use backslashes, which `Path` does not split on elsewhere.
    app_path
        .rsplit(['/', '\\'])
        .next()
        .filter(|name| !name.is_empty())
        .unwrap_or(app_path)
        .to_owned()
}

fn capture_error_status(error: &CaptureError) -> Status {
    match error {
        CaptureError::AlreadyActive
        | CaptureError::NotActive
        | CaptureError::StillActive
        | CaptureError::NoCaptureData
        | CaptureError::PcapUnavailable(_) => Status::failed_precondition(error.to_string()),
        CaptureError::DeviceNotFound(_) | CaptureError::InvalidFilter(_) => {
            Status::invalid_argument(error.to_string())
        }
        CaptureError::StartFailed(_) | CaptureError::StartTimeout | CaptureError::Storage(_) => {
            Status::internal(error.to_string())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explicit_app_name_wins_and_is_trimmed() {
        assert_eq!(
            application_name("  Browser  ", r"C:\Apps\Foo.exe"),
            "Browser"
        );
    }

    #[test]
    fn app_name_defaults_to_the_file_name_of_the_path() {
        assert_eq!(application_name("", r"C:\Apps\Foo.exe"), "Foo.exe");
        assert_eq!(application_name("  ", "/usr/bin/curl"), "curl");
        assert_eq!(application_name("", "curl"), "curl");
    }
}
