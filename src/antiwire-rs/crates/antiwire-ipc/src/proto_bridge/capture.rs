//! Packet capture status, device, and frame conversions.

use antiwire_capture::{
    CaptureDevice, CaptureFrame, CaptureSnapshot, CaptureStatus as SessionCaptureStatus,
};
use antiwire_proto::{
    CaptureDevice as ProtoCaptureDevice, CaptureStatus as ProtoCaptureStatus, CapturedPacket,
};
use tonic::Status;

/// The daemon's one capture session. The wire names it, so a client can tell
/// sessions apart if there are ever more than one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct CaptureId;

impl CaptureId {
    const WIRE: &'static str = "default";

    /// # Errors
    ///
    /// `NotFound` for any id but the session's.
    #[allow(clippy::result_large_err)] // `tonic::Status` is required by the gRPC surface.
    pub(crate) fn from_proto(id: &str) -> Result<Self, Status> {
        if id == Self::WIRE {
            Ok(Self)
        } else {
            Err(Status::not_found("Capture session was not found."))
        }
    }
}

impl std::fmt::Display for CaptureId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(Self::WIRE)
    }
}

pub(crate) fn capture_device_to_proto(device: &CaptureDevice) -> ProtoCaptureDevice {
    ProtoCaptureDevice {
        name: device.name.clone(),
        description: device.description.clone(),
        addresses: device.addresses.clone(),
        loopback: device.loopback,
    }
}

pub(crate) fn capture_status_to_proto(
    capture_id: CaptureId,
    snapshot: &CaptureSnapshot,
) -> ProtoCaptureStatus {
    let (state, active) = match snapshot.status {
        SessionCaptureStatus::Idle => ("idle", false),
        SessionCaptureStatus::Starting => ("starting", true),
        SessionCaptureStatus::Running => ("capturing", true),
        SessionCaptureStatus::Stopping => ("stopping", true),
        SessionCaptureStatus::Stopped => ("completed", false),
        SessionCaptureStatus::Faulted => ("faulted", false),
    };
    ProtoCaptureStatus {
        capture_id: capture_id.to_string(),
        state: state.to_owned(),
        active,
        packets: snapshot.packets,
        bytes: snapshot.bytes,
        dropped_packets: snapshot.dropped_packets,
        elapsed_seconds: snapshot.elapsed_seconds,
        device_name: snapshot.device_name.clone(),
        message: snapshot.message.clone(),
        filtered_packets: snapshot.filtered_packets,
        app_name: snapshot.app_name.clone(),
    }
}

pub(crate) fn capture_frame_to_proto(frame: &CaptureFrame) -> CapturedPacket {
    CapturedPacket {
        sequence: frame.sequence,
        timestamp_us: frame.timestamp_us,
        captured_length: frame.captured_length,
        original_length: frame.original_length,
        link_layer: frame.link_layer,
        protocol: frame.protocol.clone(),
        source: frame.source.clone(),
        destination: frame.destination.clone(),
        source_port: frame.source_port,
        destination_port: frame.destination_port,
        info: frame.info.clone(),
        data: frame.payload.clone(),
    }
}
