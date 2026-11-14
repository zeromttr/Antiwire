//! How the local network is scanned.

use antiwire_netmap::{
    discover_local_ipv4_interfaces, NetworkDeviceSnapshot, NetworkInterfaceRange, ScanError,
    SystemNetworkScanner,
};
use tokio_util::sync::CancellationToken;

/// Finds devices on the local network.
#[async_trait::async_trait]
pub trait NetworkScanner: Send + Sync {
    /// Devices answering in `ranges`, until `cancellation` fires.
    async fn scan(
        &self,
        ranges: &[String],
        cancellation: &CancellationToken,
    ) -> Result<Vec<NetworkDeviceSnapshot>, ScanError>;

    /// Private IPv4 ranges of this host's active interfaces.
    async fn local_ranges(&self) -> Result<Vec<NetworkInterfaceRange>, ScanError>;
}

/// Probes with UDP and reads the operating system's neighbor table.
#[derive(Debug, Default)]
pub struct SystemScanner;

#[async_trait::async_trait]
impl NetworkScanner for SystemScanner {
    async fn scan(
        &self,
        ranges: &[String],
        cancellation: &CancellationToken,
    ) -> Result<Vec<NetworkDeviceSnapshot>, ScanError> {
        SystemNetworkScanner.scan(ranges, cancellation).await
    }

    async fn local_ranges(&self) -> Result<Vec<NetworkInterfaceRange>, ScanError> {
        discover_local_ipv4_interfaces().await
    }
}
