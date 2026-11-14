//! Cross-platform LAN device discovery using active neighbor-cache probing.

mod scan;
mod state;

pub use scan::{
    canonical_mac, discover_from_neighbor_table, discover_local_ipv4_interfaces,
    validate_scan_ranges, NetworkDeviceSnapshot, NetworkInterfaceRange, ScanError,
    SystemNetworkScanner,
};
pub use state::NetworkMappingState;
