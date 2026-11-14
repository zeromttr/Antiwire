//! Network mapping state and scan/device-watch conversions.

use super::scalars::i32_to_u32;
use super::timestamps::format_timestamp_rfc3339;

use antiwire_proto::{
    NetworkDevice as ProtoNetworkDevice, NetworkDeviceWatch as ProtoDeviceWatch,
    NetworkMappingState as ProtoNetmapState, NetworkScanRange as ProtoScanRange,
};
use antiwire_services::{DeviceWatchRequest, NetworkOverview};
use antiwire_store::NetworkScanRange;

pub(crate) fn netmap_overview_to_proto(overview: &NetworkOverview) -> ProtoNetmapState {
    let NetworkOverview {
        state,
        devices,
        scan_ranges,
        watches,
    } = overview;
    ProtoNetmapState {
        supported: true,
        message: state.message.clone(),
        devices: devices
            .iter()
            .map(|device| ProtoNetworkDevice {
                mac_address: device.mac_address.clone(),
                ip_address: device.ip_address.clone(),
                manufacturer: device.manufacturer.clone(),
                mdns_name: device.mdns_name.clone(),
                adapter_id: device.adapter_id.clone(),
                present: device.present,
                watched: watches.iter().any(|watch| {
                    antiwire_services::watch_matches_addr(
                        watch,
                        &device.ip_address,
                        &device.mac_address,
                    )
                }),
                last_seen: format_timestamp_rfc3339(device.last_seen),
            })
            .collect(),
        scan_ranges: scan_ranges
            .iter()
            .map(|range| ProtoScanRange {
                id: range.id,
                adapter_id: range.adapter_id.clone(),
                cidr: range.cidr.clone(),
            })
            .collect(),
        device_watches: watches
            .iter()
            .map(|watch| ProtoDeviceWatch {
                id: watch.id,
                ip_address: watch.ip_address.clone(),
                mac_address: watch.mac_address.clone(),
                adapter_id: watch.adapter_id.clone(),
                cidr: watch.cidr.clone(),
                interval_minutes: i32_to_u32(watch.interval_minutes),
                enabled: watch.enabled,
                present: watch.present,
                last_checked: format_timestamp_rfc3339(watch.last_checked),
            })
            .collect(),
        last_scan: state.last_scan.clone(),
        is_scanning: state.scan_in_progress,
    }
}

pub(crate) fn scan_range_to_store(range: &ProtoScanRange) -> NetworkScanRange {
    NetworkScanRange {
        id: range.id,
        adapter_id: range.adapter_id.clone(),
        cidr: range.cidr.clone(),
    }
}

pub(crate) fn device_watch_request(watch: ProtoDeviceWatch) -> DeviceWatchRequest {
    DeviceWatchRequest {
        id: watch.id,
        ip_address: watch.ip_address,
        mac_address: watch.mac_address,
        adapter_id: watch.adapter_id,
        cidr: watch.cidr,
        interval_minutes: watch.interval_minutes,
        enabled: watch.enabled,
    }
}
