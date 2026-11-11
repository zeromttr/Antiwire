use crate::scan::NetworkDeviceSnapshot;
use serde::{Deserialize, Serialize};

/// Aggregated network mapping state for IPC.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NetworkMappingState {
    pub devices: Vec<NetworkDeviceSnapshot>,
    pub scan_in_progress: bool,
    pub last_scan: String,
    pub message: String,
}

impl NetworkMappingState {
    pub fn merge_devices(&mut self, discovered: Vec<NetworkDeviceSnapshot>) {
        for device in discovered {
            if let Some(existing) = self
                .devices
                .iter_mut()
                .find(|known| known.mac_address.eq_ignore_ascii_case(&device.mac_address))
            {
                existing.ip_address = device.ip_address;
                existing.mac_address = device.mac_address;
                if !device.vendor.is_empty() {
                    existing.vendor = device.vendor;
                }
                if !device.hostname.is_empty() {
                    existing.hostname = device.hostname;
                }
                existing.is_online = device.is_online;
            } else {
                self.devices.push(device);
            }
        }
        // Keep the latest discoveries and prefer retaining online devices.
        // Offline devices remain in the durable store subject to its retention policy.
        const MAX_DEVICES: usize = 4_096;
        let mut excess = self.devices.len().saturating_sub(MAX_DEVICES);
        self.devices.retain(|device| {
            if excess > 0 && !device.is_online {
                excess -= 1;
                false
            } else {
                true
            }
        });
        if excess > 0 {
            self.devices.drain(..excess);
        }
    }

    pub fn begin_scan(&mut self) {
        self.scan_in_progress = true;
        self.message = "Scanning local network…".to_owned();
    }

    pub fn finish_scan(&mut self, devices: Vec<NetworkDeviceSnapshot>, scanned_at: String) {
        for device in &mut self.devices {
            device.is_online = false;
        }
        self.merge_devices(devices);
        self.scan_in_progress = false;
        self.last_scan = scanned_at;
        self.message = format!(
            "Scan complete: {} device(s) found",
            self.devices
                .iter()
                .filter(|device| device.is_online)
                .count()
        );
    }

    pub fn fail_scan(&mut self, message: impl Into<String>) {
        self.scan_in_progress = false;
        self.message = message.into();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn device(ip: &str, mac: &str, vendor: &str) -> NetworkDeviceSnapshot {
        NetworkDeviceSnapshot {
            ip_address: ip.to_owned(),
            mac_address: mac.to_owned(),
            vendor: vendor.to_owned(),
            hostname: String::new(),
            is_online: true,
        }
    }

    #[test]
    fn randomized_mac_addresses_do_not_grow_memory_without_bound() {
        let mut state = NetworkMappingState::default();
        state.merge_devices(vec![device("192.168.1.1", "retained-online", "")]);
        for index in 0..5_000 {
            let mut discovered = device("192.168.1.2", &format!("random-{index}"), "");
            discovered.is_online = false;
            state.merge_devices(vec![discovered]);
        }
        assert_eq!(state.devices.len(), 4_096);
        assert_eq!(state.devices[0].mac_address, "retained-online");
        assert_eq!(state.devices.last().unwrap().mac_address, "random-4999");
    }

    #[test]
    fn merge_tracks_a_device_by_mac_when_its_ip_changes() {
        let mut state = NetworkMappingState::default();
        state.merge_devices(vec![device("192.168.1.2", "AA:BB:CC:00:00:01", "Vendor")]);
        state.merge_devices(vec![device("192.168.1.9", "aa:bb:cc:00:00:01", "")]);

        assert_eq!(state.devices.len(), 1);
        assert_eq!(state.devices[0].ip_address, "192.168.1.9");
        assert_eq!(state.devices[0].vendor, "Vendor");
    }

    #[test]
    fn finishing_scan_marks_devices_not_seen_as_offline() {
        let mut state = NetworkMappingState {
            devices: vec![
                device("192.168.1.2", "AA:BB:CC:00:00:01", "One"),
                device("192.168.1.3", "AA:BB:CC:00:00:02", "Two"),
            ],
            ..NetworkMappingState::default()
        };
        state.finish_scan(
            vec![device("192.168.1.2", "AA:BB:CC:00:00:01", "One")],
            "2026-08-03T12:00:00Z".to_owned(),
        );

        assert!(state.devices[0].is_online);
        assert!(!state.devices[1].is_online);
        assert_eq!(state.last_scan, "2026-08-03T12:00:00Z");
    }
}
