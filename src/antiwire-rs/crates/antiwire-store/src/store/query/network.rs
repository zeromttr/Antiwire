//! Network mapping queries: discovered devices, scan ranges, presence watches.

use rusqlite::{OptionalExtension, Row};
use time::OffsetDateTime;

use crate::error::{Result, StoreError};
use crate::models::{
    bool_to_i64, format_timestamp, i64_to_bool, NetworkDevice, NetworkDeviceWatch, NetworkScanRange,
};

use crate::store::Store;
use crate::store::{get_timestamp, row_id_to_i32};

impl Store {
    /// Inserts or updates a discovered network device keyed by MAC address.
    pub fn upsert_network_device(&self, device: &NetworkDevice) -> Result<()> {
        self.db.execute(
            "INSERT INTO network_devices (
                mac_address, ip_address, manufacturer, mdns_name, adapter_id,
                first_seen, last_seen, present
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
             ON CONFLICT(mac_address) DO UPDATE SET
                ip_address = excluded.ip_address,
                manufacturer = excluded.manufacturer,
                mdns_name = CASE
                    WHEN excluded.mdns_name = '' THEN network_devices.mdns_name
                    ELSE excluded.mdns_name
                END,
                adapter_id = excluded.adapter_id,
                last_seen = excluded.last_seen,
                present = excluded.present",
            rusqlite::params![
                device.mac_address,
                device.ip_address,
                device.manufacturer,
                device.mdns_name,
                device.adapter_id,
                format_timestamp(device.first_seen),
                format_timestamp(device.last_seen),
                bool_to_i64(device.present),
            ],
        )?;
        Ok(())
    }

    /// Atomically applies a complete network scan.
    ///
    /// Devices absent from `devices` are retained as offline so their identity,
    /// history, and presence watches survive a temporary disconnect.
    pub fn apply_network_scan(&self, devices: &[NetworkDevice]) -> Result<()> {
        self.db.transaction(|tx| {
            tx.execute("UPDATE network_devices SET present = 0", [])?;
            let mut upsert = tx.prepare(
                "INSERT INTO network_devices (
                    mac_address, ip_address, manufacturer, mdns_name, adapter_id,
                    first_seen, last_seen, present
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
                 ON CONFLICT(mac_address) DO UPDATE SET
                    ip_address = excluded.ip_address,
                    manufacturer = excluded.manufacturer,
                    mdns_name = CASE
                        WHEN excluded.mdns_name = '' THEN network_devices.mdns_name
                        ELSE excluded.mdns_name
                    END,
                    adapter_id = excluded.adapter_id,
                    last_seen = excluded.last_seen,
                    present = excluded.present",
            )?;
            for device in devices {
                upsert.execute(rusqlite::params![
                    device.mac_address,
                    device.ip_address,
                    device.manufacturer,
                    device.mdns_name,
                    device.adapter_id,
                    format_timestamp(device.first_seen),
                    format_timestamp(device.last_seen),
                    bool_to_i64(device.present),
                ])?;
            }
            drop(upsert);
            Ok(())
        })
    }

    /// Updates presence for a known device matched by MAC or IP address.
    pub fn set_network_device_presence(
        &self,
        mac_address: &str,
        ip_address: &str,
        present: bool,
        checked_at: OffsetDateTime,
    ) -> Result<u64> {
        self.db.execute(
            "UPDATE network_devices
             SET present = ?1,
                 last_seen = CASE WHEN ?1 = 1 THEN ?2 ELSE last_seen END
             WHERE (?3 <> '' AND LOWER(mac_address) = LOWER(?3))
                OR (?4 <> '' AND ip_address = ?4)",
            rusqlite::params![
                bool_to_i64(present),
                format_timestamp(checked_at),
                mac_address,
                ip_address,
            ],
        )
    }

    /// Returns every known network device ordered by last seen time.
    pub fn list_network_devices(&self) -> Result<Vec<NetworkDevice>> {
        self.db.query_map(
            "SELECT mac_address, ip_address, manufacturer, mdns_name, adapter_id,
                    first_seen, last_seen, present
             FROM network_devices
             ORDER BY last_seen DESC, mac_address ASC",
            [],
            map_network_device,
        )
    }

    /// Deletes all network devices.
    pub fn clear_network_devices(&self) -> Result<u64> {
        self.db.execute("DELETE FROM network_devices", [])
    }

    /// Returns configured network scan ranges.
    pub fn list_scan_ranges(&self) -> Result<Vec<NetworkScanRange>> {
        self.db.query_map(
            "SELECT id, adapter_id, cidr
             FROM network_scan_ranges
             ORDER BY id ASC",
            [],
            map_network_scan_range,
        )
    }

    /// Saves a scan range and returns its id. A positive `range.id` replaces
    /// that range; the delete and insert commit together, so a failed insert
    /// keeps the original.
    pub fn save_scan_range(&self, range: &NetworkScanRange) -> Result<i32> {
        self.db.transaction_with(|tx| {
            if range.id > 0 {
                tx.execute(
                    "DELETE FROM network_scan_ranges WHERE id = ?1",
                    rusqlite::params![range.id],
                )?;
            }
            tx.execute(
                "INSERT INTO network_scan_ranges (adapter_id, cidr)
                 VALUES (?1, ?2)",
                rusqlite::params![range.adapter_id, range.cidr],
            )?;
            row_id_to_i32(tx.last_insert_rowid())
        })
    }

    /// Deletes a network scan range by id.
    pub fn delete_scan_range(&self, id: i32) -> Result<()> {
        self.db
            .execute(
                "DELETE FROM network_scan_ranges WHERE id = ?1",
                rusqlite::params![id],
            )
            .map(|_| ())
    }

    /// Returns configured network device watches.
    pub fn list_device_watches(&self) -> Result<Vec<NetworkDeviceWatch>> {
        self.db.query_map(
            "SELECT id, ip_address, mac_address, adapter_id, cidr, interval_minutes,
                    enabled, present, baseline_established, last_checked
             FROM network_device_watches
             ORDER BY id ASC",
            [],
            map_network_device_watch,
        )
    }

    /// Saves a device watch and returns its id. A positive `watch.id` replaces
    /// that watch.
    ///
    /// The duplicate check, delete, and insert commit together: two concurrent
    /// saves cannot both pass the check, and a failed insert keeps the
    /// original watch. Empty fields do not participate in the duplicate
    /// match, and the MAC comparison is case-insensitive because watch rows
    /// and scan snapshots do not agree on canonical MAC casing.
    ///
    /// # Errors
    ///
    /// [`StoreError::WatchAlreadyExists`] when another watch has the same
    /// IPv4 address or MAC address.
    pub fn save_device_watch(&self, watch: &NetworkDeviceWatch) -> Result<i32> {
        self.db.transaction_with(|tx| {
            let duplicate = tx
                .query_row(
                    "SELECT 1 FROM network_device_watches
                     WHERE id <> ?3
                       AND ((?1 <> '' AND ip_address = ?1)
                         OR (?2 <> '' AND LOWER(mac_address) = LOWER(?2)))
                     LIMIT 1",
                    rusqlite::params![watch.ip_address, watch.mac_address, watch.id],
                    |row| row.get::<_, i64>(0),
                )
                .optional()?;
            if duplicate.is_some() {
                return Err(StoreError::WatchAlreadyExists);
            }
            if watch.id > 0 {
                tx.execute(
                    "DELETE FROM network_device_watches WHERE id = ?1",
                    rusqlite::params![watch.id],
                )?;
            }
            tx.execute(
                "INSERT INTO network_device_watches (
                    ip_address, mac_address, adapter_id, cidr, interval_minutes,
                    enabled, present, baseline_established, last_checked
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                rusqlite::params![
                    watch.ip_address,
                    watch.mac_address,
                    watch.adapter_id,
                    watch.cidr,
                    watch.interval_minutes,
                    bool_to_i64(watch.enabled),
                    bool_to_i64(watch.present),
                    bool_to_i64(watch.baseline_established),
                    format_timestamp(watch.last_checked),
                ],
            )?;
            row_id_to_i32(tx.last_insert_rowid())
        })
    }

    /// Inserts a network device watch and returns its id.
    #[cfg(any(test, feature = "test-support"))]
    pub fn insert_device_watch(&self, watch: &NetworkDeviceWatch) -> Result<i32> {
        let row_id = self.db.execute_insert(
            "INSERT INTO network_device_watches (
                ip_address, mac_address, adapter_id, cidr, interval_minutes,
                enabled, present, baseline_established, last_checked
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            rusqlite::params![
                watch.ip_address,
                watch.mac_address,
                watch.adapter_id,
                watch.cidr,
                watch.interval_minutes,
                bool_to_i64(watch.enabled),
                bool_to_i64(watch.present),
                bool_to_i64(watch.baseline_established),
                format_timestamp(watch.last_checked),
            ],
        )?;
        row_id_to_i32(row_id)
    }

    /// Records the result of one scheduled device presence check.
    pub fn update_device_watch_state(
        &self,
        id: i32,
        present: bool,
        baseline_established: bool,
        checked_at: OffsetDateTime,
    ) -> Result<()> {
        self.db
            .execute(
                "UPDATE network_device_watches
                 SET present = ?1, baseline_established = ?2, last_checked = ?3
                 WHERE id = ?4",
                rusqlite::params![
                    bool_to_i64(present),
                    bool_to_i64(baseline_established),
                    format_timestamp(checked_at),
                    id,
                ],
            )
            .map(|_| ())
    }

    /// Deletes a network device watch by id.
    pub fn delete_device_watch(&self, id: i32) -> Result<()> {
        self.db
            .execute(
                "DELETE FROM network_device_watches WHERE id = ?1",
                rusqlite::params![id],
            )
            .map(|_| ())
    }
}

fn map_network_device(row: &Row) -> std::result::Result<NetworkDevice, rusqlite::Error> {
    Ok(NetworkDevice {
        mac_address: row.get(0)?,
        ip_address: row.get(1)?,
        manufacturer: row.get(2)?,
        mdns_name: row.get(3)?,
        adapter_id: row.get(4)?,
        first_seen: get_timestamp(row, 5)?,
        last_seen: get_timestamp(row, 6)?,
        present: i64_to_bool(row.get(7)?),
    })
}

fn map_network_scan_range(row: &Row) -> std::result::Result<NetworkScanRange, rusqlite::Error> {
    Ok(NetworkScanRange {
        id: row.get(0)?,
        adapter_id: row.get(1)?,
        cidr: row.get(2)?,
    })
}

fn map_network_device_watch(row: &Row) -> std::result::Result<NetworkDeviceWatch, rusqlite::Error> {
    Ok(NetworkDeviceWatch {
        id: row.get(0)?,
        ip_address: row.get(1)?,
        mac_address: row.get(2)?,
        adapter_id: row.get(3)?,
        cidr: row.get(4)?,
        interval_minutes: row.get(5)?,
        enabled: i64_to_bool(row.get(6)?),
        present: i64_to_bool(row.get(7)?),
        baseline_established: i64_to_bool(row.get(8)?),
        last_checked: get_timestamp(row, 9)?,
    })
}

#[cfg(test)]
mod save_watch_tests {
    use super::*;
    use crate::models::NetworkDeviceWatch;

    fn watch(ip_address: &str, mac_address: &str) -> NetworkDeviceWatch {
        NetworkDeviceWatch {
            id: 0,
            ip_address: ip_address.to_owned(),
            mac_address: mac_address.to_owned(),
            adapter_id: String::new(),
            cidr: String::new(),
            interval_minutes: 5,
            enabled: true,
            present: false,
            baseline_established: false,
            last_checked: OffsetDateTime::UNIX_EPOCH,
        }
    }

    fn is_duplicate(result: &Result<i32>) -> bool {
        matches!(result, Err(StoreError::WatchAlreadyExists))
    }

    #[test]
    fn rejects_matches_by_ip_or_mac_and_ignores_empty_fields() {
        let file = tempfile::NamedTempFile::new().expect("temp store file");
        let store = Store::open(file.path()).expect("open store");
        let id = store
            .save_device_watch(&watch("192.168.1.7", "00:1B:63:00:00:01"))
            .expect("save watch");

        assert!(is_duplicate(
            &store.save_device_watch(&watch("192.168.1.7", ""))
        ));
        assert!(
            is_duplicate(&store.save_device_watch(&watch("", "00:1b:63:00:00:01"))),
            "mac match must be case-insensitive"
        );
        store
            .save_device_watch(&watch("192.168.1.8", ""))
            .expect("a different ip is not a duplicate");

        store.delete_device_watch(id).expect("delete watch");
        store
            .save_device_watch(&watch("192.168.1.7", ""))
            .expect("no rows means no duplicate");
    }

    #[test]
    fn several_watches_can_have_no_mac() {
        // Every IP-only watch stores an empty MAC, which the unique MAC index
        // used to count as one value.
        let file = tempfile::NamedTempFile::new().expect("temp store file");
        let store = Store::open(file.path()).expect("open store");
        for ip in ["192.168.1.5", "192.168.1.6", "192.168.1.7"] {
            store.save_device_watch(&watch(ip, "")).expect(ip);
        }
        assert_eq!(store.list_device_watches().expect("list").len(), 3);
    }

    #[test]
    fn a_failed_replace_keeps_the_original_watch() {
        let file = tempfile::NamedTempFile::new().expect("temp store file");
        let store = Store::open(file.path()).expect("open store");
        let first = store
            .save_device_watch(&watch("192.168.1.5", "00:1B:63:00:00:01"))
            .expect("first");
        store
            .save_device_watch(&watch("192.168.1.6", "00:1B:63:00:00:02"))
            .expect("second");

        let mut edit = watch("192.168.1.5", "00:1B:63:00:00:02");
        edit.id = first;
        assert!(is_duplicate(&store.save_device_watch(&edit)));

        let watches = store.list_device_watches().expect("list");
        assert_eq!(watches.len(), 2);
        assert!(watches.iter().any(|w| w.id == first));
    }

    #[test]
    fn editing_a_watch_may_keep_its_own_address() {
        let file = tempfile::NamedTempFile::new().expect("temp store file");
        let store = Store::open(file.path()).expect("open store");
        let id = store
            .save_device_watch(&watch("192.168.1.5", ""))
            .expect("save");
        let mut edit = watch("192.168.1.5", "");
        edit.id = id;
        edit.interval_minutes = 30;
        store.save_device_watch(&edit).expect("edit");

        let watches = store.list_device_watches().expect("list");
        assert_eq!(watches.len(), 1);
        assert_eq!(watches[0].interval_minutes, 30);
    }

    #[test]
    fn replacing_a_scan_range_leaves_one_row() {
        let file = tempfile::NamedTempFile::new().expect("temp store file");
        let store = Store::open(file.path()).expect("open store");
        let mut range = NetworkScanRange {
            id: 0,
            adapter_id: String::new(),
            cidr: "192.168.1.0/24".to_owned(),
        };
        range.id = store.save_scan_range(&range).expect("save");
        range.cidr = "10.0.0.0/24".to_owned();
        store.save_scan_range(&range).expect("replace");

        let ranges = store.list_scan_ranges().expect("list");
        assert_eq!(ranges.len(), 1);
        assert_eq!(ranges[0].cidr, "10.0.0.0/24");
    }
}
