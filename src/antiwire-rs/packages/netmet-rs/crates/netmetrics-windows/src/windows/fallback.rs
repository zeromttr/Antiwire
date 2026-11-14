//! IP Helper polling while ETW is unavailable, plus interface counters.

use crate::owner_module;
use netmetrics_core::{FlowKey, InterfaceStats, unix_now_ms};
use netmetrics_sys::{BackendError, BackendErrorKind, BackendEvent, EventSink};
use std::collections::{HashMap, HashSet};
use std::ptr;
use std::slice;
use windows::Win32::NetworkManagement::IpHelper::{
    FreeMibTable, GetIfTable2, MIB_IF_ROW2, MIB_IF_TABLE2,
};

/// The fallback's name in the events it reports.
pub(super) const IP_HELPER_SOURCE: &str = "windows-ip-helper";

/// Snapshot-only polling of the owner tables while kernel ETW is unavailable, run by a
/// [`netmetrics_sys::SnapshotFallback`].
///
/// Opens and closes come from table diffs; there are no byte counts. The known sockets
/// persist across ETW retries, so returning to polling does not re-announce every socket.
#[derive(Debug, Default)]
pub(super) struct IpHelperFallback {
    previous: HashMap<FlowKey, i64>,
}

impl IpHelperFallback {
    /// The connections the fallback announced and has not seen close, for the source that
    /// takes over from it.
    pub(super) fn into_announced(self) -> HashSet<FlowKey> {
        self.previous.into_keys().collect()
    }

    /// Reads the owner tables once and reports what changed since the last poll.
    pub(super) fn poll(&mut self, sink: &EventSink) -> Result<(), BackendError> {
        let timestamp = unix_now_ms();
        // The owner-module tables carry pid and creation timestamp together, so this path
        // gets both attribution and identity from one call.
        let sockets = owner_module::snapshot().map_err(|detail| {
            BackendError::new(BackendErrorKind::Io, "windows-owner-module", detail)
        })?;
        let mut current = HashMap::with_capacity(sockets.len());
        for socket in &sockets {
            current.insert(socket.key, socket.created);
            // A changed timestamp on a known tuple means the port was recycled onto a new
            // socket between polls; the cookie lets the flow table split them.
            if self.previous.get(&socket.key) != Some(&socket.created) {
                sink.emit(BackendEvent::Opened {
                    key: socket.key,
                    pid: socket.pid,
                    cookie: Some(socket.cookie()),
                    timestamp,
                    if_index: None,
                });
            }
        }
        for key in self.previous.keys() {
            if !current.contains_key(key) {
                sink.emit(BackendEvent::Closed {
                    pid: 0,
                    key: *key,
                    timestamp,
                });
            }
        }
        if let Ok(samples) = interface_stats(timestamp) {
            for sample in samples {
                sink.emit(BackendEvent::Interface(sample));
            }
        }
        self.previous = current;
        Ok(())
    }
}

pub(super) fn interface_stats(timestamp: u64) -> Result<Vec<InterfaceStats>, String> {
    let mut table = ptr::null_mut::<MIB_IF_TABLE2>();
    // SAFETY: the API initializes `table` on success.
    let status = unsafe { GetIfTable2(&raw mut table) };
    if status.0 != 0 || table.is_null() {
        return Err(format!("GetIfTable2 failed with {}", status.0));
    }
    // SAFETY: successful API call returned a readable table header.
    let count = unsafe { (*table).NumEntries as usize };
    // SAFETY: variable-sized rows immediately follow the header.
    let first = unsafe { ptr::addr_of!((*table).Table).cast::<MIB_IF_ROW2>() };
    // SAFETY: the API's returned count describes rows in its allocation.
    let rows = unsafe { slice::from_raw_parts(first, count) };
    let samples = rows
        .iter()
        .map(|row| InterfaceStats {
            index: row.InterfaceIndex,
            name: utf16_c_string(&row.Alias),
            rx_bytes: row.InOctets,
            tx_bytes: row.OutOctets,
            rx_errors: row.InErrors,
            tx_errors: row.OutErrors,
            rx_drops: row.InDiscards,
            tx_drops: row.OutDiscards,
            timestamp,
        })
        .collect();
    // SAFETY: `table` came from GetIfTable2 and has not been freed.
    unsafe {
        FreeMibTable(table.cast());
    }
    Ok(samples)
}

fn utf16_c_string(value: &[u16]) -> String {
    let end = value
        .iter()
        .position(|code_unit| *code_unit == 0)
        .unwrap_or(value.len());
    String::from_utf16_lossy(&value[..end])
}
