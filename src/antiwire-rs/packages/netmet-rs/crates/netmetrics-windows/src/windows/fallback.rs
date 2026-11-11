//! IP Helper polling while ETW is unavailable, plus interface counters.

use crate::owner_module;
use netmetrics_core::{DegradeReason, FlowKey, InterfaceStats, unix_now_ms};
use netmetrics_sys::{
    BackendConfig, BackendError, BackendErrorKind, BackendEvent, EventSink, StopFlag,
};
use std::collections::HashMap;
use std::ptr;
use std::slice;
use std::time::{Duration, Instant};
use windows::Win32::NetworkManagement::IpHelper::{
    FreeMibTable, GetIfTable2, MIB_IF_ROW2, MIB_IF_TABLE2,
};

/// How long snapshot polling runs before kernel ETW is tried again.
pub(super) const ETW_RETRY_INTERVAL: Duration = Duration::from_secs(60);

/// Why IP Helper polling returned.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum FallbackExit {
    Stopped,
    RetryEtw,
}

/// Snapshot-only polling of the owner tables while kernel ETW is unavailable.
///
/// Opens and closes come from table diffs; there are no byte counts. The known sockets
/// persist across ETW retries, so returning to polling does not re-announce every socket.
#[derive(Debug, Default)]
pub(super) struct IpHelperFallback {
    previous: HashMap<FlowKey, i64>,
    pub(super) entered: bool,
}

impl IpHelperFallback {
    /// Polls until `stop`, or until `retry_after` has passed and ETW should be tried again.
    pub(super) fn run(
        &mut self,
        config: &BackendConfig,
        sink: &EventSink,
        stop: &StopFlag,
        retry_after: Duration,
    ) -> Result<FallbackExit, BackendError> {
        if !self.entered {
            self.entered = true;
            sink.emit(BackendEvent::Degraded(DegradeReason::SnapshotOnly {
                source: "windows-ip-helper".to_owned(),
            }));
        }
        let retry_at = Instant::now() + retry_after;
        let interval = Duration::from_millis(config.poll_interval_ms.max(250));
        while !stop.is_stop_requested() {
            self.poll(sink)?;
            if Instant::now() >= retry_at {
                return Ok(FallbackExit::RetryEtw);
            }
            stop.wait_timeout(interval);
        }
        Ok(FallbackExit::Stopped)
    }

    fn poll(&mut self, sink: &EventSink) -> Result<(), BackendError> {
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
