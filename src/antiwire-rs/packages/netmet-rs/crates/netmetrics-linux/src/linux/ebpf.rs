//! eBPF ring processing, process lifecycle updates, and procfs reconciliation.

use super::interface::{best_interface_index, emit_interface_samples, enrich_if_index};
use super::io_error;
use super::process::read_process_identity;
use super::procfs::{inode_pid_map, read_proc_flows, snapshot_row_is_news};
use crate::capability::CapabilityMatrix;
use aya::Ebpf;
use aya::maps::{Array, MapData, RingBuf};
use netmetrics_core::{DegradeReason, ProcessIdentity, ProcessInfo, unix_now_ms};
use netmetrics_sys::{
    BackendConfig, BackendError, BackendErrorKind, BackendEvent, EventSink, StopFlag, WireFlowKind,
    WireFlowRecord,
};
use std::collections::HashMap;
use std::os::fd::AsRawFd;
use std::path::Path;
use std::time::{Duration, Instant};

mod probes;
use probes::{attach_probes, loader_error};

const RING_DRAIN_BUDGET: usize = 1_024;
/// Longest wait for ring data before the stop flag is checked again.
const MAX_RING_WAIT: Duration = Duration::from_millis(250);

pub(super) fn run(
    object: &Path,
    config: &BackendConfig,
    sink: &EventSink,
    stop: &StopFlag,
) -> Result<(), BackendError> {
    let mut bpf = Ebpf::load_file(object).map_err(|error| {
        BackendError::new(
            BackendErrorKind::Unavailable,
            "aya-loader",
            error.to_string(),
        )
    })?;

    let capabilities = attach_probes(&mut bpf, sink);
    if !capabilities.has_byte_accounting() {
        return Err(loader_error(
            "no viable eBPF byte-accounting capability group".to_owned(),
        ));
    }

    let owners_supported = owner_records_supported(&bpf, capabilities, sink);
    let (mut ring, diagnostics) = take_maps(&mut bpf)?;
    let owners =
        owners_supported.then(netmetrics_sys::endpoint_owner::EndpointOwnerSource::default);
    let mut processes = HashMap::<u32, ProcessIdentity>::new();
    let mut next_process_sweep = Instant::now();
    let interface_interval = Duration::from_millis(config.poll_interval_ms.max(250));
    let mut next_interface_poll = Instant::now();
    let mut reported_decode_error = false;
    let mut reported_send_context_loss = false;
    let mut next_diagnostic_poll = Instant::now();
    let mut snapshot_flows = HashMap::new();
    report_reconciliation(sink, reconcile_snapshot(sink, &mut snapshot_flows, true));
    let mut next_reconciliation = Instant::now() + interface_interval;

    while !stop.is_stop_requested() {
        if Instant::now() >= next_interface_poll {
            emit_interface_samples(sink, unix_now_ms());
            next_interface_poll = Instant::now() + interface_interval;
        }
        let mut received = 0;
        while received < RING_DRAIN_BUDGET {
            if stop.is_stop_requested() {
                return Ok(());
            }
            if let Some(owners) = &owners {
                owners.processing();
            }
            let Some(item) = ring.next() else {
                break;
            };
            received += 1;
            let Ok(record) = WireFlowRecord::decode(&item) else {
                if !reported_decode_error {
                    reported_decode_error = true;
                    sink.emit(BackendEvent::Degraded(DegradeReason::DecodeError {
                        source: "aya-ringbuf".to_owned(),
                    }));
                }
                continue;
            };
            if let Some(owners) = &owners {
                record_owner(owners, &record);
            }
            if record.kind != WireFlowKind::Owner {
                emit_record(record, sink, &mut processes);
            }
        }
        if Instant::now() >= next_process_sweep {
            sweep_processes(sink, &mut processes);
            next_process_sweep = Instant::now() + Duration::from_secs(1);
        }
        if capabilities.needs_reconciliation() && Instant::now() >= next_reconciliation {
            report_reconciliation(sink, reconcile_snapshot(sink, &mut snapshot_flows, false));
            next_reconciliation = Instant::now() + interface_interval;
        }
        if Instant::now() >= next_diagnostic_poll {
            let store_failures = diagnostics.get(&0, 0).unwrap_or(0);
            let missing_returns = diagnostics.get(&1, 0).unwrap_or(0);
            if !reported_send_context_loss && (store_failures != 0 || missing_returns != 0) {
                reported_send_context_loss = true;
                sink.emit(BackendEvent::Degraded(DegradeReason::SourceUnavailable {
                    source: "linux-ebpf-send-context".to_owned(),
                    detail: format!(
                        "send context losses: {store_failures} stores failed, {missing_returns} returns unmatched"
                    ),
                }));
            }
            next_diagnostic_poll = Instant::now() + Duration::from_secs(1);
        }
        if received == 0 {
            if let Some(owners) = &owners {
                owners.drained();
            }
            let mut deadline = next_interface_poll
                .min(next_process_sweep)
                .min(next_diagnostic_poll);
            if capabilities.needs_reconciliation() {
                deadline = deadline.min(next_reconciliation);
            }
            // The programs submit without `BPF_RB_NO_WAKEUP`, so the kernel signals the
            // map fd once the consumer has drained everything, which is when this runs.
            netmetrics_sys::wait_readable(ring.as_raw_fd(), deadline, MAX_RING_WAIT);
        }
    }
    Ok(())
}

/// Emits a flow record's collector event, refreshing its process first.
fn emit_record(
    mut record: WireFlowRecord,
    sink: &EventSink,
    processes: &mut HashMap<u32, ProcessIdentity>,
) {
    record.if_index = enrich_if_index(record.key.remote_addr, record.if_index);
    let timestamp = unix_now_ms();
    if record.pid != 0
        && (record.kind == WireFlowKind::Open || !processes.contains_key(&record.pid))
    {
        refresh_process(record.pid, timestamp, sink, processes);
    }
    if let Some(event) = record.backend_event(timestamp) {
        sink.emit(event);
    }
}

/// Whether the loaded object and probes can prove endpoint ownership.
///
/// Owner records come from the send entry probes, and objects built before
/// them have no `SEND_OWNERS` map. Without them, byte records alone would let
/// a lookup return the previous owner of a reused port, so publish nothing
/// and leave lookups `Unavailable`.
fn owner_records_supported(bpf: &Ebpf, capabilities: CapabilityMatrix, sink: &EventSink) -> bool {
    let detail = if bpf.map("SEND_OWNERS").is_none() {
        "BPF object predates send-entry owner records; rebuild netmetrics.bpf.o"
    } else if !(capabilities.tcp_send && capabilities.udp_send) {
        "TCP and UDP send probes are both required"
    } else {
        return true;
    };
    sink.emit(BackendEvent::Degraded(DegradeReason::SourceUnavailable {
        source: "linux-ebpf-endpoint-owner".to_owned(),
        detail: detail.to_owned(),
    }));
    false
}

/// Feeds a ring record's owner to the history.
///
/// Owner records are timed before they take their ring position, so they
/// arrive in time order and prove progress. Byte records are timed when the
/// call returns, out of order, so they only add history. I/O probes run in
/// the owning task; state tracepoints can run in softirq context, whose
/// current PID is not the socket owner, so they are not used.
fn record_owner(
    owners: &netmetrics_sys::endpoint_owner::EndpointOwnerSource,
    record: &WireFlowRecord,
) {
    let Some(event_at) = netmetrics_sys::endpoint_owner::monotonic_event_time(record.timestamp)
    else {
        return;
    };
    match record.kind {
        WireFlowKind::Owner => owners.record(record.key, record.pid, event_at),
        WireFlowKind::Sent | WireFlowKind::Received => {
            owners.observe(record.key, record.pid, event_at);
        }
        WireFlowKind::Open | WireFlowKind::Close => {}
    }
}

/// The `EVENTS` ring and the `SEND_DIAGNOSTICS` counters from the loaded object.
fn take_maps(bpf: &mut Ebpf) -> Result<(RingBuf<MapData>, Array<MapData, u64>), BackendError> {
    let map = bpf.take_map("EVENTS").ok_or_else(|| {
        BackendError::new(
            BackendErrorKind::Unavailable,
            "aya-loader",
            "BPF object does not contain an EVENTS ring buffer",
        )
    })?;
    let ring = RingBuf::try_from(map).map_err(|error| {
        BackendError::new(
            BackendErrorKind::Unavailable,
            "aya-ringbuf",
            error.to_string(),
        )
    })?;
    let diagnostics_map = bpf.take_map("SEND_DIAGNOSTICS").ok_or_else(|| {
        BackendError::new(
            BackendErrorKind::Unavailable,
            "aya-loader",
            "BPF object does not contain SEND_DIAGNOSTICS",
        )
    })?;
    let diagnostics = Array::<_, u64>::try_from(diagnostics_map)
        .map_err(|error| loader_error(error.to_string()))?;
    Ok((ring, diagnostics))
}

fn refresh_process(
    pid: u32,
    timestamp: u64,
    sink: &EventSink,
    processes: &mut HashMap<u32, ProcessIdentity>,
) {
    let Some(identity) = read_process_identity(Path::new("/proc"), pid) else {
        return;
    };
    if processes.get(&pid) == Some(&identity) {
        return;
    }
    if processes.contains_key(&pid) {
        sink.emit(BackendEvent::ProcessStopped {
            pid,
            timestamp,
            identity: processes.get(&pid).cloned(),
        });
    }
    processes.insert(pid, identity.clone());
    sink.emit(BackendEvent::ProcessStarted(ProcessInfo { pid, identity }));
}

fn sweep_processes(sink: &EventSink, processes: &mut HashMap<u32, ProcessIdentity>) {
    let stopped_at = unix_now_ms();
    processes.retain(|pid, identity| {
        let live = Path::new("/proc").join(pid.to_string()).exists();
        if !live {
            sink.emit(BackendEvent::ProcessStopped {
                pid: *pid,
                timestamp: stopped_at,
                identity: Some(identity.clone()),
            });
        }
        live
    });
}

fn reconcile_snapshot(
    sink: &EventSink,
    previous: &mut HashMap<netmetrics_core::FlowKey, (u32, u64)>,
    initial: bool,
) -> Result<(), BackendError> {
    let timestamp = unix_now_ms();
    let inode_pids = inode_pid_map(Path::new("/proc"));
    let current = read_proc_flows(Path::new("/proc/net"), &inode_pids)
        .map_err(|error| io_error("procfs eBPF reconciliation", &error))?;
    for (key, (pid, inode)) in &current {
        if snapshot_row_is_news(previous.get(key), *pid, *inode) {
            sink.emit(BackendEvent::Opened {
                key: *key,
                pid: *pid,
                cookie: Some(netmetrics_core::SocketCookie {
                    value: *inode,
                    source: netmetrics_core::CookieSource::LinuxInode,
                }),
                timestamp,
                if_index: best_interface_index(key.remote_addr),
            });
        }
    }
    if !initial {
        for key in previous.keys() {
            if !current.contains_key(key) {
                sink.emit(BackendEvent::Closed {
                    pid: 0,
                    key: *key,
                    timestamp,
                });
            }
        }
    }
    *previous = current;
    Ok(())
}

fn report_reconciliation(sink: &EventSink, result: Result<(), BackendError>) {
    if let Err(error) = result {
        sink.emit(BackendEvent::Degraded(DegradeReason::SourceUnavailable {
            source: "linux-ebpf-reconciliation".to_owned(),
            detail: error.to_string(),
        }));
    }
}
