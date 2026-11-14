//! eBPF ring processing, process lifecycle updates, and procfs reconciliation.

use super::StartFailure;
use super::interface::{emit_interface_samples, enrich_if_index};
use super::procfs::ProcfsListing;
use crate::capability::CapabilityMatrix;
use aya::maps::{Array, MapData, RingBuf};
use aya::{Ebpf, EbpfLoader};
use netmetrics_core::{DegradeReason, unix_now_ms};
use netmetrics_sys::endpoint_owner::EndpointOwnerSource;
use netmetrics_sys::{
    BackendError, BackendErrorKind, BackendEvent, EventSink, StopFlag, TotalDelta, WireFlowKind,
    WireFlowRecord, WireRecord,
};
use std::error::Error;
use std::io;
use std::iter;
use std::os::fd::AsRawFd;
use std::path::Path;
use std::time::{Duration, Instant};

mod probes;
mod processes;
use probes::{attach_probes, loader_error};
use processes::Processes;

const RING_DRAIN_BUDGET: usize = 1_024;
/// Longest wait for ring data before the stop flag is checked again.
const MAX_RING_WAIT: Duration = Duration::from_millis(250);

/// The object's programs attached to the kernel, the maps the reader drains, and the endpoint
/// owners it publishes.
///
/// Dropping it releases all of them: Aya unloads each program and detaches its links when the
/// program is dropped, and closes each map's descriptor with the map. The object pins
/// nothing, so nothing outlives it.
pub(super) struct Probes {
    owners: Option<EndpointOwnerSource>,
    programs: Ebpf,
    ring: RingBuf<MapData>,
    diagnostics: Array<MapData, u64>,
    /// The programs' count of records the ring had no room for, when the object keeps one.
    lost_records: Option<Array<MapData, u64>>,
    capabilities: CapabilityMatrix,
}

/// Loads `object` and attaches its programs.
///
/// A failed start releases whatever it had taken, as dropping [`Probes`] does.
pub(super) fn start(object: &Path, sink: &EventSink) -> Result<Probes, StartFailure> {
    let namespace = foreign_pid_namespace();
    let mut loader = EbpfLoader::new();
    if let Some(PidNamespace { device, inode }) = &namespace {
        // An object built before it had these keeps the kernel's own PIDs, as it always did.
        loader
            .set_global("LOADER_PIDNS_DEV", device, false)
            .set_global("LOADER_PIDNS_INO", inode, false);
    }
    let mut programs = loader.load_file(object).map_err(|error| StartFailure {
        passes: passes(&error),
        error: BackendError::new(
            BackendErrorKind::Unavailable,
            "aya-loader",
            error.to_string(),
        ),
    })?;
    // From here on the start fails only when no byte-accounting group loads and attaches, or
    // the object lacks a map: the object does not fit this kernel, and will not until one of
    // them changes. A cause that passes fails only the programs it hits, so it fails the
    // start only by hitting every byte-accounting group at once, which is taken to repeat.
    let repeats = |error| StartFailure {
        error,
        passes: false,
    };
    let capabilities = attach_probes(&mut programs, sink);
    if !capabilities.has_byte_accounting() {
        return Err(repeats(loader_error(
            "no viable eBPF byte-accounting capability group".to_owned(),
        )));
    }
    let owners_supported = owner_records_supported(&programs, capabilities, sink);
    let (ring, diagnostics) = take_maps(&mut programs).map_err(repeats)?;
    let lost_records = take_lost_records(&mut programs, sink);
    Ok(Probes {
        owners: owners_supported.then(EndpointOwnerSource::default),
        programs,
        ring,
        diagnostics,
        lost_records,
        capabilities,
    })
}

/// A PID namespace as `bpf_get_ns_current_pid_tgid()` names one: the device and inode of
/// its `/proc/<pid>/ns/pid` file (bpf-helpers(7)).
struct PidNamespace {
    device: u64,
    inode: u64,
}

/// Inode of the initial PID namespace, `PROC_PID_INIT_INO` in the kernel's
/// `include/linux/proc_ns.h`. It is fixed, unlike that of every namespace created later.
const INITIAL_PID_NAMESPACE_INODE: u64 = 0xEFFF_FFFC;

/// This process's PID namespace when it is not the initial one, as in a container or WSL.
///
/// The programs take a task's PID from the kernel, which numbers it in the initial
/// namespace. Inside another namespace `/proc` lists the same task under a different
/// number (`pid_namespaces(7)`), so every PID in a record would name the wrong process or
/// none. Given this namespace, the programs report the PID it uses instead.
///
/// `None` in the initial namespace, where the two numbers agree, and when the namespace
/// file cannot be read: the programs then keep the kernel's PIDs.
fn foreign_pid_namespace() -> Option<PidNamespace> {
    use std::os::unix::fs::MetadataExt as _;

    let metadata = std::fs::metadata("/proc/self/ns/pid").ok()?;
    (metadata.ino() != INITIAL_PID_NAMESPACE_INODE).then(|| PidNamespace {
        device: metadata.dev(),
        inode: metadata.ino(),
    })
}

/// Whether a load that failed with `error` could succeed with the same object: `bpf(2)` says
/// `ENOMEM` is a lack of memory, and `EAGAIN`, from `BPF_PROG_LOAD`, a verification a pending
/// signal interrupted, which the caller should try again. Every other cause it documents, from
/// a missing privilege (`EPERM`) to a rejected program (`EACCES`, `EINVAL`, `E2BIG`), repeats.
/// Aya keeps the system call's error as the source of its own.
fn passes(error: &(dyn Error + 'static)) -> bool {
    iter::successors(Some(error), |&error| error.source()).any(|cause| {
        cause
            .downcast_ref::<io::Error>()
            .and_then(io::Error::raw_os_error)
            .is_some_and(|code| code == libc::ENOMEM || code == libc::EAGAIN)
    })
}

/// Reads `probes`' ring until stop is requested.
///
/// Nothing else ends it. `RingBuf::next` reads shared memory and only says whether a record
/// is waiting, a failed `poll` only ends a wait early, an undecodable record is reported and
/// skipped, and a reconciliation that fails is reported and tried again.
///
/// It starts by reconciling `listing`, which holds what the procfs fallback last listed when
/// it ran: a connection the fallback announced is not announced again, one that has gone is
/// closed, and the rest close as any connection does on eBPF. The processes the fallback
/// reported are kept current from then on.
pub(super) fn read(
    probes: Probes,
    listing: &mut ProcfsListing,
    interval: Duration,
    sink: &EventSink,
    stop: &StopFlag,
) {
    let Probes {
        owners,
        programs,
        mut ring,
        diagnostics,
        lost_records,
        capabilities,
    } = probes;
    let mut lost = TotalDelta::default();
    let mut processes = Processes::adopting(listing.take_processes());
    let mut next_process_sweep = Instant::now();
    let mut next_interface_poll = Instant::now();
    let mut reported_decode_error = false;
    let mut reported_send_context_loss = false;
    let mut next_diagnostic_poll = Instant::now();
    report_reconciliation(sink, listing.reconcile(sink));
    let mut next_reconciliation = Instant::now() + interval;

    'reading: while !stop.is_stop_requested() {
        if Instant::now() >= next_interface_poll {
            emit_interface_samples(sink, unix_now_ms());
            next_interface_poll = Instant::now() + interval;
        }
        let mut received = 0;
        while received < RING_DRAIN_BUDGET {
            if stop.is_stop_requested() {
                break 'reading;
            }
            if let Some(owners) = &owners {
                owners.processing();
            }
            let Some(item) = ring.next() else {
                break;
            };
            received += 1;
            let record = match WireRecord::decode(&item) {
                Ok(WireRecord::Flow(record)) => record,
                Ok(WireRecord::Process(record)) => {
                    processes.observe(&record, unix_now_ms(), sink);
                    continue;
                }
                Err(_) => {
                    if !reported_decode_error {
                        reported_decode_error = true;
                        sink.emit(BackendEvent::Degraded(DegradeReason::DecodeError {
                            source: "aya-ringbuf".to_owned(),
                        }));
                    }
                    continue;
                }
            };
            if let Some(owners) = &owners {
                record_owner(owners, &record);
            }
            emit_record(record, capabilities, sink, &mut processes);
        }
        if capabilities.needs_process_sweep() && Instant::now() >= next_process_sweep {
            processes.sweep(sink);
            next_process_sweep = Instant::now() + Duration::from_secs(1);
        }
        if capabilities.needs_reconciliation() && Instant::now() >= next_reconciliation {
            report_reconciliation(sink, listing.reconcile(sink));
            next_reconciliation = Instant::now() + interval;
        }
        if Instant::now() >= next_diagnostic_poll {
            if !reported_send_context_loss {
                reported_send_context_loss = report_send_context_loss(&diagnostics, sink);
            }
            if let Some(lost_records) = &lost_records {
                report_lost_records(lost_records, &mut lost, sink);
            }
            next_diagnostic_poll = Instant::now() + Duration::from_secs(1);
        }
        if received == 0 {
            if let Some(owners) = &owners {
                owners.drained();
            }
            let mut deadline = next_interface_poll.min(next_diagnostic_poll);
            if capabilities.needs_process_sweep() {
                deadline = deadline.min(next_process_sweep);
            }
            if capabilities.needs_reconciliation() {
                deadline = deadline.min(next_reconciliation);
            }
            // The programs submit without `BPF_RB_NO_WAKEUP`, so the kernel signals the
            // map fd once the consumer has drained everything, which is when this runs.
            netmetrics_sys::wait_readable([ring.as_raw_fd()], deadline, MAX_RING_WAIT);
        }
    }
    // Stops the kernel writing records nobody reads any more, before the maps close.
    drop(programs);
}

/// Reports the send probes' lost contexts, if there are any. Returns whether it did.
fn report_send_context_loss(diagnostics: &Array<MapData, u64>, sink: &EventSink) -> bool {
    let store_failures = diagnostics.get(&0, 0).unwrap_or(0);
    let missing_returns = diagnostics.get(&1, 0).unwrap_or(0);
    if store_failures == 0 && missing_returns == 0 {
        return false;
    }
    sink.emit(BackendEvent::Degraded(DegradeReason::SourceUnavailable {
        source: "linux-ebpf-send-context".to_owned(),
        detail: format!(
            "send context losses: {store_failures} stores failed, {missing_returns} returns unmatched"
        ),
    }));
    true
}

/// Reports the records the kernel programs could not put in the ring since the last report.
///
/// The ring is full when this reader has not emptied it in time, and a record with no room
/// is gone: its bytes are counted nowhere, and a close it carried leaves its flow open.
/// The kernel keeps no count of these, so the programs count them in `LOST_RECORDS`.
fn report_lost_records(
    lost_records: &Array<MapData, u64>,
    lost: &mut TotalDelta<u64>,
    sink: &EventSink,
) {
    // A count that cannot be read is no count: reading zero would look like a wrap.
    let Ok(total) = lost_records.get(&0, 0) else {
        return;
    };
    let dropped = lost.since_last(total);
    if dropped > 0 {
        sink.emit(BackendEvent::Degraded(DegradeReason::BufferOverflow {
            dropped,
        }));
    }
}

/// The `LOST_RECORDS` count from the loaded object. An object built before the count has
/// none: its losses cannot be reported, which is said once.
fn take_lost_records(bpf: &mut Ebpf, sink: &EventSink) -> Option<Array<MapData, u64>> {
    let lost_records = bpf
        .take_map("LOST_RECORDS")
        .and_then(|map| Array::<_, u64>::try_from(map).ok());
    if lost_records.is_none() {
        sink.emit(BackendEvent::Degraded(DegradeReason::SourceUnavailable {
            source: "linux-ebpf-lost-records".to_owned(),
            detail: "BPF object predates the lost-record count; rebuild netmetrics.bpf.o"
                .to_owned(),
        }));
    }
    lost_records
}

/// Emits a flow record's collector event, reporting its process first.
///
/// A process is read from `/proc` the first time it is seen. After that the kernel's exec
/// and exit records keep it current; a kernel that sends no exit records has every open
/// read it again instead, so a reused PID is noticed.
fn emit_record(
    mut record: WireFlowRecord,
    capabilities: CapabilityMatrix,
    sink: &EventSink,
    processes: &mut Processes,
) {
    record.if_index = enrich_if_index(record.key.remote_addr, record.if_index);
    let timestamp = unix_now_ms();
    let reread = record.kind == WireFlowKind::Open && capabilities.needs_process_sweep();
    if record.pid != 0 && (reread || !processes.knows(record.pid)) {
        processes.refresh(record.pid, timestamp, sink);
    }
    if let Some(event) = record.backend_event(timestamp) {
        sink.emit(event);
    }
}

/// Whether the loaded object and probes can prove endpoint ownership.
///
/// Owner records come from the connect, accept and send entry probes, and
/// objects built before them have no `SEND_OWNERS` map. Without them, byte records alone would let
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
fn record_owner(owners: &EndpointOwnerSource, record: &WireFlowRecord) {
    let Some(event_at) = netmetrics_sys::endpoint_owner::monotonic_event_time(record.timestamp)
    else {
        return;
    };
    match record.kind {
        WireFlowKind::Owner => owners.record(record.key, record.pid, event_at),
        WireFlowKind::Sent | WireFlowKind::Received => {
            owners.observe(record.key, record.pid, event_at);
        }
        WireFlowKind::Open | WireFlowKind::Close | WireFlowKind::Finishing => {}
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

fn report_reconciliation(sink: &EventSink, result: Result<(), BackendError>) {
    if let Err(error) = result {
        sink.emit(BackendEvent::Degraded(DegradeReason::SourceUnavailable {
            source: "linux-ebpf-reconciliation".to_owned(),
            detail: error.to_string(),
        }));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fmt::{self, Display, Formatter};

    /// An error that keeps the system call's error as its source, as Aya's do.
    #[derive(Debug)]
    struct Wrapped(io::Error);

    impl Display for Wrapped {
        fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
            formatter.write_str("the bpf system call failed")
        }
    }

    impl Error for Wrapped {
        fn source(&self) -> Option<&(dyn Error + 'static)> {
            Some(&self.0)
        }
    }

    fn failed_with(code: i32) -> Wrapped {
        Wrapped(io::Error::from_raw_os_error(code))
    }

    #[test]
    fn a_lack_of_memory_or_an_interrupted_verification_passes() {
        assert!(passes(&failed_with(libc::ENOMEM)));
        assert!(passes(&failed_with(libc::EAGAIN)));
        assert!(passes(&io::Error::from_raw_os_error(libc::ENOMEM)));
    }

    #[test]
    fn a_missing_privilege_or_a_rejected_program_repeats() {
        for code in [
            libc::EPERM,
            libc::EACCES,
            libc::EINVAL,
            libc::E2BIG,
            libc::ENOENT,
        ] {
            assert!(!passes(&failed_with(code)), "errno {code}");
        }
        assert!(!passes(&io::Error::other("not a system call error")));
    }
}
