//! Kernel provider setup and process/network callback wiring.

use super::network::{ConnIdCache, ProcessAnnouncements, decode_network_event, emit_decoded};
use super::session::{
    ProcessingWorker, RunningTrace, SessionOwners, TraceStartError, etw_trace_properties,
    failed_start_may_own_session, report_decode_error_once, stop_stale_session,
};
use crate::filetime::filetime_to_unix_ms;
use crate::owner_module::{TcpOwnerSnapshot, UdpOwnerSnapshot};
use arc_swap::ArcSwap;
use ferrisetw::parser::Parser;
use ferrisetw::provider::{Provider, kernel_providers};
use ferrisetw::schema_locator::SchemaLocator;
use ferrisetw::trace::KernelTrace;
use ferrisetw::{EventRecord, GUID};
use netmetrics_core::{ProcessIdentity, ProcessInfo, Protocol, unix_now_ms};
use netmetrics_sys::{BackendConfig, BackendEvent, EventSink};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

const UDP_IP_GUID: &str = "bf3a50c5-a9c9-4988-a005-2df0b7c80f80";

/// State the kernel trace's callbacks share with the rest of the backend.
pub(super) struct KernelTraceState<'a> {
    pub(super) tcp_owners: &'a Arc<ArcSwap<TcpOwnerSnapshot>>,
    pub(super) udp_owners: &'a Arc<ArcSwap<UdpOwnerSnapshot>>,
    pub(super) flow_owners: &'a Arc<Mutex<crate::flow_owner::FlowOwnerCache>>,
    /// Set while the process-image trace reports stops (see
    /// [`kernel_process_callback`]).
    pub(super) image_stops: &'a Arc<AtomicBool>,
}

/// Builds the kernel providers and starts the trace.
///
/// Separated from `run` so a retry can construct a fresh set of providers: the builder
/// consumes them, so the first attempt cannot be replayed.
pub(super) fn start_kernel_trace(
    config: &BackendConfig,
    logger_name: &str,
    owners: &SessionOwners,
    sink: &EventSink,
    state: &KernelTraceState<'_>,
) -> Result<RunningTrace<KernelTrace>, TraceStartError> {
    let KernelTraceState {
        tcp_owners,
        udp_owners,
        flow_owners,
        image_stops,
    } = *state;
    let tcp_errors = Arc::new(AtomicU64::new(0));
    let tcp_sink = sink.clone();
    let callback_errors = Arc::clone(&tcp_errors);
    let tcp_callback = {
        let tcp_owners = Arc::clone(tcp_owners);
        let flow_owners = Arc::clone(flow_owners);
        let mut connids = ConnIdCache::default();
        let mut announced = ProcessAnnouncements::default();
        move |record: &EventRecord, locator: &SchemaLocator| match decode_network_event(
            record,
            locator,
            Protocol::Tcp,
            Some(&tcp_owners),
            None,
            &flow_owners,
            &mut connids,
        ) {
            Ok(Some(decoded)) => emit_decoded(&tcp_sink, decoded, &mut announced),
            Ok(None) => {}
            Err(()) => {
                report_decode_error_once(&tcp_sink, &callback_errors, "windows-kernel-tcpip");
            }
        }
    };

    let udp_errors = Arc::new(AtomicU64::new(0));
    let udp_sink = sink.clone();
    let callback_errors = Arc::clone(&udp_errors);
    let udp_callback = {
        let udp_owners = Arc::clone(udp_owners);
        let flow_owners = Arc::clone(flow_owners);
        let udp_sink = udp_sink.clone();
        let mut connids = ConnIdCache::default();
        let mut announced = ProcessAnnouncements::default();
        move |record: &EventRecord, locator: &SchemaLocator| match decode_network_event(
            record,
            locator,
            Protocol::Udp,
            None,
            Some(&udp_owners),
            &flow_owners,
            &mut connids,
        ) {
            Ok(Some(decoded)) => emit_decoded(&udp_sink, decoded, &mut announced),
            Ok(None) => {}
            Err(()) => {
                report_decode_error_once(&udp_sink, &callback_errors, "windows-kernel-udpip");
            }
        }
    };

    let process_callback = kernel_process_callback(sink, image_stops);

    let tcp_provider = Provider::kernel(&kernel_providers::TCP_IP_PROVIDER)
        .add_callback(tcp_callback)
        .build();
    let udp_kernel_provider = kernel_providers::KernelProvider::new(
        GUID::from(UDP_IP_GUID),
        kernel_providers::TCP_IP_PROVIDER.flags,
    );
    let udp_provider = Provider::kernel(&udp_kernel_provider)
        .add_callback(udp_callback)
        .build();
    let process_provider = Provider::kernel(&kernel_providers::PROCESS_PROVIDER)
        .add_callback(process_callback)
        .build();

    let started = KernelTrace::new()
        .named(logger_name.to_owned())
        .set_trace_properties(etw_trace_properties(config.buffer_mb))
        .enable(tcp_provider)
        .enable(udp_provider)
        .enable(process_provider)
        .start();
    let (trace, handle) = match started {
        Ok(started) => started,
        Err(error) => {
            if failed_start_may_own_session(&error) {
                let _ = stop_stale_session(owners, logger_name);
            }
            return Err(TraceStartError::Native(error));
        }
    };
    match ProcessingWorker::spawn::<KernelTrace>(handle, "netmetrics-etw-kernel") {
        Ok(worker) => Ok(RunningTrace::new(trace, worker, logger_name)),
        Err(detail) => {
            let _ = trace.stop();
            Err(TraceStartError::Worker(detail))
        }
    }
}

/// Decodes kernel process events. While `image_stops` is set it drops their
/// stops: the process-image trace reports each one with the stopped process's
/// creation time, which tells a stop for an earlier process with a reused PID
/// from one for the current process. These events carry none, so they stand in
/// only while that trace is down.
fn kernel_process_callback(
    sink: &EventSink,
    image_stops: &Arc<AtomicBool>,
) -> impl FnMut(&EventRecord, &SchemaLocator) + Send + Sync + 'static {
    let sink = sink.clone();
    let errors = Arc::new(AtomicU64::new(0));
    let image_stops = Arc::clone(image_stops);
    move |record: &EventRecord, locator: &SchemaLocator| match decode_process_event(record, locator)
    {
        Ok(Some(BackendEvent::ProcessStopped { .. })) if image_stops.load(Ordering::Acquire) => {}
        Ok(Some(event)) => {
            sink.emit(event);
        }
        Ok(None) => {}
        Err(()) => report_decode_error_once(&sink, &errors, "windows-kernel-process"),
    }
}

fn decode_process_event(
    record: &EventRecord,
    locator: &SchemaLocator,
) -> Result<Option<BackendEvent>, ()> {
    if !matches!(record.opcode(), 1..=4) {
        return Ok(None);
    }
    let schema = locator.event_schema(record).map_err(|_| ())?;
    let parser = Parser::create(record, &schema);
    let pid = parser
        .try_parse::<u32>("ProcessId")
        .or_else(|_| parser.try_parse::<u32>("PID"))
        .unwrap_or_else(|_| record.process_id());
    let timestamp = unix_now_ms();
    let stopped = matches!(record.opcode(), 2 | 4);
    let mut identity = parse_process_identity(&parser);
    if stopped {
        return Ok(Some(BackendEvent::ProcessStopped {
            pid,
            timestamp,
            identity: identity.is_usable().then_some(identity),
        }));
    }
    if let Some(image) =
        crate::process_image::resolve_process_image(pid, process_create_time(&parser))
    {
        image
            .path
            .rsplit(['\\', '/'])
            .next()
            .unwrap_or_default()
            .clone_into(&mut identity.name);
        identity.executable = image.path;
        identity.start_ts = image.start_unix_ms;
    }
    Ok(Some(BackendEvent::ProcessStarted(ProcessInfo {
        pid,
        identity,
    })))
}

fn parse_process_identity(parser: &Parser<'_, '_>) -> ProcessIdentity {
    let executable = parser
        .try_parse::<String>("ImageFileName")
        .or_else(|_| parser.try_parse::<String>("ImageName"))
        .unwrap_or_default();
    let name = executable
        .rsplit(['\\', '/'])
        .next()
        .unwrap_or_default()
        .to_owned();
    let start_ts = process_create_time(parser)
        .and_then(filetime_to_unix_ms)
        .unwrap_or(0);
    ProcessIdentity {
        executable,
        name,
        start_ts,
    }
}

pub(super) fn process_create_time(parser: &Parser<'_, '_>) -> Option<u64> {
    parser
        .try_parse::<i64>("CreateTime")
        .ok()
        .and_then(|value| u64::try_from(value).ok())
        .or_else(|| parser.try_parse::<u64>("CreateTime").ok())
}
