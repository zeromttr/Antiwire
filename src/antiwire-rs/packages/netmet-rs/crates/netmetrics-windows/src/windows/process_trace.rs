//! Executable paths recorded by the OS at process creation, before a live
//! image query can lose a race with process exit, and process stops with the
//! creation time that says which process with a reused PID ended.
use super::kernel_trace::process_create_time;
use super::session::{
    ProcessingWorker, RunningTrace, SessionOwners, TraceStartError, classify_trace_error,
    etw_trace_properties, failed_start_may_own_session, report_decode_error_once,
    start_clearing_stale_session, stop_stale_session,
};
use crate::filetime::filetime_to_unix_ms;
use ferrisetw::EventRecord;
use ferrisetw::parser::Parser;
use ferrisetw::provider::{EventFilter, Provider};
use ferrisetw::schema_locator::SchemaLocator;
use ferrisetw::trace::UserTrace;
use netmetrics_core::{ProcessIdentity, ProcessInfo, unix_now_ms};
use netmetrics_sys::{BackendConfig, BackendError, BackendEvent, EventSink};
use std::sync::Arc;
use std::sync::atomic::AtomicU64;

const PROCESS_GUID: &str = "22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716";
const PROCESS_START: u16 = 1;
const PROCESS_STOP: u16 = 2;

pub(super) fn start(
    config: &BackendConfig,
    name: &str,
    owners: &SessionOwners,
    sink: &EventSink,
) -> Result<RunningTrace<UserTrace>, BackendError> {
    start_clearing_stale_session(owners, name, || build(config, name, owners, sink))
        .map_err(|detail| classify_trace_error("process image ETW", &detail))
}

fn build(
    config: &BackendConfig,
    name: &str,
    owners: &SessionOwners,
    sink: &EventSink,
) -> Result<RunningTrace<UserTrace>, TraceStartError> {
    let sink = sink.clone();
    let errors = Arc::new(AtomicU64::new(0));
    let callback =
        move |record: &EventRecord, locator: &SchemaLocator| match decode(record, locator) {
            Ok(Some(event)) => {
                sink.emit(event);
            }
            Ok(None) => {}
            Err(()) => report_decode_error_once(&sink, &errors, "windows-process-image"),
        };
    let provider = Provider::by_guid(PROCESS_GUID)
        .any(0x10)
        .level(4)
        .add_filter(EventFilter::ByEventIds(vec![PROCESS_START, PROCESS_STOP]))
        .add_callback(callback)
        .build();
    let (trace, handle) = UserTrace::new()
        .named(name.to_owned())
        .set_trace_properties(etw_trace_properties((config.buffer_mb / 4).max(1)))
        .enable(provider)
        .start()
        .map_err(|error| {
            if failed_start_may_own_session(&error) {
                let _ = stop_stale_session(owners, name);
            }
            TraceStartError::Native(error)
        })?;
    match ProcessingWorker::spawn::<UserTrace>(handle, "netmetrics-etw-process-image") {
        Ok(worker) => Ok(RunningTrace::new(trace, worker)),
        Err(detail) => {
            let _ = trace.stop();
            Err(TraceStartError::Worker(detail))
        }
    }
}

fn decode(record: &EventRecord, locator: &SchemaLocator) -> Result<Option<BackendEvent>, ()> {
    match record.event_id() {
        PROCESS_START => decode_start(record, locator),
        PROCESS_STOP => decode_stop(record, locator),
        _ => Ok(None),
    }
}

fn decode_start(record: &EventRecord, locator: &SchemaLocator) -> Result<Option<BackendEvent>, ()> {
    let schema = locator.event_schema(record).map_err(|_| ())?;
    let parser = Parser::create(record, &schema);
    // Manifest payload spelling is case-sensitive. The header PID is the
    // creator, not the child; it must never be used as an ownership fallback.
    let pid = parser.try_parse::<u32>("ProcessID").map_err(|_| ())?;
    let start_ts = process_create_time(&parser)
        .and_then(filetime_to_unix_ms)
        .filter(|time| *time > 0)
        .ok_or(())?;
    let executable = parser.try_parse::<String>("ImageName").map_err(|_| ())?;
    if pid <= 4 || executable.is_empty() {
        return Ok(None);
    }
    let name = executable
        .rsplit(['\\', '/'])
        .next()
        .unwrap_or_default()
        .to_owned();
    Ok(Some(BackendEvent::ProcessStarted(ProcessInfo {
        pid,
        identity: ProcessIdentity {
            executable,
            name,
            start_ts,
        },
    })))
}

/// A stop carrying the stopped process's creation time and its exit time,
/// both in the clock process creation times use, so the process table can
/// reject a stop for an earlier process with the same PID.
fn decode_stop(record: &EventRecord, locator: &SchemaLocator) -> Result<Option<BackendEvent>, ()> {
    let schema = locator.event_schema(record).map_err(|_| ())?;
    let parser = Parser::create(record, &schema);
    let pid = parser.try_parse::<u32>("ProcessID").map_err(|_| ())?;
    if pid <= 4 {
        return Ok(None);
    }
    let start_ts = process_create_time(&parser)
        .and_then(filetime_to_unix_ms)
        .unwrap_or(0);
    let stop_ts = filetime_field(&parser, "ExitTime")
        .and_then(filetime_to_unix_ms)
        .filter(|time| *time > 0)
        .unwrap_or_else(unix_now_ms);
    let executable = parser.try_parse::<String>("ImageName").unwrap_or_default();
    let name = executable
        .rsplit(['\\', '/'])
        .next()
        .unwrap_or_default()
        .to_owned();
    let identity = ProcessIdentity {
        executable,
        name,
        start_ts,
    };
    let usable = !identity.executable.is_empty() || identity.start_ts != 0;
    Ok(Some(BackendEvent::ProcessStopped {
        pid,
        timestamp: stop_ts,
        identity: usable.then_some(identity),
    }))
}

fn filetime_field(parser: &Parser<'_, '_>, field: &str) -> Option<u64> {
    parser
        .try_parse::<i64>(field)
        .ok()
        .and_then(|value| u64::try_from(value).ok())
        .or_else(|| parser.try_parse::<u64>(field).ok())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session_names::SessionNames;
    use std::process::{Command, Stdio};
    use std::sync::mpsc;
    use std::time::{Duration, Instant};

    #[test]
    #[ignore = "requires Administrator; starts its own process-image ETW session"]
    fn exited_process_start_retains_full_image_path() {
        let names =
            SessionNames::new(&format!("image-test-{}", std::process::id()), false).expect("names");
        let owners = SessionOwners::acquire(&names).expect("own test session");
        let (sender, receiver) = mpsc::sync_channel(1024);
        let sink = EventSink::new(sender, Arc::new(AtomicU64::new(0)));
        let config = BackendConfig {
            session_name: names.kernel().to_owned(),
            buffer_mb: 4,
            poll_interval_ms: 250,
            dns_hints: false,
        };
        let trace = start(&config, names.process(), &owners, &sink).expect("process trace");
        let executable = std::env::current_exe().expect("test executable");
        let mut child = Command::new(&executable)
            .arg("--help")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("child");
        let child_pid = child.id();
        assert!(child.wait().expect("child exit").success());
        // Read only after exit: correctness must not depend on OpenProcess.
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut captured = None;
        while Instant::now() < deadline {
            if let Ok(BackendEvent::ProcessStarted(info)) =
                receiver.recv_timeout(Duration::from_millis(100))
                && info.pid == child_pid
            {
                captured = Some(info.identity);
                break;
            }
        }
        trace.stop().expect("stop own trace");
        let identity =
            captured.expect("OS start event must identify the exited child, not its parent");
        assert!(identity.start_ts > 0);
        assert!(identity.executable.starts_with(r"\Device\"));
        assert!(
            identity.executable.ends_with(
                executable
                    .file_name()
                    .expect("name")
                    .to_str()
                    .expect("UTF-8")
            )
        );
        println!(
            "exited PID {child_pid}: {} (created {})",
            identity.executable, identity.start_ts
        );
    }

    #[test]
    #[ignore = "requires Administrator; starts its own process-image ETW session"]
    fn exited_process_stop_names_its_creation_time() {
        use netmetrics_core::{ProcessTable, StopOutcome};

        let names = SessionNames::new(&format!("image-stop-test-{}", std::process::id()), false)
            .expect("names");
        let owners = SessionOwners::acquire(&names).expect("own test session");
        let (sender, receiver) = mpsc::sync_channel(1024);
        let sink = EventSink::new(sender, Arc::new(AtomicU64::new(0)));
        let config = BackendConfig {
            session_name: names.kernel().to_owned(),
            buffer_mb: 4,
            poll_interval_ms: 250,
            dns_hints: false,
        };
        let trace = start(&config, names.process(), &owners, &sink).expect("process trace");
        let executable = std::env::current_exe().expect("test executable");
        let mut child = Command::new(&executable)
            .arg("--help")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("child");
        let child_pid = child.id();
        assert!(child.wait().expect("child exit").success());
        let deadline = Instant::now() + Duration::from_secs(5);
        let (mut started, mut stopped) = (None, None);
        while Instant::now() < deadline && (started.is_none() || stopped.is_none()) {
            match receiver.recv_timeout(Duration::from_millis(100)) {
                Ok(BackendEvent::ProcessStarted(info)) if info.pid == child_pid => {
                    started = Some(info);
                }
                Ok(BackendEvent::ProcessStopped {
                    pid,
                    timestamp,
                    identity,
                }) if pid == child_pid => stopped = Some((timestamp, identity)),
                _ => {}
            }
        }
        trace.stop().expect("stop own trace");
        let started = started.expect("start event for the child");
        let (stop_ts, identity) = stopped.expect("stop event for the child");
        let identity = identity.expect("the stop names the stopped process");
        println!(
            "PID {child_pid}: created {}, stop names creation {} and exit {stop_ts}, image {}",
            started.identity.start_ts, identity.start_ts, identity.executable
        );
        assert_eq!(
            identity.start_ts, started.identity.start_ts,
            "start and stop must name the same creation time"
        );
        assert!(stop_ts >= started.identity.start_ts);
        // The stop names the kernel's short image name, cut to 14 characters,
        // not a path.
        let file_name = executable
            .file_name()
            .expect("name")
            .to_str()
            .expect("UTF-8");
        assert!(!identity.executable.is_empty());
        assert!(
            file_name.starts_with(&identity.executable),
            "{} is not a prefix of {file_name}",
            identity.executable
        );

        // The process table accepts the child's own stop and would reject it
        // for a later process that reused the PID.
        let mut current = ProcessTable::new(60_000, 4);
        current.started(started.clone());
        assert_eq!(
            current.stopped_with_identity(child_pid, stop_ts, Some(identity.clone())),
            StopOutcome::Stopped
        );
        let mut reused = ProcessTable::new(60_000, 4);
        let mut later = started;
        later.identity.start_ts = stop_ts + 1;
        reused.started(later);
        assert_eq!(
            reused.stopped_with_identity(child_pid, stop_ts, Some(identity)),
            StopOutcome::Stale
        );
    }
}
