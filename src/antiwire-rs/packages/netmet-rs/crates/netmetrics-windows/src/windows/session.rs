//! ETW session ownership, stale-session recovery, and processing worker lifetime.

use crate::session_names::{SessionNames, canonical_identity};
use ferrisetw::native::{EvntraceNativeError, TraceHandle};
use ferrisetw::trace::{TraceError, TraceProperties, TraceTrait};
use netmetrics_core::DegradeReason;
use netmetrics_sys::{BackendError, BackendErrorKind, BackendEvent, EventSink};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, TryRecvError};
use std::thread::JoinHandle;
use std::time::Duration;
use windows::Win32::Foundation::{
    CloseHandle, HANDLE, WAIT_ABANDONED, WAIT_OBJECT_0, WAIT_TIMEOUT,
};
use windows::Win32::System::Threading::{CreateMutexW, ReleaseMutex, WaitForSingleObject};
use windows::core::PCWSTR;

pub(super) struct SessionOwner(HANDLE);

impl SessionOwner {
    pub(super) fn acquire(session_name: &str) -> Result<Self, String> {
        let name = session_owner_name(session_name);
        // SAFETY: `name` is a NUL-terminated UTF-16 string that outlives the call.
        let handle = unsafe { CreateMutexW(None, false, PCWSTR(name.as_ptr())) }
            .map_err(|error| format!("creating session ownership mutex failed: {error}"))?;
        // SAFETY: `handle` is the mutex just created and still open.
        let wait = unsafe { WaitForSingleObject(handle, 0) };
        if wait == WAIT_OBJECT_0 || wait == WAIT_ABANDONED {
            return Ok(Self(handle));
        }
        let detail = if wait == WAIT_TIMEOUT {
            "another live collector owns this ETW session name".to_owned()
        } else {
            format!(
                "waiting for session ownership failed with status {}",
                wait.0
            )
        };
        // SAFETY: the mutex is not owned, so this closes the only reference to `handle`.
        unsafe {
            let _ = CloseHandle(handle);
        }
        Err(detail)
    }
}

impl Drop for SessionOwner {
    fn drop(&mut self) {
        // SAFETY: `acquire` only returns a `SessionOwner` for a mutex this thread owns, and
        // the handle is released and closed exactly once, here.
        unsafe {
            let _ = ReleaseMutex(self.0);
            let _ = CloseHandle(self.0);
        }
    }
}

fn session_owner_name(session_name: &str) -> Vec<u16> {
    let hash = crate::session_names::identity_hash(session_name);
    format!("Global\\netmetrics-etw-{hash:016x}")
        .encode_utf16()
        .chain(Some(0))
        .collect()
}

pub(super) struct SessionOwners {
    _owners: Vec<SessionOwner>,
    identities: Vec<Vec<u16>>,
}

impl SessionOwners {
    pub(super) fn acquire(names: &SessionNames) -> Result<Self, String> {
        let mut names: Vec<_> = names.all().collect();
        names.sort_by_key(|name| canonical_identity(name));
        let mut owners = Vec::with_capacity(names.len());
        let mut identities = Vec::with_capacity(names.len());
        for name in names {
            owners.push(SessionOwner::acquire(name)?);
            identities.push(canonical_identity(name));
        }
        Ok(Self {
            _owners: owners,
            identities,
        })
    }

    pub(super) fn owns(&self, name: &str) -> bool {
        let identity = canonical_identity(name);
        self.identities.contains(&identity)
    }
}

pub(super) fn is_session_collision(error: &TraceError) -> bool {
    matches!(
        error,
        TraceError::EtwNativeError(EvntraceNativeError::AlreadyExist)
    )
}

pub(super) struct ProcessingWorker {
    receiver: Receiver<Result<(), String>>,
    handle: Option<JoinHandle<()>>,
}

impl ProcessingWorker {
    pub(super) fn spawn<T: TraceTrait>(
        trace_handle: TraceHandle,
        name: &str,
    ) -> Result<Self, String> {
        Self::spawn_job(name, move || {
            T::process_from_handle(trace_handle).map_err(|error| format!("{error:?}"))
        })
    }

    pub(super) fn spawn_job(
        name: &str,
        job: impl FnOnce() -> Result<(), String> + Send + 'static,
    ) -> Result<Self, String> {
        let (sender, receiver) = mpsc::channel();
        let handle = std::thread::Builder::new()
            .name(name.to_owned())
            .spawn(move || {
                let _ = sender.send(job());
            })
            .map_err(|error| format!("spawning ETW processing worker failed: {error}"))?;
        Ok(Self {
            receiver,
            handle: Some(handle),
        })
    }

    pub(super) fn poll(&self) -> Option<Result<(), String>> {
        match self.receiver.try_recv() {
            Ok(result) => Some(result),
            Err(TryRecvError::Empty) => None,
            Err(TryRecvError::Disconnected) => {
                Some(Err("ETW processing worker disconnected".to_owned()))
            }
        }
    }

    pub(super) fn join(mut self) -> Result<(), String> {
        self.handle
            .take()
            .expect("processing worker handle")
            .join()
            .map_err(|_| "ETW processing worker panicked".to_owned())
    }
}

pub(super) struct RunningTrace<T: TraceTrait> {
    trace: Option<T>,
    worker: Option<ProcessingWorker>,
}

impl<T: TraceTrait> RunningTrace<T> {
    pub(super) fn new(trace: T, worker: ProcessingWorker) -> Self {
        Self {
            trace: Some(trace),
            worker: Some(worker),
        }
    }

    pub(super) fn processing_result(&self) -> Option<Result<(), String>> {
        self.worker.as_ref().and_then(ProcessingWorker::poll)
    }

    pub(super) fn stop(mut self) -> Result<(), String> {
        let stop_result = self
            .trace
            .take()
            .expect("running trace")
            .stop()
            .map_err(|error| format!("{error:?}"));
        let join_result = self.worker.take().expect("processing worker").join();
        stop_result.and(join_result)
    }
}

impl<T: TraceTrait> Drop for RunningTrace<T> {
    fn drop(&mut self) {
        // Optional side channels also need cleanup on a kernel worker error.
        if let Some(trace) = self.trace.take() {
            let _ = trace.stop();
        }
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

pub(super) enum TraceStartError {
    Native(TraceError),
    Worker(String),
}

impl TraceStartError {
    pub(super) fn detail(&self) -> String {
        match self {
            Self::Native(error) => format!("{error:?}"),
            Self::Worker(detail) => detail.clone(),
        }
    }
}

pub(super) fn is_start_collision(error: &TraceStartError) -> bool {
    matches!(error, TraceStartError::Native(error) if is_session_collision(error))
}

pub(super) fn failed_start_may_own_session(error: &TraceError) -> bool {
    !matches!(
        error,
        TraceError::InvalidTraceName
            | TraceError::EtwNativeError(EvntraceNativeError::AlreadyExist)
    )
}

pub(super) fn etw_trace_properties(total_buffer_mb: u32) -> TraceProperties {
    const BUFFER_KB: u32 = 64;
    let min_buffer = total_buffer_mb
        .saturating_mul(1024)
        .div_ceil(BUFFER_KB)
        .clamp(2, 1024);
    TraceProperties {
        buffer_size: BUFFER_KB,
        min_buffer,
        max_buffer: min_buffer.saturating_mul(2).min(1024),
        flush_timer: Duration::from_secs(1),
        ..TraceProperties::default()
    }
}

pub(super) fn report_decode_error_once(sink: &EventSink, errors: &AtomicU64, source: &str) {
    if errors.fetch_add(1, Ordering::Relaxed) == 0 {
        sink.emit(BackendEvent::Degraded(DegradeReason::DecodeError {
            source: source.to_owned(),
        }));
    }
}

/// Starts a trace named `name` with `start`, clearing a stale session that
/// holds the name and trying once more.
///
/// An ETW session outlives the process that created it, so an ungraceful exit
/// leaves the name taken and every later start fails with
/// `ERROR_ALREADY_EXISTS`. Errors carry the native detail of each attempt.
pub(super) fn start_clearing_stale_session<T>(
    owners: &SessionOwners,
    name: &str,
    mut start: impl FnMut() -> Result<T, TraceStartError>,
) -> Result<T, String> {
    /// `ERROR_WMI_INSTANCE_NOT_FOUND`: no stale session existed, so the name was not the problem.
    const NOT_FOUND: u32 = 4201;

    let first = match start() {
        Ok(trace) => return Ok(trace),
        Err(error) if is_start_collision(&error) => error.detail(),
        Err(error) => return Err(error.detail()),
    };
    let status = stop_stale_session(owners, name);
    if status != 0 && status != NOT_FOUND {
        return Err(format!(
            "{first}; stopping the stale session failed with {status}"
        ));
    }
    let trace = start().map_err(|retry| {
        format!(
            "{first}; retry after clearing stale session: {}",
            retry.detail()
        )
    })?;
    tracing_stale_session_recovered(name);
    Ok(trace)
}

/// Stops an ETW session left behind by a previous process.
///
/// ETW sessions are owned by the kernel, not by the process that created them, so an
/// ungraceful exit leaves the name registered and running. Every later start then fails with
/// `ERROR_ALREADY_EXISTS` and the collector falls back to a source with no byte accounting —
/// permanently, and silently, until someone clears the session by hand.
///
/// Returns the Win32 status; `ERROR_WMI_INSTANCE_NOT_FOUND` simply means there was nothing
/// stale to clear.
pub(super) fn stop_stale_session(owners: &SessionOwners, name: &str) -> u32 {
    use windows::Win32::System::Diagnostics::Etw::EVENT_TRACE_CONTROL_STOP;

    /// `ERROR_WMI_INSTANCE_NOT_FOUND`: treat unowned names as "nothing to stop".
    const NOT_FOUND: u32 = 4201;

    if !owners.owns(name) {
        return NOT_FOUND;
    }
    control_session(name, EVENT_TRACE_CONTROL_STOP)
}

/// Sends `control` to the ETW session named `name` and returns the Win32 status.
pub(super) fn control_session(
    name: &str,
    control: windows::Win32::System::Diagnostics::Etw::EVENT_TRACE_CONTROL,
) -> u32 {
    use windows::Win32::System::Diagnostics::Etw::{
        CONTROLTRACE_HANDLE, ControlTraceW, EVENT_TRACE_PROPERTIES,
    };

    // Room for the logger and log-file names ETW writes back into the trailing buffer.
    const NAME_BYTES: usize = 1024;

    let header = size_of::<EVENT_TRACE_PROPERTIES>();
    let total = header + NAME_BYTES * 2;
    // `EVENT_TRACE_PROPERTIES` contains 64-bit fields, so back the allocation with `u64`
    // rather than a byte vector to guarantee its alignment.
    let mut buffer = vec![0_u64; total.div_ceil(size_of::<u64>())];
    let allocated = buffer.len() * size_of::<u64>();
    let properties = buffer.as_mut_ptr().cast::<EVENT_TRACE_PROPERTIES>();

    // SAFETY: `properties` points at an allocation of `allocated` bytes, aligned for the
    // struct, and every field written below is within the header.
    unsafe {
        (*properties).Wnode.BufferSize = u32::try_from(allocated).unwrap_or(0);
        (*properties).LoggerNameOffset = u32::try_from(header).unwrap_or(0);
        (*properties).LogFileNameOffset = u32::try_from(header + NAME_BYTES).unwrap_or(0);
    }

    let wide: Vec<u16> = name.encode_utf16().chain(Some(0)).collect();
    // SAFETY: the properties buffer is sized and aligned as required, and `wide` is a
    // NUL-terminated string that outlives the call.
    let status = unsafe {
        ControlTraceW(
            CONTROLTRACE_HANDLE::default(),
            PCWSTR(wide.as_ptr()),
            properties,
            control,
        )
    };
    status.0
}

fn tracing_stale_session_recovered(name: &str) {
    // The backend has no logger of its own; the recovery is worth recording where the host
    // application can see it, so it rides the standard degraded channel's sibling path.
    eprintln!("netmetrics: cleared stale ETW session '{name}' and restarted tracing");
}

pub(super) fn classify_trace_error(source: &str, detail: &str) -> BackendError {
    let lowercase = detail.to_ascii_lowercase();
    let kind = if lowercase.contains("access")
        || lowercase.contains("denied")
        || lowercase.contains("privilege")
    {
        BackendErrorKind::PermissionDenied
    } else {
        BackendErrorKind::SessionLost
    };
    BackendError::new(kind, source, detail)
}
