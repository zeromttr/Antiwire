use crate::app_filter::{AppFilter, HoldQueue, Released};
use crate::native::{self, NativeCapture, NativePacket, NextPacketResult};
use antiwire_tuning::{
    CAPTURE_LIVE_PAYLOAD_MAX_BYTES, CAPTURE_LIVE_QUEUE_MAX_CAPACITY,
    CAPTURE_LIVE_QUEUE_MEMORY_BUDGET, CAPTURE_LIVE_QUEUE_MIN_CAPACITY,
    CAPTURE_STATS_SAMPLE_MIN_INTERVAL_MS, CAPTURE_TYPICAL_FRAME_BYTES,
};
use parking_lot::{Mutex, RwLock};
use std::collections::VecDeque;
use std::fs::File;
use std::io::{BufWriter, Write};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};
use tempfile::NamedTempFile;
use thiserror::Error;
use tokio::sync::{watch, Notify};

const DEFAULT_CAPTURE_MAX_BYTES: u64 = 50 * 1024 * 1024;
const HARD_CAPTURE_MAX_BYTES: u64 = 500 * 1024 * 1024;
const PCAP_GLOBAL_HEADER_BYTES: u64 = 24;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaptureDevice {
    pub name: String,
    pub description: String,
    pub addresses: Vec<String>,
    pub loopback: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaptureFrame {
    pub sequence: u64,
    pub timestamp_us: u64,
    pub captured_length: u32,
    pub original_length: u32,
    pub link_layer: u32,
    pub protocol: String,
    pub source: String,
    pub destination: String,
    pub source_port: u32,
    pub destination_port: u32,
    pub info: String,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct CaptureOptions {
    pub device_name: String,
    pub capture_filter: String,
    pub snap_length: u32,
    pub promiscuous: bool,
    pub read_timeout_ms: u32,
    pub max_seconds: u32,
    pub max_bytes: u64,
    /// Keeps only one application's packets; `None` captures everything.
    pub app_filter: Option<AppFilter>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaptureSnapshot {
    pub status: CaptureStatus,
    pub packets: u64,
    pub bytes: u64,
    pub dropped_packets: u64,
    /// Packets an application capture left out as another application's.
    pub filtered_packets: u64,
    /// Application the capture is restricted to; empty when it is not.
    pub app_name: String,
    pub elapsed_seconds: u32,
    pub device_name: String,
    pub message: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CaptureStatus {
    Idle,
    Starting,
    Running,
    Stopping,
    Stopped,
    Faulted,
}

impl CaptureStatus {
    pub fn is_active(self) -> bool {
        matches!(self, Self::Starting | Self::Running | Self::Stopping)
    }
}

#[derive(Debug, Error)]
pub enum CaptureError {
    #[error("capture session already active")]
    AlreadyActive,
    #[error("no active capture session")]
    NotActive,
    #[error("capture device was not found: {0}")]
    DeviceNotFound(String),
    #[error("pcap unavailable: {0}")]
    PcapUnavailable(String),
    #[error("capture could not start: {0}")]
    StartFailed(String),
    #[error("capture worker did not start in time")]
    StartTimeout,
    #[error("capture cannot be downloaded while it is active")]
    StillActive,
    #[error("capture has no packet data to download")]
    NoCaptureData,
    #[error("capture storage failed: {0}")]
    Storage(String),
}

/// What the session and its worker share. Every lock of it is brief and
/// never held across I/O.
struct SessionState {
    status: CaptureStatus,
    /// Tells the current capture's worker to stop.
    stop_requested: Option<Arc<AtomicBool>>,
    /// Counts started captures, so a reader can tell when the capture it
    /// was following has been replaced by a newer one.
    generation: u64,
    /// The newest [`FrameReader`]; live frames go to it alone.
    reader: u64,
    live_frames: VecDeque<CaptureFrame>,
    live_bytes: usize,
    live_max_frames: usize,
    live_max_payload: usize,
    capture_file: Option<NamedTempFile>,
    packets: u64,
    bytes: u64,
    dropped_packets: u64,
    filtered_packets: u64,
    app_name: String,
    device_name: String,
    message: String,
    started_at: Option<Instant>,
    stopped_elapsed: Duration,
    next_sequence: u64,
    /// Each status the capture enters.
    status_changes: watch::Sender<CaptureStatus>,
    /// Wakes the reader when frames arrive, the status changes, or a newer
    /// reader takes over.
    readers: Arc<Notify>,
}

impl SessionState {
    fn new() -> Self {
        let live_max_frames = ((CAPTURE_LIVE_QUEUE_MEMORY_BUDGET
            / i64::from(CAPTURE_TYPICAL_FRAME_BYTES)) as usize)
            .clamp(
                CAPTURE_LIVE_QUEUE_MIN_CAPACITY as usize,
                CAPTURE_LIVE_QUEUE_MAX_CAPACITY as usize,
            );
        Self {
            status: CaptureStatus::Idle,
            stop_requested: None,
            generation: 0,
            reader: 0,
            live_frames: VecDeque::new(),
            live_bytes: 0,
            live_max_frames,
            live_max_payload: CAPTURE_LIVE_PAYLOAD_MAX_BYTES as usize,
            capture_file: None,
            packets: 0,
            bytes: 0,
            dropped_packets: 0,
            filtered_packets: 0,
            app_name: String::new(),
            device_name: String::new(),
            message: String::new(),
            started_at: None,
            stopped_elapsed: Duration::ZERO,
            next_sequence: 0,
            status_changes: watch::Sender::new(CaptureStatus::Idle),
            readers: Arc::new(Notify::new()),
        }
    }

    /// Clears the previous capture and enters `Starting` for a new one.
    fn reset(&mut self, options: &CaptureOptions, stop_requested: Arc<AtomicBool>) {
        self.live_frames.clear();
        self.live_bytes = 0;
        self.capture_file = None;
        self.packets = 0;
        self.bytes = 0;
        self.dropped_packets = 0;
        self.filtered_packets = 0;
        self.app_name = options
            .app_filter
            .as_ref()
            .map(|filter| filter.app_name.clone())
            .unwrap_or_default();
        self.device_name.clone_from(&options.device_name);
        self.started_at = None;
        self.stopped_elapsed = Duration::ZERO;
        self.next_sequence = 0;
        self.stop_requested = Some(stop_requested);
        self.generation = self.generation.wrapping_add(1);
        self.transition(CaptureStatus::Starting, "Opening capture interface…");
    }

    /// Enters `status`, tells subscribers, and wakes the reader.
    fn transition(&mut self, status: CaptureStatus, message: impl Into<String>) {
        self.status = status;
        self.message = message.into();
        self.status_changes.send_replace(status);
        self.readers.notify_waiters();
    }

    /// Ends the capture as faulted, keeping how long it ran.
    fn fault(&mut self, message: impl Into<String>) {
        if let Some(started_at) = self.started_at.take() {
            self.stopped_elapsed = started_at.elapsed();
        }
        self.transition(CaptureStatus::Faulted, message);
    }

    fn push_frame(&mut self, mut frame: CaptureFrame, stored_bytes: u64) {
        self.packets = self.packets.saturating_add(1);
        self.bytes = self.bytes.saturating_add(stored_bytes);
        self.next_sequence = self.next_sequence.saturating_add(1);

        frame.sequence = self.next_sequence;
        frame.payload.truncate(self.live_max_payload);
        let live_length = frame.payload.len();
        let live_budget = CAPTURE_LIVE_QUEUE_MEMORY_BUDGET as usize;
        while self.live_frames.len() >= self.live_max_frames
            || self.live_bytes.saturating_add(live_length) > live_budget
        {
            let Some(removed) = self.live_frames.pop_front() else {
                break;
            };
            self.live_bytes = self.live_bytes.saturating_sub(removed.payload.len());
        }

        // The reader takes the whole queue each time it wakes, so only the
        // first frame into an empty queue needs to wake it.
        let was_empty = self.live_frames.is_empty();
        self.live_bytes = self.live_bytes.saturating_add(live_length);
        self.live_frames.push_back(frame);
        if was_empty {
            self.readers.notify_waiters();
        }
    }

    /// Puts frames a reader took but never delivered back at the head of
    /// the queue, oldest first, then trims to the queue's bounds from the
    /// oldest end as [`Self::push_frame`] does.
    fn requeue_frames(&mut self, frames: Vec<CaptureFrame>) {
        for frame in frames.into_iter().rev() {
            self.live_bytes = self.live_bytes.saturating_add(frame.payload.len());
            self.live_frames.push_front(frame);
        }
        let live_budget = CAPTURE_LIVE_QUEUE_MEMORY_BUDGET as usize;
        while self.live_frames.len() > self.live_max_frames || self.live_bytes > live_budget {
            let Some(removed) = self.live_frames.pop_front() else {
                break;
            };
            self.live_bytes = self.live_bytes.saturating_sub(removed.payload.len());
        }
        self.readers.notify_waiters();
    }

    fn elapsed(&self) -> Duration {
        self.started_at
            .map_or(self.stopped_elapsed, |started_at| started_at.elapsed())
    }

    fn snapshot(&self) -> CaptureSnapshot {
        CaptureSnapshot {
            status: self.status,
            packets: self.packets,
            bytes: self.bytes,
            dropped_packets: self.dropped_packets,
            filtered_packets: self.filtered_packets,
            app_name: self.app_name.clone(),
            elapsed_seconds: u32::try_from(self.elapsed().as_secs()).unwrap_or(u32::MAX),
            device_name: self.device_name.clone(),
            message: self.message.clone(),
        }
    }
}

fn discover_devices() -> Vec<CaptureDevice> {
    native::discover_devices()
        .unwrap_or_default()
        .into_iter()
        .map(|device| CaptureDevice {
            name: device.name,
            description: device.description,
            addresses: device.addresses,
            loopback: device.loopback,
        })
        .collect()
}

/// Single active capture with separate bounded archive and live-stream queues.
///
/// Every method takes `&self`, so the session is shared as it is. Starts are
/// serialized among themselves; status, stop, and the frame reader never
/// wait behind one, nor behind interface discovery.
pub struct CaptureSession {
    state: Arc<Mutex<SessionState>>,
    /// Interfaces as last discovered. Discovery runs outside every lock.
    devices: RwLock<Vec<CaptureDevice>>,
    /// The capture worker. Held for a whole start, including the wait for a
    /// previous worker to exit, so only one start runs at a time.
    worker: Mutex<Option<JoinHandle<()>>>,
}

/// Archives live in one directory under a recognisable name, so one a crash
/// left behind can be found and deleted at the next start.
const ARCHIVE_DIR: &str = "antiwire-capture";
const ARCHIVE_PREFIX: &str = "capture-";
const ARCHIVE_SUFFIX: &str = ".pcap";

fn archive_dir() -> std::path::PathBuf {
    std::env::temp_dir().join(ARCHIVE_DIR)
}

/// Creates the archive file in [`archive_dir`], which is owner-only on unix.
fn create_archive() -> std::io::Result<NamedTempFile> {
    let dir = archive_dir();
    std::fs::create_dir_all(&dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))?;
    }
    tempfile::Builder::new()
        .prefix(ARCHIVE_PREFIX)
        .suffix(ARCHIVE_SUFFIX)
        .tempfile_in(dir)
}

/// Deletes archives a previous run left behind. A clean exit deletes its own
/// archive; one that crashed cannot, and full packets must not pile up.
fn remove_orphaned_archives(dir: &std::path::Path) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name.starts_with(ARCHIVE_PREFIX) && name.ends_with(ARCHIVE_SUFFIX) {
            if let Err(error) = std::fs::remove_file(entry.path()) {
                tracing::warn!(%error, file = %name, "could not delete a leftover capture archive");
            }
        }
    }
}

impl CaptureSession {
    /// Starts an idle session, deleting any capture archive a crashed run left.
    pub fn new() -> Self {
        remove_orphaned_archives(&archive_dir());
        Self {
            state: Arc::new(Mutex::new(SessionState::new())),
            devices: RwLock::new(discover_devices()),
            worker: Mutex::new(None),
        }
    }

    pub fn status(&self) -> CaptureStatus {
        self.state.lock().status
    }

    pub fn snapshot(&self) -> CaptureSnapshot {
        self.state.lock().snapshot()
    }

    /// Notified with each status the capture enters.
    pub fn status_changes(&self) -> watch::Receiver<CaptureStatus> {
        self.state.lock().status_changes.subscribe()
    }

    /// The capture interfaces, discovered again unless a capture is running.
    /// Blocking.
    pub fn discover_devices(&self) -> Vec<CaptureDevice> {
        if !self.status().is_active() {
            self.refresh_devices();
        }
        self.devices.read().clone()
    }

    fn refresh_devices(&self) {
        let found = discover_devices();
        *self.devices.write() = found;
    }

    fn has_device(&self, name: &str) -> bool {
        self.devices.read().iter().any(|device| device.name == name)
    }

    /// Starts the capture worker. Wait for the interface to open with
    /// [`CaptureStartup::wait`]. Blocking: it may discover interfaces and
    /// wait briefly for the previous worker to exit.
    pub fn start(&self, mut options: CaptureOptions) -> Result<CaptureStartup, CaptureError> {
        let mut worker = self.worker.lock();
        if !reap_worker(&mut worker, self.status().is_active()) || self.status().is_active() {
            return Err(CaptureError::AlreadyActive);
        }
        if !self.has_device(&options.device_name) {
            self.refresh_devices();
        }
        if !self.has_device(&options.device_name) {
            if let Err(error) = native::discover_devices() {
                return Err(CaptureError::PcapUnavailable(error));
            }
            return Err(CaptureError::DeviceNotFound(options.device_name));
        }

        options.snap_length = options.snap_length.clamp(64, 65_535);
        options.read_timeout_ms = options.read_timeout_ms.clamp(50, 1_000);
        options.max_bytes = bounded_max_bytes(options.max_bytes);
        let stop_requested = Arc::new(AtomicBool::new(false));
        self.state
            .lock()
            .reset(&options, Arc::clone(&stop_requested));

        let state = Arc::clone(&self.state);
        let panic_state = Arc::clone(&state);
        let worker_stop = Arc::clone(&stop_requested);
        let (ready_tx, ready_rx) = mpsc::sync_channel(1);
        let spawned = thread::Builder::new()
            .name("antiwire-packet-capture".to_owned())
            .spawn(move || {
                if catch_unwind(AssertUnwindSafe(|| {
                    run_capture_worker(&state, &worker_stop, options, &ready_tx);
                }))
                .is_err()
                {
                    panic_state
                        .lock()
                        .fault("Capture worker stopped unexpectedly.");
                }
            });
        match spawned {
            Ok(spawned) => *worker = Some(spawned),
            Err(error) => {
                let message = error.to_string();
                self.state.lock().fault(message.clone());
                return Err(CaptureError::StartFailed(message));
            }
        }
        Ok(CaptureStartup {
            ready: ready_rx,
            state: Arc::clone(&self.state),
            stop_requested,
        })
    }

    pub fn stop(&self) -> Result<(), CaptureError> {
        // Check and set in one critical section: the worker's final write of `Stopped` or
        // `Faulted` serializes with this, so `Stopping` can never clobber a terminal status.
        let mut state = self.state.lock();
        if !state.status.is_active() {
            return Err(CaptureError::NotActive);
        }
        if let Some(stop_requested) = &state.stop_requested {
            stop_requested.store(true, Ordering::Release);
        }
        state.transition(CaptureStatus::Stopping, "Finishing capture…");
        Ok(())
    }

    /// Becomes the one reader of the current capture's live frames. A
    /// previous reader stops receiving them.
    pub fn frame_reader(&self) -> FrameReader {
        let mut state = self.state.lock();
        state.reader = state.reader.wrapping_add(1);
        state.readers.notify_waiters();
        FrameReader {
            state: Arc::clone(&self.state),
            readers: Arc::clone(&state.readers),
            lease: state.reader,
            generation: state.generation,
        }
    }

    pub fn capture_reader(&self) -> Result<File, CaptureError> {
        let state = self.state.lock();
        if state.status.is_active() {
            return Err(CaptureError::StillActive);
        }
        let reader = state
            .capture_file
            .as_ref()
            .ok_or(CaptureError::NoCaptureData)?
            .reopen()
            .map_err(|error| CaptureError::Storage(error.to_string()))?;
        Ok(reader)
    }
}

/// Joins `worker` if it has finished, returning whether the slot is free.
///
/// One that has stopped capturing exits right after, so it gets a short
/// wait; one still stuck opening the interface after a start timeout is left
/// running, and the start reports the session as busy instead of blocking.
fn reap_worker(worker: &mut Option<JoinHandle<()>>, active: bool) -> bool {
    let Some(running) = worker.as_ref() else {
        return true;
    };
    if !active {
        let deadline = Instant::now() + WORKER_EXIT_GRACE;
        while !running.is_finished() && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(10));
        }
    }
    if !running.is_finished() {
        return false;
    }
    if let Some(finished) = worker.take() {
        let _ = finished.join();
    }
    true
}

/// The one reader of a capture's live frames; see
/// [`CaptureSession::frame_reader`].
pub struct FrameReader {
    state: Arc<Mutex<SessionState>>,
    readers: Arc<Notify>,
    lease: u64,
    generation: u64,
}

impl FrameReader {
    /// Every queued frame, possibly none. `None` once a newer reader took
    /// over, a newer capture started, or this capture ended and every frame
    /// was read.
    pub fn take_frames(&self) -> Option<Vec<CaptureFrame>> {
        let mut state = self.state.lock();
        if state.reader != self.lease || state.generation != self.generation {
            return None;
        }
        if state.live_frames.is_empty() && !state.status.is_active() {
            return None;
        }
        state.live_bytes = 0;
        Some(state.live_frames.drain(..).collect())
    }

    /// The next frames, waiting until there are some. `None` as for
    /// [`Self::take_frames`].
    pub async fn next_frames(&self) -> Option<Vec<CaptureFrame>> {
        loop {
            // Registered before looking, so a wake between the look and the
            // wait is not lost.
            let woken = self.readers.notified();
            tokio::pin!(woken);
            woken.as_mut().enable();
            match self.take_frames() {
                Some(frames) if frames.is_empty() => woken.await,
                taken => return taken,
            }
        }
    }

    /// Returns frames that were taken but could not be delivered, so the
    /// next reader of the same capture receives them.
    pub fn give_back(&self, frames: Vec<CaptureFrame>) {
        let mut state = self.state.lock();
        if state.generation == self.generation {
            state.requeue_frames(frames);
        }
    }
}

/// How long a start waits for the interface to open.
const START_TIMEOUT: Duration = Duration::from_secs(8);
/// How long a worker that has stopped capturing gets to exit.
const WORKER_EXIT_GRACE: Duration = Duration::from_secs(1);

/// A capture whose interface is still opening; see [`CaptureSession::start`].
#[must_use = "the capture has not necessarily started until `wait` returns"]
pub struct CaptureStartup {
    ready: mpsc::Receiver<Result<(), String>>,
    state: Arc<Mutex<SessionState>>,
    stop_requested: Arc<AtomicBool>,
}

impl CaptureStartup {
    /// Waits for the interface to open.
    ///
    /// # Errors
    ///
    /// Returns [`CaptureError::StartFailed`] when the interface cannot be
    /// opened, or [`CaptureError::StartTimeout`] when it does not open in
    /// time; the worker is then told to stop and is joined later.
    pub fn wait(self) -> Result<(), CaptureError> {
        let (error, message) = match self.ready.recv_timeout(START_TIMEOUT) {
            Ok(Ok(())) => return Ok(()),
            Ok(Err(error)) => return Err(CaptureError::StartFailed(error)),
            Err(mpsc::RecvTimeoutError::Timeout) => {
                self.stop_requested.store(true, Ordering::Release);
                (
                    CaptureError::StartTimeout,
                    "Capture interface did not open in time.".to_owned(),
                )
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                let message = "capture worker exited before startup completed".to_owned();
                (CaptureError::StartFailed(message.clone()), message)
            }
        };
        self.state.lock().fault(message);
        Err(error)
    }
}

fn bounded_max_bytes(requested: u64) -> u64 {
    match requested {
        0 => DEFAULT_CAPTURE_MAX_BYTES,
        bytes => bytes.min(HARD_CAPTURE_MAX_BYTES),
    }
}

impl Default for CaptureSession {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for CaptureSession {
    fn drop(&mut self) {
        if let Some(stop_requested) = &self.state.lock().stop_requested {
            stop_requested.store(true, Ordering::Release);
        }
        if let Some(worker) = self.worker.get_mut().take() {
            let _ = worker.join();
        }
    }
}

fn run_capture_worker(
    state: &Mutex<SessionState>,
    stop_requested: &AtomicBool,
    options: CaptureOptions,
    ready: &mpsc::SyncSender<Result<(), String>>,
) {
    let mut capture = match NativeCapture::open(
        &options.device_name,
        options.snap_length,
        options.promiscuous,
        options.read_timeout_ms,
        &options.capture_filter,
    ) {
        Ok(capture) => capture,
        Err(error) => {
            fail_capture_start(state, ready, error);
            return;
        }
    };

    let capture_file = match create_archive() {
        Ok(file) => file,
        Err(error) => {
            fail_capture_start(state, ready, error.to_string());
            return;
        }
    };
    let capture_writer_file = match capture_file.reopen() {
        Ok(file) => file,
        Err(error) => {
            fail_capture_start(state, ready, error.to_string());
            return;
        }
    };
    let mut capture_writer = BufWriter::with_capacity(256 * 1024, capture_writer_file);
    if let Err(error) = write_pcap_header(
        &mut capture_writer,
        options.snap_length,
        capture.link_layer(),
    ) {
        fail_capture_start(state, ready, error.to_string());
        return;
    }

    let started_at = Instant::now();
    let mut hold_queue = options
        .app_filter
        .as_ref()
        .map(|filter| HoldQueue::new(filter, started_at));
    {
        let mut state = state.lock();
        state.started_at = Some(started_at);
        state.bytes = PCAP_GLOBAL_HEADER_BYTES;
        state.capture_file = Some(capture_file);
        let message = match &options.app_filter {
            Some(filter) => format!("Capturing traffic from {}.", filter.app_name),
            None => "Capture is receiving traffic.".to_owned(),
        };
        state.transition(CaptureStatus::Running, message);
    }
    let _ = ready.send(Ok(()));

    let stats_interval =
        Duration::from_millis(u64::try_from(CAPTURE_STATS_SAMPLE_MIN_INTERVAL_MS).unwrap_or(500));
    let mut last_stats = Instant::now();
    let mut completion_message = "Capture stopped.".to_owned();
    let mut released = Vec::new();
    let mut size_limited = false;

    loop {
        if stop_requested.load(Ordering::Acquire) {
            break;
        }
        if options.max_seconds > 0
            && started_at.elapsed().as_secs() >= u64::from(options.max_seconds)
        {
            completion_message = "Capture reached its time limit.".to_owned();
            break;
        }
        let frame = match capture.next_packet() {
            Ok(NextPacketResult::Packet(packet)) => {
                Some(decode_packet(packet, capture.link_layer()))
            }
            Ok(NextPacketResult::Timeout) => None,
            Err(error) => {
                let _ = capture_writer.flush();
                drop(capture_writer);
                state.lock().fault(error);
                return;
            }
        };
        match hold_queue.as_mut() {
            None => released.extend(frame.map(Released::Keep)),
            Some(queue) => {
                let now = Instant::now();
                if let Some(frame) = frame {
                    released.extend(queue.push(frame, now));
                }
                queue.release(now, false, &mut released);
            }
        }
        match store_released(state, &mut capture_writer, &mut released, options.max_bytes) {
            Ok(Stored::Continue) => {}
            Ok(Stored::SizeLimit) => {
                completion_message = "Capture reached its size limit.".to_owned();
                size_limited = true;
                break;
            }
            Err(error) => {
                drop(capture_writer);
                state
                    .lock()
                    .fault(format!("capture storage failed: {error}"));
                return;
            }
        }

        if last_stats.elapsed() >= stats_interval {
            if let Ok(statistics) = capture.statistics() {
                state.lock().dropped_packets = statistics
                    .dropped
                    .saturating_add(statistics.interface_dropped);
            }
            last_stats = Instant::now();
        }
    }

    if let Ok(statistics) = capture.statistics() {
        state.lock().dropped_packets = statistics
            .dropped
            .saturating_add(statistics.interface_dropped);
    }
    // Settle the packets still waiting for an owner. After a size limit they
    // are left out: the archive is full.
    if let Some(queue) = hold_queue.as_mut().filter(|_| !size_limited) {
        queue.release(Instant::now(), true, &mut released);
        match store_released(state, &mut capture_writer, &mut released, options.max_bytes) {
            Ok(Stored::Continue) => {}
            Ok(Stored::SizeLimit) => {
                completion_message = "Capture reached its size limit.".to_owned();
            }
            Err(error) => {
                drop(capture_writer);
                state
                    .lock()
                    .fault(format!("capture storage failed: {error}"));
                return;
            }
        }
    }
    if let Err(error) = capture_writer.flush() {
        state
            .lock()
            .fault(format!("capture storage failed: {error}"));
        return;
    }
    let mut state = state.lock();
    state.stopped_elapsed = started_at.elapsed();
    state.started_at = None;
    state.transition(CaptureStatus::Stopped, completion_message);
}

enum Stored {
    Continue,
    SizeLimit,
}

/// Writes the kept frames to the archive and the live queue, and counts the
/// filtered ones. Stops at the first frame that would pass `max_bytes`.
fn store_released(
    state: &Mutex<SessionState>,
    writer: &mut impl Write,
    released: &mut Vec<Released>,
    max_bytes: u64,
) -> std::io::Result<Stored> {
    let mut filtered = 0_u64;
    let mut outcome = Ok(Stored::Continue);
    for item in released.drain(..) {
        let frame = match item {
            Released::Keep(frame) => frame,
            Released::Filtered => {
                filtered += 1;
                continue;
            }
        };
        let record_bytes = pcap_record_size(&frame);
        if state.lock().bytes.saturating_add(record_bytes) > max_bytes {
            outcome = Ok(Stored::SizeLimit);
            break;
        }
        if let Err(error) = write_pcap_record(writer, &frame) {
            outcome = Err(error);
            break;
        }
        state.lock().push_frame(frame, record_bytes);
    }
    if filtered > 0 {
        let mut state = state.lock();
        state.filtered_packets = state.filtered_packets.saturating_add(filtered);
    }
    outcome
}

fn fail_capture_start(
    state: &Mutex<SessionState>,
    ready: &mpsc::SyncSender<Result<(), String>>,
    message: String,
) {
    state.lock().fault(message.clone());
    let _ = ready.send(Err(message));
}

fn decode_packet(packet: NativePacket, link_layer: u32) -> CaptureFrame {
    let summary = summarize_packet(&packet.data, link_layer);
    CaptureFrame {
        sequence: 0,
        timestamp_us: packet.timestamp_us,
        captured_length: packet.captured_length,
        original_length: packet.original_length,
        link_layer,
        protocol: summary.protocol,
        source: summary.source,
        destination: summary.destination,
        source_port: summary.source_port,
        destination_port: summary.destination_port,
        info: summary.info,
        payload: packet.data,
    }
}

#[derive(Default)]
struct PacketSummary {
    protocol: String,
    source: String,
    destination: String,
    source_port: u32,
    destination_port: u32,
    info: String,
}

fn summarize_packet(data: &[u8], link_layer: u32) -> PacketSummary {
    let (offset, ether_type) = match link_layer {
        1 if data.len() >= 14 => {
            let mut ether_type = u16::from_be_bytes([data[12], data[13]]);
            let mut offset = 14;
            if matches!(ether_type, 0x8100 | 0x88a8) && data.len() >= 18 {
                ether_type = u16::from_be_bytes([data[16], data[17]]);
                offset = 18;
            }
            (offset, Some(ether_type))
        }
        0 if data.len() >= 4 => (4, None),
        12 | 101 => (0, None),
        113 if data.len() >= 16 => {
            let protocol = u16::from_be_bytes([data[14], data[15]]);
            (16, Some(protocol))
        }
        _ => (0, None),
    };

    if ether_type == Some(0x0806) {
        return PacketSummary {
            protocol: "ARP".to_owned(),
            info: "Address Resolution Protocol".to_owned(),
            ..PacketSummary::default()
        };
    }
    // Version-nibble sniffing applies only to the raw-IP link layers summarized above
    // (DLT 0 NULL, 12/101 RAW), which have no protocol field. Link layers that carry a
    // protocol field — Ethernet (1), LINUX_SLL (113), SLL2 (276), or any unhandled DLT —
    // are left unclassified rather than guessed from header bytes, which would read
    // MAC/protocol fields as IP versions and fabricate addresses.
    let version_nibble = if ether_type.is_none() && matches!(link_layer, 0 | 12 | 101) {
        data.get(offset).map(|byte| byte >> 4)
    } else {
        None
    };
    if ether_type == Some(0x0800) || version_nibble == Some(4) {
        return summarize_ipv4(data, offset);
    }
    if ether_type == Some(0x86dd) || version_nibble == Some(6) {
        return summarize_ipv6(data, offset);
    }
    PacketSummary {
        protocol: "OTHER".to_owned(),
        info: format!("Link-layer frame (DLT {link_layer})"),
        ..PacketSummary::default()
    }
}

fn summarize_ipv4(data: &[u8], offset: usize) -> PacketSummary {
    if data.len() < offset + 20 {
        return truncated_summary("IPv4");
    }
    let header_length = usize::from(data[offset] & 0x0f) * 4;
    if header_length < 20 || data.len() < offset + header_length {
        return truncated_summary("IPv4");
    }
    let source = Ipv4Addr::new(
        data[offset + 12],
        data[offset + 13],
        data[offset + 14],
        data[offset + 15],
    )
    .to_string();
    let destination = Ipv4Addr::new(
        data[offset + 16],
        data[offset + 17],
        data[offset + 18],
        data[offset + 19],
    )
    .to_string();
    let fragment_offset = u16::from_be_bytes([data[offset + 6], data[offset + 7]]) & 0x1fff;
    if fragment_offset != 0 {
        return PacketSummary {
            protocol: "IPv4".to_owned(),
            source,
            destination,
            info: format!("Fragment at byte {}", u32::from(fragment_offset) * 8),
            ..PacketSummary::default()
        };
    }
    summarize_transport(
        data,
        offset + header_length,
        data[offset + 9],
        source,
        destination,
    )
}

fn summarize_ipv6(data: &[u8], offset: usize) -> PacketSummary {
    if data.len() < offset + 40 {
        return truncated_summary("IPv6");
    }
    let mut source_bytes = [0_u8; 16];
    source_bytes.copy_from_slice(&data[offset + 8..offset + 24]);
    let mut destination_bytes = [0_u8; 16];
    destination_bytes.copy_from_slice(&data[offset + 24..offset + 40]);
    let source = Ipv6Addr::from(source_bytes).to_string();
    let destination = Ipv6Addr::from(destination_bytes).to_string();
    let mut next_header = data[offset + 6];
    let mut transport_offset = offset + 40;
    for _ in 0..8 {
        let extension_length = match next_header {
            0 | 43 | 60 => {
                if data.len() < transport_offset + 2 {
                    return truncated_ip_summary("IPv6 extension header", source, destination);
                }
                let following_header = data[transport_offset];
                let length = (usize::from(data[transport_offset + 1]) + 1) * 8;
                next_header = following_header;
                length
            }
            44 => {
                if data.len() < transport_offset + 8 {
                    return truncated_ip_summary("IPv6 fragment header", source, destination);
                }
                let following_header = data[transport_offset];
                let fragment =
                    u16::from_be_bytes([data[transport_offset + 2], data[transport_offset + 3]]);
                if fragment & 0xfff8 != 0 {
                    return PacketSummary {
                        protocol: "IPv6".to_owned(),
                        source,
                        destination,
                        info: format!("Fragment (next header {following_header})"),
                        ..PacketSummary::default()
                    };
                }
                next_header = following_header;
                8
            }
            51 => {
                if data.len() < transport_offset + 2 {
                    return truncated_ip_summary("IPv6 authentication header", source, destination);
                }
                let following_header = data[transport_offset];
                let length = (usize::from(data[transport_offset + 1]) + 2) * 4;
                next_header = following_header;
                length
            }
            59 => {
                return PacketSummary {
                    protocol: "IPv6".to_owned(),
                    source,
                    destination,
                    info: "No next header".to_owned(),
                    ..PacketSummary::default()
                };
            }
            _ => break,
        };
        if data.len() < transport_offset.saturating_add(extension_length) {
            return truncated_ip_summary("IPv6 extension header", source, destination);
        }
        transport_offset = transport_offset.saturating_add(extension_length);
    }
    summarize_transport(data, transport_offset, next_header, source, destination)
}

fn truncated_ip_summary(label: &str, source: String, destination: String) -> PacketSummary {
    PacketSummary {
        protocol: "IPv6".to_owned(),
        source,
        destination,
        info: format!("Truncated {label}"),
        ..PacketSummary::default()
    }
}

fn summarize_transport(
    data: &[u8],
    offset: usize,
    protocol_number: u8,
    source: String,
    destination: String,
) -> PacketSummary {
    let (protocol, minimum_length) = match protocol_number {
        6 => ("TCP", 20),
        17 => ("UDP", 8),
        1 => ("ICMP", 0),
        58 => ("ICMPv6", 0),
        number => {
            return PacketSummary {
                protocol: format!("IP/{number}"),
                source,
                destination,
                info: format!("IP protocol {number}"),
                ..PacketSummary::default()
            };
        }
    };
    if minimum_length == 0 {
        return PacketSummary {
            protocol: protocol.to_owned(),
            source,
            destination,
            info: protocol.to_owned(),
            ..PacketSummary::default()
        };
    }
    if data.len() < offset + minimum_length {
        return PacketSummary {
            protocol: protocol.to_owned(),
            source,
            destination,
            info: format!("Truncated {protocol} header"),
            ..PacketSummary::default()
        };
    }
    let source_port = u32::from(u16::from_be_bytes([data[offset], data[offset + 1]]));
    let destination_port = u32::from(u16::from_be_bytes([data[offset + 2], data[offset + 3]]));
    let info = if protocol == "TCP" {
        let flags = tcp_flags(data[offset + 13]);
        format!("{source_port} → {destination_port}{flags}")
    } else {
        format!("{source_port} → {destination_port}")
    };
    PacketSummary {
        protocol: protocol.to_owned(),
        source,
        destination,
        source_port,
        destination_port,
        info,
    }
}

fn tcp_flags(flags: u8) -> String {
    let labels = [
        (0x02, "SYN"),
        (0x10, "ACK"),
        (0x01, "FIN"),
        (0x04, "RST"),
        (0x08, "PSH"),
        (0x20, "URG"),
    ]
    .into_iter()
    .filter_map(|(mask, label)| (flags & mask != 0).then_some(label))
    .collect::<Vec<_>>();
    if labels.is_empty() {
        String::new()
    } else {
        format!(" [{}]", labels.join(", "))
    }
}

fn truncated_summary(protocol: &str) -> PacketSummary {
    PacketSummary {
        protocol: protocol.to_owned(),
        info: format!("Truncated {protocol} packet"),
        ..PacketSummary::default()
    }
}

fn write_pcap_header(
    writer: &mut impl Write,
    snap_length: u32,
    link_layer: u32,
) -> std::io::Result<()> {
    let mut header = [0_u8; 24];
    header[0..4].copy_from_slice(&0xa1b2_c3d4_u32.to_le_bytes());
    header[4..6].copy_from_slice(&2_u16.to_le_bytes());
    header[6..8].copy_from_slice(&4_u16.to_le_bytes());
    header[16..20].copy_from_slice(&snap_length.to_le_bytes());
    header[20..24].copy_from_slice(&link_layer.to_le_bytes());
    writer.write_all(&header)
}

fn write_pcap_record(writer: &mut impl Write, frame: &CaptureFrame) -> std::io::Result<()> {
    let seconds = u32::try_from(frame.timestamp_us / 1_000_000).unwrap_or(u32::MAX);
    let microseconds = u32::try_from(frame.timestamp_us % 1_000_000).unwrap_or_default();
    let captured_length = u32::try_from(frame.payload.len()).unwrap_or(u32::MAX);
    let mut header = [0_u8; 16];
    header[0..4].copy_from_slice(&seconds.to_le_bytes());
    header[4..8].copy_from_slice(&microseconds.to_le_bytes());
    header[8..12].copy_from_slice(&captured_length.to_le_bytes());
    header[12..16].copy_from_slice(&frame.original_length.to_le_bytes());
    writer.write_all(&header)?;
    writer.write_all(&frame.payload)
}

fn pcap_record_size(frame: &CaptureFrame) -> u64 {
    16_u64.saturating_add(u64::try_from(frame.payload.len()).unwrap_or(u64::MAX))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ethernet_ipv4_tcp_packet() -> Vec<u8> {
        let mut packet = vec![0_u8; 14 + 20 + 20];
        packet[12..14].copy_from_slice(&0x0800_u16.to_be_bytes());
        packet[14] = 0x45;
        packet[23] = 6;
        packet[26..30].copy_from_slice(&[192, 168, 1, 10]);
        packet[30..34].copy_from_slice(&[1, 1, 1, 1]);
        packet[34..36].copy_from_slice(&52_000_u16.to_be_bytes());
        packet[36..38].copy_from_slice(&443_u16.to_be_bytes());
        packet[47] = 0x12;
        packet
    }

    fn ethernet_ipv6_hop_by_hop_udp_packet() -> Vec<u8> {
        let mut packet = vec![0_u8; 14 + 40 + 8 + 8];
        packet[12..14].copy_from_slice(&0x86dd_u16.to_be_bytes());
        packet[14] = 0x60;
        packet[20] = 0;
        packet[22..38].copy_from_slice(&Ipv6Addr::LOCALHOST.octets());
        packet[38..54].copy_from_slice(&Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1).octets());
        packet[54] = 17;
        packet[55] = 0;
        packet[62..64].copy_from_slice(&53_000_u16.to_be_bytes());
        packet[64..66].copy_from_slice(&53_u16.to_be_bytes());
        packet
    }

    fn test_frame(sequence: u64, payload: Vec<u8>) -> CaptureFrame {
        let length = u32::try_from(payload.len()).unwrap();
        CaptureFrame {
            sequence,
            timestamp_us: sequence.saturating_mul(1_000_000),
            captured_length: length,
            original_length: length,
            link_layer: 1,
            protocol: String::new(),
            source: String::new(),
            destination: String::new(),
            source_port: 0,
            destination_port: 0,
            info: String::new(),
            payload,
        }
    }

    #[test]
    fn queue_bounds_drop_oldest() {
        let mut state = SessionState::new();
        state.live_max_frames = 2;
        for sequence in 1..=5 {
            let frame = test_frame(sequence, vec![1, 2, 3]);
            let stored_bytes = pcap_record_size(&frame);
            state.push_frame(frame, stored_bytes);
        }
        assert_eq!(state.live_frames.len(), 2);
        assert_eq!(state.live_frames.front().unwrap().sequence, 4);
        assert_eq!(state.bytes, 95);
    }

    #[test]
    fn requeued_frames_come_back_first_and_in_order() {
        let mut state = SessionState::new();
        for sequence in 1..=4 {
            let frame = test_frame(sequence, vec![1, 2, 3]);
            let stored_bytes = pcap_record_size(&frame);
            state.push_frame(frame, stored_bytes);
        }
        let taken: Vec<_> = state.live_frames.drain(..2).collect();
        state.live_bytes = state.live_frames.iter().map(|f| f.payload.len()).sum();

        state.requeue_frames(taken);

        let order: Vec<_> = state.live_frames.iter().map(|f| f.sequence).collect();
        assert_eq!(order, vec![1, 2, 3, 4]);
        assert_eq!(state.live_bytes, 12);

        state.live_max_frames = 3;
        state.requeue_frames(vec![test_frame(0, vec![9])]);
        let order: Vec<_> = state.live_frames.iter().map(|f| f.sequence).collect();
        assert_eq!(
            order,
            vec![2, 3, 4],
            "over the bound, the oldest are dropped"
        );
    }

    #[test]
    fn live_payload_is_truncated_to_the_stream_limit() {
        let mut state = SessionState::new();
        state.live_max_payload = 4;
        let frame = test_frame(1, vec![0_u8; 12]);
        let stored_bytes = pcap_record_size(&frame);
        state.push_frame(frame, stored_bytes);
        assert_eq!(state.live_frames[0].payload.len(), 4);
    }

    #[test]
    fn ethernet_tcp_packet_is_summarized() {
        let summary = summarize_packet(&ethernet_ipv4_tcp_packet(), 1);
        assert_eq!(summary.protocol, "TCP");
        assert_eq!(summary.source, "192.168.1.10");
        assert_eq!(summary.destination, "1.1.1.1");
        assert_eq!(summary.source_port, 52_000);
        assert_eq!(summary.destination_port, 443);
        assert!(summary.info.contains("SYN"));
        assert!(summary.info.contains("ACK"));
    }

    #[test]
    fn ipv6_extension_headers_are_followed_to_udp() {
        let summary = summarize_packet(&ethernet_ipv6_hop_by_hop_udp_packet(), 1);
        assert_eq!(summary.protocol, "UDP");
        assert_eq!(summary.source, "::1");
        assert_eq!(summary.destination, "2001:db8::1");
        assert_eq!(summary.source_port, 53_000);
        assert_eq!(summary.destination_port, 53);
    }

    #[test]
    fn ethernet_unknown_ethertype_is_not_version_sniffed() {
        let mut packet = ethernet_ipv4_tcp_packet();
        packet[12..14].copy_from_slice(&0x88b5_u16.to_be_bytes());
        let summary = summarize_packet(&packet, 1);
        assert_eq!(summary.protocol, "OTHER");
        assert!(summary.info.contains("DLT 1"));
    }

    #[test]
    fn raw_ipv4_frame_is_version_sniffed() {
        let packet = ethernet_ipv4_tcp_packet()[14..].to_vec();
        let summary = summarize_packet(&packet, 101);
        assert_eq!(summary.protocol, "TCP");
        assert_eq!(summary.source, "192.168.1.10");
    }

    #[test]
    fn truncated_ethernet_frame_is_left_unclassified() {
        let mut packet = ethernet_ipv4_tcp_packet()[..12].to_vec();
        packet[0] = 0x45;
        let summary = summarize_packet(&packet, 1);
        assert_eq!(summary.protocol, "OTHER");
    }

    #[test]
    fn unhandled_link_layer_is_left_unclassified() {
        let packet = ethernet_ipv4_tcp_packet()[14..].to_vec();
        let summary = summarize_packet(&packet, 276);
        assert_eq!(summary.protocol, "OTHER");
        assert!(summary.info.contains("DLT 276"));
    }

    #[test]
    fn pcap_encoder_writes_header_and_records() {
        let mut encoded = Vec::new();
        write_pcap_header(&mut encoded, 65_535, 1).unwrap();
        write_pcap_record(&mut encoded, &test_frame(1, vec![1, 2, 3, 4])).unwrap();
        assert_eq!(&encoded[..4], &0xa1b2_c3d4_u32.to_le_bytes());
        assert_eq!(encoded.len(), 24 + 16 + 4);
        assert_eq!(&encoded[40..], &[1, 2, 3, 4]);
    }

    #[test]
    fn capture_storage_is_always_bounded() {
        assert_eq!(bounded_max_bytes(0), DEFAULT_CAPTURE_MAX_BYTES);
        assert_eq!(bounded_max_bytes(10), 10);
        assert_eq!(bounded_max_bytes(u64::MAX), HARD_CAPTURE_MAX_BYTES);
    }

    #[test]
    fn leftover_archives_are_removed_and_other_files_kept() {
        let dir = tempfile::tempdir().expect("tempdir");
        let leftover = dir
            .path()
            .join(format!("{ARCHIVE_PREFIX}abc{ARCHIVE_SUFFIX}"));
        let unrelated = dir.path().join("notes.txt");
        std::fs::write(&leftover, b"packets").expect("leftover");
        std::fs::write(&unrelated, b"keep").expect("unrelated");

        remove_orphaned_archives(dir.path());

        assert!(!leftover.exists());
        assert!(unrelated.exists());
    }

    /// The regression this guards: after a start timed out, the next start
    /// joined the stuck worker and blocked with the session locked.
    #[test]
    fn a_stuck_worker_makes_start_busy_instead_of_blocking() {
        let release = Arc::new(AtomicBool::new(false));
        let stuck = Arc::clone(&release);
        let session = CaptureSession::new();
        *session.worker.lock() = Some(thread::spawn(move || {
            while !stuck.load(Ordering::Acquire) {
                thread::sleep(Duration::from_millis(5));
            }
        }));
        session.state.lock().status = CaptureStatus::Faulted;

        let started = Instant::now();
        let result = session.start(CaptureOptions {
            device_name: "none".to_owned(),
            capture_filter: String::new(),
            snap_length: 96,
            promiscuous: false,
            read_timeout_ms: 100,
            max_seconds: 1,
            max_bytes: 1024,
            app_filter: None,
        });

        assert!(matches!(result, Err(CaptureError::AlreadyActive)));
        assert!(started.elapsed() < WORKER_EXIT_GRACE * 2);
        release.store(true, Ordering::Release);
    }

    /// A session in the middle of a capture, without a worker or interface.
    fn running_session() -> CaptureSession {
        let session = CaptureSession::new();
        session.state.lock().generation = 1;
        session
            .state
            .lock()
            .transition(CaptureStatus::Running, "running");
        session
    }

    fn push(session: &CaptureSession, sequence: u64) {
        let frame = test_frame(sequence, vec![1, 2, 3]);
        let stored_bytes = pcap_record_size(&frame);
        session.state.lock().push_frame(frame, stored_bytes);
    }

    #[tokio::test]
    async fn the_reader_wakes_for_frames_and_ends_with_the_capture() {
        let session = running_session();
        let reader = session.frame_reader();

        let waiting = tokio::spawn(async move {
            let first = reader.next_frames().await;
            (reader, first)
        });
        tokio::task::yield_now().await;
        push(&session, 1);
        let (reader, first) = tokio::time::timeout(Duration::from_secs(1), waiting)
            .await
            .expect("woken by the frame")
            .expect("reader task");
        assert_eq!(first.map(|frames| frames.len()), Some(1));

        push(&session, 2);
        session
            .state
            .lock()
            .transition(CaptureStatus::Stopped, "stopped");
        assert_eq!(
            reader.next_frames().await.map(|frames| frames.len()),
            Some(1),
            "frames left when the capture ends are still read"
        );
        assert!(
            tokio::time::timeout(Duration::from_secs(1), reader.next_frames())
                .await
                .expect("an ended capture does not wait")
                .is_none()
        );
    }

    #[tokio::test]
    async fn a_newer_reader_takes_over_and_receives_what_the_old_one_gave_back() {
        let session = running_session();
        let old = session.frame_reader();
        push(&session, 1);
        let taken = old.take_frames().expect("current reader");

        let new = session.frame_reader();
        assert!(old.take_frames().is_none(), "the old reader is replaced");
        assert!(
            tokio::time::timeout(Duration::from_secs(1), old.next_frames())
                .await
                .expect("a replaced reader does not wait")
                .is_none()
        );
        old.give_back(taken);
        let order: Vec<_> = new
            .take_frames()
            .expect("new reader")
            .iter()
            .map(|frame| frame.sequence)
            .collect();
        assert_eq!(order, vec![1]);
    }

    #[test]
    fn frames_from_an_older_capture_are_not_given_back_to_a_newer_one() {
        let session = running_session();
        let reader = session.frame_reader();
        push(&session, 1);
        let taken = reader.take_frames().expect("current reader");
        session.state.lock().generation = 2;

        reader.give_back(taken);

        assert!(session.state.lock().live_frames.is_empty());
    }

    #[tokio::test]
    async fn stopping_is_published_to_status_subscribers() {
        let session = running_session();
        let mut changes = session.status_changes();
        changes.mark_unchanged();

        session.stop().expect("stop");

        tokio::time::timeout(Duration::from_secs(1), changes.changed())
            .await
            .expect("notified")
            .expect("sender alive");
        assert_eq!(*changes.borrow(), CaptureStatus::Stopping);
    }
}
