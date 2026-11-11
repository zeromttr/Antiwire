//! Session-end notifications for interactive (non-service) Windows daemons.
//!
//! Console control handlers alone do not receive `CTRL_LOGOFF` /
//! `CTRL_SHUTDOWN` once the process loads `user32.dll` / `gdi32.dll` (or Shell
//! APIs that pull them in). Microsoft's guidance for that case is a top-level
//! hidden window that handles `WM_QUERYENDSESSION` / `WM_ENDSESSION`.
//!
//! While host-state restore runs we call [`ShutdownBlockReasonCreate`] so the
//! system surfaces a reason and delays force-killing the process until
//! the watcher is dropped after teardown.
//!
//! # Safety model
//!
//! Every `unsafe` block here is a thin FFI call into Win32. Invariants are:
//! - HWND values are stored as plain integers (`isize`) so sharing them across
//!   threads needs no `unsafe impl Send`/`Sync`.
//! - The window procedure only runs on the thread that created the window.
//! - `class_storage` outlives `RegisterClassExW` / `CreateWindowExW`.
//! - Block-reason create/destroy always use the HWND we created.

#![allow(unsafe_code)]

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use anyhow::{anyhow, Context};
use tokio::sync::watch;
use tracing::{error, info, warn};
use windows::core::{w, PCWSTR};
use windows::Win32::Foundation::{HINSTANCE, HWND, LPARAM, LRESULT, WPARAM};
use windows::Win32::Graphics::Gdi::HBRUSH;
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
use windows::Win32::System::Shutdown::{ShutdownBlockReasonCreate, ShutdownBlockReasonDestroy};
use windows::Win32::System::Threading::SetProcessShutdownParameters;
use windows::Win32::System::WindowsProgramming::SHUTDOWN_NORETRY;
use windows::Win32::UI::WindowsAndMessaging::{
    CreateWindowExW, DefWindowProcW, DestroyWindow, DispatchMessageW, GetMessageW, PostMessageW,
    PostQuitMessage, RegisterClassExW, TranslateMessage, CW_USEDEFAULT, HCURSOR, HICON, MSG,
    WM_CLOSE, WM_DESTROY, WM_ENDSESSION, WM_QUERYENDSESSION, WNDCLASSEXW, WS_OVERLAPPED,
};

/// Shown in the Windows shutdown UI while adapter DNS and firewall rules revert.
const SHUTDOWN_BLOCK_REASON: PCWSTR = w!("Antiwire is restoring network and firewall settings");

/// Bit-pattern of an `HWND`. Storing the integer form keeps `Shared: Send + Sync`
/// without an `unsafe impl` (the `windows` crate's `HWND` is a raw pointer).
type HwndBits = isize;

#[inline]
fn hwnd_bits(hwnd: HWND) -> HwndBits {
    hwnd.0 as HwndBits
}

#[inline]
fn hwnd_from_bits(bits: HwndBits) -> HWND {
    HWND(bits as *mut core::ffi::c_void)
}

struct Shared {
    end_tx: watch::Sender<bool>,
    /// Our top-level window, if created. Integer bits only — see [`HwndBits`].
    hwnd: Mutex<Option<HwndBits>>,
    blocking: AtomicBool,
    /// Set when [`SessionEndWatcher::start`] gave up waiting for the thread.
    /// A window created after that is destroyed at once instead of pumped.
    cancelled: AtomicBool,
}

/// How long [`SessionEndWatcher::start`] waits for the window, and then, if
/// it gave up, for the abandoned thread to stop.
const STARTUP_TIMEOUT: Duration = if cfg!(test) {
    Duration::from_millis(200)
} else {
    Duration::from_secs(5)
};

/// Owns the session-end message thread and the optional shutdown block reason.
pub struct SessionEndWatcher {
    shared: Arc<Shared>,
    /// The window thread. Never joined: dropping the watcher posts
    /// `WM_CLOSE`, and the thread ends once its window is destroyed.
    _thread: JoinHandle<()>,
}

impl SessionEndWatcher {
    /// Spawns a hidden top-level window and message pump.
    ///
    /// Returns `None` when the window cannot be created; the daemon still runs
    /// with console control handlers only.
    pub fn start() -> Option<Self> {
        let (end_tx, _end_rx) = watch::channel(false);
        let shared = Arc::new(Shared {
            end_tx,
            hwnd: Mutex::new(None),
            blocking: AtomicBool::new(false),
            cancelled: AtomicBool::new(false),
        });

        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        let (finished_tx, finished_rx) = std::sync::mpsc::channel::<()>();
        let thread_shared = Arc::clone(&shared);

        let thread = thread::Builder::new()
            .name("antiwire-session-end".into())
            .spawn(move || {
                // Dropped when the thread returns, however it returns.
                let _finished = finished_tx;
                if let Err(error) = run_window_thread(thread_shared, ready_tx) {
                    error!(error = %format!("{error:#}"), "session-end window thread failed");
                }
            })
            .map_err(|error| {
                error!(%error, "failed to spawn session-end window thread");
                error
            })
            .ok()?;

        match ready_rx.recv_timeout(STARTUP_TIMEOUT) {
            Ok(Ok(())) => {
                info!("session-end window ready (WM_QUERYENDSESSION)");
                Some(Self {
                    shared,
                    _thread: thread,
                })
            }
            Ok(Err(error)) => {
                error!(error = %format!("{error:#}"), "failed to create session-end window");
                None
            }
            Err(_) => {
                error!("session-end window thread timed out during startup; stopping it");
                abandon_window_thread(&shared, thread, &finished_rx);
                // A failure the thread reported after this stopped waiting.
                if let Ok(Err(error)) = ready_rx.try_recv() {
                    error!(error = %format!("{error:#}"), "session-end window thread failed");
                }
                None
            }
        }
    }

    /// Receiver that becomes `true` when Windows is ending the session.
    pub fn subscribe(&self) -> watch::Receiver<bool> {
        self.shared.end_tx.subscribe()
    }
}

impl Drop for SessionEndWatcher {
    fn drop(&mut self) {
        release_block(&self.shared);
        let bits = self
            .shared
            .hwnd
            .lock()
            .ok()
            .and_then(|mut guard| guard.take());
        if let Some(bits) = bits {
            post_close(bits);
        }
    }
}

/// Asks the window `bits` names to close. Its thread ends once the window
/// is destroyed.
fn post_close(bits: HwndBits) {
    // SAFETY: `bits` is the window this process created; `PostMessageW` is
    // valid from any thread for a window in this process.
    if let Err(error) =
        unsafe { PostMessageW(Some(hwnd_from_bits(bits)), WM_CLOSE, WPARAM(0), LPARAM(0)) }
    {
        warn!(%error, "failed to post WM_CLOSE to the session-end window");
    }
}

/// Stops a window thread [`SessionEndWatcher::start`] stopped waiting for.
///
/// Returning `None` alone would leave it running: once its window exists it
/// pumps messages, and `WM_QUERYENDSESSION` would take a shutdown block
/// reason that nobody clears, delaying logoff, while the daemon, which never
/// subscribed, is not listening. So the thread is told to stop, its window
/// closed if it has one, and the thread waited for again. However that ends,
/// the shared state is withdrawn from the window procedure, so no window of
/// this thread can block shutdown afterwards.
fn abandon_window_thread(
    shared: &Arc<Shared>,
    thread: JoinHandle<()>,
    finished: &std::sync::mpsc::Receiver<()>,
) {
    // The thread checks this under the `ACTIVE` lock before publishing, so
    // once `withdraw` has run it cannot install itself again.
    shared.cancelled.store(true, Ordering::SeqCst);
    withdraw(shared);
    let published = shared.hwnd.lock().ok().and_then(|guard| *guard);
    if let Some(bits) = published {
        post_close(bits);
    }
    match finished.recv_timeout(STARTUP_TIMEOUT) {
        Ok(()) | Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
            if thread.join().is_err() {
                error!("session-end window thread panicked");
            }
        }
        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
            error!("abandoned session-end window thread did not stop; detaching it");
        }
    }
    release_block(shared);
}

/// Removes `shared` from the window procedure's view, if it is installed.
fn withdraw(shared: &Arc<Shared>) {
    let mut slot = ACTIVE
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if slot
        .as_ref()
        .is_some_and(|active| Arc::ptr_eq(active, shared))
    {
        *slot = None;
    }
}

fn release_block(shared: &Shared) {
    if !shared.blocking.swap(false, Ordering::SeqCst) {
        return;
    }
    let Some(bits) = shared.hwnd.lock().ok().and_then(|guard| *guard) else {
        return;
    };
    let hwnd = hwnd_from_bits(bits);
    // SAFETY: `hwnd` is the window we passed to `ShutdownBlockReasonCreate`.
    match unsafe { ShutdownBlockReasonDestroy(hwnd) } {
        Ok(()) => info!("released Windows shutdown block reason"),
        Err(error) => warn!(%error, "ShutdownBlockReasonDestroy failed"),
    }
}

/// Tells the daemon the session is ending.
///
/// `send_replace`, not `send`: `send` stores nothing while no receiver
/// exists, and the daemon subscribes only after the window is already
/// pumping messages. A session end in between must still reach it.
fn signal_session_end(shared: &Shared) {
    shared.end_tx.send_replace(true);
}

fn begin_block(shared: &Shared, hwnd: HWND) {
    if shared.blocking.swap(true, Ordering::SeqCst) {
        return;
    }
    // SAFETY: `hwnd` is our top-level window; `SHUTDOWN_BLOCK_REASON` is a
    // static NUL-terminated wide string from `w!`.
    match unsafe { ShutdownBlockReasonCreate(hwnd, SHUTDOWN_BLOCK_REASON) } {
        Ok(()) => {
            info!("blocking Windows shutdown until host state is restored");
        }
        Err(error) => {
            warn!(%error, "ShutdownBlockReasonCreate failed");
            shared.blocking.store(false, Ordering::SeqCst);
        }
    }
}

fn run_window_thread(
    shared: Arc<Shared>,
    ready_tx: std::sync::mpsc::Sender<anyhow::Result<()>>,
) -> anyhow::Result<()> {
    // Install the shared state before creating the window so the wndproc can
    // observe it on the first session-end message.
    {
        let mut slot = ACTIVE
            .lock()
            .map_err(|_| anyhow!("session-end state lock poisoned"))?;
        // Checked under the lock `abandon_window_thread` withdraws under.
        if shared.cancelled.load(Ordering::SeqCst) {
            return Ok(());
        }
        *slot = Some(Arc::clone(&shared));
    }

    let result = (|| {
        // Ask to be notified early in the process shutdown pass (high level =
        // shut down first) while the network stack is still up. SHUTDOWN_NORETRY
        // avoids the hung-app dialog that would otherwise delay or skip us.
        // SAFETY: process-wide shutdown parameters; no handles.
        if let Err(error) = unsafe { SetProcessShutdownParameters(0x3FF, SHUTDOWN_NORETRY) } {
            warn!(%error, "SetProcessShutdownParameters failed");
        }

        // SAFETY: `None` means the calling process's executable module; the
        // returned handle is a pseudo-handle and must not be closed.
        let module = unsafe { GetModuleHandleW(None).context("GetModuleHandleW")? };
        let hinstance = HINSTANCE::from(module);

        // Kept alive for both RegisterClassExW and CreateWindowExW below.
        let class_storage: Vec<u16> = format!("AntiwireDaemonSession.{}", std::process::id())
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        let class_name = PCWSTR(class_storage.as_ptr());

        let cb_size = u32::try_from(std::mem::size_of::<WNDCLASSEXW>()).unwrap_or(u32::MAX);
        let wnd_class = WNDCLASSEXW {
            cbSize: cb_size,
            style: Default::default(),
            lpfnWndProc: Some(session_wnd_proc),
            cbClsExtra: 0,
            cbWndExtra: 0,
            hInstance: hinstance,
            hIcon: HICON::default(),
            hCursor: HCURSOR::default(),
            hbrBackground: HBRUSH::default(),
            lpszMenuName: PCWSTR::null(),
            lpszClassName: class_name,
            hIconSm: HICON::default(),
        };

        // SAFETY: `wnd_class` and `class_storage` are valid for this call;
        // `session_wnd_proc` matches `WNDPROC`.
        let atom = unsafe { RegisterClassExW(&wnd_class) };
        if atom == 0 {
            return Err(std::io::Error::last_os_error()).context("RegisterClassExW");
        }

        // Top-level hidden window (not HWND_MESSAGE): message-only windows do
        // not receive broadcast session notifications. Avoid WS_EX_TOOLWINDOW —
        // some Windows builds under-notify tool windows during system shutdown.
        // SAFETY: class is registered; `class_storage` still live; no parent/menu.
        let hwnd = unsafe {
            CreateWindowExW(
                Default::default(),
                class_name,
                w!("Antiwire Daemon"),
                WS_OVERLAPPED,
                CW_USEDEFAULT,
                0,
                0,
                0,
                None,
                None,
                Some(hinstance),
                None,
            )
            .context("CreateWindowExW")?
        };

        if let Ok(mut guard) = shared.hwnd.lock() {
            *guard = Some(hwnd_bits(hwnd));
        }
        // Published first, so `start` either sees the window and closes it or
        // its cancellation is seen here.
        if shared.cancelled.load(Ordering::SeqCst) {
            // SAFETY: destroys only the window this thread just created.
            let _ = unsafe { DestroyWindow(hwnd) };
            return Ok(());
        }

        let _ = ready_tx.send(Ok(()));

        let mut msg = MSG::default();
        loop {
            // SAFETY: `msg` is a valid out-buffer owned by this thread.
            let status = unsafe { GetMessageW(&mut msg, None, 0, 0) };
            match status.0 {
                0 => break,
                -1 => {
                    return Err(std::io::Error::last_os_error()).context("GetMessageW");
                }
                _ => {
                    // SAFETY: pump only dispatches messages for windows on this thread.
                    unsafe {
                        let _ = TranslateMessage(&msg);
                        DispatchMessageW(&msg);
                    }
                }
            }
        }

        Ok(())
    })();

    if let Ok(mut slot) = ACTIVE.lock() {
        *slot = None;
    }
    if let Ok(mut guard) = shared.hwnd.lock() {
        *guard = None;
    }

    // `start` reports the failure while it is still waiting for the window;
    // once it has stopped listening, the error comes back for this thread
    // to log.
    result.or_else(|error| {
        ready_tx
            .send(Err(error))
            .or_else(|std::sync::mpsc::SendError(unsent)| unsent)
    })
}

static ACTIVE: Mutex<Option<Arc<Shared>>> = Mutex::new(None);

/// The session is ending: take the shutdown block reason and tell the
/// daemon. The shutdown future restores on a blocking worker, so the
/// message pump stays responsive while the block reason is held.
fn note_session_ending(hwnd: HWND) {
    if let Ok(guard) = ACTIVE.lock() {
        if let Some(shared) = guard.as_ref() {
            begin_block(shared, hwnd);
            signal_session_end(shared);
        }
    }
}

/// Window procedure for the hidden session-end window.
///
/// Marked `unsafe` because it is an FFI callback. The body only uses `unsafe`
/// for further Win32 calls; lock/signal work is safe Rust.
///
/// # Safety
///
/// Invoked by the system on the window's owning thread with a valid `hwnd` for
/// this class.
unsafe extern "system" fn session_wnd_proc(
    hwnd: HWND,
    msg: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    match msg {
        WM_QUERYENDSESSION => {
            note_session_ending(hwnd);
            // TRUE: allow shutdown to continue; the block reason delays kill.
            LRESULT(1)
        }
        WM_ENDSESSION => {
            if wparam.0 != 0 {
                // Also when QUERYENDSESSION was skipped. Restoration is owned
                // by the shutdown future, so repeated messages cannot race it.
                note_session_ending(hwnd);
            } else if let Ok(guard) = ACTIVE.lock() {
                // Shutdown cancelled after QUERYENDSESSION.
                if let Some(shared) = guard.as_ref() {
                    release_block(shared);
                }
            }
            LRESULT(0)
        }
        WM_CLOSE => {
            // SAFETY: destroys only this window, on its owning thread.
            let _ = unsafe { DestroyWindow(hwnd) };
            LRESULT(0)
        }
        WM_DESTROY => {
            // SAFETY: ends the GetMessage loop on this thread only.
            unsafe { PostQuitMessage(0) };
            LRESULT(0)
        }
        _ => {
            // SAFETY: required for unhandled messages on a registered class.
            unsafe { DefWindowProcW(hwnd, msg, wparam, lparam) }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `ACTIVE` is process-wide; these tests take turns with it.
    static SERIAL: Mutex<()> = Mutex::new(());

    fn shared() -> Arc<Shared> {
        Arc::new(Shared {
            end_tx: watch::channel(false).0,
            hwnd: Mutex::new(None),
            blocking: AtomicBool::new(false),
            cancelled: AtomicBool::new(false),
        })
    }

    fn active_is(shared: &Arc<Shared>) -> bool {
        ACTIVE
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_ref()
            .is_some_and(|active| Arc::ptr_eq(active, shared))
    }

    /// Stands in for a window thread that published itself and stops once
    /// it sees the cancellation.
    fn published_thread(
        shared: &Arc<Shared>,
        honours_cancel: bool,
    ) -> (JoinHandle<()>, std::sync::mpsc::Receiver<()>) {
        *ACTIVE.lock().expect("active") = Some(Arc::clone(shared));
        let (finished_tx, finished_rx) = std::sync::mpsc::channel::<()>();
        let worker = Arc::clone(shared);
        let thread = thread::spawn(move || {
            let _finished = finished_tx;
            let started = std::time::Instant::now();
            while !(honours_cancel && worker.cancelled.load(Ordering::SeqCst)) {
                if started.elapsed() > STARTUP_TIMEOUT * 10 {
                    return;
                }
                thread::sleep(Duration::from_millis(5));
            }
        });
        (thread, finished_rx)
    }

    /// The regression this guards: the watcher's only receiver was dropped
    /// before the daemon subscribed, and `send` stores nothing while no
    /// receiver exists. A session end in that gap was lost, although its
    /// shutdown block reason had been taken, and the daemon never stopped.
    #[test]
    fn a_session_end_before_anyone_subscribes_is_kept() {
        let shared = shared();
        assert_eq!(shared.end_tx.receiver_count(), 0);

        signal_session_end(&shared);

        assert!(
            *shared.end_tx.subscribe().borrow(),
            "a later subscriber sees the session ending"
        );
    }

    /// The regression this guards: a startup timeout dropped the handle and
    /// left the thread installed, free to take a shutdown block reason.
    #[test]
    fn abandoning_a_late_thread_withdraws_it_and_waits_for_it() {
        let _serial = SERIAL
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let shared = shared();
        let (thread, finished) = published_thread(&shared, true);

        abandon_window_thread(&shared, thread, &finished);

        assert!(shared.cancelled.load(Ordering::SeqCst));
        assert!(!active_is(&shared));
        assert!(
            matches!(
                finished.try_recv(),
                Err(std::sync::mpsc::TryRecvError::Disconnected)
            ),
            "the thread was joined"
        );
    }

    #[test]
    fn a_thread_that_never_stops_is_still_withdrawn_within_the_bound() {
        let _serial = SERIAL
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let shared = shared();
        let (thread, finished) = published_thread(&shared, false);

        let started = std::time::Instant::now();
        abandon_window_thread(&shared, thread, &finished);

        assert!(started.elapsed() < STARTUP_TIMEOUT * 5);
        assert!(!active_is(&shared));
    }

    /// A thread that starts after `start` gave up must not install itself.
    #[test]
    fn a_cancelled_thread_does_not_publish_itself() {
        let _serial = SERIAL
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let shared = shared();
        shared.cancelled.store(true, Ordering::SeqCst);
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();

        assert!(run_window_thread(Arc::clone(&shared), ready_tx).is_ok());

        assert!(!active_is(&shared));
        assert!(shared.hwnd.lock().expect("hwnd").is_none());
        assert!(ready_rx.try_recv().is_err(), "no window was reported ready");
    }
}
