//! How the daemon learns it should stop: Unix signals, Windows console
//! control events and the session-end window, and the Windows service's
//! stop control.

use tokio::signal;
use tracing::info;

/// A signal handler, or `None`, logged, when it could not be installed.
fn installed<T>(name: &'static str, result: std::io::Result<T>) -> Option<T> {
    match result {
        Ok(handler) => Some(handler),
        Err(error) => {
            tracing::error!(error = %error, signal = name, "could not install a stop signal handler");
            None
        }
    }
}

/// Resolves when the process is asked to stop: SIGTERM, which is how init
/// systems ask, also on the way to a reboot; SIGINT (Ctrl-C); or SIGHUP,
/// when the terminal it runs in closes.
///
/// All three are installed when this is first polled, which the daemon does
/// as it begins to start. A handler that cannot be installed is logged and
/// the others still stop the daemon. Without any, it resolves at once:
/// stopping cleanly is a better answer than running with no way to stop,
/// since an unhandled signal kills the process with DNS still redirected.
#[cfg(not(windows))]
pub(crate) async fn interactive_shutdown_requested() {
    use signal::unix::{signal as unix_signal, Signal, SignalKind};

    /// Awaits one signal, or never resolves when it could not be installed.
    async fn received(handler: &mut Option<Signal>) {
        match handler {
            Some(handler) => {
                handler.recv().await;
            }
            None => std::future::pending().await,
        }
    }

    let mut terminate = installed("SIGTERM", unix_signal(SignalKind::terminate()));
    let mut interrupt = installed("SIGINT", unix_signal(SignalKind::interrupt()));
    let mut hangup = installed("SIGHUP", unix_signal(SignalKind::hangup()));
    if terminate.is_none() && interrupt.is_none() && hangup.is_none() {
        tracing::error!("no stop signal handler could be installed; shutting down");
        return;
    }

    let signal = tokio::select! {
        () = received(&mut terminate) => "SIGTERM",
        () = received(&mut interrupt) => "SIGINT",
        () = received(&mut hangup) => "SIGHUP",
    };
    info!(signal, "termination signal received");
}

/// Resolves when Windows asks this process to go away.
///
/// - **Console** (`--foreground`, or detach failed): `CTRL_C` / `CTRL_BREAK` /
///   `CTRL_CLOSE`. Returning from those handlers would terminate immediately;
///   Tokio parks until this future consumes the event.
/// - **Session end** (default detached path, and any process with the session
///   window): `WM_QUERYENDSESSION` via [`super::windows::session::SessionEndWatcher`].
///
/// `CTRL_LOGOFF` / `CTRL_SHUTDOWN` are intentionally not watched: with `user32`
/// loaded (session window) Windows does not deliver them to console handlers,
/// and interactive apps are not present for service-style `CTRL_SHUTDOWN`.
#[cfg(windows)]
pub(crate) async fn interactive_shutdown_requested(
    session_end: Option<tokio::sync::watch::Receiver<bool>>,
) {
    /// Awaits one control event, or never resolves when it could not be registered.
    macro_rules! event {
        ($source:expr) => {
            async {
                match $source.as_mut() {
                    Some(source) => {
                        source.recv().await;
                    }
                    None => std::future::pending().await,
                }
            }
        };
    }

    let mut ctrl_c = installed("ctrl-c", signal::windows::ctrl_c());
    let mut ctrl_break = installed("ctrl-break", signal::windows::ctrl_break());
    let mut ctrl_close = installed("ctrl-close", signal::windows::ctrl_close());

    if ctrl_c.is_none() && ctrl_break.is_none() && ctrl_close.is_none() && session_end.is_none() {
        tracing::error!("no console control handler or session-end watcher; shutting down");
        return;
    }

    let signal = tokio::select! {
        () = event!(ctrl_c) => "ctrl-c",
        () = event!(ctrl_break) => "ctrl-break",
        () = event!(ctrl_close) => "ctrl-close",
        () = async {
            match session_end {
                Some(rx) => service_stop_requested(rx).await,
                None => std::future::pending().await,
            }
        } => "session-end",
    };

    info!(signal, "interactive shutdown signal received");
}

/// Resolves once `shutdown_rx` reads `true`, or its sender is gone. Used for the
/// SCM stop request and for the interactive session-end watcher.
///
/// A `watch` channel rather than [`std::sync::mpsc`]: this is awaited from async
/// context, and `mpsc::Receiver::recv` blocks the thread it is polled on. Blocking
/// inside a `tokio::select!` branch parks the `block_on` thread, and because
/// `block_on` only drives its future on the calling thread, the daemon future then
/// stops being polled entirely — the service reports `Running` while doing nothing.
#[cfg(windows)]
pub(crate) async fn service_stop_requested(mut shutdown_rx: tokio::sync::watch::Receiver<bool>) {
    while !*shutdown_rx.borrow_and_update() {
        // A closed channel means the control handler is gone; stopping is the only
        // safe reading of that.
        if shutdown_rx.changed().await.is_err() {
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The regressions this guards: SIGHUP, which closing the daemon's
    /// terminal sends, killed it outright, and no signal had a handler until
    /// the daemon finished starting. Once the shutdown future has been
    /// polled, a signal stops it cleanly.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_hangup_after_the_first_poll_stops_the_daemon() {
        let mut shutdown = std::pin::pin!(interactive_shutdown_requested());
        let first_poll = futures_poll_once(shutdown.as_mut()).await;
        assert!(!first_poll, "the handlers were installed");

        // SAFETY: raising a signal this process now handles.
        #[allow(unsafe_code)]
        let raised = unsafe { libc::raise(libc::SIGHUP) };
        assert_eq!(raised, 0);

        tokio::time::timeout(std::time::Duration::from_secs(5), shutdown)
            .await
            .expect("SIGHUP stops the daemon");
    }

    /// Polls `future` once; whether it finished.
    #[cfg(unix)]
    async fn futures_poll_once(
        future: std::pin::Pin<&mut impl std::future::Future<Output = ()>>,
    ) -> bool {
        tokio::select! {
            biased;
            () = future => true,
            () = std::future::ready(()) => false,
        }
    }

    /// The service stop signal must not block the thread it is polled on.
    ///
    /// A single-threaded runtime is the point: the previous `std::sync::mpsc::recv()`
    /// parked the only worker, so the branch standing in for the daemon never got
    /// polled again and this test would hang rather than fail.
    #[cfg(windows)]
    #[tokio::test(flavor = "current_thread")]
    async fn service_stop_signal_lets_the_daemon_future_keep_running() {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Arc;

        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let started = Arc::new(AtomicBool::new(false));
        let observed = Arc::clone(&started);

        let daemon = async move {
            // Stands in for `runtime.start().await` yielding to the executor.
            tokio::task::yield_now().await;
            observed.store(true, Ordering::SeqCst);
            shutdown_tx.send(true).expect("signal service stop");
            std::future::pending::<()>().await;
        };

        tokio::select! {
            () = daemon => unreachable!("the daemon runs until a stop is signalled"),
            () = service_stop_requested(shutdown_rx) => {}
        }

        assert!(
            started.load(Ordering::SeqCst),
            "daemon future must keep being polled while the stop signal is pending"
        );
    }

    /// A dropped control handler is a stop request, not a hang.
    #[cfg(windows)]
    #[tokio::test(flavor = "current_thread")]
    async fn service_stop_requested_resolves_when_the_sender_is_dropped() {
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        drop(shutdown_tx);
        service_stop_requested(shutdown_rx).await;
    }

    /// An already-signalled channel must resolve without waiting for a second change,
    /// so a stop that races startup is not missed.
    #[cfg(windows)]
    #[tokio::test(flavor = "current_thread")]
    async fn service_stop_requested_observes_a_signal_sent_before_it_is_awaited() {
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        shutdown_tx.send(true).expect("signal service stop");
        service_stop_requested(shutdown_rx).await;
    }
}
