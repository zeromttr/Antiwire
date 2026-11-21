//! The long-running daemon: taking the instance lock, starting the runtime
//! and the gRPC server, and stopping them all together when told to.

use std::future::Future;
use std::path::PathBuf;
use std::sync::Arc;

use antiwire_ipc::{GrpcServer, IpcEndpoint, IpcPaths};
use antiwire_runtime::AntiwireRuntime;
use antiwire_tuning::{IPC_SERVER_DRAIN_TIMEOUT, PROCESS_EXIT_BLOCKING_TIMEOUT};
use antiwire_update::launcher::DetachedLauncher;
use anyhow::{Context, Result};
use tracing::{info, warn};

use crate::cli::Cli;
use crate::{process_lock, reaper};

pub(crate) mod shutdown_signal;
#[cfg(windows)]
pub(crate) mod windows;

/// Runs the daemon until it is told to stop.
///
/// # Errors
///
/// When the daemon cannot start, its gRPC server fails, or its stop leaves
/// host state unreverted.
#[cfg(not(windows))]
pub(crate) fn run(cli: Cli, data_dir: PathBuf) -> Result<()> {
    block_on_bounded(run_daemon(
        cli,
        data_dir,
        shutdown_signal::interactive_shutdown_requested(),
        || {},
        DaemonHost::Service,
    ))?
}

/// Runs the daemon until it is told to stop, as a service or interactively.
///
/// # Errors
///
/// When the daemon or the service dispatcher fails.
#[cfg(windows)]
pub(crate) fn run(cli: Cli, data_dir: PathBuf) -> Result<()> {
    windows::run(cli, data_dir)
}

/// How the daemon is hosted, which decides how its runtime is built.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DaemonHost {
    /// Run by a service manager: the SCM, systemd or launchd.
    Service,
    /// An interactive Windows run, detached from its terminal. It registers
    /// the ONSTART heal task, since no service manager stops it on shutdown.
    #[cfg_attr(not(windows), allow(dead_code))]
    Interactive,
}

/// Runs the daemon until `shutdown` resolves, then tears it down.
///
/// `shutdown` is supplied by the caller rather than hardcoded to Ctrl-C because a
/// Windows service is stopped by the SCM, which never delivers one. `on_ready` fires
/// once the runtime is up and the gRPC server is listening, so a service host can
/// move from `StartPending` to `Running` at the moment that is actually true.
///
/// The gRPC server is the only way to control the daemon, so if it fails, the
/// daemon stops and returns the error instead of running on without it.
async fn run_daemon<S, R>(
    cli: Cli,
    data_dir: PathBuf,
    shutdown: S,
    on_ready: R,
    host: DaemonHost,
) -> Result<()>
where
    S: Future<Output = ()>,
    R: FnOnce(),
{
    // Before anything below that can fail, so an update that a reboot cut
    // short is rolled back even when the version it left in place cannot
    // start. Only a release build run by the service manager updates itself.
    if matches!(host, DaemonHost::Service) && !cfg!(debug_assertions) {
        antiwire_update::recover_interrupted_install(&data_dir, &DetachedLauncher);
    }

    // Listened to from the start, not only once the daemon runs. A stop that
    // arrives while the daemon waits for its lock or starts up is otherwise
    // acted on late or not at all, and the shutdown future installs its
    // signal handlers when first polled: until then a Unix SIGTERM kills
    // the process outright, redirected DNS and all.
    let mut shutdown = std::pin::pin!(shutdown);

    let Some(lock) = unless_shutdown(process_lock::wait_for_daemon_lock(), shutdown.as_mut()).await
    else {
        info!("shutdown requested before the daemon started");
        return Ok(());
    };
    let _single_instance = lock?;

    if let Err(error) = reaper::spawn(&data_dir) {
        // The daemon still restores host state when it stops, and the next
        // start recovers what a crash leaves; only the crash-time revert is
        // missing.
        tracing::error!(
            error = %error,
            "host-state reaper was not started; a crash leaves DNS and rules until the next start"
        );
    }
    let endpoint = match &cli.listen {
        Some(listen) => IpcEndpoint::parse(listen).context("parse --listen")?,
        None => IpcEndpoint::from_environment_or_platform_default(),
    };
    let ipc_paths = IpcPaths::from_environment();

    let runtime = Arc::new(match host {
        DaemonHost::Interactive => AntiwireRuntime::bootstrap_interactive(data_dir)?,
        DaemonHost::Service => AntiwireRuntime::bootstrap(data_dir)?,
    });
    // A stop that arrives now lets the start finish rather than abandoning
    // it: a start cut short would leave DNS redirected with nothing to
    // revert it. The daemon then stops at once.
    let (started, stop_requested) =
        finish_noting_shutdown(runtime.start(), shutdown.as_mut()).await;
    started?;
    if stop_requested {
        info!("shutdown requested while starting; stopping");
        return runtime.stop().await.context("runtime shutdown");
    }

    let parts = runtime.ipc_service_parts();
    let grpc = GrpcServer::new(endpoint, ipc_paths, parts);
    let (listening_tx, listening_rx) = tokio::sync::oneshot::channel();
    let mut grpc_task = tokio::spawn(grpc.serve(move |bound| {
        let _ = listening_tx.send(bound.to_string());
    }));

    // The sender is dropped unsent only when the server ended before binding.
    let grpc_ended = if let Ok(bound) = listening_rx.await {
        info!(listen = %bound, "antiwire-daemon running");
        on_ready();
        tokio::select! {
            () = shutdown.as_mut() => {
                info!("shutdown requested");
                None
            }
            ended = &mut grpc_task => Some(ended),
        }
    } else {
        Some((&mut grpc_task).await)
    };

    let stopped = if grpc_ended.is_none() {
        // One signal stops everything at once. `runtime.stop` cancels the
        // token the server holds a child of, so the server refuses new
        // connections and ends its streams while DNS and the firewall are
        // reverted beside it, rather than delaying the DNS restore by up to
        // its whole drain budget. A request still running cannot undo the
        // revert: the DNS slot and the firewall worker close as they stop.
        let (stopped, ()) = tokio::join!(runtime.stop(), drain_grpc(&mut grpc_task));
        stopped
    } else {
        runtime.stop().await
    };
    // Normally finished by now. Aborted regardless, so a server that would
    // not drain, or an error on the way out, cannot leave the listener open.
    grpc_task.abort();
    if let Some(ended) = grpc_ended {
        log_stop_failure(stopped);
        return Err(match ended {
            Ok(Ok(())) => anyhow::anyhow!("gRPC server stopped unexpectedly"),
            Ok(Err(error)) => anyhow::Error::new(error).context("gRPC server failed"),
            Err(error) => anyhow::Error::new(error).context("gRPC server task failed"),
        });
    }
    stopped.context("runtime shutdown")
}

/// Runs `work` unless `shutdown` fires first, which abandons it: for work
/// that changes nothing, such as waiting for the daemon lock. `None` when
/// shutdown fired, which then must not be polled again.
async fn unless_shutdown<T>(
    work: impl Future<Output = T>,
    shutdown: std::pin::Pin<&mut impl Future<Output = ()>>,
) -> Option<T> {
    tokio::select! {
        biased;
        () = shutdown => None,
        output = work => Some(output),
    }
}

/// Runs `work` to completion even when `shutdown` fires meanwhile, and
/// returns whether it did, in which case it must not be polled again. For
/// work that must not be abandoned halfway, such as the runtime start.
async fn finish_noting_shutdown<T>(
    work: impl Future<Output = T>,
    shutdown: std::pin::Pin<&mut impl Future<Output = ()>>,
) -> (T, bool) {
    let mut work = std::pin::pin!(work);
    tokio::select! {
        biased;
        output = &mut work => (output, false),
        () = shutdown => (work.await, true),
    }
}

/// Gives the gRPC server [`IPC_SERVER_DRAIN_TIMEOUT`] to finish the requests
/// already running once shutdown has cancelled it.
async fn drain_grpc(
    grpc_task: &mut tokio::task::JoinHandle<std::result::Result<(), antiwire_ipc::IpcError>>,
) {
    match tokio::time::timeout(IPC_SERVER_DRAIN_TIMEOUT, grpc_task).await {
        Ok(Ok(Ok(()))) => {}
        Ok(Ok(Err(error))) => warn!(%error, "gRPC server failed while stopping"),
        Ok(Err(error)) => warn!(%error, "gRPC server task failed while stopping"),
        Err(_) => warn!("gRPC requests were still running when the drain budget ran out"),
    }
}

/// Logs a shutdown failure that happened while returning a more important error.
fn log_stop_failure<E: std::fmt::Display>(stopped: std::result::Result<(), E>) {
    if let Err(error) = stopped {
        tracing::error!(error = %error, "runtime shutdown failed");
    }
}

/// Runs `future` on a new multi-thread runtime, then shuts the runtime down
/// without waiting more than [`PROCESS_EXIT_BLOCKING_TIMEOUT`] for blocking
/// work still running.
///
/// Dropping a runtime waits for every blocking task already started, and a
/// revert that timed out still has one running. A native call that never
/// returns would then keep the process alive, and the reaper, which only
/// starts once the process is gone, from ever taking over.
fn block_on_bounded<F: Future>(future: F) -> Result<F::Output> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    let output = runtime.block_on(future);
    runtime.shutdown_timeout(PROCESS_EXIT_BLOCKING_TIMEOUT);
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The regression this guards: the daemon only listened for a stop once
    /// it had started, so a stop while it waited up to 30 s for its lock
    /// was acted on only after a full start.
    #[tokio::test]
    async fn a_stop_abandons_the_wait_for_the_lock() {
        let shutdown = std::pin::pin!(std::future::ready(()));
        let waited = unless_shutdown(std::future::pending::<()>(), shutdown).await;
        assert!(waited.is_none());
    }

    #[tokio::test]
    async fn work_finishes_when_no_stop_comes() {
        let shutdown = std::pin::pin!(std::future::pending::<()>());
        assert_eq!(unless_shutdown(async { 7 }, shutdown).await, Some(7));
    }

    /// A start is never abandoned halfway, which would leave DNS redirected
    /// with nothing to revert it; a stop during it is reported once the
    /// start has finished.
    #[tokio::test]
    async fn a_stop_during_the_start_lets_it_finish_and_is_reported() {
        let (finish, finished) = tokio::sync::oneshot::channel::<()>();
        let start = async move {
            finished.await.expect("released");
            "started"
        };
        let shutdown = std::pin::pin!(async move {
            let _ = finish.send(());
        });
        let (started, stop_requested) = finish_noting_shutdown(start, shutdown).await;
        assert_eq!(started, "started");
        assert!(stop_requested);
    }

    #[tokio::test]
    async fn a_start_with_no_stop_reports_none() {
        let shutdown = std::pin::pin!(std::future::pending::<()>());
        assert_eq!(
            finish_noting_shutdown(async { "started" }, shutdown).await,
            ("started", false)
        );
    }
}
