//! How the daemon is hosted on Windows: as a service under the SCM, or
//! interactively, detached from its terminal, with a hidden window that
//! watches for the session ending.

use std::path::PathBuf;

use anyhow::Result;

use super::{block_on_bounded, run_daemon, shutdown_signal, DaemonHost};
use crate::cli::Cli;

pub(crate) mod detach;
mod privilege;
mod service;
pub(super) mod session;

/// Runs the daemon on Windows, as a service or interactively.
///
/// # Errors
///
/// When the daemon or the service dispatcher fails.
pub(super) fn run(cli: Cli, data_dir: PathBuf) -> Result<()> {
    // Only the daemon itself resolves other processes' executables; the
    // one-shot modes above have no use for the privilege.
    let run_as_service = !cli.no_service && !cli.foreground && !cfg!(debug_assertions);
    if run_as_service {
        privilege::enable_debug_privilege();
        let _ = service::SERVICE_CLI.set((cli, data_dir));
        return service::run_windows_service_mode();
    }

    // Break out of the terminal/cargo Job Object. System restart otherwise
    // TerminateProcess-es the whole job with no WM_QUERYENDSESSION / CTRL_*.
    if !detach::ensure_detached_or_continue(cli.foreground, cli.detached_child) {
        return Ok(());
    }
    privilege::enable_debug_privilege();

    // Hidden window + ShutdownBlockReasonCreate so logoff/shutdown wait for
    // DNS/firewall restore. Console handlers alone miss those events once
    // user32 is loaded (and the session window intentionally loads it).
    let session = session::SessionEndWatcher::start();
    let session_rx = session.as_ref().map(session::SessionEndWatcher::subscribe);

    // `session` Drop releases any shutdown block reason and tears down the window.
    let _session = session;
    block_on_bounded(run_daemon(
        cli,
        data_dir,
        shutdown_signal::interactive_shutdown_requested(session_rx),
        || {},
        DaemonHost::Interactive,
    ))?
}
