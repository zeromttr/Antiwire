//! The Antiwire daemon: the privileged process that redirects DNS, enforces
//! firewall rules and accounts traffic, and the one-shot helper modes the
//! same executable runs in.
//!
//! The `antiwire-daemon` binary only calls [`run`].

use anyhow::Result;
use std::path::Path;

mod cli;
mod daemon;
mod heal;
mod process_lock;
mod reaper;
mod setup;
mod update_helper;

use cli::Cli;

/// Runs a one-shot mode, which exits without starting the daemon: the
/// reaper, an update helper, or `--heal-host-state`.
///
/// `None` when the command line is not one of them. [`run`] records any
/// error it returns in the crash log: these processes run with their
/// standard streams on the null device, so nothing else would show it.
fn run_oneshot(cli: &Cli, data_dir: &Path) -> Option<Result<()>> {
    if let Some(pid) = cli.reap_parent {
        return Some(reaper::reap(pid, data_dir));
    }
    if let Some(result) = run_update_helper(cli, data_dir) {
        return Some(result);
    }
    if cli.heal_host_state {
        return Some(heal::heal_host_state(data_dir));
    }
    None
}

/// Runs an update helper mode, which exits without starting the daemon.
///
/// `None` when the command line is not a helper mode.
fn run_update_helper(cli: &Cli, data_dir: &Path) -> Option<Result<()>> {
    if let (Some(version), Some(request_id)) =
        (cli.apply_update.as_deref(), cli.update_request.as_deref())
    {
        return Some(update_helper::run_apply(data_dir, version, request_id));
    }
    if cli.recover_update {
        return Some(update_helper::run_recover(data_dir));
    }
    None
}

/// Runs the daemon, or the one-shot mode its command line asks for, until
/// it is told to stop.
///
/// # Errors
///
/// When the mode fails; the error is also written to the crash log, as is
/// a failure of the Windows service dispatcher.
pub fn run() -> Result<()> {
    let (cli, data_dir) = setup::startup();
    let result = run_oneshot(&cli, &data_dir).unwrap_or_else(|| daemon::run(cli, data_dir));
    setup::record_fatal(&result);
    result
}
