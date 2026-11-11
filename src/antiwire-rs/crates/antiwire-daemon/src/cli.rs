//! The daemon's command line.

use std::path::PathBuf;

use clap::Parser;

// A plain comment, not a doc comment: clap would show one in `--help`.
// The hidden flags start the one-shot modes other parts of Antiwire run the
// daemon in: the reaper, the update helper, and the detached Windows copy.
#[derive(Clone, Debug, Parser)]
#[command(
    name = "antiwire-daemon",
    about = "Antiwire privileged networking daemon"
)]
pub(crate) struct Cli {
    /// Data directory for database and secrets.
    #[arg(long, env = "ANTIWIRE_DATA_DIR")]
    pub(crate) data_dir: Option<PathBuf>,

    /// IPC endpoint: `host:port` on Windows, `unix:<path>` elsewhere.
    /// Defaults to where the client connects: `127.0.0.1:50051` on Windows,
    /// else `ANTIWIRE_IPC_SOCKET` or `/var/run/antiwire.sock`.
    #[arg(long)]
    pub(crate) listen: Option<String>,

    /// Run as normal process even on Windows (skip windows-service registration).
    /// Windows only; accepted and ignored elsewhere.
    #[arg(long, hide = cfg!(not(windows)))]
    pub(crate) no_service: bool,

    /// Keep the daemon attached to the launching terminal/job (Windows interactive).
    ///
    /// Default is to re-spawn as a breakaway detached process so a system restart
    /// does not `TerminateProcess` the daemon with the terminal job before DNS
    /// can be restored. Use this flag when you need live console logs and accept
    /// that reboot cleanup may require the boot heal task instead. Implies
    /// `--no-service`, since a service has no terminal to stay attached to.
    /// Windows only; accepted and ignored elsewhere.
    #[arg(long, hide = cfg!(not(windows)))]
    pub(crate) foreground: bool,

    /// Set by a Windows daemon on the breakaway copy of itself it starts, so
    /// that copy runs the daemon instead of detaching again. Hidden.
    #[arg(long, hide = true)]
    pub(crate) detached_child: bool,

    /// Revert host state a stopped daemon left behind, then exit. Does nothing
    /// while a daemon is running. Used by the Windows ONSTART heal task, which
    /// restores dirty DNS, and the Linux unit's `ExecStopPost`, which makes the
    /// reaper's full revert.
    #[arg(long)]
    pub(crate) heal_host_state: bool,

    /// Watch this pid and revert host state when it exits. Hidden reaper mode.
    #[arg(long, hide = true)]
    pub(crate) reap_parent: Option<u32>,

    /// Apply the update the client requested, then exit. Hidden helper mode, started
    /// from the new version's tree. Needs `--update-request`.
    #[arg(long, hide = true, value_name = "VERSION", requires = "update_request")]
    pub(crate) apply_update: Option<String>,

    /// The one-time request id that `--apply-update` must match. Hidden helper mode.
    #[arg(long, hide = true, requires = "apply_update")]
    pub(crate) update_request: Option<String>,

    /// Roll back an interrupted update, then exit. Hidden helper mode.
    #[arg(long, hide = true)]
    pub(crate) recover_update: bool,
}
