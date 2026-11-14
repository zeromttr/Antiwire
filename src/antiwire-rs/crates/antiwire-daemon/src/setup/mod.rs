//! What every mode of the daemon does first: point the crash log and the
//! tracing log at the data directory, parse the command line, and publish
//! the data directory to child processes.

use std::path::{Path, PathBuf};

use antiwire_platform::crash;
use anyhow::Result;
use clap::Parser;

use crate::cli::Cli;

pub(crate) mod data_dir;
pub(crate) mod logging;

/// Starts crash logging and tracing, parses the command line, and resolves
/// and publishes the data directory. On macOS it also turns packet capture on.
pub(crate) fn startup() -> (Cli, PathBuf) {
    let early_dir = data_dir::early_data_dir();
    init_crash_logging(&early_dir);
    logging::init_tracing(&early_dir);

    let cli = Cli::parse();
    let data_dir = cli
        .data_dir
        .clone()
        .unwrap_or_else(data_dir::default_data_dir);
    crash::set_data_dir(&data_dir);
    data_dir::publish_data_dir(&data_dir);
    #[cfg(target_os = "macos")]
    default_packet_capture();
    (cli, data_dir)
}

/// Turns packet capture on for the macOS collector unless the environment already chose.
///
/// `netmetrics` captures only when `NETMETRICS_PKTAP_INTERFACE` names a PKTAP interface,
/// because it creates that interface, and a library does not change the host unasked. The
/// daemon always wants it: without capture the collector lists connections with no byte
/// counts and cannot tell which process asked for a name. A value already set is kept, so a
/// run can name another interface.
///
/// Same rule as [`data_dir::publish_data_dir`]: once, before any thread exists.
#[cfg(target_os = "macos")]
fn default_packet_capture() {
    const VARIABLE: &str = "NETMETRICS_PKTAP_INTERFACE";
    if std::env::var_os(VARIABLE).is_none() {
        std::env::set_var(VARIABLE, "pktap0");
    }
}

/// Starts crash logging before anything that can panic.
///
/// The resolved `--data-dir` is not known until parsing finishes, so the crash
/// log is pointed at the environment/default location first and re-pointed once
/// the CLI is parsed. That window only covers argument parsing itself.
fn init_crash_logging(data_dir: &Path) {
    crash::set_data_dir(data_dir);
    crash::install_panic_hook();
}

/// Records a fatal error before [`crate::run`] returns it and the process exits non-zero.
pub(crate) fn record_fatal(result: &Result<()>) {
    if let Err(error) = result {
        crash::record_fatal_error(format_args!("{error:#}"));
    }
}
