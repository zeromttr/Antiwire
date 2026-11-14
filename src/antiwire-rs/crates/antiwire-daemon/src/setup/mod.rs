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
/// and publishes the data directory.
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
    (cli, data_dir)
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
