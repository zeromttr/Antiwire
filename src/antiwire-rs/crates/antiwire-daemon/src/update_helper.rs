//! The one-shot helper that runs an install swap.
//!
//! On Windows and macOS the daemon starts this process from the new version's
//! tree with `--apply-update` or `--recover-update`. It is detached, so stopping
//! the daemon service does not stop it. The swap itself is in
//! [`antiwire_update::apply`].
//!
//! On Linux the daemon starts it from its own executable, in a transient
//! systemd unit, and it installs the new package with the package manager
//! ([`antiwire_update::package_apply`]).
//!
//! It has no console, so its log goes to `update.log` in the data directory.

use std::path::Path;

use antiwire_update::launcher::{APPLY_FLAG, RECOVER_FLAG};
use anyhow::Result;

/// Log file the helper appends to, in the data directory.
pub const LOG_FILE: &str = "update.log";

/// Whether this process was started as the helper. Logging is set up before
/// the command line is parsed, so the helper's log must be chosen from the raw
/// arguments.
///
/// Reads them as `OsString`s: `std::env::args` panics on an argument that is
/// not valid Unicode, before the crash log could say why.
#[must_use]
pub fn is_helper_invocation() -> bool {
    std::env::args_os().any(|arg| arg == APPLY_FLAG || arg == RECOVER_FLAG)
}

/// Runs the swap that the client requested. Refuses to run while another helper
/// holds the lock.
///
/// # Errors
///
/// When the helper is not in a versioned tree, another helper is running, or
/// the swap fails (after any rollback).
#[cfg(any(windows, target_os = "macos"))]
pub fn run_apply(data_dir: &Path, version: &str, request_id: &str) -> Result<()> {
    let version = parse_version(version)?;
    let paths = update_paths(data_dir)?;
    with_helper_lock(IfBusy::Fail, || {
        tracing::info!(%version, "apply helper started");
        antiwire_update::apply::apply(&paths, &version, request_id, &DaemonService::default())?;
        Ok(())
    })
}

/// Installs the package the client requested. Refuses to run while another
/// helper holds the lock.
///
/// # Errors
///
/// When another helper is running or the install fails (after any rollback).
#[cfg(target_os = "linux")]
pub fn run_apply(data_dir: &Path, version: &str, request_id: &str) -> Result<()> {
    use antiwire_update::package_install::SystemPackageInstaller;

    let version = parse_version(version)?;
    let paths = antiwire_update::UpdatePaths::for_package(data_dir);
    with_helper_lock(IfBusy::Fail, || {
        tracing::info!(%version, "package update helper started");
        antiwire_update::package_apply::apply(
            &paths,
            &version,
            request_id,
            &DaemonService::default(),
            &SystemPackageInstaller,
        )?;
        Ok(())
    })
}

/// Rolls back an interrupted package install. Does nothing while an apply
/// holds the lock, because that apply owns the install.
///
/// # Errors
///
/// When the rollback fails.
#[cfg(target_os = "linux")]
pub fn run_recover(data_dir: &Path) -> Result<()> {
    use antiwire_update::package_install::SystemPackageInstaller;

    let paths = antiwire_update::UpdatePaths::for_package(data_dir);
    with_helper_lock(IfBusy::Skip, || {
        antiwire_update::package_apply::recover(
            &paths,
            &DaemonService::default(),
            &SystemPackageInstaller,
        )?;
        Ok(())
    })
}

/// Rolls back an interrupted swap. Does nothing while an apply holds the lock,
/// because that apply owns the swap.
///
/// # Errors
///
/// When the helper is not in a versioned tree or the rollback fails.
#[cfg(any(windows, target_os = "macos"))]
pub fn run_recover(data_dir: &Path) -> Result<()> {
    let paths = update_paths(data_dir)?;
    with_helper_lock(IfBusy::Skip, || {
        antiwire_update::apply::recover(&paths, &DaemonService::default())?;
        Ok(())
    })
}
/// Runs the swap that the client requested.
///
/// # Errors
///
/// Always: the helper runs only on Windows, macOS, and Linux.
#[cfg(not(any(windows, target_os = "macos", target_os = "linux")))]
pub fn run_apply(_data_dir: &Path, _version: &str, _request_id: &str) -> Result<()> {
    Err(anyhow::anyhow!(UNSUPPORTED))
}

/// Rolls back an interrupted swap.
///
/// # Errors
///
/// Always: the helper runs only on Windows, macOS, and Linux.
#[cfg(not(any(windows, target_os = "macos", target_os = "linux")))]
pub fn run_recover(_data_dir: &Path) -> Result<()> {
    Err(anyhow::anyhow!(UNSUPPORTED))
}

#[cfg(not(any(windows, target_os = "macos", target_os = "linux")))]
const UNSUPPORTED: &str = "the update helper runs only on Windows, macOS, and Linux";

/// The service manager the daemon runs under on this platform.
#[cfg(windows)]
type DaemonService = antiwire_update::service_control::WindowsDaemonService;
#[cfg(target_os = "macos")]
type DaemonService = antiwire_update::service_control::LaunchdDaemonService;
#[cfg(target_os = "linux")]
type DaemonService = antiwire_update::service_control::SystemdDaemonService;

/// Lock shared by apply and recover, so the two never run together.
#[cfg(windows)]
const LOCK_NAME: &str = "Global\\AntiwireUpdateHelper";
#[cfg(any(target_os = "macos", target_os = "linux"))]
const LOCK_NAME: &str = "antiwire-update-helper";

/// The helper lock, or `None` while another helper holds it.
#[cfg(any(windows, target_os = "macos", target_os = "linux"))]
fn helper_lock() -> Result<Option<crate::process_lock::ProcessLock>> {
    use anyhow::Context;

    crate::process_lock::ProcessLock::try_acquire(LOCK_NAME).context("create update helper lock")
}

/// What to do when another helper already holds the lock.
#[cfg(any(windows, target_os = "macos", target_os = "linux"))]
#[derive(Clone, Copy)]
enum IfBusy {
    /// Fail: an apply must not run beside another helper.
    Fail,
    /// Do nothing and succeed: the helper holding it owns the swap, and a
    /// recovery would undo it.
    Skip,
}

/// Runs `body` while holding the helper lock, so apply and recover never
/// run together. The lock is held until `body` returns.
///
/// # Errors
///
/// When the lock cannot be created, when it is busy and `if_busy` is
/// [`IfBusy::Fail`], or when `body` fails.
#[cfg(any(windows, target_os = "macos", target_os = "linux"))]
fn with_helper_lock(if_busy: IfBusy, body: impl FnOnce() -> Result<()>) -> Result<()> {
    with_lock(helper_lock, if_busy, body)
}

/// Runs `body` while holding the lock `acquire` takes, or, while it is busy,
/// does what `if_busy` says without running `body`.
#[cfg(any(windows, target_os = "macos", target_os = "linux"))]
fn with_lock<L>(
    acquire: impl FnOnce() -> Result<Option<L>>,
    if_busy: IfBusy,
    body: impl FnOnce() -> Result<()>,
) -> Result<()> {
    let Some(lock) = acquire()? else {
        return match if_busy {
            IfBusy::Fail => Err(anyhow::anyhow!("another update helper is already running")),
            IfBusy::Skip => {
                tracing::info!("an update is in progress; leaving recovery to it");
                Ok(())
            }
        };
    };
    let result = body();
    drop(lock);
    result
}

/// The version the client asked for, parsed before any lock is taken.
#[cfg(any(windows, target_os = "macos", target_os = "linux"))]
fn parse_version(version: &str) -> Result<semver::Version> {
    use anyhow::Context;

    semver::Version::parse(version).with_context(|| format!("parse update version {version}"))
}

/// Paths for the install this helper belongs to, taken from its own location.
///
/// # Errors
///
/// When the helper is not running from `versions/{version}/daemon/`.
#[cfg(any(windows, target_os = "macos"))]
fn update_paths(data_dir: &Path) -> Result<antiwire_update::UpdatePaths> {
    use anyhow::Context;

    let exe = std::env::current_exe().context("locate the helper executable")?;
    antiwire_update::UpdatePaths::from_daemon_exe(data_dir, &exe).ok_or_else(|| {
        anyhow::anyhow!(
            "the update helper must run from a versioned install tree, not {}",
            exe.display()
        )
    })
}

#[cfg(all(test, any(windows, target_os = "macos", target_os = "linux")))]
mod tests {
    use super::*;

    /// Another process holding the lock is what makes it busy; that the
    /// lock excludes other processes is tested in `process_lock`.
    fn busy() -> Result<Option<()>> {
        Ok(None)
    }

    fn free() -> Result<Option<()>> {
        Ok(Some(()))
    }

    #[test]
    fn a_busy_lock_fails_an_apply_and_skips_a_recovery() {
        let applied = with_lock(busy, IfBusy::Fail, || panic!("must not run while busy"));
        assert!(applied.is_err());
        let recovered = with_lock(busy, IfBusy::Skip, || panic!("must not run while busy"));
        assert!(recovered.is_ok());
    }

    #[test]
    fn a_free_lock_runs_the_body_and_returns_its_result() {
        let mut ran = false;
        with_lock(free, IfBusy::Fail, || {
            ran = true;
            Ok(())
        })
        .expect("free lock");
        assert!(ran);
        let failed = with_lock(free, IfBusy::Skip, || Err(anyhow::anyhow!("swap failed")));
        assert!(failed.is_err(), "the body's failure is returned");
    }

    #[test]
    fn a_lock_that_cannot_be_created_fails_either_way() {
        let broken = || -> Result<Option<()>> { Err(anyhow::anyhow!("no lock")) };
        assert!(with_lock(broken, IfBusy::Fail, || panic!("must not run")).is_err());
        assert!(with_lock(broken, IfBusy::Skip, || panic!("must not run")).is_err());
    }

    #[test]
    fn the_real_helper_lock_can_be_taken_and_released() {
        let mut ran = false;
        with_helper_lock(IfBusy::Fail, || {
            ran = true;
            Ok(())
        })
        .expect("no other helper runs in tests");
        assert!(ran);
    }

    #[test]
    fn a_bad_version_is_rejected() {
        assert!(parse_version("1.2.3").is_ok());
        assert!(parse_version("not-a-version").is_err());
    }
}
