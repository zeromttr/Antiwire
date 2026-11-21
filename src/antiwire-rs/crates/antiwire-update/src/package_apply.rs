//! The Linux install, run by the one-shot helper process.
//!
//! The helper runs in its own transient systemd unit (see
//! [`crate::launcher`]), so stopping `antiwire-daemon.service`, which the
//! package's own scripts do during the upgrade, does not stop the install.
//!
//! 1. Accept only a `pending` request in phase `Requested` with a matching id,
//!    and move it to `Swapping` before touching the service.
//! 2. Stop the service and copy the database to `db-backup/{version}`.
//! 3. Install the new package with the package manager.
//! 4. Start the service until healthy, and check that the package manager
//!    reports the new version installed.
//! 5. Success: `previous = current`, `current = version`, keep the package for
//!    the next rollback, remove the staging files.
//! 6. Failure: stop, restore the database, set `last_error`, reinstall the
//!    previous version's package, start, clear `pending`.

use std::path::Path;

use semver::Version;

use crate::apply::{
    backup_database, clean_staging, discard_backup, finish_rollback, record, record_failure,
    record_reason_before_restart, remove_dir_if_present, restore_database,
};
use crate::package::{PackageFormat, PackagePlan};
use crate::package_install::PackageInstaller;
use crate::service_control::{DaemonService, SETTLE_TIME, START_TIMEOUT, STOP_TIMEOUT};
use crate::state::{ApplyPhase, InstallState};
use crate::{UpdateError, UpdatePaths};

/// Applies the requested package install.
///
/// # Errors
///
/// [`UpdateError::NoRequest`] when there is no matching request; otherwise the
/// error that made the install roll back.
pub fn apply(
    paths: &UpdatePaths,
    version: &Version,
    request_id: &str,
    service: &dyn DaemonService,
    installer: &dyn PackageInstaller,
) -> Result<(), UpdateError> {
    let state_path = paths.install_state();
    let mut state = InstallState::load(&state_path)?;
    let requested = state.pending.as_ref().is_some_and(|pending| {
        pending.version == *version
            && pending.request_id == request_id
            && pending.phase == ApplyPhase::Requested
    });
    if !requested {
        return Err(UpdateError::NoRequest);
    }
    let Some(current) = state.current.clone() else {
        return Err(UpdateError::Unsupported(
            "install state has no current version".to_owned(),
        ));
    };

    // Each failure below happens before the service is touched, so there is
    // nothing to roll back; the request is only marked as failed.
    let staged = paths.verified(version);
    let plan = match PackagePlan::load(&staged) {
        Ok(plan) => plan,
        Err(error) => return Err(record_failure(&state_path, &mut state, error)),
    };
    let package = staged.join(&plan.package);
    if !package.is_file() {
        let missing = std::io::Error::from(std::io::ErrorKind::NotFound);
        let error = UpdateError::io("find", &package, missing);
        return Err(record_failure(&state_path, &mut state, error));
    }
    if let Err(error) = discard_backup(paths, version) {
        return Err(record_failure(&state_path, &mut state, error));
    }

    if let Some(pending) = state.pending.as_mut() {
        pending.phase = ApplyPhase::Swapping;
    }
    state.store(&state_path)?;
    tracing::info!(%version, format = %plan.format, "installing the new package");

    match install(paths, version, plan.format, &package, service, installer) {
        Ok(()) => commit(paths, &mut state, version, &current, &package),
        Err(cause) => {
            if let Err(rollback) = roll_back(paths, &mut state, version, service, installer, &cause)
            {
                tracing::error!(error = %rollback, "rollback did not fully succeed");
            }
            Err(cause)
        }
    }
}

/// Rolls back an install left in phase `Swapping` by a crash or reboot. Does
/// nothing when no install is pending.
///
/// # Errors
///
/// When the rollback itself fails.
pub fn recover(
    paths: &UpdatePaths,
    service: &dyn DaemonService,
    installer: &dyn PackageInstaller,
) -> Result<(), UpdateError> {
    let state_path = paths.install_state();
    let mut state = InstallState::load(&state_path)?;
    let Some(pending) = state.pending.clone() else {
        return Ok(());
    };
    if pending.phase != ApplyPhase::Swapping {
        return Ok(());
    }
    tracing::warn!(version = %pending.version, "rolling back an interrupted package install");
    let cause = UpdateError::Unhealthy(format!(
        "the install of {} was interrupted",
        pending.version
    ));
    roll_back(
        paths,
        &mut state,
        &pending.version,
        service,
        installer,
        &cause,
    )
}

/// The steps between the request and the health check. Any error here means
/// the install must roll back.
fn install(
    paths: &UpdatePaths,
    version: &Version,
    format: PackageFormat,
    package: &Path,
    service: &dyn DaemonService,
    installer: &dyn PackageInstaller,
) -> Result<(), UpdateError> {
    service.stop(STOP_TIMEOUT)?;
    backup_database(paths, version)?;
    installer.install(format, package, false)?;
    service.start_healthy(START_TIMEOUT, SETTLE_TIME)?;
    match installer.installed_version(format)? {
        Some(found) if found == *version => Ok(()),
        Some(found) => Err(UpdateError::Unhealthy(format!(
            "the package manager reports {found} installed, not {version}"
        ))),
        None => Err(UpdateError::Unhealthy(
            "the package manager reports antiwire as not installed".to_owned(),
        )),
    }
}

fn commit(
    paths: &UpdatePaths,
    state: &mut InstallState,
    version: &Version,
    current: &Version,
    package: &Path,
) -> Result<(), UpdateError> {
    state.previous = Some(current.clone());
    state.current = Some(version.clone());
    state.pending = None;
    state.last_error = None;
    state.store(&paths.install_state())?;
    // Without the copy the next update downloads this package again.
    if let Err(error) = keep_installed_package(paths, package) {
        tracing::warn!(error = %error, "the installed package was not kept for rollback");
    }
    clean_staging(paths, version);
    tracing::info!(%version, "update installed");
    Ok(())
}

/// Moves `package` into `updates/installed`, replacing what was there.
fn keep_installed_package(paths: &UpdatePaths, package: &Path) -> Result<(), UpdateError> {
    let Some(name) = package.file_name() else {
        return Ok(());
    };
    let kept = paths.installed_packages();
    remove_dir_if_present(&kept)?;
    std::fs::create_dir_all(&kept).map_err(|error| UpdateError::io("create", &kept, error))?;
    let destination = kept.join(name);
    std::fs::rename(package, &destination).map_err(|error| UpdateError::io("move", package, error))
}

/// Puts the previous version back in service and records why the install
/// failed. As on the other platforms, every step is attempted even after an
/// earlier one fails, except that nothing touches the database while the
/// service might still be running.
///
/// The reason is recorded before the reinstall, because the package's
/// post-install script starts the daemon.
fn roll_back(
    paths: &UpdatePaths,
    state: &mut InstallState,
    version: &Version,
    service: &dyn DaemonService,
    installer: &dyn PackageInstaller,
    cause: &UpdateError,
) -> Result<(), UpdateError> {
    let staged = paths.verified(version);
    let backup = paths.db_backup(version);
    let mut failures = Vec::new();
    let stopped = record(
        &mut failures,
        "the service could not be stopped for rollback",
        service.stop(STOP_TIMEOUT),
    );
    if stopped {
        if backup.is_dir() {
            record(
                &mut failures,
                "the database could not be restored",
                restore_database(paths.data_dir(), &backup),
            );
        }
        record_reason_before_restart(paths, state, cause, &failures);
        match PackagePlan::load(&staged) {
            Ok(PackagePlan {
                format,
                rollback: Some(previous),
                ..
            }) => {
                record(
                    &mut failures,
                    "the previous version could not be reinstalled",
                    installer.install(format, &staged.join(previous), true),
                );
            }
            Ok(PackagePlan { rollback: None, .. }) => {
                failures.push("no package of the previous version was available".to_owned());
            }
            Err(error) => failures.push(format!("the install plan could not be read: {error}")),
        }
        record(
            &mut failures,
            "the daemon did not start",
            service.start_healthy(START_TIMEOUT, SETTLE_TIME),
        );
    }
    finish_rollback(paths, state, cause, failures)
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::path::PathBuf;
    use std::time::Duration;

    use super::*;
    use crate::state::PendingInstall;

    const REQUEST: &str = "request-1";

    /// Records what the swap asked of the service and package manager. The
    /// installed version follows the installs, as a real package manager's would.
    struct Fake {
        log: RefCell<Vec<String>>,
        installed: RefCell<Option<Version>>,
        /// The version each package file installs, by file name.
        versions: Vec<(&'static str, Version)>,
        fail_install: bool,
        fail_healthy_once: RefCell<bool>,
    }

    impl Fake {
        fn new(installed: Version) -> Self {
            Self {
                log: RefCell::new(Vec::new()),
                installed: RefCell::new(Some(installed)),
                versions: vec![
                    ("new.deb", Version::new(0, 3, 0)),
                    ("old.deb", Version::new(0, 2, 0)),
                ],
                fail_install: false,
                fail_healthy_once: RefCell::new(false),
            }
        }

        fn log(&self) -> Vec<String> {
            self.log.borrow().clone()
        }
    }

    impl DaemonService for Fake {
        fn stop(&self, _timeout: Duration) -> Result<(), UpdateError> {
            self.log.borrow_mut().push("stop".to_owned());
            Ok(())
        }

        fn image(&self) -> Result<PathBuf, UpdateError> {
            Ok(PathBuf::from("/usr/bin/antiwire-daemon"))
        }

        fn set_image(&self, _daemon_exe: &Path, _data_dir: &Path) -> Result<(), UpdateError> {
            unreachable!("the package flow never repoints the unit")
        }

        fn start_healthy(&self, _start: Duration, _settle: Duration) -> Result<(), UpdateError> {
            self.log.borrow_mut().push("start".to_owned());
            if self.fail_healthy_once.replace(false) {
                return Err(UpdateError::Unhealthy("crashed".to_owned()));
            }
            Ok(())
        }
    }

    impl PackageInstaller for Fake {
        fn installed_version(
            &self,
            _format: PackageFormat,
        ) -> Result<Option<Version>, UpdateError> {
            Ok(self.installed.borrow().clone())
        }

        fn install(
            &self,
            _format: PackageFormat,
            package: &Path,
            rollback: bool,
        ) -> Result<(), UpdateError> {
            let name = package
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or_default()
                .to_owned();
            self.log.borrow_mut().push(format!(
                "install {name}{}",
                if rollback { " (rollback)" } else { "" }
            ));
            if self.fail_install && !rollback {
                return Err(UpdateError::Service("dpkg exploded".to_owned()));
            }
            let version = self
                .versions
                .iter()
                .find(|(file, _)| *file == name)
                .map(|(_, version)| version.clone());
            *self.installed.borrow_mut() = version;
            Ok(())
        }
    }

    fn staged(rollback: Option<&str>) -> (tempfile::TempDir, UpdatePaths) {
        let dir = tempfile::tempdir().expect("tempdir");
        let paths = UpdatePaths::for_package(dir.path());
        let version = Version::new(0, 3, 0);
        let verified = paths.verified(&version);
        std::fs::create_dir_all(&verified).expect("verified dir");
        std::fs::write(verified.join("new.deb"), b"new").expect("new package");
        if let Some(name) = rollback {
            std::fs::write(verified.join(name), b"old").expect("old package");
        }
        PackagePlan {
            format: PackageFormat::Deb,
            package: "new.deb".to_owned(),
            rollback: rollback.map(str::to_owned),
        }
        .store(&verified)
        .expect("plan");
        std::fs::write(dir.path().join("antiwire.libsql"), b"before").expect("database");
        InstallState {
            current: Some(Version::new(0, 2, 0)),
            previous: None,
            pending: Some(PendingInstall {
                version,
                request_id: REQUEST.to_owned(),
                phase: ApplyPhase::Requested,
            }),
            last_error: None,
        }
        .store(&paths.install_state())
        .expect("state");
        (dir, paths)
    }

    fn state(paths: &UpdatePaths) -> InstallState {
        InstallState::load(&paths.install_state()).expect("state")
    }

    #[test]
    fn installs_and_keeps_the_package() {
        let (_dir, paths) = staged(Some("old.deb"));
        let fake = Fake::new(Version::new(0, 2, 0));
        apply(&paths, &Version::new(0, 3, 0), REQUEST, &fake, &fake).expect("installed");

        assert_eq!(fake.log(), ["stop", "install new.deb", "start"]);
        let state = state(&paths);
        assert_eq!(state.current, Some(Version::new(0, 3, 0)));
        assert_eq!(state.previous, Some(Version::new(0, 2, 0)));
        assert_eq!(state.pending, None);
        assert!(paths.installed_packages().join("new.deb").is_file());
        assert!(!paths.verified(&Version::new(0, 3, 0)).exists());
    }

    #[test]
    fn an_unhealthy_daemon_reinstalls_the_previous_package() {
        let (dir, paths) = staged(Some("old.deb"));
        let fake = Fake::new(Version::new(0, 2, 0));
        *fake.fail_healthy_once.borrow_mut() = true;
        // The new daemon writes to the database before it crashes.
        let database = dir.path().join("antiwire.libsql");
        let installer = ReadsStateOnRollback {
            inner: &fake,
            state_path: paths.install_state(),
            read: RefCell::new(None),
        };
        let result = {
            let service = WritesDatabase {
                inner: &fake,
                database: &database,
            };
            apply(
                &paths,
                &Version::new(0, 3, 0),
                REQUEST,
                &service,
                &installer,
            )
        };

        assert!(matches!(result, Err(UpdateError::Unhealthy(_))));
        assert_eq!(
            fake.log(),
            [
                "stop",
                "install new.deb",
                "start",
                "stop",
                "install old.deb (rollback)",
                "start"
            ]
        );
        let state = state(&paths);
        assert_eq!(state.current, Some(Version::new(0, 2, 0)));
        assert_eq!(state.pending, None);
        assert!(state
            .last_error
            .is_some_and(|error| error.contains("crashed")));
        assert_eq!(std::fs::read(&database).expect("database"), b"before");
        assert_eq!(*fake.installed.borrow(), Some(Version::new(0, 2, 0)));
        // The daemon the reinstall starts reads why, and a rollback cut short
        // after that is still recovered.
        let restarted = installer
            .read
            .take()
            .expect("the previous package was reinstalled");
        assert!(restarted
            .last_error
            .is_some_and(|error| error.contains("crashed")));
        assert_eq!(
            restarted.pending.map(|pending| pending.phase),
            Some(ApplyPhase::Swapping)
        );
    }

    #[test]
    fn a_failed_install_without_a_rollback_package_says_so() {
        let (_dir, paths) = staged(None);
        let mut fake = Fake::new(Version::new(0, 2, 0));
        fake.fail_install = true;
        let result = apply(&paths, &Version::new(0, 3, 0), REQUEST, &fake, &fake);

        assert!(matches!(result, Err(UpdateError::Service(_))));
        assert_eq!(fake.log(), ["stop", "install new.deb", "stop", "start"]);
        let error = state(&paths).last_error.expect("recorded");
        assert!(error.contains("dpkg exploded"));
        assert!(error.contains("no package of the previous version"));
    }

    #[test]
    fn a_wrong_installed_version_rolls_back() {
        let (_dir, paths) = staged(Some("old.deb"));
        let mut fake = Fake::new(Version::new(0, 2, 0));
        // The package file claims to be 0.3.0 but installs something else.
        fake.versions[0].1 = Version::new(0, 2, 9);
        let result = apply(&paths, &Version::new(0, 3, 0), REQUEST, &fake, &fake);

        assert!(
            matches!(result, Err(UpdateError::Unhealthy(message)) if message.contains("0.2.9"))
        );
        assert_eq!(state(&paths).current, Some(Version::new(0, 2, 0)));
    }

    #[test]
    fn refuses_a_request_it_was_not_given() {
        let (_dir, paths) = staged(Some("old.deb"));
        let fake = Fake::new(Version::new(0, 2, 0));
        assert!(matches!(
            apply(&paths, &Version::new(0, 3, 0), "other", &fake, &fake),
            Err(UpdateError::NoRequest)
        ));
        assert_eq!(fake.log(), [] as [String; 0]);
    }

    #[test]
    fn recovers_an_interrupted_install() {
        let (_dir, paths) = staged(Some("old.deb"));
        let mut interrupted = state(&paths);
        if let Some(pending) = interrupted.pending.as_mut() {
            pending.phase = ApplyPhase::Swapping;
        }
        interrupted.store(&paths.install_state()).expect("state");

        let fake = Fake::new(Version::new(0, 3, 0));
        recover(&paths, &fake, &fake).expect("recovered");
        assert_eq!(fake.log(), ["stop", "install old.deb (rollback)", "start"]);
        let state = state(&paths);
        assert_eq!(state.pending, None);
        assert_eq!(state.current, Some(Version::new(0, 2, 0)));
    }

    /// Wraps the fake package manager to read the install state when it
    /// reinstalls the previous version, whose post-install script starts the
    /// daemon.
    struct ReadsStateOnRollback<'a> {
        inner: &'a Fake,
        state_path: PathBuf,
        read: RefCell<Option<InstallState>>,
    }

    impl PackageInstaller for ReadsStateOnRollback<'_> {
        fn installed_version(&self, format: PackageFormat) -> Result<Option<Version>, UpdateError> {
            self.inner.installed_version(format)
        }

        fn install(
            &self,
            format: PackageFormat,
            package: &Path,
            rollback: bool,
        ) -> Result<(), UpdateError> {
            self.inner.install(format, package, rollback)?;
            if rollback {
                let state = InstallState::load(&self.state_path).expect("read state");
                self.read.replace(Some(state));
            }
            Ok(())
        }
    }

    /// Wraps the fake service so starting the new version overwrites the
    /// database, as a new daemon running migrations would.
    struct WritesDatabase<'a> {
        inner: &'a Fake,
        database: &'a Path,
    }

    impl DaemonService for WritesDatabase<'_> {
        fn stop(&self, timeout: Duration) -> Result<(), UpdateError> {
            self.inner.stop(timeout)
        }

        fn image(&self) -> Result<PathBuf, UpdateError> {
            self.inner.image()
        }

        fn set_image(&self, daemon_exe: &Path, data_dir: &Path) -> Result<(), UpdateError> {
            self.inner.set_image(daemon_exe, data_dir)
        }

        fn start_healthy(&self, start: Duration, settle: Duration) -> Result<(), UpdateError> {
            if *self.inner.installed.borrow() == Some(Version::new(0, 3, 0)) {
                std::fs::write(self.database, b"migrated").expect("write database");
            }
            self.inner.start_healthy(start, settle)
        }
    }
}
