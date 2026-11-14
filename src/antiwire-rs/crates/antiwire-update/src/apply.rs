//! The swap, run by the one-shot helper process.
//!
//! Steps, from `tasks/update-plan.md`:
//!
//! 1. Accept only a `pending` request in phase `Requested` with a matching id;
//!    move it to `Swapping` and store before touching the service.
//! 2. Stop the service and wait for the daemon process to exit. The reaper may
//!    still be reverting host state; the new daemon waits for it on its own.
//! 3. Copy the database files (`antiwire.libsql` and any `-wal` / `-shm`
//!    beside it) to `db-backup/{version}`.
//! 4. Point the service at the new tree and start it until healthy.
//! 5. Success: `previous = current`, `current = version`, clear `pending`,
//!    delete version trees and staging older than `previous`.
//! 6. Failure: stop, restore the database copy, point back at `previous`,
//!    start, clear `pending`, set `last_error`.

use std::ffi::OsString;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use antiwire_platform::DataPaths;
use semver::Version;

use crate::service_control::{DaemonService, SETTLE_TIME, START_TIMEOUT, STOP_TIMEOUT};
use crate::state::{ApplyPhase, InstallState};
use crate::{UpdateError, UpdatePaths};

/// Applies the requested install.
///
/// # Errors
///
/// [`UpdateError::NoRequest`] when there is no matching request; otherwise the
/// error that made the swap roll back.
pub fn apply(
    paths: &UpdatePaths,
    version: &Version,
    request_id: &str,
    service: &dyn DaemonService,
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
    let new_exe = paths.daemon_exe(version);
    if !new_exe.is_file() {
        let missing = io::Error::from(io::ErrorKind::NotFound);
        let error = UpdateError::io("find", &new_exe, missing);
        return Err(record_failure(&state_path, &mut state, error));
    }
    // A backup left by an earlier attempt must not be restored by this one.
    if let Err(error) = discard_backup(paths, version) {
        return Err(record_failure(&state_path, &mut state, error));
    }

    if let Some(pending) = state.pending.as_mut() {
        pending.phase = ApplyPhase::Swapping;
    }
    state.store(&state_path)?;
    tracing::info!(%version, "swapping the daemon service to the new version");

    match swap(paths, version, service) {
        Ok(()) => commit(paths, &mut state, version, &current),
        Err(cause) => {
            // A rollback failure is already in `last_error`; the swap's own
            // error is what the caller needs to see.
            if let Err(rollback) = roll_back(paths, &mut state, &current, version, service, &cause)
            {
                tracing::error!(error = %rollback, "rollback did not fully succeed");
            }
            Err(cause)
        }
    }
}

/// Rolls back a swap left in phase `Swapping` by a crash or reboot. Does
/// nothing when no swap is pending.
///
/// # Errors
///
/// When the rollback itself fails.
pub fn recover(paths: &UpdatePaths, service: &dyn DaemonService) -> Result<(), UpdateError> {
    let state_path = paths.install_state();
    let mut state = InstallState::load(&state_path)?;
    let Some(pending) = state.pending.clone() else {
        return Ok(());
    };
    if pending.phase != ApplyPhase::Swapping {
        return Ok(());
    }
    let Some(current) = state.current.clone() else {
        let error = UpdateError::Unsupported("install state has no current version".to_owned());
        return Err(record_failure(&state_path, &mut state, error));
    };

    tracing::warn!(version = %pending.version, "rolling back an interrupted swap");
    let cause = UpdateError::Unhealthy(format!("the swap to {} was interrupted", pending.version));
    roll_back(
        paths,
        &mut state,
        &current,
        &pending.version,
        service,
        &cause,
    )
}

/// The steps between the request and the health check. Any error here means
/// the swap must roll back.
fn swap(
    paths: &UpdatePaths,
    version: &Version,
    service: &dyn DaemonService,
) -> Result<(), UpdateError> {
    service.stop(STOP_TIMEOUT)?;
    backup_database(paths, version)?;
    service.set_image(&paths.daemon_exe(version), paths.data_dir())?;
    service.start_healthy(START_TIMEOUT, SETTLE_TIME)
}

/// Makes `version` the current install once its service is healthy, then
/// removes what the install no longer needs.
fn commit(
    paths: &UpdatePaths,
    state: &mut InstallState,
    version: &Version,
    current: &Version,
) -> Result<(), UpdateError> {
    state.previous = Some(current.clone());
    state.current = Some(version.clone());
    state.pending = None;
    state.last_error = None;
    state.store(&paths.install_state())?;
    // A failure leaves the user launching the previous version's client, which
    // keeps working until a later update removes that tree, so it is logged
    // rather than undoing a healthy install.
    if let Err(error) = publish_client(paths, version) {
        tracing::warn!(error = %error, "the new client was not published");
    }
    clean_up(paths, state, version);
    tracing::info!(%version, "update installed");
    Ok(())
}

/// Makes the new client the one the user launches.
///
/// Windows repoints the `current` junction the Start Menu shortcut goes
/// through. macOS replaces `/Applications/Antiwire.app`. A client that is
/// running keeps its old image until the user reopens it.
fn publish_client(paths: &UpdatePaths, version: &Version) -> Result<(), UpdateError> {
    #[cfg(windows)]
    {
        point_current_link(&paths.current_link(), &paths.version_root(version))
    }
    #[cfg(target_os = "macos")]
    {
        publish_app_bundle(&paths.client_exe(version), Path::new(APPLICATIONS_APP))
    }
    #[cfg(not(any(windows, target_os = "macos")))]
    {
        let _ = (paths, version);
        Ok(())
    }
}

/// Repoints the junction `link` at `target`.
///
/// Removing a junction removes only the link. There is no std API that creates
/// one, so this uses `mklink /J`, the same command the installer runs.
#[cfg(windows)]
fn point_current_link(link: &Path, target: &Path) -> Result<(), UpdateError> {
    match fs::remove_dir(link) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(UpdateError::io("remove", link, error)),
    }
    let status = std::process::Command::new("cmd")
        .arg("/c")
        .arg("mklink")
        .arg("/J")
        .arg(link)
        .arg(target)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map_err(|error| UpdateError::io("link", link, error))?;
    if status.success() {
        Ok(())
    } else {
        Err(UpdateError::io(
            "link",
            link,
            io::Error::other(format!("mklink exited with {status}")),
        ))
    }
}

/// Where `packaging/macos/install.sh` puts the app.
#[cfg(target_os = "macos")]
const APPLICATIONS_APP: &str = "/Applications/Antiwire.app";

/// Replaces the app bundle at `app` with a copy of `bundle`.
///
/// The copy is made beside `app` with `ditto`, which keeps the bundle's
/// symlinks and code signature, then swapped in with two renames, so `app` is
/// only ever missing between them. A running copy keeps its open files.
#[cfg(target_os = "macos")]
fn publish_app_bundle(bundle: &Path, app: &Path) -> Result<(), UpdateError> {
    let staged = with_suffix(app, ".new");
    let replaced = with_suffix(app, ".old");
    remove_dir_if_present(&staged)?;
    remove_dir_if_present(&replaced)?;
    let status = std::process::Command::new("/usr/bin/ditto")
        .arg(bundle)
        .arg(&staged)
        .status()
        .map_err(|error| UpdateError::io("copy", bundle, error))?;
    if !status.success() {
        let _ = fs::remove_dir_all(&staged);
        return Err(UpdateError::io(
            "copy",
            bundle,
            io::Error::other(format!("ditto exited with {status}")),
        ));
    }
    if app.exists() {
        fs::rename(app, &replaced).map_err(|error| UpdateError::io("move", app, error))?;
    }
    fs::rename(&staged, app).map_err(|error| UpdateError::io("move", &staged, error))?;
    if let Err(error) = fs::remove_dir_all(&replaced) {
        tracing::warn!(error = %error, "the replaced app bundle was not removed");
    }
    Ok(())
}

/// Puts `current` back in service and records why the swap failed in `state`.
///
/// The database copy is restored only when the backup was completed, because
/// the service must be stopped first. Every step is attempted even after an
/// earlier one fails, except that nothing touches the database or the
/// configuration while the old service might still be running.
///
/// # Errors
///
/// The rollback's own failures. The original cause is recorded in
/// `last_error` and is not part of this error.
fn roll_back(
    paths: &UpdatePaths,
    state: &mut InstallState,
    current: &Version,
    version: &Version,
    service: &dyn DaemonService,
    cause: &UpdateError,
) -> Result<(), UpdateError> {
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
        record(
            &mut failures,
            "the previous version could not be pointed at",
            service.set_image(&paths.daemon_exe(current), paths.data_dir()),
        );
        record(
            &mut failures,
            "the previous version did not start",
            service.start_healthy(START_TIMEOUT, SETTLE_TIME),
        );
    }

    let mut last_error = cause.to_string();
    for failure in &failures {
        last_error.push_str("; ");
        last_error.push_str(failure);
    }
    state.pending = None;
    state.last_error = Some(last_error);
    if let Err(error) = state.store(&paths.install_state()) {
        failures.push(format!("the failure could not be recorded: {error}"));
    }
    if failures.is_empty() {
        Ok(())
    } else {
        Err(UpdateError::Service(format!(
            "rollback failed: {}",
            failures.join("; ")
        )))
    }
}

/// Clears the pending install and records `error` as the reason it failed.
/// For failures before the service was touched.
pub(crate) fn record_failure(
    state_path: &Path,
    state: &mut InstallState,
    error: UpdateError,
) -> UpdateError {
    state.pending = None;
    state.last_error = Some(error.to_string());
    if let Err(store) = state.store(state_path) {
        tracing::error!(error = %store, "could not record the failed install");
    }
    error
}

/// Notes a failed step in `failures`. Returns whether the step succeeded.
pub(crate) fn record(
    failures: &mut Vec<String>,
    action: &str,
    result: Result<(), UpdateError>,
) -> bool {
    match result {
        Ok(()) => true,
        Err(error) => {
            failures.push(format!("{action}: {error}"));
            false
        }
    }
}

/// File names of the database and its SQLite sidecars.
fn database_files(data_dir: &Path) -> Vec<OsString> {
    let database = DataPaths::new(data_dir).database();
    let base = database.file_name().unwrap_or(database.as_os_str());
    ["", "-wal", "-shm"]
        .iter()
        .map(|suffix| {
            let mut name = base.to_os_string();
            name.push(suffix);
            name
        })
        .collect()
}

/// Copies the database into `db-backup/{version}`.
///
/// The copy is written under a partial name and renamed into place only when
/// complete. The final directory therefore exists only for a whole copy, which
/// is how rollback tells a usable backup from none.
pub(crate) fn backup_database(paths: &UpdatePaths, version: &Version) -> Result<(), UpdateError> {
    let target = paths.db_backup(version);
    let partial = with_suffix(&target, ".partial");
    fs::create_dir_all(&partial).map_err(|error| UpdateError::io("create", &partial, error))?;
    if let Err(error) = copy_database(paths.data_dir(), &partial) {
        let _ = fs::remove_dir_all(&partial);
        return Err(error);
    }
    fs::rename(&partial, &target).map_err(|error| UpdateError::io("rename", &partial, error))
}

fn copy_database(data_dir: &Path, dest: &Path) -> Result<(), UpdateError> {
    for name in database_files(data_dir) {
        let source = data_dir.join(&name);
        if let Err(error) = fs::copy(&source, dest.join(&name)) {
            // A sidecar that does not exist is simply not part of the copy.
            if error.kind() != io::ErrorKind::NotFound {
                return Err(UpdateError::io("copy", &source, error));
            }
        }
    }
    Ok(())
}

/// Puts the database back exactly as the backup holds it. A file the backup
/// lacks did not exist before the swap, so it is removed.
pub(crate) fn restore_database(data_dir: &Path, backup: &Path) -> Result<(), UpdateError> {
    for name in database_files(data_dir) {
        let saved = backup.join(&name);
        let live = data_dir.join(&name);
        match fs::copy(&saved, &live) {
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                remove_file_if_present(&live)?;
            }
            Err(error) => return Err(UpdateError::io("restore", &saved, error)),
        }
    }
    Ok(())
}

/// Removes the backup for `version`, complete or partial.
pub(crate) fn discard_backup(paths: &UpdatePaths, version: &Version) -> Result<(), UpdateError> {
    let target = paths.db_backup(version);
    remove_dir_if_present(&with_suffix(&target, ".partial"))?;
    remove_dir_if_present(&target)
}

/// Best-effort removal of version trees and staging the install no longer
/// needs. Failures are logged, because the install has already committed.
fn clean_up(paths: &UpdatePaths, state: &InstallState, version: &Version) {
    let keep: Vec<PathBuf> = state
        .current
        .iter()
        .chain(state.previous.iter())
        .map(|kept| paths.version_root(kept))
        .collect();
    for path in child_paths(&paths.versions_dir()) {
        if !keep.contains(&path) {
            remove_entry(&path);
        }
    }
    clean_staging(paths, version);
}

/// Best-effort removal of every download, verified copy, and database backup
/// once an install has committed.
pub(crate) fn clean_staging(paths: &UpdatePaths, version: &Version) {
    for staging in [
        paths.incoming(version),
        paths.verified(version),
        paths.db_backup(version),
    ] {
        if let Some(parent) = staging.parent() {
            for path in child_paths(parent) {
                remove_entry(&path);
            }
        }
    }
}

fn child_paths(dir: &Path) -> Vec<PathBuf> {
    match fs::read_dir(dir) {
        Ok(entries) => entries.flatten().map(|entry| entry.path()).collect(),
        Err(error) => {
            if error.kind() != io::ErrorKind::NotFound {
                tracing::warn!(dir = %dir.display(), error = %error, "could not list update files");
            }
            Vec::new()
        }
    }
}

fn remove_entry(path: &Path) {
    let removed = if path.is_dir() {
        fs::remove_dir_all(path)
    } else {
        fs::remove_file(path)
    };
    if let Err(error) = removed {
        tracing::warn!(path = %path.display(), error = %error, "could not remove an old update file");
    }
}

/// Removes a file, treating one that is already gone as success.
pub(crate) fn remove_file_if_present(path: &Path) -> Result<(), UpdateError> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(UpdateError::io("remove", path, error)),
    }
}

/// Removes a directory tree, treating one that is already gone as success.
pub(crate) fn remove_dir_if_present(path: &Path) -> Result<(), UpdateError> {
    match fs::remove_dir_all(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(UpdateError::io("remove", path, error)),
    }
}

fn with_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.as_os_str().to_os_string();
    name.push(suffix);
    PathBuf::from(name)
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::time::Duration;

    use super::*;
    use crate::state::PendingInstall;

    const DB: &str = "antiwire.libsql";
    const WAL: &str = "antiwire.libsql-wal";

    #[derive(Debug, PartialEq, Eq)]
    enum Call {
        Stop,
        SetImage(PathBuf),
        Start(PathBuf),
    }

    /// Records every call. Starting the `failing` image first migrates the
    /// database, as a new daemon does, and then fails.
    struct FakeDaemonService {
        data_dir: PathBuf,
        image: RefCell<PathBuf>,
        failing: Option<PathBuf>,
        calls: RefCell<Vec<Call>>,
    }

    impl FakeDaemonService {
        fn new(paths: &UpdatePaths, running: &Version) -> Self {
            Self {
                data_dir: paths.data_dir().to_path_buf(),
                image: RefCell::new(paths.daemon_exe(running)),
                failing: None,
                calls: RefCell::new(Vec::new()),
            }
        }
    }

    impl DaemonService for FakeDaemonService {
        fn stop(&self, _timeout: Duration) -> Result<(), UpdateError> {
            self.calls.borrow_mut().push(Call::Stop);
            Ok(())
        }

        fn image(&self) -> Result<PathBuf, UpdateError> {
            Ok(self.image.borrow().clone())
        }

        fn set_image(&self, daemon_exe: &Path, _data_dir: &Path) -> Result<(), UpdateError> {
            *self.image.borrow_mut() = daemon_exe.to_path_buf();
            self.calls
                .borrow_mut()
                .push(Call::SetImage(daemon_exe.to_path_buf()));
            Ok(())
        }

        fn start_healthy(&self, _start: Duration, _settle: Duration) -> Result<(), UpdateError> {
            let image = self.image.borrow().clone();
            self.calls.borrow_mut().push(Call::Start(image.clone()));
            if self.failing.as_ref() == Some(&image) {
                fs::write(self.data_dir.join(DB), b"migrated").expect("migrate db");
                fs::write(self.data_dir.join(WAL), b"wal").expect("write wal");
                return Err(UpdateError::Unhealthy("the new daemon exited".to_owned()));
            }
            Ok(())
        }
    }

    struct Fixture {
        _dir: tempfile::TempDir,
        paths: UpdatePaths,
    }

    fn version(text: &str) -> Version {
        Version::parse(text).expect("test version")
    }

    fn old() -> Version {
        version("1.0.0")
    }

    fn new() -> Version {
        version("1.1.0")
    }

    fn add_daemon(paths: &UpdatePaths, version: &Version) {
        let exe = paths.daemon_exe(version);
        fs::create_dir_all(exe.parent().expect("daemon dir")).expect("daemon dir");
        fs::write(exe, b"daemon").expect("daemon exe");
    }

    fn fixture() -> Fixture {
        let dir = tempfile::tempdir().expect("temp dir");
        let data = dir.path().join("data");
        fs::create_dir_all(&data).expect("data dir");
        let paths = UpdatePaths::new(&data, dir.path().join("install"));
        add_daemon(&paths, &old());
        add_daemon(&paths, &new());
        fs::write(data.join(DB), b"schema-1").expect("db");
        Fixture { _dir: dir, paths }
    }

    fn pending(phase: ApplyPhase) -> PendingInstall {
        PendingInstall {
            version: new(),
            request_id: "req-1".to_owned(),
            phase,
        }
    }

    fn save(paths: &UpdatePaths, state: &InstallState) {
        state.store(&paths.install_state()).expect("save state");
    }

    fn load(paths: &UpdatePaths) -> InstallState {
        InstallState::load(&paths.install_state()).expect("load state")
    }

    #[test]
    fn success_commits_state_and_removes_stale_trees() {
        let fx = fixture();
        let paths = &fx.paths;
        add_daemon(paths, &version("0.9.0"));
        fs::create_dir_all(paths.incoming(&new())).expect("incoming");
        save(
            paths,
            &InstallState {
                current: Some(old()),
                previous: None,
                pending: Some(pending(ApplyPhase::Requested)),
                last_error: Some("an earlier failure".to_owned()),
            },
        );
        let service = FakeDaemonService::new(paths, &old());

        apply(paths, &new(), "req-1", &service).expect("apply");

        assert_eq!(
            *service.calls.borrow(),
            vec![
                Call::Stop,
                Call::SetImage(paths.daemon_exe(&new())),
                Call::Start(paths.daemon_exe(&new())),
            ]
        );
        assert_eq!(
            load(paths),
            InstallState {
                current: Some(new()),
                previous: Some(old()),
                pending: None,
                last_error: None,
            }
        );
        assert!(!paths.version_root(&version("0.9.0")).exists());
        assert!(paths.version_root(&old()).exists());
        assert!(!paths.incoming(&new()).exists());
        assert!(!paths.db_backup(&new()).exists());
        // The shortcut's link now leads into the new tree.
        #[cfg(windows)]
        assert_eq!(
            fs::canonicalize(paths.current_link()).expect("link resolves"),
            fs::canonicalize(paths.version_root(&new())).expect("new tree")
        );
    }

    #[test]
    fn mismatched_request_id_is_refused_without_touching_the_service() {
        let fx = fixture();
        let paths = &fx.paths;
        let state = InstallState {
            current: Some(old()),
            previous: None,
            pending: Some(pending(ApplyPhase::Requested)),
            last_error: None,
        };
        save(paths, &state);
        let service = FakeDaemonService::new(paths, &old());

        let error = apply(paths, &new(), "not-the-request", &service).expect_err("refused");

        assert!(matches!(error, UpdateError::NoRequest));
        assert!(service.calls.borrow().is_empty());
        assert_eq!(load(paths), state);
    }

    #[test]
    fn a_request_already_swapping_is_not_applied_again() {
        let fx = fixture();
        let paths = &fx.paths;
        save(
            paths,
            &InstallState {
                current: Some(old()),
                previous: None,
                pending: Some(pending(ApplyPhase::Swapping)),
                last_error: None,
            },
        );
        let service = FakeDaemonService::new(paths, &old());

        let error = apply(paths, &new(), "req-1", &service).expect_err("refused");

        assert!(matches!(error, UpdateError::NoRequest));
        assert!(service.calls.borrow().is_empty());
    }

    #[test]
    fn failed_start_restores_database_and_previous_image() {
        let fx = fixture();
        let paths = &fx.paths;
        save(
            paths,
            &InstallState {
                current: Some(old()),
                previous: None,
                pending: Some(pending(ApplyPhase::Requested)),
                last_error: None,
            },
        );
        let service = FakeDaemonService {
            failing: Some(paths.daemon_exe(&new())),
            ..FakeDaemonService::new(paths, &old())
        };

        let error = apply(paths, &new(), "req-1", &service).expect_err("start fails");

        assert!(matches!(error, UpdateError::Unhealthy(_)));
        assert_eq!(
            *service.calls.borrow(),
            vec![
                Call::Stop,
                Call::SetImage(paths.daemon_exe(&new())),
                Call::Start(paths.daemon_exe(&new())),
                Call::Stop,
                Call::SetImage(paths.daemon_exe(&old())),
                Call::Start(paths.daemon_exe(&old())),
            ]
        );
        let data = paths.data_dir();
        assert_eq!(fs::read(data.join(DB)).expect("db"), b"schema-1");
        assert!(
            !data.join(WAL).exists(),
            "wal absent before the swap must go"
        );
        let state = load(paths);
        assert_eq!(state.current, Some(old()));
        assert_eq!(state.previous, None);
        assert_eq!(state.pending, None);
        assert_eq!(
            state.last_error.as_deref(),
            Some("the new version did not start correctly: the new daemon exited")
        );
    }

    #[test]
    fn missing_daemon_exe_fails_before_the_service_is_touched() {
        let fx = fixture();
        let paths = &fx.paths;
        fs::remove_file(paths.daemon_exe(&new())).expect("remove exe");
        save(
            paths,
            &InstallState {
                current: Some(old()),
                previous: None,
                pending: Some(pending(ApplyPhase::Requested)),
                last_error: None,
            },
        );
        let service = FakeDaemonService::new(paths, &old());

        let error = apply(paths, &new(), "req-1", &service).expect_err("missing exe");

        assert!(matches!(error, UpdateError::Io { .. }));
        assert!(service.calls.borrow().is_empty());
        let state = load(paths);
        assert_eq!(state.pending, None);
        assert!(state.last_error.is_some());
    }

    #[test]
    fn recover_with_a_swap_in_progress_rolls_back() {
        let fx = fixture();
        let paths = &fx.paths;
        save(
            paths,
            &InstallState {
                current: Some(old()),
                previous: None,
                pending: Some(pending(ApplyPhase::Swapping)),
                last_error: None,
            },
        );
        let backup = paths.db_backup(&new());
        fs::create_dir_all(&backup).expect("backup");
        fs::write(backup.join(DB), b"schema-1").expect("backup db");
        fs::write(paths.data_dir().join(DB), b"migrated").expect("migrated db");
        // The interrupted swap had already pointed the service at the new tree.
        let service = FakeDaemonService::new(paths, &new());

        recover(paths, &service).expect("recover");

        assert_eq!(
            *service.calls.borrow(),
            vec![
                Call::Stop,
                Call::SetImage(paths.daemon_exe(&old())),
                Call::Start(paths.daemon_exe(&old())),
            ]
        );
        assert_eq!(
            fs::read(paths.data_dir().join(DB)).expect("db"),
            b"schema-1"
        );
        let state = load(paths);
        assert_eq!(state.current, Some(old()));
        assert_eq!(state.pending, None);
    }

    #[test]
    fn recover_without_a_backup_leaves_the_database_alone() {
        let fx = fixture();
        let paths = &fx.paths;
        save(
            paths,
            &InstallState {
                current: Some(old()),
                previous: None,
                pending: Some(pending(ApplyPhase::Swapping)),
                last_error: None,
            },
        );
        let service = FakeDaemonService::new(paths, &old());

        recover(paths, &service).expect("recover");

        assert_eq!(
            fs::read(paths.data_dir().join(DB)).expect("db"),
            b"schema-1"
        );
        assert_eq!(load(paths).pending, None);
    }

    #[test]
    fn recover_with_nothing_to_roll_back_makes_no_service_calls() {
        let fx = fixture();
        let paths = &fx.paths;
        let service = FakeDaemonService::new(paths, &old());

        save(
            paths,
            &InstallState {
                current: Some(old()),
                previous: None,
                pending: None,
                last_error: None,
            },
        );
        recover(paths, &service).expect("no pending");

        save(
            paths,
            &InstallState {
                current: Some(old()),
                previous: None,
                pending: Some(pending(ApplyPhase::Requested)),
                last_error: None,
            },
        );
        recover(paths, &service).expect("requested but not started");

        assert!(service.calls.borrow().is_empty());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn publishing_replaces_the_app_bundle() {
        let dir = tempfile::tempdir().expect("tempdir");
        let bundle = |name: &str, marker: &str| {
            let path = dir.path().join(name).join("Antiwire.app");
            fs::create_dir_all(path.join("Contents")).expect("bundle");
            fs::write(path.join("Contents").join("marker"), marker).expect("marker");
            path
        };
        let app = dir.path().join("Applications").join("Antiwire.app");
        fs::create_dir_all(app.parent().expect("parent")).expect("applications");

        publish_app_bundle(&bundle("v1", "one"), &app).expect("first publish");
        publish_app_bundle(&bundle("v2", "two"), &app).expect("second publish");

        let marker = fs::read_to_string(app.join("Contents").join("marker")).expect("marker");
        assert_eq!(marker, "two");
        assert!(!with_suffix(&app, ".new").exists());
        assert!(!with_suffix(&app, ".old").exists());
    }
}
