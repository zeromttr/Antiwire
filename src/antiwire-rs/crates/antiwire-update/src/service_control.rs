//! Controls the platform service that runs the daemon.

use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::UpdateError;

#[cfg(any(target_os = "macos", test))]
mod launchd;
#[cfg(target_os = "macos")]
pub use launchd::LaunchdDaemonService;

// Built on every platform: it only runs `systemctl`, and its parsing is tested
// everywhere.
mod systemd;
pub use systemd::SystemdDaemonService;

/// How long a stop may take. Matches the installer's wait.
pub const STOP_TIMEOUT: Duration = Duration::from_secs(90);
/// How long the new daemon has to report running.
pub const START_TIMEOUT: Duration = Duration::from_secs(60);
/// How long a started daemon must stay running before it counts as healthy.
pub const SETTLE_TIME: Duration = Duration::from_secs(15);

/// The daemon service. A trait so the swap logic is tested without a real
/// service manager.
pub trait DaemonService {
    /// Stops the service and returns once its process has exited.
    ///
    /// # Errors
    ///
    /// [`UpdateError::Service`] when it is still running after `timeout`.
    fn stop(&self, timeout: Duration) -> Result<(), UpdateError>;

    /// The executable the service is configured to run.
    ///
    /// # Errors
    ///
    /// [`UpdateError::Service`] when the configuration cannot be read.
    fn image(&self) -> Result<PathBuf, UpdateError>;

    /// Points the service at `daemon_exe --data-dir {data_dir}`. Called only
    /// while the service is stopped.
    ///
    /// # Errors
    ///
    /// [`UpdateError::Service`] when the configuration cannot be changed.
    fn set_image(&self, daemon_exe: &Path, data_dir: &Path) -> Result<(), UpdateError>;

    /// Starts the service and returns once it is healthy: it reports running
    /// within `start_timeout` and the same process is still running after
    /// `settle`. On Windows the daemon reports running only after its gRPC
    /// listener is bound; launchd reports it as soon as the process exists.
    ///
    /// # Errors
    ///
    /// [`UpdateError::Unhealthy`] otherwise.
    fn start_healthy(&self, start_timeout: Duration, settle: Duration) -> Result<(), UpdateError>;
}

/// The `AntiwireDaemon` Windows service.
#[cfg(windows)]
#[derive(Debug, Default, Clone, Copy)]
pub struct WindowsDaemonService;

#[cfg(windows)]
const SERVICE_NAME: &str = "AntiwireDaemon";

/// How often the service state is polled while waiting for a transition.
const POLL_INTERVAL: Duration = Duration::from_millis(500);

#[cfg(windows)]
impl DaemonService for WindowsDaemonService {
    fn stop(&self, timeout: Duration) -> Result<(), UpdateError> {
        use windows_service::service::{ServiceAccess, ServiceState};

        let service = open_service(ServiceAccess::QUERY_STATUS | ServiceAccess::STOP)?;
        let status = service
            .query_status()
            .map_err(|error| service_error("read the service status", &error))?;
        if status.current_state == ServiceState::Stopped {
            return Ok(());
        }
        // Not `status.process_id`, which windows-service fills in only for a
        // running service. A rollback can stop one that is still starting or
        // already stopping, and its process must be gone before the database is
        // restored.
        let process_id = service_process_id(&service)?;
        // A stop already pending would be refused, so only send one when none is in flight.
        if status.current_state != ServiceState::StopPending {
            service
                .stop()
                .map_err(|error| service_error("stop the service", &error))?;
        }

        let deadline = std::time::Instant::now() + timeout;
        loop {
            let state = service
                .query_status()
                .map_err(|error| service_error("read the service status", &error))?
                .current_state;
            if state == ServiceState::Stopped {
                break;
            }
            if std::time::Instant::now() >= deadline {
                return Err(UpdateError::Service(format!(
                    "the service did not stop within {} seconds",
                    timeout.as_secs()
                )));
            }
            std::thread::sleep(POLL_INTERVAL);
        }

        // The service reports stopped a moment before its process is gone. The
        // revert of host state runs after that, so wait for the process itself.
        match process_id {
            Some(pid) => wait_for_process_exit(
                pid,
                deadline.saturating_duration_since(std::time::Instant::now()),
            ),
            None => Ok(()),
        }
    }

    fn image(&self) -> Result<PathBuf, UpdateError> {
        use windows_service::service::ServiceAccess;

        let service = open_service(ServiceAccess::QUERY_CONFIG)?;
        let config = service
            .query_config()
            .map_err(|error| service_error("read the service configuration", &error))?;
        // The SCM stores the whole command line, arguments included.
        Ok(executable_of(&config.executable_path.to_string_lossy()))
    }

    fn set_image(&self, daemon_exe: &Path, data_dir: &Path) -> Result<(), UpdateError> {
        use std::ffi::OsString;
        use windows_service::service::{ServiceAccess, ServiceInfo};

        let service = open_service(ServiceAccess::QUERY_CONFIG | ServiceAccess::CHANGE_CONFIG)?;
        let config = service
            .query_config()
            .map_err(|error| service_error("read the service configuration", &error))?;
        let info = ServiceInfo {
            name: OsString::from(SERVICE_NAME),
            display_name: config.display_name,
            service_type: config.service_type,
            start_type: config.start_type,
            error_control: config.error_control,
            executable_path: daemon_exe.to_path_buf(),
            launch_arguments: vec![
                OsString::from("--data-dir"),
                data_dir.as_os_str().to_os_string(),
            ],
            dependencies: config.dependencies,
            account_name: config.account_name,
            // None keeps the password the service already has.
            account_password: None,
        };
        service
            .change_config(&info)
            .map_err(|error| service_error("change the service configuration", &error))
    }

    fn start_healthy(&self, start_timeout: Duration, settle: Duration) -> Result<(), UpdateError> {
        use windows_service::service::{ServiceAccess, ServiceState};

        let service = open_service(ServiceAccess::QUERY_STATUS | ServiceAccess::START)?;
        service.start(&[] as &[&str]).map_err(|error| {
            UpdateError::Unhealthy(format!("the service did not start: {error}"))
        })?;

        let deadline = std::time::Instant::now() + start_timeout;
        let pid = loop {
            let status = service
                .query_status()
                .map_err(|error| service_error("read the service status", &error))?;
            match status.current_state {
                ServiceState::Running => break status.process_id,
                ServiceState::Stopped => {
                    return Err(UpdateError::Unhealthy(
                        "the service stopped right after it started".to_owned(),
                    ));
                }
                _ => {}
            }
            if std::time::Instant::now() >= deadline {
                return Err(UpdateError::Unhealthy(format!(
                    "the service did not report running within {} seconds",
                    start_timeout.as_secs()
                )));
            }
            std::thread::sleep(POLL_INTERVAL);
        };

        std::thread::sleep(settle);
        let status = service
            .query_status()
            .map_err(|error| service_error("read the service status", &error))?;
        if status.current_state != ServiceState::Running || status.process_id != pid {
            return Err(UpdateError::Unhealthy(
                "the service stopped or restarted during the settle window".to_owned(),
            ));
        }
        Ok(())
    }
}

/// Opens the daemon service with only the access the caller needs.
#[cfg(windows)]
fn open_service(
    access: windows_service::service::ServiceAccess,
) -> Result<windows_service::service::Service, UpdateError> {
    use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
        .map_err(|error| service_error("connect to the service manager", &error))?;
    manager
        .open_service(SERVICE_NAME, access)
        .map_err(|error| service_error("open the Antiwire service", &error))
}

/// The id of `service`'s process, or `None` when it has none because it is
/// stopped.
///
/// windows-service's `query_status` reads the same structure but reports the
/// process only for a running service. `QueryServiceStatusEx` with
/// `SC_STATUS_PROCESS_INFO` fills a `SERVICE_STATUS_PROCESS`, whose
/// `dwProcessId` is the service's process, and zero once it is stopped:
/// <https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-queryservicestatusex>,
/// <https://learn.microsoft.com/en-us/windows/win32/api/winsvc/ns-winsvc-service_status_process>.
///
/// # Errors
///
/// [`UpdateError::Service`] when the status cannot be read, for one because
/// the handle lacks `SERVICE_QUERY_STATUS`.
#[cfg(windows)]
#[expect(
    unsafe_code,
    reason = "QueryServiceStatusEx: windows-service drops the process id of a service that is not running"
)]
fn service_process_id(
    service: &windows_service::service::Service,
) -> Result<Option<u32>, UpdateError> {
    use windows::Win32::System::Services::{
        QueryServiceStatusEx, SC_HANDLE, SC_STATUS_PROCESS_INFO, SERVICE_STATUS_PROCESS,
    };

    let mut status = SERVICE_STATUS_PROCESS::default();
    let mut needed = 0_u32;
    // SAFETY: `service` owns the handle and keeps it open for the call. The
    // buffer is `status`, a whole `SERVICE_STATUS_PROCESS` that lives across
    // the call: exactly what `SC_STATUS_PROCESS_INFO` writes, with its own
    // alignment, and the slice's length is its size. `needed` is a valid
    // out-pointer. The structure is read only after the call succeeded.
    let queried = unsafe {
        let buffer = std::slice::from_raw_parts_mut(
            (&raw mut status).cast::<u8>(),
            std::mem::size_of::<SERVICE_STATUS_PROCESS>(),
        );
        QueryServiceStatusEx(
            SC_HANDLE(service.raw_handle()),
            SC_STATUS_PROCESS_INFO,
            Some(buffer),
            &raw mut needed,
        )
    };
    queried.map_err(|error| {
        UpdateError::Service(format!("could not read the service status: {error}"))
    })?;
    Ok((status.dwProcessId != 0).then_some(status.dwProcessId))
}

#[cfg(windows)]
fn service_error(action: &str, error: &windows_service::Error) -> UpdateError {
    UpdateError::Service(format!("could not {action}: {error}"))
}

/// The executable from a service command line such as
/// `"C:\...\antiwire-daemon.exe" --data-dir "C:\...\Antiwire"`.
///
/// A quoted path ends at its closing quote. An unquoted one ends at the first
/// space, so a path with spaces must be quoted, as the installer writes it.
#[cfg(any(windows, test))]
fn executable_of(command_line: &str) -> PathBuf {
    let trimmed = command_line.trim_start();
    if let Some(quoted) = trimmed.strip_prefix('"') {
        return PathBuf::from(quoted.split('"').next().unwrap_or_default());
    }
    PathBuf::from(trimmed.split_whitespace().next().unwrap_or_default())
}

/// Waits until the process `pid` exits, or `timeout` passes.
///
/// # Errors
///
/// [`UpdateError::Service`] when the process is still running after `timeout`.
///
/// A process that cannot be opened, for lack of access say, is not taken
/// for gone: the open is retried until `timeout`. See
/// [`antiwire_platform::process_wait::wait_for_exit`].
#[cfg(windows)]
fn wait_for_process_exit(pid: u32, timeout: Duration) -> Result<(), UpdateError> {
    use antiwire_platform::process_wait::{wait_for_exit, ProcessWait};

    match wait_for_exit(pid, Some(std::time::Instant::now() + timeout)) {
        ProcessWait::Exited => Ok(()),
        ProcessWait::TimedOut => Err(UpdateError::Service(format!(
            "process {pid} did not exit within the stop timeout"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quoted_command_line_yields_only_the_executable() {
        let line = r#""C:\Program Files\Antiwire\versions\1.2.0\daemon\antiwire-daemon.exe" --data-dir "C:\ProgramData\Antiwire""#;
        assert_eq!(
            executable_of(line),
            PathBuf::from(r"C:\Program Files\Antiwire\versions\1.2.0\daemon\antiwire-daemon.exe")
        );
    }

    #[test]
    fn unquoted_command_line_yields_the_first_token() {
        assert_eq!(
            executable_of(r"C:\aw\antiwire-daemon.exe --data-dir C:\data"),
            PathBuf::from(r"C:\aw\antiwire-daemon.exe")
        );
    }

    /// The Remote Procedure Call service runs on every Windows machine, and
    /// any account can read its status.
    #[cfg(windows)]
    fn rpc_service(
        access: windows_service::service::ServiceAccess,
    ) -> windows_service::service::Service {
        use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

        ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
            .expect("service manager")
            .open_service("RpcSs", access)
            .expect("open RpcSs")
    }

    #[cfg(windows)]
    #[test]
    fn reads_the_process_of_a_running_service() {
        let service = rpc_service(windows_service::service::ServiceAccess::QUERY_STATUS);
        let reported = service.query_status().expect("status").process_id;
        assert!(reported.is_some(), "RpcSs is running");
        assert_eq!(service_process_id(&service).expect("process id"), reported);
    }

    #[cfg(windows)]
    #[test]
    fn a_handle_without_status_access_is_refused() {
        let service = rpc_service(windows_service::service::ServiceAccess::QUERY_CONFIG);
        assert!(service_process_id(&service).is_err());
    }
}
