//! Running as a Windows service: the SCM dispatcher and the status the SCM
//! is told. The `windows_service` crate is reached as `::windows_service`.

use anyhow::{Context, Result};

use crate::daemon::shutdown_signal::service_stop_requested;
use antiwire_platform::crash;

use crate::daemon::{block_on_bounded, run_daemon, DaemonHost};
use crate::Cli;

/// Command line, and the data directory it resolves to, captured before the
/// SCM dispatcher takes over.
///
/// `service_main` runs on a thread the SCM owns, and a clap parse failure exits the
/// process outright — which inside `service_main` means exiting without ever having
/// reported a status. Parsing in `crate::run` keeps that failure on the ordinary path.
pub(crate) static SERVICE_CLI: std::sync::OnceLock<(Cli, std::path::PathBuf)> =
    std::sync::OnceLock::new();

pub(crate) fn run_windows_service_mode() -> Result<()> {
    ::windows_service::define_windows_service!(ffi_service_main, service_main);
    ::windows_service::service_dispatcher::start("AntiwireDaemon", ffi_service_main)
        .context("service dispatcher")
}

fn service_main(_arguments: Vec<std::ffi::OsString>) {
    if let Err(e) = run_windows_service() {
        tracing::error!(error = %e, "service failed");
        crash::record_fatal_error(format_args!("service failed: {e:#}"));
    }
}

/// Start budget reported to the SCM. Startup captures adapter DNS, applies the
/// redirect, and installs every persisted firewall rule, none of which is instant.
const SERVICE_START_WAIT_HINT: std::time::Duration = std::time::Duration::from_secs(60);

/// Stop budget reported to the SCM, covering the runtime's teardown: the
/// reverts and the drain together within `SHUTDOWN_DRAIN_TIMEOUT`, then up to
/// `PROCESS_EXIT_BLOCKING_TIMEOUT` for blocking work still running.
///
/// Only honoured for a `Stop`. Once the machine is going down the SCM stops
/// consulting wait hints and applies the system-wide `WaitToKillServiceTimeout`
/// (5s by default) to every service at once, which this teardown cannot fit in.
/// That is what `SERVICE_ACCEPT_PRESHUTDOWN` is for: preshutdown is delivered
/// first, sequentially, while the network stack and the firewall service are
/// still up, and carries its own per-service timeout (`PreshutdownTimeout`,
/// 180s by default) instead of the shared one.
const SERVICE_STOP_WAIT_HINT: std::time::Duration = std::time::Duration::from_secs(30);

/// The controls the service accepts in `state`: a stop, whether from `sc
/// stop` or a machine going down, from the moment it starts until it is
/// stopping.
///
/// Including while it starts. The start redirects DNS early on, and a
/// machine shut down then would otherwise skip the service's preshutdown and
/// kill it with DNS still redirected. A stop that arrives while starting
/// lets the start finish and then stops at once; see `run_daemon`.
fn controls_accepted(
    state: ::windows_service::service::ServiceState,
) -> ::windows_service::service::ServiceControlAccept {
    use ::windows_service::service::{ServiceControlAccept, ServiceState};

    match state {
        ServiceState::StartPending | ServiceState::Running => {
            ServiceControlAccept::STOP
                | ServiceControlAccept::PRESHUTDOWN
                | ServiceControlAccept::SHUTDOWN
        }
        _ => ServiceControlAccept::empty(),
    }
}

#[allow(clippy::too_many_lines)]
fn run_windows_service() -> Result<()> {
    use ::windows_service::service::{
        ServiceControl, ServiceExitCode, ServiceState, ServiceStatus, ServiceType,
    };
    use ::windows_service::service_control_handler::{self, ServiceControlHandlerResult};
    use std::time::Duration;

    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);

    let event_handler = move |control_event| -> ServiceControlHandlerResult {
        match control_event {
            // All three mean the same thing to this daemon: revert the host and go.
            // Preshutdown is the one that makes the machine-off case survivable —
            // see `SERVICE_STOP_WAIT_HINT` for why Shutdown alone is not enough.
            ServiceControl::Stop | ServiceControl::Preshutdown | ServiceControl::Shutdown => {
                let _ = shutdown_tx.send(true);
                ServiceControlHandlerResult::NoError
            }
            // Interrogate must be acknowledged; the SCM re-reads status on its own.
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            _ => ServiceControlHandlerResult::NotImplemented,
        }
    };

    let status_handle = service_control_handler::register("AntiwireDaemon", event_handler)
        .map_err(|e| anyhow::anyhow!("register handler: {e}"))?;

    let report = |state: ServiceState, exit_code: ServiceExitCode, wait_hint: Duration| {
        let controls_accepted = controls_accepted(state);
        // A pending state must carry a non-zero checkpoint, and a settled one must not.
        let checkpoint = u32::from(matches!(
            state,
            ServiceState::StartPending | ServiceState::StopPending
        ));
        if let Err(error) = status_handle.set_service_status(ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: state,
            controls_accepted,
            exit_code,
            checkpoint,
            wait_hint,
            process_id: None,
        }) {
            tracing::error!(error = %error, ?state, "failed to report service status");
        }
    };

    report(
        ServiceState::StartPending,
        ServiceExitCode::Win32(0),
        SERVICE_START_WAIT_HINT,
    );

    let result = (|| -> Result<()> {
        let (cli, data_dir) = SERVICE_CLI
            .get()
            .cloned()
            .context("service command line was not captured before dispatch")?;

        // Bounded, so a stuck native call cannot hold the service in
        // StopPending; see `block_on_bounded`.
        block_on_bounded(run_daemon(
            cli,
            data_dir,
            async {
                service_stop_requested(shutdown_rx).await;
                // Teardown drains the DNS restore, the download schedulers, and the
                // final flow flush; the SCM needs to know that is underway or it
                // times the stop out and kills the process mid-shutdown.
                report(
                    ServiceState::StopPending,
                    ServiceExitCode::Win32(0),
                    SERVICE_STOP_WAIT_HINT,
                );
            },
            || {
                report(
                    ServiceState::Running,
                    ServiceExitCode::Win32(0),
                    Duration::ZERO,
                );
            },
            DaemonHost::Service,
        ))?
    })();

    // Reported unconditionally, including on a failed start. Without it the SCM waits
    // out its timeout and surfaces error 1053, and `sc stop` hangs — the unclean exit
    // that leaves adapter DNS pointed at the loopback stub.
    let exit_code = match &result {
        Ok(()) => ServiceExitCode::Win32(0),
        Err(error) => {
            tracing::error!(error = %error, "antiwire-daemon exited with an error");
            ServiceExitCode::ServiceSpecific(1)
        }
    };
    report(ServiceState::Stopped, exit_code, Duration::ZERO);

    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use ::windows_service::service::{ServiceControlAccept, ServiceState};

    const STOPS: ServiceControlAccept = ServiceControlAccept::STOP
        .union(ServiceControlAccept::PRESHUTDOWN)
        .union(ServiceControlAccept::SHUTDOWN);

    /// The regression this guards: a starting service accepted no control,
    /// so a machine shut down mid-start skipped preshutdown and killed it
    /// with DNS still redirected.
    #[test]
    fn a_starting_service_accepts_a_stop() {
        assert_eq!(controls_accepted(ServiceState::StartPending), STOPS);
        assert_eq!(controls_accepted(ServiceState::Running), STOPS);
    }

    #[test]
    fn a_stopping_service_accepts_nothing_more() {
        assert!(controls_accepted(ServiceState::StopPending).is_empty());
        assert!(controls_accepted(ServiceState::Stopped).is_empty());
    }
}
