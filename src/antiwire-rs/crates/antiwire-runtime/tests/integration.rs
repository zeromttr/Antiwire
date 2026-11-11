use antiwire_enforce::{EnforceError, EnforcementClient, FirewallFilter};
use antiwire_ipc::{GrpcServer, IpcEndpoint, IpcPaths};
use antiwire_policy::EnforcementOp;
use antiwire_runtime::AntiwireRuntime;
use std::time::Duration;
use tempfile::tempdir;

// Offline CI has neither PF root access nor Linux NET_ADMIN capability.
#[derive(Default)]
struct TestFirewall {
    started: bool,
}

impl FirewallFilter for TestFirewall {
    fn start(&mut self) -> antiwire_enforce::Result<()> {
        self.started = true;
        Ok(())
    }

    fn stop(&mut self) -> antiwire_enforce::Result<()> {
        self.started = false;
        Ok(())
    }

    fn is_enforcing(&self) -> bool {
        self.started
    }

    fn apply(&mut self, _op: EnforcementOp) -> antiwire_enforce::Result<()> {
        if self.started {
            Ok(())
        } else {
            Err(EnforceError::NotStarted)
        }
    }
}

struct FailingStartFirewall;

impl FirewallFilter for FailingStartFirewall {
    fn start(&mut self) -> antiwire_enforce::Result<()> {
        Err(EnforceError::InvalidOp(
            "injected firewall start failure".into(),
        ))
    }

    fn stop(&mut self) -> antiwire_enforce::Result<()> {
        Ok(())
    }

    fn is_enforcing(&self) -> bool {
        false
    }

    fn apply(&mut self, _op: EnforcementOp) -> antiwire_enforce::Result<()> {
        Err(EnforceError::NotStarted)
    }
}

fn test_runtime() -> (tempfile::TempDir, AntiwireRuntime) {
    let dir = tempdir().expect("tempdir");
    let enforce = EnforcementClient::with_filter(TestFirewall::default()).expect("firewall worker");
    let runtime =
        AntiwireRuntime::bootstrap_with_enforcement(dir.path(), enforce).expect("bootstrap");
    (dir, runtime)
}

#[tokio::test]
async fn bootstrap_start_stop() {
    let (_dir, runtime) = test_runtime();
    runtime.start().await.expect("start");
    runtime.stop().await.expect("stop");
}

#[tokio::test]
async fn stop_without_start_succeeds() {
    let (_dir, runtime) = test_runtime();
    runtime.stop().await.expect("stop without start");
}

#[tokio::test]
async fn stop_is_idempotent() {
    let (_dir, runtime) = test_runtime();
    runtime.start().await.expect("start");
    runtime.stop().await.expect("stop");
    runtime.stop().await.expect("second stop");
}

#[tokio::test]
async fn start_is_single_use() {
    let (_dir, runtime) = test_runtime();
    runtime.start().await.expect("start");
    let already = runtime.start().await.expect_err("second start");
    let already_message = format!("{already:#}");
    assert!(
        already_message.contains("already started"),
        "unexpected second-start error: {already_message}"
    );
    runtime.stop().await.expect("stop");
    let restart = runtime.start().await.expect_err("start after stop");
    let restart_message = format!("{restart:#}");
    assert!(
        restart_message.contains("cannot be restarted"),
        "unexpected restart error: {restart_message}"
    );
}

#[tokio::test]
async fn failed_start_rolls_back_and_cannot_be_retried() {
    let dir = tempdir().expect("tempdir");
    let enforce = EnforcementClient::with_filter(FailingStartFirewall).expect("firewall worker");
    let runtime =
        AntiwireRuntime::bootstrap_with_enforcement(dir.path(), enforce).expect("bootstrap");

    let error = runtime.start().await.expect_err("start should fail");
    let message = format!("{error:#}");
    assert!(
        message.contains("injected firewall start failure"),
        "unexpected start error: {message}"
    );
    runtime.stop().await.expect("stop after failed start");
    let retry = runtime.start().await.expect_err("retry after failed start");
    assert!(
        retry.to_string().contains("cannot be restarted"),
        "unexpected retry error: {retry:#}"
    );
}

#[tokio::test]
async fn the_ipc_server_is_built_from_the_runtime() {
    let dir = tempdir().expect("tempdir");
    let enforce = EnforcementClient::with_filter(TestFirewall::default()).expect("firewall worker");
    let runtime =
        AntiwireRuntime::bootstrap_with_enforcement(dir.path(), enforce).expect("bootstrap");
    let endpoint = IpcEndpoint::platform_default();
    let server = GrpcServer::new(
        endpoint.clone(),
        IpcPaths::beside(dir.path().join("ipc.token")),
        runtime.ipc_service_parts(),
    );
    assert_eq!(server.endpoint(), &endpoint);
}

#[tokio::test(flavor = "current_thread")]
async fn start_stop_does_not_deadlock_on_current_thread_runtime() {
    let (_dir, runtime) = test_runtime();
    tokio::time::timeout(Duration::from_secs(20), async {
        runtime.start().await.expect("start");
        runtime.stop().await.expect("stop");
    })
    .await
    .expect("start/stop deadlocked on the current-thread runtime");
}
