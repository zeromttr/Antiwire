use std::panic::{self, AssertUnwindSafe};
use std::sync::mpsc::{self, Receiver, SyncSender, TrySendError};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::Duration;

use antiwire_policy::EnforcementOp;

use crate::filter::FirewallFilter;
use crate::firew::FirewFilter;
use crate::{EnforceError, Result};

const COMMAND_QUEUE_CAPACITY: usize = 256;

/// How long dropping the worker waits for its thread to finish.
///
/// A native call that never returns would otherwise hold the dropping
/// thread, and with it process exit, forever. Past this the thread is left
/// to end with the process.
const WORKER_JOIN_TIMEOUT: Duration = if cfg!(test) {
    Duration::from_millis(200)
} else {
    Duration::from_secs(5)
};

enum Command {
    Start {
        keep_rules_offline: bool,
        reply: SyncSender<Result<()>>,
    },
    Stop {
        keep_rules: bool,
        reply: SyncSender<Result<()>>,
    },
    Close {
        keep_rules: bool,
        reply: SyncSender<Result<()>>,
    },
    Apply(EnforcementOp, SyncSender<Result<()>>),
    ApplyMany(Vec<EnforcementOp>, SyncSender<Result<Vec<FailedOp>>>),
    RemoveAllManaged(SyncSender<Result<()>>),
    IsEnforcing(SyncSender<Result<bool>>),
    TakeDrift(SyncSender<Result<Vec<String>>>),
    Shutdown,
}

struct Worker {
    tx: SyncSender<Command>,
    join: Option<JoinHandle<()>>,
    /// Disconnects when the worker thread returns.
    finished: std::sync::Mutex<Receiver<()>>,
}

impl Drop for Worker {
    fn drop(&mut self) {
        // Not a blocking send: a full queue behind a stuck command would hang
        // here. Disconnecting the queue below ends the worker's loop anyway,
        // once it drains.
        if let Err(TrySendError::Full(_)) = self.tx.try_send(Command::Shutdown) {
            tracing::warn!("firewall worker queue is full; it stops once the queue drains");
        }
        drop(std::mem::replace(&mut self.tx, mpsc::sync_channel(0).0));

        let Some(join) = self.join.take() else {
            return;
        };
        let finished = self
            .finished
            .get_mut()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match finished.recv_timeout(WORKER_JOIN_TIMEOUT) {
            Ok(()) | Err(mpsc::RecvTimeoutError::Disconnected) => {
                if join.join().is_err() {
                    tracing::error!("firewall worker thread panicked");
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                tracing::error!(
                    timeout = ?WORKER_JOIN_TIMEOUT,
                    "firewall worker did not stop in time; leaving it to end with the process"
                );
            }
        }
    }
}

/// An operation the backend rejected during [`EnforcementClient::apply_many`].
#[derive(Debug)]
pub struct FailedOp {
    pub op: EnforcementOp,
    pub error: EnforceError,
}

/// Bounded command client for a single-owner native firewall worker.
#[derive(Clone)]
pub struct EnforcementClient {
    worker: Arc<Worker>,
}

impl EnforcementClient {
    /// Starts a worker backed by the platform firewall implementation.
    ///
    /// # Errors
    ///
    /// Returns an error if the worker thread cannot be created.
    pub fn try_new() -> Result<Self> {
        Self::spawn(FirewFilter::new())
    }

    #[cfg(any(test, feature = "test-support"))]
    /// Starts a worker with a supplied filter, primarily for deterministic tests.
    ///
    /// # Errors
    ///
    /// Returns an error if the worker thread cannot be created.
    pub fn with_filter(filter: impl FirewallFilter + 'static) -> Result<Self> {
        Self::spawn(filter)
    }

    fn spawn(filter: impl FirewallFilter + 'static) -> Result<Self> {
        let (tx, rx) = mpsc::sync_channel(COMMAND_QUEUE_CAPACITY);
        let (finished_tx, finished) = mpsc::sync_channel(0);
        let join = std::thread::Builder::new()
            .name("antiwire-firewall".to_owned())
            .spawn(move || {
                // Dropped when the thread returns, however it returns.
                let _finished = finished_tx;
                run_worker(filter, &rx);
            })
            .map_err(|error| EnforceError::WorkerUnavailable(error.to_string()))?;
        Ok(Self {
            worker: Arc::new(Worker {
                tx,
                join: Some(join),
                finished: std::sync::Mutex::new(finished),
            }),
        })
    }

    /// Starts the native backend, with rules that go when this process dies
    /// where the backend can arrange that.
    pub fn start(&self) -> Result<()> {
        self.start_with_persistence(false)
    }

    /// Starts the native backend for a daemon whose "persist rules offline"
    /// setting is `keep_rules_offline`. See
    /// [`FirewallFilter::start_with_persistence`].
    pub fn start_with_persistence(&self, keep_rules_offline: bool) -> Result<()> {
        self.request(|reply| Command::Start {
            keep_rules_offline,
            reply,
        })
    }

    /// Stops the native backend and removes managed rules.
    pub fn stop(&self) -> Result<()> {
        self.request(|reply| Command::Stop {
            keep_rules: false,
            reply,
        })
    }

    /// Stops the native backend, leaving the managed rules that protect the
    /// host while the daemon is offline installed. For "persist rules
    /// offline": see [`FirewallFilter::stop_keeping_rules`].
    pub fn stop_keeping_rules(&self) -> Result<()> {
        self.request(|reply| Command::Stop {
            keep_rules: true,
            reply,
        })
    }

    /// Stops the native backend for the last time, as [`Self::stop`] or,
    /// with `keep_rules`, [`Self::stop_keeping_rules`] would.
    ///
    /// From then on the worker refuses every command that would start the
    /// backend or change its rules with [`EnforceError::Closed`], even when
    /// this stop failed and left the backend open. Shutdown runs this beside
    /// requests that may still be running, and none of them can install a
    /// rule after it. Commands queued before it run first.
    pub fn close(&self, keep_rules: bool) -> Result<()> {
        self.request(|reply| Command::Close { keep_rules, reply })
    }

    /// Applies one enforcement operation.
    pub fn apply(&self, op: EnforcementOp) -> Result<()> {
        self.request(|reply| Command::Apply(op, reply))
    }

    /// Applies every operation in order, continuing past ones the backend rejects.
    ///
    /// One bad rule must not leave the others unenforced, so a rejection is
    /// collected rather than aborting the batch. Each operation is atomic on its
    /// own: a rejected one leaves nothing of itself installed.
    ///
    /// # Errors
    ///
    /// Returns an error only when the worker itself is unavailable. Rejected
    /// operations are returned in the `Ok` value, in their supplied order.
    pub fn apply_many(&self, ops: Vec<EnforcementOp>) -> Result<Vec<FailedOp>> {
        if ops.is_empty() {
            return Ok(Vec::new());
        }
        self.request(|reply| Command::ApplyMany(ops, reply))
    }

    /// Removes every rule this manager owns, leaving the backend started.
    pub fn remove_all_managed(&self) -> Result<()> {
        self.request(Command::RemoveAllManaged)
    }

    /// Returns whether the backend is actively enforcing.
    pub fn is_enforcing(&self) -> Result<bool> {
        self.request(Command::IsEnforcing)
    }

    /// Drains managed rules that drifted out of recognition.
    ///
    /// Each call returns only newly observed drift, so a caller can poll this
    /// and report without repeating itself.
    pub fn take_drift(&self) -> Result<Vec<String>> {
        self.request(Command::TakeDrift)
    }

    fn request<T>(&self, make_command: impl FnOnce(SyncSender<Result<T>>) -> Command) -> Result<T> {
        let (reply_tx, reply_rx) = mpsc::sync_channel(1);
        self.worker.tx.send(make_command(reply_tx)).map_err(|_| {
            EnforceError::WorkerUnavailable("firewall worker has stopped".to_owned())
        })?;
        // The reply is dropped unanswered only when the command panicked.
        reply_rx.recv().map_err(|_| {
            EnforceError::WorkerUnavailable("firewall command failed unexpectedly".to_owned())
        })?
    }
}

fn run_worker(mut filter: impl FirewallFilter, rx: &Receiver<Command>) {
    let mut closed = false;
    while let Ok(command) = rx.recv() {
        let Some(command) = refuse_once_closed(closed, command) else {
            continue;
        };
        if matches!(command, Command::Close { .. }) {
            // Before the stop runs, so a stop that fails or panics still
            // leaves the worker closed.
            closed = true;
        }
        // A panic fails the one command, whose caller sees its reply dropped,
        // and the worker keeps serving the rest instead of every later request
        // failing with no record of why.
        let handled = panic::catch_unwind(AssertUnwindSafe(|| handle(&mut filter, command)));
        match handled {
            Ok(true) => {}
            Ok(false) => return,
            Err(_) => tracing::error!("firewall command panicked; the worker continues"),
        }
    }
    // The queue disconnected without a `Shutdown`, which a full queue at drop
    // can cause. Stop as `Shutdown` would; after an earlier stop this does
    // nothing.
    if let Err(error) = filter.stop() {
        tracing::warn!(%error, "firewall stop on worker exit failed");
    }
}

/// Answers a command that would start the backend or change its rules with
/// [`EnforceError::Closed`] once the worker is closed, and returns every
/// other command to run. Stops and queries still run: they change nothing a
/// shutdown has to undo.
fn refuse_once_closed(closed: bool, command: Command) -> Option<Command> {
    if !closed {
        return Some(command);
    }
    match command {
        Command::Start { reply, .. } | Command::Apply(_, reply) => {
            let _ = reply.send(Err(EnforceError::Closed));
            None
        }
        Command::ApplyMany(_, reply) => {
            let _ = reply.send(Err(EnforceError::Closed));
            None
        }
        command => Some(command),
    }
}

/// Runs one command, returning false once the worker should stop.
fn handle(filter: &mut impl FirewallFilter, command: Command) -> bool {
    match command {
        Command::Start {
            keep_rules_offline,
            reply,
        } => {
            let _ = reply.send(filter.start_with_persistence(keep_rules_offline));
        }
        Command::Stop { keep_rules, reply } | Command::Close { keep_rules, reply } => {
            let stopped = if keep_rules {
                filter.stop_keeping_rules()
            } else {
                filter.stop()
            };
            let _ = reply.send(stopped);
        }
        Command::Apply(op, reply) => {
            let _ = reply.send(filter.apply(op));
        }
        Command::ApplyMany(ops, reply) => {
            let failed = ops
                .into_iter()
                .filter_map(|op| {
                    filter
                        .apply(op.clone())
                        .err()
                        .map(|error| FailedOp { op, error })
                })
                .collect();
            let _ = reply.send(Ok(failed));
        }
        Command::RemoveAllManaged(reply) => {
            let _ = reply.send(filter.remove_all_managed());
        }
        Command::IsEnforcing(reply) => {
            let _ = reply.send(Ok(filter.is_enforcing()));
        }
        Command::TakeDrift(reply) => {
            let _ = reply.send(filter.take_drift());
        }
        Command::Shutdown => {
            let _ = filter.stop();
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    struct CountingFilter {
        started: bool,
    }

    impl FirewallFilter for CountingFilter {
        fn start(&mut self) -> Result<()> {
            self.started = true;
            Ok(())
        }

        fn stop(&mut self) -> Result<()> {
            self.started = false;
            Ok(())
        }

        fn is_enforcing(&self) -> bool {
            self.started
        }

        fn apply(&mut self, _op: EnforcementOp) -> Result<()> {
            if !self.started {
                return Err(EnforceError::NotStarted);
            }
            Ok(())
        }
    }

    #[test]
    fn serializes_commands_through_owned_filter() {
        let client =
            EnforcementClient::with_filter(CountingFilter { started: false }).expect("worker");

        client.start().expect("start");
        client.apply(EnforcementOp::RemoveDohBlocks).expect("apply");

        assert!(client.is_enforcing().expect("state"));
        client.stop().expect("stop");
    }

    /// Rejects one specific operation and records every one it accepts.
    struct RejectingFilter {
        applied: Arc<std::sync::Mutex<Vec<EnforcementOp>>>,
    }

    impl FirewallFilter for RejectingFilter {
        fn start(&mut self) -> Result<()> {
            Ok(())
        }

        fn stop(&mut self) -> Result<()> {
            Ok(())
        }

        fn is_enforcing(&self) -> bool {
            true
        }

        fn apply(&mut self, op: EnforcementOp) -> Result<()> {
            if op == EnforcementOp::RemoveDohBlocks {
                return Err(EnforceError::InvalidOp("rejected".to_owned()));
            }
            self.applied.lock().expect("applied").push(op);
            Ok(())
        }
    }

    #[test]
    fn apply_many_continues_past_a_rejected_operation() {
        let applied = Arc::new(std::sync::Mutex::new(Vec::new()));
        let client = EnforcementClient::with_filter(RejectingFilter {
            applied: Arc::clone(&applied),
        })
        .expect("worker");
        let first = EnforcementOp::RemoveIpRule {
            rule_id: 1,
            ip: "192.0.2.1".to_owned(),
        };
        let last = EnforcementOp::RemoveIpRule {
            rule_id: 2,
            ip: "192.0.2.2".to_owned(),
        };

        let failed = client
            .apply_many(vec![
                first.clone(),
                EnforcementOp::RemoveDohBlocks,
                last.clone(),
            ])
            .expect("worker available");

        assert_eq!(failed.len(), 1);
        assert_eq!(failed[0].op, EnforcementOp::RemoveDohBlocks);
        assert_eq!(*applied.lock().expect("applied"), vec![first, last]);
    }

    /// Panics on one specific operation.
    struct PanickingFilter;

    impl FirewallFilter for PanickingFilter {
        fn start(&mut self) -> Result<()> {
            Ok(())
        }

        fn stop(&mut self) -> Result<()> {
            Ok(())
        }

        fn is_enforcing(&self) -> bool {
            true
        }

        fn apply(&mut self, op: EnforcementOp) -> Result<()> {
            assert!(op != EnforcementOp::RemoveDohBlocks, "backend bug");
            Ok(())
        }
    }

    /// Records which start and stop the worker ran.
    struct LifecycleRecordingFilter {
        calls: Arc<std::sync::Mutex<Vec<&'static str>>>,
    }

    impl FirewallFilter for LifecycleRecordingFilter {
        fn start(&mut self) -> Result<()> {
            self.calls.lock().expect("calls").push("start");
            Ok(())
        }

        fn start_with_persistence(&mut self, keep_rules_offline: bool) -> Result<()> {
            let started = if keep_rules_offline {
                "start keeping rules"
            } else {
                "start"
            };
            self.calls.lock().expect("calls").push(started);
            Ok(())
        }

        fn stop(&mut self) -> Result<()> {
            self.calls.lock().expect("calls").push("stop");
            Ok(())
        }

        fn stop_keeping_rules(&mut self) -> Result<()> {
            self.calls.lock().expect("calls").push("keep");
            Ok(())
        }

        fn is_enforcing(&self) -> bool {
            true
        }

        fn apply(&mut self, _op: EnforcementOp) -> Result<()> {
            Ok(())
        }
    }

    #[test]
    fn persistence_choices_reach_the_filter() {
        let calls = Arc::new(std::sync::Mutex::new(Vec::new()));
        let client = EnforcementClient::with_filter(LifecycleRecordingFilter {
            calls: Arc::clone(&calls),
        })
        .expect("worker");

        client
            .start_with_persistence(true)
            .expect("start keeping rules");
        client.stop_keeping_rules().expect("stop keeping rules");
        assert_eq!(
            *calls.lock().expect("calls"),
            ["start keeping rules", "keep"]
        );
    }

    fn remove_rule() -> EnforcementOp {
        EnforcementOp::RemoveIpRule {
            rule_id: 1,
            ip: "192.0.2.1".to_owned(),
        }
    }

    #[test]
    fn a_closed_worker_starts_nothing_and_installs_nothing() {
        let client =
            EnforcementClient::with_filter(CountingFilter { started: false }).expect("worker");
        client.start().expect("start");
        client.close(false).expect("close");

        assert!(matches!(client.start(), Err(EnforceError::Closed)));
        assert!(matches!(
            client.apply(remove_rule()),
            Err(EnforceError::Closed)
        ));
        assert!(matches!(
            client.apply_many(vec![remove_rule()]),
            Err(EnforceError::Closed)
        ));
        assert!(
            !client.is_enforcing().expect("state"),
            "nothing restarted it"
        );
        client.stop().expect("a later stop still runs");
    }

    /// Fails every stop and stays started, as a backend whose rule removal
    /// fails does.
    struct UnstoppableFilter {
        started: bool,
    }

    impl FirewallFilter for UnstoppableFilter {
        fn start(&mut self) -> Result<()> {
            self.started = true;
            Ok(())
        }

        fn stop(&mut self) -> Result<()> {
            Err(EnforceError::InvalidOp("removal failed".to_owned()))
        }

        fn is_enforcing(&self) -> bool {
            self.started
        }

        fn apply(&mut self, _op: EnforcementOp) -> Result<()> {
            if !self.started {
                return Err(EnforceError::NotStarted);
            }
            Ok(())
        }
    }

    /// The regression this guards: a stop that failed left the backend
    /// open, and a request still running at shutdown could install rules
    /// through it after the host was meant to be reverted.
    #[test]
    fn a_close_that_fails_still_closes_the_worker() {
        let client =
            EnforcementClient::with_filter(UnstoppableFilter { started: false }).expect("worker");
        client.start().expect("start");

        assert!(client.close(false).is_err());
        assert!(
            client.is_enforcing().expect("state"),
            "the backend is still open"
        );
        assert!(matches!(
            client.apply(remove_rule()),
            Err(EnforceError::Closed)
        ));
    }

    #[test]
    fn a_close_that_keeps_rules_stops_keeping_them() {
        let calls = Arc::new(std::sync::Mutex::new(Vec::new()));
        let client = EnforcementClient::with_filter(LifecycleRecordingFilter {
            calls: Arc::clone(&calls),
        })
        .expect("worker");

        client.close(true).expect("close keeping rules");
        client.close(false).expect("close removing rules");
        assert_eq!(*calls.lock().expect("calls"), ["keep", "stop"]);
    }

    /// Blocks in `stop`, the call a dropped worker makes on its way out,
    /// until the test releases it.
    struct StuckFilter {
        release: std::sync::Mutex<mpsc::Receiver<()>>,
    }

    impl FirewallFilter for StuckFilter {
        fn start(&mut self) -> Result<()> {
            Ok(())
        }

        fn stop(&mut self) -> Result<()> {
            let _ = self.release.lock().expect("release").recv();
            Ok(())
        }

        fn is_enforcing(&self) -> bool {
            true
        }

        fn apply(&mut self, _op: EnforcementOp) -> Result<()> {
            Ok(())
        }
    }

    /// The regression this guards: dropping the client joined the worker
    /// thread without limit, so a native call that never returned kept the
    /// process alive after shutdown.
    #[test]
    fn dropping_the_client_does_not_wait_forever_for_a_stuck_worker() {
        let (release, release_rx) = mpsc::channel();
        let client = EnforcementClient::with_filter(StuckFilter {
            release: std::sync::Mutex::new(release_rx),
        })
        .expect("worker");

        let started = std::time::Instant::now();
        let dropping = std::thread::spawn(move || drop(client));
        while !dropping.is_finished() {
            assert!(
                started.elapsed() < WORKER_JOIN_TIMEOUT * 10,
                "drop must give up on a stuck worker"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(
            started.elapsed() >= WORKER_JOIN_TIMEOUT,
            "drop waited for the worker before giving up"
        );
        drop(release);
    }

    /// The regression this guards: one panicking command killed the worker
    /// thread, and every later request failed until the daemon restarted.
    #[test]
    fn a_panicking_command_fails_alone() {
        let client = EnforcementClient::with_filter(PanickingFilter).expect("worker");

        assert!(matches!(
            client.apply(EnforcementOp::RemoveDohBlocks),
            Err(EnforceError::WorkerUnavailable(_))
        ));
        client
            .apply(EnforcementOp::RemoveIpRule {
                rule_id: 1,
                ip: "192.0.2.1".to_owned(),
            })
            .expect("the worker still serves commands");
    }
}
