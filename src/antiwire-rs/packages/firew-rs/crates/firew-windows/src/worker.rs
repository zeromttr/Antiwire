//! Synchronous request channel to a dedicated native worker thread.

use std::sync::mpsc::{self, Receiver, Sender};
use std::thread::{self, JoinHandle};

use firew_core::{Error, ErrorKind, Rule, RuleKey};
use firew_sys::{HealthSnapshot, NativeRuleRef, RuleFilter};

fn worker_dead_error() -> Error {
    Error::new(ErrorKind::Internal, "native worker thread stopped")
}

/// Handle to a worker thread that processes synchronous requests.
struct WorkerHandle<Req> {
    tx: Sender<Req>,
    join: Option<JoinHandle<()>>,
}

impl<Req: Send> WorkerHandle<Req> {
    /// Spawns a worker thread, runs `init` once, then `run` with the initialized state.
    fn spawn<State, FInit, FRun>(thread_name: &str, init: FInit, run: FRun) -> Result<Self, Error>
    where
        FInit: FnOnce() -> Result<State, Error> + Send + 'static,
        FRun: FnOnce(&Receiver<Req>, State) + Send + 'static,
        Req: Send + 'static,
    {
        let (tx, rx) = mpsc::channel();
        let (ready_tx, ready_rx) = mpsc::channel();

        let join = thread::Builder::new()
            .name(thread_name.to_owned())
            .spawn(move || {
                let state = match init() {
                    Ok(state) => {
                        let _ = ready_tx.send(Ok(()));
                        state
                    }
                    Err(err) => {
                        let _ = ready_tx.send(Err(err));
                        return;
                    }
                };
                run(&rx, state);
            })
            .map_err(|e| Error::new(ErrorKind::Internal, format!("spawn {thread_name}: {e}")))?;

        match ready_rx.recv() {
            Ok(Ok(())) => Ok(Self {
                tx,
                join: Some(join),
            }),
            Ok(Err(err)) => Err(err),
            Err(_) => Err(worker_dead_error()),
        }
    }

    fn send(&self, request: Req) -> Result<(), Error> {
        self.tx.send(request).map_err(|_| worker_dead_error())
    }
}

impl<Req> Drop for WorkerHandle<Req> {
    fn drop(&mut self) {
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}

/// Native state owned by a worker thread, driven one request at a time.
///
/// `INetFw` and WFP both keep their COM or Fwpm session on a dedicated thread.
/// They implement this, and [`WorkerClient`] carries each call across. The
/// state is built on its thread and never leaves it, so it need not be `Send`.
pub(crate) trait NativeWorker: 'static {
    fn add_rule(&mut self, rule: &Rule) -> Result<NativeRuleRef, Error>;
    fn update_rule(&mut self, id: &NativeRuleRef, rule: &Rule) -> Result<NativeRuleRef, Error>;
    fn remove_rule(&mut self, id: &NativeRuleRef) -> Result<(), Error>;
    fn get_rule(&mut self, id: &NativeRuleRef) -> Result<Rule, Error>;
    fn list_rules(&mut self, filter: &RuleFilter) -> Result<Vec<(NativeRuleRef, Rule)>, Error>;
    fn begin_transaction(&mut self) -> Result<(), Error>;
    fn commit_transaction(&mut self) -> Result<(), Error>;
    fn abort_transaction(&mut self) -> Result<(), Error>;
    fn health_probe(&mut self, expected_keys: &[RuleKey]) -> Result<HealthSnapshot, Error>;
    fn remove_all_managed(&mut self) -> Result<(), Error>;
    fn take_drift(&mut self) -> Vec<String>;
    fn incomplete_keys(&mut self) -> Result<Vec<RuleKey>, Error>;
}

type Reply<T> = Sender<Result<T, Error>>;

/// One [`NativeWorker`] call and the channel its result goes back on.
enum Request {
    AddRule(Rule, Reply<NativeRuleRef>),
    UpdateRule(NativeRuleRef, Rule, Reply<NativeRuleRef>),
    RemoveRule(NativeRuleRef, Reply<()>),
    GetRule(NativeRuleRef, Reply<Rule>),
    ListRules(RuleFilter, Reply<Vec<(NativeRuleRef, Rule)>>),
    BeginTransaction(Reply<()>),
    CommitTransaction(Reply<()>),
    AbortTransaction(Reply<()>),
    HealthProbe(Vec<RuleKey>, Reply<HealthSnapshot>),
    RemoveAllManaged(Reply<()>),
    TakeDrift(Reply<Vec<String>>),
    IncompleteKeys(Reply<Vec<RuleKey>>),
    Shutdown,
}

/// Answers requests until the client shuts down or goes away.
fn serve<W: NativeWorker>(rx: &Receiver<Request>, mut worker: W) {
    while let Ok(request) = rx.recv() {
        // A dropped receiver means the client gave up waiting; nothing to report.
        match request {
            Request::AddRule(rule, reply) => drop(reply.send(worker.add_rule(&rule))),
            Request::UpdateRule(id, rule, reply) => {
                drop(reply.send(worker.update_rule(&id, &rule)));
            }
            Request::RemoveRule(id, reply) => drop(reply.send(worker.remove_rule(&id))),
            Request::GetRule(id, reply) => drop(reply.send(worker.get_rule(&id))),
            Request::ListRules(filter, reply) => drop(reply.send(worker.list_rules(&filter))),
            Request::BeginTransaction(reply) => drop(reply.send(worker.begin_transaction())),
            Request::CommitTransaction(reply) => drop(reply.send(worker.commit_transaction())),
            Request::AbortTransaction(reply) => drop(reply.send(worker.abort_transaction())),
            Request::HealthProbe(keys, reply) => drop(reply.send(worker.health_probe(&keys))),
            Request::RemoveAllManaged(reply) => drop(reply.send(worker.remove_all_managed())),
            Request::TakeDrift(reply) => drop(reply.send(Ok(worker.take_drift()))),
            Request::IncompleteKeys(reply) => drop(reply.send(worker.incomplete_keys())),
            Request::Shutdown => break,
        }
    }
}

/// Calling side of a [`NativeWorker`] running on its own thread.
///
/// Dropping the client stops the worker and waits for its thread to exit.
pub(crate) struct WorkerClient {
    worker: WorkerHandle<Request>,
}

impl WorkerClient {
    /// Starts a thread named `thread_name` that builds its worker with `init`.
    ///
    /// Returns once `init` has finished, with its error if it failed.
    pub(crate) fn spawn<W: NativeWorker>(
        thread_name: &str,
        init: impl FnOnce() -> Result<W, Error> + Send + 'static,
    ) -> Result<Self, Error> {
        let worker = WorkerHandle::spawn(thread_name, init, serve::<W>)?;
        Ok(Self { worker })
    }

    fn call<T>(&self, request: impl FnOnce(Reply<T>) -> Request) -> Result<T, Error> {
        let (reply, result) = mpsc::channel();
        self.worker.send(request(reply))?;
        result.recv().map_err(|_| worker_dead_error())?
    }

    pub(crate) fn add_rule(&self, rule: &Rule) -> Result<NativeRuleRef, Error> {
        self.call(|reply| Request::AddRule(rule.clone(), reply))
    }

    pub(crate) fn update_rule(
        &self,
        id: &NativeRuleRef,
        rule: &Rule,
    ) -> Result<NativeRuleRef, Error> {
        self.call(|reply| Request::UpdateRule(id.clone(), rule.clone(), reply))
    }

    pub(crate) fn remove_rule(&self, id: &NativeRuleRef) -> Result<(), Error> {
        self.call(|reply| Request::RemoveRule(id.clone(), reply))
    }

    pub(crate) fn get_rule(&self, id: &NativeRuleRef) -> Result<Rule, Error> {
        self.call(|reply| Request::GetRule(id.clone(), reply))
    }

    pub(crate) fn list_rules(
        &self,
        filter: &RuleFilter,
    ) -> Result<Vec<(NativeRuleRef, Rule)>, Error> {
        self.call(|reply| Request::ListRules(filter.clone(), reply))
    }

    pub(crate) fn begin_transaction(&self) -> Result<(), Error> {
        self.call(Request::BeginTransaction)
    }

    pub(crate) fn commit_transaction(&self) -> Result<(), Error> {
        self.call(Request::CommitTransaction)
    }

    pub(crate) fn abort_transaction(&self) -> Result<(), Error> {
        self.call(Request::AbortTransaction)
    }

    pub(crate) fn health_probe(&self, expected_keys: &[RuleKey]) -> Result<HealthSnapshot, Error> {
        self.call(|reply| Request::HealthProbe(expected_keys.to_vec(), reply))
    }

    pub(crate) fn remove_all_managed(&self) -> Result<(), Error> {
        self.call(Request::RemoveAllManaged)
    }

    pub(crate) fn take_drift(&self) -> Result<Vec<String>, Error> {
        self.call(Request::TakeDrift)
    }

    pub(crate) fn incomplete_keys(&self) -> Result<Vec<RuleKey>, Error> {
        self.call(Request::IncompleteKeys)
    }
}

/// Expands, inside an `impl Backend` block, to every rule and transaction
/// method, each sent to the [`WorkerClient`] stored in `self.$field`.
///
/// `add_rule` and `update_rule` first run the backend's own `validate_rule`, so
/// a rule the backend cannot represent never crosses to the worker thread. The
/// backend still writes `open`, `name`, its capabilities, and `validate_rule`.
macro_rules! forward_to_worker {
    ($field:ident) => {
        fn add_rule(
            &mut self,
            rule: &::firew_core::Rule,
        ) -> ::core::result::Result<::firew_sys::NativeRuleRef, ::firew_core::Error> {
            self.validate_rule(rule)?;
            self.$field.add_rule(rule)
        }

        fn update_rule(
            &mut self,
            id: &::firew_sys::NativeRuleRef,
            rule: &::firew_core::Rule,
        ) -> ::core::result::Result<::firew_sys::NativeRuleRef, ::firew_core::Error> {
            self.validate_rule(rule)?;
            self.$field.update_rule(id, rule)
        }

        fn remove_rule(
            &mut self,
            id: &::firew_sys::NativeRuleRef,
        ) -> ::core::result::Result<(), ::firew_core::Error> {
            self.$field.remove_rule(id)
        }

        fn get_rule(
            &self,
            id: &::firew_sys::NativeRuleRef,
        ) -> ::core::result::Result<::firew_core::Rule, ::firew_core::Error> {
            self.$field.get_rule(id)
        }

        fn list_rules(
            &self,
            filter: &::firew_sys::RuleFilter,
        ) -> ::core::result::Result<
            ::std::vec::Vec<(::firew_sys::NativeRuleRef, ::firew_core::Rule)>,
            ::firew_core::Error,
        > {
            self.$field.list_rules(filter)
        }

        fn begin_transaction(&mut self) -> ::core::result::Result<(), ::firew_core::Error> {
            self.$field.begin_transaction()
        }

        fn commit_transaction(&mut self) -> ::core::result::Result<(), ::firew_core::Error> {
            self.$field.commit_transaction()
        }

        fn abort_transaction(&mut self) -> ::core::result::Result<(), ::firew_core::Error> {
            self.$field.abort_transaction()
        }

        fn health_probe(
            &self,
            expected_keys: &[::firew_core::RuleKey],
        ) -> ::core::result::Result<::firew_sys::HealthSnapshot, ::firew_core::Error> {
            self.$field.health_probe(expected_keys)
        }

        fn remove_all_managed(&mut self) -> ::core::result::Result<(), ::firew_core::Error> {
            self.$field.remove_all_managed()
        }

        fn take_drift(
            &mut self,
        ) -> ::core::result::Result<::std::vec::Vec<::std::string::String>, ::firew_core::Error> {
            self.$field.take_drift()
        }

        fn incomplete_keys(
            &self,
        ) -> ::core::result::Result<::std::vec::Vec<::firew_core::RuleKey>, ::firew_core::Error> {
            self.$field.incomplete_keys()
        }
    };
}
pub(crate) use forward_to_worker;

impl Drop for WorkerClient {
    fn drop(&mut self) {
        let _ = self.worker.send(Request::Shutdown);
    }
}
