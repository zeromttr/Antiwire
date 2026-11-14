use super::BackendFactory;
use netmetrics_sys::{BackendConfig, BackendError, EventGate, EventSink, StopFlag};
use std::sync::mpsc::{self, Receiver};
use std::thread::{self, JoinHandle};
use std::time::Instant;

pub(super) struct BackendRun {
    pub(super) name: &'static str,
    pub(super) handle: JoinHandle<()>,
    pub(super) status: Receiver<Result<(), BackendError>>,
    pub(super) gate: EventGate,
    /// When this run started, to tell a crash loop from an occasional failure.
    pub(super) started: Instant,
}

pub(super) fn spawn_backend(
    factory: &BackendFactory,
    config: &BackendConfig,
    sink: &EventSink,
    stop: StopFlag,
) -> Result<BackendRun, std::io::Error> {
    let mut backend = factory();
    let name = backend.name();
    let config = config.clone();
    let (sink, gate) = sink.revocable();
    let (status_sender, status) = mpsc::channel();
    let handle = thread::Builder::new()
        .name(format!("{name}-source"))
        .spawn(move || {
            let result = backend.run(&config, sink, stop);
            let _ = status_sender.send(result);
        })?;
    Ok(BackendRun {
        name,
        handle,
        status,
        gate,
        started: Instant::now(),
    })
}
