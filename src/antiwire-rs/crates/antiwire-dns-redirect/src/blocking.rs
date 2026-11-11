//! Running blocking OS calls without holding up the async runtime.

use tracing::warn;

/// Runs a blocking OS DNS call off the async runtime's worker threads.
///
/// Resolver configuration may enumerate adapters, update system files, or
/// wait on platform utilities. None of those operations belongs on a tokio
/// worker thread. `None` when the call panicked or the runtime is shutting
/// down; the caller takes that as the call not having done its work.
pub(crate) async fn blocking_os<F, T>(op: F) -> Option<T>
where
    F: FnOnce() -> T + Send + 'static,
    T: Send + 'static,
{
    match tokio::task::spawn_blocking(op).await {
        Ok(value) => Some(value),
        Err(error) => {
            warn!(%error, "os dns helper task failed");
            None
        }
    }
}

/// Runs a blocking `job` off the runtime without waiting for it, or in place
/// when there is no runtime.
///
/// The runtime waits for its blocking jobs when it shuts down, so a job
/// started here still finishes before a clean process exit.
pub(crate) fn run_off_runtime(job: impl FnOnce() + Send + 'static) {
    match tokio::runtime::Handle::try_current() {
        Ok(handle) => {
            handle.spawn_blocking(job);
        }
        Err(_) => job(),
    }
}
