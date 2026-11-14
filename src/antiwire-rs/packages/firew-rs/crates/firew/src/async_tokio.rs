//! Tokio-native asynchronous facade.

use firew_core::{Error, ErrorKind};

use crate::async_facade::async_facade;

async_facade! {
    /// Firewall owner whose blocking native work runs on Tokio's blocking pool.
    ///
    /// A blocking task that panics or is cancelled fails with
    /// [`ErrorKind::Internal`].
    pub struct TokioFirewall;
    runtime = "Tokio",
    into = into_tokio,
    run = run,
}

async fn run<T: Send + 'static>(
    operation: impl FnOnce() -> Result<T, Error> + Send + 'static,
) -> Result<T, Error> {
    tokio::task::spawn_blocking(operation)
        .await
        .map_err(|source| {
            Error::new(ErrorKind::Internal, "Tokio blocking task failed").with_source(source)
        })?
}
