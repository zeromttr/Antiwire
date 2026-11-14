//! How handlers turn outcomes into replies.
//!
//! Every handler follows one contract, which the client relies on:
//!
//! - An action RPC, one that replies [`ActionResponse`], reports every
//!   outcome of the action as `success` with a message the user can read:
//!   done, or refused and why. Invalid input, nothing to act on, a conflict,
//!   the wrong state, and a failure the service reports are all refusals.
//! - An RPC that returns data reports invalid input as `InvalidArgument`, a
//!   missing row as `NotFound`, the wrong state as `FailedPrecondition`, and
//!   any failure as `Internal`.
//! - Either kind returns `Internal` when the work never finished, such as a
//!   panicked blocking task.
//!
//! [`query`] runs a store read for a data RPC; [`blocking`] runs any other
//! blocking work, leaving its outcome to the handler.

use std::fmt::Display;

use antiwire_proto::ActionResponse;
use tonic::Status;

/// The action was done.
pub(crate) fn done(message: impl Into<String>) -> ActionResponse {
    ActionResponse {
        success: true,
        message: message.into(),
    }
}

/// The action was not done, for `reason`.
pub(crate) fn refused(reason: impl Display) -> ActionResponse {
    ActionResponse {
        success: false,
        message: reason.to_string(),
    }
}

/// `Internal`, for a failure an RPC that returns data cannot recover from.
pub(crate) fn internal(error: impl Display) -> Status {
    Status::internal(error.to_string())
}

/// Runs a blocking store read for an RPC that returns data.
///
/// # Errors
///
/// `Internal` when the read fails or never finishes; `what` names it.
#[allow(clippy::result_large_err)] // `tonic::Status` is required by the gRPC surface.
pub(crate) async fn query<T, E, F>(what: &'static str, work: F) -> Result<T, Status>
where
    T: Send + 'static,
    E: Display + Send + 'static,
    F: FnOnce() -> Result<T, E> + Send + 'static,
{
    blocking(what, work)
        .await?
        .map_err(|error| Status::internal(format!("{what} failed: {error}")))
}

/// Runs blocking `work` (store, firewall, or file I/O) off the async runtime.
///
/// # Errors
///
/// `Internal` when the task panics or is cancelled; `what` names the work.
#[allow(clippy::result_large_err)] // `tonic::Status` is required by the gRPC surface.
pub(crate) async fn blocking<T, F>(what: &'static str, work: F) -> Result<T, Status>
where
    T: Send + 'static,
    F: FnOnce() -> T + Send + 'static,
{
    tokio::task::spawn_blocking(work)
        .await
        .map_err(|error| Status::internal(format!("{what} did not finish: {error}")))
}
