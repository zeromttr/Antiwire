//! Update status and install requests from the client.

use crate::proto_bridge::update_status_to_proto;
use crate::reply::{done, refused};
use antiwire_update::{UpdateError, UpdateService};
use std::sync::Arc;
use tonic::{Request, Response};

/// Update status and installs.
pub(crate) struct UpdatesApi {
    pub(crate) updates: Arc<UpdateService>,
}

impl UpdatesApi {
    pub(super) fn handle_get_update_status(
        &self,
        _request: Request<antiwire_proto::Empty>,
    ) -> Response<antiwire_proto::UpdateStatus> {
        Response::new(update_status_to_proto(&self.updates.status()))
    }

    /// Reads the release feeds now and returns the resulting status.
    pub(super) async fn handle_check_for_updates(
        &self,
        _request: Request<antiwire_proto::Empty>,
    ) -> Response<antiwire_proto::UpdateStatus> {
        Response::new(update_status_to_proto(&self.updates.check_now().await))
    }

    pub(super) fn handle_install_update(
        &self,
        request: Request<antiwire_proto::InstallUpdateRequest>,
    ) -> Response<antiwire_proto::ActionResponse> {
        let version = request.into_inner().version;
        let outcome = self.updates.request_install(&version);
        Response::new(install_action_response(&version, outcome))
    }
}

/// Maps the outcome of an install request to the reply the client shows.
///
/// A request that is already running is not a failure, so it reports success.
fn install_action_response(
    version: &str,
    outcome: Result<(), UpdateError>,
) -> antiwire_proto::ActionResponse {
    match outcome {
        Ok(()) => done(format!("Installing {version}.")),
        Err(UpdateError::AlreadyInstalling) => done("An update is already being installed."),
        Err(error) => refused(error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepted_install_reports_the_version() {
        let response = install_action_response("0.3.0", Ok(()));
        assert!(response.success);
        assert_eq!(response.message, "Installing 0.3.0.");
    }

    #[test]
    fn install_already_running_reports_success() {
        let response = install_action_response("0.3.0", Err(UpdateError::AlreadyInstalling));
        assert!(response.success);
        assert_eq!(response.message, "An update is already being installed.");
    }

    #[test]
    fn other_install_errors_report_failure_with_their_message() {
        let response = install_action_response(
            "0.3.0",
            Err(UpdateError::VersionMismatch {
                requested: "0.3.0".to_owned(),
            }),
        );
        assert!(!response.success);
        assert_eq!(
            response.message,
            "version 0.3.0 is not the available update"
        );

        let response = install_action_response(
            "0.3.0",
            Err(UpdateError::Unsupported("debug build".to_owned())),
        );
        assert!(!response.success);
        assert_eq!(
            response.message,
            "updates are not supported here: debug build"
        );
    }
}
