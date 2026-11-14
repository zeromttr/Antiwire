//! Saved `TypeSafe` domain classification history.

use crate::proto_bridge::{
    ai_decision_page_to_response, ai_decisions_query_from_proto, domain_decision_to_proto,
};
use crate::reply::{done, internal, refused};
use antiwire_services::{AiDecisionError, AiDecisionService, Scan};
use std::sync::Arc;
use tonic::{Request, Response, Status};

/// The saved AI decisions.
pub(crate) struct AiDecisionsApi {
    pub(crate) decisions: Arc<AiDecisionService>,
}

#[allow(clippy::result_large_err)] // `tonic::Status` is required by the gRPC surface.
impl AiDecisionsApi {
    pub(super) async fn handle_get_ai_decisions(
        &self,
        request: Request<antiwire_proto::AiDecisionsRequest>,
    ) -> Result<Response<antiwire_proto::AiDecisionsResponse>, Status> {
        let query = ai_decisions_query_from_proto(&request.into_inner())
            .map_err(Status::invalid_argument)?;
        let page = self.decisions.page(query).await.map_err(decision_status)?;
        Ok(Response::new(ai_decision_page_to_response(&page)))
    }

    pub(super) async fn handle_delete_ai_decision(
        &self,
        request: Request<antiwire_proto::DeleteAiDecisionRequest>,
    ) -> Result<Response<antiwire_proto::ActionResponse>, Status> {
        let domain = request.into_inner().domain;
        Ok(Response::new(match self.decisions.delete(&domain).await {
            Ok(true) => done("Decision deleted"),
            Ok(false) => refused("Decision not found"),
            Err(error) => refused(error),
        }))
    }

    pub(super) async fn handle_refresh_ai_decision(
        &self,
        request: Request<antiwire_proto::RefreshAiDecisionRequest>,
    ) -> Result<Response<antiwire_proto::AiDecision>, Status> {
        self.reclassify(&request.into_inner().domain, Scan::Basic)
            .await
    }

    pub(super) async fn handle_advanced_ai_decision(
        &self,
        request: Request<antiwire_proto::AdvancedAiDecisionRequest>,
    ) -> Result<Response<antiwire_proto::AiDecision>, Status> {
        self.reclassify(&request.into_inner().domain, Scan::Advanced)
            .await
    }

    async fn reclassify(
        &self,
        domain: &str,
        scan: Scan,
    ) -> Result<Response<antiwire_proto::AiDecision>, Status> {
        let decision = self
            .decisions
            .reclassify(domain, scan)
            .await
            .map_err(decision_status)?;
        Ok(Response::new(domain_decision_to_proto(&decision)))
    }
}

fn decision_status(error: AiDecisionError) -> Status {
    match error {
        AiDecisionError::EmptyDomain => Status::invalid_argument(error.to_string()),
        AiDecisionError::NotFound => Status::not_found(error.to_string()),
        AiDecisionError::NoApiKey | AiDecisionError::ClassifierUnavailable(_) => {
            Status::failed_precondition(error.to_string())
        }
        AiDecisionError::Registry(_)
        | AiDecisionError::Classification(_)
        | AiDecisionError::Store(_)
        | AiDecisionError::Interrupted(_) => internal(error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_failure_has_its_status() {
        let cases = [
            (AiDecisionError::EmptyDomain, tonic::Code::InvalidArgument),
            (AiDecisionError::NotFound, tonic::Code::NotFound),
            (AiDecisionError::NoApiKey, tonic::Code::FailedPrecondition),
            (
                AiDecisionError::Registry(antiwire_lookup::Error::RateLimited),
                tonic::Code::Internal,
            ),
        ];
        for (error, code) in cases {
            assert_eq!(decision_status(error).code(), code);
        }
    }
}
