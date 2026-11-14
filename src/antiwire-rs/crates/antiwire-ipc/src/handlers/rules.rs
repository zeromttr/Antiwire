//! Firewall rules, country blocks, and domain-block explanations.

use std::sync::Arc;

use antiwire_services::RuleService;
use tonic::{Request, Response, Status};

use crate::proto_bridge::{
    country_selector_from_proto, country_summary_to_proto, new_country_block_from_proto,
    new_rule_from_proto, rule_selector_from_proto, rule_to_proto,
};
use crate::reply::{blocking, done, query, refused};

/// Firewall and country rules.
pub(crate) struct RulesApi {
    pub(crate) rules: Arc<RuleService>,
}

#[allow(clippy::result_large_err)] // `tonic::Status` is required by the gRPC surface.
impl RulesApi {
    pub(super) async fn handle_get_rules(
        &self,
        _request: Request<antiwire_proto::Empty>,
    ) -> Result<Response<antiwire_proto::RulesResponse>, Status> {
        let rules = Arc::clone(&self.rules);
        let listing = query("rule listing", move || rules.list()).await?;
        Ok(Response::new(antiwire_proto::RulesResponse {
            rules: listing.rules.iter().map(rule_to_proto).collect(),
            country_rules: listing
                .countries
                .iter()
                .map(country_summary_to_proto)
                .collect(),
        }))
    }

    pub(super) async fn handle_add_rule(
        &self,
        request: Request<antiwire_proto::Rule>,
    ) -> Result<Response<antiwire_proto::ActionResponse>, Status> {
        let rule = match new_rule_from_proto(request.into_inner()) {
            Ok(rule) => rule,
            Err(problem) => return Ok(Response::new(refused(problem))),
        };
        let rules = Arc::clone(&self.rules);
        let outcome = blocking("rule add", move || rules.add_rule(&rule)).await?;
        Ok(Response::new(match outcome {
            Ok(saved) => done(format!("Rule {} added", saved.id)),
            Err(error) => refused(error),
        }))
    }

    pub(super) async fn handle_remove_rule(
        &self,
        request: Request<antiwire_proto::Rule>,
    ) -> Result<Response<antiwire_proto::ActionResponse>, Status> {
        let selector = match rule_selector_from_proto(request.into_inner()) {
            Ok(selector) => selector,
            Err(problem) => return Ok(Response::new(refused(problem))),
        };
        let rules = Arc::clone(&self.rules);
        let outcome = blocking("rule removal", move || rules.remove_rule(&selector)).await?;
        Ok(Response::new(match outcome {
            Ok(true) => done("Rule removed"),
            Ok(false) => refused("Rule not found"),
            Err(error) => refused(error),
        }))
    }

    pub(super) async fn handle_add_country_rule(
        &self,
        request: Request<antiwire_proto::CountryRule>,
    ) -> Result<Response<antiwire_proto::ActionResponse>, Status> {
        let block = match new_country_block_from_proto(request.into_inner()) {
            Ok(block) => block,
            Err(problem) => return Ok(Response::new(refused(problem))),
        };
        let rules = Arc::clone(&self.rules);
        // A large country writes tens of thousands of rows.
        let outcome = blocking("country block", move || rules.add_country_rule(&block)).await?;
        Ok(Response::new(match outcome {
            Ok(summary) => done(format!(
                "Blocked {} ({} networks)",
                summary.code, summary.network_count
            )),
            Err(error) => refused(error),
        }))
    }

    pub(super) async fn handle_remove_country_rule(
        &self,
        request: Request<antiwire_proto::CountryRule>,
    ) -> Result<Response<antiwire_proto::ActionResponse>, Status> {
        let selector = match country_selector_from_proto(request.into_inner()) {
            Ok(selector) => selector,
            Err(problem) => return Ok(Response::new(refused(problem))),
        };
        let rules = Arc::clone(&self.rules);
        let outcome = blocking("country block removal", move || {
            rules.remove_country_rule(&selector)
        })
        .await?;
        Ok(Response::new(match outcome {
            Ok(true) => done("Country block removed"),
            Ok(false) => refused("Country block not found"),
            Err(error) => refused(error),
        }))
    }

    pub(super) fn handle_explain_domain_block(
        &self,
        request: Request<antiwire_proto::ExplainDomainBlockRequest>,
    ) -> Response<antiwire_proto::ExplainDomainBlockResponse> {
        let block = self
            .rules
            .explain_domain_block(&request.into_inner().domain);
        Response::new(match block {
            Some(block) => antiwire_proto::ExplainDomainBlockResponse {
                blocked: true,
                source: block
                    .source
                    .map(antiwire_policy::DomainBlockSource::as_str)
                    .unwrap_or_default()
                    .to_owned(),
                blocklist_names: block.blocklist_names,
            },
            None => antiwire_proto::ExplainDomainBlockResponse::default(),
        })
    }
}
