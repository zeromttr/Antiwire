//! What the record inspector can learn about a domain on request.

use crate::proto_bridge::{
    certificate_lookup_to_proto, records_to_proto, registration_lookup_to_proto,
    seen_subdomains_to_proto,
};
use crate::reply::internal;
use antiwire_services::{DomainLookupError, DomainLookupService};
use std::net::IpAddr;
use std::sync::Arc;
use tonic::{Request, Response, Status};

/// The record inspector's lookups.
pub(crate) struct DomainLookupApi {
    pub(crate) lookups: Arc<DomainLookupService>,
}

#[allow(clippy::result_large_err)] // `tonic::Status` is required by the gRPC surface.
impl DomainLookupApi {
    /// Reads the registration record for one observed hostname. Anything
    /// that is not a record comes back as an outcome, not an error.
    pub(super) async fn handle_lookup_domain(
        &self,
        request: Request<antiwire_proto::LookupDomainRequest>,
    ) -> Result<Response<antiwire_proto::LookupDomainResponse>, Status> {
        let domain = request.into_inner().domain;
        let found = self.lookups.registration(&domain).await;
        Ok(Response::new(registration_lookup_to_proto(&found)))
    }

    pub(super) async fn handle_lookup_dns_records(
        &self,
        request: Request<antiwire_proto::DnsRecordsRequest>,
    ) -> Result<Response<antiwire_proto::DnsRecordsResponse>, Status> {
        let request = request.into_inner();
        let address = request.address.trim().parse::<IpAddr>().ok();
        let lookup = self
            .lookups
            .dns_records(&request.host, &request.domain, address)
            .await
            .map_err(lookup_status)?;
        Ok(Response::new(records_to_proto(lookup)))
    }

    pub(super) async fn handle_get_seen_subdomains(
        &self,
        request: Request<antiwire_proto::SeenSubdomainsRequest>,
    ) -> Result<Response<antiwire_proto::SeenSubdomainsResponse>, Status> {
        let request = request.into_inner();
        let seen = self
            .lookups
            .seen_subdomains(&request.host, &request.domain)
            .await
            .map_err(lookup_status)?;
        Ok(Response::new(seen_subdomains_to_proto(seen)))
    }

    pub(super) async fn handle_search_certificates(
        &self,
        request: Request<antiwire_proto::CertificateSearchRequest>,
    ) -> Result<Response<antiwire_proto::CertificateSearchResponse>, Status> {
        let request = request.into_inner();
        let lookup = self
            .lookups
            .certificates(&request.host, &request.domain)
            .await
            .map_err(lookup_status)?;
        Ok(Response::new(certificate_lookup_to_proto(lookup)))
    }
}

fn lookup_status(error: DomainLookupError) -> Status {
    match error {
        DomainLookupError::NotAHostname(message) => Status::invalid_argument(message),
        DomainLookupError::NoResolver(message) => Status::failed_precondition(message),
        DomainLookupError::Store(_) | DomainLookupError::Interrupted(_) => internal(error),
    }
}
