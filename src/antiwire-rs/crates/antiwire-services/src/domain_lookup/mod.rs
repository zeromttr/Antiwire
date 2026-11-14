//! What the record inspector can learn about a domain on request: its
//! official registration, its live DNS records, the names under it this
//! machine has seen, and the names on its logged TLS certificates.

use std::net::IpAddr;
use std::sync::Arc;

use antiwire_lookup::{CertificateSearchResult, Registration};
use antiwire_store::{
    DeletionFence, DomainLookup, SeenSubdomain, Store, StoreError, INFERRED_SUFFIX,
};
use time::OffsetDateTime;

use crate::context::ServiceContext;
use crate::lookup_clients::{CertificateLog, LookupClients, RegistryClient};
use crate::settings_feed::SettingsFeed;

#[cfg(test)]
mod tests;

/// Local names returned per request; the rest are counted as truncated.
pub const SEEN_SUBDOMAIN_LIMIT: usize = 500;

/// Why a domain question could not be asked.
#[derive(Debug, thiserror::Error)]
pub enum DomainLookupError {
    /// The name is not a hostname.
    #[error("{0}")]
    NotAHostname(String),
    /// The saved settings do not give a usable DNS upstream.
    #[error("{0}")]
    NoResolver(String),
    #[error(transparent)]
    Store(StoreError),
    #[error("the lookup did not finish: {0}")]
    Interrupted(String),
}

impl From<antiwire_dns::DnsError> for DomainLookupError {
    fn from(error: antiwire_dns::DnsError) -> Self {
        match error {
            antiwire_dns::DnsError::Upstream(message) => Self::NotAHostname(message),
            other => Self::NoResolver(other.to_string()),
        }
    }
}

/// A registration record, and when it was read.
#[derive(Debug, Clone)]
pub struct RegistrationLookup {
    pub record: Registration,
    pub fetched_at: OffsetDateTime,
}

/// The names under a domain in local history.
#[derive(Debug, Clone)]
pub struct SeenSubdomains {
    /// The domain they were collected under.
    pub domain: String,
    /// Busiest first, at most [`SEEN_SUBDOMAIN_LIMIT`].
    pub names: Vec<SeenSubdomain>,
    /// More names were seen than are listed.
    pub truncated: bool,
}

/// What the Certificate Transparency index answered for a domain.
#[derive(Debug)]
pub struct CertificateLookup {
    /// The domain that was searched.
    pub domain: String,
    pub result: Result<CertificateSearchResult, antiwire_lookup::Error>,
}

/// Answers the record inspector.
pub struct DomainLookupService {
    store: Arc<Store>,
    settings: SettingsFeed,
    registry: Arc<dyn RegistryClient>,
    certificates: Arc<dyn CertificateLog>,
}

impl DomainLookupService {
    #[must_use]
    pub fn new(context: &ServiceContext, clients: &LookupClients) -> Self {
        Self {
            store: Arc::clone(&context.store),
            settings: context.settings.clone(),
            registry: Arc::clone(&clients.registry),
            certificates: Arc::clone(&clients.certificates),
        }
    }

    /// Reads the registration record for one observed hostname.
    ///
    /// The record is saved only when `save_domain_lookups` is on, and not if
    /// the user deleted the domain while the lookup ran. A failed save is
    /// logged and the record still returned.
    ///
    /// # Errors
    ///
    /// Why the registry gave no record.
    pub async fn registration(
        &self,
        domain: &str,
    ) -> Result<RegistrationLookup, antiwire_lookup::Error> {
        let fence = DeletionFence::now();
        let record = self.registry.lookup(lookup_name(domain)).await?;
        let fetched_at = OffsetDateTime::now_utc();
        if self.settings.current().save_domain_lookups {
            let store = Arc::clone(&self.store);
            let row = registration_row(&record, fetched_at);
            match tokio::task::spawn_blocking(move || store.upsert_domain_lookup(&row, fence)).await
            {
                Ok(Ok(_)) => {}
                Ok(Err(error)) => tracing::warn!(%error, "saving domain lookup failed"),
                Err(error) => tracing::warn!(%error, "saving domain lookup did not finish"),
            }
        }
        Ok(RegistrationLookup { record, fetched_at })
    }

    /// Asks the configured upstream for the host's and its domain's records.
    ///
    /// The upstream is built from the saved settings, so Antiwire's own
    /// policy never answers: a blocked name still shows its real records.
    ///
    /// # Errors
    ///
    /// [`DomainLookupError::NotAHostname`] or
    /// [`DomainLookupError::NoResolver`].
    pub async fn dns_records(
        &self,
        host: &str,
        domain_hint: &str,
        address: Option<IpAddr>,
    ) -> Result<antiwire_dns::RecordLookup, DomainLookupError> {
        let settings = self.settings.current();
        Ok(
            antiwire_dns::lookup_records(&settings, lookup_name(host), hint(domain_hint), address)
                .await?,
        )
    }

    /// Names equal to or under the host's domain in local connection and DNS
    /// history.
    ///
    /// # Errors
    ///
    /// As [`Self::dns_records`] when the domain cannot be found, or a store
    /// failure.
    pub async fn seen_subdomains(
        &self,
        host: &str,
        domain_hint: &str,
    ) -> Result<SeenSubdomains, DomainLookupError> {
        let domain = self.domain_of(host, domain_hint).await?;
        let store = Arc::clone(&self.store);
        let under = domain.clone();
        let mut names = tokio::task::spawn_blocking(move || {
            store.seen_subdomains(&under, SEEN_SUBDOMAIN_LIMIT + 1)
        })
        .await
        .map_err(|error| DomainLookupError::Interrupted(error.to_string()))?
        .map_err(DomainLookupError::Store)?;
        let truncated = names.len() > SEEN_SUBDOMAIN_LIMIT;
        names.truncate(SEEN_SUBDOMAIN_LIMIT);
        Ok(SeenSubdomains {
            domain,
            names,
            truncated,
        })
    }

    /// Names under the host's domain on Certificate Transparency logs.
    ///
    /// This is the one lookup that sends the domain to a third party, so the
    /// client only calls it when the user asks.
    ///
    /// # Errors
    ///
    /// As [`Self::dns_records`] when the domain cannot be found. What the
    /// index answered, failures included, is in the result.
    pub async fn certificates(
        &self,
        host: &str,
        domain_hint: &str,
    ) -> Result<CertificateLookup, DomainLookupError> {
        let domain = self.domain_of(host, domain_hint).await?;
        let result = self.certificates.search(&domain).await;
        Ok(CertificateLookup { domain, result })
    }

    /// The registered domain for a host: the hint when it fits, else the
    /// zone the configured DNS upstream reports.
    async fn domain_of(&self, host: &str, domain_hint: &str) -> Result<String, DomainLookupError> {
        let settings = self.settings.current();
        Ok(antiwire_dns::find_domain(&settings, lookup_name(host), hint(domain_hint)).await?)
    }
}

/// The saved form of a registration record.
pub(crate) fn registration_row(record: &Registration, fetched_at: OffsetDateTime) -> DomainLookup {
    DomainLookup {
        domain: record.domain.clone(),
        source: record.source.as_str().to_owned(),
        registrar: record.registrar.clone(),
        registrar_id: record.registrar_id.clone(),
        statuses: record.statuses.clone(),
        nameservers: record.nameservers.clone(),
        registered_at: record.registered_at,
        expires_at: record.expires_at,
        registry_updated_at: record.updated_at,
        registrant_name: record.registrant_name.clone(),
        registrant_organization: record.registrant_organization.clone(),
        redacted: record.redacted,
        dnssec: record.dnssec,
        fetched_at,
    }
}

/// The hostname to ask about: a stored domain may end in the
/// inferred-domain marker, which is display text and not part of the name.
pub(crate) fn lookup_name(domain: &str) -> &str {
    let domain = domain.trim();
    domain
        .strip_suffix(INFERRED_SUFFIX)
        .unwrap_or(domain)
        .trim()
}

fn hint(domain_hint: &str) -> Option<&str> {
    Some(lookup_name(domain_hint)).filter(|hint| !hint.is_empty())
}
