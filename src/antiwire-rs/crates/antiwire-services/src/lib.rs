//! Domain services of the Antiwire daemon.
//!
//! Rule persistence and enforcement, the `DoH` block, hosts blocklists, the
//! `GeoIP` database, network mapping, the saved AI decisions, and domain
//! lookups. Nothing here depends on the IPC
//! transport: the IPC layer calls these services and converts their results
//! to wire types.

mod ai_decisions;
mod assemble;
mod background;
mod backoff;
mod blocklist_target;
mod context;
mod doh;
mod domain_lookup;
mod geo_database;
mod hosts_blocklist;
mod lookup_clients;
#[cfg(test)]
mod lookup_fakes;
mod network_mapping;
mod rule_service;
mod settings_feed;
mod settings_service;
mod sync_runner;

pub use ai_decisions::{AiDecisionError, AiDecisionService, Scan};
pub use assemble::{DomainServices, DomainServicesParts};
pub use blocklist_target::BlocklistTarget;
pub use context::ServiceContext;
pub use doh::{DohBlockError, DohBlocker};
pub use domain_lookup::{
    CertificateLookup, DomainLookupError, DomainLookupService, RegistrationLookup, SeenSubdomains,
    SEEN_SUBDOMAIN_LIMIT,
};
pub use geo_database::{GeoDatabaseService, GeoDatabaseSource, JsDelivrGeoSource};
pub use hosts_blocklist::{HostsBlocklistService, HostsFetcher, HttpHostsFetcher};
pub use lookup_clients::{
    CertificateLog, ClassifierSource, DomainClassifier, LookupClients, RegistryClient,
    TypeSafeClassifiers,
};
pub use network_mapping::{
    watch_matches_addr, DeviceWatchRequest, NetworkMappingWorker, NetworkMappingWorkerError,
    NetworkOverview, NetworkScanner, SystemScanner,
};
pub use rule_service::{
    CountryRuleSummary, CountrySelector, DomainBlock, NewCountryBlock, NewRule, RetargetOutcome,
    RuleListing, RuleSelector, RuleService, RuleServiceError,
};
pub use settings_feed::SettingsFeed;
pub use settings_service::{SettingsError, SettingsService, SettingsServiceParts, SettingsUpdate};
