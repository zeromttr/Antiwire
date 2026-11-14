//! Wiring every domain service together, in one place.

use std::sync::Arc;

use antiwire_dns::{DnsBlockSink, DnsDependencies, DnsInterceptorSlot};
use antiwire_enforce::EnforcementClient;
use antiwire_geo::{GeoIpLookup, OuiResolver};
use antiwire_platform::SiemExporter;
use antiwire_policy::RuleEngine;
use arc_swap::ArcSwap;
use parking_lot::RwLock;

use crate::ai_decisions::AiDecisionService;
use crate::blocklist_target::BlocklistTarget;
use crate::context::ServiceContext;
use crate::doh::DohBlocker;
use crate::domain_lookup::DomainLookupService;
use crate::geo_database::GeoDatabaseService;
use crate::hosts_blocklist::HostsBlocklistService;
use crate::lookup_clients::LookupClients;
use crate::network_mapping::NetworkMappingWorker;
use crate::rule_service::RuleService;
use crate::settings_service::{SettingsService, SettingsServiceParts};

/// What the domain services are built from.
pub struct DomainServicesParts {
    pub context: ServiceContext,
    /// Built first, because the flow layer that reports application moves
    /// to it is built before the rest.
    pub rules: Arc<RuleService>,
    /// Evaluates rules, blocklists, and AI decisions; DNS answers from it.
    pub engine: Arc<RwLock<RuleEngine>>,
    pub enforce: EnforcementClient,
    /// The lookup flows are enriched from; the `GeoIP` service fills it.
    pub geo: Arc<ArcSwap<GeoIpLookup>>,
    pub dns_interceptor: Arc<DnsInterceptorSlot>,
    pub dns_block_sink: Option<Arc<dyn DnsBlockSink>>,
    pub siem: SiemExporter,
    pub oui: Option<OuiResolver>,
    /// The registries, certificate index, and classifier asked on request.
    pub lookups: LookupClients,
}

/// Every domain service, wired to one context. The daemon and the tests
/// both build their services here, so they cannot drift apart.
#[derive(Clone)]
pub struct DomainServices {
    pub rules: Arc<RuleService>,
    pub doh: Arc<DohBlocker>,
    pub hosts_blocklist: Arc<HostsBlocklistService>,
    pub geo_database: Arc<GeoDatabaseService>,
    pub network_mapping: Arc<NetworkMappingWorker>,
    pub settings: Arc<SettingsService>,
    pub ai_decisions: Arc<AiDecisionService>,
    pub domain_lookup: Arc<DomainLookupService>,
    /// What the DNS interceptor is started with.
    pub dns: DnsDependencies,
}

impl DomainServices {
    #[must_use]
    pub fn assemble(parts: DomainServicesParts) -> Self {
        let DomainServicesParts {
            context,
            rules,
            engine,
            enforce,
            geo,
            dns_interceptor,
            dns_block_sink,
            siem,
            oui,
            lookups,
        } = parts;
        let doh = Arc::new(DohBlocker::new(Arc::clone(&context.store), enforce));
        let hosts_blocklist = Arc::new(HostsBlocklistService::new(
            &context,
            Arc::clone(&engine) as Arc<dyn BlocklistTarget>,
        ));
        let geo_database = Arc::new(GeoDatabaseService::new(&context, geo));
        let network_mapping = Arc::new(NetworkMappingWorker::new(&context, oui));
        let ai_decisions = Arc::new(AiDecisionService::new(&context, &lookups));
        let domain_lookup = Arc::new(DomainLookupService::new(&context, &lookups));
        let dns = DnsDependencies {
            engine,
            store: Arc::clone(&context.store),
            data_dir: context.data_paths.root.clone(),
            block_sink: dns_block_sink,
            alerts: Some(context.alerts.clone()),
            registration_dates: Some(lookups.registration_dates.clone()),
        };
        let settings = Arc::new(SettingsService::new(SettingsServiceParts {
            rules: Arc::clone(&rules),
            settings: context.settings.clone(),
            doh: Arc::clone(&doh),
            dns: dns.clone(),
            dns_interceptor,
            hosts_blocklist: Arc::clone(&hosts_blocklist),
            geo_database: Arc::clone(&geo_database),
            siem,
        }));
        Self {
            rules,
            doh,
            hosts_blocklist,
            geo_database,
            network_mapping,
            settings,
            ai_decisions,
            domain_lookup,
            dns,
        }
    }
}
