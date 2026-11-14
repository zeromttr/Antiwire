//! Outside services that answer from memory, for tests.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use antiwire_ai::{AdvancedAssessment, DomainAssessment, RegistrationEvidence};
use antiwire_lookup::{CertificateSearchResult, Registration, Source};
use antiwire_platform::DataPaths;
use antiwire_store::{DaemonSetting, SecretBytes, Store};
use time::macros::datetime;
use tokio_util::sync::CancellationToken;

use crate::context::ServiceContext;
use crate::lookup_clients::{
    CertificateLog, ClassifierSource, DomainClassifier, LookupClients, RegistryClient,
};
use crate::settings_feed::SettingsFeed;

/// A registry that knows one record, for whatever name is asked.
pub(crate) struct FakeRegistry {
    pub(crate) calls: AtomicUsize,
}

#[async_trait::async_trait]
impl RegistryClient for FakeRegistry {
    async fn lookup(&self, domain: &str) -> Result<Registration, antiwire_lookup::Error> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if domain == "unregistered.example" {
            return Err(antiwire_lookup::Error::NotFound(domain.to_owned()));
        }
        Ok(registration(domain))
    }
}

/// An index with no certificates on record.
pub(crate) struct NoCertificates;

#[async_trait::async_trait]
impl CertificateLog for NoCertificates {
    async fn search(
        &self,
        _domain: &str,
    ) -> Result<CertificateSearchResult, antiwire_lookup::Error> {
        Err(antiwire_lookup::Error::RateLimited)
    }
}

/// Scores every domain as advertising, with the given probability.
pub(crate) struct FakeClassifier(pub(crate) f64);

#[async_trait::async_trait]
impl DomainClassifier for FakeClassifier {
    async fn classify(&self, domain: &str) -> Result<DomainAssessment, antiwire_ai::Error> {
        Ok(assessment(domain, self.0))
    }

    async fn classify_advanced(
        &self,
        evidence: &RegistrationEvidence,
    ) -> Result<AdvancedAssessment, antiwire_ai::Error> {
        Ok(AdvancedAssessment {
            assessment: assessment(&evidence.domain, self.0),
            newly_registered: 0.9,
            registry_hold: 0.0,
            hidden_registrant: f64::from(u8::from(evidence.redacted)),
            abusive_registrar: 0.0,
        })
    }
}

impl ClassifierSource for FakeClassifier {
    fn connect(&self, _api_key: &str) -> Result<Box<dyn DomainClassifier>, antiwire_ai::Error> {
        Ok(Box::new(Self(self.0)))
    }
}

fn assessment(domain: &str, advertising: f64) -> DomainAssessment {
    DomainAssessment {
        domain: domain.to_owned(),
        model: "fake".to_owned(),
        advertising,
        tracking: 0.0,
        telemetry: 0.0,
        analytics: 0.0,
        malicious: 0.0,
        security_fraud: 0.0,
        cryptomining: 0.0,
        tunnel: 0.0,
    }
}

pub(crate) fn registration(domain: &str) -> Registration {
    Registration {
        domain: domain.to_owned(),
        queried: domain.to_owned(),
        source: Source::Rdap,
        registrar: Some("Example Registrar".to_owned()),
        registrar_id: None,
        statuses: vec!["client transfer prohibited".to_owned()],
        nameservers: vec!["a.iana-servers.net".to_owned()],
        registered_at: Some(datetime!(1995-08-14 04:00 UTC)),
        expires_at: None,
        updated_at: None,
        registrant_name: None,
        registrant_organization: None,
        redacted: true,
        dnssec: Some(true),
        ds_records: Vec::new(),
        nameserver_addresses: Vec::new(),
        handle: None,
        unicode_name: None,
        registrar_url: None,
        registrar_country: None,
        whois_server: None,
        abuse_email: None,
        abuse_phone: None,
        abuse_url: None,
        registrant_country: None,
        registrant_region: None,
        registrant_contact_url: None,
        registrar_expires_at: None,
        transferred_at: None,
        database_updated_at: None,
        registry_source: None,
        registrar_source: None,
    }
}

/// A context over a fresh store, and fake outside services.
pub(crate) struct LookupHarness {
    _dir: tempfile::TempDir,
    pub(crate) context: ServiceContext,
    pub(crate) registry: Arc<FakeRegistry>,
    pub(crate) clients: LookupClients,
}

impl LookupHarness {
    pub(crate) fn new(advertising: f64) -> Self {
        let dir = tempfile::tempdir().expect("temp dir");
        let data_paths = DataPaths::new(dir.path());
        let store = Arc::new(Store::open(data_paths.database()).expect("open store"));
        let context = ServiceContext {
            settings: SettingsFeed::load(Arc::clone(&store)).expect("feed"),
            store,
            alerts: antiwire_events::AlertPublisher::unsaved(
                antiwire_events::NotificationHub::with_capacity(4),
                None,
            ),
            data_paths,
            shutdown: CancellationToken::new(),
        };
        let registry = Arc::new(FakeRegistry {
            calls: AtomicUsize::new(0),
        });
        let clients = LookupClients {
            registry: Arc::clone(&registry) as Arc<dyn RegistryClient>,
            certificates: Arc::new(NoCertificates),
            classifiers: Arc::new(FakeClassifier(advertising)),
            registration_dates: antiwire_dns::RegistrationDates::official(Arc::new(
                antiwire_lookup::Lookup::new().expect("lookup client"),
            )),
        };
        Self {
            _dir: dir,
            context,
            registry,
            clients,
        }
    }

    /// Saves an API key, and whether registration records are kept.
    pub(crate) fn configure(&self, api_key: &str, save_domain_lookups: bool) {
        self.context
            .settings
            .modify(|saved| {
                Ok(DaemonSetting {
                    ai_api_key: SecretBytes::from_string(api_key.to_owned()),
                    save_domain_lookups,
                    ..saved.clone()
                })
            })
            .expect("save settings");
    }

    pub(crate) fn registry_calls(&self) -> usize {
        self.registry.calls.load(Ordering::SeqCst)
    }
}
