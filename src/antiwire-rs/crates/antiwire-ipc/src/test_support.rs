//! A gRPC service over a temporary store, for tests.

use std::ops::Deref;
use std::sync::Arc;

use antiwire_capture::CaptureSession;
use antiwire_enforce::{EnforcementClient, FirewallFilter};
use antiwire_events::{
    ActiveConnectionCounter, AlertPublisher, CollectorHealth, NotificationHub, TrafficStreamingHub,
    ZeroActiveConnectionCounter,
};
use antiwire_geo::GeoIpLookup;
use antiwire_platform::{DataPaths, SiemConfig, SiemExporter};
use antiwire_policy::{EnforcementOp, RuleEngine};
use antiwire_services::{
    DomainServices, DomainServicesParts, LookupClients, RuleService, ServiceContext, SettingsFeed,
};
use antiwire_store::Store;
use antiwire_update::launcher::DetachedLauncher;
use antiwire_update::{UpdateService, UpdateSupport};
use arc_swap::ArcSwap;
use parking_lot::RwLock;
use tokio_util::sync::CancellationToken;

use crate::service::{ServiceImpl, ServiceParts};

/// A firewall that accepts every change and installs nothing.
struct AcceptingFirewall {
    started: bool,
}

impl FirewallFilter for AcceptingFirewall {
    fn start(&mut self) -> antiwire_enforce::Result<()> {
        self.started = true;
        Ok(())
    }

    fn stop(&mut self) -> antiwire_enforce::Result<()> {
        self.started = false;
        Ok(())
    }

    fn is_enforcing(&self) -> bool {
        self.started
    }

    fn apply(&mut self, _op: EnforcementOp) -> antiwire_enforce::Result<()> {
        Ok(())
    }
}

/// A [`ServiceImpl`] over a temporary store, wired the way the daemon wires
/// its own, with no flow tracker and a firewall that installs nothing.
pub struct TestService {
    service: ServiceImpl,
    /// The store the service reads and writes.
    pub store: Arc<Store>,
    /// Publishes alerts to the service's notification stream.
    pub alerts: AlertPublisher,
    /// The domain services the RPCs reach, for arranging their state.
    pub services: DomainServices,
    /// Ends the service's streams when cancelled.
    pub shutdown: CancellationToken,
    // Last, so the store's files close before the directory is removed.
    _dir: tempfile::TempDir,
}

impl TestService {
    /// # Panics
    ///
    /// Panics if the temporary store or firewall worker cannot be created.
    #[must_use]
    pub fn new() -> Self {
        Self::with_active_connections(Arc::new(ZeroActiveConnectionCounter))
    }

    /// A service whose connection counts come from `active_connections`.
    ///
    /// # Panics
    ///
    /// Panics if the temporary store or firewall worker cannot be created.
    #[must_use]
    pub fn with_active_connections(active_connections: Arc<dyn ActiveConnectionCounter>) -> Self {
        let parts = TestParts::new(active_connections);
        Self {
            store: Arc::clone(&parts.service.store),
            alerts: parts.service.alerts.clone(),
            services: parts.service.services.clone(),
            shutdown: parts.service.shutdown.clone(),
            service: ServiceImpl::new(parts.service),
            _dir: parts.dir,
        }
    }

    /// Starts the daemon's shutdown, as the runtime does.
    pub fn begin_shutdown(&self) {
        self.shutdown.cancel();
    }
}

/// What a [`TestService`] is built from, for a test that serves it.
pub(crate) struct TestParts {
    pub(crate) service: ServiceParts,
    /// Holds the store's files; drop it after the service.
    pub(crate) dir: tempfile::TempDir,
}

impl TestParts {
    pub(crate) fn new(active_connections: Arc<dyn ActiveConnectionCounter>) -> Self {
        let dir = tempfile::tempdir().expect("temporary directory");
        let data_paths = DataPaths::new(dir.path());
        let store = Arc::new(Store::open(data_paths.database()).expect("open the temporary store"));
        let siem = SiemExporter::new(SiemConfig::default());
        let alerts = AlertPublisher::saved(
            NotificationHub::new(),
            Arc::clone(&store),
            Some(siem.clone()),
        );
        let enforce = EnforcementClient::with_filter(AcceptingFirewall { started: false })
            .expect("firewall worker");
        enforce.start().expect("start the firewall worker");
        let engine = Arc::new(RwLock::new(RuleEngine::new()));
        let rules = Arc::new(RuleService::new(
            Arc::clone(&store),
            Arc::clone(&engine),
            enforce.clone(),
            alerts.clone(),
        ));
        let services = DomainServices::assemble(DomainServicesParts {
            context: ServiceContext {
                store: Arc::clone(&store),
                settings: SettingsFeed::load(Arc::clone(&store)).expect("settings"),
                alerts: alerts.clone(),
                data_paths,
                shutdown: CancellationToken::new(),
            },
            rules,
            engine,
            enforce,
            geo: Arc::new(ArcSwap::from_pointee(GeoIpLookup::new())),
            dns_interceptor: Arc::new(antiwire_dns::DnsInterceptorSlot::new()),
            dns_block_sink: None,
            siem,
            oui: None,
            lookups: LookupClients::online().expect("lookup clients"),
        });
        let service = ServiceParts {
            services,
            store,
            traffic_hub: TrafficStreamingHub::new(),
            alerts,
            active_connections,
            collector_health: Arc::new(CollectorHealth::default()),
            capture: Arc::new(CaptureSession::new()),
            updates: UpdateService::new(
                UpdateSupport::Unsupported {
                    reason: "test".into(),
                    trust: None,
                },
                Arc::new(DetachedLauncher),
            ),
            shutdown: CancellationToken::new(),
        };
        Self { service, dir }
    }
}

impl Default for TestService {
    fn default() -> Self {
        Self::new()
    }
}

impl Deref for TestService {
    type Target = ServiceImpl;

    fn deref(&self) -> &ServiceImpl {
        &self.service
    }
}
