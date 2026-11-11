//! Shared daemon service graph for gRPC and background workers.

use std::sync::Arc;

use antiwire_capture::CaptureSession;
use antiwire_dns::DnsInterceptorSlot;
use antiwire_enforce::EnforcementClient;
use antiwire_events::{AlertPublisher, CollectorHealth, NotificationHub, TrafficStreamingHub};
use antiwire_flow::{
    AppIdResolver, DnsBlockRecorder, DnsQueryCorrelator, FlowProcessor, FlowTracker,
    StoreFlowAdapter,
};
use antiwire_geo::{GeoIpLookup, OuiResolver};
use antiwire_platform::{DataPaths, SiemConfig, SiemExporter};
use antiwire_policy::RuleEngine;
use antiwire_services::{
    DomainServices, DomainServicesParts, LookupClients, RuleService, ServiceContext, SettingsFeed,
};
use antiwire_store::Store;
use antiwire_update::launcher::DetachedLauncher;
use antiwire_update::{Channel, UpdateService, UpdateSupport};
use arc_swap::ArcSwap;
use parking_lot::RwLock;
use tokio_util::sync::CancellationToken;
use tracing::warn;

use crate::rule_retarget::RuleRetargeter;

/// Live handles shared between gRPC, collectors, and schedulers.
pub struct DaemonContext {
    pub store: Arc<Store>,
    pub enforce: EnforcementClient,
    pub services: DomainServices,
    pub flow_tracker: Arc<FlowTracker<antiwire_flow::StoreFlowAdapter>>,
    /// Collector capability status, written by the flow tracker and read by gRPC stats.
    pub collector_health: Arc<CollectorHealth>,
    pub capture: Arc<CaptureSession>,
    pub siem: SiemExporter,
    pub traffic_hub: TrafficStreamingHub,
    pub alerts: AlertPublisher,
    pub dns_interceptor: Arc<DnsInterceptorSlot>,
    pub dns_block_recorder: Arc<DnsBlockRecorder>,
    pub updates: Arc<UpdateService>,
    pub settings: SettingsFeed,
    /// Cancelled once, at shutdown; every background service stops on it.
    pub shutdown: CancellationToken,
}

impl DaemonContext {
    pub fn request_shutdown(&self) {
        self.shutdown.cancel();
        self.traffic_hub.cancel_all();
    }
}

/// Builds the service graph the runtime, the IPC server and the background
/// workers share.
pub(crate) fn assemble_daemon_context(
    data_paths: DataPaths,
    store: Arc<Store>,
    settings_feed: SettingsFeed,
    enforce: EnforcementClient,
    updates: Arc<UpdateService>,
    lookups: LookupClients,
) -> Arc<DaemonContext> {
    let settings = &*settings_feed.current();
    let rule_engine = Arc::new(RwLock::new(RuleEngine::new()));
    let flow_store = StoreFlowAdapter::new(Arc::clone(&store));
    let traffic_hub = TrafficStreamingHub::new();
    let siem = SiemExporter::new(SiemConfig::from_settings(settings));
    let alerts = AlertPublisher::saved(
        NotificationHub::new(),
        Arc::clone(&store),
        Some(siem.clone()),
    );
    let rule_service = Arc::new(RuleService::new(
        Arc::clone(&store),
        Arc::clone(&rule_engine),
        enforce.clone(),
        alerts.clone(),
    ));
    // Empty until the `GeoIP` service loads the database at start.
    let geo = Arc::new(ArcSwap::from_pointee(GeoIpLookup::new()));
    let app_resolver = Arc::new(
        AppIdResolver::new(Arc::clone(&store), alerts.clone(), siem.clone()).with_rule_retargeter(
            Arc::new(RuleRetargeter::spawn(
                Arc::clone(&rule_service),
                alerts.clone(),
            )),
        ),
    );
    let dns_correlator = Arc::new(DnsQueryCorrelator::default());
    let flow_processor = Arc::new(FlowProcessor::with_correlator(
        Arc::clone(&app_resolver),
        Some(Arc::clone(&geo)),
        Arc::clone(&rule_engine),
        Arc::clone(&store),
        traffic_hub.clone(),
        alerts.clone(),
        siem.clone(),
        Arc::clone(&dns_correlator),
    ));
    let dns_block_recorder = DnsBlockRecorder::with_correlator(
        app_resolver,
        Arc::clone(&store),
        alerts.clone(),
        siem.clone(),
        Arc::clone(&dns_correlator),
    );
    dns_block_recorder.update_settings(
        settings.log_daemon_connections,
        settings.notify_threat_detected,
    );
    let collector_health = Arc::new(CollectorHealth::default());
    dns_block_recorder.set_collector_health(Arc::clone(&collector_health));
    let flow_tracker = Arc::new(
        FlowTracker::with_processor(flow_store, Some(flow_processor))
            .with_collector_health(Arc::clone(&collector_health)),
    );
    let shutdown = CancellationToken::new();
    let dns_interceptor = Arc::new(antiwire_dns::DnsInterceptorSlot::new());
    let services = DomainServices::assemble(DomainServicesParts {
        context: ServiceContext {
            store: Arc::clone(&store),
            settings: settings_feed.clone(),
            alerts: alerts.clone(),
            data_paths,
            shutdown: shutdown.clone(),
        },
        rules: rule_service,
        engine: rule_engine,
        enforce: enforce.clone(),
        geo,
        dns_interceptor: Arc::clone(&dns_interceptor),
        dns_block_sink: Some(Arc::clone(&dns_block_recorder) as Arc<dyn antiwire_dns::DnsBlockSink>),
        siem: siem.clone(),
        oui: OuiResolver::from_embedded().ok(),
        lookups,
    });

    Arc::new(DaemonContext {
        store,
        enforce,
        services,
        flow_tracker,
        collector_health,
        capture: Arc::new(CaptureSession::new()),
        siem,
        traffic_hub,
        alerts,
        dns_interceptor,
        dns_block_recorder,
        updates,
        settings: settings_feed,
        shutdown,
    })
}

/// Builds the updater. Only a service install on a release build with the
/// versioned layout can install; everything else reports why it cannot. The
/// update channel is read from the saved settings at each check, so a change
/// applies to the next check without a restart.
pub(crate) fn build_update_service(
    data_dir: &std::path::Path,
    is_service: bool,
    settings: SettingsFeed,
) -> Arc<UpdateService> {
    let support = match std::env::current_exe() {
        Ok(daemon_exe) => UpdateSupport::detect(data_dir, &daemon_exe, is_service),
        Err(error) => {
            warn!(error = %error, "cannot locate the daemon executable; updates are unavailable");
            UpdateSupport::Unsupported {
                reason: "the daemon executable path is unknown".to_owned(),
                trust: None,
            }
        }
    };
    UpdateService::with_channel(
        support,
        Arc::new(DetachedLauncher),
        Arc::new(move || Channel::parse_or_stable(&settings.current().update_channel)),
    )
}
