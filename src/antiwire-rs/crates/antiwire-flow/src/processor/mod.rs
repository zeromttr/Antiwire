use std::collections::HashMap;
use std::net::IpAddr;
use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

use antiwire_events::{
    Alert, AlertKind, AlertPublisher, Severity, TrafficEvent, TrafficEventKind, TrafficStreamingHub,
};
use antiwire_geo::GeoIpLookup;
use antiwire_platform::SiemExporter;
use antiwire_policy::{DomainBlockSource, RuleEngine, Verdict, FIREWALL_RULE_LABEL};
use antiwire_store::{DnsCacheEntry, NewConnectionLog};
use antiwire_tuning::SEEN_DOMAINS_CAP;
use arc_swap::ArcSwap;
use lru::LruCache;
use netmetrics_core::{
    ByteDelta, DnsResolutionAttribution, FlowEvent, FlowKey, FlowMeta, Protocol,
};
use parking_lot::{Mutex, RwLock};
use time::OffsetDateTime;

use crate::app_resolver::{AppIdResolver, ResolvedApplication};
use crate::correlator::DnsQueryCorrelator;
use crate::domain_stats::{DomainLookupSnapshot, DomainLookupStats, HintSource};
use crate::process_resolver::ProcessIdentities;
use crate::sanitize;
use crate::store::DomainStore;
use crate::system_services::SystemAttributor;
use crate::timestamps::unix_secs;

mod closed_names;
mod dns_hints;
mod domain_names;
mod hint_scopes;
mod newly_named;
mod system_attribution;

use closed_names::{ClosedNames, ReadyUpgrade};
use domain_names::{needs_dns_sanitization, strip_inferred_suffix};
use hint_scopes::HintScopes;
pub(crate) use hint_scopes::Opening;
pub(crate) use newly_named::NewlyNamed;

/// PIDs whose image is remembered for classifying their DNS hints; past
/// this, the one used least recently is forgotten.
const HINT_IMAGE_CACHE_CAP: usize = 4_096;

/// How far the answer of one name lookup can be relied on.
///
/// A connection is named from the hints its process held when it opened. A
/// hint is stamped when its answer was given and can be delivered a second or
/// more later, so a lookup made just after a connection opened may not have
/// seen all of them. Its answer is provisional until they have had time to
/// arrive: evidence that turns up before then may be from before the opening,
/// and what a lookup then finds replaces the answer, confirmed or not.
///
/// Once the answer is complete it only gets stronger, and one that is
/// confirmed, or was left open because the process's own names competed, is
/// final. Nothing recorded after the connection opened changes either.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct Naming {
    /// When every hint recorded before the connection opened will have
    /// arrived, in Unix epoch milliseconds.
    pub(crate) complete_at_ms: u64,
    /// Whether the answer is final once it is complete.
    pub(crate) lasting: bool,
}

impl Naming {
    /// Whether evidence that arrives at `at_ms` may be from before the
    /// connection opened, so that what is found then replaces the answer.
    pub(crate) fn provisional_at(self, at_ms: u64) -> bool {
        at_ms < self.complete_at_ms
    }

    /// Whether evidence that arrives at `at_ms` could change the answer.
    pub(crate) fn open_at(self, at_ms: u64) -> bool {
        !self.lasting || self.provisional_at(at_ms)
    }
}

/// What is asked of a connection's name as its row is written.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum NameRequest {
    /// Keep the name as written: nothing new is known about its address.
    Keep,
    /// Look the name up as of the connection's opening.
    Judge {
        opening: Opening,
        /// The answer takes the place of the written name, even where it is
        /// weaker or there is none: the written one was provisional, or was
        /// judged for another owner. Otherwise the answer only strengthens
        /// the written name.
        replaces: bool,
    },
}

impl NameRequest {
    /// A lookup whose answer only strengthens the written name.
    #[cfg(test)]
    pub(crate) fn adding(opening: Opening) -> Self {
        Self::Judge {
            opening,
            replaces: false,
        }
    }

    /// A lookup whose answer takes the place of the written name.
    pub(crate) fn replacing(opening: Opening) -> Self {
        Self::Judge {
            opening,
            replaces: true,
        }
    }
}

/// Enriches flow events with policy, geo, DNS, and fan-out side effects.
pub struct FlowProcessor {
    app_resolver: Arc<AppIdResolver>,
    geo: Option<Arc<ArcSwap<GeoIpLookup>>>,
    rule_engine: Arc<RwLock<RuleEngine>>,
    store: Arc<dyn DomainStore>,
    traffic_hub: TrafficStreamingHub,
    alerts: AlertPublisher,
    siem: SiemExporter,
    correlator: Arc<DnsQueryCorrelator>,
    dns_hints: RwLock<HintScopes>,
    /// DNS answers observed since the last flush, keyed by canonical IP.
    pending_dns: Mutex<HashMap<IpAddr, DnsCacheEntry>>,
    /// Set while the last DNS cache write failed, so a full buffer waits for the
    /// flush tick instead of retrying inline on every answer.
    dns_cache_failing: AtomicBool,
    /// Domains already recorded in `seen_domains`, so a repeated close does not
    /// compile and run an `INSERT OR IGNORE` for a domain it has already seen.
    /// A domain that falls out is announced again, which the store ignores.
    seen_domains: Mutex<LruCache<String, ()>>,
    /// Inferred-to-confirmed domain upgrades performed by enrichment.
    domain_upgrades: AtomicU64,
    /// Which lookup step named each connection, and where hints came from.
    domain_stats: DomainLookupStats,
    /// What a hinting PID's image says about it, until the process stops.
    hint_images: Mutex<LruCache<u32, dns_hints::HintImage>>,
    /// Closed connections whose name could still change.
    closed_names: Mutex<ClosedNames>,
    /// Addresses DNS evidence has arrived for since the tracker last asked.
    newly_named: Mutex<NewlyNamed>,
    /// Names for closed connections' written or queued rows, oldest first,
    /// with write attempts left.
    ready_domain_upgrades: Mutex<Vec<ReadyUpgrade>>,
    /// Rate-limited impersonation alert gate for system-service signatures.
    system_attributor: SystemAttributor,
}

impl FlowProcessor {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        app_resolver: Arc<AppIdResolver>,
        geo: Option<Arc<ArcSwap<GeoIpLookup>>>,
        rule_engine: Arc<RwLock<RuleEngine>>,
        store: Arc<impl DomainStore + 'static>,
        traffic_hub: TrafficStreamingHub,
        alerts: AlertPublisher,
        siem: SiemExporter,
    ) -> Self {
        Self::with_correlator(
            app_resolver,
            geo,
            rule_engine,
            store,
            traffic_hub,
            alerts,
            siem,
            Arc::new(DnsQueryCorrelator::default()),
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn with_correlator(
        app_resolver: Arc<AppIdResolver>,
        geo: Option<Arc<ArcSwap<GeoIpLookup>>>,
        rule_engine: Arc<RwLock<RuleEngine>>,
        store: Arc<impl DomainStore + 'static>,
        traffic_hub: TrafficStreamingHub,
        alerts: AlertPublisher,
        siem: SiemExporter,
        correlator: Arc<DnsQueryCorrelator>,
    ) -> Self {
        Self {
            app_resolver,
            geo,
            rule_engine,
            store,
            traffic_hub,
            alerts,
            siem,
            correlator,
            dns_hints: RwLock::new(HintScopes::new()),
            pending_dns: Mutex::new(HashMap::new()),
            dns_cache_failing: AtomicBool::new(false),
            seen_domains: Mutex::new(bounded(SEEN_DOMAINS_CAP)),
            domain_upgrades: AtomicU64::new(0),
            domain_stats: DomainLookupStats::default(),
            hint_images: Mutex::new(bounded(HINT_IMAGE_CACHE_CAP)),
            closed_names: Mutex::new(ClosedNames::default()),
            newly_named: Mutex::new(NewlyNamed::default()),
            ready_domain_upgrades: Mutex::new(Vec::new()),
            system_attributor: SystemAttributor::new(),
        }
    }

    /// Number of inferred domains that process-scoped evidence upgraded.
    #[must_use]
    pub fn domain_upgrade_count(&self) -> u64 {
        self.domain_upgrades.load(Ordering::Relaxed)
    }

    /// The process evidence flows are attributed from.
    pub(crate) fn processes(&self) -> &ProcessIdentities {
        self.app_resolver.processes()
    }

    /// Counters for how connection domains were named.
    #[must_use]
    pub(crate) fn domain_lookup_stats(&self) -> DomainLookupSnapshot {
        self.domain_stats.snapshot()
    }

    pub(crate) fn handle_event(&self, event: &FlowEvent) {
        match event {
            FlowEvent::DnsResolved { answers, query, .. } => {
                self.record_dns_resolution(query, answers);
            }
            FlowEvent::DnsResolvedWithMetadata {
                attribution,
                answers,
                query,
                ttl_ms,
                observed_at,
            } => {
                let pid = match attribution {
                    DnsResolutionAttribution::Process(pid) => *pid,
                    DnsResolutionAttribution::Shared => 0,
                };
                self.record_hint(HintSource::Etw, pid, query, answers, *ttl_ms, *observed_at);
            }
            FlowEvent::DnsQuery(query) => {
                if needs_dns_sanitization(&query.name) {
                    let mut sanitized = query.clone();
                    sanitized.name = sanitize::trimmed(&query.name, sanitize::MAX_DOMAIN_CHARS);
                    self.correlator.record_query(&sanitized);
                } else {
                    self.correlator.record_query(query);
                }
            }
            FlowEvent::ProcessStarted(process) => {
                self.app_resolver.processes().process_started(
                    process.pid,
                    &process.identity.executable,
                    &process.identity.name,
                    process.identity.start_ts,
                );
                // A reused PID must not inherit its predecessor's names as
                // confirmed. Hints recorded since the start are this process's.
                self.hint_images.lock().pop(&process.pid);
                if process.identity.start_ts > 0 {
                    self.dns_hints
                        .write()
                        .forget_before(process.pid, process.identity.start_ts);
                }
            }
            FlowEvent::ProcessStopped { pid, stop_ts } => {
                self.app_resolver
                    .processes()
                    .process_stopped_at(*pid, *stop_ts);
                self.hint_images.lock().pop(pid);
            }
            _ => {}
        }
    }

    pub(crate) fn resolve_app(&self, pid: u32, meta: &FlowMeta) -> ResolvedApplication {
        let process = meta.process.as_ref();
        let meta_path = process.map(|process| process.executable.as_str());
        let meta_name = process.map(|process| process.name.as_str());
        let meta_start_ts = process.map(|process| process.start_ts);
        let identity =
            self.app_resolver
                .processes()
                .resolve(pid, meta_path, meta_name, meta_start_ts);
        // A process created after the flow opened took over the PID once the
        // flow's own process had exited, so it is not the flow's owner.
        if crate::process_resolver::started_after(identity.start_ts, meta.open_ts) {
            return self
                .app_resolver
                .application_for(crate::process_resolver::ResolvedIdentity {
                    path: String::new(),
                    name: String::new(),
                    start_ts: 0,
                });
        }
        self.app_resolver.application_for(identity)
    }

    /// Canonical identity for a flow with no observed PID at persist time.
    pub(crate) fn unknown_no_owner(&self) -> (i32, String, String) {
        self.app_resolver.unknown_no_owner()
    }

    /// Enrich a log whose byte counters represent the flow's lifetime totals.
    /// Persistence deltas cannot establish whether traffic was actually blocked.
    ///
    /// `log.dst_domain` comes in as the name the row has now and leaves as
    /// the name it should have, which `request` says how to arrive at. Where
    /// the store would not take that name over its own, the log is marked as
    /// replacing it.
    ///
    /// Returns what the lookup said of its answer, or `None` when the name
    /// was kept as written.
    pub(crate) fn enrich_connection_log(
        &self,
        key: &FlowKey,
        flow_pid: u32,
        app_path: &str,
        app_name: &str,
        request: NameRequest,
        log: &mut NewConnectionLog,
    ) -> Option<Naming> {
        if log.app_id <= 0 {
            if app_path.is_empty() {
                log.app_id = self.app_resolver.unknown_no_owner().0;
            } else {
                log.app_id = self.app_resolver.get_or_create_app_id(app_path, app_name);
            }
        }

        let naming = match request {
            NameRequest::Keep => None,
            NameRequest::Judge { opening, replaces } => {
                Some(self.name_log(key, flow_pid, app_path, opening, replaces, log))
            }
        };

        if log.country_code.is_empty() || log.isp.is_empty() {
            if let Some(geo) = &self.geo {
                if let Ok(result) = geo.load().lookup(key.remote_addr) {
                    if log.country_code.is_empty() {
                        log.country_code = result.country_code;
                    }
                    if log.isp.is_empty() {
                        log.isp = result.isp;
                    }
                }
            }
        }

        let engine = self.rule_engine.read();
        let eval_domain = strip_inferred_suffix(&log.dst_domain);
        let verdict = engine.evaluate_with_ip(app_path, key.remote_addr, eval_domain);
        if verdict == Some(Verdict::Block) {
            log.blocklist_names = antiwire_store::encode_blocklist_names(connection_block_labels(
                &engine,
                app_path,
                eval_domain,
            ));
        }

        // Policy evaluation alone is not an observed firewall enforcement result for
        // TCP/UDP flows. If bytes were transferred (bytes_sent > 0 || bytes_received > 0),
        // traffic physically traversed the network stack and cannot be marked BLOCKED.
        // Only mark BLOCKED when no bytes transferred (0 bytes) and policy verdict is Block.
        if log.bytes_sent > 0 || log.bytes_received > 0 {
            "ALLOWED".clone_into(&mut log.action_taken);
        } else {
            log.action_taken = verdict_to_action(verdict);
        }
        naming
    }

    pub(crate) fn record_byte_delta(&self, delta: &ByteDelta) {
        self.traffic_hub.record_bytes(delta.sent, delta.received);
    }

    pub(crate) fn wants_byte_updates(&self) -> bool {
        self.traffic_hub.has_subscribers()
    }

    pub(crate) fn byte_update_template(
        key: &FlowKey,
        app_name: &str,
        app_path: &str,
    ) -> Arc<TrafficEvent> {
        Arc::new(TrafficEvent {
            app_name: app_name.to_owned(),
            app_path: app_path.to_owned(),
            protocol: protocol_label(key.protocol).to_owned(),
            src_ip: key.local_addr.to_string(),
            src_port: u32::from(key.local_port),
            dst_ip: key.remote_addr.to_string(),
            dst_port: u32::from(key.remote_port),
            action: "UPDATE".to_owned(),
            is_active: true,
            ..TrafficEvent::default()
        })
    }

    pub(crate) fn publish_byte_update_shared(
        &self,
        delta: &ByteDelta,
        template: Arc<TrafficEvent>,
        now: OffsetDateTime,
    ) {
        if delta.is_zero() {
            return;
        }
        self.record_byte_delta(delta);
        self.traffic_hub
            .publish_byte_delta(template, delta.sent, delta.received, unix_secs(now));
    }

    #[cfg(test)]
    pub(crate) fn publish_byte_update(
        &self,
        key: &FlowKey,
        delta: &ByteDelta,
        app_name: &str,
        app_path: &str,
        now: OffsetDateTime,
    ) {
        if self.wants_byte_updates() {
            self.publish_byte_update_shared(
                delta,
                Self::byte_update_template(key, app_name, app_path),
                now,
            );
        } else {
            self.record_byte_delta(delta);
        }
    }

    pub(crate) fn publish_closed_flow(
        &self,
        app_path: &str,
        app_name: &str,
        log: &NewConnectionLog,
    ) {
        self.traffic_hub
            .publish(traffic_event_from_log(app_name, app_path, log));
        self.maybe_notify_blocked_traffic(app_name, log);
        self.siem.queue_connection_event(log, app_name, app_path);
        self.maybe_queue_new_domain(log, app_name, app_path);
    }

    fn maybe_notify_blocked_traffic(&self, app_name: &str, log: &NewConnectionLog) {
        if !log.action_taken.eq_ignore_ascii_case("BLOCKED") {
            return;
        }
        let app_name = sanitize::trimmed(app_name, sanitize::MAX_NAME_CHARS);
        let domain = sanitize::text(log.dst_domain.trim(), sanitize::MAX_NAME_CHARS);
        let message = if domain.is_empty() {
            format!(
                "Blocked connection to {ip}:{port} from {app_name}.",
                ip = log.dst_ip,
                port = log.dst_port,
            )
        } else {
            format!(
                "Blocked connection to {domain} ({ip}:{port}) from {app_name}.",
                ip = log.dst_ip,
                port = log.dst_port,
            )
        };
        self.alerts.publish(
            Alert::new(
                AlertKind::MaliciousFlow,
                Severity::High,
                "Blocked Connection",
                message,
            )
            .at(unix_secs(log.last_seen)),
        );
    }
}

fn protocol_label(protocol: Protocol) -> &'static str {
    match protocol {
        Protocol::Tcp => "TCP",
        Protocol::Udp => "UDP",
    }
}

/// An LRU holding at most `capacity` entries, and at least one.
fn bounded<K: std::hash::Hash + Eq, V>(capacity: usize) -> LruCache<K, V> {
    LruCache::new(NonZeroUsize::new(capacity).unwrap_or(NonZeroUsize::MIN))
}

fn connection_block_labels(engine: &RuleEngine, app_path: &str, dest_domain: &str) -> Vec<String> {
    if engine.evaluate(app_path, "", "") == Some(Verdict::Block) {
        return vec![FIREWALL_RULE_LABEL.to_owned()];
    }

    let Some(decision) = engine.evaluate_domain_with_source(dest_domain) else {
        return vec![FIREWALL_RULE_LABEL.to_owned()];
    };
    let matching_lists = if decision.source == Some(DomainBlockSource::Blocklist) {
        engine.matching_blocklists(dest_domain)
    } else {
        Vec::new()
    };
    decision.source.map_or_else(
        || vec![FIREWALL_RULE_LABEL.to_owned()],
        |source| source.reported_blocklist_names(matching_lists),
    )
}

fn verdict_to_action(verdict: Option<Verdict>) -> String {
    match verdict {
        Some(Verdict::Block) => "BLOCKED".to_owned(),
        Some(Verdict::Allow) | None => "ALLOWED".to_owned(),
    }
}

fn traffic_event_from_log(app_name: &str, app_path: &str, log: &NewConnectionLog) -> TrafficEvent {
    TrafficEvent {
        kind: TrafficEventKind::FlowRecord,
        timestamp: unix_secs(log.timestamp),
        app_name: app_name.to_owned(),
        app_path: app_path.to_owned(),
        protocol: log.protocol.clone(),
        src_ip: log.src_ip.clone(),
        src_port: i32_to_u32(log.src_port),
        dst_ip: log.dst_ip.clone(),
        dst_port: i32_to_u32(log.dst_port),
        dst_domain: log.dst_domain.clone(),
        bytes_sent: i64_to_u64(log.bytes_sent),
        bytes_received: i64_to_u64(log.bytes_received),
        action: log.action_taken.clone(),
        last_seen: unix_secs(log.last_seen),
        country_code: log.country_code.clone(),
        isp: log.isp.clone(),
        blocklist_names: antiwire_store::decode_blocklist_names(&log.blocklist_names),
        // Realtime-only event: no database row exists for it yet.
        id: 0,
        closed_at: if log.is_close {
            unix_secs(log.last_seen)
        } else {
            0
        },
        // Close evidence wins: a closing realtime event is never active.
        is_active: !log.is_close,
    }
}

fn i32_to_u32(value: i32) -> u32 {
    u32::try_from(value.max(0)).unwrap_or(0)
}

fn i64_to_u64(value: i64) -> u64 {
    u64::try_from(value.max(0)).unwrap_or(0)
}

#[cfg(test)]
mod tests;
