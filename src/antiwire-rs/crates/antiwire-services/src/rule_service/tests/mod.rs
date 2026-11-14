//! Rule service tests, by operation, over one scriptable fake firewall.

mod concurrency;
mod country;
mod drift;
mod load;
mod private_relay;
mod retarget;
mod rules;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use antiwire_enforce::{EnforceError, EnforcementClient, FirewallFilter};
use antiwire_events::{AlertPublisher, NotificationHub, NotificationSubscription};
use antiwire_policy::{EnforcementOp, RuleDirection, RuleEngine, TargetType, Verdict};
use antiwire_store::Store;
use parking_lot::{Mutex, RwLock};

use super::{NewCountryBlock, NewRule, RuleService};

/// What a test sees of the native firewall, and how it scripts failures.
#[derive(Clone, Default)]
struct FakeFirewall {
    state: Arc<Mutex<FirewallState>>,
}

#[derive(Default)]
struct FirewallState {
    started: bool,
    /// Ops the firewall accepted, in order. A failed op is not here.
    applied: Vec<EnforcementOp>,
    /// Lifecycle calls and applies, in order.
    events: Vec<&'static str>,
    failures: Vec<ScriptedFailure>,
    drift: Vec<String>,
}

struct ScriptedFailure {
    matches: Box<dyn Fn(&EnforcementOp) -> bool + Send>,
    remaining: usize,
}

impl FakeFirewall {
    /// Fails the next `count` ops that `matches`.
    fn fail(&self, count: usize, matches: impl Fn(&EnforcementOp) -> bool + Send + 'static) {
        self.state.lock().failures.push(ScriptedFailure {
            matches: Box::new(matches),
            remaining: count,
        });
    }

    /// Reports `names` as rules changed outside Antiwire at the next drain.
    fn drift(&self, names: &[&str]) {
        self.state
            .lock()
            .drift
            .extend(names.iter().map(|name| (*name).to_owned()));
    }

    fn applied(&self) -> Vec<EnforcementOp> {
        self.state.lock().applied.clone()
    }

    fn events(&self) -> Vec<&'static str> {
        self.state.lock().events.clone()
    }

    fn clear(&self) {
        let mut state = self.state.lock();
        state.applied.clear();
        state.events.clear();
    }
}

struct FakeFilter(FakeFirewall);

impl FirewallFilter for FakeFilter {
    fn start(&mut self) -> antiwire_enforce::Result<()> {
        let mut state = self.0.state.lock();
        state.started = true;
        state.events.push("start");
        Ok(())
    }

    fn stop(&mut self) -> antiwire_enforce::Result<()> {
        let mut state = self.0.state.lock();
        state.started = false;
        state.events.push("stop");
        Ok(())
    }

    fn is_enforcing(&self) -> bool {
        self.0.state.lock().started
    }

    fn apply(&mut self, op: EnforcementOp) -> antiwire_enforce::Result<()> {
        let mut state = self.0.state.lock();
        if !state.started && is_add(&op) {
            return Err(EnforceError::NotStarted);
        }
        state.events.push("apply");
        if let Some(failure) = state
            .failures
            .iter_mut()
            .find(|failure| failure.remaining > 0 && (failure.matches)(&op))
        {
            failure.remaining -= 1;
            return Err(EnforceError::InvalidOp("scripted failure".to_owned()));
        }
        state.applied.push(op);
        Ok(())
    }

    fn remove_all_managed(&mut self) -> antiwire_enforce::Result<()> {
        self.0.state.lock().events.push("remove_all_managed");
        Ok(())
    }

    fn take_drift(&mut self) -> antiwire_enforce::Result<Vec<String>> {
        Ok(std::mem::take(&mut self.0.state.lock().drift))
    }
}

/// A rule service over a temporary store and a started fake firewall.
struct Harness {
    _file: tempfile::NamedTempFile,
    store: Arc<Store>,
    engine: Arc<RwLock<RuleEngine>>,
    firewall: FakeFirewall,
    alerts: NotificationSubscription,
    /// How often the service ran its hook for a changed rule on a domain.
    domain_rule_changes: Arc<AtomicUsize>,
    service: RuleService,
}

fn harness() -> Harness {
    let file = tempfile::NamedTempFile::new().expect("temp");
    let store = Arc::new(Store::open(file.path()).expect("open"));
    let engine = Arc::new(RwLock::new(RuleEngine::new()));
    let firewall = FakeFirewall::default();
    let enforce =
        EnforcementClient::with_filter(FakeFilter(firewall.clone())).expect("enforcement worker");
    enforce.start().expect("start");
    let publisher = AlertPublisher::unsaved(NotificationHub::with_capacity(16), None);
    let alerts = publisher.subscribe();
    let domain_rule_changes = Arc::new(AtomicUsize::new(0));
    let counted = Arc::clone(&domain_rule_changes);
    let service = RuleService::new(Arc::clone(&store), Arc::clone(&engine), enforce, publisher)
        .on_domain_rule_change(move || {
            counted.fetch_add(1, Ordering::SeqCst);
        });
    firewall.clear();
    Harness {
        _file: file,
        store,
        engine,
        firewall,
        alerts,
        domain_rule_changes,
        service,
    }
}

impl Harness {
    /// Saves the Private Relay compatibility setting and applies it as a settings change
    /// does.
    fn set_private_relay_compatibility(&self, on: bool) {
        let mut settings = self.store.get_settings().expect("settings");
        settings.private_relay_compatibility = on;
        self.store.update_settings(&settings).expect("save");
        self.service.install_saved_rules().expect("install");
    }
}

fn rule(target_type: TargetType, target: &str, verdict: Verdict) -> NewRule {
    NewRule {
        target_type,
        target: target.to_owned(),
        verdict,
        direction: RuleDirection::Both,
    }
}

fn app(path: &str, verdict: Verdict) -> NewRule {
    rule(TargetType::App, path, verdict)
}

fn country(code: &str, networks: &[&str]) -> NewCountryBlock {
    NewCountryBlock {
        code: code.to_owned(),
        networks: networks
            .iter()
            .map(|network| (*network).to_owned())
            .collect(),
        verdict: Verdict::Block,
        direction: RuleDirection::Both,
    }
}

fn is_add(op: &EnforcementOp) -> bool {
    matches!(
        op,
        EnforcementOp::AddAppRule { .. }
            | EnforcementOp::AddIpRule { .. }
            | EnforcementOp::AddCountryBlock { .. }
    )
}

fn is_country(op: &EnforcementOp) -> bool {
    matches!(
        op,
        EnforcementOp::AddCountryBlock { .. } | EnforcementOp::RemoveCountryBlock { .. }
    )
}
