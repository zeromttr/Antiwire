//! Periodic native-state health monitoring and repair.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, SystemTime};

use firew_core::{Error, ErrorKind, Rule, RuleKey};
use firew_sys::{NativeRuleRef, RuleFilter};
use parking_lot::{Condvar, Mutex};

use crate::domain_manager::DomainSetManager;
use crate::engine::{Engine, PrepContext, PreparedRule};
use crate::firewall::FirewallState;

/// Health monitor configuration.
#[derive(Clone, Debug)]
pub struct HealthMonitorConfig {
    /// Interval between health checks.
    pub interval: Duration,
    /// Re-apply missing or modified rules and remove exact owned extras.
    pub auto_repair: bool,
}

impl Default for HealthMonitorConfig {
    fn default() -> Self {
        Self {
            interval: Duration::from_secs(30),
            auto_repair: true,
        }
    }
}

/// Result of one native-state health check.
#[derive(Debug)]
pub struct HealthReport {
    /// When the check ran.
    pub checked_at: SystemTime,
    /// Desired keys missing from native state or modified out of spec.
    pub missing_keys: Vec<RuleKey>,
    /// Owned native keys absent from current-session desired state.
    pub extra_keys: Vec<RuleKey>,
    /// Keys repaired during this check.
    pub repaired_keys: Vec<RuleKey>,
    /// Typed probe or repair failures.
    pub errors: Vec<Error>,
}

struct ReportSlotState {
    latest: Option<HealthReport>,
    closed: bool,
}

/// Retains the latest [`HealthReport`] while merging unread `errors` and
/// `repaired_keys` from superseded reports so drained DNS errors and repair
/// events are never silently dropped when the caller polls slower than `interval`.
struct LatestReportChannel {
    state: Mutex<ReportSlotState>,
    ready: Condvar,
}

impl LatestReportChannel {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(ReportSlotState {
                latest: None,
                closed: false,
            }),
            ready: Condvar::new(),
        })
    }

    fn publish(&self, mut next: HealthReport) {
        let mut guard = self.state.lock();
        if let Some(previous) = guard.latest.take() {
            if !previous.errors.is_empty() {
                let mut combined_errors = previous.errors;
                combined_errors.extend(next.errors);
                next.errors = combined_errors;
            }
            if !previous.repaired_keys.is_empty() {
                let mut combined_repaired: BTreeSet<RuleKey> =
                    previous.repaired_keys.into_iter().collect();
                combined_repaired.extend(next.repaired_keys);
                next.repaired_keys = combined_repaired.into_iter().collect();
            }
        }
        guard.latest = Some(next);
        self.ready.notify_all();
    }

    fn mark_closed(&self) {
        let mut guard = self.state.lock();
        guard.closed = true;
        self.ready.notify_all();
    }

    fn recv_timeout(&self, timeout: Duration) -> Result<Option<HealthReport>, Error> {
        let mut guard = self.state.lock();
        if let Some(report) = guard.latest.take() {
            return Ok(Some(report));
        }
        if guard.closed {
            return Err(Error::new(
                ErrorKind::Internal,
                "health monitor report channel disconnected",
            ));
        }
        let _ = self.ready.wait_for(&mut guard, timeout);
        if let Some(report) = guard.latest.take() {
            return Ok(Some(report));
        }
        if guard.closed {
            return Err(Error::new(
                ErrorKind::Internal,
                "health monitor report channel disconnected",
            ));
        }
        Ok(None)
    }
}

pub(crate) struct MonitorRegistration {
    stop_tx: Sender<()>,
    stopped: Arc<AtomicBool>,
    worker: Mutex<Option<JoinHandle<()>>>,
}

impl MonitorRegistration {
    pub(crate) fn stop_and_join(&self) {
        self.stopped.store(true, Ordering::Release);
        let _ = self.stop_tx.send(());
        if let Some(worker) = self.worker.lock().take() {
            if worker.thread().id() != thread::current().id() {
                let _ = worker.join();
            }
        }
    }
}

/// Handle for receiving reports and stopping a running health monitor.
pub struct HealthMonitorHandle {
    registration: Arc<MonitorRegistration>,
    reports: Arc<LatestReportChannel>,
}

impl HealthMonitorHandle {
    /// Waits up to `timeout` for the next report.
    ///
    /// # Errors
    ///
    /// Returns an error if the monitor worker stops before producing a report.
    pub fn recv_report_timeout(&self, timeout: Duration) -> Result<Option<HealthReport>, Error> {
        self.reports.recv_timeout(timeout)
    }

    /// Stops the health monitor thread and waits for it to exit.
    pub fn stop(&mut self) {
        self.registration.stop_and_join();
    }
}

impl Drop for HealthMonitorHandle {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Periodic health monitor.
pub struct HealthMonitor;

impl HealthMonitor {
    pub(crate) fn spawn(
        state: Arc<Mutex<FirewallState>>,
        domains: DomainSetManager,
        dns_timeout: Duration,
        config: &HealthMonitorConfig,
    ) -> Result<HealthMonitorHandle, Error> {
        let auto_repair = config.auto_repair;
        let interval = config.interval;
        let (stop_tx, stop_rx): (Sender<()>, Receiver<()>) = mpsc::channel();
        let stopped = Arc::new(AtomicBool::new(false));
        let stopped_worker = stopped.clone();
        let reports = LatestReportChannel::new();
        let reports_worker = reports.clone();
        let state_for_reg = state.clone();

        let worker = thread::Builder::new()
            .name("firew-rs-health".to_owned())
            .spawn(move || {
                loop {
                    if stopped_worker.load(Ordering::Acquire) {
                        break;
                    }
                    let Some(report) = run_check(&state, &domains, dns_timeout, auto_repair) else {
                        break;
                    };
                    reports_worker.publish(report);
                    if stopped_worker.load(Ordering::Acquire) {
                        break;
                    }
                    match stop_rx.recv_timeout(interval) {
                        Ok(()) | Err(mpsc::RecvTimeoutError::Disconnected) => break,
                        Err(mpsc::RecvTimeoutError::Timeout) => {}
                    }
                }
                reports_worker.mark_closed();
            })
            .map_err(|source| {
                Error::new(ErrorKind::Internal, "failed to spawn health monitor")
                    .with_source(source)
            })?;

        let registration = Arc::new(MonitorRegistration {
            stop_tx,
            stopped,
            worker: Mutex::new(Some(worker)),
        });
        state_for_reg.lock().monitors.push(registration.clone());

        Ok(HealthMonitorHandle {
            registration,
            reports,
        })
    }
}

/// Owned rules listed natively, by logical key.
type ActualRules = BTreeMap<RuleKey, (NativeRuleRef, Rule)>;

/// A registered rule to reinstall, captured under the lock before its DNS is
/// resolved outside it.
struct RepairPlan {
    key: RuleKey,
    rule: Rule,
    existing: Option<NativeRuleRef>,
    generation: u64,
}

impl RepairPlan {
    /// Whether desired state moved while DNS was resolved outside the lock. A
    /// changed rule makes this repair stale. So does any change to a domain
    /// rule: the logical rule can compare equal while a newer resolution was
    /// installed, and this repair would write its own, older expansion over it.
    /// The next pass repairs whatever is still wrong.
    fn is_stale(&self, state: &FirewallState) -> bool {
        state.desired_generation != self.generation
            && (state.registry.get(&self.key) != Some(&self.rule)
                || !self.rule.remote_domains().is_empty())
    }
}

fn run_check(
    state: &Arc<Mutex<FirewallState>>,
    domains: &DomainSetManager,
    dns_timeout: Duration,
    auto_repair: bool,
) -> Option<HealthReport> {
    let mut report = HealthReport {
        checked_at: SystemTime::now(),
        missing_keys: Vec::new(),
        extra_keys: Vec::new(),
        repaired_keys: Vec::new(),
        errors: Vec::new(),
    };
    report.errors.extend(domains.take_refresh_errors());

    // Phase 1: Inspect native state and desired state under the lock.
    let (plans, prep_ctx) = {
        let mut guard = state.lock();
        if guard.closed {
            return None;
        }
        let Some(actual_by_key) = inspect(&mut guard, domains, &mut report) else {
            return Some(report);
        };
        if !auto_repair {
            return Some(report);
        }
        remove_extras(&mut guard, &actual_by_key, &mut report);
        let plans = plan_repairs(&guard, &actual_by_key, &mut report);
        (plans, PrepContext::from_state(&guard))
    };

    if !plans.is_empty() {
        // Phase 2: Resolve DNS outside the lock so we never deadlock with background refresh (#17).
        let mut prepared_repairs = Vec::with_capacity(plans.len());
        for plan in plans {
            match Engine::prepare_unlocked(&prep_ctx, domains, dns_timeout, &plan.rule) {
                Ok(prepared) => prepared_repairs.push((plan, prepared)),
                Err(error) => report.errors.push(error),
            }
        }

        // Phase 3: Re-acquire the lock and apply each repair still current.
        let mut guard = state.lock();
        if guard.closed {
            return None;
        }
        for (plan, prepared) in prepared_repairs {
            if plan.is_stale(&guard) {
                continue;
            }
            match apply_repair(&mut guard, domains, &plan, prepared) {
                Ok(native) => {
                    guard.native_rules.insert(plan.key.clone(), native);
                    report.repaired_keys.push(plan.key);
                }
                Err(error) => report.errors.push(error),
            }
        }
    }

    report.repaired_keys.sort();
    report.repaired_keys.dedup();
    Some(report)
}

/// Fills the report's missing and extra keys. Returns the native listing, or
/// `None` after recording the error when native state could not be read.
fn inspect(
    guard: &mut FirewallState,
    domains: &DomainSetManager,
    report: &mut HealthReport,
) -> Option<ActualRules> {
    let expected: Vec<RuleKey> = guard
        .registry
        .rules()
        .map(|rule| rule.logical_key().clone())
        .collect();
    let probed = guard.backend.health_probe(&expected);
    let listed = probed.and_then(|snapshot| {
        Engine::list_native_rules(guard, &RuleFilter::new()).map(|listed| (snapshot, listed))
    });
    let (snapshot, listed) = match listed {
        Ok(found) => found,
        Err(error) => {
            report.errors.push(error);
            return None;
        }
    };
    let actual_by_key: ActualRules = listed
        .into_iter()
        .map(|(native, rule)| (native.logical_key().clone(), (native, rule)))
        .collect();

    let mut missing_or_modified: BTreeSet<RuleKey> = snapshot.missing_keys.into_iter().collect();
    // Check content drift: compare each present rule's decoded matchers/action
    // against the desired rule in `guard.registry` (#36).
    let max_set = guard.backend.max_address_set_entries();
    for desired_rule in guard.registry.rules() {
        let key = desired_rule.logical_key();
        if missing_or_modified.contains(key) {
            continue;
        }
        let expected_native = domains.expected_native(desired_rule, max_set);
        let actual = actual_by_key.get(key).map(|(_, rule)| rule);
        if actual.is_none() || expected_native.as_ref() != actual {
            missing_or_modified.insert(key.clone());
        }
    }
    report.missing_keys = missing_or_modified.into_iter().collect();

    // Until the caller declares the complete desired set (reconcile or
    // remove_all_rules), the registry holds only the rules this owner touched.
    // Every other owned rule, such as one recovered from a persistent
    // namespace, is unknown rather than extra, and must never be deleted (#8).
    // Registered rules are still checked and repaired.
    if guard.desired_initialized {
        let extra_keys: BTreeSet<RuleKey> = snapshot.extra_keys.into_iter().collect();
        report.extra_keys = extra_keys.into_iter().collect();
    }
    Some(actual_by_key)
}

fn remove_extras(
    guard: &mut FirewallState,
    actual_by_key: &ActualRules,
    report: &mut HealthReport,
) {
    for key in &report.extra_keys {
        let Some((native, _)) = actual_by_key.get(key) else {
            continue;
        };
        match guard.backend.remove_rule(native) {
            Ok(()) => {
                guard.native_rules.remove(key);
                report.repaired_keys.push(key.clone());
            }
            Err(error) => report.errors.push(error),
        }
    }
}

fn plan_repairs(
    guard: &FirewallState,
    actual_by_key: &ActualRules,
    report: &mut HealthReport,
) -> Vec<RepairPlan> {
    let mut plans = Vec::new();
    for key in &report.missing_keys {
        if let Some(rule) = guard.registry.get(key).cloned() {
            plans.push(RepairPlan {
                key: key.clone(),
                rule,
                existing: actual_by_key.get(key).map(|(native, _)| native.clone()),
                generation: guard.desired_generation,
            });
        } else {
            report.errors.push(
                Error::new(
                    ErrorKind::CorruptNativeState,
                    "health snapshot referenced unknown desired rule",
                )
                .with_logical_key(key),
            );
        }
    }
    plans
}

/// Installs one repair and re-registers its domains, rolling the native rule
/// back when registration fails.
fn apply_repair(
    guard: &mut FirewallState,
    domains: &DomainSetManager,
    plan: &RepairPlan,
    prepared: PreparedRule,
) -> Result<NativeRuleRef, Error> {
    guard.backend.validate_rule(&prepared.native)?;
    let native = install_repair(guard, plan, &prepared.native)?;
    if let Err(error) = Engine::sync_domain_registration(domains, &plan.rule, prepared) {
        if let Err(rollback) = guard.backend.remove_rule(&native) {
            return Err(Error::new(
                ErrorKind::RollbackFailed,
                format!("health repair registration failed ({error}); rollback failed"),
            )
            .with_logical_key(&plan.key)
            .with_source(rollback));
        }
        return Err(error);
    }
    Ok(native)
}

fn install_repair(
    guard: &mut FirewallState,
    plan: &RepairPlan,
    native_rule: &Rule,
) -> Result<NativeRuleRef, Error> {
    let Some(existing) = &plan.existing else {
        return guard.backend.add_rule(native_rule);
    };
    match guard.backend.update_rule(existing, native_rule) {
        Ok(native) => Ok(native),
        // Install the replacement only when the old rule is really gone, either
        // before the update or because the failed update removed it. A rule
        // that is still there keeps enforcing; deleting it on a transient error
        // and then failing the add would leave nothing.
        Err(update_err) if guard.backend.get_rule(existing).is_err() => {
            guard.backend.add_rule(native_rule).map_err(|add_err| {
                Error::new(
                    ErrorKind::PartialMutation,
                    format!("health repair update failed ({update_err}); re-adding failed"),
                )
                .with_logical_key(&plan.key)
                .with_source(add_err)
            })
        }
        Err(update_err) => Err(update_err),
    }
}
