//! Firewall facade, lifecycle, and native reconciliation.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

use firew_core::{BulkExecution, BulkRequest, Error, ErrorKind, Rule, RuleKey, RuleRegistry};
use firew_sys::{Backend, BackendConfig, NativeRuleRef, RuleFilter};
use parking_lot::{Mutex, MutexGuard};

use crate::backend_factory::open_backend;
use crate::builder::FirewallBuilder;
use crate::bulk_executor::BulkExecutor;
use crate::domain_manager::{CustomDnsResolver, DomainSetManager};
use crate::engine::{Engine, PrepContext, PreparedRule};
use crate::health::{HealthMonitor, HealthMonitorConfig, HealthMonitorHandle, MonitorRegistration};
use crate::rule_id::RuleId;

pub(crate) struct FirewallState {
    pub(crate) backend: Box<dyn Backend>,
    pub(crate) config: BackendConfig,
    pub(crate) registry: RuleRegistry,
    pub(crate) native_rules: HashMap<RuleKey, NativeRuleRef>,
    /// True once the caller has declared the complete desired set, through
    /// `reconcile` or `remove_all_rules`. Until then the registry holds only the
    /// rules this owner touched, not the whole namespace, so health monitoring
    /// repairs registered rules but must never delete the other owned rules as
    /// extras (#8). Single-rule calls and bulk requests are incremental and do
    /// not set it.
    pub(crate) desired_initialized: bool,
    pub(crate) desired_generation: u64,
    pub(crate) closed: bool,
    pub(crate) monitors: Vec<Arc<MonitorRegistration>>,
    pub(crate) dns_resolver: Option<CustomDnsResolver>,
}

/// The error every operation on a closed owner returns.
pub(crate) fn closed_error() -> Error {
    Error::new(ErrorKind::InvalidConfiguration, "firewall owner is closed")
}

impl FirewallState {
    pub(crate) fn ensure_open(&self) -> Result<(), Error> {
        if self.closed {
            Err(closed_error())
        } else {
            Ok(())
        }
    }

    /// Marks desired state as changed, so work prepared outside the lock
    /// against the previous state can tell it is stale.
    pub(crate) fn bump_generation(&mut self) {
        self.desired_generation = self.desired_generation.wrapping_add(1);
    }
}

/// Per-rule reconciliation status.
#[derive(Debug)]
pub enum ReconcileStatus {
    /// The native representation already matches the desired rule.
    Unchanged,
    /// A missing native rule was created.
    Created,
    /// A changed native rule was replaced.
    Updated,
    /// An owned native rule absent from desired state was removed.
    Removed,
    /// The requested change failed without stopping independent changes.
    Error(Error),
}

/// Result for one logical rule considered during reconciliation.
#[derive(Debug)]
pub struct ReconcileItem {
    /// Stable logical identity.
    pub key: RuleKey,
    /// Action taken or error encountered.
    pub status: ReconcileStatus,
}

/// Complete deterministic reconciliation report.
///
/// `reconcile` returns `Ok` once it has tried every change, even when some of
/// them failed. Check [`ReconcileReport::has_errors`] or call
/// [`ReconcileReport::into_result`]: an `Ok` alone does not mean the native
/// state now matches the desired set.
#[derive(Debug, Default)]
#[must_use = "a reconcile report can carry per-rule failures; check `has_errors` or `into_result`"]
pub struct ReconcileReport {
    /// Results ordered by logical rule key.
    pub items: Vec<ReconcileItem>,
}

impl ReconcileReport {
    /// Whether any rule failed to reach its desired state.
    #[must_use]
    pub fn has_errors(&self) -> bool {
        self.items
            .iter()
            .any(|item| matches!(item.status, ReconcileStatus::Error(_)))
    }

    /// The failed rules and their errors, in key order.
    pub fn errors(&self) -> impl Iterator<Item = (&RuleKey, &Error)> {
        self.items.iter().filter_map(|item| match &item.status {
            ReconcileStatus::Error(error) => Some((&item.key, error)),
            _ => None,
        })
    }

    /// Returns the report when every rule reached its desired state.
    ///
    /// # Errors
    ///
    /// Returns [`ErrorKind::PartialMutation`] when any item failed, with the
    /// first failure attached as the source.
    pub fn into_result(mut self) -> Result<Self, Error> {
        let total = self.items.len();
        let failed = self
            .items
            .iter()
            .filter(|item| matches!(item.status, ReconcileStatus::Error(_)))
            .count();
        let Some(index) = self
            .items
            .iter()
            .position(|item| matches!(item.status, ReconcileStatus::Error(_)))
        else {
            return Ok(self);
        };
        let item = self.items.swap_remove(index);
        let ReconcileStatus::Error(first) = item.status else {
            unreachable!("position matched an error item");
        };
        Err(Error::new(
            ErrorKind::PartialMutation,
            format!("reconcile left {failed} of {total} rules out of their desired state"),
        )
        .with_logical_key(&item.key)
        .with_source(first))
    }
}

/// Cross-platform native firewall manager.
pub struct Firewall {
    state: Arc<Mutex<FirewallState>>,
    domain_manager: DomainSetManager,
    dns_timeout: Duration,
    closed: bool,
}

impl Firewall {
    /// Creates a builder for configuring a firewall instance.
    #[must_use]
    pub fn builder() -> FirewallBuilder {
        FirewallBuilder::new("firew")
    }

    pub(crate) fn open(
        config: BackendConfig,
        dns_timeout: Duration,
        refresh_interval: Duration,
    ) -> Result<Self, Error> {
        config.validate()?;
        let backend = open_backend(&config)?;
        let mut state = FirewallState {
            backend,
            config,
            registry: RuleRegistry::new(),
            native_rules: HashMap::new(),
            desired_initialized: false,
            desired_generation: 0,
            closed: false,
            monitors: Vec::new(),
            dns_resolver: None,
        };
        for (native, _) in state.backend.list_rules(&RuleFilter::new())? {
            state
                .native_rules
                .insert(native.logical_key().clone(), native);
        }
        let state = Arc::new(Mutex::new(state));
        Ok(Self {
            domain_manager: DomainSetManager::new(refresh_interval, Arc::downgrade(&state))?,
            state,
            dns_timeout,
            closed: false,
        })
    }

    /// Name of the active native backend, for diagnostics and capability checks.
    #[must_use]
    pub fn backend_name(&self) -> &'static str {
        self.state.lock().backend.name()
    }

    /// Maximum remote addresses the active backend holds in ONE native object.
    ///
    /// `None` means the backend emits one native row per address, so callers
    /// with large address lists must split them across several rules. See
    /// [`firew_core::AddressSetMode`].
    #[must_use]
    pub fn max_address_set_entries(&self) -> Option<usize> {
        self.state.lock().backend.max_address_set_entries()
    }

    /// Whether the active backend can install a rule with an IPv6 address or `ICMPv6`.
    ///
    /// One that cannot, as iptables without `ip6tables`, refuses such a rule with
    /// [`firew_core::ErrorKind::UnsupportedMatcher`], so a caller with addresses of both
    /// families can leave the IPv6 ones out instead of losing the whole rule.
    #[must_use]
    pub fn supports_ipv6(&self) -> bool {
        self.state.lock().backend.supports_ipv6()
    }

    /// Drains managed rules that drifted out of recognition.
    ///
    /// Returns the native names of rules that carry our ownership grouping but
    /// whose marker no longer parses — normally because they were renamed or
    /// edited outside the manager. They are skipped rather than treated as
    /// corruption, so the caller can report the drift without losing service.
    ///
    /// # Errors
    ///
    /// Returns an error when the backend cannot be queried.
    pub fn take_drift(&mut self) -> Result<Vec<String>, Error> {
        self.ensure_open()?;
        self.state.lock().backend.take_drift()
    }

    /// Adds a rule to the native firewall.
    ///
    /// # Errors
    ///
    /// Returns an error when validation, DNS resolution, capability preflight, or
    /// native insertion fails.
    #[allow(clippy::needless_pass_by_value)]
    pub fn add_rule(&mut self, rule: Rule) -> Result<RuleId, Error> {
        self.ensure_open()?;
        let prepared = self.prepare(&rule)?;
        let mut state = self.lock_open()?;
        let result = Engine::add_prepared_rule(&mut state, &self.domain_manager, prepared);
        state.bump_generation();
        result
    }

    /// Fetches a rule by logical identifier from authoritative native state.
    ///
    /// # Errors
    ///
    /// Returns an error when the rule does not exist or native state cannot be read.
    pub fn get_rule(&self, id: &RuleId) -> Result<Rule, Error> {
        self.ensure_open()?;
        Engine::get_rule(&mut self.state.lock(), &self.domain_manager, id)
    }

    /// Updates an existing rule.
    ///
    /// # Errors
    ///
    /// Returns an error when validation, preflight, lookup, or native replacement
    /// fails.
    #[allow(clippy::needless_pass_by_value)]
    pub fn update_rule(&mut self, id: &RuleId, rule: Rule) -> Result<(), Error> {
        self.ensure_open()?;
        if id.key() != rule.logical_key() {
            return Err(firew_sys::key_mismatch(&rule));
        }
        let prepared = self.prepare(&rule)?;
        let mut state = self.lock_open()?;
        let result = Engine::update_prepared_rule(&mut state, &self.domain_manager, id, prepared);
        state.bump_generation();
        result
    }

    /// Removes a rule by identifier.
    ///
    /// # Errors
    ///
    /// Returns an error when the rule does not exist or native removal fails.
    pub fn remove_rule(&mut self, id: &RuleId) -> Result<(), Error> {
        self.ensure_open()?;
        let mut state = self.state.lock();
        // A failed removal can still change the registry (a rule already gone
        // is dropped from desired state), so the generation moves either way.
        let result = Engine::remove_rule(&mut state, &self.domain_manager, id);
        state.bump_generation();
        result
    }

    /// Lists rules reconstructed from authoritative native state.
    ///
    /// # Errors
    ///
    /// Returns an error when native enumeration or reconstruction fails.
    pub fn list_rules(&self, filter: &RuleFilter) -> Result<Vec<(RuleId, Rule)>, Error> {
        self.ensure_open()?;
        Engine::list_rules(&mut self.state.lock(), &self.domain_manager, filter)
    }

    /// Removes every rule owned by this manager namespace.
    ///
    /// # Errors
    ///
    /// Returns an error when native cleanup fails.
    pub fn remove_all_rules(&mut self) -> Result<(), Error> {
        self.ensure_open()?;
        let mut state = self.state.lock();
        Engine::remove_all_rules(&mut state, &self.domain_manager)?;
        state.desired_initialized = true;
        state.bump_generation();
        Ok(())
    }

    /// Reconciles caller-provided desired state against native enumeration.
    ///
    /// The entire desired set is validated, resolved once, and capability-checked
    /// before any native mutation. The enumeration and mutation phases run under a
    /// single lock acquisition so background health monitoring cannot interleave.
    ///
    /// # Errors
    ///
    /// Returns an error before mutation for duplicate keys, invalid desired rules,
    /// unsupported matchers, DNS failures, or native enumeration failures.
    pub fn reconcile(&mut self, desired: &[Rule]) -> Result<ReconcileReport, Error> {
        self.ensure_open()?;
        // Resolve and prepare every desired rule ONCE outside the lock (#17, #34).
        let prepared_by_key = self.prepare_desired(desired)?;

        // Acquire the lock once for capability validation, native enumeration, and apply (#8, #34).
        let mut state = self.lock_open()?;
        for prepared in prepared_by_key.values() {
            state.backend.validate_rule(&prepared.native)?;
        }
        let actual_by_key: BTreeMap<RuleKey, Rule> =
            Engine::list_native_rules(&mut state, &RuleFilter::new())?
                .into_iter()
                .map(|(native, rule)| (native.logical_key().clone(), rule))
                .collect();
        // Rows of damaged rules are not listed, yet can still match traffic.
        let incomplete_keys = state.backend.incomplete_keys()?;

        let items =
            self.apply_desired(&mut state, &prepared_by_key, actual_by_key, incomplete_keys);
        self.forget_undesired(&mut state, &prepared_by_key);
        state.desired_initialized = true;
        state.bump_generation();
        Ok(ReconcileReport { items })
    }

    /// Rejects duplicate keys, then validates and resolves every desired rule.
    fn prepare_desired(&self, desired: &[Rule]) -> Result<BTreeMap<RuleKey, PreparedRule>, Error> {
        let mut seen = HashSet::with_capacity(desired.len());
        for rule in desired {
            if !seen.insert(rule.logical_key().clone()) {
                return Err(
                    Error::new(ErrorKind::InvalidRule, "duplicate desired rule key")
                        .with_logical_key(rule.logical_key()),
                );
            }
        }
        let prep_ctx = self.prep_context()?;
        desired
            .iter()
            .map(|rule| {
                Engine::prepare_unlocked(&prep_ctx, &self.domain_manager, self.dns_timeout, rule)
                    .map(|prepared| (rule.logical_key().clone(), prepared))
            })
            .collect()
    }

    /// Creates, updates, or confirms each desired rule, then removes every
    /// listed rule, and every damaged rule's leftover rows, that is not
    /// desired. Items come back in key order.
    ///
    /// A desired key with leftover rows is not listed, so it is created, and
    /// the backend replaces the leftovers as it installs the rule.
    fn apply_desired(
        &self,
        state: &mut FirewallState,
        prepared_by_key: &BTreeMap<RuleKey, PreparedRule>,
        mut actual_by_key: BTreeMap<RuleKey, Rule>,
        incomplete_keys: Vec<RuleKey>,
    ) -> Vec<ReconcileItem> {
        let mut items = Vec::with_capacity(actual_by_key.len().max(prepared_by_key.len()));
        for (key, prepared) in prepared_by_key {
            let actual = actual_by_key.remove(key);
            items.push(ReconcileItem {
                key: key.clone(),
                status: self.reconcile_one(state, key, prepared, actual),
            });
        }
        let undesired_incomplete = incomplete_keys
            .into_iter()
            .filter(|key| !prepared_by_key.contains_key(key) && !actual_by_key.contains_key(key))
            .collect::<BTreeSet<_>>();
        for key in actual_by_key.into_keys().chain(undesired_incomplete) {
            let status =
                Engine::remove_rule(state, &self.domain_manager, &RuleId::new(key.clone()))
                    .map_or_else(ReconcileStatus::Error, |()| ReconcileStatus::Removed);
            items.push(ReconcileItem { key, status });
        }
        items.sort_by(|left, right| left.key.cmp(&right.key));
        items
    }

    fn reconcile_one(
        &self,
        state: &mut FirewallState,
        key: &RuleKey,
        prepared: &PreparedRule,
        actual: Option<Rule>,
    ) -> ReconcileStatus {
        let domains = &self.domain_manager;
        match actual {
            None => Engine::add_prepared_rule(state, domains, prepared.clone())
                .map_or_else(ReconcileStatus::Error, |_| ReconcileStatus::Created),
            Some(actual_rule) if actual_rule == prepared.native => {
                match Engine::sync_domain_registration(domains, &prepared.logical, prepared.clone())
                {
                    Ok(()) => {
                        state.registry.register(prepared.logical.clone());
                        ReconcileStatus::Unchanged
                    }
                    Err(err) => ReconcileStatus::Error(err),
                }
            }
            Some(_) => Engine::update_prepared_rule(
                state,
                domains,
                &RuleId::new(key.clone()),
                prepared.clone(),
            )
            .map_or_else(ReconcileStatus::Error, |()| ReconcileStatus::Updated),
        }
    }

    /// Drops desired-state entries outside the desired set, such as rules
    /// deleted externally and omitted from `desired` (#34).
    fn forget_undesired(
        &self,
        state: &mut FirewallState,
        prepared_by_key: &BTreeMap<RuleKey, PreparedRule>,
    ) {
        let stale_registry_keys: Vec<RuleKey> = state
            .registry
            .rules()
            .map(|r| r.logical_key().clone())
            .filter(|k| !prepared_by_key.contains_key(k))
            .collect();
        for key in stale_registry_keys {
            state.registry.unregister(&key);
            state.native_rules.remove(&key);
            self.domain_manager.unregister(&key);
        }
        let domain_keep: HashSet<RuleKey> = prepared_by_key
            .iter()
            .filter(|(_, p)| !p.logical.remote_domains().is_empty())
            .map(|(k, _)| k.clone())
            .collect();
        self.domain_manager.retain_only(&domain_keep);
    }

    /// Executes a bulk CRUD request.
    ///
    /// # Errors
    ///
    /// Returns an error when a required transaction is unavailable or transaction
    /// setup, commit, or rollback itself fails. Per-item errors are reported in the
    /// returned execution.
    pub fn execute_bulk(&mut self, request: &BulkRequest) -> Result<BulkExecution, Error> {
        self.ensure_open()?;
        BulkExecutor::execute_unlocked(&self.state, &self.domain_manager, self.dns_timeout, request)
    }

    /// Spawns a periodic native-state health monitor.
    ///
    /// # Errors
    ///
    /// Returns an error when the monitor thread cannot be spawned.
    pub fn spawn_health_monitor(
        &self,
        config: &HealthMonitorConfig,
    ) -> Result<HealthMonitorHandle, Error> {
        self.ensure_open()?;
        HealthMonitor::spawn(
            self.state.clone(),
            self.domain_manager.clone(),
            self.dns_timeout,
            config,
        )
    }

    /// Closes this owner, stopping background health monitors and DNS refresh workers
    /// before performing final memory-mode cleanup (#20).
    ///
    /// Persistent rules remain installed. Memory-mode rules are removed before the
    /// method returns.
    ///
    /// # Errors
    ///
    /// Returns an error when memory-mode native cleanup fails.
    pub fn close(&mut self) -> Result<(), Error> {
        if self.closed {
            return Ok(());
        }
        self.stop_monitors();
        if self.state.lock().config.memory_mode {
            Engine::remove_all_rules(&mut self.state.lock(), &self.domain_manager)?;
        }
        self.finish_close();
        Ok(())
    }

    /// Returns whether this owner has been closed.
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.closed || self.state.lock().closed
    }

    fn ensure_open(&self) -> Result<(), Error> {
        if self.is_closed() {
            Err(closed_error())
        } else {
            Ok(())
        }
    }

    /// Locks the shared state, failing when the owner was closed meanwhile.
    fn lock_open(&self) -> Result<MutexGuard<'_, FirewallState>, Error> {
        let state = self.state.lock();
        state.ensure_open()?;
        Ok(state)
    }

    fn prep_context(&self) -> Result<PrepContext, Error> {
        Ok(PrepContext::from_state(&*self.lock_open()?))
    }

    /// Validates `rule` and resolves its domains outside the native mutation
    /// lock, so background refresh never deadlocks with initial resolution (#17).
    fn prepare(&self, rule: &Rule) -> Result<PreparedRule, Error> {
        let prep_ctx = self.prep_context()?;
        Engine::prepare_unlocked(&prep_ctx, &self.domain_manager, self.dns_timeout, rule)
    }

    /// Stops and joins every health monitor, so none writes during cleanup.
    fn stop_monitors(&self) {
        let monitors = std::mem::take(&mut self.state.lock().monitors);
        for monitor in &monitors {
            monitor.stop_and_join();
        }
    }

    fn finish_close(&mut self) {
        self.domain_manager.shutdown();
        self.state.lock().closed = true;
        self.closed = true;
    }
}

impl Drop for Firewall {
    fn drop(&mut self) {
        if self.closed {
            return;
        }
        self.stop_monitors();
        if self.state.lock().config.memory_mode {
            let mut state = self.state.lock();
            if Engine::remove_all_rules(&mut state, &self.domain_manager).is_err() {
                // Drop cannot report the failure or be retried, so fall back to
                // removing each rule this owner knows about one at a time: a
                // single stuck rule must not leave every other one installed.
                Engine::remove_known_rules_best_effort(&mut state, &self.domain_manager);
            }
        }
        self.finish_close();
    }
}

#[cfg(test)]
mod tests;
