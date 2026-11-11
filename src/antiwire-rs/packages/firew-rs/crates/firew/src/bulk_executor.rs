//! Bulk operation executor.

use std::collections::{HashMap, HashSet};
use std::time::Duration;

use firew_core::{
    BulkExecution, BulkItemResult, BulkOperation, BulkOutcome, BulkRead, BulkRequest, Error,
    ErrorKind, ExecutionAtomicity, Rule, RuleKey, RuleRegistry, TransactionMode,
};
use firew_sys::{NativeRuleRef, RuleFilter};

use crate::domain_manager::{DomainCheckpoint, DomainSetManager};
use crate::engine::{Engine, PrepContext, PreparedRule};
use crate::firewall::FirewallState;
use crate::rule_id::RuleId;

/// Executes backend-agnostic bulk CRUD batches.
pub(crate) struct BulkExecutor;

enum PreparedItem {
    Delete(RuleKey),
    Update(RuleKey, Result<PreparedRule, Error>),
    Create(RuleKey, Result<PreparedRule, Error>),
    Read(BulkRead),
}

/// Prepared items in evaluation order, tagged with their caller indices.
type PreparedOps = Vec<(usize, usize, PreparedItem)>;

/// Facade state saved before a native transaction.
struct Checkpoint {
    registry: RuleRegistry,
    native_rules: HashMap<RuleKey, NativeRuleRef>,
    domains: DomainCheckpoint,
}

impl Checkpoint {
    fn take(state: &FirewallState, domains: &DomainSetManager) -> Self {
        Self {
            registry: state.registry.clone(),
            native_rules: state.native_rules.clone(),
            domains: domains.checkpoint(),
        }
    }

    /// The native rollback worked, so the facade rewinds with it.
    fn restore(self, state: &mut FirewallState, domains: &DomainSetManager) {
        state.registry = self.registry;
        state.native_rules = self.native_rules;
        domains.restore(&self.domains);
    }

    /// Recovers after a native rollback failed, leaving native state unknown.
    ///
    /// Desired state goes back to the checkpoint, since the caller is told the
    /// request failed. The native-reference cache is NOT rewound: it is rebuilt
    /// from a fresh listing, so a rule the failed rollback left installed stays
    /// known and a later add of the same key is refused as a duplicate instead
    /// of installing a second native object. When the listing itself fails, the
    /// cache keeps the post-transaction references, the closer guess.
    fn restore_after_failed_rollback(self, state: &mut FirewallState, domains: &DomainSetManager) {
        state.registry = self.registry;
        domains.restore(&self.domains);
        let _ = Engine::list_native_rules(state, &RuleFilter::new());
    }
}

/// Keys already seen per operation kind; a repeat within a request is refused.
#[derive(Default)]
struct SeenKeys {
    deletes: HashSet<RuleKey>,
    updates: HashSet<RuleKey>,
    creates: HashSet<RuleKey>,
}

fn first_use(seen: &mut HashSet<RuleKey>, key: &RuleKey, what: &str) -> Result<(), Error> {
    if seen.insert(key.clone()) {
        Ok(())
    } else {
        Err(Error::new(
            ErrorKind::InvalidRule,
            format!("duplicate {what} key in bulk request"),
        )
        .with_logical_key(key))
    }
}

/// Fails when the request requires native transactions the backend lacks.
fn ensure_transactions_available(
    state: &FirewallState,
    request: &BulkRequest,
) -> Result<(), Error> {
    if request.transaction_mode == TransactionMode::RequireNative
        && !state.backend.supports_transactions()
    {
        return Err(Error::new(
            ErrorKind::UnsupportedOperation,
            format!(
                "backend {} does not support native transactions",
                state.backend.name()
            ),
        )
        .with_platform_detail(state.backend.name()));
    }
    Ok(())
}

impl BulkExecutor {
    /// Resolves and prepares all `Create` and `Update` items outside the `FirewallState` mutex,
    /// then executes the batch under the lock.
    pub(crate) fn execute_unlocked(
        state_arc: &parking_lot::Mutex<FirewallState>,
        domains: &DomainSetManager,
        dns_timeout: Duration,
        request: &BulkRequest,
    ) -> Result<BulkExecution, Error> {
        let prep_ctx = {
            let state = state_arc.lock();
            state.ensure_open()?;
            ensure_transactions_available(&state, request)?;
            PrepContext::from_state(&state)
        };
        let prepared_ops = Self::prepare(&prep_ctx, domains, dns_timeout, request);
        let mut state = state_arc.lock();
        state.ensure_open()?;
        Self::execute_prepared(&mut state, domains, request, prepared_ops)
    }

    #[cfg(test)]
    pub(crate) fn execute(
        state: &mut FirewallState,
        domains: &DomainSetManager,
        dns_timeout: Duration,
        request: &BulkRequest,
    ) -> Result<BulkExecution, Error> {
        ensure_transactions_available(state, request)?;
        let prep_ctx = PrepContext::from_state(state);
        let prepared_ops = Self::prepare(&prep_ctx, domains, dns_timeout, request);
        Self::execute_prepared(state, domains, request, prepared_ops)
    }

    /// Prepares every item in delete, update, create, read order.
    fn prepare(
        prep_ctx: &PrepContext,
        domains: &DomainSetManager,
        dns_timeout: Duration,
        request: &BulkRequest,
    ) -> PreparedOps {
        let prepare = |rule: &Rule| Engine::prepare_unlocked(prep_ctx, domains, dns_timeout, rule);
        let mut ordered_ops: Vec<(usize, &BulkOperation)> =
            request.operations.iter().enumerate().collect();
        ordered_ops.sort_by_key(|(_, operation)| bulk_priority(operation));

        let mut prepared_ops = PreparedOps::new();
        for (operation_index, operation) in ordered_ops {
            match operation {
                BulkOperation::Delete(keys) => {
                    prepared_ops.extend(keys.iter().enumerate().map(|(item_index, key)| {
                        (
                            operation_index,
                            item_index,
                            PreparedItem::Delete(key.clone()),
                        )
                    }));
                }
                BulkOperation::Update(updates) => {
                    prepared_ops.extend(updates.iter().enumerate().map(|(item_index, update)| {
                        let prep = if update.logical_key == *update.rule.logical_key() {
                            prepare(&update.rule)
                        } else {
                            Err(firew_sys::key_mismatch(&update.rule))
                        };
                        let item = PreparedItem::Update(update.logical_key.clone(), prep);
                        (operation_index, item_index, item)
                    }));
                }
                BulkOperation::Create(rules) => {
                    prepared_ops.extend(rules.iter().enumerate().map(|(item_index, rule)| {
                        let item = PreparedItem::Create(rule.logical_key().clone(), prepare(rule));
                        (operation_index, item_index, item)
                    }));
                }
                BulkOperation::Read(filter) => {
                    prepared_ops.push((operation_index, 0, PreparedItem::Read(filter.clone())));
                }
            }
        }
        prepared_ops
    }

    fn execute_prepared(
        state: &mut FirewallState,
        domains: &DomainSetManager,
        request: &BulkRequest,
        prepared_ops: PreparedOps,
    ) -> Result<BulkExecution, Error> {
        let native_transaction = match request.transaction_mode {
            TransactionMode::Sequential => false,
            TransactionMode::PreferNative => state.backend.supports_transactions(),
            TransactionMode::RequireNative => {
                ensure_transactions_available(state, request)?;
                true
            }
        };
        let checkpoint = native_transaction.then(|| Checkpoint::take(state, domains));
        if native_transaction {
            state.backend.begin_transaction()?;
        }

        let mut seen = SeenKeys::default();
        let mut results = Vec::with_capacity(prepared_ops.len());
        let mut any_failure = false;
        for (operation_index, item_index, item) in prepared_ops {
            let outcome = if native_transaction && any_failure {
                // Short-circuit remaining items in a native transaction once any item fails (#39).
                Ok(BulkOutcome::RolledBack)
            } else {
                let outcome = Self::run_item(state, domains, &mut seen, item);
                any_failure |= outcome.is_err();
                outcome
            };
            results.push(BulkItemResult {
                operation_index,
                item_index,
                outcome,
            });
        }

        if let Some(checkpoint) = checkpoint {
            Self::finish_transaction(state, domains, checkpoint, any_failure, &mut results)?;
        }

        results.sort_by_key(|result| (result.operation_index, result.item_index));
        Ok(BulkExecution {
            atomicity: if native_transaction {
                ExecutionAtomicity::NativeAtomic
            } else {
                ExecutionAtomicity::SequentialBestEffort
            },
            results,
        })
    }

    fn run_item(
        state: &mut FirewallState,
        domains: &DomainSetManager,
        seen: &mut SeenKeys,
        item: PreparedItem,
    ) -> Result<BulkOutcome, Error> {
        // Reads leave desired state alone; every other item may move it, even
        // on failure. Bulk requests are incremental, so none of them declares
        // the complete desired set (#8).
        if !matches!(item, PreparedItem::Read(_)) {
            state.bump_generation();
        }
        match item {
            PreparedItem::Delete(key) => {
                first_use(&mut seen.deletes, &key, "delete")?;
                Engine::remove_rule(state, domains, &RuleId::new(key.clone()))
                    .map(|()| BulkOutcome::Deleted(key))
            }
            PreparedItem::Update(key, prep_res) => {
                first_use(&mut seen.updates, &key, "update target")?;
                Engine::update_prepared_rule(state, domains, &RuleId::new(key.clone()), prep_res?)
                    .map(|()| BulkOutcome::Updated(key))
            }
            PreparedItem::Create(key, prep_res) => {
                first_use(&mut seen.creates, &key, "create")?;
                Engine::add_prepared_rule(state, domains, prep_res?)
                    .map(|_| BulkOutcome::Created(key))
            }
            PreparedItem::Read(filter) => Self::read(state, domains, &filter),
        }
    }

    /// Commits the native transaction, or aborts it after a failed item, and
    /// keeps the facade's own state in step with the outcome.
    fn finish_transaction(
        state: &mut FirewallState,
        domains: &DomainSetManager,
        checkpoint: Checkpoint,
        any_failure: bool,
        results: &mut [BulkItemResult],
    ) -> Result<(), Error> {
        if any_failure {
            if let Err(source) = state.backend.abort_transaction() {
                checkpoint.restore_after_failed_rollback(state, domains);
                return Err(Error::new(
                    ErrorKind::RollbackFailed,
                    "native bulk transaction rollback failed",
                )
                .with_source(source));
            }
            checkpoint.restore(state, domains);
            for result in results.iter_mut().filter(|result| result.outcome.is_ok()) {
                result.outcome = Ok(BulkOutcome::RolledBack);
            }
            return Ok(());
        }

        let Err(source) = state.backend.commit_transaction() else {
            return Ok(());
        };
        if let Err(rollback_source) = state.backend.abort_transaction() {
            checkpoint.restore_after_failed_rollback(state, domains);
            return Err(Error::new(
                ErrorKind::RollbackFailed,
                format!("native commit failed ({source}); subsequent rollback failed"),
            )
            .with_source(rollback_source));
        }
        checkpoint.restore(state, domains);
        Err(Error::new(
            ErrorKind::TransactionFailed,
            "native bulk transaction commit failed",
        )
        .with_source(source))
    }

    fn read(
        state: &mut FirewallState,
        domains: &DomainSetManager,
        filter: &BulkRead,
    ) -> Result<BulkOutcome, Error> {
        let rule_filter = RuleFilter {
            key_prefix: filter.key_prefix.clone(),
            direction: filter.direction,
        };
        let rules = Engine::list_rules(state, domains, &rule_filter)?
            .into_iter()
            .map(|(id, rule)| (id.key().clone(), rule))
            .collect();
        Ok(BulkOutcome::Read(rules))
    }
}

fn bulk_priority(operation: &BulkOperation) -> u8 {
    match operation {
        BulkOperation::Delete(_) => 0,
        BulkOperation::Update(_) => 1,
        BulkOperation::Create(_) => 2,
        BulkOperation::Read(_) => 3,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::{Arc, Weak};

    use firew_core::{Action, BulkUpdate, Direction, Rule, RuleRegistry};
    use firew_sys::BackendConfig;
    use ipnet::IpNet;

    use super::*;
    use crate::test_support::{BackendCall, ScriptControl, ScriptedBackend};

    fn rule(key: &str, host: u8) -> Rule {
        Rule::builder(key, Action::Block, Direction::Outbound)
            .remote_address(
                IpNet::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, host)), 32).expect("host network"),
            )
            .build()
            .expect("valid rule")
    }

    fn harness(supports_transactions: bool) -> (FirewallState, DomainSetManager, ScriptControl) {
        let (backend, control) = ScriptedBackend::new(supports_transactions);
        let state = FirewallState {
            backend: Box::new(backend),
            config: BackendConfig::new("bulk-test"),
            registry: RuleRegistry::new(),
            native_rules: HashMap::new(),
            desired_initialized: false,
            desired_generation: 0,
            closed: false,
            monitors: Vec::new(),
            dns_resolver: None,
        };
        let domains =
            DomainSetManager::new(Duration::from_secs(60), Weak::new()).expect("domain manager");
        (state, domains, control)
    }

    #[test]
    fn require_native_rejects_before_any_backend_call() {
        let (mut state, domains, control) = harness(false);
        let request = BulkRequest::new(vec![BulkOperation::Create(vec![rule("a", 1)])])
            .with_transaction_mode(TransactionMode::RequireNative);

        let error = BulkExecutor::execute(&mut state, &domains, Duration::from_secs(1), &request)
            .expect_err("native transaction must be required");

        assert_eq!(error.kind(), ErrorKind::UnsupportedOperation);
        assert!(control.calls().is_empty());
        assert!(control.rules().is_empty());
        assert!(state.registry.is_empty());
    }

    #[test]
    fn native_failure_short_circuits_later_items_and_rolls_back_prior_items() {
        let (mut state, domains, control) = harness(true);
        control.fail_add("bad");
        let request = BulkRequest::prefer_native(vec![BulkOperation::Create(vec![
            rule("good", 2),
            rule("bad", 3),
            rule("after-bad", 4),
        ])]);

        let execution =
            BulkExecutor::execute(&mut state, &domains, Duration::from_secs(1), &request)
                .expect("execution report");

        assert_eq!(execution.atomicity, ExecutionAtomicity::NativeAtomic);
        assert!(matches!(
            execution.results[0].outcome,
            Ok(BulkOutcome::RolledBack)
        ));
        assert_eq!(
            execution.results[1]
                .outcome
                .as_ref()
                .expect_err("scripted failure")
                .kind(),
            ErrorKind::Internal
        );
        assert!(matches!(
            execution.results[2].outcome,
            Ok(BulkOutcome::RolledBack)
        ));
        assert_eq!(
            control.calls(),
            vec![
                BackendCall::Begin,
                BackendCall::Add("good".to_owned()),
                BackendCall::Add("bad".to_owned()),
                BackendCall::Abort,
            ]
        );
        assert!(control.rules().is_empty());
        assert!(state.registry.is_empty());
        assert!(state.native_rules.is_empty());
    }

    #[test]
    fn duplicate_target_key_in_bulk_update_is_rejected_and_rolls_back_native_transaction() {
        let (mut state, domains, control) = harness(true);
        let initial = rule("dup", 1);
        let key = initial.logical_key().clone();
        control.seed(initial.clone());
        state.registry.register(initial.clone());
        state.native_rules.insert(
            key.clone(),
            firew_sys::NativeRuleRef::new("scripted", key.to_string(), key.clone()),
        );
        control.clear_calls();

        let request = BulkRequest::prefer_native(vec![BulkOperation::Update(vec![
            BulkUpdate {
                logical_key: key.clone(),
                rule: rule("dup", 2),
            },
            BulkUpdate {
                logical_key: key.clone(),
                rule: rule("dup", 3),
            },
        ])]);

        let execution =
            BulkExecutor::execute(&mut state, &domains, Duration::from_secs(1), &request)
                .expect("execution report");

        assert!(matches!(
            execution.results[0].outcome,
            Ok(BulkOutcome::RolledBack)
        ));
        assert_eq!(
            execution.results[1]
                .outcome
                .as_ref()
                .expect_err("duplicate update key")
                .kind(),
            ErrorKind::InvalidRule
        );
        assert_eq!(control.rules(), vec![initial]);
    }

    #[test]
    fn sequential_execution_continues_and_preserves_caller_result_order() {
        let (mut state, domains, control) = harness(false);
        control.fail_add("bad");
        let request = BulkRequest::new(vec![
            BulkOperation::Create(vec![rule("bad", 4), rule("good", 5)]),
            BulkOperation::Delete(vec![RuleKey::try_from("missing").expect("key")]),
        ]);

        let execution =
            BulkExecutor::execute(&mut state, &domains, Duration::from_secs(1), &request)
                .expect("execution report");

        assert_eq!(
            execution.atomicity,
            ExecutionAtomicity::SequentialBestEffort
        );
        assert_eq!(
            execution
                .results
                .iter()
                .map(|result| (result.operation_index, result.item_index))
                .collect::<Vec<_>>(),
            vec![(0, 0), (0, 1), (1, 0)]
        );
        assert!(execution.results[0].outcome.is_err());
        assert!(matches!(
            execution.results[1].outcome,
            Ok(BulkOutcome::Created(_))
        ));
        assert!(execution.results[2].outcome.is_err());
        assert_eq!(
            control.calls(),
            vec![
                BackendCall::List,
                // Deleting an unlisted key still asks the backend to remove
                // any rows a damaged rule left behind; there are none here.
                BackendCall::Remove("missing".to_owned()),
                BackendCall::Add("bad".to_owned()),
                BackendCall::Add("good".to_owned()),
            ]
        );
        assert_eq!(control.rules(), vec![rule("good", 5)]);
    }

    #[test]
    fn commit_and_abort_failure_reports_rollback_failure() {
        let (mut state, domains, control) = harness(true);
        control.fail_commit();
        control.fail_abort();
        let request =
            BulkRequest::prefer_native(vec![BulkOperation::Create(vec![rule("created", 6)])]);

        let error = BulkExecutor::execute(&mut state, &domains, Duration::from_secs(1), &request)
            .expect_err("rollback failure");

        assert_eq!(error.kind(), ErrorKind::RollbackFailed);
        assert_eq!(
            control.calls(),
            vec![
                BackendCall::Begin,
                BackendCall::Add("created".to_owned()),
                BackendCall::Commit,
                BackendCall::Abort,
                BackendCall::List,
            ]
        );
        // The failed rollback left the rule installed. Desired state goes back
        // to the checkpoint, but the native cache keeps the rule it found...
        assert_eq!(control.rules(), vec![rule("created", 6)]);
        assert!(state.registry.is_empty());
        assert!(state
            .native_rules
            .contains_key(&RuleKey::try_from("created").expect("key")));

        // ...so adding the same key again is refused instead of installing a
        // second native object.
        let retry = BulkRequest::new(vec![BulkOperation::Create(vec![rule("created", 6)])]);
        let execution = BulkExecutor::execute(&mut state, &domains, Duration::from_secs(1), &retry)
            .expect("execution report");
        assert_eq!(
            execution.results[0]
                .outcome
                .as_ref()
                .expect_err("duplicate of the leftover rule")
                .kind(),
            ErrorKind::InvalidRule
        );
        assert_eq!(control.rules(), vec![rule("created", 6)]);
    }

    #[test]
    fn bulk_requests_do_not_declare_the_complete_desired_set() {
        let (mut state, domains, _control) = harness(true);
        let request = BulkRequest::new(vec![
            BulkOperation::Read(BulkRead::default()),
            BulkOperation::Create(vec![rule("one", 7)]),
        ]);

        BulkExecutor::execute(&mut state, &domains, Duration::from_secs(1), &request)
            .expect("execution report");

        assert!(
            !state.desired_initialized,
            "a bulk read or create must not let health delete unregistered rules"
        );
    }

    #[test]
    fn native_rollback_restores_domain_refresh_registration() {
        let (mut state, domains, control) = harness(true);
        let domain_rule = Rule::builder("domain", Action::Block, Direction::Outbound)
            .remote_domain("example.com")
            .expect("domain")
            .build()
            .expect("domain rule");
        let key = domain_rule.logical_key().clone();
        control.seed(domain_rule.clone());
        state.registry.register(domain_rule.clone());
        state.native_rules.insert(
            key.clone(),
            firew_sys::NativeRuleRef::new("scripted", key.to_string(), key.clone()),
        );
        domains
            .register_resolved(
                &domain_rule,
                Arc::from(["192.0.2.2/32".parse::<IpNet>().expect("resolved network")]),
            )
            .expect("register domain refresh");
        control.fail_add("bad");
        let request = BulkRequest::prefer_native(vec![
            BulkOperation::Delete(vec![key.clone()]),
            BulkOperation::Create(vec![rule("bad", 10)]),
        ]);

        BulkExecutor::execute(&mut state, &domains, Duration::from_secs(1), &request)
            .expect("rollback report");

        assert!(domains.is_registered(&key));
        assert!(state.registry.get(&key).is_some());
        assert!(state.native_rules.contains_key(&key));
        assert_eq!(control.rules(), vec![domain_rule]);
    }
}
