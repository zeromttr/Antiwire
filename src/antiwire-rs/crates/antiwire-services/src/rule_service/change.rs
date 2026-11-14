//! One rule change, applied step by step across the store, the policy engine,
//! and the native firewall, and undone in reverse when a step fails.
//!
//! Every operation takes the same shape: write the row it needs an id from,
//! change the engine, apply the firewall ops the engine returns, and delete a
//! row last, when nothing after it can fail. The firewall ops always come from
//! the engine, so what is installed is exactly what the engine evaluates.

use antiwire_policy::{CountrySnapshot, EnforcementOp, RuleSnapshot};
use antiwire_store::{FirewallRule, StoreError};

use super::error::{Result, RuleServiceError};
use super::service::{ChangeGuard, RuleService};

/// A change in progress. Run one with [`RuleChange::run`].
pub(super) struct RuleChange<'a> {
    service: &'a RuleService,
    /// What to do to take back each step so far, oldest first.
    undo: Vec<Undo>,
}

enum Undo {
    DeleteRow(i32),
    RestoreRow(FirewallRule),
    /// Put a rule back in the engine as it was before.
    RestoreRule(RuleSnapshot),
    /// Take a rule the change added back out of the engine.
    DropRule(RuleSnapshot),
    RestoreCountry(CountrySnapshot),
    DropCountry(i32),
    /// Apply this op to take back one the change applied.
    Native(EnforcementOp),
}

/// The rule an engine change replaced or removed, which a removal's inverse
/// op is built from.
enum Previous<'a> {
    Rule(Option<&'a RuleSnapshot>),
    Country(Option<&'a CountrySnapshot>),
}

impl<'a> RuleChange<'a> {
    /// Runs `steps` as one change under `guard`, keeping every step when it
    /// succeeds and undoing all of them when it fails.
    pub(super) fn run<T>(
        guard: &ChangeGuard<'a>,
        steps: impl FnOnce(&mut Self) -> Result<T>,
    ) -> Result<T> {
        let mut change = Self {
            service: guard.service(),
            undo: Vec::new(),
        };
        match steps(&mut change) {
            Ok(value) => Ok(value),
            Err(error) => Err(change.undo_all(error)),
        }
    }

    pub(super) fn insert_row(&mut self, rule: &FirewallRule) -> Result<i32> {
        let id = self.service.store.insert_rule(rule)?;
        self.undo.push(Undo::DeleteRow(id));
        Ok(id)
    }

    pub(super) fn insert_country_row(
        &mut self,
        rule: &FirewallRule,
        networks: &[String],
    ) -> Result<i32> {
        let id = self.service.store.insert_rule_with_cidrs(rule, networks)?;
        self.undo.push(Undo::DeleteRow(id));
        Ok(id)
    }

    /// Saves `updated` over `previous`.
    pub(super) fn update_row(
        &mut self,
        previous: &FirewallRule,
        updated: &FirewallRule,
    ) -> Result<()> {
        self.service.store.update_rule(updated)?;
        self.undo.push(Undo::RestoreRow(previous.clone()));
        Ok(())
    }

    /// Deletes the row of a rule being removed: the last step of a removal,
    /// so it needs no undo. A row already gone counts as deleted.
    pub(super) fn delete_row(&mut self, id: i32) -> Result<()> {
        match self.service.store.delete_rule(id) {
            Ok(()) | Err(StoreError::RuleNotFound(_)) => Ok(()),
            Err(error) => Err(error.into()),
        }
    }

    /// Adds or replaces `rule` in the engine and the firewall.
    pub(super) fn upsert_rule(&mut self, rule: RuleSnapshot) -> Result<()> {
        let engine = &self.service.engine;
        let previous = engine.read().rule(rule.id).cloned();
        let ops = engine.write().upsert_rule(rule.clone());
        self.undo.push(match previous.clone() {
            Some(previous) => Undo::RestoreRule(previous),
            None => Undo::DropRule(rule),
        });
        self.apply_native(ops, &Previous::Rule(previous.as_ref()))
    }

    /// Takes the rule with `id` out of the engine and the firewall.
    pub(super) fn remove_rule(&mut self, id: i32) -> Result<()> {
        let engine = &self.service.engine;
        let Some(previous) = engine.read().rule(id).cloned() else {
            return Ok(());
        };
        let ops = engine.write().remove_rule(&previous);
        self.undo.push(Undo::RestoreRule(previous.clone()));
        self.apply_native(ops, &Previous::Rule(Some(&previous)))
    }

    /// Adds or replaces `country` in the engine and the firewall.
    pub(super) fn upsert_country(&mut self, country: &CountrySnapshot) -> Result<()> {
        let engine = &self.service.engine;
        let previous = engine.read().country_rule(country.id).cloned();
        let op = engine.write().upsert_country_rule(country);
        self.undo.push(match previous.clone() {
            Some(previous) => Undo::RestoreCountry(previous),
            None => Undo::DropCountry(country.id),
        });
        self.apply_native(vec![op], &Previous::Country(previous.as_ref()))
    }

    /// Takes the country with `id` out of the engine and the firewall.
    pub(super) fn remove_country(&mut self, id: i32) -> Result<()> {
        let engine = &self.service.engine;
        let Some(previous) = engine.read().country_rule(id).cloned() else {
            return Ok(());
        };
        let ops = engine.write().remove_country_rule(id);
        self.undo.push(Undo::RestoreCountry(previous.clone()));
        self.apply_native(ops, &Previous::Country(Some(&previous)))
    }

    /// Applies `ops` in order, recording how to take back each one that
    /// succeeds before trying the next.
    fn apply_native(&mut self, ops: Vec<EnforcementOp>, previous: &Previous<'_>) -> Result<()> {
        for op in ops {
            let inverse = op.undo_install().or_else(|| reinstall(&op, previous));
            self.service.enforce.apply(op)?;
            if let Some(inverse) = inverse {
                self.undo.push(Undo::Native(inverse));
            }
        }
        Ok(())
    }

    /// Takes back every step in reverse, then returns `error`, or an
    /// [`RuleServiceError::Inconsistent`] naming each step that stayed.
    fn undo_all(self, error: RuleServiceError) -> RuleServiceError {
        let service = self.service;
        let mut unrestored = Vec::new();
        for step in self.undo.into_iter().rev() {
            if let Err(failure) = undo_step(service, step) {
                unrestored.push(failure);
            }
        }
        if unrestored.is_empty() {
            error
        } else {
            RuleServiceError::Inconsistent {
                cause: Box::new(error),
                unrestored,
            }
        }
    }
}

/// The op that puts back what `op` removes, built from the rule it removed.
fn reinstall(op: &EnforcementOp, previous: &Previous<'_>) -> Option<EnforcementOp> {
    match (op, previous) {
        (
            EnforcementOp::RemoveAppRule { .. } | EnforcementOp::RemoveIpRule { .. },
            Previous::Rule(Some(rule)),
        ) => EnforcementOp::native_add(rule),
        (EnforcementOp::RemoveCountryBlock { .. }, Previous::Country(Some(country))) => {
            Some(EnforcementOp::country_add(country))
        }
        // A DNS rule is never installed natively, so its leftover-key
        // teardown has nothing to put back.
        _ => None,
    }
}

fn undo_step(service: &RuleService, step: Undo) -> std::result::Result<(), String> {
    // Engine steps discard the ops the engine returns: the firewall is put
    // back by the recorded `Native` steps, which ran first.
    match step {
        Undo::DeleteRow(id) => match service.store.delete_rule(id) {
            Ok(()) | Err(StoreError::RuleNotFound(_)) => Ok(()),
            Err(error) => Err(format!("rule {id} is still saved: {error}")),
        },
        Undo::RestoreRow(rule) => service
            .store
            .update_rule(&rule)
            .map_err(|error| format!("rule {} was not saved back: {error}", rule.id)),
        Undo::RestoreRule(rule) => {
            let _ = service.engine.write().upsert_rule(rule);
            Ok(())
        }
        Undo::DropRule(rule) => {
            let _ = service.engine.write().remove_rule(&rule);
            Ok(())
        }
        Undo::RestoreCountry(country) => {
            let _ = service.engine.write().upsert_country_rule(&country);
            Ok(())
        }
        Undo::DropCountry(id) => {
            let _ = service.engine.write().remove_country_rule(id);
            Ok(())
        }
        Undo::Native(op) => {
            let rule_id = op.rule_id();
            service.enforce.apply(op).map_err(|error| match rule_id {
                Some(id) => format!("the firewall rule for rule {id} was not restored: {error}"),
                None => format!("a firewall rule was not restored: {error}"),
            })
        }
    }
}
