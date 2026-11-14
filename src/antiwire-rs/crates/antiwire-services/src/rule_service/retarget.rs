//! Moving an application's rules when its executable path changes.

use antiwire_policy::Verdict;
use antiwire_store::FirewallRule;

use super::change::RuleChange;
use super::classify::{rule_snapshot, snapshots};
use super::error::{Result, RuleServiceError};
use super::service::{ChangeGuard, RuleService};

/// What [`RuleService::retarget_app_rules`] did with one application's rules.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct RetargetOutcome {
    /// Rules now targeting the new executable.
    pub moved: usize,
    /// Allow rules left on the old path because the new executable's publisher
    /// could not be verified.
    pub held_allows: usize,
}

impl RuleService {
    /// Re-points saved application rules of one version family at the
    /// current executable path.
    ///
    /// Called when an application updates in place. Candidates are selected by
    /// normalized application-family identity rather than the immediately
    /// previous exact path, so a rule left on any earlier version (a skipped
    /// update, an offline update the migration merged, or a previously failed
    /// retarget) is caught as well. Rules keep their id, verdict, and
    /// direction; only the target moves.
    ///
    /// A path inside the same install root does not prove the new executable is
    /// the same application: those directories are often writable by the user
    /// running it. So every rule follows only when `same_publisher` says both
    /// executables carry a valid signature from one publisher. Otherwise only a
    /// block can follow, and only when the family's latest rule is a block:
    /// carrying a block forward can restrict the new executable but never grant
    /// it anything. Allow rules that stay behind are counted in the outcome so
    /// the caller can tell the user.
    ///
    /// While the settings keep packet rules off (`DaemonSetting::uses_packet_rules`) no
    /// application rule is in the engine or the firewall, so only the saved rows move.
    /// They are installed at the new path when packet rules come back.
    ///
    /// Each rule moves as its own change. One that fails and is fully undone
    /// stays at its old path and is retried on the next version move. The
    /// engine is then rebuilt in saved order, so precedence stays identical
    /// to a restart.
    ///
    /// # Errors
    ///
    /// A store failure reading the rules, or one
    /// [`RuleServiceError::Inconsistent`] per rule whose move could not be
    /// undone, combined in [`RuleServiceError::Several`] when there are more.
    pub fn retarget_app_rules(
        &self,
        previous_path: &str,
        new_path: &str,
        same_publisher: bool,
    ) -> Result<RetargetOutcome> {
        let guard = self.begin_change();
        let previous_path = previous_path.trim();
        let new_path = new_path.trim();
        if previous_path.is_empty()
            || new_path.is_empty()
            || previous_path.eq_ignore_ascii_case(new_path)
        {
            return Ok(RetargetOutcome::default());
        }

        let family = antiwire_policy::app_rule_identity(new_path);
        if antiwire_policy::app_rule_identity(previous_path) != family {
            // Only a within-family move retargets; a different path is a new
            // application whose rules must not be touched.
            return Ok(RetargetOutcome::default());
        }

        // Saved order is precedence order, so the last rule is the one the
        // family currently resolves to.
        let family_rules: Vec<FirewallRule> = self
            .store
            .list_application_rules()?
            .into_iter()
            .filter(|rule| antiwire_policy::app_rule_identity(&rule.target_value) == family)
            .collect();
        let family_blocks = family_rules
            .last()
            .is_some_and(|rule| rule.action == Verdict::Block);

        let in_effect = self.store.get_settings()?.uses_packet_rules();
        let mut outcome = RetargetOutcome::default();
        let mut failures = Vec::new();
        for rule in &family_rules {
            let follows = same_publisher || (family_blocks && rule.action == Verdict::Block);
            if !follows {
                if rule.action == Verdict::Allow
                    && !rule.target_value.eq_ignore_ascii_case(new_path)
                {
                    outcome.held_allows += 1;
                }
                continue;
            }
            match move_app_rule(&guard, rule, new_path, in_effect) {
                Ok(true) => outcome.moved += 1,
                Ok(false) => {}
                Err(error) if error.is_inconsistent() => failures.push(error),
                Err(error) => tracing::warn!(
                    rule_id = rule.id,
                    %error,
                    "could not move an application rule to its new path; it stays at the old one"
                ),
            }
        }

        // Moving changes targets but not creation order. Rebuilding from
        // saved order keeps precedence identical to a restart; the engine
        // otherwise promotes every moved rule to the end of its bucket, which
        // could flip a block over a newer allow.
        if outcome.moved > 0 && in_effect {
            if let Err(error) = self.rebuild_engine_from_store() {
                failures.push(error);
            }
        }

        match failures.len() {
            0 => Ok(outcome),
            1 => Err(failures.remove(0)),
            _ => Err(RuleServiceError::Several(failures)),
        }
    }

    /// Rebuilds the engine's rules in saved order. The caller holds the gate,
    /// so what is read here is current.
    fn rebuild_engine_from_store(&self) -> Result<()> {
        let rules = self.store.list_rules()?;
        let networks = self.store.list_all_rule_cidrs()?;
        let (simple, countries) = snapshots(&rules, &networks);
        self.engine.write().replace_user_rules(simple, countries);
        Ok(())
    }
}

/// Moves one saved application rule to `new_path`, as one change: its row, and with
/// `in_effect` its place in the engine and the firewall. Returns `false` when there is
/// nothing to move.
fn move_app_rule(
    guard: &ChangeGuard<'_>,
    rule: &FirewallRule,
    new_path: &str,
    in_effect: bool,
) -> Result<bool> {
    if rule.target_value.eq_ignore_ascii_case(new_path) {
        return Ok(false);
    }
    let mut moved = rule.clone();
    new_path.clone_into(&mut moved.target_value);
    let snapshot = rule_snapshot(&moved)?;
    if snapshot.target == rule.target_value {
        return Ok(false);
    }
    moved.target_value.clone_from(&snapshot.target);
    RuleChange::run(guard, |change| {
        change.update_row(rule, &moved)?;
        if in_effect {
            change.upsert_rule(snapshot)?;
        }
        Ok(true)
    })
}
