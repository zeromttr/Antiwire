//! Startup: install the saved rules into the firewall and the policy engine.

use std::collections::HashSet;

use antiwire_policy::{EnforcementOp, TargetType};

use super::classify::snapshots;
use super::error::Result;
use super::service::RuleService;

/// Rejected rules logged one by one at startup; the rest are only counted.
const MAX_LOGGED_LOAD_FAILURES: usize = 20;

impl RuleService {
    /// Makes the saved rules the whole of what Antiwire enforces.
    ///
    /// Run once at startup, before anything else installs rules: it clears
    /// every rule Antiwire manages, including the `DoH` block and rules a
    /// killed process left behind, then installs the saved ones. Nothing is
    /// filtered between the clear and the install, which is acceptable only
    /// because nothing was being filtered by this process before it.
    ///
    /// A rule the firewall rejects is logged and left out of the policy
    /// engine too, so the engine never answers as if it were enforced.
    ///
    /// Run again when the settings switch packet rules on or off
    /// (`DaemonSetting::uses_packet_rules`). While they are off the firewall is
    /// stopped and only the rules on domains are in effect.
    ///
    /// # Errors
    ///
    /// A store failure reading the rules, or an enforcement failure starting
    /// the native firewall.
    pub fn install_saved_rules(&self) -> Result<()> {
        let _guard = self.begin_change();
        let rules = self.store.list_rules()?;
        let networks = self.store.list_all_rule_cidrs()?;
        let (simple, countries) = snapshots(&rules, &networks);
        let settings = self.store.get_settings()?;

        if !settings.uses_packet_rules() {
            // Private Relay compatibility: the firewall stays off, and stopping it takes
            // out what it held. Only the rules the resolver answers from are in effect,
            // so those are all the engine is given, as for a rule the firewall rejects.
            if self.enforce.is_enforcing()? {
                self.enforce.stop()?;
            }
            self.engine.write().replace_user_rules(
                simple
                    .into_iter()
                    .filter(|rule| rule.target_type == TargetType::Dns),
                std::iter::empty(),
            );
            return Ok(());
        }

        let mut ops: Vec<EnforcementOp> = simple
            .iter()
            .filter_map(EnforcementOp::native_add)
            .collect();
        ops.extend(countries.iter().map(EnforcementOp::country_add));

        if self.enforce.is_enforcing()? {
            self.enforce.stop()?;
        }
        // So the backend knows whether its rules may end with this process; see
        // `FirewallFilter::start_with_persistence`.
        self.enforce
            .start_with_persistence(settings.persist_rules_offline)?;

        // The backend enumerates the host's rules when it opens and refuses
        // to re-add a key it can already see, so without this the first start
        // after an unclean exit fails on a duplicate and the orphans stay.
        if let Err(error) = self.enforce.remove_all_managed() {
            tracing::warn!(%error, "could not clear previously installed firewall rules");
        }

        // A rule the backend rejects is reported and skipped. Stopping here
        // would leave every other saved rule unenforced, which fails open far
        // worse than the one rule that could not be installed.
        let rejected: HashSet<i32> = self
            .enforce
            .apply_many(ops)?
            .into_iter()
            .enumerate()
            .filter_map(|(index, failure)| {
                if index < MAX_LOGGED_LOAD_FAILURES {
                    tracing::error!(
                        rule_id = ?failure.op.rule_id(),
                        error = %failure.error,
                        "firewall rejected a saved rule; it is not enforced"
                    );
                }
                failure.op.rule_id()
            })
            .collect();
        if !rejected.is_empty() {
            tracing::error!(
                rejected = rejected.len(),
                "some saved rules could not be installed; the rest are enforced"
            );
        }

        self.engine.write().replace_user_rules(
            simple
                .into_iter()
                .filter(|rule| !rejected.contains(&rule.id)),
            countries
                .into_iter()
                .filter(|country| !rejected.contains(&country.id)),
        );
        Ok(())
    }
}
