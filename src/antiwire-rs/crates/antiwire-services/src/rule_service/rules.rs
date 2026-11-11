//! Rules on one application, address, or domain; listing; domain explanations.

use antiwire_policy::{DomainBlockSource, RuleTargetKind, Verdict};
use antiwire_store::FirewallRule;
use time::OffsetDateTime;

use super::change::RuleChange;
use super::classify::{normalize_target, rule_snapshot};
use super::country::country_summaries;
use super::error::{Result, RuleServiceError};
use super::request::{NewRule, RuleListing, RuleSelector};
use super::service::RuleService;

/// Why the policy blocks a domain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DomainBlock {
    /// What blocks it, when the engine records that.
    pub source: Option<DomainBlockSource>,
    /// Blocklists that list the domain, as the user sees them.
    pub blocklist_names: Vec<String>,
}

impl RuleService {
    /// Saves `rule` and puts it into effect. Returns the rule as saved, with
    /// its id and normalized target.
    ///
    /// # Errors
    ///
    /// [`RuleServiceError::Invalid`](super::RuleServiceError::Invalid) for a
    /// target that does not normalize. Otherwise a store or firewall failure;
    /// the change is then undone.
    pub fn add_rule(&self, rule: &NewRule) -> Result<FirewallRule> {
        let guard = self.begin_change();
        let mut stored = FirewallRule {
            id: 0,
            target_type: RuleTargetKind::from(rule.target_type),
            target_value: normalize_target(rule.target_type, &rule.target)?,
            action: rule.verdict,
            direction: rule.direction,
            created_at: OffsetDateTime::now_utc(),
        };
        RuleChange::run(&guard, |change| {
            stored.id = change.insert_row(&stored)?;
            change.upsert_rule(rule_snapshot(&stored)?)?;
            Ok(stored)
        })
    }

    /// Removes the rule `selector` names. Returns `false` when there is none.
    ///
    /// # Errors
    ///
    /// [`RuleServiceError::Invalid`](super::RuleServiceError::Invalid) for an
    /// id naming a country block, or a target that does not normalize.
    /// Otherwise a store or firewall failure; the change is then undone.
    pub fn remove_rule(&self, selector: &RuleSelector) -> Result<bool> {
        let guard = self.begin_change();
        let Some(stored) = self.find_rule(selector)? else {
            return Ok(false);
        };
        if stored.target_type == RuleTargetKind::Country {
            return Err(RuleServiceError::invalid(format!(
                "rule {} is a country block",
                stored.id
            )));
        }
        // The engine may not hold a row that failed to load; deleting it
        // still works, so the user can always remove a bad rule.
        RuleChange::run(&guard, |change| {
            change.remove_rule(stored.id)?;
            change.delete_row(stored.id)?;
            Ok(true)
        })
    }

    fn find_rule(&self, selector: &RuleSelector) -> Result<Option<FirewallRule>> {
        match selector {
            RuleSelector::Id(id) => match self.store.get_rule(*id) {
                Ok(rule) => Ok(Some(rule)),
                Err(antiwire_store::StoreError::RuleNotFound(_)) => Ok(None),
                Err(error) => Err(error.into()),
            },
            RuleSelector::Target {
                target_type,
                target,
            } => {
                let kind = RuleTargetKind::from(*target_type);
                let target = normalize_target(*target_type, target)?;
                Ok(self
                    .store
                    .list_rules()?
                    .into_iter()
                    .find(|rule| rule.target_type == kind && rule.target_value == target))
            }
        }
    }

    /// Every saved rule, read at one moment between changes.
    ///
    /// # Errors
    ///
    /// A store failure.
    pub fn list(&self) -> Result<RuleListing> {
        let _gate = self.read_gate();
        let (countries, rules) = self
            .store
            .list_rules()?
            .into_iter()
            .partition::<Vec<_>, _>(|rule| rule.target_type == RuleTargetKind::Country);
        Ok(RuleListing {
            rules,
            countries: country_summaries(&self.store, &countries)?,
        })
    }

    /// Why the policy blocks `domain`, or `None` when it does not.
    #[must_use]
    pub fn explain_domain_block(&self, domain: &str) -> Option<DomainBlock> {
        let domain = domain.trim();
        if domain.is_empty() {
            return None;
        }
        let engine = self.engine.read();
        let decision = engine.evaluate_domain_with_source(domain)?;
        if decision.verdict != Verdict::Block {
            return None;
        }
        let source = decision.source;
        let matching_lists = if source == Some(DomainBlockSource::Blocklist) {
            engine.matching_blocklists(domain)
        } else {
            Vec::new()
        };
        Some(DomainBlock {
            source,
            blocklist_names: source
                .map(|source| source.reported_blocklist_names(matching_lists))
                .unwrap_or_default(),
        })
    }
}
