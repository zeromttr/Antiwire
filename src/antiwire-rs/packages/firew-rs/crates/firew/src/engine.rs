//! Single synchronous implementation shared by all facade adapters.

use std::collections::HashSet;
use std::time::Duration;

use firew_core::{Error, ErrorKind, Rule, RuleKey};
use firew_sys::{NativeRuleRef, RuleFilter};

use crate::domain_manager::{CustomDnsResolver, DomainSetManager, FamilySupport, ResolvedNetworks};
use crate::firewall::FirewallState;
use crate::rule_id::RuleId;

pub(crate) struct Engine;

#[derive(Clone)]
pub(crate) struct PreparedRule {
    pub(crate) logical: Rule,
    pub(crate) native: Rule,
    pub(crate) resolved: Option<ResolvedNetworks>,
}

/// Snapshot of state needed to validate and resolve a rule without holding the
/// `FirewallState` mutex across DNS I/O.
#[derive(Clone)]
pub(crate) struct PrepContext {
    pub(crate) memory_mode: bool,
    pub(crate) supports_ipv6: bool,
    pub(crate) max_address_set_entries: Option<usize>,
    pub(crate) dns_resolver: Option<CustomDnsResolver>,
}

impl PrepContext {
    pub(crate) fn from_state(state: &FirewallState) -> Self {
        Self {
            memory_mode: state.config.memory_mode,
            supports_ipv6: state.backend.supports_ipv6(),
            max_address_set_entries: state.backend.max_address_set_entries(),
            dns_resolver: state.dns_resolver.clone(),
        }
    }
}

impl Engine {
    /// Performs rule validation and initial DNS resolution outside the `FirewallState` lock.
    pub(crate) fn prepare_unlocked(
        ctx: &PrepContext,
        domains: &DomainSetManager,
        dns_timeout: Duration,
        rule: &Rule,
    ) -> Result<PreparedRule, Error> {
        rule.validate()?;
        if rule.remote_domains().is_empty() {
            return Ok(PreparedRule {
                logical: rule.clone(),
                native: rule.clone(),
                resolved: None,
            });
        }
        if !ctx.memory_mode {
            return Err(Error::new(
                ErrorKind::UnsupportedOperation,
                "domain-backed rules require memory mode",
            )
            .with_logical_key(rule.logical_key()));
        }

        let family = FamilySupport::for_rule(rule, ctx.supports_ipv6);
        let resolved = domains.resolve_initial_for_family(
            rule,
            dns_timeout,
            family,
            ctx.dns_resolver.as_ref(),
        )?;
        let native_rule =
            DomainSetManager::expand_resolved(rule, &resolved, ctx.max_address_set_entries)?;
        Ok(PreparedRule {
            logical: rule.clone(),
            native: native_rule,
            resolved: Some(resolved),
        })
    }

    pub(crate) fn add_prepared_rule(
        state: &mut FirewallState,
        domains: &DomainSetManager,
        prepared: PreparedRule,
    ) -> Result<RuleId, Error> {
        state.backend.validate_rule(&prepared.native)?;
        let rule = prepared.logical.clone();
        let key = rule.logical_key().clone();

        if let Some(cached) = state.native_rules.get(&key).cloned() {
            // Revalidate cached reference against authoritative native state (#16):
            // if the rule was deleted externally, evict the stale entry rather than failing.
            if state.backend.get_rule(&cached).is_ok() {
                return Err(
                    Error::new(ErrorKind::InvalidRule, "duplicate logical rule key")
                        .with_logical_key(&key),
                );
            }
            state.native_rules.remove(&key);
        }

        let native = state.backend.add_rule(&prepared.native)?;
        if let Err(source) = Self::sync_domain_registration(domains, &rule, prepared) {
            if let Err(rollback) = state.backend.remove_rule(&native) {
                return Err(Error::new(
                    ErrorKind::RollbackFailed,
                    format!("domain registration failed ({source}); native add rollback failed"),
                )
                .with_logical_key(&key)
                .with_source(rollback));
            }
            return Err(source);
        }
        state.native_rules.insert(key.clone(), native);
        state.registry.register(rule);
        Ok(RuleId::new(key))
    }

    pub(crate) fn get_rule(
        state: &mut FirewallState,
        domains: &DomainSetManager,
        id: &RuleId,
    ) -> Result<Rule, Error> {
        let native = Self::find_native(state, id.key())?;
        match state.backend.get_rule(&native) {
            Ok(actual) => Ok(Self::restore_logical_domain_rule(
                state,
                domains,
                id.key(),
                actual,
            )),
            Err(err) => {
                if err.kind() == ErrorKind::RuleNotFound {
                    state.native_rules.remove(id.key());
                }
                Err(err)
            }
        }
    }

    pub(crate) fn update_prepared_rule(
        state: &mut FirewallState,
        domains: &DomainSetManager,
        id: &RuleId,
        prepared: PreparedRule,
    ) -> Result<(), Error> {
        let rule = prepared.logical.clone();
        if id.key() != rule.logical_key() {
            return Err(firew_sys::key_mismatch(&rule));
        }
        state.backend.validate_rule(&prepared.native)?;

        let native = Self::find_native(state, id.key())?;
        let previous_logical = state
            .registry
            .get(id.key())
            .cloned()
            .or_else(|| state.backend.get_rule(&native).ok());
        let max_set = state.backend.max_address_set_entries();
        let previous_native = previous_logical
            .as_ref()
            .and_then(|prev| domains.expected_native(prev, max_set));

        let new_native = match state.backend.update_rule(&native, &prepared.native) {
            Ok(updated) => updated,
            Err(update_err) => {
                if update_err.kind() == ErrorKind::RuleNotFound {
                    state.native_rules.remove(id.key());
                    return Err(update_err);
                }
                // Ensure the previous rule remains enforced if a backend's update
                // removed the old rule before failing to add the replacement (#4).
                if state.backend.get_rule(&native).is_err() {
                    if let Some(ref prev_nat) = previous_native {
                        match state.backend.add_rule(prev_nat) {
                            Ok(restored_ref) => {
                                state.native_rules.insert(id.key().clone(), restored_ref);
                            }
                            Err(restore_err) => {
                                state.native_rules.remove(id.key());
                                state.registry.unregister(id.key());
                                domains.unregister(id.key());
                                return Err(Error::new(
                                    ErrorKind::RollbackFailed,
                                    format!(
                                        "rule update failed ({update_err}); restoring previous rule failed"
                                    ),
                                )
                                .with_logical_key(id.key())
                                .with_source(restore_err));
                            }
                        }
                    } else {
                        state.native_rules.remove(id.key());
                    }
                }
                return Err(update_err);
            }
        };

        if let Err(source) = Self::sync_domain_registration(domains, &rule, prepared) {
            // Mirror the add path: put the previous native rule back, so the
            // registry, the native rule, and the refresh bookkeeping (still on
            // the previous registration) all agree again.
            let restored = previous_native
                .as_ref()
                .map(|prev_nat| state.backend.update_rule(&new_native, prev_nat));
            return match restored {
                Some(Ok(restored_ref)) => {
                    state.native_rules.insert(id.key().clone(), restored_ref);
                    Err(source)
                }
                outcome => {
                    // The replacement stays installed. Record it as desired and
                    // drop the stale refresh registration so a later refresh
                    // cannot write the previous addresses over it.
                    state.native_rules.insert(id.key().clone(), new_native);
                    state.registry.register(rule);
                    domains.unregister(id.key());
                    let detail = match outcome {
                        Some(Err(restore_err)) => {
                            format!("; restoring the previous rule failed: {restore_err}")
                        }
                        _ => "; no previous rule to restore".to_owned(),
                    };
                    Err(Error::new(
                        ErrorKind::PartialMutation,
                        format!("native rule updated but refresh registration failed{detail}"),
                    )
                    .with_logical_key(id.key())
                    .with_source(source))
                }
            };
        }
        state.native_rules.insert(id.key().clone(), new_native);
        state.registry.register(rule);
        Ok(())
    }

    pub(crate) fn remove_rule(
        state: &mut FirewallState,
        domains: &DomainSetManager,
        id: &RuleId,
    ) -> Result<(), Error> {
        let native = match Self::find_native(state, id.key()) {
            Ok(native) => native,
            // No complete rule is listed, but rows of a damaged one, such as
            // the surviving half of a bidirectional rule, can still be
            // installed and matching. Given the bare key, the backend deletes
            // them, or reports `RuleNotFound` when there are none.
            Err(err) if err.kind() == ErrorKind::RuleNotFound => {
                NativeRuleRef::from_handles(state.backend.name(), Vec::new(), id.key().clone())
            }
            Err(err) => return Err(err),
        };
        let removed = state.backend.remove_rule(&native);
        // A rule that is gone natively leaves desired state too, or health
        // repair would put back a rule the caller removed.
        let gone = match &removed {
            Ok(()) => true,
            Err(err) => err.kind() == ErrorKind::RuleNotFound,
        };
        if gone {
            state.native_rules.remove(id.key());
            state.registry.unregister(id.key());
            domains.unregister(id.key());
        }
        removed
    }

    pub(crate) fn list_rules(
        state: &mut FirewallState,
        domains: &DomainSetManager,
        filter: &RuleFilter,
    ) -> Result<Vec<(RuleId, Rule)>, Error> {
        let listed = state.backend.list_rules(filter)?;
        Self::sync_native_cache_from_listing(state, filter, &listed);
        Ok(listed
            .into_iter()
            .map(|(native, actual_rule)| {
                let key = native.logical_key().clone();
                let logical = Self::restore_logical_domain_rule(state, domains, &key, actual_rule);
                (RuleId::new(key), logical)
            })
            .collect())
    }

    /// Lists raw native rules (without substituting logical domain rules) while
    /// refreshing `state.native_rules` authoritatively.
    pub(crate) fn list_native_rules(
        state: &mut FirewallState,
        filter: &RuleFilter,
    ) -> Result<Vec<(NativeRuleRef, Rule)>, Error> {
        let listed = state.backend.list_rules(filter)?;
        Self::sync_native_cache_from_listing(state, filter, &listed);
        Ok(listed)
    }

    fn sync_native_cache_from_listing(
        state: &mut FirewallState,
        filter: &RuleFilter,
        listed: &[(NativeRuleRef, Rule)],
    ) {
        let present: HashSet<&RuleKey> = listed
            .iter()
            .map(|(native, _)| native.logical_key())
            .collect();

        if filter.key_prefix.is_none() && filter.direction.is_none() {
            state.native_rules.retain(|k, _| present.contains(k));
        } else if let Some(prefix) = &filter.key_prefix {
            if filter.direction.is_none() {
                state
                    .native_rules
                    .retain(|k, _| !k.as_str().starts_with(prefix.as_str()) || present.contains(k));
            }
        }

        for (native, _) in listed {
            state
                .native_rules
                .insert(native.logical_key().clone(), native.clone());
        }
    }

    /// When `actual_rule` matches the expanded native representation of a registered
    /// domain rule, returns the logical domain rule so `get_rule`/`list_rules`
    /// preserve `remote_domains` while still surfacing external native edits.
    fn restore_logical_domain_rule(
        state: &FirewallState,
        domains: &DomainSetManager,
        key: &RuleKey,
        actual_rule: Rule,
    ) -> Rule {
        let Some(logical) = domains
            .registered_rule(key)
            .or_else(|| state.registry.get(key).cloned())
        else {
            return actual_rule;
        };
        if logical.remote_domains().is_empty() {
            return actual_rule;
        }
        let expected = domains.expected_native(&logical, state.backend.max_address_set_entries());
        if expected.as_ref() == Some(&actual_rule) {
            logical
        } else {
            actual_rule
        }
    }

    pub(crate) fn remove_all_rules(
        state: &mut FirewallState,
        domains: &DomainSetManager,
    ) -> Result<(), Error> {
        state.backend.remove_all_managed()?;
        for rule in state.registry.rules() {
            domains.unregister(rule.logical_key());
        }
        state.registry.clear();
        state.native_rules.clear();
        Ok(())
    }

    /// Removes every rule in the native-reference cache one at a time, ignoring
    /// failures, then forgets them. A fallback for drop cleanup when the
    /// namespace-wide removal failed and nothing can report the error.
    pub(crate) fn remove_known_rules_best_effort(
        state: &mut FirewallState,
        domains: &DomainSetManager,
    ) {
        if let Ok(listed) = state.backend.list_rules(&RuleFilter::new()) {
            Self::sync_native_cache_from_listing(state, &RuleFilter::new(), &listed);
        }
        let natives: Vec<NativeRuleRef> = state.native_rules.values().cloned().collect();
        for native in natives {
            if state.backend.remove_rule(&native).is_ok() {
                state.native_rules.remove(native.logical_key());
            }
        }
        for rule in state.registry.rules() {
            domains.unregister(rule.logical_key());
        }
        state.registry.clear();
    }

    pub(crate) fn sync_domain_registration(
        domains: &DomainSetManager,
        rule: &Rule,
        prepared: PreparedRule,
    ) -> Result<(), Error> {
        if let Some(resolved) = prepared.resolved {
            domains.register_resolved(rule, resolved)?;
        } else {
            domains.unregister(rule.logical_key());
        }
        Ok(())
    }

    pub(crate) fn find_native(
        state: &mut FirewallState,
        key: &RuleKey,
    ) -> Result<NativeRuleRef, Error> {
        if let Some(native) = state.native_rules.get(key).cloned() {
            if state.backend.get_rule(&native).is_ok() {
                return Ok(native);
            }
            state.native_rules.remove(key);
        }

        let listed = state.backend.list_rules(&RuleFilter::new())?;
        Self::sync_native_cache_from_listing(state, &RuleFilter::new(), &listed);
        state
            .native_rules
            .get(key)
            .cloned()
            .ok_or_else(|| firew_sys::rule_not_found(key))
    }
}
