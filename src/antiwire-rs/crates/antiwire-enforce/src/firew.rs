use std::collections::HashMap;

use antiwire_policy::EnforcementOp;
use firew_rs::{
    BulkOperation, BulkOutcome, BulkRequest, BulkUpdate, ErrorKind, Firewall, Rule, RuleFilter,
    RuleId, RuleKey,
};

use crate::country::BackendCaps;
use crate::filter::FirewallFilter;
use crate::mapping::{apply_country_op, apply_op, op_rule_keys};
use crate::mapping::{country_key_prefix, DOH_KEY_PREFIX};
use crate::{EnforceError, Result, MANAGER_PREFIX};

/// [`FirewallFilter`] backed by [`firew_rs::Firewall`] on all supported platforms.
pub(crate) struct FirewFilter {
    firewall: Option<Firewall>,
    installed: HashMap<String, InstalledRule>,
    doh_rule_keys: Vec<String>,
    /// Keys installed for each country rule id.
    ///
    /// Tracked rather than recomputed because the chunk count depends on the
    /// backend's capabilities, which can differ across a restart — recomputing
    /// could then miss rules that are still installed.
    country_rule_keys: HashMap<i32, Vec<String>>,
    caps: BackendCaps,
    /// The open backend's rules go when this process ends, so it cannot
    /// leave them installed on a stop. See [`open_backend`].
    rules_end_with_process: bool,
}

#[derive(Clone)]
struct InstalledRule {
    id: RuleId,
    rule: Rule,
}

impl Default for FirewFilter {
    fn default() -> Self {
        Self::new()
    }
}

impl FirewFilter {
    #[must_use]
    pub(crate) fn new() -> Self {
        Self {
            firewall: None,
            installed: HashMap::new(),
            doh_rule_keys: Vec::new(),
            country_rule_keys: HashMap::new(),
            caps: BackendCaps::default(),
            rules_end_with_process: false,
        }
    }

    /// Installs (or replaces) every rule backing one country block.
    ///
    /// Always uses the bulk path: pf rebuilds its whole anchor per add and
    /// nftables applies one batch per call, so a native transaction turns N
    /// round trips into one.
    ///
    /// A replacement installs the new generation before retiring the old one, so
    /// a failed replacement leaves the previous block enforcing rather than none.
    /// Chunk keys depend only on the country and chunk index, so a key both
    /// generations share is updated in place, and only old chunks the new
    /// generation no longer uses are removed afterwards.
    fn install_country_block(
        &mut self,
        rule_id: i32,
        code: &str,
        networks: &[ipnet::IpNet],
        verdict: antiwire_policy::Verdict,
        direction: antiwire_policy::RuleDirection,
    ) -> Result<()> {
        let rules = apply_country_op(code, networks, verdict, direction, self.caps)?;
        if rules.is_empty() {
            return Err(EnforceError::InvalidOp(format!(
                "country {code} has no networks to install"
            )));
        }

        // Another rule id holding these keys is a second block for the same
        // country. Updating them would silently take over its rules.
        let owned_elsewhere = self
            .country_rule_keys
            .iter()
            .filter(|(id, _)| **id != rule_id)
            .any(|(_, keys)| rules.iter().any(|(key, _)| keys.contains(key)));
        if owned_elsewhere {
            return Err(EnforceError::InvalidOp(format!(
                "country {code} already has a firewall block"
            )));
        }

        let previous_keys = self
            .country_rule_keys
            .get(&rule_id)
            .cloned()
            .unwrap_or_default();
        let mut to_update = Vec::new();
        let mut to_create = Vec::new();
        for (key, rule) in &rules {
            if previous_keys.contains(key) || self.installed.contains_key(key) {
                to_update.push(BulkUpdate {
                    logical_key: rule.logical_key().clone(),
                    rule: rule.clone(),
                });
            } else {
                to_create.push(rule.clone());
            }
        }
        let mut operations = Vec::with_capacity(2);
        if !to_update.is_empty() {
            operations.push(BulkOperation::Update(to_update));
        }
        if !to_create.is_empty() {
            operations.push(BulkOperation::Create(to_create));
        }

        let firewall = self.firewall.as_mut().ok_or(EnforceError::NotStarted)?;
        let execution = firewall.execute_bulk(&BulkRequest::prefer_native(operations))?;
        let mut created = Vec::new();
        let mut updated = Vec::new();
        let mut failure = None;
        for item in execution.results {
            match item.outcome {
                Ok(BulkOutcome::Created(key)) => created.push(key),
                Ok(BulkOutcome::Updated(key)) => updated.push(key),
                Ok(_) => {}
                Err(error) => {
                    failure.get_or_insert(error);
                }
            }
        }
        if let Some(error) = failure {
            // Whatever this call changed must be undone, so a failed install never
            // leaves a partial or half-replaced block behind.
            self.roll_back_country_install(created, updated);
            return Err(error.into());
        }

        let new_keys: Vec<String> = rules.iter().map(|(key, _)| key.clone()).collect();
        let stale: Vec<String> = previous_keys
            .into_iter()
            .filter(|key| !new_keys.contains(key))
            .collect();
        // Tracked before anything else can fail, so every chunk now installed
        // stays removable by key.
        let mut tracked = new_keys.clone();
        tracked.extend(stale.iter().cloned());
        self.country_rule_keys.insert(rule_id, tracked);

        // `RuleId` cannot be constructed outside `firew_rs`, so the ids are read
        // back from the installed set. One listing covers every chunk. Removal
        // works by key, so a failed read-back only loses the rollback copies.
        match self.country_rule_ids(code) {
            Ok(installed_ids) => {
                for (key, rule) in rules {
                    if let Some(id) = installed_ids.get(&key) {
                        self.installed.insert(
                            key,
                            InstalledRule {
                                id: id.clone(),
                                rule,
                            },
                        );
                    }
                }
            }
            Err(error) => {
                tracing::warn!(%error, code, "could not read back installed country rules");
                for key in &new_keys {
                    self.installed.remove(key);
                }
            }
        }

        // The new generation is enforcing, so an old chunk that will not go away
        // only over-blocks. It stays tracked for the next removal.
        let (remaining, result) = self.delete_country_keys(stale);
        let mut tracked = new_keys;
        tracked.extend(remaining);
        self.country_rule_keys.insert(rule_id, tracked);
        if let Err(error) = result {
            tracing::warn!(%error, code, "could not remove superseded country rules");
        }
        Ok(())
    }

    /// Undoes a sequential bulk install that failed part-way.
    ///
    /// Created chunks are deleted and updated chunks get their previous
    /// definition back. A native transaction has already rolled itself back and
    /// reports neither.
    fn roll_back_country_install(&mut self, created: Vec<RuleKey>, updated: Vec<RuleKey>) {
        let restores: Vec<BulkUpdate> = updated
            .into_iter()
            .filter_map(|key| {
                self.installed.get(key.as_str()).map(|previous| BulkUpdate {
                    logical_key: key,
                    rule: previous.rule.clone(),
                })
            })
            .collect();
        let mut operations = Vec::with_capacity(2);
        if !created.is_empty() {
            operations.push(BulkOperation::Delete(created));
        }
        if !restores.is_empty() {
            operations.push(BulkOperation::Update(restores));
        }
        let Some(firewall) = self.firewall.as_mut() else {
            return;
        };
        if operations.is_empty() {
            return;
        }
        match firewall.execute_bulk(&BulkRequest::new(operations)) {
            Ok(execution) => {
                for error in execution
                    .results
                    .into_iter()
                    .filter_map(|item| item.outcome.err())
                {
                    tracing::error!(%error, "could not roll back a partial country block");
                }
            }
            Err(error) => tracing::error!(%error, "could not roll back a partial country block"),
        }
    }

    /// Deletes country chunks by logical key.
    ///
    /// Returns the keys still installed alongside the first failure. Chunks are
    /// addressed by key rather than by read-back id, so a chunk stays removable
    /// even if the read-back after install failed. A chunk the backend no longer
    /// has counts as removed, so drift cannot pin a key in tracking forever.
    fn delete_country_keys(&mut self, keys: Vec<String>) -> (Vec<String>, Result<()>) {
        if keys.is_empty() {
            return (keys, Ok(()));
        }
        let mut rule_keys = Vec::with_capacity(keys.len());
        for key in &keys {
            match RuleKey::try_from(key.as_str()) {
                Ok(rule_key) => rule_keys.push(rule_key),
                Err(error) => return (keys, Err(EnforceError::InvalidOp(error.to_string()))),
            }
        }
        let Some(firewall) = self.firewall.as_mut() else {
            return (keys, Err(EnforceError::NotStarted));
        };
        // Sequential, so one missing chunk cannot roll back the deletion of the rest.
        let request = BulkRequest::new(vec![BulkOperation::Delete(rule_keys)]);
        let execution = match firewall.execute_bulk(&request) {
            Ok(execution) => execution,
            Err(error) => return (keys, Err(error.into())),
        };

        let mut remaining = Vec::new();
        let mut failure = None;
        for item in execution.results {
            let Some(key) = keys.get(item.item_index) else {
                continue;
            };
            match item.outcome {
                Ok(BulkOutcome::Deleted(_)) => {
                    self.installed.remove(key);
                }
                Err(error) if error.kind() == ErrorKind::RuleNotFound => {
                    self.installed.remove(key);
                }
                Ok(_) => remaining.push(key.clone()),
                Err(error) => {
                    remaining.push(key.clone());
                    failure.get_or_insert(error);
                }
            }
        }
        (remaining, failure.map_or(Ok(()), |error| Err(error.into())))
    }

    /// Reads back the native ids for one country's rules, keyed by logical key.
    fn country_rule_ids(&self, code: &str) -> Result<HashMap<String, RuleId>> {
        let firewall = self.firewall.as_ref().ok_or(EnforceError::NotStarted)?;
        let prefix = country_key_prefix(code);
        let filter = RuleFilter::new().with_key_prefix(
            RuleKey::try_from(prefix.as_str())
                .map_err(|error| EnforceError::InvalidOp(error.to_string()))?,
        );
        Ok(firewall
            .list_rules(&filter)?
            .into_iter()
            .map(|(id, _)| (id.key().as_str().to_owned(), id))
            .collect())
    }

    fn install_rules(&mut self, op: &EnforcementOp) -> Result<()> {
        let rules = apply_op(op)?;
        let firewall = self.firewall.as_mut().ok_or(EnforceError::NotStarted)?;
        let mut changes = Vec::new();

        for (key, rule) in rules {
            let previous = self.installed.get(&key).cloned();
            // Writing a rule again costs a native round trip even when nothing
            // changes: re-applying the DoH block's hundred rules took most of
            // a minute on Windows.
            if previous
                .as_ref()
                .is_some_and(|installed| is_installed_as(&installed.rule, &rule))
            {
                continue;
            }
            let result = match &previous {
                Some(installed) => firewall
                    .update_rule(&installed.id, rule.clone())
                    .map(|()| installed.id.clone()),
                None => firewall.add_rule(rule.clone()),
            };
            match result {
                Ok(id) => {
                    self.installed
                        .insert(key.clone(), InstalledRule { id, rule });
                    changes.push((key, previous));
                }
                Err(error) => {
                    for (changed_key, old) in changes.into_iter().rev() {
                        match old {
                            Some(old) => {
                                let _ = firewall.update_rule(&old.id, old.rule.clone());
                                self.installed.insert(changed_key, old);
                            }
                            None => {
                                if let Some(added) = self.installed.remove(&changed_key) {
                                    let _ = firewall.remove_rule(&added.id);
                                }
                            }
                        }
                    }
                    return Err(error.into());
                }
            }
        }

        Ok(())
    }

    fn remove_keys(&mut self, keys: &[String]) -> Result<()> {
        if keys.is_empty() {
            return Ok(());
        }

        let firewall = self.firewall.as_mut().ok_or(EnforceError::NotStarted)?;

        let mut removed: Vec<(String, InstalledRule)> = Vec::new();
        for key in keys {
            if let Some(installed) = self.installed.get(key).cloned() {
                if let Err(error) = firewall.remove_rule(&installed.id) {
                    for (removed_key, removed_rule) in removed {
                        if let Ok(id) = firewall.add_rule(removed_rule.rule.clone()) {
                            self.installed.insert(
                                removed_key,
                                InstalledRule {
                                    id,
                                    rule: removed_rule.rule,
                                },
                            );
                        }
                    }
                    return Err(error.into());
                }
                self.installed.remove(key);
                removed.push((key.clone(), installed));
            }
        }

        Ok(())
    }

    fn replace_doh_rules(&mut self, op: &EnforcementOp, new_keys: Vec<String>) -> Result<()> {
        let old_keys = self.doh_rule_keys.clone();
        let old_rules: Vec<_> = old_keys
            .iter()
            .filter_map(|key| {
                self.installed
                    .get(key)
                    .cloned()
                    .map(|rule| (key.clone(), rule))
            })
            .collect();

        self.install_rules(op)?;
        let stale: Vec<_> = old_keys
            .iter()
            .filter(|key| !new_keys.contains(key))
            .cloned()
            .collect();
        if let Err(error) = self.remove_keys(&stale) {
            let added: Vec<_> = new_keys
                .iter()
                .filter(|key| !old_keys.contains(key))
                .cloned()
                .collect();
            let _ = self.remove_keys(&added);

            if let Some(firewall) = self.firewall.as_mut() {
                for (key, old) in old_rules {
                    if let Some(current) = self.installed.get(&key).cloned() {
                        if firewall.update_rule(&current.id, old.rule.clone()).is_ok() {
                            self.installed.insert(
                                key,
                                InstalledRule {
                                    id: current.id,
                                    rule: old.rule,
                                },
                            );
                        }
                    } else if let Ok(id) = firewall.add_rule(old.rule.clone()) {
                        self.installed
                            .insert(key, InstalledRule { id, rule: old.rule });
                    }
                }
            }
            return Err(error);
        }

        self.doh_rule_keys = new_keys;
        Ok(())
    }
}

/// A filter dropped while started removes its rules, as memory mode used to.
/// `stop_keeping_rules` detaches the backend before cleanup, so even a cleanup
/// failure cannot make this remove rules meant to persist.
impl Drop for FirewFilter {
    fn drop(&mut self) {
        if self.firewall.is_some() {
            if let Err(error) = FirewallFilter::stop(self) {
                tracing::warn!(%error, "firewall rules could not be removed on drop");
            }
        }
    }
}

impl FirewFilter {
    /// Detaches the backend, runs cleanup, and closes it even if cleanup fails.
    ///
    /// Never reattach it on error: worker shutdown and Drop call ordinary
    /// `stop`, which would delete rules the caller asked to keep. Outside
    /// memory mode, closing it leaves the remaining rules intact; see
    /// [`open_backend`] for the one case that uses memory mode.
    fn close(&mut self, cleanup: impl FnOnce(&mut Firewall) -> Result<()>) -> Result<()> {
        let firewall = self.firewall.take();
        self.installed.clear();
        self.doh_rule_keys.clear();
        self.country_rule_keys.clear();

        if let Some(mut firewall) = firewall {
            let removed = cleanup(&mut firewall);
            let closed = firewall.close();
            removed?;
            closed?;
        }
        Ok(())
    }
}

/// Removes the rules that must not outlive Antiwire's resolver: the `DoH`
/// blocks.
///
/// They steer lookups onto the resolver. Once it stops and adapter DNS goes
/// back to its original servers, a `DoH` block left in place could cut off
/// the user's own encrypted DNS. Read from native state, so it also finds
/// rules a dead process installed.
fn remove_resolver_dependent_rules(firewall: &mut Firewall) -> Result<()> {
    let prefix = RuleKey::try_from(DOH_KEY_PREFIX)
        .map_err(|error| EnforceError::InvalidOp(error.to_string()))?;
    let rules = firewall.list_rules(&RuleFilter::new().with_key_prefix(prefix))?;
    let mut failure = None;
    for (id, _) in rules {
        if let Err(error) = firewall.remove_rule(&id) {
            failure.get_or_insert(error);
        }
    }
    failure.map_or(Ok(()), |error| Err(error.into()))
}

/// Opens the native backend. Returns it, and whether its rules go when this
/// process ends.
///
/// Memory mode makes `close` remove every managed rule, so a clean stop
/// could never leave rules in place for "persist rules offline"; `stop`
/// removes them explicitly instead. Antiwire installs no domain-backed rules,
/// the one feature that needs memory mode.
///
/// The exception is the WFP fallback on Windows. Without memory mode its
/// filters are persistent and survive a reboot; with it they belong to this
/// process's session and go when it dies, however it dies. So it uses memory
/// mode unless the rules are meant to stay. `INetFw`, tried first, keeps its
/// rules in the firewall policy either way, so it never needs memory mode.
#[cfg(windows)]
fn open_backend(
    keep_rules_offline: bool,
) -> std::result::Result<(Firewall, bool), firew_rs::Error> {
    use firew_rs::BackendPreference;

    let builder = Firewall::builder().name_prefix(MANAGER_PREFIX);
    match builder
        .clone()
        .prefer_backend(BackendPreference::InetFw)
        .memory_mode(false)
        .build()
    {
        Ok(firewall) => Ok((firewall, false)),
        Err(inetfw) => {
            tracing::warn!(error = %inetfw, "INetFw firewall backend unavailable; trying WFP");
            let memory_mode = !keep_rules_offline;
            let firewall = builder
                .prefer_backend(BackendPreference::Wfp)
                .memory_mode(memory_mode)
                .build()?;
            Ok((firewall, memory_mode))
        }
    }
}

/// Opens the native backend. Returns it, and whether its rules go when this
/// process ends, which they never do here. See the Windows version.
#[cfg(not(windows))]
fn open_backend(
    keep_rules_offline: bool,
) -> std::result::Result<(Firewall, bool), firew_rs::Error> {
    let _ = keep_rules_offline;
    let firewall = Firewall::builder()
        .name_prefix(MANAGER_PREFIX)
        .memory_mode(false)
        .build()?;
    Ok((firewall, false))
}

impl FirewallFilter for FirewFilter {
    fn start(&mut self) -> Result<()> {
        self.start_with_persistence(false)
    }

    fn start_with_persistence(&mut self, keep_rules_offline: bool) -> Result<()> {
        if self.firewall.is_some() {
            return Err(EnforceError::AlreadyStarted);
        }

        match open_backend(keep_rules_offline) {
            Ok((firewall, rules_end_with_process)) => {
                self.rules_end_with_process = rules_end_with_process;
                // The override exists so live tests can exercise the multi-part
                // path without generating tens of thousands of networks.
                let native = firewall.max_address_set_entries();
                let limit = std::env::var("FIREW_MAX_ADDRESS_SET_ENTRIES")
                    .ok()
                    .and_then(|raw| raw.parse::<usize>().ok())
                    .filter(|value| *value > 0)
                    .map_or(native, |value| Some(native.map_or(value, |n| n.min(value))));
                self.caps = BackendCaps {
                    max_address_set_entries: limit,
                };
                self.firewall = Some(firewall);
            }
            Err(error) => {
                return Err(error.into());
            }
        }

        Ok(())
    }

    fn stop(&mut self) -> Result<()> {
        if let Some(firewall) = self.firewall.as_mut() {
            firewall.remove_all_rules()?;
        }
        self.close(|_| Ok(()))
    }

    fn stop_keeping_rules(&mut self) -> Result<()> {
        if self.firewall.is_some() && self.rules_end_with_process {
            tracing::warn!(
                "the WFP firewall backend was opened before rules were set to persist \
                 offline, so its rules end with this process; they persist from the next start"
            );
        }
        self.close(remove_resolver_dependent_rules)
    }

    fn is_enforcing(&self) -> bool {
        self.firewall.is_some()
    }

    fn apply(&mut self, op: EnforcementOp) -> Result<()> {
        match &op {
            EnforcementOp::RemoveIpRule { .. }
            | EnforcementOp::RemoveAppRule { .. }
            | EnforcementOp::RemoveDnsRule { .. } => {
                let keys = op_rule_keys(&op)?;
                self.remove_keys(&keys)?;
                return Ok(());
            }
            EnforcementOp::RemoveDohBlocks => {
                let keys = self.doh_rule_keys.clone();
                self.remove_keys(&keys)?;
                self.doh_rule_keys.clear();
                return Ok(());
            }
            EnforcementOp::RemoveCountryBlock { rule_id, .. } => {
                // Tracking is dropped only for chunks that are actually gone, so a
                // failed removal can be retried instead of reporting success.
                let keys = self
                    .country_rule_keys
                    .get(rule_id)
                    .cloned()
                    .unwrap_or_default();
                let (remaining, result) = self.delete_country_keys(keys);
                if remaining.is_empty() {
                    self.country_rule_keys.remove(rule_id);
                } else {
                    self.country_rule_keys.insert(*rule_id, remaining);
                }
                return result;
            }
            _ => {}
        }

        if !self.is_enforcing() {
            return Err(EnforceError::NotStarted);
        }

        if matches!(&op, EnforcementOp::AddDohBlock { .. }) {
            let keys = op_rule_keys(&op)?;
            return self.replace_doh_rules(&op, keys);
        }
        if let EnforcementOp::AddCountryBlock {
            rule_id,
            code,
            networks,
            verdict,
            direction,
        } = &op
        {
            return self.install_country_block(*rule_id, code, networks, *verdict, *direction);
        }
        self.install_rules(&op)?;
        Ok(())
    }

    fn remove_all_managed(&mut self) -> Result<()> {
        let firewall = self.firewall.as_mut().ok_or(EnforceError::NotStarted)?;
        firewall.remove_all_rules()?;
        self.installed.clear();
        self.doh_rule_keys.clear();
        self.country_rule_keys.clear();
        Ok(())
    }

    fn take_drift(&mut self) -> Result<Vec<String>> {
        match self.firewall.as_mut() {
            Some(firewall) => Ok(firewall.take_drift()?),
            None => Ok(Vec::new()),
        }
    }
}

/// Whether the rule tracked as `installed` is already what `wanted` asks for,
/// so writing it again would change nothing.
///
/// [`Rule`]'s equality covers what traffic a rule matches. The label and the
/// address set mode change the native rows too, so they are compared as well.
fn is_installed_as(installed: &Rule, wanted: &Rule) -> bool {
    installed == wanted
        && installed.label() == wanted.label()
        && installed.address_set_mode() == wanted.address_set_mode()
}

/// Deletes every rule in the Antiwire firewall namespace.
///
/// A fresh backend has no in-memory copy of rules installed by a dead process,
/// so each one rebuilds Antiwire's rules from native state before removing
/// them: Windows `INetFw` from the system store, macOS by rewriting the managed
/// anchors empty, and Linux nftables and iptables from the kernel listing.
///
/// Only Antiwire's namespace is removed. The nftables `firew_rs` table is
/// shared with any other firew manager on the host, so it is never deleted.
///
/// # Errors
///
/// Fails when the firewall cannot be opened, the native rules cannot be read,
/// or any of them could not be removed.
pub(crate) fn purge_ephemeral_rules() -> Result<()> {
    let mut firewall = Firewall::builder()
        .name_prefix(MANAGER_PREFIX)
        .memory_mode(false)
        .build()?;
    let removed = firewall.remove_all_rules();
    let closed = firewall.close();
    removed?;
    closed?;
    Ok(())
}

/// Deletes the rules a dead daemon left that must not outlive its resolver,
/// keeping the rest. For "persist rules offline"; see
/// [`remove_resolver_dependent_rules`].
///
/// # Errors
///
/// Fails when the firewall cannot be opened, the native rules cannot be read,
/// or any of them could not be removed.
pub(crate) fn purge_resolver_dependent_rules() -> Result<()> {
    let mut firewall = Firewall::builder()
        .name_prefix(MANAGER_PREFIX)
        .memory_mode(false)
        .build()?;
    let removed = remove_resolver_dependent_rules(&mut firewall);
    let closed = firewall.close();
    removed?;
    closed?;
    Ok(())
}

#[cfg(test)]
mod shutdown_tests;

#[cfg(test)]
mod tests {
    use super::shutdown_tests::NativeRules;
    use super::*;
    use antiwire_policy::{RuleDirection, Verdict};
    use firew_rs::{Action, Direction};

    #[test]
    fn only_a_rule_that_differs_from_the_installed_one_is_written_again() {
        let block = || Rule::builder("dhtest", Action::Block, Direction::Outbound);
        let net = |address: &str| address.parse::<ipnet::IpNet>().expect("network");
        let build = |rule: firew_rs::RuleBuilder| rule.build().expect("rule");

        let installed = build(block().remote_address(net("192.0.2.1/32")));
        let same = build(block().remote_address(net("192.0.2.1/32")));
        assert!(is_installed_as(&installed, &same));

        let other_traffic = build(block().remote_address(net("192.0.2.2/32")));
        let other_label = build(block().remote_address(net("192.0.2.1/32")).label("renamed"));
        let other_rows = build(block().remote_address_set([net("192.0.2.1/32")]));
        // The library's own comparison does not see the last two.
        assert_eq!(installed, other_label);
        assert_eq!(installed, other_rows);
        for changed in [other_traffic, other_label, other_rows] {
            assert!(!is_installed_as(&installed, &changed), "{changed:?}");
        }
    }

    /// The `DoH` block is applied again whenever the settings that shape it are
    /// saved, mostly with the addresses it already has.
    #[test]
    #[ignore = "requires administrator and native firewall access"]
    fn live_reapplied_doh_block_keeps_what_is_installed_and_changes_the_rest() {
        let doh = |ips: &[&str]| EnforcementOp::AddDohBlock {
            doh_ips: ips.iter().map(|&ip| ip.to_owned()).collect(),
            port: 443,
        };
        let (rules, mut filter) = NativeRules::seed();
        let seeded = rules.keys();

        filter.apply(doh(&["192.0.2.2"])).expect("same block");
        assert_eq!(rules.keys(), seeded);

        filter
            .apply(doh(&["192.0.2.2", "192.0.2.3"]))
            .expect("wider block");
        assert_eq!(rules.keys().len(), seeded.len() + 2);
        assert_eq!(filter.doh_rule_keys.len(), 4);

        filter.apply(doh(&["192.0.2.3"])).expect("moved block");
        assert_eq!(rules.keys().len(), seeded.len());
        assert_ne!(rules.keys(), seeded);
        assert!(filter
            .doh_rule_keys
            .iter()
            .all(|key| filter.installed.contains_key(key)));

        filter
            .apply(EnforcementOp::RemoveDohBlocks)
            .expect("remove");
        assert_eq!(rules.keys().len(), seeded.len() - 2);

        // A hundred rules, as the daemon installs: the second apply must not
        // write them again.
        let addresses: Vec<String> = (1..=50).map(|host| format!("198.51.100.{host}")).collect();
        let hundred = EnforcementOp::AddDohBlock {
            doh_ips: addresses,
            port: 443,
        };
        let started = std::time::Instant::now();
        filter.apply(hundred.clone()).expect("first apply");
        let first = started.elapsed();
        let started = std::time::Instant::now();
        filter.apply(hundred).expect("second apply");
        let second = started.elapsed();
        println!("100 DoH rules: first apply {first:?}, same again {second:?}");
        assert_eq!(rules.keys().len(), seeded.len() - 2 + 100);
        assert!(second < first, "an unchanged block was written again");
    }

    /// Held by every test that opens the real firewall. All of them share the
    /// Antiwire rule namespace, and closing one filter removes every rule in it,
    /// including rules another test is still using.
    static SYSTEM_FIREWALL: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn system_firewall() -> std::sync::MutexGuard<'static, ()> {
        SYSTEM_FIREWALL
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    #[test]
    fn start_stop_lifecycle() {
        let _firewall = system_firewall();
        let mut filter = FirewFilter::new();
        assert!(!filter.is_enforcing());

        if filter.start().is_ok() {
            assert!(filter.is_enforcing());
            if let Err(EnforceError::Firewall(ref error)) = filter.stop() {
                if error.kind() == ErrorKind::PermissionDenied {
                    return;
                }
                panic!("stop: {error}");
            }
            assert!(!filter.is_enforcing());
        }
    }

    #[test]
    fn installs_app_rules() {
        let _firewall = system_firewall();
        let mut filter = FirewFilter::new();
        if filter.start().is_err() {
            return;
        }

        if filter
            .apply(EnforcementOp::AddAppRule {
                rule_id: 5,
                app_path: r"C:\Windows\System32\notepad.exe".to_owned(),
                verdict: Verdict::Block,
                direction: RuleDirection::Outbound,
            })
            .is_err()
        {
            return;
        }

        assert!(filter.installed.contains_key("ar00005"));
    }
}
