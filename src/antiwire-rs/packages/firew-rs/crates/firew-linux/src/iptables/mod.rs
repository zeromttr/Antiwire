//! iptables backend via the `iptables` crate (`iptables` binary).

#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

use std::collections::{BTreeMap, BTreeSet, HashMap};

use firew_core::{AddressSetMode, Error, ErrorKind, PortRange, Protocol, Rule, RuleKey};
use firew_sys::{
    unsupported_matcher, Backend, BackendConfig, DriftTracker, HealthSnapshot, NativeRuleRef,
    RuleFilter,
};

mod ops;
mod parse;
mod rows;
#[cfg(test)]
mod tests;

use ops::IptablesOps;
pub(crate) use parse::parse_protocol;
use parse::EnumeratedIptables;
use parse::{parse_native_row, reconstruct_record, try_extract_key_from_spec, ParsedRow};

/// iptables backend using the `iptables` command wrapper.
pub struct IptablesBackend {
    config: BackendConfig,
    in_chain: String,
    out_chain: String,
    rules: HashMap<RuleKey, IptablesRecord>,
    broken_records: HashMap<RuleKey, BrokenIptablesRecord>,
    orphan_rows: Vec<(String, String)>,
    drift: DriftTracker,
    /// Whether the `ipset` binary is usable; probed once at open.
    ipset_available: bool,
}

#[derive(Clone, Debug)]
pub(crate) struct IptablesRecord {
    pub(crate) rule: Rule,
    pub(crate) rows: Vec<(String, String)>,
    pub(crate) set_name: Option<String>,
}

#[derive(Clone, Debug, Default)]
pub(crate) struct BrokenIptablesRecord {
    pub(crate) rows: Vec<(String, String)>,
    pub(crate) set_name: Option<String>,
}

#[derive(Clone)]
struct RuleVariant<'a> {
    inbound: bool,
    /// When set, remote addresses live in this ipset instead of `-s`/`-d`.
    remote_set: Option<&'a str>,
    remote_address: Option<&'a ipnet::IpNet>,
    local_address: Option<&'a ipnet::IpNet>,
    remote_port: Option<&'a PortRange>,
    local_port: Option<&'a PortRange>,
    marker: String,
}

impl IptablesBackend {
    pub fn open(config: &BackendConfig) -> Result<Self, Error> {
        let namespace = config.managed_namespace();
        let mut backend = Self {
            config: config.clone(),
            in_chain: format!("FWI_{}", namespace.as_str()),
            out_chain: format!("FWO_{}", namespace.as_str()),
            rules: HashMap::new(),
            broken_records: HashMap::new(),
            orphan_rows: Vec::new(),
            drift: DriftTracker::new(),
            ipset_available: crate::ipset::is_available(),
        };
        let ipt = Self::ipt()?;
        Self::ensure_chain_with(&ipt, &backend.in_chain, "INPUT")?;
        Self::ensure_chain_with(&ipt, &backend.out_chain, "OUTPUT")?;
        backend.refresh_from_native()?;
        Ok(backend)
    }

    fn refresh_from_native(&mut self) -> Result<(), Error> {
        let ipt = Self::ipt()?;
        Self::ensure_chain_with(&ipt, &self.in_chain, "INPUT")?;
        Self::ensure_chain_with(&ipt, &self.out_chain, "OUTPUT")?;
        let enumerated = self.enumerate_with(&ipt, crate::ipset::list_entries_opt)?;
        self.apply_enumerated(enumerated);
        Ok(())
    }

    /// Reads this namespace's rows and backing sets from the kernel now.
    fn enumerate_live(&self) -> Result<EnumeratedIptables, Error> {
        self.enumerate_with(&Self::ipt()?, crate::ipset::list_entries_opt)
    }

    fn apply_enumerated(&mut self, enumerated: EnumeratedIptables) {
        self.rules = enumerated.rules;
        self.broken_records = enumerated.broken_records;
        self.orphan_rows = enumerated.orphan_rows;

        self.drift.observe(enumerated.drifted);
    }

    pub(crate) fn enumerate_with<F>(
        &self,
        ipt: &dyn IptablesOps,
        load_set: F,
    ) -> Result<EnumeratedIptables, Error>
    where
        F: Fn(&str) -> Result<Option<Vec<ipnet::IpNet>>, Error>,
    {
        let namespace = self.config.managed_namespace();
        let mut grouped: BTreeMap<RuleKey, Vec<ParsedRow>> = BTreeMap::new();
        let mut broken_records: HashMap<RuleKey, BrokenIptablesRecord> = HashMap::new();
        let mut orphan_rows: Vec<(String, String)> = Vec::new();
        let mut drifted: Vec<String> = Vec::new();

        for (chain, inbound) in [(&self.in_chain, true), (&self.out_chain, false)] {
            // A chain released by `remove_all_managed` holds no rows until a rule is added.
            if !ipt.chain_exists("filter", chain)? {
                continue;
            }
            for line in ipt.list("filter", chain)? {
                let prefix = format!("-A {chain} ");
                let Some(spec) = line.strip_prefix(&prefix) else {
                    continue;
                };
                if let Ok(row) = parse_native_row(&line, chain, inbound, &namespace) {
                    grouped.entry(row.marker.key.clone()).or_default().push(row);
                } else {
                    if let Some(key) = try_extract_key_from_spec(spec, &namespace) {
                        broken_records
                            .entry(key)
                            .or_default()
                            .rows
                            .push((chain.clone(), spec.to_owned()));
                    } else {
                        orphan_rows.push((chain.clone(), spec.to_owned()));
                    }
                    drifted.push(spec.to_owned());
                }
            }
        }

        let mut rules = HashMap::with_capacity(grouped.len());
        for (key, rows) in grouped {
            let reconstructed = match reconstruct_record(key.clone(), rows.clone(), &load_set) {
                // Only a row set that is itself inconsistent is quarantined. A
                // failure to read native state, such as `ipset list` failing,
                // says nothing about the rule, which may still be enforcing.
                Err(error) if error.kind() != ErrorKind::CorruptNativeState => return Err(error),
                other => other,
            };
            if let Ok((_, record)) = reconstructed {
                if broken_records.contains_key(&key) {
                    // Another row for this key failed to parse earlier; quarantine the whole key.
                    let entry = broken_records.entry(key.clone()).or_default();
                    entry.rows.extend(record.rows);
                    if entry.set_name.is_none() {
                        entry.set_name = record.set_name;
                    }
                    drifted.push(key.to_string());
                } else {
                    rules.insert(key, record);
                }
            } else {
                let entry = broken_records.entry(key.clone()).or_default();
                for row in rows {
                    if entry.set_name.is_none() && row.remote_set.is_some() {
                        entry.set_name = row.remote_set;
                    }
                    entry.rows.push((row.chain, row.spec));
                }
                drifted.push(key.to_string());
            }
        }

        Ok(EnumeratedIptables {
            rules,
            broken_records,
            orphan_rows,
            drifted,
        })
    }

    /// Deletes the rows and set of a key whose native state is broken.
    ///
    /// A broken row left behind keeps deciding traffic ahead of anything
    /// installed after it in this first-match chain, so a failed delete is an
    /// error rather than something to reinstall over.
    fn cleanup_broken_key(&mut self, ipt: &dyn IptablesOps, key: &RuleKey) -> Result<(), Error> {
        let Some(broken) = self.broken_records.remove(key) else {
            return Ok(());
        };
        for (chain, spec) in &broken.rows {
            ipt.delete("filter", chain, spec)
                .map_err(|source| source.with_logical_key(key))?;
        }
        if let Some(set_name) = &broken.set_name {
            crate::ipset::destroy(set_name)?;
        }
        Ok(())
    }

    /// This namespace's chain for one direction.
    fn chain(&self, inbound: bool) -> &str {
        if inbound {
            &self.in_chain
        } else {
            &self.out_chain
        }
    }

    fn add_rule_inner(&mut self, rule: &Rule) -> Result<NativeRuleRef, Error> {
        self.refresh_from_native()?;
        firew_sys::reject_unresolved_domains(rule)?;
        if rule.application_path().is_some() {
            return Err(Error::new(
                ErrorKind::UnsupportedMatcher,
                "application rules not supported on iptables backend",
            )
            .with_logical_key(rule.logical_key()));
        }

        let key = rule.logical_key().clone();
        if self.rules.contains_key(&key) {
            return Err(firew_sys::duplicate_rule(key));
        }

        let ipt = Self::ipt()?;
        self.cleanup_broken_key(&ipt, &key)?;

        let set_name = if rule.address_set_mode() == AddressSetMode::Set {
            let name = crate::ipset::set_name_for(&self.config.managed_namespace(), &key);
            crate::ipset::create_and_fill(&name, rule.remote_addresses())?;
            Some(name)
        } else {
            None
        };

        let rows = match &set_name {
            Some(name) => self.build_set_rule_rows(rule, name)?,
            None => self.build_rule_rows(rule)?,
        };
        for (index, (chain, spec)) in rows.iter().enumerate() {
            if let Err(source) = ipt.append("filter", chain, spec) {
                for (added_chain, added_spec) in &rows[..index] {
                    let _ = ipt.delete("filter", added_chain, added_spec);
                }
                if let Some(name) = &set_name {
                    let _ = crate::ipset::destroy(name);
                }
                return Err(Error::new(
                    ErrorKind::PartialMutation,
                    format!("added {index} of {} iptables rows", rows.len()),
                )
                .with_logical_key(&key)
                .with_source(source));
            }
        }

        let handles: Vec<String> = rows
            .iter()
            .map(|(chain, spec)| format!("{chain}:{spec}"))
            .collect();
        self.rules.insert(
            key.clone(),
            IptablesRecord {
                rule: rule.clone(),
                rows,
                set_name,
            },
        );
        Ok(NativeRuleRef::from_handles("iptables", handles, key))
    }

    fn update_rule_inner(
        &mut self,
        id: &NativeRuleRef,
        rule: &Rule,
    ) -> Result<NativeRuleRef, Error> {
        self.refresh_from_native()?;
        let key = id.logical_key().clone();
        if &key != rule.logical_key() {
            return Err(firew_sys::key_mismatch(rule));
        }
        let old_record = self
            .rules
            .get(&key)
            .cloned()
            .ok_or_else(|| firew_sys::rule_not_found(&key))?;

        let new_set_name = if rule.address_set_mode() == AddressSetMode::Set {
            let name = crate::ipset::set_name_for(&self.config.managed_namespace(), &key);
            crate::ipset::create_and_fill(&name, rule.remote_addresses())?;
            Some(name)
        } else {
            None
        };

        let new_rows = match &new_set_name {
            Some(name) => self.build_set_rule_rows(rule, name)?,
            None => self.build_rule_rows(rule)?,
        };

        let ipt = Self::ipt()?;
        let mut added_rows: Vec<(String, String)> = Vec::new();
        for (chain, spec) in &new_rows {
            if old_record
                .rows
                .iter()
                .any(|(old_c, old_s)| old_c == chain && old_s == spec)
            {
                continue;
            }
            if let Err(source) = ipt.append("filter", chain, spec) {
                for (added_chain, added_spec) in &added_rows {
                    let _ = ipt.delete("filter", added_chain, added_spec);
                }
                if old_record.set_name.is_some() {
                    let _ = crate::ipset::create_and_fill(
                        old_record.set_name.as_deref().unwrap_or_default(),
                        old_record.rule.remote_addresses(),
                    );
                } else if let Some(name) = &new_set_name {
                    let _ = crate::ipset::destroy(name);
                }
                return Err(source.with_logical_key(&key));
            }
            added_rows.push((chain.clone(), spec.clone()));
        }

        // Remove obsolete old rows only after all new rows are active. The new
        // rows are appended, so an old row left behind sits ahead of them in a
        // first-match chain and keeps deciding the traffic: an allow turned
        // into a block would still accept. That is a failed update, not a
        // success.
        let mut stale_rows = 0usize;
        let mut first_failure = None;
        for (old_chain, old_spec) in &old_record.rows {
            if !new_rows
                .iter()
                .any(|(new_c, new_s)| new_c == old_chain && new_s == old_spec)
            {
                if let Err(source) = ipt.delete("filter", old_chain, old_spec) {
                    stale_rows += 1;
                    first_failure.get_or_insert(source);
                }
            }
        }
        if let Some(source) = first_failure {
            // Native state now holds both generations; the next operation
            // re-reads it and quarantines the key.
            self.rules.remove(&key);
            return Err(Error::new(
                ErrorKind::PartialMutation,
                format!(
                    "installed the replacement but {stale_rows} obsolete iptables rows are still active ahead of it"
                ),
            )
            .with_logical_key(&key)
            .with_source(source));
        }
        if let Some(old_set) = &old_record.set_name {
            if new_set_name.as_ref() != Some(old_set) {
                let _ = crate::ipset::destroy(old_set);
            }
        }

        let handles: Vec<String> = new_rows
            .iter()
            .map(|(chain, spec)| format!("{chain}:{spec}"))
            .collect();
        self.rules.insert(
            key.clone(),
            IptablesRecord {
                rule: rule.clone(),
                rows: new_rows,
                set_name: new_set_name,
            },
        );
        Ok(NativeRuleRef::from_handles("iptables", handles, key))
    }

    fn remove_rule_inner(&mut self, id: &NativeRuleRef) -> Result<(), Error> {
        self.refresh_from_native()?;
        let key = id.logical_key().clone();
        let record = self.rules.get(&key).cloned();
        let broken = self.broken_records.get(&key).cloned();
        if record.is_none() && broken.is_none() {
            return Err(firew_sys::rule_not_found(&key));
        }

        let ipt = Self::ipt()?;
        if let Some(record) = record {
            for (index, (chain, spec)) in record.rows.iter().enumerate() {
                if let Err(source) = ipt.delete("filter", chain, spec) {
                    return Err(Error::new(
                        ErrorKind::PartialMutation,
                        format!("removed {index} of {} iptables rows", record.rows.len()),
                    )
                    .with_logical_key(&key)
                    .with_source(source));
                }
            }
            if let Some(name) = &record.set_name {
                crate::ipset::destroy(name)?;
            }
            self.rules.remove(&key);
        }
        if broken.is_some() {
            self.cleanup_broken_key(&ipt, &key)?;
        }
        Ok(())
    }
}

impl Backend for IptablesBackend {
    fn open(config: &BackendConfig) -> Result<Self, Error> {
        Self::open(config)
    }

    fn name(&self) -> &'static str {
        "iptables"
    }

    fn supports_transactions(&self) -> bool {
        false
    }

    fn supports_ipv6(&self) -> bool {
        false
    }

    fn max_address_set_entries(&self) -> Option<usize> {
        self.ipset_available
            .then_some(crate::ipset::MAX_SET_ENTRIES)
    }

    fn validate_rule(&self, rule: &Rule) -> Result<(), Error> {
        firew_sys::validate_native_rule(self, "iptables", rule)?;
        firew_sys::reject_application_matchers("iptables", "iptables", rule)?;
        if rule
            .remote_addresses()
            .iter()
            .chain(rule.local_addresses())
            .any(|address| address.addr().is_ipv6())
            || rule.protocol() == Protocol::IcmpV6
        {
            return unsupported(rule, "IPv6 matchers");
        }
        Ok(())
    }

    fn add_rule(&mut self, rule: &Rule) -> Result<NativeRuleRef, Error> {
        self.validate_rule(rule)?;
        self.add_rule_inner(rule)
    }

    fn update_rule(&mut self, id: &NativeRuleRef, rule: &Rule) -> Result<NativeRuleRef, Error> {
        self.validate_rule(rule)?;
        self.update_rule_inner(id, rule)
    }

    fn remove_rule(&mut self, id: &NativeRuleRef) -> Result<(), Error> {
        self.remove_rule_inner(id)
    }

    fn get_rule(&self, id: &NativeRuleRef) -> Result<Rule, Error> {
        let enumerated = self.enumerate_live()?;
        enumerated
            .rules
            .get(id.logical_key())
            .map(|record| record.rule.clone())
            .ok_or_else(|| firew_sys::rule_not_found(id.logical_key()))
    }

    fn list_rules(&self, filter: &RuleFilter) -> Result<Vec<(NativeRuleRef, Rule)>, Error> {
        let enumerated = self.enumerate_live()?;
        let mut out = Vec::new();
        for (key, record) in &enumerated.rules {
            let rule = &record.rule;
            if !filter.matches(key, rule) {
                continue;
            }
            let handles: Vec<String> = record
                .rows
                .iter()
                .map(|(chain, spec)| format!("{chain}:{spec}"))
                .collect();
            out.push((
                NativeRuleRef::from_handles("iptables", handles, key.clone()),
                rule.clone(),
            ));
        }
        Ok(out)
    }

    fn begin_transaction(&mut self) -> Result<(), Error> {
        Ok(())
    }

    fn commit_transaction(&mut self) -> Result<(), Error> {
        Ok(())
    }

    fn abort_transaction(&mut self) -> Result<(), Error> {
        Ok(())
    }

    fn health_probe(&self, expected_keys: &[RuleKey]) -> Result<HealthSnapshot, Error> {
        let ipt = Self::ipt()?;
        if !Self::chains_attached_with(&ipt, &self.in_chain, &self.out_chain)? {
            return Ok(HealthSnapshot::from_present(
                std::iter::empty(),
                expected_keys,
            ));
        }
        let enumerated = self.enumerate_with(&ipt, crate::ipset::list_entries_opt)?;
        Ok(HealthSnapshot::from_present(
            enumerated.rules.keys(),
            expected_keys,
        ))
    }

    fn remove_all_managed(&mut self) -> Result<(), Error> {
        self.refresh_from_native()?;
        let ipt = Self::ipt()?;

        // Remove as much as possible, then report the first failure so a
        // caller never mistakes a partial cleanup for a complete one.
        let mut first_error = None;
        let mut note = |result: Result<(), Error>| {
            if let Err(error) = result {
                first_error.get_or_insert(error);
            }
        };
        let mut all_sets = BTreeSet::new();
        let rows = self
            .rules
            .values()
            .map(|record| (&record.rows, &record.set_name))
            .chain(
                self.broken_records
                    .values()
                    .map(|broken| (&broken.rows, &broken.set_name)),
            );
        for (rows, set_name) in rows {
            for (chain, spec) in rows {
                note(ipt.delete("filter", chain, spec));
            }
            if let Some(set_name) = set_name {
                all_sets.insert(set_name.clone());
            }
        }
        for (chain, spec) in &self.orphan_rows {
            note(ipt.delete("filter", chain, spec));
        }
        for set_name in all_sets {
            note(crate::ipset::destroy(&set_name));
        }
        if let Some(error) = first_error {
            return Err(error);
        }

        self.rules.clear();
        self.broken_records.clear();
        self.orphan_rows.clear();
        self.drift.clear();
        Self::release_chain_with(&ipt, &self.in_chain, "INPUT");
        Self::release_chain_with(&ipt, &self.out_chain, "OUTPUT");
        Ok(())
    }

    fn take_drift(&mut self) -> Result<Vec<String>, Error> {
        self.refresh_from_native()?;
        Ok(self.drift.take())
    }

    fn incomplete_keys(&self) -> Result<Vec<RuleKey>, Error> {
        Ok(self.enumerate_live()?.broken_records.into_keys().collect())
    }
}

fn unsupported(rule: &Rule, field: &str) -> Result<(), Error> {
    Err(unsupported_matcher("iptables", "iptables", rule, field))
}
