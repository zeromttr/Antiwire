//! `INetFw` COM backend (dedicated worker thread).

use std::collections::{BTreeMap, BTreeSet, HashMap};

use firew_core::{AddressSetMode, Direction, Error, ErrorKind, Rule, RuleKey};
use firew_sys::{
    complete_parts, split_directions, Backend, BackendConfig, DriftTracker, HealthSnapshot,
    NativeRuleRef, PartMarkers, RuleFilter,
};

use crate::naming::{native_display_name, native_group_name};
use crate::sys::{needs_set_mode, ComInetFwSession, InetFwNativeRow};
use crate::validation::{refuse_reject, validate_application_path};
use crate::worker::{forward_to_worker, NativeWorker, WorkerClient};

struct InetFwWorker {
    config: BackendConfig,
    session: ComInetFwSession,
    cache: HashMap<RuleKey, Rule>,
    native_names: HashMap<RuleKey, Vec<String>>,
    drift: DriftTracker,
    /// Native rule names of drifted or incomplete rules indexed by their logical key.
    drifted_by_key: HashMap<RuleKey, Vec<String>>,
}

struct ReconstructedRules {
    rules: HashMap<RuleKey, Rule>,
    names: HashMap<RuleKey, Vec<String>>,
    incomplete_by_key: HashMap<RuleKey, Vec<String>>,
}

impl InetFwWorker {
    fn open(config: BackendConfig) -> Result<Self, Error> {
        let session = ComInetFwSession::open()?;
        let mut worker = Self {
            config,
            session,
            cache: HashMap::new(),
            native_names: HashMap::new(),
            drift: DriftTracker::new(),
            drifted_by_key: HashMap::new(),
        };
        worker.refresh_from_native()?;
        Ok(worker)
    }

    fn native_group(&self) -> String {
        native_group_name(&self.config.managed_namespace())
    }

    fn refresh_from_native(&mut self) -> Result<(), Error> {
        let namespace = self.config.managed_namespace();
        let enumerated = self.session.enumerate(&namespace, &self.native_group())?;
        let reconstructed = reconstruct_rows(enumerated.rows);
        self.cache = reconstructed.rules;
        self.native_names = reconstructed.names;

        let mut drifted_by_key = enumerated.drifted_by_key;
        for (key, names) in reconstructed.incomplete_by_key {
            drifted_by_key.entry(key).or_default().extend(names);
        }

        self.drift.observe(
            enumerated
                .drifted
                .into_iter()
                .chain(drifted_by_key.values().flatten().cloned()),
        );
        self.drifted_by_key = drifted_by_key;
        Ok(())
    }

    /// The native rows `rule` expands to, one per direction.
    fn parts_for(&self, rule: &Rule) -> Result<Vec<RulePart>, Error> {
        let key = rule.logical_key();
        let directions = split_directions(rule.direction());
        let namespace = self.config.managed_namespace();
        let mut markers = PartMarkers::new("INetFw", key, &namespace, directions.len())?;
        directions
            .iter()
            .map(|&direction| {
                let name =
                    native_display_name(&namespace, key, markers.next_part(), markers.total());
                Ok(RulePart {
                    direction,
                    marker: markers.encode_next()?,
                    name,
                })
            })
            .collect()
    }

    fn install_rule_parts(&mut self, rule: &Rule) -> Result<Vec<String>, Error> {
        let key = rule.logical_key();
        let native_group = self.native_group();
        let mut names: Vec<String> = Vec::new();
        for part in self.parts_for(rule)? {
            let fw_rule = ComInetFwSession::build_rule(
                rule,
                part.direction,
                &part.name,
                &part.marker,
                &native_group,
            )?;
            if let Err(error) = self.session.add_rule(&fw_rule, key) {
                for added_name in &names {
                    let _ = self.session.remove_rule(added_name, &native_group, key);
                }
                let _ = self.refresh_from_native();
                return Err(error);
            }
            names.push(part.name);
        }
        Ok(names)
    }

    /// Undoes a failed update: removes the parts it added and writes the
    /// previous rule back over every part it was rewriting in place.
    ///
    /// COM commits each property setter as it runs, so a part whose rewrite
    /// failed halfway may already carry the new action or direction. It is
    /// restored like the parts that were rewritten completely.
    fn roll_back_update(
        &mut self,
        previous_rule: &Rule,
        previous_names: &[String],
        new_names: &[String],
        touched_in_place: bool,
    ) -> Result<(), Error> {
        let key = previous_rule.logical_key();
        let native_group = self.native_group();
        let mut first_failure = None;
        for added in new_names {
            if !previous_names.contains(added) {
                if let Err(error) = self.session.remove_rule(added, &native_group, key) {
                    first_failure.get_or_insert(error);
                }
            }
        }
        if touched_in_place {
            for part in self.parts_for(previous_rule)? {
                if let Err(error) = self.session.upsert_rule(
                    previous_rule,
                    part.direction,
                    &part.name,
                    &part.marker,
                    &native_group,
                ) {
                    first_failure.get_or_insert(error);
                }
            }
        }
        let _ = self.refresh_from_native();
        first_failure.map_or(Ok(()), Err)
    }

    /// Removes the previous parts the replacement no longer has (e.g. Both to
    /// one direction). A part left behind keeps enforcing the old rule in its
    /// direction, so a failed removal fails the update instead of reporting
    /// success.
    fn remove_obsolete_parts(
        &mut self,
        key: &RuleKey,
        previous_names: &[String],
        new_names: &[String],
    ) -> Result<(), Error> {
        let native_group = self.native_group();
        let mut stale_parts = 0usize;
        let mut first_failure = None;
        for old_name in previous_names {
            if new_names.contains(old_name) {
                continue;
            }
            if let Err(source) = self.session.remove_rule(old_name, &native_group, key) {
                stale_parts += 1;
                first_failure.get_or_insert(source);
            }
        }
        let Some(source) = first_failure else {
            return Ok(());
        };
        // Native state now mixes both versions; re-read it so the key is
        // quarantined instead of cached as the replacement.
        let _ = self.refresh_from_native();
        Err(Error::new(
            ErrorKind::PartialMutation,
            format!("installed the replacement but {stale_parts} obsolete INetFw rows are still enforcing"),
        )
        .with_logical_key(key)
        .with_source(source))
    }
}

/// One native row of a logical rule.
struct RulePart {
    direction: Direction,
    marker: String,
    name: String,
}

impl NativeWorker for InetFwWorker {
    fn add_rule(&mut self, rule: &Rule) -> Result<NativeRuleRef, Error> {
        self.refresh_from_native()?;
        let key = rule.logical_key().clone();
        if self.cache.contains_key(&key) {
            return Err(firew_sys::duplicate_rule(key));
        }

        // If this key had broken/disabled drifted remnants, clean them up so
        // reconciliation or health repair can reinstall a healthy rule.
        let native_group = self.native_group();
        if let Some(drifted_names) = self.drifted_by_key.remove(&key) {
            for name in &drifted_names {
                // A remnant left behind keeps enforcing next to the new rule.
                self.session.remove_rule(name, &native_group, &key)?;
                self.drift.resolve(name);
            }
        }

        let names = self.install_rule_parts(rule)?;
        self.cache.insert(key.clone(), rule.clone());
        self.native_names.insert(key.clone(), names.clone());
        Ok(NativeRuleRef::from_handles("inetfw", names, key))
    }

    fn update_rule(&mut self, id: &NativeRuleRef, rule: &Rule) -> Result<NativeRuleRef, Error> {
        self.refresh_from_native()?;
        let key = id.logical_key().clone();
        if &key != rule.logical_key() {
            return Err(firew_sys::key_mismatch(rule));
        }
        let previous_rule = self
            .cache
            .get(&key)
            .cloned()
            .ok_or_else(|| firew_sys::rule_not_found(&key))?;
        let previous_names = self
            .native_names
            .get(&key)
            .cloned()
            .unwrap_or_else(|| id.handles().to_vec());

        let native_group = self.native_group();
        let mut new_names = Vec::new();
        let mut touched_in_place = false;
        for part in self.parts_for(rule)? {
            // Mark the part before writing it: a rewrite that fails partway has
            // still changed the live rule.
            touched_in_place |= previous_names.contains(&part.name);
            if let Err(error) = self.session.upsert_rule(
                rule,
                part.direction,
                &part.name,
                &part.marker,
                &native_group,
            ) {
                if let Err(rollback) = self.roll_back_update(
                    &previous_rule,
                    &previous_names,
                    &new_names,
                    touched_in_place,
                ) {
                    return Err(Error::new(
                        ErrorKind::RollbackFailed,
                        format!(
                            "INetFw update failed ({error}); restoring the previous rule failed"
                        ),
                    )
                    .with_logical_key(&key)
                    .with_source(rollback));
                }
                return Err(error);
            }
            new_names.push(part.name);
        }
        self.remove_obsolete_parts(&key, &previous_names, &new_names)?;

        self.cache.insert(key.clone(), rule.clone());
        self.native_names.insert(key.clone(), new_names.clone());
        Ok(NativeRuleRef::from_handles("inetfw", new_names, key))
    }

    fn remove_rule(&mut self, id: &NativeRuleRef) -> Result<(), Error> {
        self.refresh_from_native()?;
        let key = id.logical_key();
        let in_cache = self.cache.contains_key(key);
        let in_drifted = self.drifted_by_key.contains_key(key);
        if !in_cache && !in_drifted {
            return Err(firew_sys::rule_not_found(key));
        }
        let mut names = self
            .native_names
            .get(key)
            .cloned()
            .unwrap_or_else(|| id.handles().to_vec());
        if let Some(drifted_names) = self.drifted_by_key.get(key) {
            for drifted_name in drifted_names {
                if !names.contains(drifted_name) {
                    names.push(drifted_name.clone());
                }
            }
        }
        let native_group = self.native_group();
        for (index, name) in names.iter().enumerate() {
            if let Err(source) = self.session.remove_rule(name, &native_group, key) {
                let _ = self.refresh_from_native();
                return Err(Error::new(
                    ErrorKind::PartialMutation,
                    format!("removed {index} of {} INetFw rows", names.len()),
                )
                .with_logical_key(key)
                .with_source(source));
            }
            self.drift.resolve(name);
        }
        self.cache.remove(key);
        self.native_names.remove(key);
        self.drifted_by_key.remove(key);
        Ok(())
    }

    fn get_rule(&mut self, id: &NativeRuleRef) -> Result<Rule, Error> {
        self.refresh_from_native()?;
        self.cache
            .get(id.logical_key())
            .cloned()
            .ok_or_else(|| firew_sys::rule_not_found(id.logical_key()))
    }

    fn list_rules(&mut self, filter: &RuleFilter) -> Result<Vec<(NativeRuleRef, Rule)>, Error> {
        self.refresh_from_native()?;
        let mut out = Vec::new();
        for (key, rule) in &self.cache {
            if !filter.matches(key, rule) {
                continue;
            }
            let names = self.native_names.get(key).cloned().unwrap_or_default();
            out.push((
                NativeRuleRef::from_handles("inetfw", names, key.clone()),
                rule.clone(),
            ));
        }
        Ok(out)
    }

    fn health_probe(&mut self, expected_keys: &[RuleKey]) -> Result<HealthSnapshot, Error> {
        self.refresh_from_native()?;
        Ok(HealthSnapshot::from_present(
            self.cache.keys(),
            expected_keys,
        ))
    }

    fn remove_all_managed(&mut self) -> Result<(), Error> {
        self.refresh_from_native()?;
        let fallback_key = RuleKey::try_from("cleanup").expect("valid cleanup key");

        let mut all_names = BTreeSet::new();
        for names in self.native_names.values() {
            for name in names {
                all_names.insert(name.clone());
            }
        }
        for names in self.drifted_by_key.values() {
            for name in names {
                all_names.insert(name.clone());
            }
        }
        for name in self.drift.active() {
            all_names.insert(name.to_owned());
        }

        for name in all_names {
            self.session.remove_verified_rule(&name, &fallback_key)?;
        }

        self.cache.clear();
        self.native_names.clear();
        self.drift.clear();
        self.drifted_by_key.clear();
        Ok(())
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

    fn take_drift(&mut self) -> Vec<String> {
        self.drift.take()
    }

    fn incomplete_keys(&mut self) -> Result<Vec<RuleKey>, Error> {
        self.refresh_from_native()?;
        Ok(self.drifted_by_key.keys().cloned().collect())
    }
}

fn reconstruct_rows(rows: Vec<InetFwNativeRow>) -> ReconstructedRules {
    let mut grouped: BTreeMap<RuleKey, Vec<InetFwNativeRow>> = BTreeMap::new();
    for row in rows {
        grouped.entry(row.marker.key.clone()).or_default().push(row);
    }

    let mut rules = HashMap::with_capacity(grouped.len());
    let mut names = HashMap::with_capacity(grouped.len());
    let mut incomplete_by_key: HashMap<RuleKey, Vec<String>> = HashMap::new();

    for (key, mut parts) in grouped {
        let total = complete_parts(&mut parts, |row| &row.marker);
        // INetFw splits a rule into at most an inbound and an outbound row.
        let Some(total) = total.filter(|&total| total <= 2) else {
            incomplete_by_key.insert(key, parts.into_iter().map(|row| row.name).collect());
            continue;
        };

        let first = &parts[0].rule;
        if parts
            .iter()
            .skip(1)
            .any(|row| !equivalent_except_direction(first, &row.rule))
        {
            incomplete_by_key.insert(key, parts.into_iter().map(|row| row.name).collect());
            continue;
        }
        let direction = if total == 1 {
            first.direction()
        } else {
            let inbound = parts
                .iter()
                .filter(|row| row.rule.direction() == Direction::Inbound)
                .count();
            let outbound = parts
                .iter()
                .filter(|row| row.rule.direction() == Direction::Outbound)
                .count();
            if inbound != 1 || outbound != 1 {
                incomplete_by_key.insert(key, parts.into_iter().map(|row| row.name).collect());
                continue;
            }
            Direction::Both
        };
        let Ok(logical_rule) = copy_with_direction(first, direction) else {
            incomplete_by_key.insert(key, parts.into_iter().map(|row| row.name).collect());
            continue;
        };
        let native_names = parts.into_iter().map(|row| row.name).collect();
        names.insert(key.clone(), native_names);
        rules.insert(key, logical_rule);
    }
    ReconstructedRules {
        rules,
        names,
        incomplete_by_key,
    }
}

fn equivalent_except_direction(left: &Rule, right: &Rule) -> bool {
    left.logical_key() == right.logical_key()
        && left.action() == right.action()
        && left.protocol() == right.protocol()
        && left.remote_addresses() == right.remote_addresses()
        && left.local_addresses() == right.local_addresses()
        && left.remote_ports() == right.remote_ports()
        && left.local_ports() == right.local_ports()
        && left.application_path() == right.application_path()
        && left.package_sid() == right.package_sid()
        && left.remote_domains() == right.remote_domains()
}

fn copy_with_direction(rule: &Rule, direction: Direction) -> Result<Rule, Error> {
    let mut builder = rule
        .to_builder()
        .direction(direction)
        .without_remote_addresses();
    let use_set = needs_set_mode(
        rule.address_set_mode() == AddressSetMode::Set,
        direction,
        rule.remote_addresses().len(),
        rule.local_addresses().len(),
        rule.remote_ports().len(),
        rule.local_ports().len(),
    );
    if use_set {
        builder = builder.remote_address_set(rule.remote_addresses().iter().copied());
    } else {
        for address in rule.remote_addresses() {
            builder = builder.remote_address(*address);
        }
    }
    builder.build().map_err(|error| {
        Error::new(
            ErrorKind::CorruptNativeState,
            format!("failed to reconstruct managed INetFw rule: {error}"),
        )
        .with_logical_key(rule.logical_key())
    })
}

/// `INetFw` firewall backend via COM on a dedicated worker thread.
pub struct InetFwBackend {
    worker: WorkerClient,
    /// Resolved at open time; the worker owns the `BackendConfig` itself.
    max_address_set_entries: usize,
}

impl InetFwBackend {
    /// Opens the `INetFw` backend and starts its worker thread.
    pub fn open(config: &BackendConfig) -> Result<Self, Error> {
        let max_address_set_entries = config
            .max_address_set_entries
            .unwrap_or(firew_sys::DEFAULT_INETFW_ADDRESS_SET_LIMIT);
        let config = config.clone();
        let worker = WorkerClient::spawn("firew-rs-inetfw", move || InetFwWorker::open(config))?;
        Ok(Self {
            worker,
            max_address_set_entries,
        })
    }
}

impl Backend for InetFwBackend {
    fn open(config: &BackendConfig) -> Result<Self, Error> {
        Self::open(config)
    }

    fn name(&self) -> &'static str {
        "inetfw"
    }

    fn supports_transactions(&self) -> bool {
        false
    }

    fn max_address_set_entries(&self) -> Option<usize> {
        Some(self.max_address_set_entries)
    }

    fn validate_rule(&self, rule: &Rule) -> Result<(), Error> {
        firew_sys::validate_native_rule(self, "INetFw", rule)?;
        refuse_reject("INetFw", "inetfw", rule)?;
        validate_application_path("INetFw", rule)
    }

    forward_to_worker!(worker);
}

#[cfg(test)]
mod tests {
    use super::*;
    use firew_core::{Action, PortRange, Protocol};
    use firew_sys::ManagedMarker;
    use ipnet::IpNet;

    #[test]
    fn incomplete_multipart_group_is_quarantined_without_failing_healthy_rules() {
        let healthy_key = RuleKey::try_from("healthy").expect("key");
        let broken_key = RuleKey::try_from("broken").expect("key");
        let healthy_rule = Rule::builder("healthy", Action::Block, Direction::Outbound)
            .remote_address("192.0.2.1/32".parse::<IpNet>().expect("net"))
            .build()
            .expect("rule");
        let broken_part = Rule::builder("broken", Action::Block, Direction::Inbound)
            .remote_address("192.0.2.2/32".parse::<IpNet>().expect("net"))
            .build()
            .expect("rule");

        let rows = vec![
            InetFwNativeRow {
                marker: ManagedMarker {
                    key: healthy_key.clone(),
                    part: 0,
                    total: 1,
                },
                name: "firew-rs:NS:healthy [1/1]".to_owned(),
                rule: healthy_rule.clone(),
            },
            InetFwNativeRow {
                marker: ManagedMarker {
                    key: broken_key.clone(),
                    part: 0,
                    total: 2,
                },
                name: "firew-rs:NS:broken [1/2]".to_owned(),
                rule: broken_part,
            },
        ];

        let reconstructed = reconstruct_rows(rows);
        assert_eq!(reconstructed.rules.get(&healthy_key), Some(&healthy_rule));
        assert!(!reconstructed.rules.contains_key(&broken_key));
        assert_eq!(
            reconstructed.incomplete_by_key.get(&broken_key),
            Some(&vec!["firew-rs:NS:broken [1/2]".to_owned()])
        );
    }

    #[test]
    fn bidirectional_sub_cap_set_rule_reconstructs_cleanly() {
        let key = RuleKey::try_from("set-both").expect("key");
        let nets: Vec<IpNet> = (0..30)
            .map(|i| format!("10.0.0.{i}/32").parse::<IpNet>().expect("net"))
            .collect();
        let make_part = |dir: Direction| {
            let mut b = Rule::builder("set-both", Action::Block, dir)
                .protocol(Protocol::Tcp)
                .remote_address_set(nets.iter().copied());
            for port in [80, 443, 8080, 8443, 9000] {
                b = b.remote_port(PortRange::single(port).expect("port"));
            }
            b.build().expect("part builds")
        };

        let rows = vec![
            InetFwNativeRow {
                marker: ManagedMarker {
                    key: key.clone(),
                    part: 0,
                    total: 2,
                },
                name: "firew-rs:NS:set-both [1/2]".to_owned(),
                rule: make_part(Direction::Inbound),
            },
            InetFwNativeRow {
                marker: ManagedMarker {
                    key: key.clone(),
                    part: 1,
                    total: 2,
                },
                name: "firew-rs:NS:set-both [2/2]".to_owned(),
                rule: make_part(Direction::Outbound),
            },
        ];

        let reconstructed = reconstruct_rows(rows);
        assert!(reconstructed.incomplete_by_key.is_empty());
        let rule = reconstructed.rules.get(&key).expect("reconstructed");
        assert_eq!(rule.direction(), Direction::Both);
        assert_eq!(rule.address_set_mode(), AddressSetMode::Set);
        assert_eq!(rule.remote_addresses().len(), 30);
        assert_eq!(rule.remote_ports().len(), 5);
    }
}
