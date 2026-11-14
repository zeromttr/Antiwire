//! nftables backend via `nftables-rs` (libnftables JSON / `nft -j`).

#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

use std::borrow::Cow;
use std::collections::HashMap;

use firew_core::{AddressSetMode, Error, ErrorKind, PortRange, Rule, RuleKey};
use firew_sys::{
    Backend, BackendConfig, DriftTracker, HealthSnapshot, ManagedMarker, NativeRuleRef, RuleFilter,
};
use ipnet::IpNet;
use nftables::batch::Batch;
use nftables::helper::{self, NftablesError};
use nftables::schema::{Chain, NfListObject, NfObject, Nftables, Rule as NftRule, Set, Table};
use nftables::types::{NfChainPolicy, NfChainType, NfFamily, NfHook};

mod build;
mod reconstruct;
#[cfg(test)]
mod tests;

use reconstruct::{ensure_rule_handles, reconstruct_from_ruleset, ReconstructedNftables};

const TABLE_NAME: &str = "firew_rs";
const FAMILY: NfFamily = NfFamily::INet;

/// Upper bound on addresses in one nftables named set.
const MAX_SET_ENTRIES: usize = 65_536;

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub(crate) struct NftHandle {
    pub(crate) chain: String,
    pub(crate) handle: u32,
}

#[derive(Clone, Debug)]
pub(crate) struct RuleRecord {
    rule: Rule,
    handles: Vec<NftHandle>,
    /// Named sets backing an [`AddressSetMode::Set`] rule, deleted with it.
    sets: Vec<String>,
    /// True when added or modified inside an uncommitted transaction.
    dirty: bool,
}

/// Named sets plus the rules referencing them for one address-set rule.
pub(crate) struct SetInstall {
    pub(crate) sets: Vec<Set<'static>>,
    pub(crate) rules: Vec<NftRule<'static>>,
    pub(crate) set_names: Vec<String>,
}

#[derive(Clone, Copy)]
struct RuleVariant<'a> {
    inbound: bool,
    remote_address: Option<&'a IpNet>,
    local_address: Option<&'a IpNet>,
    remote_port: Option<&'a PortRange>,
    local_port: Option<&'a PortRange>,
}

/// nftables backend using `nftables-rs`.
pub struct NftablesBackend {
    config: BackendConfig,
    out_chain: String,
    in_chain: String,
    rules: HashMap<RuleKey, RuleRecord>,
    orphan_handles: HashMap<RuleKey, Vec<NftHandle>>,
    orphan_sets: HashMap<RuleKey, Vec<String>>,
    unkeyed_orphans: Vec<NftHandle>,
    drift: DriftTracker,
    in_transaction: bool,
    transaction_snapshot: Option<HashMap<RuleKey, RuleRecord>>,
    /// Orphan rows an open transaction has taken over: deleted by its commit,
    /// handed back to the orphan maps if it does not commit.
    staged_orphans: Vec<StagedOrphans>,
}

/// Orphan rows and sets of one key, or the unkeyed orphans when `key` is `None`.
#[derive(Clone, Debug)]
pub(crate) struct StagedOrphans {
    key: Option<RuleKey>,
    handles: Vec<NftHandle>,
    sets: Vec<String>,
}

impl NftablesBackend {
    pub fn open(config: &BackendConfig) -> Result<Self, Error> {
        let suffix = config.managed_namespace();
        let mut backend = Self {
            config: config.clone(),
            out_chain: format!("firew_out_{}", suffix.as_str()),
            in_chain: format!("firew_in_{}", suffix.as_str()),
            rules: HashMap::new(),
            orphan_handles: HashMap::new(),
            orphan_sets: HashMap::new(),
            unkeyed_orphans: Vec::new(),
            drift: DriftTracker::new(),
            in_transaction: false,
            transaction_snapshot: None,
            staged_orphans: Vec::new(),
        };
        backend.ensure_infrastructure()?;
        // An owner that cannot read its table would start from an empty map
        // and later rewrite or report the namespace from that wrong picture.
        backend.refresh_from_native()?;
        Ok(backend)
    }

    pub(crate) fn map_nft_err(err: &NftablesError) -> Error {
        let text = err.to_string();
        let kind = match err {
            NftablesError::NftExecution { .. } => ErrorKind::BackendUnavailable,
            NftablesError::NftInvalidJson { .. } | NftablesError::NftOutputEncoding { .. } => {
                ErrorKind::CorruptNativeState
            }
            NftablesError::NftFailed { .. } => firew_sys::classify_cli_failure(
                &text,
                &["conflicting intervals", "syntax error", "invalid argument"],
            ),
        };
        Error::new(kind, format!("nft: {text}"))
    }

    /// Ensures the `firew_rs` table and this namespace's input/output chains exist.
    ///
    /// Applies an idempotent `Batch` adding the table and chains directly rather
    /// than dumping and deserializing the entire host ruleset via `nft -j list ruleset`.
    fn ensure_infrastructure(&self) -> Result<(), Error> {
        let batch = Self::infrastructure_batch(&self.out_chain, &self.in_chain);
        helper::apply_ruleset(&batch.to_nftables()).map_err(|e| Self::map_nft_err(&e))?;
        Ok(())
    }

    pub(crate) fn infrastructure_batch(out_chain: &str, in_chain: &str) -> Batch<'static> {
        let mut batch = Batch::new();
        batch.add(NfListObject::Table(Table {
            family: FAMILY,
            name: Cow::Borrowed(TABLE_NAME),
            ..Default::default()
        }));
        batch.add(NfListObject::Chain(Self::chain_def(
            out_chain,
            NfHook::Output,
        )));
        batch.add(NfListObject::Chain(Self::chain_def(
            in_chain,
            NfHook::Input,
        )));
        batch
    }

    fn chain_def(chain_name: &str, hook: NfHook) -> Chain<'static> {
        Chain {
            family: FAMILY,
            table: Cow::Borrowed(TABLE_NAME),
            name: Cow::Owned(chain_name.to_owned()),
            _type: Some(NfChainType::Filter),
            hook: Some(hook),
            prio: Some(0),
            policy: Some(NfChainPolicy::Accept),
            ..Default::default()
        }
    }

    fn refresh_from_native(&mut self) -> Result<(), Error> {
        if self.in_transaction {
            return Ok(());
        }
        let ruleset = Self::list_table()?;
        self.apply_reconstructed_ruleset(&ruleset);
        Ok(())
    }

    /// Lists the `firew_rs` table with rule handles.
    ///
    /// `-a` asks for handles explicitly, and a listing that still omits one for
    /// a rule in the table is refused: deletes address rules by handle, so a
    /// guessed handle would target the wrong rule and leave the real one.
    fn list_table() -> Result<Nftables<'static>, Error> {
        let ruleset = helper::get_current_ruleset_with_args(
            helper::DEFAULT_NFT,
            ["-a", "list", "table", "inet", TABLE_NAME],
        )
        .map_err(|e| Self::map_nft_err(&e))?;
        ensure_rule_handles(&ruleset)?;
        Ok(ruleset)
    }

    /// The rules a read reports: a fresh kernel listing, or the transaction's
    /// own view while one is open. Outside a transaction the kernel is
    /// authoritative, and failing to read it is an error, never a cue to
    /// answer from process memory.
    fn visible_rules(&self) -> Result<Cow<'_, HashMap<RuleKey, RuleRecord>>, Error> {
        if self.in_transaction {
            return Ok(Cow::Borrowed(&self.rules));
        }
        Ok(Cow::Owned(self.reconstruct_live()?.rules))
    }

    /// Lists the table now and rebuilds this namespace's rules from it,
    /// without touching the cached state.
    fn reconstruct_live(&self) -> Result<ReconstructedNftables, Error> {
        let ruleset = Self::list_table()?;
        let namespace = self.config.managed_namespace();
        Ok(reconstruct_from_ruleset(
            &ruleset,
            &namespace,
            &self.in_chain,
            &self.out_chain,
        ))
    }

    /// Checks that `rule` builds into nft objects, for a transaction that
    /// installs it at commit, and returns the set names it will use.
    fn staged_set_names(&self, rule: &Rule) -> Result<Vec<String>, Error> {
        if rule.address_set_mode() == AddressSetMode::Set {
            Ok(self.build_set_objects(rule)?.set_names)
        } else {
            self.build_cartesian_rules(rule)?;
            Ok(Vec::new())
        }
    }

    pub(crate) fn apply_reconstructed_ruleset(&mut self, ruleset: &Nftables<'_>) {
        let namespace = self.config.managed_namespace();
        let reconstructed =
            reconstruct_from_ruleset(ruleset, &namespace, &self.in_chain, &self.out_chain);
        self.rules = reconstructed.rules;
        self.orphan_handles = reconstructed.orphan_handles;
        self.orphan_sets = reconstructed.orphan_sets;
        self.unkeyed_orphans = reconstructed.unkeyed_orphans;

        self.drift.observe(reconstructed.drifted);
    }

    fn apply_batch(&mut self, batch: Batch<'static>, want_handles: bool) -> Result<(), Error> {
        let nftables = batch.to_nftables();
        if nftables.objects.is_empty() {
            return Ok(());
        }
        if want_handles {
            let returned =
                helper::apply_and_return_ruleset(&nftables).map_err(|e| Self::map_nft_err(&e))?;
            self.assign_handles_from_echo(&returned);
        } else {
            helper::apply_ruleset(&nftables).map_err(|e| Self::map_nft_err(&e))?;
        }
        Ok(())
    }

    pub(crate) fn assign_handles_from_echo(&mut self, returned: &Nftables<'_>) {
        let namespace = self.config.managed_namespace();
        for obj in returned.objects.iter() {
            let (NfObject::ListObject(NfListObject::Rule(rule))
            | NfObject::CmdObject(nftables::schema::NfCmd::Add(NfListObject::Rule(rule)))) = obj
            else {
                continue;
            };
            let Some(handle) = rule.handle else {
                continue;
            };
            let Some(comment) = rule.comment.as_deref() else {
                continue;
            };
            let Ok(marker) = ManagedMarker::parse(comment, &namespace) else {
                continue;
            };
            if let Some(record) = self.rules.get_mut(&marker.key) {
                let entry = NftHandle {
                    chain: rule.chain.to_string(),
                    handle,
                };
                if !record.handles.contains(&entry) {
                    record.handles.push(entry);
                }
            }
        }
    }

    fn native_ref_for(&self, key: &RuleKey) -> NativeRuleRef {
        record_ref(key, self.rules.get(key))
    }

    /// Moves `key`'s orphan rows and sets into the open transaction, so its
    /// commit deletes them in the same batch.
    fn stage_orphans_of(&mut self, key: &RuleKey) {
        let handles = self.orphan_handles.remove(key).unwrap_or_default();
        let sets = self.orphan_sets.remove(key).unwrap_or_default();
        if !handles.is_empty() || !sets.is_empty() {
            self.staged_orphans.push(StagedOrphans {
                key: Some(key.clone()),
                handles,
                sets,
            });
        }
    }

    /// Closes a transaction that did not reach the kernel: the rules return
    /// to `snapshot` and staged orphans to the orphan maps.
    fn end_transaction_unapplied(&mut self, snapshot: Option<HashMap<RuleKey, RuleRecord>>) {
        if let Some(snapshot) = snapshot {
            self.rules = snapshot;
        }
        self.restore_staged_orphans();
        self.in_transaction = false;
    }

    /// Returns orphans staged by a transaction that did not commit.
    fn restore_staged_orphans(&mut self) {
        for staged in std::mem::take(&mut self.staged_orphans) {
            match staged.key {
                Some(key) => {
                    if !staged.handles.is_empty() {
                        self.orphan_handles
                            .entry(key.clone())
                            .or_default()
                            .extend(staged.handles);
                    }
                    if !staged.sets.is_empty() {
                        self.orphan_sets.entry(key).or_default().extend(staged.sets);
                    }
                }
                None => self.unkeyed_orphans.extend(staged.handles),
            }
        }
    }

    fn add_rule_inner(&mut self, rule: &Rule) -> Result<NativeRuleRef, Error> {
        self.refresh_from_native()?;
        let key = rule.logical_key().clone();
        if self.rules.contains_key(&key) {
            return Err(firew_sys::duplicate_rule(key));
        }

        if self.in_transaction {
            let set_names = self.staged_set_names(rule)?;
            // Leftover rows of a damaged earlier install would keep matching
            // beside the new rule; the commit deletes them.
            self.stage_orphans_of(&key);
            self.rules.insert(
                key.clone(),
                RuleRecord {
                    rule: rule.clone(),
                    handles: Vec::new(),
                    sets: set_names,
                    dirty: true,
                },
            );
            return Ok(self.native_ref_for(&key));
        }

        let mut batch = Batch::new();
        if let Some(orphans) = self.orphan_handles.remove(&key) {
            let orphan_sets = self.orphan_sets.remove(&key).unwrap_or_default();
            Self::append_record_deletion_to_batch(&mut batch, &orphans, &orphan_sets);
        }
        let set_names = self.append_rule_install_to_batch(&mut batch, rule)?;
        self.rules.insert(
            key.clone(),
            RuleRecord {
                rule: rule.clone(),
                handles: Vec::new(),
                sets: set_names,
                dirty: false,
            },
        );
        if let Err(error) = self.apply_batch(batch, true) {
            self.rules.remove(&key);
            return Err(error);
        }
        Ok(self.native_ref_for(&key))
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
        let previous = self
            .rules
            .get(&key)
            .cloned()
            .ok_or_else(|| firew_sys::rule_not_found(&key))?;

        if self.in_transaction {
            let set_names = self.staged_set_names(rule)?;
            self.rules.insert(
                key.clone(),
                RuleRecord {
                    rule: rule.clone(),
                    handles: Vec::new(),
                    sets: set_names,
                    dirty: true,
                },
            );
            return Ok(self.native_ref_for(&key));
        }

        // Single atomic kernel batch: delete previous handles/sets and add replacement.
        let mut batch = Batch::new();
        Self::append_record_deletion_to_batch(&mut batch, &previous.handles, &previous.sets);
        let set_names = self.append_rule_install_to_batch(&mut batch, rule)?;
        self.rules.insert(
            key.clone(),
            RuleRecord {
                rule: rule.clone(),
                handles: Vec::new(),
                sets: set_names,
                dirty: false,
            },
        );
        if let Err(error) = self.apply_batch(batch, true) {
            self.rules.insert(key, previous);
            return Err(error);
        }
        Ok(self.native_ref_for(&key))
    }

    fn remove_rule_inner(&mut self, id: &NativeRuleRef) -> Result<(), Error> {
        self.refresh_from_native()?;
        let key = id.logical_key().clone();
        if !self.rules.contains_key(&key) && !self.orphan_handles.contains_key(&key) {
            return Err(firew_sys::rule_not_found(&key));
        }

        if self.in_transaction {
            // The commit deletes the record's rows by diffing against the
            // snapshot. Orphan rows are not in it, so they are staged instead.
            self.rules.remove(&key);
            self.stage_orphans_of(&key);
            return Ok(());
        }

        let record = self.rules.remove(&key);
        let orphan_handles = self.orphan_handles.remove(&key);
        let orphan_sets = self.orphan_sets.remove(&key);

        let mut batch = Batch::new();
        if let Some(ref rec) = record {
            Self::append_record_deletion_to_batch(&mut batch, &rec.handles, &rec.sets);
        }
        if let Some(ref orphans) = orphan_handles {
            let sets = orphan_sets.as_deref().unwrap_or(&[]);
            Self::append_record_deletion_to_batch(&mut batch, orphans, sets);
        }

        if let Err(error) = self.apply_batch(batch, false) {
            if let Some(rec) = record {
                self.rules.insert(key, rec);
            }
            return Err(error);
        }
        Ok(())
    }

    /// Builds a single coalesced `Batch` from `self.transaction_snapshot` to `self.rules`.
    pub(crate) fn build_commit_batch(
        &mut self,
        snapshot: &HashMap<RuleKey, RuleRecord>,
    ) -> Result<(Batch<'static>, bool), Error> {
        let mut batch = Batch::new();
        let mut want_handles = false;

        // 1. Delete any pre-transaction rules that were removed or modified.
        let mut snapshot_keys: Vec<&RuleKey> = snapshot.keys().collect();
        snapshot_keys.sort();
        for key in snapshot_keys {
            let old_record = &snapshot[key];
            let needs_delete = match self.rules.get(key) {
                None => true,
                Some(current) => current.dirty,
            };
            if needs_delete {
                Self::append_record_deletion_to_batch(
                    &mut batch,
                    &old_record.handles,
                    &old_record.sets,
                );
            }
        }

        // 2. Delete orphan rows the transaction took over, before an add can
        //    reuse one of their set names.
        for staged in &self.staged_orphans {
            Self::append_record_deletion_to_batch(&mut batch, &staged.handles, &staged.sets);
        }

        // 3. Add any newly created or modified rules once using their final desired state.
        let mut current_keys: Vec<RuleKey> = self.rules.keys().cloned().collect();
        current_keys.sort();
        for key in current_keys {
            let rule_clone = {
                let record = &self.rules[&key];
                if !record.dirty {
                    continue;
                }
                record.rule.clone()
            };
            let set_names = self.append_rule_install_to_batch(&mut batch, &rule_clone)?;
            if let Some(record) = self.rules.get_mut(&key) {
                record.sets = set_names;
                record.handles.clear();
                record.dirty = false;
            }
            want_handles = true;
        }

        Ok((batch, want_handles))
    }
}

/// The native reference for `key`: its rule handles, or the bare key for a
/// rule not yet installed (a transaction applies it at commit).
fn record_ref(key: &RuleKey, record: Option<&RuleRecord>) -> NativeRuleRef {
    let handles: Vec<String> = match record {
        Some(record) if !record.handles.is_empty() => record
            .handles
            .iter()
            .map(|handle| format!("{}:{}", handle.chain, handle.handle))
            .collect(),
        _ => vec![key.to_string()],
    };
    NativeRuleRef::from_handles("nftables", handles, key.clone())
}

impl Backend for NftablesBackend {
    fn open(config: &BackendConfig) -> Result<Self, Error> {
        Self::open(config)
    }

    fn name(&self) -> &'static str {
        "nftables"
    }

    fn supports_transactions(&self) -> bool {
        true
    }

    fn max_address_set_entries(&self) -> Option<usize> {
        Some(MAX_SET_ENTRIES)
    }

    fn validate_rule(&self, rule: &Rule) -> Result<(), Error> {
        firew_sys::validate_native_rule(self, "nftables", rule)?;
        firew_sys::reject_application_matchers("nftables", "nftables", rule)?;
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
        self.visible_rules()?
            .get(id.logical_key())
            .map(|r| r.rule.clone())
            .ok_or_else(|| firew_sys::rule_not_found(id.logical_key()))
    }

    fn list_rules(&self, filter: &RuleFilter) -> Result<Vec<(NativeRuleRef, Rule)>, Error> {
        Ok(self
            .visible_rules()?
            .iter()
            .filter(|(key, record)| filter.matches(key, &record.rule))
            .map(|(key, record)| (record_ref(key, Some(record)), record.rule.clone()))
            .collect())
    }

    fn begin_transaction(&mut self) -> Result<(), Error> {
        if self.in_transaction {
            return Err(Error::new(
                ErrorKind::TransactionFailed,
                "transaction already open",
            ));
        }
        // The snapshot is what an abort restores; it must reflect the kernel.
        self.refresh_from_native()?;
        self.transaction_snapshot = Some(self.rules.clone());
        self.in_transaction = true;
        Ok(())
    }

    fn commit_transaction(&mut self) -> Result<(), Error> {
        if !self.in_transaction {
            return Ok(());
        }
        let snapshot = self.transaction_snapshot.take().unwrap_or_default();
        let committed = self
            .build_commit_batch(&snapshot)
            .and_then(|(batch, want_handles)| self.apply_batch(batch, want_handles));
        if committed.is_ok() {
            self.staged_orphans.clear();
            self.in_transaction = false;
        } else {
            self.end_transaction_unapplied(Some(snapshot));
        }
        committed
    }

    fn abort_transaction(&mut self) -> Result<(), Error> {
        if self.in_transaction {
            let snapshot = self.transaction_snapshot.take();
            self.end_transaction_unapplied(snapshot);
        }
        Ok(())
    }

    fn health_probe(&self, expected_keys: &[RuleKey]) -> Result<HealthSnapshot, Error> {
        Ok(HealthSnapshot::from_present(
            self.visible_rules()?.keys(),
            expected_keys,
        ))
    }

    fn remove_all_managed(&mut self) -> Result<(), Error> {
        if self.in_transaction {
            self.rules.clear();
            // Orphan sets are only recorded for keys with orphan rows.
            let keys: Vec<RuleKey> = self.orphan_handles.keys().cloned().collect();
            for key in keys {
                self.stage_orphans_of(&key);
            }
            let unkeyed = std::mem::take(&mut self.unkeyed_orphans);
            if !unkeyed.is_empty() {
                self.staged_orphans.push(StagedOrphans {
                    key: None,
                    handles: unkeyed,
                    sets: Vec::new(),
                });
            }
            return Ok(());
        }
        // A fresh process knows nothing in memory, so the kernel listing is the
        // only record of what to remove. Failing to read it is a failure, not
        // an empty namespace.
        self.refresh_from_native()?;
        let mut batch = Batch::new();
        for record in self.rules.values() {
            Self::append_record_deletion_to_batch(&mut batch, &record.handles, &record.sets);
        }
        for (key, orphans) in &self.orphan_handles {
            let sets = self.orphan_sets.get(key).map_or(&[][..], Vec::as_slice);
            Self::append_record_deletion_to_batch(&mut batch, orphans, sets);
        }
        Self::append_record_deletion_to_batch(&mut batch, &self.unkeyed_orphans, &[]);

        self.apply_batch(batch, false)?;
        self.rules.clear();
        self.orphan_handles.clear();
        self.orphan_sets.clear();
        self.unkeyed_orphans.clear();
        self.drift.clear();
        Ok(())
    }

    fn take_drift(&mut self) -> Result<Vec<String>, Error> {
        self.refresh_from_native()?;
        Ok(self.drift.take())
    }

    fn incomplete_keys(&self) -> Result<Vec<RuleKey>, Error> {
        if self.in_transaction {
            return Ok(self.orphan_handles.keys().cloned().collect());
        }
        Ok(self
            .reconstruct_live()?
            .orphan_handles
            .into_keys()
            .collect())
    }
}
