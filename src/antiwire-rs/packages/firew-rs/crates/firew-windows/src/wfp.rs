//! WFP fallback backend (dedicated worker thread).

use std::collections::{BTreeSet, HashMap};

use firew_core::{Direction, Error, ErrorKind, Rule, RuleKey, MAX_NATIVE_EXPANSION};
use firew_sys::{
    unsupported_matcher, Backend, BackendConfig, DriftTracker, HealthSnapshot, NativeRuleRef,
    RuleFilter,
};

use crate::sys::{layers_for_empty_remote, WfpEngine};
use crate::validation::{refuse_reject, validate_application_path};
use crate::worker::{forward_to_worker, NativeWorker, WorkerClient};

type WfpSnapshot = (HashMap<RuleKey, Rule>, HashMap<RuleKey, Vec<u64>>);

struct WfpWorker {
    config: BackendConfig,
    engine: WfpEngine,
    cache: HashMap<RuleKey, Rule>,
    filter_ids: HashMap<RuleKey, Vec<u64>>,
    orphan_ids: HashMap<RuleKey, Vec<u64>>,
    unkeyed_orphan_ids: Vec<u64>,
    drift: DriftTracker,
    transaction_open: bool,
    transaction_snapshot: Option<WfpSnapshot>,
    state_uncertain: bool,
}

impl WfpWorker {
    fn open(config: BackendConfig) -> Result<Self, Error> {
        let engine = WfpEngine::open(&config)?;
        let mut worker = Self {
            config,
            engine,
            cache: HashMap::new(),
            filter_ids: HashMap::new(),
            orphan_ids: HashMap::new(),
            unkeyed_orphan_ids: Vec::new(),
            drift: DriftTracker::new(),
            transaction_open: false,
            transaction_snapshot: None,
            state_uncertain: false,
        };
        worker.refresh_from_native()?;
        Ok(worker)
    }

    fn refresh_from_native(&mut self) -> Result<(), Error> {
        if self.transaction_open {
            return Ok(());
        }
        let namespace = self.config.managed_namespace();
        let enumerated = self.engine.enumerate_managed(&namespace)?;
        self.cache = enumerated.rules;
        self.filter_ids = enumerated.filter_ids;
        self.orphan_ids = enumerated.orphan_ids;
        self.unkeyed_orphan_ids = enumerated.unkeyed_orphan_ids;

        self.drift.observe(enumerated.drifted);
        self.state_uncertain = false;
        Ok(())
    }

    fn add_filters(&mut self, rule: &Rule) -> Result<Vec<u64>, Error> {
        firew_sys::reject_unresolved_domains(rule)?;
        self.engine.add_filters_for_rule(&self.config, rule)
    }

    fn delete_filters_for_key(&mut self, key: &RuleKey, filter_ids: &[u64]) -> Result<(), Error> {
        for (index, &filter_id) in filter_ids.iter().enumerate() {
            if let Err(err) = self.engine.delete_filter_by_id(filter_id) {
                if !self.transaction_open {
                    self.filter_ids
                        .insert(key.clone(), filter_ids[index..].to_vec());
                }
                return Err(err.with_logical_key(key));
            }
        }
        Ok(())
    }

    fn run_in_auto_transaction<T>(
        &mut self,
        op: impl FnOnce(&mut Self) -> Result<T, Error>,
    ) -> Result<T, Error> {
        if self.transaction_open {
            return op(self);
        }
        self.engine.transaction_begin()?;
        match op(self) {
            Ok(val) => {
                if let Err(commit_err) = self.engine.transaction_commit() {
                    let _ = self.engine.transaction_abort();
                    let _ = self.refresh_from_native();
                    return Err(commit_err);
                }
                Ok(val)
            }
            Err(op_err) => {
                if let Err(abort_err) = self.engine.transaction_abort() {
                    self.state_uncertain = true;
                    let _ = self.refresh_from_native();
                    return Err(Error::new(
                        ErrorKind::RollbackFailed,
                        format!("WFP operation failed ({op_err}); transaction abort failed"),
                    )
                    .with_source(abort_err));
                }
                let _ = self.refresh_from_native();
                Err(op_err)
            }
        }
    }

    fn native_ref_for(&self, key: &RuleKey) -> NativeRuleRef {
        let handles = self
            .filter_ids
            .get(key)
            .into_iter()
            .flatten()
            .map(ToString::to_string)
            .collect::<Vec<_>>();
        NativeRuleRef::from_handles("wfp", handles, key.clone())
    }
}

impl NativeWorker for WfpWorker {
    fn add_rule(&mut self, rule: &Rule) -> Result<NativeRuleRef, Error> {
        self.refresh_from_native()?;
        let key = rule.logical_key().clone();
        if self.cache.contains_key(&key) {
            return Err(firew_sys::duplicate_rule(key));
        }
        self.run_in_auto_transaction(|worker| {
            // An orphan filter left behind keeps enforcing next to the new
            // rule; failing to delete it aborts the transaction instead.
            if let Some(orphans) = worker.orphan_ids.remove(&key) {
                for id in orphans {
                    worker.engine.delete_filter_by_id(id)?;
                }
            }
            let ids = worker.add_filters(rule)?;
            worker.filter_ids.insert(key.clone(), ids);
            worker.cache.insert(key.clone(), rule.clone());
            Ok(worker.native_ref_for(&key))
        })
    }

    fn update_rule(&mut self, id: &NativeRuleRef, rule: &Rule) -> Result<NativeRuleRef, Error> {
        self.refresh_from_native()?;
        let key = id.logical_key().clone();
        if &key != rule.logical_key() {
            return Err(firew_sys::key_mismatch(rule));
        }
        if !self.cache.contains_key(&key) {
            return Err(firew_sys::rule_not_found(&key));
        }
        self.run_in_auto_transaction(|worker| {
            let old_rule = worker.cache.get(&key).cloned();
            let old_ids = worker.filter_ids.get(&key).cloned().unwrap_or_default();
            worker.delete_filters_for_key(&key, &old_ids)?;
            match worker.add_filters(rule) {
                Ok(new_ids) => {
                    worker.filter_ids.insert(key.clone(), new_ids);
                    worker.cache.insert(key.clone(), rule.clone());
                    Ok(worker.native_ref_for(&key))
                }
                Err(error) => {
                    if worker.transaction_open {
                        if let Some(old) = old_rule {
                            worker.cache.insert(key.clone(), old);
                        }
                        worker.filter_ids.insert(key, old_ids);
                    }
                    Err(error)
                }
            }
        })
    }

    fn remove_rule(&mut self, id: &NativeRuleRef) -> Result<(), Error> {
        self.refresh_from_native()?;
        let key = id.logical_key().clone();
        let in_cache = self.cache.contains_key(&key);
        let in_orphans = self.orphan_ids.contains_key(&key);
        if !in_cache && !in_orphans {
            return Err(firew_sys::rule_not_found(&key));
        }
        self.run_in_auto_transaction(|worker| {
            let mut ids = worker.filter_ids.get(&key).cloned().unwrap_or_default();
            if let Some(orphans) = worker.orphan_ids.get(&key) {
                for &orphan_id in orphans {
                    if !ids.contains(&orphan_id) {
                        ids.push(orphan_id);
                    }
                }
            }
            worker.delete_filters_for_key(&key, &ids)?;
            worker.cache.remove(&key);
            worker.filter_ids.remove(&key);
            worker.orphan_ids.remove(&key);
            Ok(())
        })
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
            out.push((self.native_ref_for(key), rule.clone()));
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
        self.run_in_auto_transaction(|worker| {
            let mut all_ids = BTreeSet::new();
            for ids in worker.filter_ids.values() {
                for &id in ids {
                    all_ids.insert(id);
                }
            }
            for ids in worker.orphan_ids.values() {
                for &id in ids {
                    all_ids.insert(id);
                }
            }
            // Unmarked filters in our sublayer belong to this namespace too;
            // leaving them would keep enforcing after a full cleanup.
            all_ids.extend(worker.unkeyed_orphan_ids.iter().copied());
            for id in all_ids {
                worker.engine.delete_filter_by_id(id)?;
            }
            worker.cache.clear();
            worker.filter_ids.clear();
            worker.orphan_ids.clear();
            worker.unkeyed_orphan_ids.clear();
            worker.drift.clear();
            Ok(())
        })
    }

    fn begin_transaction(&mut self) -> Result<(), Error> {
        if self.transaction_open {
            return Err(Error::new(
                ErrorKind::TransactionFailed,
                "WFP transaction already open",
            ));
        }
        self.refresh_from_native()?;
        self.engine.transaction_begin()?;
        self.transaction_snapshot = Some((self.cache.clone(), self.filter_ids.clone()));
        self.transaction_open = true;
        Ok(())
    }

    fn commit_transaction(&mut self) -> Result<(), Error> {
        if !self.transaction_open {
            return Ok(());
        }
        self.engine.transaction_commit()?;
        self.transaction_open = false;
        self.transaction_snapshot = None;
        Ok(())
    }

    fn abort_transaction(&mut self) -> Result<(), Error> {
        if !self.transaction_open {
            return Ok(());
        }
        self.transaction_open = false;
        match self.engine.transaction_abort() {
            Ok(()) => {
                if let Some((cache, filter_ids)) = self.transaction_snapshot.take() {
                    self.cache = cache;
                    self.filter_ids = filter_ids;
                }
                Ok(())
            }
            Err(err) => {
                self.transaction_snapshot = None;
                self.state_uncertain = true;
                let _ = self.refresh_from_native();
                Err(err)
            }
        }
    }

    fn take_drift(&mut self) -> Vec<String> {
        self.drift.take()
    }

    fn incomplete_keys(&mut self) -> Result<Vec<RuleKey>, Error> {
        self.refresh_from_native()?;
        Ok(self.orphan_ids.keys().cloned().collect())
    }
}

/// WFP fallback backend using Fwpm APIs on a dedicated worker thread.
pub struct WfpBackend {
    worker: WorkerClient,
}

impl WfpBackend {
    /// Opens the WFP backend and starts its worker thread.
    pub fn open(config: &BackendConfig) -> Result<Self, Error> {
        let config = config.clone();
        let worker = WorkerClient::spawn("firew-rs-wfp", move || WfpWorker::open(config))?;
        Ok(Self { worker })
    }
}

impl Backend for WfpBackend {
    fn open(config: &BackendConfig) -> Result<Self, Error> {
        Self::open(config)
    }

    fn name(&self) -> &'static str {
        "wfp"
    }

    fn supports_transactions(&self) -> bool {
        true
    }

    fn max_address_set_entries(&self) -> Option<usize> {
        None
    }

    fn validate_rule(&self, rule: &Rule) -> Result<(), Error> {
        firew_sys::validate_native_rule(self, "WFP", rule)?;
        refuse_reject("WFP", "wfp", rule)?;
        if !rule.local_addresses().is_empty() {
            return unsupported(rule, "local addresses");
        }
        if !rule.local_ports().is_empty() {
            return unsupported(rule, "local ports");
        }
        if rule.remote_ports().len() > 1 {
            return unsupported(rule, "multiple remote port alternatives");
        }
        if rule.package_sid().is_some() {
            return unsupported(rule, "package SID");
        }
        let directions = match rule.direction() {
            Direction::Both => 2,
            Direction::Inbound | Direction::Outbound => 1,
        };
        let address_rows = if rule.remote_addresses().is_empty() {
            layers_for_empty_remote(rule.protocol()).len()
        } else {
            rule.remote_addresses().len()
        };
        let rows = directions * address_rows;
        if rows > MAX_NATIVE_EXPANSION {
            return Err(Error::new(
                ErrorKind::LimitExceeded,
                format!("WFP rule requires {rows} native filters"),
            )
            .with_logical_key(rule.logical_key())
            .with_platform_detail("wfp"));
        }
        validate_application_path("WFP", rule)
    }

    forward_to_worker!(worker);
}

fn unsupported(rule: &Rule, field: &str) -> Result<(), Error> {
    Err(unsupported_matcher("WFP", "wfp", rule, field))
}
