use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use firew_core::{Error, ErrorKind, Rule, RuleKey};
use firew_sys::{Backend, BackendConfig, HealthSnapshot, NativeRuleRef, RuleFilter};
use parking_lot::Mutex;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum BackendCall {
    Add(String),
    Update(String),
    Remove(String),
    List,
    Begin,
    Commit,
    Abort,
    RemoveAll,
}

#[allow(clippy::struct_excessive_bools)]
struct ScriptState {
    rules: BTreeMap<RuleKey, Rule>,
    calls: Vec<BackendCall>,
    transaction_snapshot: Option<BTreeMap<RuleKey, Rule>>,
    fail_add: BTreeSet<RuleKey>,
    fail_update: BTreeSet<RuleKey>,
    delete_on_fail_update: BTreeSet<RuleKey>,
    fail_commit: bool,
    fail_abort: bool,
    fail_remove_all: bool,
    supports_ipv6: bool,
    max_address_set_entries: Option<usize>,
    drift: Vec<String>,
    /// Keys whose native rows are damaged: unlisted, but still installed.
    fragments: BTreeSet<RuleKey>,
}

impl Default for ScriptState {
    fn default() -> Self {
        Self {
            rules: BTreeMap::new(),
            calls: Vec::new(),
            transaction_snapshot: None,
            fail_add: BTreeSet::new(),
            fail_update: BTreeSet::new(),
            delete_on_fail_update: BTreeSet::new(),
            fail_commit: false,
            fail_abort: false,
            fail_remove_all: false,
            supports_ipv6: true,
            max_address_set_entries: Some(65_536),
            drift: Vec::new(),
            fragments: BTreeSet::new(),
        }
    }
}

#[derive(Clone)]
pub(crate) struct ScriptControl {
    state: Arc<Mutex<ScriptState>>,
}

impl ScriptControl {
    pub(crate) fn seed(&self, rule: Rule) {
        self.state
            .lock()
            .rules
            .insert(rule.logical_key().clone(), rule);
    }

    /// Deletes part of `key`'s native rows outside the manager: the rule is
    /// no longer listed, but what is left of it is still installed.
    pub(crate) fn damage(&self, key: &str) {
        let key = RuleKey::try_from(key).expect("valid scripted key");
        let mut state = self.state.lock();
        assert!(
            state.rules.remove(&key).is_some(),
            "damaging a missing rule"
        );
        state.fragments.insert(key);
    }

    /// Keys with damaged rows still installed.
    pub(crate) fn fragments(&self) -> Vec<RuleKey> {
        self.state.lock().fragments.iter().cloned().collect()
    }

    pub(crate) fn remove_external(&self, key: &str) {
        let key = RuleKey::try_from(key).expect("valid scripted key");
        self.state.lock().rules.remove(&key);
    }

    pub(crate) fn fail_add(&self, key: &str) {
        self.state
            .lock()
            .fail_add
            .insert(RuleKey::try_from(key).expect("valid scripted key"));
    }

    pub(crate) fn fail_update(&self, key: &str) {
        self.state
            .lock()
            .fail_update
            .insert(RuleKey::try_from(key).expect("valid scripted key"));
    }

    pub(crate) fn fail_update_removing_old(&self, key: &str) {
        let k = RuleKey::try_from(key).expect("valid scripted key");
        let mut guard = self.state.lock();
        guard.fail_update.insert(k.clone());
        guard.delete_on_fail_update.insert(k);
    }

    pub(crate) fn fail_commit(&self) {
        self.state.lock().fail_commit = true;
    }

    pub(crate) fn fail_abort(&self) {
        self.state.lock().fail_abort = true;
    }

    pub(crate) fn fail_remove_all(&self) {
        self.state.lock().fail_remove_all = true;
    }

    pub(crate) fn set_supports_ipv6(&self, enabled: bool) {
        self.state.lock().supports_ipv6 = enabled;
    }

    pub(crate) fn calls(&self) -> Vec<BackendCall> {
        self.state.lock().calls.clone()
    }

    pub(crate) fn clear_calls(&self) {
        self.state.lock().calls.clear();
    }

    pub(crate) fn rules(&self) -> Vec<Rule> {
        self.state.lock().rules.values().cloned().collect()
    }
}

pub(crate) struct ScriptedBackend {
    state: Arc<Mutex<ScriptState>>,
    supports_transactions: bool,
}

impl ScriptedBackend {
    pub(crate) fn new(supports_transactions: bool) -> (Self, ScriptControl) {
        let state = Arc::new(Mutex::new(ScriptState::default()));
        (
            Self {
                state: state.clone(),
                supports_transactions,
            },
            ScriptControl { state },
        )
    }

    fn native_ref(key: &RuleKey) -> NativeRuleRef {
        NativeRuleRef::new("scripted", key.to_string(), key.clone())
    }
}

impl Backend for ScriptedBackend {
    fn open(_config: &BackendConfig) -> Result<Self, Error> {
        Ok(Self::new(true).0)
    }

    fn name(&self) -> &'static str {
        "scripted"
    }

    fn supports_transactions(&self) -> bool {
        self.supports_transactions
    }

    fn supports_ipv6(&self) -> bool {
        self.state.lock().supports_ipv6
    }

    fn max_address_set_entries(&self) -> Option<usize> {
        self.state.lock().max_address_set_entries
    }

    fn validate_rule(&self, rule: &Rule) -> Result<(), Error> {
        rule.validate()?;
        if !self.supports_ipv6()
            && (rule
                .remote_addresses()
                .iter()
                .chain(rule.local_addresses())
                .any(|n| n.addr().is_ipv6())
                || rule.protocol() == firew_core::Protocol::IcmpV6)
        {
            return Err(
                Error::new(ErrorKind::UnsupportedMatcher, "IPv6 not supported")
                    .with_logical_key(rule.logical_key()),
            );
        }
        Ok(())
    }

    fn add_rule(&mut self, rule: &Rule) -> Result<NativeRuleRef, Error> {
        let mut state = self.state.lock();
        let key = rule.logical_key().clone();
        state.calls.push(BackendCall::Add(key.to_string()));
        if state.fail_add.contains(&key) {
            return Err(
                Error::new(ErrorKind::Internal, "scripted add failure").with_logical_key(key)
            );
        }
        if state.rules.contains_key(&key) {
            return Err(
                Error::new(ErrorKind::InvalidRule, "duplicate scripted rule").with_logical_key(key),
            );
        }
        // Installing a key replaces whatever damaged rows it left behind.
        state.fragments.remove(&key);
        state.rules.insert(key.clone(), rule.clone());
        Ok(Self::native_ref(&key))
    }

    fn update_rule(&mut self, id: &NativeRuleRef, rule: &Rule) -> Result<NativeRuleRef, Error> {
        let mut state = self.state.lock();
        let key = id.logical_key().clone();
        state.calls.push(BackendCall::Update(key.to_string()));
        if !state.rules.contains_key(&key) {
            return Err(
                Error::new(ErrorKind::RuleNotFound, "scripted rule not found")
                    .with_logical_key(key),
            );
        }
        if state.fail_update.contains(&key) {
            if state.delete_on_fail_update.contains(&key) {
                state.rules.remove(&key);
            }
            return Err(
                Error::new(ErrorKind::Internal, "scripted update failure").with_logical_key(key)
            );
        }
        state.rules.insert(key.clone(), rule.clone());
        Ok(Self::native_ref(&key))
    }

    fn remove_rule(&mut self, id: &NativeRuleRef) -> Result<(), Error> {
        let mut state = self.state.lock();
        let key = id.logical_key().clone();
        state.calls.push(BackendCall::Remove(key.to_string()));
        let had_fragments = state.fragments.remove(&key);
        if state.rules.remove(&key).is_none() && !had_fragments {
            return Err(
                Error::new(ErrorKind::RuleNotFound, "scripted rule not found")
                    .with_logical_key(key),
            );
        }
        Ok(())
    }

    fn get_rule(&self, id: &NativeRuleRef) -> Result<Rule, Error> {
        self.state
            .lock()
            .rules
            .get(id.logical_key())
            .cloned()
            .ok_or_else(|| {
                Error::new(ErrorKind::RuleNotFound, "scripted rule not found")
                    .with_logical_key(id.logical_key())
            })
    }

    fn list_rules(&self, filter: &RuleFilter) -> Result<Vec<(NativeRuleRef, Rule)>, Error> {
        let mut state = self.state.lock();
        state.calls.push(BackendCall::List);
        Ok(state
            .rules
            .iter()
            .filter(|(key, rule)| filter.matches(key, rule))
            .map(|(key, rule)| (Self::native_ref(key), rule.clone()))
            .collect())
    }

    fn begin_transaction(&mut self) -> Result<(), Error> {
        let mut state = self.state.lock();
        state.calls.push(BackendCall::Begin);
        if state.transaction_snapshot.is_some() {
            return Err(Error::new(
                ErrorKind::TransactionFailed,
                "scripted transaction already open",
            ));
        }
        state.transaction_snapshot = Some(state.rules.clone());
        Ok(())
    }

    fn commit_transaction(&mut self) -> Result<(), Error> {
        let mut state = self.state.lock();
        state.calls.push(BackendCall::Commit);
        if state.fail_commit {
            return Err(Error::new(
                ErrorKind::TransactionFailed,
                "scripted commit failure",
            ));
        }
        state.transaction_snapshot = None;
        Ok(())
    }

    fn abort_transaction(&mut self) -> Result<(), Error> {
        let mut state = self.state.lock();
        state.calls.push(BackendCall::Abort);
        if state.fail_abort {
            return Err(Error::new(
                ErrorKind::RollbackFailed,
                "scripted abort failure",
            ));
        }
        if let Some(snapshot) = state.transaction_snapshot.take() {
            state.rules = snapshot;
        }
        Ok(())
    }

    fn health_probe(&self, expected_keys: &[RuleKey]) -> Result<HealthSnapshot, Error> {
        Ok(HealthSnapshot::from_present(
            self.state.lock().rules.keys(),
            expected_keys,
        ))
    }

    fn remove_all_managed(&mut self) -> Result<(), Error> {
        let mut state = self.state.lock();
        state.calls.push(BackendCall::RemoveAll);
        if state.fail_remove_all {
            return Err(Error::new(
                ErrorKind::PartialMutation,
                "scripted cleanup failure",
            ));
        }
        state.rules.clear();
        Ok(())
    }

    fn incomplete_keys(&self) -> Result<Vec<RuleKey>, Error> {
        Ok(self.state.lock().fragments.iter().cloned().collect())
    }

    fn take_drift(&mut self) -> Result<Vec<String>, Error> {
        Ok(std::mem::take(&mut self.state.lock().drift))
    }
}
