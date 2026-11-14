//! Mock backend for contract tests.

use std::collections::HashMap;

use firew_core::{Error, ErrorKind, Rule, RuleKey};

use crate::backend::Backend;
use crate::config::BackendConfig;
use crate::filter::RuleFilter;
use crate::health::HealthSnapshot;
use crate::native_ref::NativeRuleRef;

/// In-memory mock backend for deterministic tests.
#[derive(Debug, Default)]
pub struct MockBackend {
    rules: HashMap<RuleKey, Rule>,
    /// Rules as they stood when the open transaction began; restored on abort.
    transaction_snapshot: Option<HashMap<RuleKey, Rule>>,
}

impl MockBackend {
    /// Creates an empty mock backend.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

impl Backend for MockBackend {
    fn open(_config: &BackendConfig) -> Result<Self, Error> {
        Ok(Self::new())
    }

    fn name(&self) -> &'static str {
        "mock"
    }

    fn supports_transactions(&self) -> bool {
        true
    }

    fn add_rule(&mut self, rule: &Rule) -> Result<NativeRuleRef, Error> {
        let key = rule.logical_key().clone();
        if self.rules.contains_key(&key) {
            return Err(
                Error::new(ErrorKind::InvalidRule, "duplicate rule key").with_logical_key(key)
            );
        }
        self.rules.insert(key.clone(), rule.clone());
        Ok(NativeRuleRef::new("mock", key.to_string(), key))
    }

    fn update_rule(&mut self, id: &NativeRuleRef, rule: &Rule) -> Result<NativeRuleRef, Error> {
        let key = id.logical_key().clone();
        let existing = self
            .rules
            .get_mut(&key)
            .ok_or_else(|| crate::rule_not_found(&key))?;
        *existing = rule.clone();
        Ok(NativeRuleRef::new("mock", key.to_string(), key))
    }

    fn remove_rule(&mut self, id: &NativeRuleRef) -> Result<(), Error> {
        if self.rules.remove(id.logical_key()).is_none() {
            return Err(crate::rule_not_found(id.logical_key()));
        }
        Ok(())
    }

    fn get_rule(&self, id: &NativeRuleRef) -> Result<Rule, Error> {
        self.rules
            .get(id.logical_key())
            .cloned()
            .ok_or_else(|| crate::rule_not_found(id.logical_key()))
    }

    fn list_rules(&self, filter: &RuleFilter) -> Result<Vec<(NativeRuleRef, Rule)>, Error> {
        let mut out = Vec::new();
        for (key, rule) in &self.rules {
            if !filter.matches(key, rule) {
                continue;
            }
            out.push((
                NativeRuleRef::new("mock", key.to_string(), key.clone()),
                rule.clone(),
            ));
        }
        Ok(out)
    }

    fn begin_transaction(&mut self) -> Result<(), Error> {
        if self.transaction_snapshot.is_some() {
            return Err(Error::new(
                ErrorKind::TransactionFailed,
                "transaction already open",
            ));
        }
        self.transaction_snapshot = Some(self.rules.clone());
        Ok(())
    }

    fn commit_transaction(&mut self) -> Result<(), Error> {
        self.transaction_snapshot = None;
        Ok(())
    }

    fn abort_transaction(&mut self) -> Result<(), Error> {
        if let Some(snapshot) = self.transaction_snapshot.take() {
            self.rules = snapshot;
        }
        Ok(())
    }

    fn health_probe(&self, expected_keys: &[RuleKey]) -> Result<HealthSnapshot, Error> {
        Ok(HealthSnapshot::from_present(
            self.rules.keys(),
            expected_keys,
        ))
    }

    fn remove_all_managed(&mut self) -> Result<(), Error> {
        self.rules.clear();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use firew_core::{Action, Direction, Rule};
    use ipnet::IpNet;
    use std::net::IpAddr;

    fn host_net(host: &str) -> IpNet {
        IpNet::from(host.parse::<IpAddr>().expect("ip"))
    }

    #[test]
    fn mock_crud_round_trip() {
        let config = BackendConfig::new("test");
        let mut backend = MockBackend::open(&config).expect("open");
        let rule = Rule::builder("k1", Action::Block, Direction::Outbound)
            .remote_address(host_net("1.1.1.1"))
            .build()
            .expect("rule");
        let id = backend.add_rule(&rule).expect("add");
        let fetched = backend.get_rule(&id).expect("get");
        assert_eq!(fetched.logical_key(), "k1");
        backend.remove_rule(&id).expect("remove");
    }

    #[test]
    fn mock_abort_restores_rules_from_before_the_transaction() {
        let mut backend = MockBackend::new();
        let kept = Rule::builder("kept", Action::Block, Direction::Outbound)
            .remote_address(host_net("192.0.2.1"))
            .build()
            .expect("rule");
        let added = Rule::builder("added", Action::Block, Direction::Outbound)
            .remote_address(host_net("192.0.2.2"))
            .build()
            .expect("rule");
        backend.add_rule(&kept).expect("add kept");

        backend.begin_transaction().expect("begin");
        backend.add_rule(&added).expect("add in transaction");
        backend.abort_transaction().expect("abort");

        let keys: Vec<_> = backend
            .list_rules(&RuleFilter::new())
            .expect("list")
            .into_iter()
            .map(|(native, _)| native.logical_key().clone())
            .collect();
        assert_eq!(keys, vec![kept.logical_key().clone()]);
    }
}
