//! In-memory rule registry for memory-mode lifecycle.

use std::collections::{BTreeMap, HashMap};

use crate::{Rule, RuleKey};

/// Tracks rules installed through the library for deterministic cleanup.
#[derive(Clone, Debug, Default)]
pub struct RuleRegistry {
    by_key: HashMap<RuleKey, (u64, Rule)>,
    order: BTreeMap<u64, RuleKey>,
    next_seq: u64,
}

impl RuleRegistry {
    /// Creates an empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers a rule by logical key.
    pub fn register(&mut self, rule: Rule) {
        if let Some((_, existing)) = self.by_key.get_mut(rule.logical_key()) {
            *existing = rule;
            return;
        }

        let seq = self.next_seq;
        self.next_seq += 1;
        let key = rule.logical_key().clone();
        self.order.insert(seq, key.clone());
        self.by_key.insert(key, (seq, rule));
    }

    /// Removes a rule by logical key.
    pub fn unregister(&mut self, logical_key: &RuleKey) -> Option<Rule> {
        let (seq, rule) = self.by_key.remove(logical_key)?;
        self.order.remove(&seq);
        Some(rule)
    }

    /// Returns a rule by logical key.
    #[must_use]
    pub fn get(&self, logical_key: &RuleKey) -> Option<&Rule> {
        self.by_key.get(logical_key).map(|(_, rule)| rule)
    }

    /// Snapshot of all registered rules in insertion order.
    #[must_use]
    pub fn snapshot(&self) -> Vec<(RuleKey, Rule)> {
        self.rules()
            .map(|rule| (rule.logical_key().clone(), rule.clone()))
            .collect()
    }

    /// Iterates over registered rules in insertion order without cloning them.
    pub fn rules(&self) -> impl Iterator<Item = &Rule> {
        self.order
            .values()
            .filter_map(|key| self.by_key.get(key).map(|(_, rule)| rule))
    }

    /// Number of registered rules.
    #[must_use]
    pub fn len(&self) -> usize {
        self.by_key.len()
    }

    /// Whether the registry is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.by_key.is_empty()
    }

    /// Clears all entries.
    pub fn clear(&mut self) {
        self.by_key.clear();
        self.order.clear();
        self.next_seq = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Action, Direction, Rule};
    use ipnet::IpNet;
    use std::net::IpAddr;

    fn host_net(host: &str) -> IpNet {
        IpNet::from(host.parse::<IpAddr>().expect("ip"))
    }

    #[test]
    fn snapshot_preserves_order() {
        let mut registry = RuleRegistry::new();
        for key in ["a", "b", "c"] {
            let rule = Rule::builder(key, Action::Block, Direction::Outbound)
                .remote_address(host_net("1.1.1.1"))
                .build()
                .expect("rule");
            registry.register(rule);
        }
        let snap = registry.snapshot();
        assert_eq!(snap.len(), 3);
        assert_eq!(snap[0].0, "a");
        assert_eq!(snap[2].0, "c");
    }
}
