//! Rule listing filters.

use firew_core::{Direction, Rule, RuleKey};

/// Filter for listing native rules.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RuleFilter {
    /// Match logical keys starting with this prefix.
    pub key_prefix: Option<RuleKey>,
    /// Match rules that cover this direction. A [`Direction::Both`] rule covers
    /// both inbound and outbound, so it passes either filter.
    pub direction: Option<Direction>,
}

impl RuleFilter {
    /// Creates an empty filter matching all managed rules.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Matches keys with the given prefix.
    #[must_use]
    pub fn with_key_prefix(mut self, prefix: RuleKey) -> Self {
        self.key_prefix = Some(prefix);
        self
    }

    /// Matches the given direction.
    #[must_use]
    pub fn with_direction(mut self, direction: Direction) -> Self {
        self.direction = Some(direction);
        self
    }

    /// Whether the rule stored under `key` passes this filter.
    #[must_use]
    pub fn matches(&self, key: &RuleKey, rule: &Rule) -> bool {
        self.key_prefix
            .as_ref()
            .is_none_or(|prefix| key.as_str().starts_with(prefix.as_str()))
            && self
                .direction
                .is_none_or(|direction| covers(rule.direction(), direction))
    }
}

/// Whether a rule in direction `rule` applies to traffic in direction `wanted`.
fn covers(rule: Direction, wanted: Direction) -> bool {
    rule == wanted || rule == Direction::Both
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use firew_core::{Action, PortRange, Protocol};

    use super::*;

    fn rule(key: &str, direction: Direction) -> (RuleKey, Rule) {
        let rule = Rule::builder(key, Action::Block, direction)
            .protocol(Protocol::Tcp)
            .remote_port(PortRange::single(443).expect("port"))
            .build()
            .expect("rule");
        (rule.logical_key().clone(), rule)
    }

    #[test]
    fn matches_on_key_prefix_and_direction() {
        let (key, outbound) = rule("app-web", Direction::Outbound);
        assert!(RuleFilter::new().matches(&key, &outbound));
        let prefix = RuleKey::from_str("app").expect("prefix");
        assert!(RuleFilter::new()
            .with_key_prefix(prefix.clone())
            .with_direction(Direction::Outbound)
            .matches(&key, &outbound));
        assert!(!RuleFilter::new()
            .with_direction(Direction::Inbound)
            .matches(&key, &outbound));
        let (both_key, both) = rule("app-both", Direction::Both);
        for direction in [Direction::Inbound, Direction::Outbound, Direction::Both] {
            assert!(RuleFilter::new()
                .with_direction(direction)
                .matches(&both_key, &both));
        }
        assert!(!RuleFilter::new()
            .with_direction(Direction::Both)
            .matches(&key, &outbound));
        let other = RuleKey::from_str("other").expect("prefix");
        assert!(!RuleFilter::new()
            .with_key_prefix(other)
            .matches(&key, &outbound));
    }
}
