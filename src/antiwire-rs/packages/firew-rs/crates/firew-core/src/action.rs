//! Firewall rule action.

/// Traffic disposition applied by a rule.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, serde::Serialize, serde::Deserialize)]
pub enum Action {
    /// Permit matching traffic.
    Allow,
    /// Drop matching traffic silently.
    Block,
    /// Reject matching traffic with an ICMP/port unreachable response when supported.
    Reject,
}

impl Action {
    /// Returns whether this action blocks traffic.
    #[must_use]
    pub fn is_block(self) -> bool {
        matches!(self, Self::Block | Self::Reject)
    }
}
