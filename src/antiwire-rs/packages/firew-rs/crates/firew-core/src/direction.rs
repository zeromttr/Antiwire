//! Traffic direction matchers.

/// Packet flow direction relative to the host.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, serde::Serialize, serde::Deserialize)]
pub enum Direction {
    /// Incoming traffic.
    Inbound,
    /// Outgoing traffic.
    Outbound,
    /// Both directions (split into inbound/outbound native rules when required).
    Both,
}
