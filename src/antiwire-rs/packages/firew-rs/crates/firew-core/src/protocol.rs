//! IP protocol matchers.

use serde::{Deserialize, Deserializer, Serialize};

/// Network protocol selector.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize)]
pub enum Protocol {
    /// Any protocol.
    Any,
    /// TCP.
    Tcp,
    /// UDP.
    Udp,
    /// ICMP for IPv4.
    IcmpV4,
    /// ICMP for IPv6.
    IcmpV6,
    /// Explicit protocol number.
    Other(u8),
}

impl Protocol {
    /// Canonicalizes numeric protocol selectors that correspond to dedicated
    /// [`Protocol`] variants (`6` -> [`Self::Tcp`], `17` -> [`Self::Udp`],
    /// `1` -> [`Self::IcmpV4`], `58` -> [`Self::IcmpV6`]).
    #[must_use]
    pub const fn canonicalize(self) -> Self {
        match self {
            Self::Other(6) => Self::Tcp,
            Self::Other(17) => Self::Udp,
            Self::Other(1) => Self::IcmpV4,
            Self::Other(58) => Self::IcmpV6,
            other => other,
        }
    }

    /// Returns the numeric protocol id when known.
    #[must_use]
    pub fn number(self) -> Option<u8> {
        match self {
            Self::Tcp => Some(6),
            Self::Udp => Some(17),
            Self::IcmpV4 => Some(1),
            Self::IcmpV6 => Some(58),
            Self::Other(n) => Some(n),
            Self::Any => None,
        }
    }
}

impl<'de> Deserialize<'de> for Protocol {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        enum RawProtocol {
            Any,
            Tcp,
            Udp,
            IcmpV4,
            IcmpV6,
            Other(u8),
        }

        let raw = RawProtocol::deserialize(deserializer)?;
        let protocol = match raw {
            RawProtocol::Any => Self::Any,
            RawProtocol::Tcp => Self::Tcp,
            RawProtocol::Udp => Self::Udp,
            RawProtocol::IcmpV4 => Self::IcmpV4,
            RawProtocol::IcmpV6 => Self::IcmpV6,
            RawProtocol::Other(n) => Self::Other(n),
        };
        Ok(protocol.canonicalize())
    }
}
