//! Addresses that new DNS evidence has arrived for.
//!
//! A connection's name can only change when something new is known about its
//! address, so the tracker looks an unconfirmed connection up again when its
//! address appears here, and not on a timer.

use std::collections::HashSet;
use std::net::IpAddr;

use netmetrics_core::canonicalize_ip;

use super::FlowProcessor;

/// Addresses remembered between two of the tracker's flushes. Past this, every
/// unconfirmed connection is looked up once instead.
const NEWLY_NAMED_CAP: usize = 8_192;

/// The addresses DNS evidence arrived for since the tracker last asked.
#[derive(Debug, Default)]
pub(crate) struct NewlyNamed {
    addresses: HashSet<IpAddr>,
    /// More addresses arrived than are remembered, so any may have.
    overflowed: bool,
}

impl NewlyNamed {
    /// Whether no evidence arrived at all.
    pub(crate) fn is_empty(&self) -> bool {
        self.addresses.is_empty() && !self.overflowed
    }

    /// Whether evidence arrived, or may have, for `address`.
    pub(crate) fn names(&self, address: IpAddr) -> bool {
        self.overflowed || self.addresses.contains(&canonicalize_ip(address))
    }

    fn note(&mut self, address: IpAddr) {
        if self.overflowed {
            return;
        }
        if self.addresses.len() >= NEWLY_NAMED_CAP {
            self.addresses.clear();
            self.overflowed = true;
            return;
        }
        self.addresses.insert(canonicalize_ip(address));
    }
}

impl FlowProcessor {
    /// Remembers that evidence naming `addresses` was just recorded.
    ///
    /// Call it after the evidence is where a lookup reads it. A lookup the
    /// tracker starts on seeing an address here must find what was recorded,
    /// since nothing prompts another.
    pub(super) fn note_named(&self, addresses: impl IntoIterator<Item = IpAddr>) {
        let mut named = self.newly_named.lock();
        for address in addresses {
            named.note(address);
        }
    }

    /// Takes the addresses DNS evidence arrived for since the last call.
    pub(crate) fn take_newly_named(&self) -> NewlyNamed {
        std::mem::take(&mut *self.newly_named.lock())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn address(index: u32) -> IpAddr {
        IpAddr::V4(Ipv4Addr::from(0x0A00_0000 + index))
    }

    #[test]
    fn an_address_is_named_in_either_spelling() {
        let mut named = NewlyNamed::default();
        assert!(named.is_empty());
        named.note(IpAddr::V6(Ipv4Addr::new(203, 0, 113, 9).to_ipv6_mapped()));
        assert!(!named.is_empty());
        assert!(named.names(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9))));
        assert!(!named.names(address(1)));
    }

    #[test]
    fn past_the_cap_every_address_may_have_been_named() {
        let mut named = NewlyNamed::default();
        for index in 0..=u32::try_from(NEWLY_NAMED_CAP).expect("small cap") {
            named.note(address(index));
        }
        assert!(named.names(address(4_000_000)));
        assert!(!named.is_empty());
        assert!(
            named.addresses.is_empty(),
            "the overflow holds no addresses"
        );
    }
}
