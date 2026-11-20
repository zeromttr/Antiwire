//! Addresses that new DNS evidence has arrived for.
//!
//! A connection's name can only change when something new is known about its
//! address, so the tracker looks an unconfirmed connection up again when its
//! address appears here, and not on a timer.

use std::collections::HashMap;
use std::net::IpAddr;

use netmetrics_core::canonicalize_ip;

use super::FlowProcessor;

/// Addresses remembered between two of the tracker's flushes. Past this, every
/// unconfirmed connection is looked up once instead.
const NEWLY_NAMED_CAP: usize = 8_192;

/// The addresses DNS evidence arrived for since the tracker last asked, and
/// when it arrived.
///
/// A name takes a correction only for so long after its connection opened,
/// and the tracker asks a flush tick after the evidence arrived, or later
/// when it is busy. So evidence is judged by when it arrived: asked about
/// just past a name's time, evidence that came within it still counts.
#[derive(Debug, Default)]
pub(crate) struct NewlyNamed {
    /// When evidence first arrived for each address, in Unix epoch
    /// milliseconds.
    addresses: HashMap<IpAddr, u64>,
    /// Set once more addresses arrived than are remembered, so any may have:
    /// when the first evidence of all arrived.
    overflowed_at_ms: Option<u64>,
}

impl NewlyNamed {
    /// Whether no evidence arrived at all.
    pub(crate) fn is_empty(&self) -> bool {
        self.addresses.is_empty() && self.overflowed_at_ms.is_none()
    }

    /// When evidence first arrived for `address`, or may have, in Unix epoch
    /// milliseconds. `None` when none did.
    pub(crate) fn arrived_at(&self, address: IpAddr) -> Option<u64> {
        self.overflowed_at_ms
            .or_else(|| self.addresses.get(&canonicalize_ip(address)).copied())
    }

    /// Evidence for `address` arrived at `arrived_ms`, in Unix epoch
    /// milliseconds.
    pub(super) fn note(&mut self, address: IpAddr, arrived_ms: u64) {
        if let Some(first) = &mut self.overflowed_at_ms {
            *first = (*first).min(arrived_ms);
            return;
        }
        let address = canonicalize_ip(address);
        if let Some(first) = self.addresses.get_mut(&address) {
            *first = (*first).min(arrived_ms);
            return;
        }
        if self.addresses.len() >= NEWLY_NAMED_CAP {
            let first = self.addresses.drain().map(|(_, at_ms)| at_ms).min();
            self.overflowed_at_ms = Some(first.map_or(arrived_ms, |at_ms| at_ms.min(arrived_ms)));
            return;
        }
        self.addresses.insert(address, arrived_ms);
    }
}

impl FlowProcessor {
    /// Remembers that evidence naming `addresses` was just recorded.
    ///
    /// Call it after the evidence is where a lookup reads it. A lookup the
    /// tracker starts on seeing an address here must find what was recorded,
    /// since nothing prompts another.
    pub(super) fn note_named(&self, addresses: impl IntoIterator<Item = IpAddr>) {
        self.note_named_at(addresses, netmetrics_core::unix_now_ms());
    }

    /// [`Self::note_named`] for evidence that arrived at `arrived_ms`, in
    /// Unix epoch milliseconds.
    pub(crate) fn note_named_at(
        &self,
        addresses: impl IntoIterator<Item = IpAddr>,
        arrived_ms: u64,
    ) {
        let mut named = self.newly_named.lock();
        for address in addresses {
            named.note(address, arrived_ms);
        }
    }

    /// Takes the addresses DNS evidence arrived for since the last call.
    pub(crate) fn take_newly_named(&self) -> NewlyNamed {
        std::mem::take(&mut *self.newly_named.lock())
    }

    /// When evidence the tracker has not asked about yet arrived for
    /// `address`, in Unix epoch milliseconds. A connection that closes before
    /// the tracker next asks has only this to tell it the evidence is there.
    pub(crate) fn evidence_not_yet_taken(&self, address: IpAddr) -> Option<u64> {
        self.newly_named.lock().arrived_at(address)
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
        named.note(
            IpAddr::V6(Ipv4Addr::new(203, 0, 113, 9).to_ipv6_mapped()),
            5_000,
        );
        assert!(!named.is_empty());
        assert_eq!(
            named.arrived_at(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9))),
            Some(5_000)
        );
        assert_eq!(named.arrived_at(address(1)), None);
    }

    #[test]
    fn an_address_is_named_from_when_its_first_evidence_arrived() {
        let mut named = NewlyNamed::default();
        named.note(address(1), 5_000);
        named.note(address(1), 9_000);
        named.note(address(2), 7_000);
        assert_eq!(named.arrived_at(address(1)), Some(5_000));
        assert_eq!(named.arrived_at(address(2)), Some(7_000));
    }

    #[test]
    fn past_the_cap_every_address_may_have_been_named() {
        let mut named = NewlyNamed::default();
        for index in 0..=u32::try_from(NEWLY_NAMED_CAP).expect("small cap") {
            named.note(address(index), 5_000 + u64::from(index));
        }
        assert_eq!(
            named.arrived_at(address(4_000_000)),
            Some(5_000),
            "any address may have been named, as early as the first was"
        );
        assert!(!named.is_empty());
        assert!(
            named.addresses.is_empty(),
            "the overflow holds no addresses"
        );
    }
}
