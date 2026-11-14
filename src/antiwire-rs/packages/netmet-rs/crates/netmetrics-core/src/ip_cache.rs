use std::collections::HashMap;
use std::net::IpAddr;

/// Allocation-free-after-warmup IP address interning table.
#[derive(Debug)]
pub struct IpCache {
    ids: HashMap<IpAddr, u32>,
    values: Vec<IpAddr>,
    max_entries: usize,
}

impl IpCache {
    /// Creates a cache with stable IDs from zero up to `max_entries - 1`.
    ///
    /// # Panics
    ///
    /// Panics when `max_entries` is zero.
    pub fn new(max_entries: usize) -> Self {
        assert!(max_entries > 0, "IP cache capacity must be non-zero");
        Self {
            ids: HashMap::with_capacity(max_entries.min(4096)),
            values: Vec::with_capacity(max_entries.min(4096)),
            max_entries,
        }
    }

    /// Returns the existing ID or interns a new address. Returns `None` when full.
    pub fn intern(&mut self, address: IpAddr) -> Option<u32> {
        if let Some(id) = self.ids.get(&address) {
            return Some(*id);
        }
        if self.values.len() >= self.max_entries || self.values.len() > u32::MAX as usize {
            return None;
        }
        let id = u32::try_from(self.values.len()).ok()?;
        self.values.push(address);
        self.ids.insert(address, id);
        Some(id)
    }

    /// Resolves an interned ID.
    pub fn resolve(&self, id: u32) -> Option<IpAddr> {
        self.values.get(id as usize).copied()
    }

    /// Returns the number of interned addresses.
    pub fn len(&self) -> usize {
        self.values.len()
    }

    /// Returns true when the cache is empty.
    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv6Addr};

    #[test]
    fn ids_are_stable_and_capacity_is_enforced() {
        let first = IpAddr::V6(Ipv6Addr::LOCALHOST);
        let second = IpAddr::V6(Ipv6Addr::UNSPECIFIED);
        let mut cache = IpCache::new(1);
        assert_eq!(cache.intern(first), Some(0));
        assert_eq!(cache.intern(first), Some(0));
        assert_eq!(cache.intern(second), None);
        assert_eq!(cache.resolve(0), Some(first));
    }
}
