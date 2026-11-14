//! Local-socket-to-owner map fed by observed flow events and socket snapshots.
//!
//! This is deliberately separate from netmetrics' `WinDivert` endpoint-owner
//! record, which flow consults after this map. That record holds only
//! kernel-reported owners and answers who established an endpoint before a
//! given moment, newest owner winning, and DNS trusts its answers outright.
//! This map holds the pids of live flows, including ETW pids that can be
//! wrong, answers only while a single process claims the socket, and drops a
//! claim when its flow closes. Merging them would either let these pids into
//! the record DNS trusts or lose one of the two answers.

use std::{
    collections::{HashMap, HashSet},
    net::IpAddr,
    num::NonZeroUsize,
    time::{Duration, Instant},
};

use lru::LruCache;
use netmetrics_core::{FlowKey, Protocol};

const CACHE_CAP: usize = 8192;
const ENTRY_TTL: Duration = Duration::from_secs(120);

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct LocalSocketKey {
    protocol: Protocol,
    address: IpAddr,
    port: u16,
}

impl From<&FlowKey> for LocalSocketKey {
    fn from(key: &FlowKey) -> Self {
        Self {
            protocol: key.protocol,
            address: key.local_addr,
            port: key.local_port,
        }
    }
}

#[derive(Debug)]
struct Owners {
    flows_by_pid: HashMap<u32, HashSet<FlowKey>>,
    last_seen: Instant,
}

impl Owners {
    fn new(now: Instant) -> Self {
        Self {
            flows_by_pid: HashMap::new(),
            last_seen: now,
        }
    }

    fn remember(&mut self, key: &FlowKey, pid: u32, now: Instant) {
        for flows in self.flows_by_pid.values_mut() {
            flows.remove(key);
        }
        self.flows_by_pid.retain(|_, flows| !flows.is_empty());
        self.flows_by_pid.entry(pid).or_default().insert(*key);
        self.last_seen = now;
    }

    fn forget(&mut self, key: &FlowKey) {
        for flows in self.flows_by_pid.values_mut() {
            flows.remove(key);
        }
        self.flows_by_pid.retain(|_, flows| !flows.is_empty());
    }

    fn unambiguous_pid(&self) -> Option<u32> {
        let mut owners = self.flows_by_pid.keys().copied();
        let pid = owners.next()?;
        owners.next().is_none().then_some(pid)
    }
}

/// Maps complete local socket identities to PIDs observed owning them.
///
/// Multiple flows may legitimately share a local port. A lookup only succeeds
/// when every live flow on the exact protocol/address/port tuple has the same
/// owner.
///
/// Bounded at [`CACHE_CAP`] sockets. Only [`Self::remember`] counts as use, so
/// when the cache is full the socket seen longest ago is the one dropped, and
/// expired sockets, being the oldest, go first.
#[derive(Debug)]
pub struct PortPidCache {
    entries: LruCache<LocalSocketKey, Owners>,
}

impl Default for PortPidCache {
    fn default() -> Self {
        Self {
            entries: LruCache::new(NonZeroUsize::new(CACHE_CAP).expect("cache cap is nonzero")),
        }
    }
}

impl PortPidCache {
    /// Records `pid` for the complete flow when ETW reports a non-zero owner.
    pub fn remember(&mut self, key: &FlowKey, pid: u32) {
        if pid == 0 || key.local_port == 0 {
            return;
        }
        let now = Instant::now();
        self.entries
            .get_or_insert_mut(LocalSocketKey::from(key), || Owners::new(now))
            .remember(key, pid, now);
    }

    /// Removes only this flow's ownership claim.
    ///
    /// Other flows sharing the local socket continue to protect the mapping
    /// from premature deletion.
    pub fn forget(&mut self, key: &FlowKey) {
        if key.local_port == 0 {
            return;
        }
        let socket = LocalSocketKey::from(key);
        if let Some(owners) = self.entries.peek_mut(&socket) {
            owners.forget(key);
            if owners.flows_by_pid.is_empty() {
                self.entries.pop(&socket);
            }
        }
    }

    /// Returns the sole live PID for this exact local socket.
    ///
    /// Ambiguous and expired entries intentionally return `None` rather than
    /// attributing traffic to the wrong application.
    #[must_use]
    pub fn lookup(&mut self, key: &FlowKey) -> Option<u32> {
        if key.local_port == 0 {
            return None;
        }
        let socket = LocalSocketKey::from(key);
        let owners = self.entries.peek(&socket)?;
        if owners.last_seen.elapsed() >= ENTRY_TTL {
            self.entries.pop(&socket);
            return None;
        }
        owners.unambiguous_pid()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn sample_key() -> FlowKey {
        FlowKey {
            protocol: Protocol::Tcp,
            local_addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            local_port: 44_321,
            remote_addr: IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
            remote_port: 443,
        }
    }

    #[test]
    fn remember_and_lookup_round_trip() {
        let mut cache = PortPidCache::default();
        let key = sample_key();
        cache.remember(&key, 4242);
        assert_eq!(cache.lookup(&key), Some(4242));
    }

    #[test]
    fn forget_removes_stale_port_mapping() {
        let mut cache = PortPidCache::default();
        let key = sample_key();
        cache.remember(&key, 4242);
        cache.forget(&key);
        assert_eq!(cache.lookup(&key), None);
    }

    #[test]
    fn ignores_zero_pid_and_port() {
        let mut cache = PortPidCache::default();
        let key = FlowKey {
            local_port: 0,
            ..sample_key()
        };
        cache.remember(&key, 100);
        assert_eq!(cache.lookup(&key), None);
        cache.remember(&sample_key(), 0);
        assert_eq!(cache.lookup(&sample_key()), None);
    }

    #[test]
    fn forgetting_one_shared_flow_preserves_the_other() {
        let mut cache = PortPidCache::default();
        let first = sample_key();
        let second = FlowKey {
            remote_addr: IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
            remote_port: 53,
            ..first
        };
        cache.remember(&first, 4242);
        cache.remember(&second, 4242);

        cache.forget(&first);

        assert_eq!(cache.lookup(&second), Some(4242));
    }

    #[test]
    fn refuses_ambiguous_shared_socket_ownership() {
        let mut cache = PortPidCache::default();
        let first = sample_key();
        let second = FlowKey {
            remote_addr: IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
            remote_port: 53,
            ..first
        };
        cache.remember(&first, 4242);
        cache.remember(&second, 8484);

        assert_eq!(cache.lookup(&first), None);
        assert_eq!(cache.lookup(&second), None);

        cache.forget(&second);
        assert_eq!(cache.lookup(&first), Some(4242));
    }

    #[test]
    fn distinguishes_same_port_on_different_local_addresses() {
        let mut cache = PortPidCache::default();
        let first = sample_key();
        let second = FlowKey {
            local_addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3)),
            ..first
        };
        cache.remember(&first, 4242);
        cache.remember(&second, 8484);

        assert_eq!(cache.lookup(&first), Some(4242));
        assert_eq!(cache.lookup(&second), Some(8484));
    }

    #[test]
    fn a_full_cache_drops_the_socket_seen_longest_ago() {
        let mut cache = PortPidCache::default();
        let first = FlowKey {
            local_port: 1,
            ..sample_key()
        };
        cache.remember(&first, 4242);

        // Fill the cache exactly to capacity with distinct sockets.
        for port in 2..=u16::try_from(CACHE_CAP).expect("cache cap fits u16") {
            cache.remember(
                &FlowKey {
                    local_port: port,
                    ..sample_key()
                },
                4242,
            );
        }
        assert_eq!(cache.entries.len(), CACHE_CAP);

        let newest = FlowKey {
            local_port: u16::try_from(CACHE_CAP).expect("port") + 1,
            ..sample_key()
        };
        cache.remember(&newest, 4242);

        assert!(cache.entries.len() <= CACHE_CAP);
        assert_eq!(
            cache.lookup(&first),
            None,
            "the oldest entry must be evicted to make room"
        );
        assert_eq!(cache.lookup(&newest), Some(4242));
    }
}
