//! Process identity captured when a flow is established.
//!
//! Kernel ETW often omits the payload PID. A connect-time owner, keyed by the
//! 5-tuple, fills that gap before the socket disappears from the owner tables.

use std::time::{Duration, Instant};

use netmetrics_core::{FlowKey, ProcessIdentity, ProcessInfo, expiring_map::ExpiringMap};

/// How long an established flow's owner stays usable after its last observation.
const RETENTION: Duration = Duration::from_secs(30);
/// How long a deleted flow's owner remains visible to a late event.
///
/// This is a hard cap: a second delete must not push the deadline out again.
const DELETE_GRACE: Duration = Duration::from_secs(5);
/// Bound on retained flow owners.
const CAPACITY: usize = 8_192;

/// Owner recorded for one established flow.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct FlowOwner {
    /// Process that created the flow.
    pub pid: u32,
    /// Executable path captured while the process was alive.
    pub executable: String,
    /// File name from `executable`.
    pub name: String,
    /// Process creation time, Unix epoch milliseconds. Zero when unknown.
    pub start_ts: u64,
}

impl FlowOwner {
    /// Process identity for the collector, when a path was captured.
    pub(crate) fn process_info(&self) -> Option<ProcessInfo> {
        if self.executable.is_empty() || self.pid == 0 {
            return None;
        }
        Some(ProcessInfo {
            pid: self.pid,
            identity: ProcessIdentity {
                executable: self.executable.clone(),
                name: self.name.clone(),
                start_ts: self.start_ts,
            },
        })
    }
}

/// Bounded `5-tuple -> owner` memory shared by the flow listener and ETW decode.
#[derive(Debug, Default)]
pub(crate) struct FlowOwnerCache {
    /// Each owner with the time it was recorded.
    entries: ExpiringMap<FlowKey, (FlowOwner, Instant), CAPACITY>,
}

/// An owner found for a flow, and how the record relates to it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct FoundOwner {
    pub owner: FlowOwner,
    /// The record is under the flow's addresses swapped. Between two local
    /// endpoints that is the other end's owner.
    pub reversed: bool,
    /// How long ago the owner was recorded.
    pub age: Duration,
}

impl FlowOwnerCache {
    /// Records the owner of `key` until it is removed or expires.
    pub(crate) fn insert(&mut self, key: FlowKey, owner: FlowOwner, now: Instant) {
        if owner.pid == 0 {
            return;
        }
        self.entries.expire(now);
        let expires_at = now.checked_add(RETENTION).unwrap_or(now);
        self.entries.insert(key, (owner, now), expires_at);
    }

    /// Keeps a deleted flow's owner for [`DELETE_GRACE`] and no longer.
    ///
    /// A deadline that is already inside that window is left alone, so a
    /// repeated delete cannot stretch the grace.
    pub(crate) fn retain_after_delete(&mut self, key: &FlowKey, now: Instant) {
        let grace_end = now.checked_add(DELETE_GRACE).unwrap_or(now);
        if self.cap_expiry(key, grace_end) {
            return;
        }
        let reversed = key.reverse();
        self.cap_expiry(&reversed, grace_end);
    }

    /// Returns the owner of `key`, trying the reversed tuple when the first misses.
    pub(crate) fn lookup(&mut self, key: &FlowKey, now: Instant) -> Option<FlowOwner> {
        self.find(key, now).map(|found| found.owner)
    }

    /// [`Self::lookup`], with which way round the record matched and its age.
    pub(crate) fn find(&mut self, key: &FlowKey, now: Instant) -> Option<FoundOwner> {
        self.entries.expire(now);
        let found = |(owner, recorded): (FlowOwner, Instant), reversed| FoundOwner {
            owner,
            reversed,
            age: now.saturating_duration_since(recorded),
        };
        self.lookup_live(key)
            .map(|record| found(record, false))
            .or_else(|| {
                self.lookup_live(&key.reverse())
                    .map(|record| found(record, true))
            })
    }

    #[cfg(test)]
    pub(crate) fn contains_pid(&mut self, pid: u32, now: Instant) -> bool {
        self.entries.expire(now);
        self.entries.values().any(|(owner, _)| owner.pid == pid)
    }

    fn lookup_live(&self, key: &FlowKey) -> Option<(FlowOwner, Instant)> {
        self.entries.get(key).cloned()
    }

    /// Pulls `key`'s deadline back to `deadline` when it is later than that.
    fn cap_expiry(&mut self, key: &FlowKey, deadline: Instant) -> bool {
        let Some(expires_at) = self.entries.deadline(key) else {
            return false;
        };
        if expires_at > deadline {
            self.entries.set_deadline(key, deadline);
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn key(port: u16) -> FlowKey {
        FlowKey {
            protocol: netmetrics_core::Protocol::Tcp,
            local_addr: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
            local_port: port,
            remote_addr: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5)),
            remote_port: 443,
        }
    }

    fn owner(pid: u32) -> FlowOwner {
        FlowOwner {
            pid,
            executable: r"C:\apps\browser.exe".to_owned(),
            name: "browser.exe".to_owned(),
            start_ts: 50,
        }
    }

    #[test]
    fn lookup_matches_either_orientation() {
        let mut cache = FlowOwnerCache::default();
        let now = Instant::now();
        let forward = key(40_000);
        cache.insert(forward, owner(42), now);
        let found = cache
            .lookup(&forward.reverse(), now)
            .expect("reverse tuple");
        assert_eq!(found.pid, 42);
        assert!(found.process_info().is_some());
    }

    #[test]
    fn expired_and_zero_pid_owners_are_not_returned() {
        let mut cache = FlowOwnerCache::default();
        let now = Instant::now();
        cache.insert(key(40_001), owner(7), now);
        assert!(
            cache
                .lookup(&key(40_001), now + RETENTION + Duration::from_millis(1))
                .is_none()
        );
        cache.insert(key(40_002), owner(0), now);
        assert!(cache.lookup(&key(40_002), now).is_none());
    }

    #[test]
    fn deleted_owner_lasts_a_few_seconds_and_no_longer() {
        let mut cache = FlowOwnerCache::default();
        let now = Instant::now();
        let flow = key(40_003);
        cache.insert(flow, owner(42), now);

        cache.retain_after_delete(&flow.reverse(), now);
        let still_kept = (now + DELETE_GRACE)
            .checked_sub(Duration::from_millis(1))
            .expect("inside the grace");
        assert_eq!(cache.lookup(&flow, still_kept).unwrap().pid, 42);

        let later = now + Duration::from_secs(2);
        cache.retain_after_delete(&flow, later);
        assert!(
            cache.lookup(&flow, now + DELETE_GRACE).is_none(),
            "the grace ends at five seconds and a second delete does not extend it"
        );
    }
}
