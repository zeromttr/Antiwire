//! Short-TTL PID cache for live process lookups.

use std::time::Duration;

use antiwire_tuning::{PROCESS_CACHE_CAP, PROCESS_CACHE_TTL_MS};
use moka::policy::EvictionPolicy;
use moka::sync::Cache;

use super::ResolvedIdentity;

pub(crate) fn build_cache(
    max_capacity: u64,
    time_to_live: Duration,
) -> Cache<u32, ResolvedIdentity> {
    Cache::builder()
        .max_capacity(max_capacity)
        .time_to_live(time_to_live)
        .eviction_policy(EvictionPolicy::lru())
        .build()
}

/// A per-PID identity cache with the configured capacity and TTL. The live
/// lookup cache and the `svchost` and `rundll32` disambiguations all use it:
/// each answer is only valid while the PID's creation timestamp matches.
pub(crate) fn identity_cache() -> Cache<u32, ResolvedIdentity> {
    build_cache(
        PROCESS_CACHE_CAP,
        Duration::from_millis(PROCESS_CACHE_TTL_MS),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity(path: &str, name: &str, start_ts: u64) -> ResolvedIdentity {
        ResolvedIdentity {
            path: path.to_owned(),
            name: name.to_owned(),
            start_ts,
        }
    }

    #[test]
    fn cache_round_trips_within_ttl() {
        let cache = build_cache(4, Duration::from_secs(60));
        cache.insert(99_001, identity(r"C:\tool.exe", "tool.exe", 1234));

        let cached = cache.get(&99_001).expect("cached");
        assert_eq!(cached.path, r"C:\tool.exe");
        assert_eq!(cached.name, "tool.exe");
        assert_eq!(cached.start_ts, 1234);
    }

    #[test]
    fn cache_expires_entries_after_ttl() {
        let cache = build_cache(4, Duration::from_millis(10));
        cache.insert(1, identity("path", "name.exe", 0));

        std::thread::sleep(Duration::from_millis(25));

        assert!(cache.get(&1).is_none());
    }

    #[test]
    fn cache_is_bounded_and_retains_recent_entries() {
        let cache = build_cache(2, Duration::from_secs(60));
        cache.insert(1, identity("path-1", "name-1.exe", 0));
        cache.insert(2, identity("path-2", "name-2.exe", 0));
        cache.run_pending_tasks();

        assert!(cache.get(&1).is_some());
        cache.run_pending_tasks();
        cache.insert(3, identity("path-3", "name-3.exe", 0));
        cache.run_pending_tasks();

        assert!(cache.entry_count() <= 2);
        assert!(cache.get(&1).is_some());
        assert!(cache.get(&2).is_none());
        assert!(cache.get(&3).is_some());
    }

    #[test]
    fn forget_invalidates_cached_identity() {
        let cache = build_cache(4, Duration::from_secs(60));
        let pid = 99_002;
        cache.insert(pid, identity(r"C:\tool.exe", "tool.exe", 0));
        assert!(cache.get(&pid).is_some());

        cache.invalidate(&pid);

        assert!(cache.get(&pid).is_none());
    }
}
