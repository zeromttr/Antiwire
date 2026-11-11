//! Socket-table snapshots shared between owner lookups.
//!
//! Reading the host's socket tables costs tens to hundreds of microseconds, so
//! a caller that names the owner of every query or flow cannot scan once per
//! lookup. A [`SocketOwnerCache`] keeps the newest snapshot of each protocol's
//! tables, runs at most one scan per protocol at a time, and lets every lookup
//! that a scan can answer share it.
//!
//! A snapshot taken before an event cannot prove the event's socket absent,
//! because the socket may have been opened after the scan. So a lookup trusts
//! a snapshot taken at or after the event for any answer, and one taken before
//! it only for a hit, and only while the snapshot is younger than the refresh
//! interval. Anything else needs a scan, and [`SocketOwnerCache::owner`] starts
//! at most one per refresh interval.
//!
//! On Windows each protocol has its own tables, and a UDP scan skips the TCP
//! ones, which cost several times as much. Elsewhere a scan reads every socket
//! anyway, so both protocols share one snapshot.

use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError, RwLock};
use std::time::{Duration, Instant};

use netmetrics_core::{LocalEndpoint, Ownership, Protocol, SocketOwnerSnapshot};

/// How often [`SocketOwnerCache::shared`] lets lookups start a scan.
pub const DEFAULT_REFRESH: Duration = Duration::from_millis(250);

/// Reads one protocol's socket owners. [`crate::socket_owner_snapshot_for`]
/// is the default.
pub type Scanner = fn(Protocol) -> SocketOwnerSnapshot;

/// Whether a lookup that needs a scan may block for one.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Wait {
    /// Never block. A lookup that needs a scan returns [`Pending::Busy`] when
    /// another scan is running or, for [`SocketOwnerCache::owner`], when the
    /// refresh interval has not passed since the last one started.
    Never,
    /// Wait for a running scan, or for the refresh interval to allow the next,
    /// until this instant, after which a new scan's answer is no longer
    /// wanted: past it the lookup neither waits nor starts a scan, and returns
    /// [`Pending::DeadlinePassed`]. A scan already started is not cut short.
    Until(Instant),
}

/// Why a lookup returned without an answer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Pending {
    /// It needed a scan it could not start without waiting, under [`Wait::Never`].
    Busy,
    /// It needed a scan it could not get before its [`Wait::Until`] deadline.
    DeadlinePassed,
}

impl Wait {
    fn passed(self, now: Instant) -> bool {
        matches!(self, Self::Until(deadline) if now >= deadline)
    }
}

impl fmt::Display for Pending {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Busy => "a socket-table scan is needed but cannot start without waiting",
            Self::DeadlinePassed => "a socket-table scan could not be had before the deadline",
        })
    }
}

impl std::error::Error for Pending {}

/// One socket-table snapshot and the moment its scan started.
#[derive(Debug)]
pub struct CachedSnapshot {
    owners: SocketOwnerSnapshot,
    captured_at: Instant,
}

impl CachedSnapshot {
    /// The socket owners the scan found.
    pub fn owners(&self) -> &SocketOwnerSnapshot {
        &self.owners
    }

    /// When the scan started. A socket opened before then and still open when
    /// the scan read its table is in [`Self::owners`]; one opened while the
    /// scan ran may not be.
    pub fn captured_at(&self) -> Instant {
        self.captured_at
    }
}

/// Newest snapshot of each protocol's socket owners, shared between lookups.
///
/// Every method is safe to call from many threads at once. A lookup the
/// newest snapshot answers takes one uncontended read lock and does not scan.
pub struct SocketOwnerCache<S = Scanner> {
    refresh: Duration,
    scan: S,
    /// One slot per protocol, or slot 0 for both when a scan reads every table.
    per_protocol: bool,
    slots: [Slot; 2],
    scans: AtomicU64,
}

impl SocketOwnerCache {
    /// A cache that reads the host's tables with
    /// [`crate::socket_owner_snapshot_for`] and lets [`Self::owner`] start a
    /// scan at most once per `refresh` per protocol.
    pub const fn new(refresh: Duration) -> Self {
        let mut cache = Self::with_scanner(refresh, crate::socket_owner_snapshot_for as Scanner);
        cache.per_protocol = cfg!(all(windows, feature = "windows"));
        cache
    }

    /// The process-wide cache, refreshed at most every [`DEFAULT_REFRESH`].
    ///
    /// The socket tables are a property of the host, so independent parts of
    /// one process gain from sharing their scans.
    pub fn shared() -> &'static Self {
        static SHARED: SocketOwnerCache = SocketOwnerCache::new(DEFAULT_REFRESH);
        &SHARED
    }
}

impl<S> SocketOwnerCache<S>
where
    S: Fn(Protocol) -> SocketOwnerSnapshot,
{
    /// A cache that reads owners with `scan`, which receives the protocol a
    /// lookup needs and should return at least that protocol's sockets.
    ///
    /// `scan` runs with no lock held, on the thread of the lookup that needs
    /// it. If it panics, the panic reaches that lookup, and the slot it used
    /// still counts against the refresh interval.
    pub const fn with_scanner(refresh: Duration, scan: S) -> Self {
        Self {
            refresh,
            scan,
            per_protocol: true,
            slots: [Slot::new(), Slot::new()],
            scans: AtomicU64::new(0),
        }
    }

    /// The shortest time between two scans [`Self::owner`] starts.
    pub fn refresh(&self) -> Duration {
        self.refresh
    }

    /// Scans run so far, by every method.
    pub fn scans(&self) -> u64 {
        self.scans.load(Ordering::Relaxed)
    }

    /// Owner of the local `endpoint` for an event observed at `observed_at`,
    /// such as a packet or query that arrived from it.
    ///
    /// Answers from the newest snapshot when it can (see the module docs).
    /// Otherwise it scans, unless a scan is running or one started less than
    /// [`Self::refresh`] ago; then `wait` decides whether to wait for that
    /// scan or the next slot. A scan this lookup runs answers it. Port 0 is
    /// never bound and answers [`Ownership::NotFound`] at once.
    ///
    /// # Errors
    ///
    /// [`Pending`] when a scan was needed and `wait` did not allow one.
    pub fn owner(
        &self,
        protocol: Protocol,
        endpoint: LocalEndpoint,
        observed_at: Instant,
        wait: Wait,
    ) -> Result<Ownership, Pending> {
        if endpoint.port == 0 {
            return Ok(Ownership::NotFound);
        }
        let slot = self.slot(protocol);
        let lookup = |snapshot: &CachedSnapshot| {
            self.trusted_owner(snapshot, protocol, endpoint, observed_at)
        };
        if let Some(owner) = slot.read(lookup) {
            return Ok(owner);
        }
        let mut state = slot.lock_state();
        let mut seen = None;
        loop {
            // A scan may have finished since the last look.
            if seen != Some(state.completed) {
                seen = Some(state.completed);
                if let Some(owner) = slot.read(lookup) {
                    return Ok(owner);
                }
            }
            let now = Instant::now();
            let next_slot = state
                .last_started
                .and_then(|at| at.checked_add(self.refresh))
                .filter(|next| *next > now);
            let idle = state.running_since.is_none();
            if idle && next_slot.is_none() {
                if wait.passed(now) {
                    return Err(Pending::DeadlinePassed);
                }
                let snapshot = self.scan_now(slot, state, protocol, now);
                return Ok(snapshot.owners.local_endpoint_owner(protocol, endpoint));
            }
            let Wait::Until(deadline) = wait else {
                return Err(Pending::Busy);
            };
            // Wait for the running scan, or until the refresh interval allows one.
            let wake = next_slot.filter(|_| idle);
            if wake.unwrap_or(now) >= deadline {
                return Err(Pending::DeadlinePassed);
            }
            state = slot.wait(state, wake.unwrap_or(deadline) - now);
        }
    }

    /// What [`Self::owner`] under [`Wait::Never`] would return without
    /// scanning, or `None` when it would scan.
    ///
    /// Never scans and never waits: it takes the snapshot's read lock and at
    /// most the scan state's lock. A caller that must not block where it
    /// stands, such as a task on an async worker, asks this first and calls
    /// [`Self::owner`] from somewhere it may block only on `None`. Most
    /// lookups end here, with an answer from the newest snapshot or with
    /// [`Pending::Busy`], because a scan is due at most once per
    /// [`Self::refresh`].
    ///
    /// `None` is a hint, not a claim on the scan: another lookup may start it
    /// first, and [`Self::owner`] then answers from that scan or with
    /// [`Pending::Busy`].
    pub fn owner_without_scan(
        &self,
        protocol: Protocol,
        endpoint: LocalEndpoint,
        observed_at: Instant,
    ) -> Option<Result<Ownership, Pending>> {
        if endpoint.port == 0 {
            return Some(Ok(Ownership::NotFound));
        }
        let slot = self.slot(protocol);
        let lookup = |snapshot: &CachedSnapshot| {
            self.trusted_owner(snapshot, protocol, endpoint, observed_at)
        };
        if let Some(owner) = slot.read(lookup) {
            return Some(Ok(owner));
        }
        let state = slot.lock_state();
        let now = Instant::now();
        let due = state
            .last_started
            .and_then(|at| at.checked_add(self.refresh))
            .is_none_or(|next| next <= now);
        let scan_would_start = state.running_since.is_none() && due;
        drop(state);
        (!scan_would_start).then_some(Err(Pending::Busy))
    }

    /// `endpoint`'s owner in `snapshot`, if the snapshot can answer for an
    /// event observed at `observed_at` (see the module docs).
    fn trusted_owner(
        &self,
        snapshot: &CachedSnapshot,
        protocol: Protocol,
        endpoint: LocalEndpoint,
        observed_at: Instant,
    ) -> Option<Ownership> {
        let owner = snapshot.owners.local_endpoint_owner(protocol, endpoint);
        let trusted = snapshot.captured_at >= observed_at
            || (owner != Ownership::NotFound && snapshot.captured_at.elapsed() < self.refresh);
        trusted.then_some(owner)
    }

    /// A snapshot of `protocol`'s owners whose scan started at or after
    /// `since`, which is clamped to now.
    ///
    /// Reuses the newest snapshot when it is recent enough, and joins a running
    /// scan that started at or after `since`. Otherwise it scans, after any
    /// running scan finishes. The refresh interval does not apply: a caller
    /// that names the freshness it needs gets it.
    ///
    /// # Errors
    ///
    /// [`Pending`] when a scan was needed and `wait` did not allow waiting
    /// for the running one, or starting one past its deadline.
    pub fn snapshot_since(
        &self,
        protocol: Protocol,
        since: Instant,
        wait: Wait,
    ) -> Result<Arc<CachedSnapshot>, Pending> {
        let slot = self.slot(protocol);
        let since = since.min(Instant::now());
        let fresh = |snapshot: &CachedSnapshot| snapshot.captured_at >= since;
        if let Some(snapshot) = slot.latest_if(fresh) {
            return Ok(snapshot);
        }
        let mut state = slot.lock_state();
        let mut seen = None;
        loop {
            if seen != Some(state.completed) {
                seen = Some(state.completed);
                if let Some(snapshot) = slot.latest_if(fresh) {
                    return Ok(snapshot);
                }
            }
            let now = Instant::now();
            if state.running_since.is_none() {
                if wait.passed(now) {
                    return Err(Pending::DeadlinePassed);
                }
                return Ok(self.scan_now(slot, state, protocol, now));
            }
            let Wait::Until(deadline) = wait else {
                return Err(Pending::Busy);
            };
            if now >= deadline {
                return Err(Pending::DeadlinePassed);
            }
            state = slot.wait(state, deadline - now);
        }
    }

    fn slot(&self, protocol: Protocol) -> &Slot {
        match protocol {
            Protocol::Udp if self.per_protocol => &self.slots[1],
            _ => &self.slots[0],
        }
    }

    /// Scans `protocol` into `slot`, which `state` shows idle, and returns the
    /// new snapshot. The state lock is released for the scan itself.
    fn scan_now(
        &self,
        slot: &Slot,
        mut state: MutexGuard<'_, ScanState>,
        protocol: Protocol,
        now: Instant,
    ) -> Arc<CachedSnapshot> {
        state.running_since = Some(now);
        state.last_started = Some(now);
        drop(state);
        // Marks the scan finished and wakes waiters even if `scan` panics.
        let finished = Finished(slot);
        self.scans.fetch_add(1, Ordering::Relaxed);
        let snapshot = Arc::new(CachedSnapshot {
            owners: (self.scan)(protocol),
            captured_at: now,
        });
        let replaced = slot.replace(Arc::clone(&snapshot));
        drop(finished);
        // The old tables can be large; free them after waking the waiters.
        drop(replaced);
        snapshot
    }
}

impl<S> fmt::Debug for SocketOwnerCache<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SocketOwnerCache")
            .field("refresh", &self.refresh)
            .field("per_protocol", &self.per_protocol)
            .field("scans", &self.scans.load(Ordering::Relaxed))
            .finish_non_exhaustive()
    }
}

/// Newest snapshot of one protocol, and the scan that refreshes it.
///
/// Lock order: `state`, then `latest`. Nothing takes `state` while holding
/// `latest`, and a scan holds neither.
struct Slot {
    latest: RwLock<Option<Arc<CachedSnapshot>>>,
    state: Mutex<ScanState>,
    finished: Condvar,
}

#[derive(Clone, Copy)]
struct ScanState {
    /// When the running scan started, if one is running.
    running_since: Option<Instant>,
    /// When the newest scan started, finished or not.
    last_started: Option<Instant>,
    /// Scans finished, including ones that panicked.
    completed: u64,
}

impl Slot {
    const fn new() -> Self {
        Self {
            latest: RwLock::new(None),
            state: Mutex::new(ScanState {
                running_since: None,
                last_started: None,
                completed: 0,
            }),
            finished: Condvar::new(),
        }
    }

    /// Applies `lookup` to the newest snapshot under the read lock.
    fn read<T>(&self, lookup: impl FnOnce(&CachedSnapshot) -> Option<T>) -> Option<T> {
        let latest = self.latest.read().unwrap_or_else(PoisonError::into_inner);
        latest.as_deref().and_then(lookup)
    }

    fn latest_if(
        &self,
        wanted: impl FnOnce(&CachedSnapshot) -> bool,
    ) -> Option<Arc<CachedSnapshot>> {
        let latest = self.latest.read().unwrap_or_else(PoisonError::into_inner);
        latest.as_ref().filter(|snapshot| wanted(snapshot)).cloned()
    }

    fn replace(&self, snapshot: Arc<CachedSnapshot>) -> Option<Arc<CachedSnapshot>> {
        let mut latest = self.latest.write().unwrap_or_else(PoisonError::into_inner);
        latest.replace(snapshot)
    }

    fn lock_state(&self) -> MutexGuard<'_, ScanState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn wait<'a>(
        &self,
        state: MutexGuard<'a, ScanState>,
        timeout: Duration,
    ) -> MutexGuard<'a, ScanState> {
        self.finished
            .wait_timeout(state, timeout)
            .unwrap_or_else(PoisonError::into_inner)
            .0
    }
}

/// Ends a scan when dropped, including by a panic.
struct Finished<'a>(&'a Slot);

impl Drop for Finished<'_> {
    fn drop(&mut self) {
        let mut state = self.0.lock_state();
        state.running_since = None;
        state.completed = state.completed.wrapping_add(1);
        drop(state);
        self.0.finished.notify_all();
    }
}

#[cfg(test)]
mod tests;
