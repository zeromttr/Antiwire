//! Shared bounded history of native endpoint ownership observations.
//!
//! Native readers supply event times, owners, and receive progress. Socket-table
//! snapshots must not be fed here: an owner seen now does not prove past ownership.

use crate::expiring_map::ExpiringMap;
use std::net::IpAddr;
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

pub use crate::EndpointOwner;
use crate::{LocalEndpoint, Protocol, canonicalize_ip};

#[cfg(test)]
mod tests;

/// How long an endpoint's owners stay known after their last event or lookup.
///
/// A native source may report a socket only once, so a lookup hit extends
/// retention. A newly observed owner supersedes it at the event timestamp.
const RETENTION: Duration = Duration::from_secs(120);
/// Bound on endpoints with retained owners.
const CAPACITY: usize = 8_192;
/// Owners kept per endpoint, newest last.
const HISTORY: usize = 4;
/// How long the listener must sit in an empty receive, after the query
/// arrived, before a waiting lookup treats it as caught up. A queued event
/// wakes the receive within microseconds; this leaves room for scheduling.
const IDLE_PROOF: Duration = Duration::from_millis(1);
/// Recorded in place of an owner the event cannot be trusted for.
const UNKNOWN_OWNER: u32 = 0;

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
struct EndpointKey {
    protocol: Protocol,
    address: IpAddr,
    port: u16,
}

impl EndpointKey {
    fn new(protocol: Protocol, endpoint: LocalEndpoint) -> Self {
        Self {
            protocol,
            address: canonicalize_ip(endpoint.address),
            port: endpoint.port,
        }
    }
}

/// Bounded `endpoint -> recent owners` memory. Each history holds
/// `(observed_at, pid)` pairs, oldest first.
#[derive(Debug, Default)]
struct Owners {
    entries: ExpiringMap<EndpointKey, Vec<(Instant, u32)>, CAPACITY>,
}

impl Owners {
    /// Records that `pid` established a flow on `key`. [`UNKNOWN_OWNER`] still
    /// supersedes earlier owners, so lookups after it find none.
    fn record(&mut self, key: EndpointKey, established_at: Instant, pid: u32, now: Instant) {
        self.entries.expire(now);
        let expires_at = now.checked_add(RETENTION).unwrap_or(now);
        if !self.entries.contains_key(&key) {
            self.entries
                .insert(key, Vec::with_capacity(HISTORY), expires_at);
        }
        let Some(history) = self.entries.get_mut(&key) else {
            return;
        };
        // Events arrive in kernel order, so this is normally the end.
        let position = history.partition_point(|(at, _)| *at <= established_at);
        // Repeated I/O must not evict history of earlier owners.
        if position > 0 && history[position - 1].1 == pid {
            self.entries.set_deadline(&key, expires_at);
            return;
        }
        history.insert(position, (established_at, pid));
        if history.len() > HISTORY {
            history.remove(0);
        }
        self.entries.set_deadline(&key, expires_at);
    }

    /// The newest owner established at or before `at`, which can be
    /// [`UNKNOWN_OWNER`].
    fn owner_at(&mut self, key: EndpointKey, at: Instant, now: Instant) -> Option<u32> {
        self.entries.expire(now);
        let wildcard = EndpointKey {
            address: crate::unspecified_address(key.address),
            ..key
        };
        // Unconnected UDP sockets can remain wildcard-bound in kernel I/O
        // records even though the captured query has a concrete source address.
        // Conflicting exact and wildcard owners cannot be disambiguated from
        // an endpoint alone (for example, shared UDP ports). Do not guess, and
        // do not extend either: the closed one must age out so the live one,
        // which keeps producing events, answers again.
        let candidate = |key: &EndpointKey| {
            self.entries
                .get(key)
                .and_then(|history| history.iter().rev().find(|(seen, _)| *seen <= at))
                .copied()
        };
        let exact = candidate(&key);
        let fallback = candidate(&wildcard);
        let (selected, (_, pid)) = match (exact, fallback) {
            (Some(exact), Some(fallback)) if exact.1 != fallback.1 => return Some(UNKNOWN_OWNER),
            (Some(exact), Some(fallback)) if fallback.0 > exact.0 => (wildcard, fallback),
            (Some(exact), _) => (key, exact),
            (None, Some(fallback)) => (wildcard, fallback),
            (None, None) => return None,
        };
        self.entries
            .set_deadline(&selected, now.checked_add(RETENTION).unwrap_or(now));
        Some(pid)
    }
}

/// What the native reader is doing, which decides what its record proves.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
enum Reader {
    /// Handling an event it already received, or not yet started. Its record
    /// may be missing that event, so it proves nothing about later queries.
    #[default]
    Processing,
    /// Blocked for the next event since this time. Once that wait outlasts
    /// [`IDLE_PROOF`], every earlier event has been recorded.
    Receiving(Instant),
    /// Stopped for good. Nothing more will be recorded.
    Closed,
}

#[derive(Debug, Default)]
struct FeedState {
    owners: Owners,
    /// Kernel time of the newest event the listener has processed.
    processed_through: Option<Instant>,
    reader: Reader,
}

impl FeedState {
    fn caught_up(&self, received_at: Instant, now: Instant) -> bool {
        self.processed_through.is_some_and(|at| at >= received_at)
            || match self.reader {
                Reader::Closed => true,
                Reader::Receiving(since) => {
                    idle_proof(since, received_at).is_some_and(|proof| now >= proof)
                }
                Reader::Processing => false,
            }
    }

    fn closed(&self) -> bool {
        self.reader == Reader::Closed
    }

    /// Moves the reader to `next`, except that a closed feed stays closed.
    fn set_reader(&mut self, next: Reader) {
        if !self.closed() {
            self.reader = next;
        }
    }
}

/// When an idle receive that began at `since` proves `received_at` covered.
fn idle_proof(since: Instant, received_at: Instant) -> Option<Instant> {
    since.max(received_at).checked_add(IDLE_PROOF)
}

/// Endpoint owners fed by one native reader, and its progress through events.
#[derive(Debug)]
pub struct EndpointOwnerFeed {
    state: Mutex<FeedState>,
    progressed: Condvar,
    owner_filter: fn(LocalEndpoint, u32) -> u32,
}

impl Default for EndpointOwnerFeed {
    fn default() -> Self {
        Self::new(|_, pid| pid)
    }
}

impl EndpointOwnerFeed {
    /// Creates a feed with a platform-specific owner validation policy.
    pub fn new(owner_filter: fn(LocalEndpoint, u32) -> u32) -> Self {
        Self {
            state: Mutex::default(),
            progressed: Condvar::new(),
            owner_filter,
        }
    }

    /// The listener is about to block for its next event.
    pub fn receiving(&self, now: Instant) {
        self.lock().set_reader(Reader::Receiving(now));
        self.progressed.notify_all();
    }

    /// The listener's receive returned an event it has not recorded yet.
    ///
    /// Called before any slow work on the event, so a lookup cannot take the
    /// receive that just ended as proof the record is current.
    pub fn processing(&self) {
        self.lock().set_reader(Reader::Processing);
    }

    /// The listener processed an event from `event_at`. `established` names
    /// the local endpoint and owner when the event established a flow.
    ///
    /// Events must be passed in time order: one from after a query proves that
    /// every owner from before it is recorded. Use [`Self::observed`] for
    /// events that can arrive out of order.
    pub fn received(
        &self,
        event_at: Instant,
        established: Option<(Protocol, LocalEndpoint, u32)>,
        now: Instant,
    ) {
        {
            let mut state = self.lock();
            state.set_reader(Reader::Processing);
            if let Some((protocol, endpoint, pid)) = established {
                state.owners.record(
                    EndpointKey::new(protocol, endpoint),
                    event_at,
                    (self.owner_filter)(endpoint, pid),
                    now,
                );
            }
            state.processed_through = Some(
                state
                    .processed_through
                    .map_or(event_at, |through| through.max(event_at)),
            );
        }
        self.progressed.notify_all();
    }

    /// Records an owner from an event that may arrive out of time order, such
    /// as a byte count reported when a send returns. It adds history but is
    /// no evidence of progress, so it never lets a lookup stop waiting.
    pub fn observed(
        &self,
        event_at: Instant,
        protocol: Protocol,
        endpoint: LocalEndpoint,
        pid: u32,
        now: Instant,
    ) {
        self.lock().owners.record(
            EndpointKey::new(protocol, endpoint),
            event_at,
            (self.owner_filter)(endpoint, pid),
            now,
        );
    }

    /// The listener stopped; waiting lookups answer from what was recorded.
    pub fn close(&self) {
        self.lock().reader = Reader::Closed;
        self.progressed.notify_all();
    }

    /// Owner of `endpoint` when a query arrived at `received_at`.
    ///
    /// Blocks until the listener has caught up with `received_at`, or until
    /// `deadline`, then answers from what it has.
    pub fn owner_at(
        &self,
        protocol: Protocol,
        endpoint: LocalEndpoint,
        received_at: Instant,
        deadline: Instant,
    ) -> EndpointOwner {
        let (caught_up, _, pid) = self.lookup(protocol, endpoint, received_at, deadline);
        match pid {
            Some(UNKNOWN_OWNER) => EndpointOwner::Untrusted,
            Some(pid) => EndpointOwner::Resolved(pid),
            None if caught_up => EndpointOwner::NotFound,
            None => EndpointOwner::Behind,
        }
    }

    /// Like [`Self::owner_at`], but answers only once a running listener has
    /// caught up: an owner recorded before then may already have been replaced.
    pub fn current_owner_at(
        &self,
        protocol: Protocol,
        endpoint: LocalEndpoint,
        received_at: Instant,
        deadline: Instant,
    ) -> Option<u32> {
        match self.lookup(protocol, endpoint, received_at, deadline) {
            (true, false, Some(pid)) if pid != UNKNOWN_OWNER => Some(pid),
            _ => None,
        }
    }

    /// Waits for the listener to catch up with `received_at`, or for
    /// `deadline`, then returns whether it caught up, whether it has closed,
    /// and the recorded owner.
    fn lookup(
        &self,
        protocol: Protocol,
        endpoint: LocalEndpoint,
        received_at: Instant,
        deadline: Instant,
    ) -> (bool, bool, Option<u32>) {
        let key = EndpointKey::new(protocol, endpoint);
        let mut state = self.lock();
        loop {
            let now = Instant::now();
            let caught_up = state.caught_up(received_at, now);
            if caught_up || now >= deadline {
                let pid = state.owners.owner_at(key, received_at, now);
                return (caught_up, state.closed(), pid);
            }
            // Wake for the next event, or when an idle receive becomes proof.
            let wake = match state.reader {
                Reader::Receiving(since) => idle_proof(since, received_at),
                Reader::Processing | Reader::Closed => None,
            }
            .map_or(deadline, |proof| proof.min(deadline));
            state = self
                .progressed
                .wait_timeout(state, wake.saturating_duration_since(now))
                .unwrap_or_else(PoisonError::into_inner)
                .0;
        }
    }

    fn lock(&self) -> MutexGuard<'_, FeedState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

static ACTIVE: Mutex<Option<Arc<EndpointOwnerFeed>>> = Mutex::new(None);

fn active() -> MutexGuard<'static, Option<Arc<EndpointOwnerFeed>>> {
    ACTIVE.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Makes `feed` the one lookups read.
pub fn publish(feed: &Arc<EndpointOwnerFeed>) {
    *active() = Some(Arc::clone(feed));
}

/// Stops lookups reading `feed`, unless a newer listener already replaced it.
pub fn withdraw(feed: &Arc<EndpointOwnerFeed>) {
    feed.close();
    let mut active = active();
    if active
        .as_ref()
        .is_some_and(|current| Arc::ptr_eq(current, feed))
    {
        *active = None;
    }
}

/// Whether a native reader is feeding endpoint owners.
#[must_use]
pub fn endpoint_owners_available() -> bool {
    active().is_some()
}

/// Owner of the local `endpoint` when a packet was captured at `received_at`,
/// only if the native reader catches up with that moment within `timeout`.
/// `None` means the caller needs another source.
pub fn current_endpoint_owner_at(
    protocol: Protocol,
    endpoint: LocalEndpoint,
    received_at: Instant,
    timeout: Duration,
) -> Option<u32> {
    let feed = active().clone()?;
    let deadline = Instant::now()
        .checked_add(timeout)
        .unwrap_or_else(Instant::now);
    feed.current_owner_at(protocol, endpoint, received_at, deadline)
}

/// Owner of the local `endpoint` when a query arrived at `received_at`.
///
/// Waits up to `timeout` for the native reader to catch up with
/// `received_at`, so call it off any latency-sensitive path. Returns
/// [`EndpointOwner::Unavailable`] when no listener is running.
#[must_use]
pub fn endpoint_owner_at(
    protocol: Protocol,
    endpoint: LocalEndpoint,
    received_at: Instant,
    timeout: Duration,
) -> EndpointOwner {
    let Some(feed) = active().clone() else {
        return EndpointOwner::Unavailable;
    };
    let deadline = Instant::now()
        .checked_add(timeout)
        .unwrap_or_else(Instant::now);
    feed.owner_at(protocol, endpoint, received_at, deadline)
}
