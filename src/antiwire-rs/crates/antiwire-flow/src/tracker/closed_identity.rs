//! Bounded evidence retained after a connection closes. A bare PID or name
//! cannot retrieve a candidate: the original creation time must match exactly.
//!
//! A connection whose process was never identified has no creation time to
//! match. It is kept by PID with the time it opened, for the caller to check
//! against the process's start and stop once those are known.
use super::{ActiveFlow, FlowKey, Instant};
use std::collections::{HashMap, VecDeque};
use std::time::Duration;

#[derive(Clone)]
pub(super) struct Candidate {
    pub key: FlowKey,
    pub flow: ActiveFlow,
    expires_at: Instant,
}

/// A process instance: its PID and creation time.
type ProcessKey = (u32, u64);

/// A held candidate and the order it arrived in.
struct Held {
    arrival: u64,
    candidate: Candidate,
}

/// Closed connections' identities, found by the exact process that owned
/// them, so neither recording nor recovering one scans the rest.
pub(super) struct ClosedIdentityQueue {
    /// Candidates by owning process, each list in arrival order.
    by_process: HashMap<ProcessKey, VecDeque<Held>>,
    /// Every candidate added, oldest first, for the capacity bound and
    /// expiry. An entry whose candidate was already taken is skipped.
    arrivals: VecDeque<(ProcessKey, u64)>,
    held: usize,
    next_arrival: u64,
    capacity: usize,
    retention: Duration,
}

impl ClosedIdentityQueue {
    pub fn new(capacity: usize, retention: Duration) -> Self {
        Self {
            by_process: HashMap::new(),
            arrivals: VecDeque::new(),
            held: 0,
            next_arrival: 0,
            capacity,
            retention,
        }
    }

    pub fn remember(&mut self, key: FlowKey, flow: ActiveFlow, now: Instant) {
        if flow.pid == 0 || flow.conn_id == 0 {
            return;
        }
        // Without a creation time, only the opening time can say which
        // process with this PID the connection belonged to.
        if flow.process_start_ts.is_none_or(|time| time == 0) && flow.open_ts == 0 {
            return;
        }
        self.restore(
            Candidate {
                key,
                flow,
                expires_at: now + self.retention,
            },
            now,
        );
    }

    pub fn restore(&mut self, candidate: Candidate, now: Instant) {
        self.drop_expired(now);
        if self.capacity == 0 || candidate.expires_at <= now {
            return;
        }
        while self.held >= self.capacity && self.drop_oldest() {}
        let process = (
            candidate.flow.pid,
            candidate.flow.process_start_ts.unwrap_or(0),
        );
        let arrival = self.next_arrival;
        self.next_arrival += 1;
        self.by_process
            .entry(process)
            .or_default()
            .push_back(Held { arrival, candidate });
        self.arrivals.push_back((process, arrival));
        self.held += 1;
        self.compact_arrivals();
    }

    pub fn take_for(&mut self, pid: u32, start_ts: u64, now: Instant) -> Vec<Candidate> {
        if start_ts == 0 {
            return Vec::new();
        }
        self.take((pid, start_ts), now)
    }

    /// Takes the candidates of `pid` whose process creation time was never
    /// learned. The caller decides, from when each opened, whether a process
    /// it now knows of owned it, and restores those it cannot place.
    pub fn take_unstarted(&mut self, pid: u32, now: Instant) -> Vec<Candidate> {
        self.take((pid, 0), now)
    }

    fn take(&mut self, process: ProcessKey, now: Instant) -> Vec<Candidate> {
        self.drop_expired(now);
        let Some(held) = self.by_process.remove(&process) else {
            return Vec::new();
        };
        self.held -= held.len();
        held.into_iter()
            .map(|held| held.candidate)
            .filter(|candidate| candidate.expires_at > now)
            .collect()
    }

    /// Drops candidates from the oldest end while they have expired.
    /// Every candidate is kept for the same retention, so arrival order is
    /// close to expiry order; a later expired one is dropped when it is
    /// taken, or reached here.
    fn drop_expired(&mut self, now: Instant) {
        while let Some(&(process, arrival)) = self.arrivals.front() {
            match self.oldest_of(process, arrival) {
                Some(candidate) if candidate.expires_at > now => return,
                Some(_) => {
                    self.drop_oldest();
                }
                None => {
                    self.arrivals.pop_front();
                }
            }
        }
    }

    /// Drops the oldest candidate still held. Returns whether there was one.
    fn drop_oldest(&mut self) -> bool {
        while let Some((process, arrival)) = self.arrivals.pop_front() {
            if self.oldest_of(process, arrival).is_none() {
                continue;
            }
            if let Some(list) = self.by_process.get_mut(&process) {
                list.pop_front();
                if list.is_empty() {
                    self.by_process.remove(&process);
                }
            }
            self.held -= 1;
            return true;
        }
        false
    }

    /// The candidate that arrived as `arrival`, when it is still `process`'s
    /// oldest. Lists only grow at the back and are taken whole, so a held
    /// candidate's arrival entry always points at its list's front by the
    /// time that entry reaches the front of [`Self::arrivals`].
    fn oldest_of(&self, process: ProcessKey, arrival: u64) -> Option<&Candidate> {
        self.by_process
            .get(&process)?
            .front()
            .filter(|held| held.arrival == arrival)
            .map(|held| &held.candidate)
    }

    /// Bounds the arrival list, which keeps entries for candidates taken
    /// since they arrived.
    fn compact_arrivals(&mut self) {
        if self.arrivals.len() <= self.capacity.saturating_mul(2).max(16) {
            return;
        }
        let by_process = &self.by_process;
        self.arrivals.retain(|(process, arrival)| {
            by_process
                .get(process)
                .is_some_and(|list| list.iter().any(|held| held.arrival == *arrival))
        });
    }

    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.held
    }
}
