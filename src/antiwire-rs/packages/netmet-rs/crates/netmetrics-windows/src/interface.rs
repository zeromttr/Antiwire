//! Asynchronous route estimates for newly created flows.
//!
//! `GetBestRoute2` is an estimate, not evidence of the interface that carried a packet.
//! Lookups run off the ETW callback path, are keyed by local and remote address, and
//! are tagged with a flow generation so a delayed result cannot annotate a recycled tuple.

use lookup::{NetworkChangeWatch, lookup_interface};
use netmetrics_core::FlowKey;
use netmetrics_sys::{BackendEvent, EventSink, StopFlag};
use std::collections::{HashMap, HashSet, VecDeque};
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender, TrySendError};
use std::thread;
use std::time::{Duration, Instant};

mod lookup;
#[cfg(test)]
mod tests;

#[cfg(test)]
pub(crate) use lookup::select_interface;

const MAX_QUEUE: usize = 1_024;
const MAX_CACHE: usize = 4_096;
const MAX_WAITERS_PER_ROUTE: usize = 16;
const INGEST_BUDGET: usize = 32;
const LOOKUP_BUDGET: usize = 8;
const SUCCESS_TTL: Duration = Duration::from_secs(30);
const FAILURE_TTL: Duration = Duration::from_millis(500);

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct RouteKey {
    local: IpAddr,
    remote: IpAddr,
}

#[derive(Clone, Copy, Debug)]
struct CacheEntry {
    result: Result<u32, ()>,
    bound: bool,
    expires_at: Instant,
    epoch: u64,
}

struct PendingRoute {
    waiters: Vec<(FlowKey, u64, u8)>,
}

/// Handle used by the collector to request an estimate when a flow is created.
pub struct InterfaceEstimator {
    requests: Option<SyncSender<(FlowKey, u64)>>,
    worker: Option<thread::JoinHandle<()>>,
}

impl InterfaceEstimator {
    /// Starts the lookup worker and network-change notifications.
    ///
    /// Returns `None` when the worker thread cannot be spawned. The collector
    /// then leaves `if_index` unknown rather than blocking the packet path.
    #[must_use]
    pub fn start(sink: EventSink, stop: StopFlag) -> Option<Self> {
        let (requests, rx) = mpsc::sync_channel(MAX_QUEUE);
        let worker = thread::Builder::new()
            .name("netmetrics-route".to_owned())
            .spawn(move || run_worker(&rx, &sink, &stop))
            .ok()?;
        Some(Self {
            requests: Some(requests),
            worker: Some(worker),
        })
    }

    /// Enqueues a lookup for `key`. Drops the request when the queue is full.
    pub fn request(&self, key: FlowKey, generation: u64) {
        let Some(requests) = &self.requests else {
            return;
        };
        match requests.try_send((key, generation)) {
            Ok(()) | Err(TrySendError::Full(_) | TrySendError::Disconnected(_)) => {}
        }
    }
}

impl Drop for InterfaceEstimator {
    fn drop(&mut self) {
        // Disconnect first so the worker cannot stay blocked in recv after stop.
        drop(self.requests.take());
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

fn run_worker(rx: &Receiver<(FlowKey, u64)>, sink: &EventSink, stop: &StopFlag) {
    let epoch = Arc::new(AtomicU64::new(1));
    let _changes = NetworkChangeWatch::new(Arc::clone(&epoch));
    let mut cache = HashMap::<RouteKey, CacheEntry>::new();
    let mut pending = HashMap::<RouteKey, PendingRoute>::new();
    let mut queue = VecDeque::<RouteKey>::new();
    let mut queued = HashSet::<RouteKey>::new();
    let mut retries: VecDeque<(Instant, FlowKey, u64, u8)> = VecDeque::new();
    while !stop.is_stop_requested() {
        if queue.is_empty() {
            match rx.recv_timeout(Duration::from_millis(50)) {
                Ok((key, generation)) => {
                    enqueue_request(
                        key,
                        generation,
                        0,
                        &mut cache,
                        &mut pending,
                        &mut queue,
                        &mut queued,
                        epoch.load(Ordering::Acquire),
                        Instant::now(),
                        sink,
                    );
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {}
                Err(mpsc::RecvTimeoutError::Disconnected) => break,
            }
        }
        if !ingest_requests(
            rx,
            stop,
            INGEST_BUDGET,
            &mut cache,
            &mut pending,
            &mut queue,
            &mut queued,
            epoch.load(Ordering::Acquire),
            sink,
        ) {
            break;
        }
        drain_queue(
            &mut cache,
            &mut pending,
            &mut queue,
            &mut queued,
            &mut retries,
            epoch.load(Ordering::Acquire),
            Instant::now(),
            sink,
            LOOKUP_BUDGET,
            stop,
        );
        promote_due_retries(
            &mut retries,
            &mut cache,
            &mut pending,
            &mut queue,
            &mut queued,
            epoch.load(Ordering::Acquire),
            Instant::now(),
            sink,
        );
    }
}

#[allow(clippy::too_many_arguments)]
fn ingest_requests(
    rx: &Receiver<(FlowKey, u64)>,
    stop: &StopFlag,
    budget: usize,
    cache: &mut HashMap<RouteKey, CacheEntry>,
    pending: &mut HashMap<RouteKey, PendingRoute>,
    queue: &mut VecDeque<RouteKey>,
    queued: &mut HashSet<RouteKey>,
    epoch: u64,
    sink: &EventSink,
) -> bool {
    for _ in 0..budget {
        if stop.is_stop_requested() {
            return true;
        }
        match rx.try_recv() {
            Ok((key, generation)) => {
                enqueue_request(
                    key,
                    generation,
                    0,
                    cache,
                    pending,
                    queue,
                    queued,
                    epoch,
                    Instant::now(),
                    sink,
                );
            }
            Err(mpsc::TryRecvError::Empty) => return true,
            Err(mpsc::TryRecvError::Disconnected) => return false,
        }
    }
    true
}

#[allow(clippy::too_many_arguments)]
fn enqueue_request(
    key: FlowKey,
    generation: u64,
    attempts: u8,
    cache: &mut HashMap<RouteKey, CacheEntry>,
    pending: &mut HashMap<RouteKey, PendingRoute>,
    queue: &mut VecDeque<RouteKey>,
    queued: &mut HashSet<RouteKey>,
    epoch: u64,
    now: Instant,
    sink: &EventSink,
) {
    let route = RouteKey {
        local: key.local_addr,
        remote: key.remote_addr,
    };
    if let Some(entry) = cache.get(&route)
        && entry.epoch == epoch
        && entry.expires_at > now
    {
        if let Ok(if_index) = entry.result {
            sink.emit(BackendEvent::InterfaceHint {
                key,
                if_index,
                bound: entry.bound,
                generation,
            });
        }
        return;
    }
    let waiters = &mut pending
        .entry(route)
        .or_insert(PendingRoute {
            waiters: Vec::new(),
        })
        .waiters;
    if waiters.len() >= MAX_WAITERS_PER_ROUTE {
        return;
    }
    if waiters.iter().any(|(existing, waiter_generation, _)| {
        *existing == key && *waiter_generation == generation
    }) {
        return;
    }
    waiters.push((key, generation, attempts));
    if queued.insert(route) {
        if queue.len() >= MAX_QUEUE {
            queued.remove(&route);
            pending.remove(&route);
            return;
        }
        queue.push_back(route);
    }
}

#[allow(clippy::too_many_arguments)]
fn drain_queue(
    cache: &mut HashMap<RouteKey, CacheEntry>,
    pending: &mut HashMap<RouteKey, PendingRoute>,
    queue: &mut VecDeque<RouteKey>,
    queued: &mut HashSet<RouteKey>,
    retries: &mut VecDeque<(Instant, FlowKey, u64, u8)>,
    epoch: u64,
    now: Instant,
    sink: &EventSink,
    budget: usize,
    stop: &StopFlag,
) {
    for _ in 0..budget {
        if stop.is_stop_requested() {
            return;
        }
        let Some(route) = queue.pop_front() else {
            return;
        };
        queued.remove(&route);
        let result = lookup_interface(route.local, route.remote);
        let bound = result.as_ref().is_ok_and(|(_, bound)| *bound);
        let ttl = if bound { SUCCESS_TTL } else { FAILURE_TTL };
        let index = result.map(|(index, _)| index);
        if cache.len() >= MAX_CACHE
            && let Some(oldest) = cache
                .iter()
                .min_by_key(|(_, entry)| entry.expires_at)
                .map(|(key, _)| *key)
        {
            cache.remove(&oldest);
        }
        cache.insert(
            route,
            CacheEntry {
                result: index,
                bound,
                expires_at: now.checked_add(ttl).unwrap_or(now),
                epoch,
            },
        );
        if let Some(PendingRoute { waiters }) = pending.remove(&route)
            && let Ok(if_index) = index
        {
            for (key, generation, attempts) in waiters {
                sink.emit(BackendEvent::InterfaceHint {
                    key,
                    if_index,
                    bound,
                    generation,
                });
                if !bound && !route.local.is_unspecified() && !route.local.is_loopback() {
                    schedule_bound_retry(retries, key, generation, attempts, now);
                }
            }
        }
    }
}

/// Prefers the interface that owns `local`. The route table is only the fallback
/// for an unspecified local address, or when that address is not in the unicast table.
const ROUTE_RETRY_LIMIT: usize = 4;

fn insert_retry(
    retries: &mut VecDeque<(Instant, FlowKey, u64, u8)>,
    due: Instant,
    key: FlowKey,
    generation: u64,
    attempts: u8,
) {
    if retries.iter().any(|(_, existing, existing_generation, _)| {
        *existing == key && *existing_generation == generation
    }) {
        return;
    }
    let index = retries
        .iter()
        .position(|(existing_due, ..)| *existing_due > due)
        .unwrap_or(retries.len());
    retries.insert(index, (due, key, generation, attempts));
}

fn schedule_bound_retry(
    retries: &mut VecDeque<(Instant, FlowKey, u64, u8)>,
    key: FlowKey,
    generation: u64,
    attempts: u8,
    now: Instant,
) {
    if usize::from(attempts) >= ROUTE_RETRY_LIMIT || retries.len() >= MAX_QUEUE {
        return;
    }
    insert_retry(
        retries,
        now.checked_add(FAILURE_TTL).unwrap_or(now),
        key,
        generation,
        attempts + 1,
    );
}

#[allow(clippy::too_many_arguments)]
fn promote_due_retries(
    retries: &mut VecDeque<(Instant, FlowKey, u64, u8)>,
    cache: &mut HashMap<RouteKey, CacheEntry>,
    pending: &mut HashMap<RouteKey, PendingRoute>,
    queue: &mut VecDeque<RouteKey>,
    queued: &mut HashSet<RouteKey>,
    epoch: u64,
    now: Instant,
    sink: &EventSink,
) {
    for _ in 0..LOOKUP_BUDGET {
        if queue.len() >= MAX_QUEUE {
            break;
        }
        let Some((due, key, generation, attempts)) = retries.front().copied() else {
            break;
        };
        if due > now {
            break;
        }
        let route = RouteKey {
            local: key.local_addr,
            remote: key.remote_addr,
        };
        // A fresh route guess must not finish the retry that is waiting for the
        // address to appear in the unicast table. Emitting it again leaves the
        // flow on that guess. A bound cache entry is the answer, so it completes.
        if let Some(entry) = cache.get(&route)
            && entry.epoch == epoch
            && entry.expires_at > now
            && entry.result.is_ok()
            && !entry.bound
        {
            retries.pop_front();
            insert_retry(retries, entry.expires_at, key, generation, attempts);
            continue;
        }
        retries.pop_front();
        enqueue_request(
            key, generation, attempts, cache, pending, queue, queued, epoch, now, sink,
        );
    }
}
