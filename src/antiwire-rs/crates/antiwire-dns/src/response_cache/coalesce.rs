//! In-flight miss coalescing and generation gating.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use dashmap::mapref::entry::Entry;
use dashmap::DashMap;
use tokio::sync::OnceCell;

use crate::{DnsError, Result};

use super::entry::CachedAnswer;
use super::key::CacheKey;

pub(crate) type SharedFetchResult = std::result::Result<CachedAnswer, Arc<DnsError>>;

/// Outcome shared across the callers coalesced onto one in-flight fetch.
#[derive(Clone)]
pub(crate) enum SharedOutcome {
    Ready(SharedFetchResult),
    /// The generation this fetch started under was retired mid-flight, so its
    /// answer or error was discarded instead of served, cached or shared.
    /// Every waiter may safely retry under the current generation.
    GenerationRetired,
    /// The fetch gave up for reasons of its own, not the name's (see
    /// [`Fetched::Withdrawn`]). Its cell is gone from the map, so a waiter
    /// that wants an answer fetches again under its own terms.
    Withdrawn,
}

/// What one fetch made of its attempt.
pub(crate) enum Fetched {
    Done(Result<CachedAnswer>),
    /// It ended without an answer for a reason of its own: a background
    /// refresh that was not sent under its narrower admission, or whose
    /// answer rebinding protection kept out of the cache. Another caller,
    /// with its own admission and its own use for the answer, may still get
    /// one, so it must not inherit this.
    Withdrawn,
}

impl From<Result<CachedAnswer>> for Fetched {
    fn from(result: Result<CachedAnswer>) -> Self {
        Self::Done(result)
    }
}

/// Total cache admission attempts the query engine allows, bounding the retry
/// when a generation bump retires a fetch. One retry absorbs any single network
/// event; more would chase generation flapping without bound.
pub(crate) const FETCH_GENERATION_ATTEMPTS: usize = 2;

pub(super) struct InflightState {
    /// Generation this fetch was started for. A caller from a later generation
    /// must never adopt the answer: it was resolved against upstreams that the
    /// bump retired.
    generation: u64,
    pub(super) result: OnceCell<SharedOutcome>,
    waiters: AtomicUsize,
}

impl InflightState {
    pub(super) fn first_waiter(generation: u64) -> Self {
        Self {
            generation,
            result: OnceCell::new(),
            waiters: AtomicUsize::new(1),
        }
    }
}

pub(super) type InflightCell = Arc<InflightState>;

struct InflightWaiter<'map, 'key> {
    map: &'map DashMap<CacheKey, InflightCell>,
    key: &'key CacheKey,
    cell: InflightCell,
}

impl Drop for InflightWaiter<'_, '_> {
    fn drop(&mut self) {
        if self.cell.waiters.fetch_sub(1, Ordering::AcqRel) != 1 {
            return;
        }

        self.map.remove_if(self.key, |_, cell| {
            Arc::ptr_eq(cell, &self.cell) && self.cell.waiters.load(Ordering::Acquire) == 0
        });
    }
}

impl super::ResponseCache {
    /// One admission attempt for `key`: joins (or installs) the in-flight cell
    /// under `generation_at_start` and awaits its outcome.
    ///
    /// Exposed so the query engine can retry a retired fetch with a freshly
    /// acquired upstream pool: each attempt pairs the generation passed here
    /// with the pool current at that moment, never a pool captured before an
    /// earlier attempt. A caller whose initializer needs no external state can
    /// simply retry the same closure under [`Self::current_generation`] when
    /// this returns [`SharedOutcome::GenerationRetired`].
    pub(crate) async fn resolve_once<F, Fut, Out>(
        &self,
        key: &CacheKey,
        generation_at_start: u64,
        init: &F,
    ) -> SharedOutcome
    where
        F: Fn() -> Fut,
        Fut: std::future::Future<Output = Out>,
        Out: Into<Fetched>,
    {
        // Entering the in-flight map must be atomic against `bump_generation`,
        // which increments the counter *before* clearing the map. A caller that
        // slips into that window would otherwise either join a cell belonging to
        // the generation just retired — adopting an answer resolved over the
        // network that has since gone away — or install a fresh cell that the
        // trailing `clear()` drops, splitting the callers behind it onto
        // duplicate upstream fetches instead of coalescing onto it.
        let cell = {
            let _generation_guard = self.generation_gate.read();
            if self.generation.load(Ordering::Acquire) != generation_at_start {
                return SharedOutcome::GenerationRetired;
            }

            let existing = self.inflight.get(key).and_then(|entry| {
                (entry.generation == generation_at_start).then(|| {
                    entry.waiters.fetch_add(1, Ordering::Relaxed);
                    Arc::clone(entry.value())
                })
            });
            if let Some(cell) = existing {
                cell
            } else {
                match self.inflight.entry(key.clone()) {
                    // Under the gate every surviving cell was installed after the
                    // last bump, so the generation match is belt-and-braces: it
                    // makes a cross-generation join impossible rather than merely
                    // unreachable, and a mismatch resolves to a fresh fetch instead
                    // of a stale answer.
                    Entry::Occupied(entry) if entry.get().generation == generation_at_start => {
                        let cell = Arc::clone(entry.get());
                        cell.waiters.fetch_add(1, Ordering::Relaxed);
                        cell
                    }
                    Entry::Occupied(mut entry) => {
                        let cell = Arc::new(InflightState::first_waiter(generation_at_start));
                        entry.insert(Arc::clone(&cell));
                        cell
                    }
                    Entry::Vacant(entry) => {
                        let cell = Arc::new(InflightState::first_waiter(generation_at_start));
                        entry.insert(Arc::clone(&cell));
                        cell
                    }
                }
            }
        };
        let _waiter = InflightWaiter {
            map: &self.inflight,
            key,
            cell: Arc::clone(&cell),
        };

        let outcome = cell
            .result
            .get_or_init(|| async move {
                if self.generation.load(Ordering::Acquire) != generation_at_start {
                    return SharedOutcome::GenerationRetired;
                }

                let fetched = init().await.into();
                let _generation_guard = self.generation_gate.read();
                if self.generation.load(Ordering::Acquire) != generation_at_start {
                    // The upstream exchange raced a generation bump. An answer
                    // came over the retired network, and an error may say only
                    // that the network went away: discard either rather than
                    // adopt, cache or share it, so the waiters retry.
                    return SharedOutcome::GenerationRetired;
                }
                match fetched {
                    Fetched::Done(Ok(entry)) => {
                        if entry.cacheable {
                            self.inner.insert(key.clone(), entry.clone());
                        }
                        self.clear_failure(key);
                        SharedOutcome::Ready(Ok(entry))
                    }
                    Fetched::Done(Err(error)) => SharedOutcome::Ready(Err(Arc::new(error))),
                    Fetched::Withdrawn => SharedOutcome::Withdrawn,
                }
            })
            .await
            .clone();
        if matches!(outcome, SharedOutcome::Withdrawn) {
            // A caller arriving next must start a fetch of its own, not join
            // this one and be told it was withdrawn.
            self.inflight
                .remove_if(key, |_, current| Arc::ptr_eq(current, &cell));
        }
        outcome
    }
}
