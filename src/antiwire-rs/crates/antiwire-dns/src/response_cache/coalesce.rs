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
    /// The generation this fetch started under was retired mid-flight, so the
    /// answer was discarded instead of served or cached. Every waiter may
    /// safely retry under the current generation.
    GenerationRetired,
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
    pub(crate) async fn resolve_once<F, Fut>(
        &self,
        key: &CacheKey,
        generation_at_start: u64,
        init: &F,
    ) -> SharedOutcome
    where
        F: Fn() -> Fut,
        Fut: std::future::Future<Output = Result<CachedAnswer>>,
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

        cell.result
            .get_or_init(|| async move {
                if self.generation.load(Ordering::Acquire) != generation_at_start {
                    return SharedOutcome::GenerationRetired;
                }

                match init().await {
                    Ok(entry) => {
                        let _generation_guard = self.generation_gate.read();
                        if self.generation.load(Ordering::Acquire) == generation_at_start {
                            if entry.cacheable {
                                self.inner.insert(key.clone(), entry.clone());
                            }
                            self.clear_failure(key);
                            SharedOutcome::Ready(Ok(entry))
                        } else {
                            // The upstream exchange raced a generation bump;
                            // discard rather than adopt or cache it.
                            SharedOutcome::GenerationRetired
                        }
                    }
                    Err(error) => SharedOutcome::Ready(Err(Arc::new(error))),
                }
            })
            .await
            .clone()
    }
}
