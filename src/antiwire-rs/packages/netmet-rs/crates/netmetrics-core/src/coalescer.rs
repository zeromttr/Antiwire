use crate::{ByteDelta, FlowKey};
use std::collections::{BTreeSet, HashMap};
use std::time::{Duration, Instant};

#[derive(Clone, Copy, Debug)]
struct PendingBytes {
    delta: ByteDelta,
    deadline: Instant,
}

/// Per-flow byte accumulator with timer and size-based flushing.
///
/// Deadlines use elapsed monotonic time. Event timestamps stay on the public
/// [`ByteDelta`] path and are never used to schedule flushes.
#[derive(Debug)]
pub struct IngressCoalescer {
    pending: HashMap<FlowKey, PendingBytes>,
    deadlines: BTreeSet<(Instant, FlowKey)>,
    interval: Duration,
    byte_threshold: u64,
}

impl IngressCoalescer {
    /// Creates a coalescer. A threshold of zero disables size-based flushes.
    ///
    /// # Panics
    ///
    /// Panics when `interval_ms` is zero.
    pub fn new(interval_ms: u64, byte_threshold: u64) -> Self {
        assert!(interval_ms > 0, "coalescing interval must be non-zero");
        Self {
            pending: HashMap::new(),
            deadlines: BTreeSet::new(),
            interval: Duration::from_millis(interval_ms),
            byte_threshold,
        }
    }

    /// Adds a delta and returns it immediately when the byte threshold is reached.
    pub fn push(
        &mut self,
        key: FlowKey,
        delta: ByteDelta,
        now: Instant,
    ) -> Option<(FlowKey, ByteDelta)> {
        if delta.is_zero() {
            return None;
        }
        let pending = self.pending.entry(key).or_insert_with(|| {
            let deadline = now.checked_add(self.interval).unwrap_or(now);
            self.deadlines.insert((deadline, key));
            PendingBytes {
                delta: ByteDelta::default(),
                deadline,
            }
        });
        pending.delta.saturating_add_assign(delta);
        if self.byte_threshold > 0 && pending.delta.total() >= self.byte_threshold {
            return self.take(&key).map(|bytes| (key, bytes));
        }
        None
    }

    /// Removes a flow's pending delta.
    pub fn take(&mut self, key: &FlowKey) -> Option<ByteDelta> {
        self.pending.remove(key).map(|pending| {
            self.deadlines.remove(&(pending.deadline, *key));
            pending.delta
        })
    }

    /// Flushes all deltas whose monotonic deadline has been reached.
    pub fn drain_due(&mut self, now: Instant) -> Vec<(FlowKey, ByteDelta)> {
        let mut due_keys = Vec::new();
        while self
            .deadlines
            .first()
            .is_some_and(|(deadline, _)| *deadline <= now)
        {
            let Some((_, key)) = self.deadlines.pop_first() else {
                break;
            };
            if let Some(pending) = self.pending.remove(&key) {
                due_keys.push((key, pending.delta));
            }
        }
        due_keys.sort_unstable_by_key(|(key, _)| *key);
        due_keys
    }

    /// Flushes every pending delta in deterministic key order.
    pub fn drain_all(&mut self) -> Vec<(FlowKey, ByteDelta)> {
        self.deadlines.clear();
        let mut keys: Vec<_> = self.pending.keys().copied().collect();
        keys.sort_unstable();
        keys.into_iter()
            .filter_map(|key| self.take(&key).map(|delta| (key, delta)))
            .collect()
    }

    /// Returns the number of flows with pending bytes.
    pub fn len(&self) -> usize {
        self.pending.len()
    }

    /// Returns true when no deltas are pending.
    pub fn is_empty(&self) -> bool {
        self.pending.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Protocol;
    use std::net::{IpAddr, Ipv4Addr};

    fn key(port: u16) -> FlowKey {
        FlowKey {
            protocol: Protocol::Tcp,
            local_addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
            local_port: port,
            remote_addr: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 4)),
            remote_port: 443,
        }
    }

    #[test]
    fn coalesces_exact_totals_until_timer() {
        let mut coalescer = IngressCoalescer::new(250, 10_000);
        let start = Instant::now();
        assert!(
            coalescer
                .push(
                    key(1),
                    ByteDelta {
                        sent: 2,
                        received: 3,
                    },
                    start,
                )
                .is_none()
        );
        coalescer.push(
            key(1),
            ByteDelta {
                sent: 5,
                received: 7,
            },
            start + Duration::from_millis(100),
        );
        assert!(
            coalescer
                .drain_due(start + Duration::from_millis(249))
                .is_empty()
        );
        assert_eq!(
            coalescer.drain_due(start + Duration::from_millis(250)),
            vec![(
                key(1),
                ByteDelta {
                    sent: 7,
                    received: 10
                }
            )]
        );
    }

    #[test]
    fn threshold_flushes_without_losing_bytes() {
        let mut coalescer = IngressCoalescer::new(250, 10);
        let start = Instant::now();
        coalescer.push(
            key(1),
            ByteDelta {
                sent: 4,
                received: 0,
            },
            start,
        );
        let flushed = coalescer
            .push(
                key(1),
                ByteDelta {
                    sent: 3,
                    received: 3,
                },
                start + Duration::from_millis(1),
            )
            .expect("threshold flush");
        assert_eq!(flushed.1.total(), 10);
        assert!(coalescer.is_empty());
    }

    #[test]
    fn stale_deadlines_do_not_flush_reused_keys_early() {
        let mut coalescer = IngressCoalescer::new(100, 0);
        let start = Instant::now();
        coalescer.push(
            key(1),
            ByteDelta {
                sent: 10,
                received: 0,
            },
            start,
        );
        assert!(coalescer.take(&key(1)).is_some());
        coalescer.push(
            key(1),
            ByteDelta {
                sent: 1,
                received: 0,
            },
            start + Duration::from_millis(40),
        );
        assert!(
            coalescer
                .drain_due(start + Duration::from_millis(100))
                .is_empty()
        );
        assert_eq!(
            coalescer
                .drain_due(start + Duration::from_millis(140))
                .len(),
            1
        );
        assert!(coalescer.deadlines.is_empty());
    }

    #[test]
    fn early_flushes_do_not_accumulate_stale_deadlines() {
        let mut coalescer = IngressCoalescer::new(100, 1);
        let start = Instant::now();
        for offset in 0..10_000 {
            assert!(
                coalescer
                    .push(
                        key(1),
                        ByteDelta {
                            sent: 1,
                            received: 0,
                        },
                        start + Duration::from_millis(offset),
                    )
                    .is_some()
            );
        }
        assert!(coalescer.deadlines.is_empty());
    }
}
