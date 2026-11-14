use super::{FlowConsumer, SharedStats, SnapshotState, write_lock};
use netmetrics_core::{FlowEvent, FlowSnapshot, FlowSnapshotSeed, FlowTable};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, RwLock};
use std::thread::{self, JoinHandle};

/// Keeps expensive metadata cloning and snapshot lock acquisition off the ingress owner.
/// At most one periodic snapshot can be queued or materialized at a time.
pub(super) struct SnapshotPublisher {
    sender: Option<mpsc::SyncSender<FlowSnapshotSeed>>,
    pub(super) idle: Arc<AtomicBool>,
    worker: Option<JoinHandle<()>>,
    generation: u64,
}

impl SnapshotPublisher {
    pub(super) fn new(
        session_name: &str,
        snapshot: Arc<RwLock<SnapshotState>>,
        generation: u64,
    ) -> Option<Self> {
        let (sender, receiver) = mpsc::sync_channel::<FlowSnapshotSeed>(1);
        let idle = Arc::new(AtomicBool::new(true));
        let worker_idle = Arc::clone(&idle);
        let worker = thread::Builder::new()
            .name(format!("{session_name}-snapshot"))
            .spawn(move || {
                while let Ok(seed) = receiver.recv() {
                    publish_snapshot(&snapshot, generation, seed.into_snapshot());
                    worker_idle.store(true, Ordering::Release);
                }
            })
            .ok()?;
        Some(Self {
            sender: Some(sender),
            idle,
            worker: Some(worker),
            generation,
        })
    }

    pub(super) fn try_publish(&self, table: &FlowTable, captured_at: u64) -> bool {
        if self
            .idle
            .compare_exchange(true, false, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return false;
        }
        let Some(sender) = self.sender.as_ref() else {
            self.idle.store(true, Ordering::Release);
            return false;
        };
        if sender.try_send(table.snapshot_seed(captured_at)).is_err() {
            self.idle.store(true, Ordering::Release);
            return false;
        }
        true
    }

    pub(super) fn finish(
        mut self,
        table: &FlowTable,
        captured_at: u64,
        snapshot: &RwLock<SnapshotState>,
    ) {
        let generation = self.generation;
        let delivered = self
            .sender
            .take()
            .is_some_and(|sender| sender.send(table.snapshot_seed(captured_at)).is_ok());
        let joined = self
            .worker
            .take()
            .is_some_and(|worker| worker.join().is_ok());
        if !delivered || !joined {
            publish_snapshot(snapshot, generation, table.snapshot(captured_at));
        }
    }
}

pub(super) fn publish_snapshot(
    snapshot: &RwLock<SnapshotState>,
    generation: u64,
    next: FlowSnapshot,
) {
    let mut state = write_lock(snapshot);
    if state.generation == generation {
        state.snapshot = next;
    }
}

impl Drop for SnapshotPublisher {
    fn drop(&mut self) {
        self.sender.take();
        if let Some(worker) = self.worker.take() {
            // Never block panic unwinding on auxiliary teardown. The snapshot
            // worker exits on its own once the sender is dropped; detaching
            // here lets the collector thread terminate promptly so
            // `is_running` and `start` observe the failure without delay.
            // Normal shutdown uses `finish`, which joins explicitly.
            if thread::panicking() {
                return;
            }
            let _ = worker.join();
        }
    }
}

pub(super) fn flush_full_batches(
    batch: &mut Vec<FlowEvent>,
    output: &mut Vec<FlowEvent>,
    consumer: &mut dyn FlowConsumer,
    batch_size: usize,
    stats: &SharedStats,
) {
    let complete = (batch.len() / batch_size) * batch_size;
    if complete == 0 {
        return;
    }
    debug_assert!(output.is_empty());
    for event in batch.drain(..complete) {
        output.push(event);
        if output.len() == batch_size {
            let published = output.len();
            consumer.on_batch_buffer(output);
            stats
                .events_published
                .fetch_add(published as u64, Ordering::Relaxed);
        }
    }
    debug_assert!(output.is_empty());
}

pub(super) fn flush_batch(
    batch: &mut Vec<FlowEvent>,
    consumer: &mut dyn FlowConsumer,
    stats: &SharedStats,
) {
    if batch.is_empty() {
        return;
    }
    let published = batch.len();
    consumer.on_batch_buffer(batch);
    stats
        .events_published
        .fetch_add(published as u64, Ordering::Relaxed);
}
