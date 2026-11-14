//! Finishes client attribution off the reply path.
//!
//! The FLOW listener's owner for a query can lag the query by a moment, and a
//! lookup that waits for it must not hold up the answer. Work submitted here
//! runs in order on one thread, started on first use. A full queue refuses
//! the job and the caller records what it already has.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender, TrySendError};
use std::sync::Arc;
use std::thread::JoinHandle;

use parking_lot::Mutex;
use tracing::warn;

/// Jobs waiting for the worker. Each can take
/// `port_mapper::RECORDED_OWNER_TIMEOUT` plus a socket-table scan, so a full
/// queue is a backlog worth shedding, not one worth waiting out; jobs that
/// still run late skip the scan (see `port_mapper::deferred_query_owner`).
const QUEUE_CAPACITY: usize = 1_024;

pub(crate) type OwnerJob = Box<dyn FnOnce() + Send>;

#[derive(Default)]
struct Running {
    tx: Option<SyncSender<OwnerJob>>,
    thread: Option<JoinHandle<()>>,
}

/// One lazily started attribution thread.
#[derive(Default)]
pub(crate) struct OwnerWorker {
    running: Mutex<Running>,
    stopped: Arc<AtomicBool>,
}

impl OwnerWorker {
    /// Queues `job`, or hands it back when the queue is full or the worker
    /// cannot run.
    pub(crate) fn submit(&self, job: OwnerJob) -> Result<(), OwnerJob> {
        if self.stopped.load(Ordering::Acquire) {
            return Err(job);
        }
        let mut running = self.running.lock();
        if running.tx.is_none() {
            let (tx, rx) = mpsc::sync_channel(QUEUE_CAPACITY);
            let stopped = Arc::clone(&self.stopped);
            match std::thread::Builder::new()
                .name("antiwire-dns-owner".to_owned())
                .spawn(move || run(&rx, &stopped))
            {
                Ok(thread) => {
                    running.tx = Some(tx);
                    running.thread = Some(thread);
                }
                Err(error) => {
                    warn!(%error, "failed to start dns attribution worker");
                    return Err(job);
                }
            }
        }
        let Some(tx) = running.tx.as_ref() else {
            return Err(job);
        };
        match tx.try_send(job) {
            Ok(()) => Ok(()),
            Err(TrySendError::Full(job)) => Err(job),
            Err(TrySendError::Disconnected(job)) => {
                // The thread is gone, which `run` does not do on its own;
                // forget it so the next submit starts another.
                warn!("dns attribution worker exited; restarting it on the next query");
                *running = Running::default();
                Err(job)
            }
        }
    }

    /// Stops the worker, abandoning queued jobs, and joins it. Blocks for the
    /// job in progress; call it from a blocking thread.
    pub(crate) fn shutdown(&self) {
        self.stopped.store(true, Ordering::Release);
        let thread = {
            let mut running = self.running.lock();
            running.tx.take();
            running.thread.take()
        };
        if let Some(thread) = thread {
            if let Err(error) = thread.join() {
                warn!(?error, "dns attribution worker panicked");
            }
        }
    }
}

impl Drop for OwnerWorker {
    fn drop(&mut self) {
        // Closing the queue ends the thread after its current job. It is not
        // joined: the last holder may be a runtime thread that must not park.
        self.stopped.store(true, Ordering::Release);
        self.running.get_mut().tx.take();
    }
}

fn run(rx: &Receiver<OwnerJob>, stopped: &AtomicBool) {
    let mut panics: u64 = 0;
    while let Ok(job) = rx.recv() {
        if stopped.load(Ordering::Acquire) {
            return;
        }
        // One bad job must not end attribution for the rest of the process.
        // A job only records a hint, so nothing it shares is left half-done.
        if std::panic::catch_unwind(std::panic::AssertUnwindSafe(job)).is_err() {
            panics += 1;
            if panics.is_power_of_two() {
                warn!(
                    panics,
                    "dns attribution job panicked; continuing with the next"
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;
    use std::time::Duration;

    #[test]
    fn jobs_run_in_order_on_one_thread() {
        let worker = OwnerWorker::default();
        let order = Arc::new(Mutex::new(Vec::new()));
        for index in 0..10 {
            let order = Arc::clone(&order);
            let submitted = worker.submit(Box::new(move || {
                order.lock().push((index, std::thread::current().id()));
            }));
            assert!(submitted.is_ok());
        }
        worker.shutdown();
        let order = order.lock();
        let indices: Vec<i32> = order.iter().map(|(index, _)| *index).collect();
        assert!(
            indices.windows(2).all(|pair| pair[0] < pair[1]),
            "{indices:?}"
        );
        assert!(order.iter().all(|(_, thread)| *thread == order[0].1));
        assert_ne!(
            order.first().map(|(_, thread)| *thread),
            Some(std::thread::current().id())
        );
    }

    #[test]
    fn a_panicking_job_does_not_stop_the_jobs_after_it() {
        let worker = OwnerWorker::default();
        let (done_tx, done) = mpsc::channel();
        assert!(worker
            .submit(Box::new(|| panic!("attribution bug")))
            .is_ok());
        assert!(worker
            .submit(Box::new(move || done_tx.send(()).expect("done")))
            .is_ok());
        done.recv_timeout(Duration::from_secs(5))
            .expect("the next job still runs");
        worker.shutdown();
    }

    #[test]
    fn a_full_queue_hands_the_job_back() {
        let worker = OwnerWorker::default();
        let (release, gate) = mpsc::channel::<()>();
        let gate = Arc::new(std::sync::Mutex::new(gate));
        let blocker = Arc::clone(&gate);
        assert!(worker
            .submit(Box::new(move || {
                let _ = blocker.lock().expect("gate").recv();
            }))
            .is_ok());
        let ran = Arc::new(AtomicUsize::new(0));
        let mut refused = 0;
        for _ in 0..=QUEUE_CAPACITY + 1 {
            let ran = Arc::clone(&ran);
            if worker
                .submit(Box::new(move || {
                    ran.fetch_add(1, Ordering::Relaxed);
                }))
                .is_err()
            {
                refused += 1;
            }
        }
        assert!(refused >= 1, "an over-capacity submit must be refused");
        release.send(()).expect("release");
        worker.shutdown();
    }

    #[test]
    fn shutdown_abandons_queued_jobs_and_refuses_new_ones() {
        let worker = OwnerWorker::default();
        let (started_tx, started) = mpsc::channel();
        let (release, gate) = mpsc::channel::<()>();
        assert!(worker
            .submit(Box::new(move || {
                started_tx.send(()).expect("started");
                let _ = gate.recv_timeout(Duration::from_secs(5));
            }))
            .is_ok());
        started
            .recv_timeout(Duration::from_secs(5))
            .expect("first job runs");
        let ran = Arc::new(AtomicBool::new(false));
        let queued = Arc::clone(&ran);
        assert!(worker
            .submit(Box::new(move || queued.store(true, Ordering::Relaxed)))
            .is_ok());
        let shutting_down = std::thread::spawn({
            let release = release.clone();
            move || {
                std::thread::sleep(Duration::from_millis(20));
                let _ = release.send(());
            }
        });
        worker.shutdown();
        shutting_down.join().expect("release thread");
        assert!(
            !ran.load(Ordering::Relaxed),
            "queued job ran after shutdown"
        );
        assert!(worker.submit(Box::new(|| {})).is_err());
    }
}
