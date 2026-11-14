//! A slow read run on a thread of its own.

use std::io;
use std::sync::mpsc::{Receiver, SyncSender, TryRecvError, sync_channel};
use std::thread::{self, JoinHandle};

/// Runs a read that takes a while on a thread of its own, so the thread that wants the
/// result never waits for it.
///
/// A thread that must keep emptying a kernel buffer cannot stop to list every socket on the
/// host: what arrives while it does is dropped. It asks for the read with
/// [`request`](Self::request), carries on, and collects the result with
/// [`take`](Self::take) once it is there. One read is under way at most, and a request made
/// before the last result was taken is ignored, so results never queue up.
///
/// Dropping this waits for a read under way to finish, then ends the thread.
#[derive(Debug)]
pub struct BackgroundRead<T> {
    /// Dropped to end the thread.
    requests: Option<SyncSender<()>>,
    results: Receiver<T>,
    /// Whether a read was asked for and its result not yet taken.
    pending: bool,
    worker: Option<JoinHandle<()>>,
}

impl<T: Send + 'static> BackgroundRead<T> {
    /// Starts a thread called `name` that runs `read` each time it is asked to.
    ///
    /// # Errors
    ///
    /// Returns the reason the thread could not be started.
    pub fn start(name: &str, mut read: impl FnMut() -> T + Send + 'static) -> io::Result<Self> {
        // Each holds one item at most: `pending` admits one request, and a request is what
        // a result answers. So neither side ever waits to send.
        let (requests, wanted) = sync_channel::<()>(1);
        let (finished, results) = sync_channel(1);
        let worker = thread::Builder::new()
            .name(name.to_owned())
            .spawn(move || {
                while wanted.recv().is_ok() {
                    if finished.send(read()).is_err() {
                        break;
                    }
                }
            })?;
        Ok(Self {
            requests: Some(requests),
            results,
            pending: false,
            worker: Some(worker),
        })
    }

    /// Asks for a read, unless one asked for earlier has not been taken yet.
    pub fn request(&mut self) {
        if self.pending {
            return;
        }
        if let Some(requests) = &self.requests {
            self.pending = requests.try_send(()).is_ok();
        }
    }

    /// The result of the read asked for, once it has finished. Does not wait.
    pub fn take(&mut self) -> Option<T> {
        if !self.pending {
            return None;
        }
        match self.results.try_recv() {
            Ok(result) => {
                self.pending = false;
                Some(result)
            }
            Err(TryRecvError::Empty) => None,
            Err(TryRecvError::Disconnected) => {
                self.pending = false;
                None
            }
        }
    }

    /// Whether the thread has ended, which it does only when `read` panics. No further
    /// request is answered then.
    #[must_use]
    pub fn has_stopped(&self) -> bool {
        self.worker.as_ref().is_none_or(JoinHandle::is_finished)
    }
}

impl<T> Drop for BackgroundRead<T> {
    fn drop(&mut self) {
        self.requests = None;
        if let Some(worker) = self.worker.take() {
            // A panic in `read` ended the thread already; there is nothing to do about it
            // here.
            let _ = worker.join();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::mpsc::channel;
    use std::time::{Duration, Instant};

    /// Waits for the result of the read asked for.
    fn wait_for<T: Send + 'static>(read: &mut BackgroundRead<T>) -> T {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if let Some(result) = read.take() {
                return result;
            }
            assert!(Instant::now() < deadline, "the read did not finish");
            thread::sleep(Duration::from_millis(1));
        }
    }

    #[test]
    fn a_read_runs_once_for_each_request_taken() {
        let runs = Arc::new(AtomicU32::new(0));
        let counted = Arc::clone(&runs);
        let mut read = BackgroundRead::start("test-read", move || {
            counted.fetch_add(1, Ordering::SeqCst) + 1
        })
        .expect("start");
        assert_eq!(read.take(), None, "nothing was asked for");

        read.request();
        assert_eq!(wait_for(&mut read), 1);
        assert_eq!(read.take(), None, "a result is taken once");

        read.request();
        assert_eq!(wait_for(&mut read), 2);
        assert_eq!(runs.load(Ordering::SeqCst), 2);
    }

    /// The owner neither waits for a read nor piles up requests behind one.
    #[test]
    fn a_request_made_before_the_result_is_taken_is_ignored() {
        let (release, released) = channel::<()>();
        let runs = Arc::new(AtomicU32::new(0));
        let counted = Arc::clone(&runs);
        let mut read = BackgroundRead::start("test-read", move || {
            released.recv().expect("release");
            counted.fetch_add(1, Ordering::SeqCst) + 1
        })
        .expect("start");

        read.request();
        read.request();
        read.request();
        assert_eq!(read.take(), None, "the read is still under way");
        release.send(()).expect("release the read");
        assert_eq!(wait_for(&mut read), 1);

        // Had the extra requests been queued, a second read would now be waiting.
        drop(read);
        assert_eq!(runs.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn a_read_that_panics_stops_and_says_so() {
        let mut read =
            BackgroundRead::<u32>::start("test-read", || panic!("the read failed")).expect("start");
        assert!(!read.has_stopped());
        read.request();
        let deadline = Instant::now() + Duration::from_secs(10);
        while !read.has_stopped() {
            assert!(Instant::now() < deadline, "the thread did not end");
            thread::sleep(Duration::from_millis(1));
        }
        assert_eq!(read.take(), None);
        read.request();
        assert_eq!(read.take(), None);
    }
}
