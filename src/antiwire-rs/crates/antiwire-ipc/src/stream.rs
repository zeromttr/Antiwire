//! Server-streaming replies, each fed by one task.
//!
//! A stream's task ends when its producer finishes, when the client goes
//! away, or when the server shuts down, whichever comes first. A producer
//! waiting on a quiet source therefore does not outlive its client, which a
//! task that only noticed a closed stream on its next send would.

use std::future::Future;

use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tokio_util::sync::CancellationToken;
use tonic::Status;

/// The client is gone; nothing more will be read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Closed;

/// The sending half of a server stream.
pub(crate) struct StreamSink<T> {
    tx: mpsc::Sender<Result<T, Status>>,
}

impl<T> StreamSink<T> {
    /// Sends `item`, waiting while the stream is full.
    pub(crate) async fn send(&self, item: T) -> Result<(), Closed> {
        self.tx.send(Ok(item)).await.map_err(|_| Closed)
    }

    /// Waits for room, then sends what `build` makes. A snapshot built this
    /// way is as fresh as it can be when it is queued.
    pub(crate) async fn send_with(&self, build: impl FnOnce() -> T) -> Result<(), Closed> {
        let permit = self.tx.reserve().await.map_err(|_| Closed)?;
        permit.send(Ok(build()));
        Ok(())
    }
}

/// Starts `produce` feeding a stream that queues up to `capacity` items.
///
/// The producer is polled before the client and shutdown checks, so one that
/// can still finish an operation (handing undelivered items back, say) does
/// so before it is dropped.
pub(crate) fn spawn_stream<T, F, Fut>(
    capacity: usize,
    shutdown: &CancellationToken,
    produce: F,
) -> ReceiverStream<Result<T, Status>>
where
    T: Send + 'static,
    F: FnOnce(StreamSink<T>) -> Fut,
    Fut: Future<Output = ()> + Send + 'static,
{
    let (tx, rx) = mpsc::channel(capacity);
    if shutdown.is_cancelled() {
        // Opened during shutdown: the stream ends at once, with nothing sent.
        return ReceiverStream::new(rx);
    }
    let client = tx.clone();
    let shutdown = shutdown.clone();
    let producing = produce(StreamSink { tx });
    tokio::spawn(async move {
        tokio::select! {
            biased;
            () = producing => {}
            () = client.closed() => {}
            () = shutdown.cancelled() => {}
        }
    });
    ReceiverStream::new(rx)
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::time::Duration;

    use tokio_stream::StreamExt as _;

    use super::*;

    /// Set when the producer future is dropped, finished or not.
    struct DropFlag(Arc<AtomicBool>);

    impl Drop for DropFlag {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }

    async fn ended(flag: &AtomicBool) -> bool {
        for _ in 0..100 {
            if flag.load(Ordering::SeqCst) {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        false
    }

    #[tokio::test]
    async fn a_waiting_producer_ends_when_the_client_leaves() {
        let dropped = Arc::new(AtomicBool::new(false));
        let flag = DropFlag(Arc::clone(&dropped));
        let stream = spawn_stream::<u32, _, _>(1, &CancellationToken::new(), |_sink| async move {
            let _flag = flag;
            std::future::pending::<()>().await;
        });

        drop(stream);

        assert!(ended(&dropped).await, "the producer outlived its client");
    }

    #[tokio::test]
    async fn shutdown_ends_the_stream() {
        let shutdown = CancellationToken::new();
        let mut stream = spawn_stream::<u32, _, _>(1, &shutdown, |sink| async move {
            let _ = sink.send(1).await;
            std::future::pending::<()>().await;
        });
        assert_eq!(stream.next().await.map(Result::ok), Some(Some(1)));

        shutdown.cancel();

        assert!(tokio::time::timeout(Duration::from_secs(1), stream.next())
            .await
            .expect("ended")
            .is_none());
    }

    #[tokio::test]
    async fn items_are_delivered_in_order_and_the_stream_ends_with_the_producer() {
        let stream = spawn_stream(2, &CancellationToken::new(), |sink| async move {
            for item in 0..5_u32 {
                if sink.send_with(|| item).await.is_err() {
                    return;
                }
            }
        });

        let items: Vec<_> = stream.map(|item| item.expect("item")).collect().await;

        assert_eq!(items, vec![0, 1, 2, 3, 4]);
    }
}
