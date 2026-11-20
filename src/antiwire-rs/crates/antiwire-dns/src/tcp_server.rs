//! Bounded TCP ingress for the DNS listener.
//!
//! Connections are admitted against a process-wide connection cap before a
//! task is created, and each one holds its slot until it closes or sits idle
//! past the I/O timeout, and none is kept past a fixed lifetime. Queries are framed with a two-byte length prefix
//! (RFC 1035 §4.2.2) and answered the same way as UDP: local answers from the
//! connection task, misses on their own tasks. DNS over TCP permits
//! out-of-order replies, so pipelined misses run concurrently up to a
//! per-connection concurrency limit, and reading pauses while that
//! limit is reached.

use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use bytes::Bytes;
use futures_util::{SinkExt, StreamExt};
use tokio::net::tcp::OwnedWriteHalf;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, Semaphore};
use tokio::task::JoinSet;
use tokio::time::{sleep, sleep_until, timeout, timeout_at};
use tokio_util::codec::{FramedRead, FramedWrite, LengthDelimitedCodec};
use tokio_util::sync::CancellationToken;
use tracing::{debug, warn};

use antiwire_tuning::{
    DNS_TCP_ACCEPT_ERROR_BACKOFF, DNS_TCP_IO_TIMEOUT, DNS_TCP_MAX_CONNECTION_LIFETIME,
};

use crate::listener::Transport;
use crate::service::{Answer, Query, Reply};
use crate::{DnsError, Result};

/// Queries one connection may have waiting on upstream at once, which keeps a
/// single client from consuming the process-wide cap.
const TCP_QUERY_CONCURRENCY: usize = 4;

/// Serves one TCP listener, admitting connections against `connections`.
pub(crate) async fn serve_tcp<F, M, R, A>(
    listener: TcpListener,
    resolve: F,
    forward: M,
    connections: Arc<Semaphore>,
    shutdown: CancellationToken,
) -> Result<()>
where
    F: Fn(Query<'_>) -> Answer<R> + Clone + Send + 'static,
    R: Send + 'static,
    M: Fn(R) -> A + Clone + Send + 'static,
    A: Future<Output = Reply> + Send + 'static,
{
    let mut tasks = JoinSet::new();
    let mut rejections: u64 = 0;

    // Connections watch a child token so the accept loop can cancel established
    // connections on the way out (unrecoverable accept error) instead of waiting
    // for each one to go idle. Global shutdown still propagates from
    // the parent token.
    let connection_shutdown = shutdown.child_token();

    loop {
        let accepted = tokio::select! {
            accepted = listener.accept() => accepted,
            () = shutdown.cancelled() => break,
        };

        let (stream, src) = match accepted {
            Ok(accepted) => accepted,
            Err(error) => {
                debug!(%error, "error accepting dns tcp connection");
                if is_unrecoverable_socket_error(&error) {
                    break;
                }
                // A failure that is not about one connection, such as running
                // out of descriptors, repeats at once; wait instead of spinning.
                if !is_connection_error(&error) {
                    tokio::select! {
                        () = sleep(DNS_TCP_ACCEPT_ERROR_BACKOFF) => {}
                        () = shutdown.cancelled() => break,
                    }
                }
                continue;
            }
        };

        // At the cap the connection is closed, not queued.
        let Ok(slot) = Arc::clone(&connections).try_acquire_owned() else {
            rejections += 1;
            if rejections.is_power_of_two() {
                warn!(
                    rejections,
                    "dns tcp connection cap reached; dropping connections"
                );
            }
            continue;
        };
        if let Err(error) = stream.set_nodelay(true) {
            debug!(%src, %error, "failed to disable Nagle on dns tcp connection");
        }
        let connection = serve_connection(
            stream,
            src,
            resolve.clone(),
            forward.clone(),
            connection_shutdown.clone(),
        );
        tasks.spawn(async move {
            let _slot = slot;
            connection.await;
        });
        reap_tasks(&mut tasks);
    }

    // The accept loop has exited, so no new connections can arrive. Cancel every
    // established connection now rather than blocking the join on their idle
    // timeouts.
    connection_shutdown.cancel();

    while let Some(result) = tasks.join_next().await {
        if let Err(error) = result {
            warn!(%error, "dns tcp connection task failed during shutdown");
        }
    }

    if shutdown.is_cancelled() {
        Ok(())
    } else {
        Err(DnsError::Bind(
            "unexpected close of TCP listener".to_owned(),
        ))
    }
}

fn dns_framing() -> LengthDelimitedCodec {
    LengthDelimitedCodec::builder()
        .length_field_type::<u16>()
        .new_codec()
}

/// Reads and answers queries until the connection ends, then flushes replies.
///
/// Local answers are written straight from this loop. Misses reply through a
/// channel the loop drains between reads, so one task owns both halves of the
/// socket and cancelling the connection stops everything at once.
async fn serve_connection<F, M, R, A>(
    stream: TcpStream,
    src: SocketAddr,
    resolve: F,
    forward: M,
    shutdown: CancellationToken,
) where
    F: Fn(Query<'_>) -> Answer<R>,
    M: Fn(R) -> A,
    A: Future<Output = Reply> + Send + 'static,
{
    let (read, write) = stream.into_split();
    let mut frames = FramedRead::new(read, dns_framing());
    let mut sink = FramedWrite::new(write, dns_framing());
    // A miss frees its concurrency slot before it queues its reply, so a
    // finishing miss can wait here for room; the loop and the close path both
    // drain the queue, so that wait always ends.
    let (replies, mut outbox) = mpsc::channel(TCP_QUERY_CONCURRENCY);
    let misses = Arc::new(Semaphore::new(TCP_QUERY_CONCURRENCY));
    let mut tasks = JoinSet::new();
    let close_at = tokio::time::Instant::now() + DNS_TCP_MAX_CONNECTION_LIFETIME;

    loop {
        reap_request_tasks(&mut tasks, src);
        let next = tokio::select! {
            // In this order, so a client that keeps sending cannot hold off
            // shutdown or the lifetime. Queued replies go out before another
            // query is read: a finished miss has given back its concurrency
            // slot, so reading on while its reply waits would let the client
            // have more replies owed than the limit allows misses.
            biased;
            () = shutdown.cancelled() => break,
            () = sleep_until(close_at) => {
                debug!(%src, "dns tcp connection reached its lifetime; closing");
                break;
            }
            Some(reply) = outbox.recv() => {
                if write_reply(&mut sink, reply, src, io_deadline()).await {
                    continue;
                }
                break;
            }
            next = timeout(DNS_TCP_IO_TIMEOUT, frames.next()) => next,
        };
        let frame = match next {
            Ok(Some(Ok(frame))) => frame,
            Ok(Some(Err(error))) => {
                debug!(%src, %error, "error reading dns tcp request");
                break;
            }
            Ok(None) | Err(_) => break,
        };
        let query = Query {
            wire: &frame,
            src,
            transport: Transport::Tcp,
            received_at: Instant::now(),
        };

        match resolve(query) {
            Answer::Local(reply) => {
                if !write_reply(&mut sink, reply, src, io_deadline()).await {
                    break;
                }
                // A local answer never waits, so a busy pipelining client
                // would otherwise keep this task running while other
                // connections queue behind it. Yielding keeps tail latency
                // across connections where a task per query used to put it.
                tokio::task::yield_now().await;
            }
            Answer::Ignored => {}
            Answer::Miss(miss) => {
                // Reading pauses here while the connection's misses are all in
                // flight; their replies are queued, not lost, meanwhile.
                let slot = tokio::select! {
                    slot = Arc::clone(&misses).acquire_owned() => slot,
                    () = shutdown.cancelled() => break,
                };
                // `misses` is never closed.
                let Ok(slot) = slot else { break };
                let reply = forward(miss);
                let replies = replies.clone();
                tasks.spawn(async move {
                    let reply = reply.await;
                    drop(slot);
                    // Fails only once the connection has given up on the client.
                    let _ = replies.send(reply).await;
                });
            }
        }
    }

    // Admitted queries finish and queue their replies; write them out before
    // closing. Draining while they finish, not after, matters: more replies
    // can be owed than the queue holds, and a task blocked on a full queue
    // would never finish. The queue ends once every task has dropped its
    // sender. The whole drain gets one I/O timeout, not one per reply, so a
    // client reading just fast enough to take each reply in time cannot keep
    // the connection, and its slot, open for a timeout per reply owed.
    drop(replies);
    let drain_until = io_deadline();
    while let Ok(Some(reply)) = timeout_at(drain_until, outbox.recv()).await {
        if !write_reply(&mut sink, reply, src, drain_until).await {
            break;
        }
    }
    // A client that stopped reading gets no more; closing the queue fails the
    // remaining sends so their tasks end.
    drop(outbox);
    while let Some(result) = tasks.join_next().await {
        log_request_task_result(result, src);
    }
}

/// When an I/O operation starting now times out.
fn io_deadline() -> tokio::time::Instant {
    tokio::time::Instant::now() + DNS_TCP_IO_TIMEOUT
}

/// Writes one framed reply by `deadline`, returning false once the client is
/// unusable.
async fn write_reply(
    sink: &mut FramedWrite<OwnedWriteHalf, LengthDelimitedCodec>,
    reply: Reply,
    src: SocketAddr,
    deadline: tokio::time::Instant,
) -> bool {
    let (bytes, receipt) = reply.into_parts();
    match timeout_at(deadline, sink.send(Bytes::from(bytes))).await {
        Ok(Ok(())) => {
            receipt.delivered();
            true
        }
        Ok(Err(error)) => {
            debug!(%src, %error, "error writing dns tcp reply");
            false
        }
        Err(_) => {
            debug!(%src, "dns tcp client stopped reading; closing");
            false
        }
    }
}

fn reap_request_tasks(tasks: &mut JoinSet<()>, src: SocketAddr) {
    while let Some(result) = tasks.try_join_next() {
        log_request_task_result(result, src);
    }
}

fn log_request_task_result(
    result: std::result::Result<(), tokio::task::JoinError>,
    src: SocketAddr,
) {
    if let Err(error) = result {
        warn!(%src, %error, "dns tcp request task failed");
    }
}

fn reap_tasks(tasks: &mut JoinSet<()>) {
    while let Some(result) = tasks.try_join_next() {
        if let Err(error) = result {
            warn!(%error, "dns tcp connection task failed");
        }
    }
}

/// An `accept` error about one connection: the peer went away between the
/// handshake and `accept`. The listener is healthy, so the loop retries at once.
fn is_connection_error(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::ConnectionAborted
            | io::ErrorKind::ConnectionRefused
            | io::ErrorKind::ConnectionReset
    )
}

/// An `accept` error that means the listener itself is unusable, so retrying
/// the same call cannot succeed. The accept loop stops and the supervisor
/// rebinds the listener.
///
/// Any other `accept` error, such as running out of descriptors, is neither
/// connection-specific nor fatal: the loop backs off and retries.
///
/// The UDP listener follows the same rule (one sender: retry at once; the
/// socket: rebind; anything else: back off), but its sets differ because
/// `recv_from` reports different things. `ConnectionAborted` is the visible
/// case: here one client gave up before being accepted, while on an
/// unconnected UDP socket it can only mean the socket was torn down. See
/// `classify_receive_error` in `udp_server.rs`.
fn is_unrecoverable_socket_error(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::InvalidInput
            | io::ErrorKind::NotConnected
            | io::ErrorKind::PermissionDenied
            | io::ErrorKind::Unsupported
    )
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    use hickory_proto::op::Message;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;
    use crate::service::testing::{forward, query_wire, resolve};

    struct Harness {
        server: tokio::task::JoinHandle<Result<()>>,
        server_addr: SocketAddr,
        started: Arc<AtomicUsize>,
        release: Arc<Semaphore>,
        shutdown: CancellationToken,
    }

    impl Harness {
        async fn start(connections: usize) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").await.expect("server bind");
            let server_addr = listener.local_addr().expect("server address");
            let started = Arc::new(AtomicUsize::new(0));
            let release = Arc::new(Semaphore::new(0));
            let shutdown = CancellationToken::new();
            let server = tokio::spawn(serve_tcp(
                listener,
                resolve(),
                forward(&started, &release),
                Arc::new(Semaphore::new(connections)),
                shutdown.clone(),
            ));
            Self {
                server,
                server_addr,
                started,
                release,
                shutdown,
            }
        }

        async fn connect(&self) -> TcpStream {
            TcpStream::connect(self.server_addr)
                .await
                .expect("client connect")
        }

        async fn stop(self, release: usize) {
            self.shutdown.cancel();
            self.release.add_permits(release);
            timeout(Duration::from_secs(1), self.server)
                .await
                .expect("server shutdown timeout")
                .expect("server task")
                .expect("clean shutdown");
        }
    }

    async fn send(client: &mut TcpStream, id: u16, name: &str) {
        let wire = query_wire(id, name);
        let len = u16::try_from(wire.len()).expect("DNS TCP frame length");
        client.write_all(&len.to_be_bytes()).await.expect("length");
        client.write_all(&wire).await.expect("query");
    }

    async fn recv(client: &mut TcpStream) -> Message {
        let mut len = [0u8; 2];
        timeout(Duration::from_secs(1), client.read_exact(&mut len))
            .await
            .expect("reply arrives")
            .expect("reply length");
        let mut wire = vec![0u8; usize::from(u16::from_be_bytes(len))];
        client.read_exact(&mut wire).await.expect("reply body");
        Message::from_vec(&wire).expect("valid reply")
    }

    #[tokio::test]
    async fn connection_admission_is_strict_and_recoverable() {
        let harness = Harness::start(1).await;
        let mut first = harness.connect().await;
        send(&mut first, 1, "cached.test.").await;
        assert_eq!(recv(&mut first).await.metadata.id, 1);

        // Over the cap: accepted by the kernel, then closed without a reply.
        let mut second = harness.connect().await;
        send(&mut second, 2, "cached.test.").await;
        let mut byte = [0u8; 1];
        let read = timeout(Duration::from_secs(1), second.read(&mut byte))
            .await
            .expect("rejected connection closes");
        assert!(matches!(read, Ok(0) | Err(_)));

        // Closing the first connection frees its slot.
        drop(first);
        timeout(Duration::from_secs(1), async {
            loop {
                let mut third = harness.connect().await;
                send(&mut third, 3, "cached.test.").await;
                let mut len = [0u8; 2];
                if third.read_exact(&mut len).await.is_ok() {
                    break;
                }
            }
        })
        .await
        .expect("a freed slot admits a new connection");
        harness.stop(0).await;
    }

    /// The regression this guards: a client sending a query just inside the
    /// idle timeout kept its connection slot forever.
    #[tokio::test(start_paused = true)]
    async fn a_busy_connection_is_closed_at_its_lifetime() {
        let harness = Harness::start(1).await;
        let mut client = harness.connect().await;
        // Waiting on a real socket counts as idle, so the paused clock would jump
        // to the server's read timeout while a query is still in the kernel and
        // close the connection early. A task that never idles leaves the clock to
        // `advance` alone.
        let busy = tokio::spawn(async {
            loop {
                tokio::task::yield_now().await;
            }
        });
        let mut id = 0;
        let started = tokio::time::Instant::now();
        let closed = loop {
            id += 1;
            let wire = query_wire(id, "cached.test.");
            let mut frame = u16::try_from(wire.len())
                .expect("length")
                .to_be_bytes()
                .to_vec();
            frame.extend_from_slice(&wire);
            let mut len = [0u8; 2];
            if client.write_all(&frame).await.is_err() || client.read_exact(&mut len).await.is_err()
            {
                break started.elapsed();
            }
            let mut wire = vec![0u8; usize::from(u16::from_be_bytes(len))];
            client.read_exact(&mut wire).await.expect("reply body");
            tokio::time::advance(DNS_TCP_IO_TIMEOUT / 2).await;
        };
        busy.abort();
        assert!(closed >= DNS_TCP_MAX_CONNECTION_LIFETIME);
        assert!(closed < DNS_TCP_MAX_CONNECTION_LIFETIME + DNS_TCP_IO_TIMEOUT);
        harness.stop(0).await;
    }

    #[tokio::test]
    async fn local_and_upstream_replies_share_a_connection() {
        let harness = Harness::start(1).await;
        harness.release.add_permits(1);
        let mut client = harness.connect().await;
        send(&mut client, 1, "upstream.test.").await;
        send(&mut client, 2, "cached.test.").await;
        let mut ids = [
            recv(&mut client).await.metadata.id,
            recv(&mut client).await.metadata.id,
        ];
        ids.sort_unstable();
        assert_eq!(ids, [1, 2]);
        harness.stop(0).await;
    }

    #[tokio::test]
    async fn pipelined_misses_run_concurrently_up_to_the_connection_limit() {
        let harness = Harness::start(1).await;
        let mut client = harness.connect().await;
        for id in 0..=u16::try_from(TCP_QUERY_CONCURRENCY).expect("small") {
            send(&mut client, id, "pipeline.test.").await;
        }

        let wait_for = |count: usize| {
            let started = Arc::clone(&harness.started);
            timeout(Duration::from_secs(1), async move {
                while started.load(Ordering::Relaxed) < count {
                    tokio::task::yield_now().await;
                }
            })
        };
        wait_for(TCP_QUERY_CONCURRENCY)
            .await
            .expect("concurrent pipelined queries start");
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert_eq!(
            harness.started.load(Ordering::Relaxed),
            TCP_QUERY_CONCURRENCY,
            "per-connection work remains bounded"
        );

        harness.release.add_permits(1);
        wait_for(TCP_QUERY_CONCURRENCY + 1)
            .await
            .expect("queued pipeline query starts after one completion");
        harness.stop(TCP_QUERY_CONCURRENCY).await;
    }

    /// The regression this guards: the loop chose between a queued reply and
    /// the client's next query at random. A finished miss has given back its
    /// concurrency slot, so while the loop read on, a client that kept
    /// sending had more replies owed than the limit allows misses: 12 to 39
    /// in a run of 20,000 pipelined misses with 16 KB replies.
    ///
    /// The queued reply and a query the loop could answer at once are both
    /// waiting when the loop next chooses; at random, all rounds would pass
    /// about once in 65,536 runs.
    #[tokio::test]
    async fn a_queued_reply_goes_out_before_the_next_query_is_read() {
        const ROUNDS: u16 = 16;
        // A connection per round, so a round never waits for the server to
        // see the last one close.
        let harness = Harness::start(usize::from(ROUNDS)).await;
        let wait_for = |count: usize| {
            let started = Arc::clone(&harness.started);
            async move {
                timeout(Duration::from_secs(1), async {
                    while started.load(Ordering::Relaxed) < count {
                        tokio::task::yield_now().await;
                    }
                })
                .await
                .expect("misses start");
            }
        };
        let in_flight = u16::try_from(TCP_QUERY_CONCURRENCY).expect("small");
        for round in 0..ROUNDS {
            let base = harness.started.load(Ordering::Relaxed);
            let mut client = harness.connect().await;
            // Fill every miss slot; the loop then waits for one with the next
            // miss in hand, reading nothing more.
            for id in 0..=in_flight {
                send(&mut client, id, "pipeline.test.").await;
            }
            wait_for(base + TCP_QUERY_CONCURRENCY).await;
            send(&mut client, 99, "cached.test.").await;
            tokio::time::sleep(Duration::from_millis(20)).await;
            // One miss finishes: its reply is queued, the waiting miss takes
            // its slot, and the cached query is still unread.
            harness.release.add_permits(1);
            let first = recv(&mut client).await.metadata.id;
            assert!(first < in_flight, "round {round}: reply {first} went first");
            harness.release.add_permits(TCP_QUERY_CONCURRENCY);
            for _ in 0..=in_flight {
                recv(&mut client).await;
            }
        }
        harness.stop(0).await;
    }

    /// The regression this guards: a miss frees its concurrency slot before
    /// queueing its reply, so a connection can hold more finished replies than
    /// the reply channel has room for. When the loop then exited, the extra
    /// task blocked on `send` while the close path waited for it, and the
    /// connection never closed or delivered its replies.
    ///
    /// The loop chose between the queued reply and the client's EOF at random
    /// then, so each round hit the bug about half the time. It now writes
    /// queued replies first, which leaves fewer owed at EOF; every round still
    /// checks that each one owed is delivered and the connection closes.
    #[tokio::test]
    async fn replies_queued_past_the_channel_still_drain_after_eof() {
        let harness = Harness::start(1).await;
        let wait_for = |count: usize| {
            let started = Arc::clone(&harness.started);
            async move {
                timeout(Duration::from_secs(1), async {
                    while started.load(Ordering::Relaxed) < count {
                        tokio::task::yield_now().await;
                    }
                })
                .await
                .expect("misses start");
            }
        };
        let in_flight = u16::try_from(TCP_QUERY_CONCURRENCY).expect("small");
        for round in 0..12 {
            let base = harness.started.load(Ordering::Relaxed);
            let mut client = harness.connect().await;
            // Fill every miss slot, then queue one more behind them.
            for id in 0..=in_flight {
                send(&mut client, id, "pipeline.test.").await;
            }
            wait_for(base + TCP_QUERY_CONCURRENCY).await;
            tokio::time::sleep(Duration::from_millis(20)).await;
            client.shutdown().await.expect("half-close");
            // One miss finishes: its reply is queued and the extra query takes
            // its slot, so five replies are now owed.
            harness.release.add_permits(1);
            wait_for(base + TCP_QUERY_CONCURRENCY + 1).await;
            harness.release.add_permits(TCP_QUERY_CONCURRENCY);
            let mut ids = Vec::new();
            for _ in 0..=in_flight {
                ids.push(recv(&mut client).await.metadata.id);
            }
            ids.sort_unstable();
            assert_eq!(ids, (0..=in_flight).collect::<Vec<_>>(), "round {round}");
            let mut byte = [0u8; 1];
            let read = timeout(Duration::from_secs(1), client.read(&mut byte))
                .await
                .expect("connection closes after its replies");
            assert!(matches!(read, Ok(0) | Err(_)));
        }
        harness.stop(0).await;
    }

    #[tokio::test]
    async fn shutdown_delivers_replies_for_admitted_queries() {
        let harness = Harness::start(1).await;
        let mut client = harness.connect().await;
        send(&mut client, 9, "drain.test.").await;
        timeout(Duration::from_secs(1), async {
            while harness.started.load(Ordering::Relaxed) == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("query starts");

        harness.shutdown.cancel();
        harness.release.add_permits(1);
        assert_eq!(recv(&mut client).await.metadata.id, 9);
        harness.stop(0).await;
    }
}
