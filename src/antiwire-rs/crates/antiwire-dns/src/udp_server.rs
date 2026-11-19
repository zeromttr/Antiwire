//! Bounded UDP ingress for the DNS listener.
//!
//! Each datagram goes to `resolve` — in production [`crate::service::Resolve`] —
//! which answers policy blocks and cache hits without I/O. Those replies are
//! sent from the receive task itself, since a task per hit would only be an
//! allocation. Only a miss gets a task, running the `forward` service, and only
//! while a worker slot is free. Admission never waits: when every slot is busy
//! the miss is dropped for the sender to retransmit, so saturation never stalls
//! socket reads, and local answers need no slot at all, so they keep flowing
//! while upstream work is saturated.
//!
//! A local answer whose client must be looked up in the socket tables first is
//! the exception: it waits on a task of its own while the lookup scans, so the
//! scan stalls no other query (see [`send_after_lookups`]).

use std::convert::Infallible;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::ops::ControlFlow;
use std::sync::Arc;
use std::time::Instant;

use hickory_server::net::udp::MAX_RECEIVE_BUFFER_SIZE;
use hickory_server::net::xfer::Protocol;
use tokio::net::UdpSocket;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use tokio::time::sleep;
use tokio_util::sync::CancellationToken;
use tower::{Service, ServiceExt};
use tracing::{debug, warn};

use antiwire_tuning::{DNS_UDP_HELD_REPLIES, DNS_UDP_RECEIVE_ERROR_BACKOFF};

use crate::port_mapper::HandedOffLookups;
use crate::service::{Answer, Query, Reply};
use crate::{DnsError, Result};

/// Serves one UDP socket until `shutdown`, then drains admitted misses.
///
/// `workers` bounds misses in flight and is shared by every UDP socket.
pub(crate) async fn serve_udp<F, M, R>(
    socket: UdpSocket,
    resolve: F,
    mut forward: M,
    workers: Arc<Semaphore>,
    shutdown: CancellationToken,
) -> Result<()>
where
    F: Fn(Query) -> Answer<R>,
    M: Service<R, Response = Reply, Error = Infallible>,
    M::Future: Send + 'static,
{
    let socket = Arc::new(socket);
    let held = Arc::new(Semaphore::new(DNS_UDP_HELD_REPLIES));
    let mut buffer = vec![0u8; MAX_RECEIVE_BUFFER_SIZE];
    let mut tasks = JoinSet::new();
    let mut receive_errors: u64 = 0;
    let mut worker_rejections: u64 = 0;

    loop {
        reap_tasks(&mut tasks);
        let received = tokio::select! {
            received = socket.recv_from(&mut buffer) => received,
            () = shutdown.cancelled() => break,
        };

        let (len, src) = match received {
            Ok(received) => received,
            Err(error) => {
                receive_errors += 1;
                if handle_receive_error(&error, receive_errors, &shutdown)
                    .await
                    .is_break()
                {
                    break;
                }
                continue;
            }
        };
        let received_at = Instant::now();
        if !is_safe_response_source(src) {
            continue;
        }

        let query = Query {
            wire: buffer[..len].to_vec(),
            src,
            protocol: Protocol::Udp,
            received_at,
        };
        let miss = match resolve(query) {
            Answer::Local(mut reply) => {
                match reply.take_lookups() {
                    Some(lookups) => {
                        send_after_lookups(&mut tasks, &held, &socket, reply, lookups, src);
                    }
                    None => send_now(&socket, reply, src),
                }
                continue;
            }
            Answer::Ignored => continue,
            Answer::Miss(miss) => miss,
        };

        // Never waits, so a full pool drops this miss instead of parking the
        // receive loop behind in-flight work.
        let Ok(worker) = Arc::clone(&workers).try_acquire_owned() else {
            worker_rejections += 1;
            if worker_rejections.is_power_of_two() {
                warn!(
                    rejections = worker_rejections,
                    "dns udp upstream workers saturated; dropping queries that need upstream"
                );
            }
            continue;
        };
        let Ok(forward) = forward.ready().await;
        let reply = forward.call(miss);
        let socket = Arc::clone(&socket);
        tasks.spawn(async move {
            let _worker = worker;
            let Ok(reply) = reply.await;
            match socket.send_to(reply.bytes(), src).await {
                Ok(_) => reply.delivered(),
                Err(error) => debug!(%src, %error, "failed to send dns udp reply"),
            }
        });
    }

    if !shutdown.is_cancelled() {
        return Err(DnsError::Bind("unexpected close of UDP socket".to_owned()));
    }
    // Tasks send their own replies, so draining admitted work is only joining.
    while let Some(result) = tasks.join_next().await {
        if let Err(error) = result {
            warn!(%error, "dns udp request task failed during shutdown");
        }
    }
    Ok(())
}

/// Sends a local answer without waiting: a full socket send buffer drops this
/// one reply, which the client retransmits, rather than stalling reads.
fn send_now(socket: &UdpSocket, reply: Reply, dst: SocketAddr) {
    match socket.try_send_to(reply.bytes(), dst) {
        Ok(_) => reply.delivered(),
        Err(error) => debug!(%dst, %error, "dropped dns udp reply"),
    }
}

/// Sends `reply` once `lookups` have run, on a task of its own: they may scan
/// the socket tables, which the receive loop must not wait for, and must see
/// the client's socket before the reply lets the client close it.
///
/// Past [`DNS_UDP_HELD_REPLIES`] held at once, the reply goes at once and the
/// lookups are dropped, so those waiting for them look the owner up later.
fn send_after_lookups(
    tasks: &mut JoinSet<()>,
    held: &Arc<Semaphore>,
    socket: &Arc<UdpSocket>,
    reply: Reply,
    lookups: HandedOffLookups,
    dst: SocketAddr,
) {
    let Ok(slot) = Arc::clone(held).try_acquire_owned() else {
        drop(lookups);
        send_now(socket, reply, dst);
        return;
    };
    let socket = Arc::clone(socket);
    tasks.spawn(async move {
        let _slot = slot;
        // A lookup that panicked still lets the reply go.
        let _ = tokio::task::spawn_blocking(move || lookups.run()).await;
        match socket.send_to(reply.bytes(), dst).await {
            Ok(_) => reply.delivered(),
            Err(error) => debug!(%dst, %error, "failed to send dns udp reply"),
        }
    });
}

/// Rejects a datagram source that must never receive an answer: a zero port or
/// an unspecified address cannot be replied to, and a broadcast address does
/// not identify a single host. TCP needs no such check, since `accept` only
/// yields connected peers.
fn is_safe_response_source(src: SocketAddr) -> bool {
    if src.port() == 0 || src.ip().is_unspecified() {
        return false;
    }
    !matches!(src.ip(), IpAddr::V4(ip) if ip.is_broadcast())
}

fn reap_tasks(tasks: &mut JoinSet<()>) {
    while let Some(result) = tasks.try_join_next() {
        if let Err(error) = result {
            warn!(%error, "dns udp request task failed");
        }
    }
}

/// How the receive loop treats a failed `recv_from`.
///
/// The rule matches the TCP accept loop: an error about one sender is retried
/// at once, an error about the socket stops it so the supervisor rebinds it,
/// and anything else is retried after a pause so it cannot spin. The two sets
/// differ only because `accept` and `recv_from` report different things.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReceiveError {
    /// About one datagram. The socket is healthy, so the loop reads again at
    /// once.
    Datagram,
    /// The socket itself is unusable. The listener stops and the supervisor
    /// rebinds it, with its own backoff.
    Socket,
    /// Neither. The loop waits [`DNS_UDP_RECEIVE_ERROR_BACKOFF`] before reading
    /// again, so an error that repeats on every call cannot spin the loop.
    Unexpected,
}

/// Windows `WSAEMSGSIZE`: a datagram larger than the receive buffer.
#[cfg(windows)]
const WSAEMSGSIZE: i32 = 10040;
/// Windows `WSAENETRESET`: an ICMP "TTL expired" for an earlier send.
#[cfg(windows)]
const WSAENETRESET: i32 = 10052;

fn classify_receive_error(error: &io::Error) -> ReceiveError {
    #[cfg(windows)]
    if matches!(error.raw_os_error(), Some(WSAEMSGSIZE | WSAENETRESET)) {
        return ReceiveError::Datagram;
    }
    match error.kind() {
        // ICMP errors for an earlier reply. Windows reports port unreachable
        // as `WSAECONNRESET` unless `disable_udp_connreset_reporting` turned
        // it off, so it is still classified here in case that failed.
        io::ErrorKind::ConnectionReset
        | io::ErrorKind::ConnectionRefused
        | io::ErrorKind::Interrupted => ReceiveError::Datagram,
        // An unconnected UDP socket has no connection to lose, so either of
        // these means the stack tore the socket down, for example on an
        // adapter reset. TCP `accept` retries `ConnectionAborted` instead,
        // because there it means one client gave up before being accepted.
        io::ErrorKind::NotConnected | io::ErrorKind::ConnectionAborted => ReceiveError::Socket,
        _ => ReceiveError::Unexpected,
    }
}

/// Acts on a failed `recv_from`, returning `Break` when the loop must stop.
///
/// Per-datagram errors arrive once per offending datagram, so any local
/// process could otherwise drive one log line per packet. Logging is
/// throttled like every other drop path in this crate.
async fn handle_receive_error(
    error: &io::Error,
    receive_errors: u64,
    shutdown: &CancellationToken,
) -> ControlFlow<()> {
    let class = classify_receive_error(error);
    if class == ReceiveError::Socket {
        warn!(%error, "unrecoverable error on dns udp socket; stopping listener");
        return ControlFlow::Break(());
    }
    if receive_errors.is_power_of_two() {
        warn!(
            %error,
            receive_errors,
            "error receiving message on dns udp socket; continuing"
        );
    }
    if class == ReceiveError::Unexpected {
        tokio::select! {
            () = sleep(DNS_UDP_RECEIVE_ERROR_BACKOFF) => {}
            () = shutdown.cancelled() => return ControlFlow::Break(()),
        }
    }
    ControlFlow::Continue(())
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    use hickory_proto::op::{Message, MessageType};

    use super::*;
    use crate::service::testing::{forward, query_wire, resolve};

    struct Harness {
        server: tokio::task::JoinHandle<Result<()>>,
        server_addr: SocketAddr,
        client: UdpSocket,
        started: Arc<AtomicUsize>,
        release: Arc<Semaphore>,
        shutdown: CancellationToken,
    }

    impl Harness {
        async fn start(workers: usize) -> Self {
            let socket = UdpSocket::bind("127.0.0.1:0").await.expect("server bind");
            let server_addr = socket.local_addr().expect("server addr");
            let client = UdpSocket::bind("127.0.0.1:0").await.expect("client bind");
            let started = Arc::new(AtomicUsize::new(0));
            let release = Arc::new(Semaphore::new(0));
            let shutdown = CancellationToken::new();
            let server = tokio::spawn(serve_udp(
                socket,
                resolve(),
                forward(&started, &release),
                Arc::new(Semaphore::new(workers)),
                shutdown.clone(),
            ));
            Self {
                server,
                server_addr,
                client,
                started,
                release,
                shutdown,
            }
        }

        async fn send(&self, id: u16, name: &str) {
            self.client
                .send_to(&query_wire(id, name), self.server_addr)
                .await
                .expect("send query");
        }

        async fn recv(&self) -> Message {
            let mut buffer = [0u8; 512];
            let (len, source) =
                tokio::time::timeout(Duration::from_secs(1), self.client.recv_from(&mut buffer))
                    .await
                    .expect("reply arrives")
                    .expect("receive reply");
            assert_eq!(source, self.server_addr);
            Message::from_vec(&buffer[..len]).expect("valid reply")
        }

        async fn wait_for_started(&self, count: usize) {
            tokio::time::timeout(Duration::from_secs(1), async {
                while self.started.load(Ordering::Relaxed) < count {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .expect("upstream work starts");
        }

        async fn stop(self, release: usize) {
            self.shutdown.cancel();
            self.release.add_permits(release);
            tokio::time::timeout(Duration::from_secs(2), self.server)
                .await
                .expect("drain completes")
                .expect("server task")
                .expect("clean shutdown");
        }
    }

    #[test]
    fn response_source_validation_rejects_unreplyable_addresses() {
        assert!(is_safe_response_source("192.0.2.1:5353".parse().unwrap()));
        assert!(is_safe_response_source(
            "[2001:db8::1]:5353".parse().unwrap()
        ));
        assert!(!is_safe_response_source("192.0.2.1:0".parse().unwrap()));
        assert!(!is_safe_response_source("0.0.0.0:5353".parse().unwrap()));
        assert!(!is_safe_response_source(
            "255.255.255.255:5353".parse().unwrap()
        ));
    }

    #[test]
    fn receive_errors_are_classified_by_what_they_concern() {
        let kind = |kind| classify_receive_error(&io::Error::from(kind));
        assert_eq!(kind(io::ErrorKind::ConnectionReset), ReceiveError::Datagram);
        assert_eq!(
            kind(io::ErrorKind::ConnectionRefused),
            ReceiveError::Datagram
        );
        assert_eq!(kind(io::ErrorKind::Interrupted), ReceiveError::Datagram);
        assert_eq!(kind(io::ErrorKind::NotConnected), ReceiveError::Socket);
        assert_eq!(kind(io::ErrorKind::ConnectionAborted), ReceiveError::Socket);
        assert_eq!(kind(io::ErrorKind::OutOfMemory), ReceiveError::Unexpected);
        assert_eq!(kind(io::ErrorKind::Other), ReceiveError::Unexpected);
    }

    #[cfg(windows)]
    #[test]
    fn windows_per_datagram_codes_are_not_fatal() {
        for code in [WSAEMSGSIZE, WSAENETRESET] {
            assert_eq!(
                classify_receive_error(&io::Error::from_raw_os_error(code)),
                ReceiveError::Datagram
            );
        }
    }

    #[tokio::test(start_paused = true)]
    async fn only_unexpected_receive_errors_wait_before_reading_again() {
        let shutdown = CancellationToken::new();
        for (kind, waits) in [
            (io::ErrorKind::ConnectionReset, false),
            (io::ErrorKind::Other, true),
        ] {
            let started = tokio::time::Instant::now();
            let flow = handle_receive_error(&io::Error::from(kind), 1, &shutdown).await;
            assert_eq!(flow, ControlFlow::Continue(()), "{kind:?}");
            let waited = started.elapsed() >= DNS_UDP_RECEIVE_ERROR_BACKOFF;
            assert_eq!(waited, waits, "{kind:?}");
        }

        let error = io::Error::from(io::ErrorKind::ConnectionAborted);
        let started = tokio::time::Instant::now();
        assert_eq!(
            handle_receive_error(&error, 1, &shutdown).await,
            ControlFlow::Break(())
        );
        assert_eq!(
            started.elapsed(),
            Duration::ZERO,
            "socket errors stop at once"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn shutdown_interrupts_the_receive_error_backoff() {
        let shutdown = CancellationToken::new();
        shutdown.cancel();
        let error = io::Error::from(io::ErrorKind::Other);
        let started = tokio::time::Instant::now();
        assert_eq!(
            handle_receive_error(&error, 1, &shutdown).await,
            ControlFlow::Break(())
        );
        assert!(started.elapsed() < DNS_UDP_RECEIVE_ERROR_BACKOFF);
    }

    #[tokio::test]
    async fn local_answers_are_sent_without_upstream_work() {
        let harness = Harness::start(2).await;
        harness.send(21, "cached.test.").await;
        let reply = harness.recv().await;
        assert_eq!(reply.metadata.id, 21);
        assert_eq!(
            harness.started.load(Ordering::Relaxed),
            0,
            "a local answer must not create a worker task"
        );
        harness.stop(0).await;
    }

    #[tokio::test]
    async fn misses_are_answered_from_their_own_task() {
        let harness = Harness::start(2).await;
        harness.release.add_permits(1);
        harness.send(5, "upstream.test.").await;
        assert_eq!(harness.recv().await.metadata.id, 5);
        harness.stop(0).await;
    }

    #[tokio::test]
    async fn a_miss_flood_cannot_create_tasks_beyond_the_worker_cap() {
        let harness = Harness::start(2).await;
        for id in 0..20 {
            harness.send(id, "flood.test.").await;
        }
        harness.wait_for_started(2).await;
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert_eq!(
            harness.started.load(Ordering::Relaxed),
            2,
            "no upstream task may start without a free worker"
        );
        harness.stop(2).await;
    }

    #[tokio::test]
    async fn local_answers_keep_flowing_while_workers_are_saturated() {
        let harness = Harness::start(1).await;
        harness.send(1, "blocked.test.").await;
        harness.wait_for_started(1).await;

        // Dropped: the only worker is busy.
        harness.send(2, "uncached.test.").await;
        harness.send(3, "cached.test.").await;
        assert_eq!(
            harness.recv().await.metadata.id,
            3,
            "a local answer bypasses the saturated workers"
        );
        harness.stop(1).await;
    }

    #[tokio::test]
    async fn saturation_drops_excess_and_keeps_the_loop_reading() {
        let harness = Harness::start(2).await;
        for id in 0..2 {
            harness.send(id, "drop.test.").await;
        }
        harness.wait_for_started(2).await;

        // Excess misses are dropped at admission instead of queueing.
        for id in 2..6 {
            harness.send(id, "drop.test.").await;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert_eq!(harness.started.load(Ordering::Relaxed), 2);

        // The receive loop never stopped draining: once a slot frees, the
        // next datagram is served without waiting out any queued backlog.
        harness.release.add_permits(1);
        let _ = harness.recv().await;
        harness.send(6, "drop.test.").await;
        harness.wait_for_started(3).await;
        harness.stop(2).await;
    }

    #[tokio::test]
    async fn shutdown_stays_responsive_while_saturated() {
        let harness = Harness::start(1).await;
        for id in 0..3 {
            harness.send(id, "stall.test.").await;
        }
        harness.wait_for_started(1).await;

        // The only await between receives is `recv_from` selected against
        // shutdown, so cancellation lands even while every slot is parked.
        let shutdown_at = Instant::now();
        harness.stop(1).await;
        assert!(
            shutdown_at.elapsed() < Duration::from_secs(1),
            "cancellation must preempt promptly under saturation"
        );
    }

    #[tokio::test]
    async fn shutdown_drains_admitted_work_and_delivers_its_reply() {
        let harness = Harness::start(1).await;
        harness.send(19, "shutdown-reply.test.").await;
        harness.wait_for_started(1).await;

        harness.shutdown.cancel();
        tokio::task::yield_now().await;
        assert!(
            !harness.server.is_finished(),
            "shutdown must not abort admitted work"
        );
        harness.release.add_permits(1);
        let reply = harness.recv().await;
        assert_eq!(reply.metadata.id, 19);
        assert_eq!(reply.metadata.message_type, MessageType::Response);
        harness.stop(0).await;
    }
}
