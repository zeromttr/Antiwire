//! Bootstrap for the loopback DNS listeners.
//!
//! Owns the UDP and TCP sockets, rebinds any whose serve loop ends without a
//! shutdown request, and runs the graceful-shutdown handshake. The per-query
//! work lives in [`crate::service`].

use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use antiwire_policy::PolicyEngine;
use antiwire_tuning::{
    DNS_LISTENER_REBIND_INITIAL_DELAY, DNS_LISTENER_REBIND_MAX_DELAY, DNS_LISTENER_STABLE_UPTIME,
    DNS_SERVER_SHUTDOWN_TIMEOUT, DNS_TCP_LISTEN_BACKLOG,
};
use futures_util::future::{BoxFuture, FutureExt};
use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};

use antiwire_tuning::{DNS_MAX_TCP_CONNECTIONS, DNS_MAX_UDP_WORKERS};

use crate::query_engine::QueryEngine;
use crate::service::{Forward, Query, Resolve};
use crate::tcp_server::serve_tcp;
use crate::udp_server::serve_udp;
use crate::{DnsError, Result};

pub(crate) fn dns_listen_addr() -> SocketAddr {
    "127.0.0.1:53".parse().expect("dns addr")
}

/// IPv6 counterpart of [`dns_listen_addr`].
///
/// Loopback-only, for the same reason as the IPv4 address: adapters are pointed
/// at this socket, so binding `[::]` would expose an open forwarder to the
/// network. Never widen either of these.
pub(crate) fn dns_listen_addr_v6() -> SocketAddr {
    "[::1]:53".parse().expect("dns v6 addr")
}

/// Binds a DNS UDP socket.
///
/// The socket is built as a std socket so that, on Windows, ICMP
/// port-unreachable reporting can be switched off before tokio takes it (see
/// `udp_socket`).
fn bind_udp_socket_at(addr: SocketAddr) -> Result<UdpSocket> {
    #[cfg(windows)]
    let socket = crate::udp_socket::bind_dns_udp_socket(addr);
    #[cfg(not(windows))]
    let socket = std::net::UdpSocket::bind(addr);
    socket
        .and_then(|socket| {
            socket.set_nonblocking(true)?;
            UdpSocket::from_std(socket)
        })
        .map_err(|error| DnsError::Bind(error.to_string()))
}

/// TCP counterpart of the UDP bind, with an explicit listen backlog so a SYN
/// flood cannot make the platform default an accidental part of admission.
fn bind_tcp_listener_at(addr: SocketAddr) -> io::Result<TcpListener> {
    let socket = Socket::new(Domain::for_address(addr), Type::STREAM, Some(Protocol::TCP))?;
    if addr.is_ipv6() {
        socket.set_only_v6(true)?;
    }
    // As `std::net::TcpListener::bind` does on Unix: without it, a connection
    // this listener closed and left in TIME_WAIT blocks rebinding the port
    // after a restart. Windows is excluded because there the option lets
    // another socket take over a port in use.
    #[cfg(not(windows))]
    socket.set_reuse_address(true)?;
    socket.bind(&addr.into())?;
    socket.listen(DNS_TCP_LISTEN_BACKLOG)?;
    socket.set_nonblocking(true)?;
    TcpListener::from_std(socket.into())
}

/// A bound pair: the UDP socket that must come up, its address, and the TCP
/// listener when one could be had.
type BoundPair = (UdpSocket, SocketAddr, Option<TcpListener>);

/// Binds UDP (required) and TCP (best effort) for one address.
///
/// With an explicit port both protocols share it. UDP and TCP port spaces are
/// independent, so TCP can fail where UDP succeeded; a resolver without TCP is
/// degraded but one that refuses to start is broken, so UDP then serves alone.
/// Port 0, which only tests use, lets each protocol pick its own port.
fn bind_dns_pair(addr: SocketAddr) -> Result<BoundPair> {
    let (udp, udp_addr) = bind_udp_at(addr)?;
    let tcp_addr = if addr.port() == 0 { addr } else { udp_addr };
    match bind_tcp_listener_at(tcp_addr) {
        Ok(tcp) => Ok((udp, udp_addr, Some(tcp))),
        Err(error) => {
            warn!(%error, addr = %tcp_addr, "dns tcp listener bind failed; serving UDP only");
            Ok((udp, udp_addr, None))
        }
    }
}

/// Binds the DNS UDP socket and reports the address it landed on.
fn bind_udp_at(addr: SocketAddr) -> Result<(UdpSocket, SocketAddr)> {
    let udp = bind_udp_socket_at(addr)?;
    let udp_addr = udp
        .local_addr()
        .map_err(|error| DnsError::Bind(error.to_string()))?;
    Ok((udp, udp_addr))
}

/// One address family's bound sockets.
struct BoundStack {
    udp_addr: SocketAddr,
    tcp_addr: Option<SocketAddr>,
}

/// The transport a listener serves, and so the one a query arrived over.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Transport {
    Udp,
    Tcp,
}

impl Transport {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Udp => "udp",
            Self::Tcp => "tcp",
        }
    }

    fn bind(self, addr: SocketAddr) -> Result<BoundSocket> {
        match self {
            Self::Udp => bind_udp_socket_at(addr).map(BoundSocket::Udp),
            Self::Tcp => bind_tcp_listener_at(addr)
                .map(BoundSocket::Tcp)
                .map_err(|error| DnsError::Bind(error.to_string())),
        }
    }
}

/// A bound socket, served and when necessary rebound by [`supervise_listener`].
enum BoundSocket {
    Udp(UdpSocket),
    Tcp(TcpListener),
}

impl BoundSocket {
    const fn transport(&self) -> Transport {
        match self {
            Self::Udp(_) => Transport::Udp,
            Self::Tcp(_) => Transport::Tcp,
        }
    }
}

/// Binds UDP (required) and TCP (best-effort) at `addr`.
///
/// Each socket is paired with the address a supervisor rebinds it at.
fn register_stack(addr: SocketAddr) -> Result<(BoundStack, Vec<(BoundSocket, SocketAddr)>)> {
    let (udp, udp_addr, tcp) = bind_dns_pair(addr)?;
    let tcp_addr = tcp.as_ref().and_then(|listener| listener.local_addr().ok());
    let mut sockets = vec![(BoundSocket::Udp(udp), udp_addr)];
    if let (Some(tcp), Some(tcp_addr)) = (tcp, tcp_addr) {
        sockets.push((BoundSocket::Tcp(tcp), tcp_addr));
    }
    Ok((BoundStack { udp_addr, tcp_addr }, sockets))
}

/// The query services, and the process-wide limits every socket shares.
struct DnsServices<P> {
    resolve: Resolve<P>,
    forward: Forward<P>,
    /// Queries waiting on upstream, across every UDP socket.
    udp_workers: Arc<Semaphore>,
    /// Open connections, across every TCP listener.
    tcp_connections: Arc<Semaphore>,
}

impl<P> Clone for DnsServices<P> {
    fn clone(&self) -> Self {
        Self {
            resolve: self.resolve.clone(),
            forward: self.forward.clone(),
            udp_workers: Arc::clone(&self.udp_workers),
            tcp_connections: Arc::clone(&self.tcp_connections),
        }
    }
}

impl<P> DnsServices<P>
where
    P: PolicyEngine + Send + Sync + Unpin + 'static,
{
    fn new(stub: Arc<QueryEngine<P>>) -> Self {
        let limit = |value: i32, fallback| usize::try_from(value).unwrap_or(fallback).max(1);
        Self {
            resolve: Resolve::new(Arc::clone(&stub)),
            forward: Forward::new(stub),
            udp_workers: Arc::new(Semaphore::new(limit(DNS_MAX_UDP_WORKERS, 512))),
            tcp_connections: Arc::new(Semaphore::new(limit(DNS_MAX_TCP_CONNECTIONS, 128))),
        }
    }

    fn serve(
        &self,
        socket: BoundSocket,
        shutdown: CancellationToken,
    ) -> BoxFuture<'static, Result<()>> {
        let resolve = self.resolve.clone();
        let resolve = move |query: Query<'_>| resolve.resolve(query);
        let forward = self.forward.clone();
        let forward = move |miss| forward.answer(miss);
        match socket {
            BoundSocket::Udp(socket) => serve_udp(
                socket,
                resolve,
                forward,
                Arc::clone(&self.udp_workers),
                shutdown,
            )
            .boxed(),
            BoundSocket::Tcp(listener) => serve_tcp(
                listener,
                resolve,
                forward,
                Arc::clone(&self.tcp_connections),
                shutdown,
            )
            .boxed(),
        }
    }
}

async fn run_dns_server<P>(
    sockets: Vec<(BoundSocket, SocketAddr)>,
    services: DnsServices<P>,
    shutdown: CancellationToken,
) -> Result<()>
where
    P: PolicyEngine + Send + Sync + Unpin + 'static,
{
    let mut tasks = JoinSet::new();
    for (socket, addr) in sockets {
        let services = services.clone();
        let serve_shutdown = shutdown.clone();
        let serve = move |socket: BoundSocket| services.serve(socket, serve_shutdown.clone());
        tasks.spawn(supervise_listener(socket, addr, serve, shutdown.clone()));
    }

    let first_error = drain_listeners(&mut tasks, &shutdown).await;

    // The listener stack is gone without a shutdown request. The adapters still
    // point at this process, so say so at the loudest level; auto-reverting the
    // OS redirect here would silently switch the host to unfiltered upstream
    // DNS, which is not a decision for a fault handler to make.
    if !shutdown.is_cancelled() {
        error!(
            error = ?first_error,
            "dns listeners are down while adapter DNS still points at this resolver"
        );
    }
    first_error.map_or(Ok(()), Err)
}

/// Serves one socket until shutdown, rebinding it whenever serving ends early.
///
/// Adapter DNS points at this socket, so a serve loop that returns, errors, or
/// panics must not leave it dead until a daemon restart. Serving runs on its
/// own task so a panic surfaces here as a join error rather than unwinding
/// through the supervisor; the `JoinSet` aborts that task if the supervisor is
/// dropped.
async fn supervise_listener<S, F>(
    mut socket: BoundSocket,
    addr: SocketAddr,
    serve: S,
    shutdown: CancellationToken,
) -> Result<()>
where
    S: Fn(BoundSocket) -> F,
    F: Future<Output = Result<()>> + Send + 'static,
{
    let transport = socket.transport();
    let mut delay = DNS_LISTENER_REBIND_INITIAL_DELAY;
    loop {
        let started = Instant::now();
        let mut serving = JoinSet::new();
        serving.spawn(serve(socket));
        let outcome = serving.join_next().await;

        if shutdown.is_cancelled() {
            return match outcome {
                Some(Ok(result)) => result,
                Some(Err(error)) => Err(DnsError::Runtime(format!(
                    "dns {} listener task failed during shutdown: {error}",
                    transport.as_str()
                ))),
                None => Ok(()),
            };
        }

        let failure = match outcome {
            Some(Ok(Ok(()))) => "stopped without a shutdown request".to_owned(),
            Some(Ok(Err(error))) => error.to_string(),
            Some(Err(error)) => format!("task failed: {error}"),
            None => "task vanished".to_owned(),
        };
        error!(
            %addr,
            protocol = transport.as_str(),
            error = %failure,
            "dns listener ended unexpectedly; rebinding it"
        );

        if started.elapsed() >= DNS_LISTENER_STABLE_UPTIME {
            delay = DNS_LISTENER_REBIND_INITIAL_DELAY;
        }
        let Some(rebound) = rebind_listener(transport, addr, &mut delay, &shutdown).await else {
            return Ok(());
        };
        info!(
            %addr,
            protocol = transport.as_str(),
            "dns listener rebound"
        );
        socket = rebound;
    }
}

/// Rebinds `addr` after `delay`, retrying until it binds or shutdown starts.
///
/// `delay` doubles after every attempt, successful or not, so a listener that
/// keeps dying backs off instead of spinning; the caller resets it once the
/// listener has stayed up for [`DNS_LISTENER_STABLE_UPTIME`].
async fn rebind_listener(
    transport: Transport,
    addr: SocketAddr,
    delay: &mut Duration,
    shutdown: &CancellationToken,
) -> Option<BoundSocket> {
    let mut failures: u64 = 0;
    loop {
        // Biased so a shutdown that lands as the backoff expires wins: once
        // shutdown is requested, the address must not be bound again.
        tokio::select! {
            biased;
            () = shutdown.cancelled() => return None,
            () = tokio::time::sleep(*delay) => {}
        }
        let attempt = transport.bind(addr);
        *delay = delay.saturating_mul(2).min(DNS_LISTENER_REBIND_MAX_DELAY);
        match attempt {
            Ok(socket) => return Some(socket),
            Err(error) => {
                failures += 1;
                if failures.is_power_of_two() {
                    warn!(
                        %addr,
                        protocol = transport.as_str(),
                        %error,
                        failures,
                        retry_in_ms = delay.as_millis(),
                        "dns listener rebind failed; retrying"
                    );
                }
            }
        }
    }
}

/// Waits for the listener supervisors, returning the first unexpected failure.
///
/// Supervisors rebind their own sockets, so one only ends early if its own
/// bookkeeping fails. Stop on that first exit and drop the rest: waiting for
/// all of them would let a partially dead stack — UDP gone but TCP still
/// accepting — keep its task unfinished, so [`DnsListener::is_running`] would
/// stay true and hide the outage.
async fn drain_listeners(
    tasks: &mut JoinSet<Result<()>>,
    shutdown: &CancellationToken,
) -> Option<DnsError> {
    while let Some(completed) = tasks.join_next().await {
        let error = match completed {
            Ok(Ok(())) if shutdown.is_cancelled() => None,
            Ok(Ok(())) => Some(DnsError::Runtime(
                "dns server task stopped unexpectedly".to_owned(),
            )),
            Ok(Err(error)) => Some(error),
            Err(error) => Some(DnsError::Runtime(format!(
                "dns server task failed: {error}"
            ))),
        };
        let Some(error) = error else {
            continue;
        };
        error!(
            %error,
            remaining = tasks.len(),
            "dns listener supervisor ended unexpectedly; stopping the stack"
        );
        return Some(error);
    }
    None
}

/// Loopback DNS listener: UDP, plus TCP when it can be bound, on IPv4 and —
/// for the production bind — IPv6.
pub(crate) struct DnsListener {
    shutdown: CancellationToken,
    task: Option<tokio::task::JoinHandle<Result<()>>>,
    #[cfg(any(test, feature = "bench-internals"))]
    udp_addr: SocketAddr,
    #[cfg(any(test, feature = "bench-internals"))]
    tcp_addr: Option<SocketAddr>,
    v6: Option<BoundStack>,
}

impl DnsListener {
    /// Binds the production loopback listeners and starts serving.
    ///
    /// IPv4 is required; IPv6 is best-effort. Whether `[::1]:53` came up decides
    /// whether the caller may redirect adapter IPv6 DNS to `::1` — see
    /// [`Self::v6_active`].
    pub(crate) fn start_default<P>(stub: Arc<QueryEngine<P>>) -> Result<Self>
    where
        P: PolicyEngine + Send + Sync + Unpin + 'static,
    {
        Self::start_with(stub, dns_listen_addr(), Some(dns_listen_addr_v6()))
    }

    /// Binds on `addr` and starts serving. Port 0 lets UDP and TCP each pick an
    /// ephemeral port, which the tests and the loopback benchmark rely on.
    #[cfg(any(test, feature = "bench-internals"))]
    pub(crate) fn start_on<P>(stub: Arc<QueryEngine<P>>, addr: SocketAddr) -> Result<Self>
    where
        P: PolicyEngine + Send + Sync + Unpin + 'static,
    {
        Self::start_with(stub, addr, None)
    }

    fn start_with<P>(
        stub: Arc<QueryEngine<P>>,
        addr: SocketAddr,
        addr_v6: Option<SocketAddr>,
    ) -> Result<Self>
    where
        P: PolicyEngine + Send + Sync + Unpin + 'static,
    {
        let services = DnsServices::new(stub);
        let (primary, mut sockets) = register_stack(addr)?;

        // A machine with IPv6 disabled, or one where something else already
        // holds [::1]:53, must still get a working IPv4 resolver. Failing here
        // only costs the IPv6 redirect, which `v6_active` then withholds.
        let v6 = match addr_v6 {
            Some(addr_v6) => match register_stack(addr_v6) {
                Ok((stack, v6_sockets)) => {
                    sockets.extend(v6_sockets);
                    Some(stack)
                }
                Err(error) => {
                    warn!(
                        %error,
                        addr = %addr_v6,
                        "dns ipv6 listener bind failed; adapter IPv6 DNS will not be redirected"
                    );
                    None
                }
            },
            None => None,
        };

        let shutdown = CancellationToken::new();
        let task_shutdown = shutdown.clone();
        let task =
            tokio::spawn(async move { run_dns_server(sockets, services, task_shutdown).await });

        info!(
            udp = %primary.udp_addr,
            tcp = ?primary.tcp_addr,
            udp_v6 = ?v6.as_ref().map(|stack| stack.udp_addr),
            tcp_v6 = ?v6.as_ref().and_then(|stack| stack.tcp_addr),
            "dns server listening"
        );

        Ok(Self {
            shutdown,
            task: Some(task),
            #[cfg(any(test, feature = "bench-internals"))]
            udp_addr: primary.udp_addr,
            #[cfg(any(test, feature = "bench-internals"))]
            tcp_addr: primary.tcp_addr,
            v6,
        })
    }

    #[cfg(any(test, feature = "bench-internals"))]
    #[must_use]
    pub(crate) fn udp_addr(&self) -> SocketAddr {
        self.udp_addr
    }

    #[cfg(any(test, feature = "bench-internals"))]
    #[must_use]
    pub(crate) fn tcp_addr(&self) -> Option<SocketAddr> {
        self.tcp_addr
    }

    #[cfg(test)]
    #[must_use]
    pub(crate) fn udp_addr_v6(&self) -> Option<SocketAddr> {
        self.v6.as_ref().map(|stack| stack.udp_addr)
    }

    /// True when `[::1]:53` is being served, and therefore when adapter IPv6 DNS
    /// may safely be redirected to it.
    ///
    /// Redirecting IPv6 without this listener would black-hole every IPv6 DNS
    /// query instead of filtering it.
    #[must_use]
    pub(crate) fn v6_active(&self) -> bool {
        self.v6.is_some()
    }

    #[must_use]
    pub(crate) fn is_running(&self) -> bool {
        self.task.as_ref().is_some_and(|task| !task.is_finished())
    }

    /// Cancels the listeners and waits for in-flight queries to drain.
    ///
    /// On timeout the task is aborted and then awaited, so a returned `Ok` always
    /// means the server task is really gone — not merely that cancellation was
    /// requested. Callers restore adapter DNS immediately after this returns.
    pub(crate) async fn shutdown(&mut self) -> Result<()> {
        self.shutdown.cancel();
        let Some(mut task) = self.task.take() else {
            return Ok(());
        };

        // `&mut JoinHandle` is a `Future`, so the handle survives the timeout and
        // can still be awaited to observe the abort landing.
        match tokio::time::timeout(DNS_SERVER_SHUTDOWN_TIMEOUT, &mut task).await {
            Ok(Ok(result)) => result,
            Ok(Err(error)) => {
                warn!(%error, "dns server task failed");
                Ok(())
            }
            Err(_) => {
                warn!("dns requests exceeded graceful shutdown timeout; cancelling them");
                task.abort();
                match task.await {
                    Ok(result) => result,
                    Err(error) if error.is_cancelled() => Ok(()),
                    Err(error) => {
                        warn!(%error, "dns server task panicked during forced shutdown");
                        Ok(())
                    }
                }
            }
        }
    }
}

impl Drop for DnsListener {
    fn drop(&mut self) {
        self.shutdown.cancel();
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

#[cfg(test)]
mod tests {
    use antiwire_policy::{DomainDecision, PolicyEngine};

    use super::*;
    use crate::settings::DnsConfig;

    struct AllowAll;

    impl PolicyEngine for AllowAll {
        fn evaluate_domain_with_source(&self, _: &str) -> Option<DomainDecision> {
            None
        }
    }

    /// The server side closes first, so its end of the connection sits in
    /// TIME_WAIT on the listening port when the listener is rebound.
    #[cfg(not(windows))]
    #[tokio::test]
    async fn tcp_listener_rebinds_while_a_closed_connection_is_in_time_wait() {
        use tokio::io::AsyncReadExt;

        let listener = bind_tcp_listener_at("127.0.0.1:0".parse().expect("addr")).expect("bind");
        let addr = listener.local_addr().expect("addr");
        let mut client = tokio::net::TcpStream::connect(addr).await.expect("connect");
        let (server_side, _) = listener.accept().await.expect("accept");
        drop(server_side);
        let mut byte = [0u8; 1];
        assert_eq!(client.read(&mut byte).await.expect("eof"), 0);
        drop(client);
        drop(listener);
        bind_tcp_listener_at(addr).expect("rebind with a connection in TIME_WAIT");
    }

    fn test_stub() -> Arc<QueryEngine<AllowAll>> {
        Arc::new(QueryEngine::new(
            AllowAll,
            DnsConfig {
                upstreams: vec!["127.0.0.1:1".to_owned()],
                ..DnsConfig::default()
            },
        ))
    }

    #[test]
    fn production_v6_address_is_loopback_only() {
        // Widening this to `[::]` would expose an open forwarder to the network.
        assert!(dns_listen_addr_v6().ip().is_loopback());
        assert_eq!(dns_listen_addr_v6().port(), dns_listen_addr().port());
    }

    #[tokio::test]
    async fn binds_both_address_families_and_reports_v6_active() {
        let mut listener = DnsListener::start_with(
            test_stub(),
            "127.0.0.1:0".parse().expect("v4 addr"),
            Some("[::1]:0".parse().expect("v6 addr")),
        )
        .expect("dual-stack listener");

        assert!(listener.v6_active(), "IPv6 listener came up");
        let v6 = listener.udp_addr_v6().expect("v6 udp addr");
        assert!(v6.is_ipv6() && v6.ip().is_loopback());
        assert!(listener.udp_addr().is_ipv4());

        listener.shutdown().await.expect("shutdown");
    }

    /// A machine with IPv6 disabled must still get a working IPv4 resolver — and
    /// must report `v6_active() == false` so the caller leaves adapter IPv6 DNS
    /// alone rather than redirecting it into a black hole.
    #[tokio::test]
    async fn failed_v6_bind_leaves_ipv4_serving_and_v6_inactive() {
        // Something else already holds the IPv6 address, so the bind cannot succeed. An
        // address the machine does not own is no substitute: a host that allows non-local
        // binds (`net.ipv6.ip_nonlocal_bind`) accepts it.
        let blocker = std::net::UdpSocket::bind("[::1]:0").expect("hold v6 addr");
        let held = blocker.local_addr().expect("held v6 addr");

        let mut listener = DnsListener::start_with(
            test_stub(),
            "127.0.0.1:0".parse().expect("v4 addr"),
            Some(held),
        )
        .expect("ipv4 listener survives a failed ipv6 bind");

        assert!(!listener.v6_active());
        assert!(listener.udp_addr_v6().is_none());
        assert!(listener.is_running());

        listener.shutdown().await.expect("shutdown");
    }

    #[tokio::test]
    async fn shutdown_is_idempotent_and_stops_the_server_task() {
        let mut listener = DnsListener::start_on(test_stub(), "127.0.0.1:0".parse().expect("addr"))
            .expect("listener");

        listener.shutdown().await.expect("first shutdown");
        assert!(
            !listener.is_running(),
            "server task is gone once shutdown returns"
        );
        listener.shutdown().await.expect("second shutdown");
    }

    fn expect_udp(socket: BoundSocket) -> UdpSocket {
        match socket {
            BoundSocket::Udp(socket) => socket,
            BoundSocket::Tcp(_) => panic!("supervisor rebound the wrong transport"),
        }
    }

    #[tokio::test]
    async fn a_panicked_serve_loop_is_rebound_at_the_same_address() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.expect("bind");
        let addr = socket.local_addr().expect("addr");
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let (rebound_tx, mut rebound_rx) = tokio::sync::mpsc::unbounded_channel();
        let shutdown = CancellationToken::new();

        let serve = {
            let calls = Arc::clone(&calls);
            let shutdown = shutdown.clone();
            move |socket: BoundSocket| {
                let call = calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let rebound_tx = rebound_tx.clone();
                let shutdown = shutdown.clone();
                async move {
                    let socket = expect_udp(socket);
                    assert!(call > 0, "serve loop panicked");
                    rebound_tx
                        .send(socket.local_addr().expect("rebound addr"))
                        .expect("report rebind");
                    shutdown.cancelled().await;
                    Ok(())
                }
            }
        };
        let supervisor = tokio::spawn(supervise_listener(
            BoundSocket::Udp(socket),
            addr,
            serve,
            shutdown.clone(),
        ));

        // The rebind itself waits 50 ms. The ceiling only catches a hang: with
        // RUST_BACKTRACE set, printing the first call's deliberate panic can
        // take over a second on Windows while other tests are panicking too.
        let rebound = tokio::time::timeout(Duration::from_secs(10), rebound_rx.recv())
            .await
            .expect("listener is rebound")
            .expect("rebound address");
        assert_eq!(rebound, addr, "adapters point at this exact address");

        shutdown.cancel();
        supervisor
            .await
            .expect("supervisor task")
            .expect("clean shutdown");
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn a_rebind_retries_until_the_address_is_free() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.expect("bind");
        let addr = socket.local_addr().expect("addr");
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let (rebound_tx, mut rebound_rx) = tokio::sync::mpsc::unbounded_channel();
        let shutdown = CancellationToken::new();
        let hold = Duration::from_millis(300);

        let serve = {
            let calls = Arc::clone(&calls);
            let shutdown = shutdown.clone();
            move |socket: BoundSocket| {
                let call = calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let rebound_tx = rebound_tx.clone();
                let shutdown = shutdown.clone();
                async move {
                    let socket = expect_udp(socket);
                    if call == 0 {
                        // Something else holds the address while the rebind runs.
                        drop(socket);
                        let blocker = std::net::UdpSocket::bind(addr).expect("hold addr");
                        tokio::spawn(async move {
                            tokio::time::sleep(hold).await;
                            drop(blocker);
                        });
                        return Err(DnsError::Bind("socket closed".to_owned()));
                    }
                    rebound_tx.send(()).expect("report rebind");
                    shutdown.cancelled().await;
                    Ok(())
                }
            }
        };
        let started = Instant::now();
        let supervisor = tokio::spawn(supervise_listener(
            BoundSocket::Udp(socket),
            addr,
            serve,
            shutdown.clone(),
        ));

        tokio::time::timeout(Duration::from_secs(3), rebound_rx.recv())
            .await
            .expect("rebind succeeds once the address frees")
            .expect("rebound");
        assert!(started.elapsed() >= hold, "cannot rebind while held");

        shutdown.cancel();
        supervisor
            .await
            .expect("supervisor task")
            .expect("clean shutdown");
    }

    /// Runs on a paused clock. On Windows' 15.6 ms timer ticks, a real 400 ms
    /// window can end in the same tick as the third backoff, so a fifth serve
    /// loop could start, and fail, just as shutdown lands.
    #[tokio::test(start_paused = true)]
    async fn a_crash_looping_listener_backs_off_and_still_shuts_down() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.expect("bind");
        let addr = socket.local_addr().expect("addr");
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let shutdown = CancellationToken::new();

        let serve = {
            let calls = Arc::clone(&calls);
            move |socket: BoundSocket| {
                calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                async move {
                    drop(socket);
                    Err(DnsError::Bind("socket closed".to_owned()))
                }
            }
        };
        let supervisor = tokio::spawn(supervise_listener(
            BoundSocket::Udp(socket),
            addr,
            serve,
            shutdown.clone(),
        ));

        tokio::time::sleep(Duration::from_millis(400)).await;
        let served = calls.load(std::sync::atomic::Ordering::SeqCst);
        // Serving starts at 0, 50, 150 and 350 ms, and the next rebind waits
        // until 750 ms; a spinning supervisor would have rebound thousands of
        // times.
        assert!(
            (2..=4).contains(&served),
            "rebinds back off (served {served} times)"
        );

        let cancelled_at = tokio::time::Instant::now();
        shutdown.cancel();
        tokio::time::timeout(Duration::from_secs(1), supervisor)
            .await
            .expect("shutdown interrupts the rebind backoff")
            .expect("supervisor task")
            .expect("clean shutdown");
        // The pending backoff had 350 ms left; shutdown must not wait it out.
        assert!(cancelled_at.elapsed() < Duration::from_millis(350));
    }

    /// Once shutdown is requested the address must not be bound again, even
    /// when the backoff expires at the same moment.
    #[tokio::test(start_paused = true)]
    async fn shutdown_wins_over_a_backoff_that_expires_with_it() {
        let addr = UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("bind")
            .local_addr()
            .expect("addr");
        // An unbiased select picks either ready branch at random, so repeat.
        for _ in 0..32 {
            let shutdown = CancellationToken::new();
            let mut delay = DNS_LISTENER_REBIND_INITIAL_DELAY;
            let mut rebind =
                std::pin::pin!(rebind_listener(Transport::Udp, addr, &mut delay, &shutdown));
            // Start the backoff, then let it expire and request shutdown
            // before the rebind is polled again.
            assert!(rebind.as_mut().now_or_never().is_none());
            tokio::time::advance(DNS_LISTENER_REBIND_INITIAL_DELAY * 2).await;
            shutdown.cancel();
            assert!(
                rebind.await.is_none(),
                "rebound after shutdown was requested"
            );
        }
    }

    /// A partially dead stack must not stay invisible: if one listener dies
    /// while another keeps running, the wait has to end so `is_running` goes
    /// false and the owner rebinds.
    #[tokio::test]
    async fn an_unexpected_listener_exit_stops_the_whole_stack() {
        let shutdown = CancellationToken::new();
        let mut tasks = JoinSet::new();
        tasks.spawn(async { Err(DnsError::Bind("udp listener died".to_owned())) });
        tasks.spawn(async {
            tokio::time::sleep(std::time::Duration::from_secs(30)).await;
            Ok(())
        });

        let started = std::time::Instant::now();
        let error = drain_listeners(&mut tasks, &shutdown).await;

        assert!(matches!(error, Some(DnsError::Bind(_))));
        assert!(
            started.elapsed() < std::time::Duration::from_secs(1),
            "must not wait for the surviving listener"
        );
    }
}
