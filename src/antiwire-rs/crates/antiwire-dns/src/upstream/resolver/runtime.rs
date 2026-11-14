//! The runtime the upstream pools open their sockets through.
//!
//! On Linux the port 53 divert lets through only a socket this resolver marked, so every
//! socket that reaches an upstream is marked before it sends: `netmetrics::dns_divert`
//! explains the mark. Without it a plain DNS upstream would be diverted back to this resolver,
//! and DNS over TLS or QUIC, on port 853, would be dropped. Root is no exception to the
//! divert, so a root process that asks another resolver directly is answered here like any
//! other.
//!
//! Elsewhere Hickory's own runtime is used as it is: Windows exempts this process from its
//! divert, and macOS exempts root.

#[cfg(not(target_os = "linux"))]
pub(super) use hickory_resolver::net::runtime::TokioRuntimeProvider as UpstreamRuntime;
#[cfg(target_os = "linux")]
pub(super) use marked::UpstreamRuntime;

#[cfg(target_os = "linux")]
mod marked {
    use std::future::Future;
    use std::io;
    use std::net::SocketAddr;
    use std::os::fd::AsFd;
    use std::pin::Pin;
    use std::sync::Arc;
    use std::time::Duration;

    use hickory_resolver::net::runtime::iocompat::AsyncIoTokioAsStd;
    use hickory_resolver::net::runtime::{
        QuicSocketBinder, RuntimeProvider, TokioHandle, TokioRuntimeProvider, TokioTime,
    };
    use quinn::Runtime as _;
    use tokio::net::{TcpSocket, TcpStream, UdpSocket};

    /// How long a TCP connect may take when the pool names no limit: Hickory's own default
    /// (`CONNECT_TIMEOUT` in `hickory-net` 0.26.3, `xfer/mod.rs`), which it does not export.
    const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

    /// Hickory's Tokio runtime, with every socket it opens marked as this resolver's own.
    ///
    /// Each method does what `TokioRuntimeProvider`'s does (`hickory-net` 0.26.3,
    /// `runtime.rs`) and marks the socket before it can send. A TCP socket is marked before
    /// it connects: the divert decides on the first packet of a connection.
    #[derive(Clone)]
    pub(in super::super) struct UpstreamRuntime(TokioRuntimeProvider);

    impl UpstreamRuntime {
        pub(in super::super) fn new() -> Self {
            Self(TokioRuntimeProvider::new())
        }
    }

    impl RuntimeProvider for UpstreamRuntime {
        type Handle = TokioHandle;
        type Timer = TokioTime;
        type Udp = UdpSocket;
        type Tcp = AsyncIoTokioAsStd<TcpStream>;

        fn create_handle(&self) -> Self::Handle {
            self.0.create_handle()
        }

        fn connect_tcp(
            &self,
            server_addr: SocketAddr,
            bind_addr: Option<SocketAddr>,
            wait_for: Option<Duration>,
        ) -> Pin<Box<dyn Send + Future<Output = io::Result<Self::Tcp>>>> {
            Box::pin(async move {
                let socket = match server_addr {
                    SocketAddr::V4(_) => TcpSocket::new_v4(),
                    SocketAddr::V6(_) => TcpSocket::new_v6(),
                }?;
                exempt_from_divert(&socket)?;
                if let Some(bind_addr) = bind_addr {
                    socket.bind(bind_addr)?;
                }
                socket.set_nodelay(true)?;
                let connecting = socket.connect(server_addr);
                match tokio::time::timeout(wait_for.unwrap_or(CONNECT_TIMEOUT), connecting).await {
                    Ok(connected) => connected.map(AsyncIoTokioAsStd),
                    Err(_) => Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "TCP connect timed out",
                    )),
                }
            })
        }

        fn bind_udp(
            &self,
            local_addr: SocketAddr,
            _server_addr: SocketAddr,
        ) -> Pin<Box<dyn Send + Future<Output = io::Result<Self::Udp>>>> {
            Box::pin(async move {
                let socket = UdpSocket::bind(local_addr).await?;
                exempt_from_divert(&socket)?;
                Ok(socket)
            })
        }

        fn quic_binder(&self) -> Option<&dyn QuicSocketBinder> {
            Some(&MarkedQuicBinder)
        }
    }

    /// Binds the UDP socket of a QUIC or HTTP/3 connection, marked.
    struct MarkedQuicBinder;

    impl QuicSocketBinder for MarkedQuicBinder {
        fn bind_quic(
            &self,
            local_addr: SocketAddr,
            _server_addr: SocketAddr,
        ) -> io::Result<Arc<dyn quinn::AsyncUdpSocket>> {
            let socket = std::net::UdpSocket::bind(local_addr)?;
            exempt_from_divert(&socket)?;
            quinn::TokioRuntime.wrap_udp_socket(socket)
        }
    }

    /// Marks `socket` as this resolver's own.
    ///
    /// A process without the privilege to mark a socket cannot have installed the divert
    /// either, since both take `CAP_NET_ADMIN`: an unprivileged run, as in the tests, has
    /// nothing to be exempt from, and goes on unmarked. Any other failure is the caller's,
    /// because a socket that stayed unmarked under a divert would send a plain DNS upstream's
    /// queries back to this resolver.
    fn exempt_from_divert(socket: &impl AsFd) -> io::Result<()> {
        match netmetrics::dns_divert::exempt_socket(socket) {
            Err(error) if error.kind() == io::ErrorKind::PermissionDenied => Ok(()),
            marked => marked,
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        /// The value is read back with `getsockopt`, which needs no privilege. Setting it
        /// does, so an unprivileged run can only show that the socket is still usable.
        fn mark_of(socket: &impl AsFd) -> u32 {
            socket2::SockRef::from(socket)
                .mark()
                .expect("read the mark")
        }

        fn expected_mark() -> u32 {
            let probe = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind");
            match netmetrics::dns_divert::exempt_socket(&probe) {
                Ok(()) => mark_of(&probe),
                Err(error) => {
                    assert_eq!(error.kind(), io::ErrorKind::PermissionDenied, "{error}");
                    0
                }
            }
        }

        #[tokio::test]
        async fn every_socket_the_pools_open_is_marked_where_this_process_may_mark() {
            let expected = expected_mark();
            let runtime = UpstreamRuntime::new();

            let udp = runtime
                .bind_udp(
                    "127.0.0.1:0".parse().expect("addr"),
                    "192.0.2.1:53".parse().expect("addr"),
                )
                .await
                .expect("udp socket");
            assert_eq!(mark_of(&udp), expected);

            let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .expect("listener");
            let server = listener.local_addr().expect("address");
            let tcp = runtime
                .connect_tcp(server, None, None)
                .await
                .expect("tcp connection");
            assert_eq!(mark_of(&tcp.0), expected);

            // A QUIC socket is bound through the binder, which has no way to show its
            // socket, so its mark is covered by the divert's own live test.
            assert!(runtime.quic_binder().is_some());
        }
    }
}
