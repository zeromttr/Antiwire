//! The authenticated IPC server.
//!
//! [`GrpcServer`] is the only way to serve the daemon's RPCs: the service
//! type is built here from [`ServiceParts`] and is not exported, so no other
//! code can mount it without the token check.
//!
//! The privileged RPCs, `InstallUpdate` among them, need no check beyond the
//! token. The token is readable only by administrators and the client group,
//! and an update installs only a release signed by the Antiwire ed25519 key,
//! so a token holder cannot install code of their own.

#[cfg(unix)]
use std::path::Path;

use antiwire_proto::antiwire_service_server::AntiwireServiceServer;
use tokio_util::sync::CancellationToken;
use tonic::service::interceptor::InterceptedService;
use tonic::transport::Server;
use tracing::info;
use zeroize::Zeroizing;

use crate::auth::{publish_new_token, AuthInterceptor};
use crate::endpoint::{IpcEndpoint, IpcPaths};
use crate::error::IpcError;
use crate::service::{ServiceImpl, ServiceParts};

/// Serves the daemon's RPCs to clients that present the IPC token.
pub struct GrpcServer {
    endpoint: IpcEndpoint,
    paths: IpcPaths,
    service: ServiceImpl,
    shutdown: CancellationToken,
}

impl GrpcServer {
    /// A server for `parts` on `endpoint`, publishing its credentials at
    /// `paths`. It stops when `parts.shutdown` is cancelled.
    #[must_use]
    pub fn new(endpoint: IpcEndpoint, paths: IpcPaths, parts: ServiceParts) -> Self {
        let shutdown = parts.shutdown.clone();
        Self {
            endpoint,
            paths,
            service: ServiceImpl::new(parts),
            shutdown,
        }
    }

    #[must_use]
    pub fn endpoint(&self) -> &IpcEndpoint {
        &self.endpoint
    }

    /// Binds the endpoint, publishes credentials, and serves until shutdown.
    ///
    /// Credentials are published only once the endpoint is bound, so a
    /// client never reads a token for a server that is not listening: on
    /// Windows the certificate first, then the token, so a client that sees
    /// a new token finds the certificate that goes with it. A fresh token on
    /// every start means one copied earlier stops working.
    ///
    /// `on_listening` then runs with the bound endpoint, whose port is the
    /// one the OS chose when the endpoint asked for port 0.
    ///
    /// Once shutdown is requested the server stops accepting connections and
    /// finishes the requests in flight; streams end at the same moment.
    ///
    /// # Errors
    ///
    /// [`IpcError::Io`] when the endpoint cannot be bound or a credential
    /// cannot be written, [`IpcError::Certificate`] when no TLS identity can
    /// be made, and [`IpcError::Transport`] when serving fails.
    pub async fn serve(
        self,
        on_listening: impl FnOnce(&IpcEndpoint) + Send,
    ) -> Result<(), IpcError> {
        #[cfg(windows)]
        {
            self.serve_tls(on_listening).await
        }
        #[cfg(unix)]
        {
            self.serve_unix(on_listening).await
        }
    }

    #[cfg(windows)]
    async fn serve_tls(
        self,
        on_listening: impl FnOnce(&IpcEndpoint) + Send,
    ) -> Result<(), IpcError> {
        use tonic::transport::server::TcpIncoming;
        use tonic::transport::{Identity, ServerTlsConfig};

        use crate::ipc_tls::{generate_server_identity, publish_public_cert};

        let IpcEndpoint::Tcp(addr) = self.endpoint;
        // The variant is public, so an endpoint not built by `parse` is
        // checked here as well.
        IpcEndpoint::loopback_tcp(addr)?;
        let listener = tokio::net::TcpListener::bind(addr).await?;
        let bound = IpcEndpoint::Tcp(listener.local_addr()?);
        let incoming = TcpIncoming::from_listener(listener, false, None).map_err(|source| {
            IpcError::Initialization {
                context: "accept IPC connections",
                source,
            }
        })?;

        let identity = generate_server_identity()?;
        publish_public_cert(&self.paths.cert, &identity.cert_pem)?;
        let token = publish_new_token(&self.paths.token)?;
        let tls = ServerTlsConfig::new().identity(Identity::from_pem(
            identity.cert_pem.as_bytes(),
            identity.key_pem.as_bytes(),
        ));
        drop(identity);

        info!(endpoint = %bound, "antiwire gRPC IPC server listening (TLS)");
        on_listening(&bound);
        Server::builder()
            .tls_config(tls)?
            .add_service(authenticated(self.service, token))
            .serve_with_incoming_shutdown(incoming, self.shutdown.cancelled_owned())
            .await?;
        Ok(())
    }

    #[cfg(unix)]
    async fn serve_unix(
        self,
        on_listening: impl FnOnce(&IpcEndpoint) + Send,
    ) -> Result<(), IpcError> {
        use tokio_stream::wrappers::UnixListenerStream;

        let IpcEndpoint::Unix(path) = &self.endpoint;
        let listener = bind_unix_socket(path).await?;
        let token = publish_new_token(&self.paths.token)?;

        info!(endpoint = %self.endpoint, "antiwire gRPC IPC server listening (unix socket)");
        on_listening(&self.endpoint);
        let served = Server::builder()
            .add_service(authenticated(self.service, token))
            .serve_with_incoming_shutdown(
                UnixListenerStream::new(listener),
                self.shutdown.cancelled_owned(),
            )
            .await;
        // Only this process could have served the socket, so the file is
        // ours to remove; the next start then has no stale socket to probe.
        if let Err(error) = std::fs::remove_file(path) {
            tracing::debug!(%error, "could not remove the IPC socket");
        }
        Ok(served?)
    }
}

/// The service behind the token check.
fn authenticated(
    service: ServiceImpl,
    token: Zeroizing<String>,
) -> InterceptedService<AntiwireServiceServer<ServiceImpl>, AuthInterceptor> {
    AntiwireServiceServer::with_interceptor(service, AuthInterceptor::from_zeroizing(token))
}

/// Binds `path` with its final permissions already in place.
///
/// The socket is created in a fresh owner-only directory beside `path`,
/// restricted there, and renamed over `path`, so there is no moment when an
/// account outside the client group could connect to it.
#[cfg(unix)]
async fn bind_unix_socket(path: &Path) -> Result<tokio::net::UnixListener, IpcError> {
    // A stale socket left by a killed process still exists on disk, but a
    // live daemon's socket answers connections. Only a refusal, or no file
    // at all, proves the owner is gone; any other failure leaves it
    // ambiguous, and replacing the socket then could cut off a live daemon.
    match tokio::net::UnixStream::connect(path).await {
        Ok(_) => {
            return Err(IpcError::Initialization {
                context: "bind the IPC unix socket",
                source: "another daemon is already serving this socket"
                    .to_owned()
                    .into(),
            });
        }
        Err(error) if unix_socket_probe_proves_stale(&error) => {}
        Err(error) => {
            return Err(IpcError::Initialization {
                context: "bind the IPC unix socket",
                source: format!(
                    "could not determine whether the existing socket is stale: {error}"
                )
                .into(),
            });
        }
    }
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(parent)?;
    // `tempfile` creates the directory owner-only, under a random name.
    let staging = tempfile::Builder::new()
        .prefix(".antiwire-ipc-")
        .tempdir_in(parent)?;
    let staged = staging.path().join("socket");
    let listener = tokio::net::UnixListener::bind(&staged)?;
    restrict_unix_socket(&staged)?;
    std::fs::rename(&staged, path)?;
    Ok(listener)
}

/// Lets only root and [`antiwire_proto::IPC_CLIENT_GROUP`] connect to the socket.
///
/// Connecting needs write access to the socket file, so its mode is the access check:
/// `0660` and group-owned by the client group, or `0600` when that group is missing.
/// A debug build keeps the old world-writable socket, matching the developer-profile
/// token in [`crate::atomic_file::restrict_ipc_token`].
#[cfg(unix)]
fn restrict_unix_socket(path: &Path) -> std::io::Result<()> {
    use std::fs;
    use std::os::unix::fs::PermissionsExt as _;

    if !crate::atomic_file::restrict_ipc_token() {
        return fs::set_permissions(path, fs::Permissions::from_mode(0o666));
    }
    if let Some(gid) = antiwire_secrets::group_id(antiwire_proto::IPC_CLIENT_GROUP)? {
        std::os::unix::fs::chown(path, None, Some(gid))?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o660))
    } else {
        tracing::error!(
            group = antiwire_proto::IPC_CLIENT_GROUP,
            "the IPC client group does not exist, so only root can connect to the daemon"
        );
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
    }
}

/// Whether a failed socket probe proves no live owner is serving it.
///
/// `ConnectionRefused` means the socket file exists but nothing accepts
/// connections on it, and `NotFound` means there is no socket at all. Every
/// other failure — permission denied, file-descriptor exhaustion — leaves
/// the owner ambiguous, and the endpoint must be preserved.
#[cfg(unix)]
fn unix_socket_probe_proves_stale(error: &std::io::Error) -> bool {
    matches!(
        error.kind(),
        std::io::ErrorKind::ConnectionRefused | std::io::ErrorKind::NotFound
    )
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use antiwire_events::ZeroActiveConnectionCounter;
    use antiwire_proto::antiwire_service_client::AntiwireServiceClient;
    use tonic::metadata::MetadataValue;
    use tonic::service::Interceptor;
    use tonic::transport::Channel;
    use tonic::{Code, Request};

    use super::*;
    use crate::auth::TOKEN_HEADER;
    use crate::test_support::TestParts;

    #[test]
    fn interceptor_rejects_missing_token() {
        let mut interceptor = AuthInterceptor::new("expected-token");
        let err = interceptor
            .call(Request::new(()))
            .expect_err("missing token");
        assert_eq!(err.code(), Code::Unauthenticated);
    }

    #[test]
    fn interceptor_accepts_valid_token() {
        let mut interceptor = AuthInterceptor::new("expected-token");
        let mut request = Request::new(());
        request
            .metadata_mut()
            .insert(TOKEN_HEADER, MetadataValue::from_static("expected-token"));

        interceptor.call(request).expect("valid token");
    }

    /// An endpoint in `dir` that nothing else uses.
    fn test_endpoint(dir: &std::path::Path) -> IpcEndpoint {
        #[cfg(windows)]
        {
            let _ = dir;
            IpcEndpoint::Tcp(std::net::SocketAddr::from(([127, 0, 0, 1], 0)))
        }
        #[cfg(unix)]
        {
            IpcEndpoint::Unix(dir.join("antiwire.sock"))
        }
    }

    /// A client of the server at `endpoint`, trusting its published certificate.
    async fn connect(endpoint: &IpcEndpoint, paths: &IpcPaths) -> Channel {
        #[cfg(windows)]
        {
            use tonic::transport::{Certificate, ClientTlsConfig, Endpoint};

            let IpcEndpoint::Tcp(addr) = endpoint;
            let cert = std::fs::read_to_string(&paths.cert).expect("published certificate");
            Endpoint::from_shared(format!("https://{addr}"))
                .expect("endpoint")
                .tls_config(ClientTlsConfig::new().ca_certificate(Certificate::from_pem(cert)))
                .expect("tls")
                .connect()
                .await
                .expect("connect")
        }
        #[cfg(unix)]
        {
            let _ = paths;
            let IpcEndpoint::Unix(path) = endpoint.clone();
            tonic::transport::Endpoint::from_static("http://[::]:0")
                .connect_with_connector(tower::service_fn(move |_| {
                    let path = path.clone();
                    async move {
                        tokio::net::UnixStream::connect(path)
                            .await
                            .map(hyper_util::rt::TokioIo::new)
                    }
                }))
                .await
                .expect("connect")
        }
    }

    /// The regression this guards: a server built without the interceptor
    /// would answer this test's first call.
    #[tokio::test]
    async fn the_served_endpoint_requires_the_published_token_and_shuts_down() {
        let dir = tempfile::tempdir().expect("tempdir");
        let paths = IpcPaths::beside(dir.path().join("ipc.token"));
        let parts = TestParts::new(Arc::new(ZeroActiveConnectionCounter));
        let shutdown = parts.service.shutdown.clone();
        let server = GrpcServer::new(test_endpoint(dir.path()), paths.clone(), parts.service);
        let (bound_tx, bound_rx) = tokio::sync::oneshot::channel();
        let serving = tokio::spawn(server.serve(move |bound| {
            let _ = bound_tx.send(bound.clone());
        }));
        let bound = bound_rx.await.expect("the server listens");

        let mut client = AntiwireServiceClient::new(connect(&bound, &paths).await);
        let refused = client
            .get_stats(antiwire_proto::Empty {})
            .await
            .expect_err("a call without the token");
        assert_eq!(refused.code(), Code::Unauthenticated);

        let token = std::fs::read_to_string(&paths.token).expect("published token");
        let mut request = Request::new(antiwire_proto::Empty {});
        request
            .metadata_mut()
            .insert(TOKEN_HEADER, token.trim().parse().expect("metadata"));
        client.get_stats(request).await.expect("an authorized call");

        // The client stays connected: shutdown must not wait for it to leave.
        shutdown.cancel();
        tokio::time::timeout(Duration::from_secs(5), serving)
            .await
            .expect("the server stops")
            .expect("server task")
            .expect("served cleanly");
        drop(parts.dir);
    }

    #[cfg(unix)]
    #[test]
    fn only_owner_death_errors_allow_stale_socket_recovery() {
        use std::io::Error;

        assert!(unix_socket_probe_proves_stale(&Error::from(
            std::io::ErrorKind::ConnectionRefused
        )));
        assert!(unix_socket_probe_proves_stale(&Error::from(
            std::io::ErrorKind::NotFound
        )));

        // Permission failures and descriptor exhaustion (EMFILE, errno 24)
        // do not establish that the owner is dead; the endpoint must survive.
        assert!(!unix_socket_probe_proves_stale(&Error::from(
            std::io::ErrorKind::PermissionDenied
        )));
        assert!(!unix_socket_probe_proves_stale(&Error::from_raw_os_error(
            24
        )));
    }
}
