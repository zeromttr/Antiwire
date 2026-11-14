//! Where the IPC server listens, and where it publishes what clients need
//! to connect.
//!
//! Both are resolved once, by the daemon at start-up, and handed to the
//! server; nothing reads the environment while serving.

use std::fmt;
#[cfg(windows)]
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use crate::error::IpcError;

/// The address the IPC server listens on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IpcEndpoint {
    /// Loopback TCP, served over TLS with a certificate the client pins.
    #[cfg(windows)]
    Tcp(SocketAddr),
    /// A Unix domain socket that only root and the client group may open.
    #[cfg(unix)]
    Unix(PathBuf),
}

/// Prefix that marks a listen address as a Unix socket path.
const UNIX_PREFIX: &str = "unix:";

impl IpcEndpoint {
    /// The endpoint the installed client connects to.
    #[must_use]
    pub fn platform_default() -> Self {
        #[cfg(windows)]
        {
            Self::Tcp(SocketAddr::from(([127, 0, 0, 1], 50051)))
        }
        #[cfg(unix)]
        {
            Self::Unix(PathBuf::from("/var/run/antiwire.sock"))
        }
    }

    /// Where the client connects when nothing else is configured: on Unix the
    /// socket `ANTIWIRE_IPC_SOCKET` names, which the client reads too, else
    /// [`Self::platform_default`]. Reads the environment.
    #[must_use]
    pub fn from_environment_or_platform_default() -> Self {
        #[cfg(unix)]
        {
            if let Some(socket) =
                std::env::var_os("ANTIWIRE_IPC_SOCKET").filter(|socket| !socket.is_empty())
            {
                return Self::Unix(PathBuf::from(socket));
            }
        }
        Self::platform_default()
    }

    /// A TCP endpoint, refused unless its address is loopback.
    ///
    /// The API is privileged. TLS and the token protect it, but nothing is
    /// meant to reach it from another machine, so a wildcard or LAN address is
    /// a configuration error, not an exposure to accept.
    ///
    /// # Errors
    ///
    /// [`IpcError::Endpoint`] when `addr` is not a loopback address.
    #[cfg(windows)]
    pub fn loopback_tcp(addr: SocketAddr) -> Result<Self, IpcError> {
        if addr.ip().is_loopback() {
            Ok(Self::Tcp(addr))
        } else {
            Err(IpcError::Endpoint(format!(
                "{addr}: the IPC endpoint must be a loopback address such as 127.0.0.1"
            )))
        }
    }

    /// Parses a listen address: `host:port` on Windows, `unix:<path>` on
    /// Unix.
    ///
    /// # Errors
    ///
    /// [`IpcError::Endpoint`] for an address this platform does not serve:
    /// Windows serves TLS over loopback TCP only, and Unix serves a socket
    /// file only, so the token never crosses a plain TCP connection.
    pub fn parse(listen: &str) -> Result<Self, IpcError> {
        let listen = listen.trim();
        let socket = listen.strip_prefix(UNIX_PREFIX);
        #[cfg(windows)]
        {
            if socket.is_some() {
                return Err(IpcError::Endpoint(format!(
                    "{listen}: Unix sockets are not served on Windows; give host:port"
                )));
            }
            let addr: SocketAddr = listen
                .parse()
                .map_err(|error| IpcError::Endpoint(format!("{listen}: {error}")))?;
            Self::loopback_tcp(addr)
        }
        #[cfg(unix)]
        {
            match socket.map(str::trim) {
                Some(path) if !path.is_empty() => Ok(Self::Unix(PathBuf::from(path))),
                _ => Err(IpcError::Endpoint(format!(
                    "{listen}: give the socket as unix:<path>; TCP is served only on Windows"
                ))),
            }
        }
    }
}

impl fmt::Display for IpcEndpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            #[cfg(windows)]
            Self::Tcp(addr) => write!(f, "{addr}"),
            #[cfg(unix)]
            Self::Unix(path) => write!(f, "{UNIX_PREFIX}{}", path.display()),
        }
    }
}

/// Where the server publishes the token and certificate clients read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpcPaths {
    /// The token every request must carry. Rewritten on each start.
    pub token: PathBuf,
    /// The server's TLS certificate, which the client pins. Only Windows
    /// serves TLS, so only Windows writes it.
    pub cert: PathBuf,
}

impl IpcPaths {
    /// The token at `token`, and the certificate beside it, where the
    /// client looks for it.
    #[must_use]
    pub fn beside(token: impl Into<PathBuf>) -> Self {
        let token = token.into();
        let cert = token.with_file_name("ipc.crt");
        Self { token, cert }
    }

    /// The installed locations, overridden by `ANTIWIRE_IPC_TOKEN` and
    /// `ANTIWIRE_IPC_CERT` where those are set. Reads the environment.
    #[must_use]
    pub fn from_environment() -> Self {
        let mut paths = Self::beside(
            path_override("ANTIWIRE_IPC_TOKEN")
                .unwrap_or_else(|| ipc_directory().join("ipc.token")),
        );
        if let Some(cert) = path_override("ANTIWIRE_IPC_CERT") {
            paths.cert = cert;
        }
        paths
    }
}

fn path_override(variable: &str) -> Option<PathBuf> {
    std::env::var(variable)
        .ok()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
}

/// The directory the client searches for the token: the user's data
/// directory in a debug build, the machine-wide one otherwise.
fn ipc_directory() -> PathBuf {
    if cfg!(debug_assertions) {
        directories::ProjectDirs::from("com", "Antiwire", "Antiwire").map_or_else(
            || PathBuf::from(".antiwire"),
            |directories| directories.data_local_dir().to_path_buf(),
        )
    } else if cfg!(windows) {
        std::env::var("PROGRAMDATA").map_or_else(
            |_| PathBuf::from(r"C:\ProgramData\Antiwire"),
            |dir| Path::new(&dir).join("Antiwire"),
        )
    } else {
        PathBuf::from("/var/lib/antiwire")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_certificate_lives_beside_the_token() {
        let paths = IpcPaths::beside(Path::new("data").join("ipc.token"));
        assert_eq!(paths.cert, Path::new("data").join("ipc.crt"));
    }

    #[test]
    fn the_default_endpoint_round_trips_through_its_listen_form() {
        let endpoint = IpcEndpoint::platform_default();
        assert_eq!(
            IpcEndpoint::parse(&endpoint.to_string()).ok(),
            Some(endpoint)
        );
    }

    #[cfg(windows)]
    #[test]
    fn windows_serves_loopback_tcp_only() {
        assert_eq!(
            IpcEndpoint::parse(" 127.0.0.1:6000 ").ok(),
            Some(IpcEndpoint::Tcp(SocketAddr::from(([127, 0, 0, 1], 6000))))
        );
        assert!(IpcEndpoint::parse("unix:/tmp/antiwire.sock").is_err());
        assert!(IpcEndpoint::parse("localhost").is_err());
        assert_eq!(
            IpcEndpoint::parse("[::1]:6000").ok(),
            Some(IpcEndpoint::Tcp("[::1]:6000".parse().expect("addr")))
        );
        for exposed in [
            "0.0.0.0:50051",
            "[::]:50051",
            "192.168.1.10:50051",
            "10.0.0.1:1",
        ] {
            assert!(
                IpcEndpoint::parse(exposed).is_err(),
                "{exposed} must not be served"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn unix_serves_a_socket_file_only() {
        assert_eq!(
            IpcEndpoint::parse("unix:/tmp/antiwire.sock").ok(),
            Some(IpcEndpoint::Unix(PathBuf::from("/tmp/antiwire.sock")))
        );
        assert!(IpcEndpoint::parse("127.0.0.1:50051").is_err());
        assert!(IpcEndpoint::parse("unix:").is_err());
    }
}
