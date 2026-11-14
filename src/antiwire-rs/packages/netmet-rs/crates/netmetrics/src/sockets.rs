//! Point-in-time socket owner lookup from the host OS.

use netmetrics_core::{Protocol, SocketOwnerSnapshot};

#[cfg(all(target_os = "linux", feature = "linux"))]
use netmetrics_linux as platform;
#[cfg(all(target_os = "macos", feature = "macos"))]
use netmetrics_macos as platform;
#[cfg(all(windows, feature = "windows"))]
use netmetrics_windows as platform;

/// No socket table to read on a target without a backend.
#[cfg(not(any(
    all(windows, feature = "windows"),
    all(target_os = "linux", feature = "linux"),
    all(target_os = "macos", feature = "macos"),
)))]
mod platform {
    use netmetrics_core::{Protocol, SocketOwnerSnapshot};

    pub(super) fn socket_owner_snapshot() -> SocketOwnerSnapshot {
        SocketOwnerSnapshot::default()
    }

    pub(super) fn socket_owner_snapshot_for(_protocol: Protocol) -> SocketOwnerSnapshot {
        SocketOwnerSnapshot::default()
    }
}

/// Captures TCP 5-tuple, TCP listener and UDP bind owners without using the collector
/// event stream.
#[must_use]
pub fn socket_owner_snapshot() -> SocketOwnerSnapshot {
    platform::socket_owner_snapshot()
}

/// Owners of `protocol`'s sockets. A lookup by local endpoint matches only
/// rows of its own protocol, so it answers as it would from
/// [`socket_owner_snapshot`] while reading only that protocol's tables.
#[must_use]
pub fn socket_owner_snapshot_for(protocol: Protocol) -> SocketOwnerSnapshot {
    platform::socket_owner_snapshot_for(protocol)
}

#[cfg(test)]
mod tests {
    use super::{socket_owner_snapshot, socket_owner_snapshot_for};
    use netmetrics_core::{FlowKey, LocalEndpoint, Ownership, Protocol};
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn captured_udp_socket_resolves_current_process() {
        let socket = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind UDP socket");
        let endpoint = socket.local_addr().expect("read UDP socket address");
        let key = FlowKey {
            protocol: Protocol::Udp,
            local_addr: endpoint.ip(),
            local_port: endpoint.port(),
            remote_addr: IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
            remote_port: 53,
        };
        assert_eq!(
            socket_owner_snapshot().lookup_owner_pid(&key),
            Some(std::process::id())
        );
    }

    #[test]
    fn a_protocol_snapshot_holds_only_that_protocols_sockets() {
        let pid = std::process::id();
        // On Windows the second scan reuses the first one's table buffers.
        for _ in 0..2 {
            let socket =
                std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind UDP socket");
            let bound = socket.local_addr().expect("read UDP socket address");
            let endpoint = LocalEndpoint {
                address: bound.ip(),
                port: bound.port(),
            };
            assert_eq!(
                socket_owner_snapshot_for(Protocol::Udp)
                    .local_endpoint_owner(Protocol::Udp, endpoint),
                Ownership::Resolved(pid)
            );
            assert_eq!(
                socket_owner_snapshot_for(Protocol::Tcp)
                    .local_endpoint_owner(Protocol::Udp, endpoint),
                Ownership::NotFound,
                "a TCP scan reads no UDP table"
            );
        }
    }

    /// A connection that has already left the socket table still belongs to whoever
    /// listens on its local port.
    #[test]
    fn a_listener_owns_an_inbound_connection_that_left_the_table() {
        let listener =
            std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind TCP listener");
        let bound = listener.local_addr().expect("read listener address");
        let departed = FlowKey {
            protocol: Protocol::Tcp,
            local_addr: bound.ip(),
            local_port: bound.port(),
            remote_addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
            remote_port: 9,
        };
        assert_eq!(
            socket_owner_snapshot_for(Protocol::Tcp).lookup_owner_pid(&departed),
            Some(std::process::id())
        );
    }
}
