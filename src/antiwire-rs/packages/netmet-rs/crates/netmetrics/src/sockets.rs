//! Point-in-time socket owner lookup from the host OS.

use netmetrics_core::{Protocol, SocketOwnerSnapshot};

/// Captures TCP 5-tuple and UDP bind owners without using the collector event stream.
#[must_use]
pub fn socket_owner_snapshot() -> SocketOwnerSnapshot {
    platform_socket_owner_snapshot()
}

#[cfg(all(windows, feature = "windows"))]
fn platform_socket_owner_snapshot() -> SocketOwnerSnapshot {
    netmetrics_windows::socket_owner_snapshot()
}

/// Owners of `protocol`'s sockets. A lookup by local endpoint matches only
/// rows of its own protocol, so it answers as it would from
/// [`socket_owner_snapshot`]; on Windows this reads fewer tables.
#[must_use]
pub fn socket_owner_snapshot_for(protocol: Protocol) -> SocketOwnerSnapshot {
    #[cfg(all(windows, feature = "windows"))]
    {
        netmetrics_windows::socket_owner_snapshot_for(protocol)
    }
    #[cfg(not(all(windows, feature = "windows")))]
    {
        let _ = protocol;
        platform_socket_owner_snapshot()
    }
}

#[cfg(all(target_os = "linux", feature = "linux"))]
fn platform_socket_owner_snapshot() -> SocketOwnerSnapshot {
    netmetrics_linux::socket_owner_snapshot()
}

#[cfg(all(target_os = "macos", feature = "macos"))]
fn platform_socket_owner_snapshot() -> SocketOwnerSnapshot {
    netmetrics_macos::socket_owner_snapshot()
}

#[cfg(not(any(
    all(windows, feature = "windows"),
    all(target_os = "linux", feature = "linux"),
    all(target_os = "macos", feature = "macos"),
)))]
fn platform_socket_owner_snapshot() -> SocketOwnerSnapshot {
    SocketOwnerSnapshot::default()
}

#[cfg(test)]
mod tests {
    use super::socket_owner_snapshot;
    use netmetrics_core::{FlowKey, Protocol};
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

    #[cfg(all(windows, feature = "windows"))]
    #[test]
    fn a_protocol_snapshot_holds_only_that_protocols_sockets() {
        use super::socket_owner_snapshot_for;
        use netmetrics_core::LocalEndpoint;

        let pid = std::process::id();
        // The second scan reuses the first one's table buffers.
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
                netmetrics_core::Ownership::Resolved(pid)
            );
            assert_eq!(
                socket_owner_snapshot_for(Protocol::Tcp)
                    .local_endpoint_owner(Protocol::Udp, endpoint),
                netmetrics_core::Ownership::NotFound,
                "a TCP scan reads no UDP table"
            );
        }
    }
}
