use crate::{FlowKey, Protocol};
use std::collections::HashMap;
use std::net::IpAddr;

/// Local bind used to attribute unconnected UDP sockets.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct LocalEndpoint {
    /// Bound address, which may be unspecified.
    pub address: IpAddr,
    /// Bound port.
    pub port: u16,
}

/// Owner of a local socket endpoint, as one socket-table snapshot saw it.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Ownership {
    /// Exactly one process owns the endpoint. The pid is never zero: tables
    /// report zero for sockets without an owner, and snapshots drop those rows.
    Resolved(u32),
    /// Several processes own the endpoint, so no single one can be named.
    Ambiguous,
    /// No socket matched the endpoint.
    NotFound,
}

impl Ownership {
    /// The owning pid when exactly one process owns the endpoint.
    #[must_use]
    pub const fn resolved_pid(self) -> Option<u32> {
        match self {
            Self::Resolved(pid) if pid > 0 => Some(pid),
            _ => None,
        }
    }
}

/// Point-in-time TCP and UDP owner maps.
///
/// TCP rows are keyed by the full 5-tuple. UDP rows are keyed by local bind because the
/// platform tables often have no peer. TCP listeners are kept separately: an inbound
/// connection whose transient 5-tuple has already left the table can still be attributed
/// to the process that owns the local listening port.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SocketOwnerSnapshot {
    tcp: HashMap<FlowKey, u32>,
    /// `None` means multiple PIDs own this local UDP endpoint.
    udp: HashMap<LocalEndpoint, Option<u32>>,
    /// `None` means multiple PIDs own this local TCP listening endpoint.
    tcp_listeners: HashMap<LocalEndpoint, Option<u32>>,
}

impl SocketOwnerSnapshot {
    /// Records an established TCP socket owner.
    pub fn insert_tcp(&mut self, key: FlowKey, pid: u32) {
        if pid == 0 || key.protocol != Protocol::Tcp {
            return;
        }
        self.tcp.insert(key, pid);
    }

    /// Records a TCP listener owner, marking the endpoint ambiguous when PIDs disagree.
    pub fn insert_tcp_listener(&mut self, endpoint: LocalEndpoint, pid: u32) {
        insert_local_bind(&mut self.tcp_listeners, endpoint, pid);
    }

    /// Records a UDP bind owner, marking the endpoint ambiguous when PIDs disagree.
    pub fn insert_udp(&mut self, endpoint: LocalEndpoint, pid: u32) {
        insert_local_bind(&mut self.udp, endpoint, pid);
    }

    /// Whether `key` is an established TCP row, in either direction.
    ///
    /// A listening socket on the same local port is not a connection. Idle eviction uses
    /// this so a quiet TCP session stays open, without keeping every flow to a server
    /// that merely has a listener.
    #[must_use]
    pub fn contains_established_tcp(&self, key: &FlowKey) -> bool {
        key.protocol == Protocol::Tcp
            && (self.tcp.contains_key(key) || self.tcp.contains_key(&key.reverse()))
    }

    /// Returns the owning PID for a flow when the socket row is still present.
    #[must_use]
    pub fn lookup_owner_pid(&self, key: &FlowKey) -> Option<u32> {
        match key.protocol {
            Protocol::Tcp => self
                .tcp
                .get(key)
                .or_else(|| self.tcp.get(&key.reverse()))
                .copied()
                .filter(|pid| *pid > 0)
                .or_else(|| lookup_tcp_listener(&self.tcp_listeners, key)),
            Protocol::Udp => lookup_local_bind(&self.udp, key),
        }
    }

    /// Owner of the socket bound to `endpoint`, keeping ambiguity visible.
    ///
    /// Unlike [`Self::lookup_owner_pid`], this needs no peer address. TCP matches established
    /// rows by their local side, then a listener; UDP matches the exact bind, then the
    /// wildcard bind, but never another address on the same port.
    #[must_use]
    pub fn local_endpoint_owner(&self, protocol: Protocol, endpoint: LocalEndpoint) -> Ownership {
        let key = FlowKey {
            protocol,
            local_addr: endpoint.address,
            local_port: endpoint.port,
            remote_addr: unspecified_address(endpoint.address),
            remote_port: 0,
        };
        let owner = match protocol {
            Protocol::Tcp => {
                let mut owner = None;
                for (row, &pid) in &self.tcp {
                    if row.local_addr != endpoint.address || row.local_port != endpoint.port {
                        continue;
                    }
                    if owner.is_some_and(|existing| existing != pid) {
                        return Ownership::Ambiguous;
                    }
                    owner = Some(pid);
                }
                owner
                    .map(Some)
                    .or_else(|| lookup_exact_or_wildcard(&self.tcp_listeners, &key))
            }
            Protocol::Udp => lookup_exact_or_wildcard(&self.udp, &key),
        };
        ownership(owner)
    }
}

/// Reads the tables' encoding: `None` is a miss and `Some(None)` an ambiguous endpoint.
#[allow(clippy::option_option)]
const fn ownership(owner: Option<Option<u32>>) -> Ownership {
    match owner {
        Some(Some(pid)) if pid > 0 => Ownership::Resolved(pid),
        Some(Some(_)) | None => Ownership::NotFound,
        Some(None) => Ownership::Ambiguous,
    }
}

fn insert_local_bind(
    table: &mut HashMap<LocalEndpoint, Option<u32>>,
    endpoint: LocalEndpoint,
    pid: u32,
) {
    if pid == 0 || endpoint.port == 0 {
        return;
    }
    match table.get_mut(&endpoint) {
        Some(existing) => {
            if *existing != Some(pid) {
                *existing = None;
            }
        }
        None => {
            table.insert(endpoint, Some(pid));
        }
    }
}

#[allow(clippy::option_option)] // None = miss; Some(None) = present but ambiguous
fn lookup_exact_or_wildcard(
    table: &HashMap<LocalEndpoint, Option<u32>>,
    key: &FlowKey,
) -> Option<Option<u32>> {
    let exact = LocalEndpoint {
        address: key.local_addr,
        port: key.local_port,
    };
    if let Some(owner) = table.get(&exact) {
        return Some(*owner);
    }

    let wildcard = LocalEndpoint {
        address: unspecified_address(key.local_addr),
        port: key.local_port,
    };
    if wildcard != exact {
        return table.get(&wildcard).copied();
    }
    None
}

fn lookup_tcp_listener(table: &HashMap<LocalEndpoint, Option<u32>>, key: &FlowKey) -> Option<u32> {
    lookup_exact_or_wildcard(table, key).flatten()
}

fn lookup_local_bind(table: &HashMap<LocalEndpoint, Option<u32>>, key: &FlowKey) -> Option<u32> {
    if let Some(owner) = lookup_exact_or_wildcard(table, key) {
        return owner;
    }

    let mut candidate = None;
    for (endpoint, owner) in table {
        if endpoint.port != key.local_port || !same_address_family(endpoint.address, key.local_addr)
        {
            continue;
        }
        let pid = (*owner)?;
        if candidate.is_some_and(|existing| existing != pid) {
            return None;
        }
        candidate = Some(pid);
    }
    candidate
}

/// The unspecified (wildcard) address of `address`'s family.
#[must_use]
pub const fn unspecified_address(address: IpAddr) -> IpAddr {
    match address {
        IpAddr::V4(_) => IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
        IpAddr::V6(_) => IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED),
    }
}

const fn same_address_family(left: IpAddr, right: IpAddr) -> bool {
    matches!(
        (left, right),
        (IpAddr::V4(_), IpAddr::V4(_)) | (IpAddr::V6(_), IpAddr::V6(_))
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn udp_key(address: IpAddr, port: u16) -> FlowKey {
        FlowKey {
            protocol: Protocol::Udp,
            local_addr: address,
            local_port: port,
            remote_addr: IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
            remote_port: 53,
        }
    }

    fn endpoint(address: Ipv4Addr, port: u16) -> LocalEndpoint {
        LocalEndpoint {
            address: IpAddr::V4(address),
            port,
        }
    }

    #[test]
    fn local_endpoint_owner_finds_a_tcp_client_by_its_local_side() {
        let client = FlowKey {
            protocol: Protocol::Tcp,
            local_addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
            local_port: 50_000,
            remote_addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
            remote_port: 53,
        };
        let mut snapshot = SocketOwnerSnapshot::default();
        snapshot.insert_tcp(client, 4242);
        snapshot.insert_tcp(client.reverse(), 7);
        assert_eq!(
            snapshot.local_endpoint_owner(Protocol::Tcp, endpoint(Ipv4Addr::LOCALHOST, 50_000)),
            Ownership::Resolved(4242)
        );
        assert_eq!(
            snapshot.local_endpoint_owner(Protocol::Udp, endpoint(Ipv4Addr::LOCALHOST, 50_000)),
            Ownership::NotFound,
            "the protocol must match"
        );
    }

    #[test]
    fn local_endpoint_owner_keeps_ambiguity_and_exact_addresses() {
        let mut snapshot = SocketOwnerSnapshot::default();
        snapshot.insert_udp(endpoint(Ipv4Addr::UNSPECIFIED, 50_000), 4242);
        snapshot.insert_udp(endpoint(Ipv4Addr::UNSPECIFIED, 50_000), 8484);
        snapshot.insert_udp(endpoint(Ipv4Addr::new(10, 0, 0, 3), 50_001), 4242);
        assert_eq!(
            snapshot.local_endpoint_owner(Protocol::Udp, endpoint(Ipv4Addr::LOCALHOST, 50_000)),
            Ownership::Ambiguous,
            "a wildcard bind shared by two processes is ambiguous"
        );
        assert_eq!(
            snapshot.local_endpoint_owner(Protocol::Udp, endpoint(Ipv4Addr::LOCALHOST, 50_001)),
            Ownership::NotFound,
            "a bind on another address is a different socket"
        );
    }

    #[test]
    fn ownership_never_resolves_to_pid_zero() {
        assert_eq!(ownership(Some(Some(0))), Ownership::NotFound);
        assert_eq!(Ownership::Resolved(0).resolved_pid(), None);
        assert_eq!(Ownership::Resolved(7).resolved_pid(), Some(7));
        assert_eq!(Ownership::Ambiguous.resolved_pid(), None);

        let mut snapshot = SocketOwnerSnapshot::default();
        snapshot.insert_udp(endpoint(Ipv4Addr::LOCALHOST, 50_000), 0);
        assert_eq!(
            snapshot.local_endpoint_owner(Protocol::Udp, endpoint(Ipv4Addr::LOCALHOST, 50_000)),
            Ownership::NotFound
        );
    }

    #[test]
    fn local_endpoint_owner_ignores_a_zero_pid_beside_a_real_owner() {
        let mut snapshot = SocketOwnerSnapshot::default();
        snapshot.insert_udp(endpoint(Ipv4Addr::LOCALHOST, 50_000), 0);
        snapshot.insert_udp(endpoint(Ipv4Addr::LOCALHOST, 50_000), 4242);
        assert_eq!(
            snapshot.local_endpoint_owner(Protocol::Udp, endpoint(Ipv4Addr::LOCALHOST, 50_000)),
            Ownership::Resolved(4242)
        );
    }

    #[test]
    fn local_endpoint_owner_does_not_borrow_an_owner_from_other_addresses() {
        let mut snapshot = SocketOwnerSnapshot::default();
        snapshot.insert_udp(endpoint(Ipv4Addr::new(192, 168, 1, 10), 50_000), 4242);
        snapshot.insert_udp(endpoint(Ipv4Addr::new(10, 0, 0, 1), 50_000), 4242);
        assert_eq!(
            snapshot.local_endpoint_owner(Protocol::Udp, endpoint(Ipv4Addr::LOCALHOST, 50_000)),
            Ownership::NotFound,
            "the same owner on other addresses is still another socket"
        );
        assert_eq!(
            snapshot.local_endpoint_owner(
                Protocol::Udp,
                endpoint(Ipv4Addr::new(192, 168, 1, 10), 50_000)
            ),
            Ownership::Resolved(4242)
        );
    }

    #[test]
    fn empty_snapshot_returns_no_pid() {
        let snapshot = SocketOwnerSnapshot::default();
        let key = FlowKey {
            protocol: Protocol::Tcp,
            local_addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            local_port: 44_321,
            remote_addr: IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
            remote_port: 443,
        };
        assert_eq!(snapshot.lookup_owner_pid(&key), None);
    }

    #[test]
    fn tcp_ipv6_owner_matches_reverse_tuple() {
        let key = FlowKey {
            protocol: Protocol::Tcp,
            local_addr: "2001:db8::1".parse().expect("local address"),
            local_port: 50_000,
            remote_addr: "2606:4700:4700::1111".parse().expect("remote address"),
            remote_port: 443,
        };
        let mut snapshot = SocketOwnerSnapshot::default();
        snapshot.insert_tcp(key, 4242);
        assert_eq!(snapshot.lookup_owner_pid(&key.reverse()), Some(4242));
    }

    #[test]
    fn tcp_listener_attributes_an_inbound_connection_without_a_tuple() {
        let mut snapshot = SocketOwnerSnapshot::default();
        snapshot.insert_tcp_listener(
            LocalEndpoint {
                address: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                port: 51_413,
            },
            4242,
        );
        let inbound = FlowKey {
            protocol: Protocol::Tcp,
            local_addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            local_port: 51_413,
            remote_addr: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7)),
            remote_port: 51_000,
        };
        assert_eq!(snapshot.lookup_owner_pid(&inbound), Some(4242));

        let outbound = FlowKey {
            protocol: Protocol::Tcp,
            local_addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            local_port: 51_000,
            remote_addr: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7)),
            remote_port: 51_413,
        };
        assert_eq!(
            snapshot.lookup_owner_pid(&outbound),
            None,
            "a listener must not claim an outbound flow on the peer side"
        );
    }

    #[test]
    fn tcp_listener_matches_the_exact_local_address() {
        let mut snapshot = SocketOwnerSnapshot::default();
        snapshot.insert_tcp_listener(
            LocalEndpoint {
                address: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
                port: 8080,
            },
            4242,
        );
        let inbound = FlowKey {
            protocol: Protocol::Tcp,
            local_addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            local_port: 8080,
            remote_addr: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7)),
            remote_port: 51_000,
        };
        assert_eq!(snapshot.lookup_owner_pid(&inbound), Some(4242));
    }

    #[test]
    fn outbound_dns_tcp_does_not_inherit_a_loopback_dns_listener() {
        let mut snapshot = SocketOwnerSnapshot::default();
        snapshot.insert_tcp_listener(
            LocalEndpoint {
                address: IpAddr::V4(Ipv4Addr::LOCALHOST),
                port: 53,
            },
            7,
        );
        let outbound = FlowKey {
            protocol: Protocol::Tcp,
            local_addr: IpAddr::V4(Ipv4Addr::new(192, 168, 68, 50)),
            local_port: 52_946,
            remote_addr: IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9)),
            remote_port: 53,
        };
        assert_eq!(
            snapshot.lookup_owner_pid(&outbound),
            None,
            "an unattributed outbound resolver flow must stay ownerless"
        );
    }

    #[test]
    fn inbound_tcp_to_a_loopback_dns_listener_is_attributed() {
        let mut snapshot = SocketOwnerSnapshot::default();
        snapshot.insert_tcp_listener(
            LocalEndpoint {
                address: IpAddr::V4(Ipv4Addr::LOCALHOST),
                port: 53,
            },
            7,
        );
        let inbound = FlowKey {
            protocol: Protocol::Tcp,
            local_addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
            local_port: 53,
            remote_addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
            remote_port: 50_000,
        };
        assert_eq!(snapshot.lookup_owner_pid(&inbound), Some(7));
    }

    #[test]
    fn tcp_listener_does_not_match_a_different_interface_on_the_same_port() {
        let mut snapshot = SocketOwnerSnapshot::default();
        snapshot.insert_tcp_listener(
            LocalEndpoint {
                address: IpAddr::V4(Ipv4Addr::LOCALHOST),
                port: 8080,
            },
            4242,
        );
        let flow = FlowKey {
            protocol: Protocol::Tcp,
            local_addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            local_port: 8080,
            remote_addr: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7)),
            remote_port: 51_000,
        };
        assert_eq!(
            snapshot.lookup_owner_pid(&flow),
            None,
            "a loopback listener must not own a flow on another interface"
        );
    }

    #[test]
    fn ambiguous_tcp_listener_is_not_attributed() {
        let endpoint = LocalEndpoint {
            address: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            port: 51_413,
        };
        let mut snapshot = SocketOwnerSnapshot::default();
        snapshot.insert_tcp_listener(endpoint, 4242);
        snapshot.insert_tcp_listener(endpoint, 8484);
        let inbound = FlowKey {
            protocol: Protocol::Tcp,
            local_addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            local_port: 51_413,
            remote_addr: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7)),
            remote_port: 51_000,
        };
        assert_eq!(snapshot.lookup_owner_pid(&inbound), None);
    }

    #[test]
    fn udp_wildcard_binding_matches_specific_local_address() {
        let mut snapshot = SocketOwnerSnapshot::default();
        snapshot.insert_udp(
            LocalEndpoint {
                address: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                port: 50_000,
            },
            4242,
        );
        assert_eq!(
            snapshot.lookup_owner_pid(&udp_key(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 50_000)),
            Some(4242)
        );
    }

    #[test]
    fn udp_shared_endpoint_with_different_pids_is_ambiguous() {
        let endpoint = LocalEndpoint {
            address: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            port: 50_000,
        };
        let mut snapshot = SocketOwnerSnapshot::default();
        snapshot.insert_udp(endpoint, 4242);
        snapshot.insert_udp(endpoint, 8484);
        assert_eq!(
            snapshot.lookup_owner_pid(&udp_key(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 50_000)),
            None
        );
    }

    #[test]
    fn udp_port_fallback_refuses_disagreeing_addresses() {
        let mut snapshot = SocketOwnerSnapshot::default();
        for (address, pid) in [
            (Ipv4Addr::new(10, 0, 0, 3), 4242),
            (Ipv4Addr::new(10, 0, 0, 4), 8484),
        ] {
            snapshot.insert_udp(
                LocalEndpoint {
                    address: IpAddr::V4(address),
                    port: 50_000,
                },
                pid,
            );
        }
        assert_eq!(
            snapshot.lookup_owner_pid(&udp_key(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 50_000)),
            None
        );
    }

    #[test]
    fn ipv6_udp_wildcard_does_not_match_ipv4() {
        let mut snapshot = SocketOwnerSnapshot::default();
        snapshot.insert_udp(
            LocalEndpoint {
                address: IpAddr::V6(Ipv6Addr::UNSPECIFIED),
                port: 53,
            },
            7,
        );
        assert_eq!(
            snapshot.lookup_owner_pid(&udp_key(IpAddr::V4(Ipv4Addr::LOCALHOST), 53)),
            None
        );
    }
}

/// Live, last-known, or missing count of host sockets.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SocketCount {
    /// Present when a count has been sampled. `None` is unavailable, not zero.
    pub count: Option<u32>,
    /// True when `count` is last-known after a failed refresh.
    pub stale: bool,
}

impl SocketCount {
    /// A live sample that should be shown as current.
    #[must_use]
    pub const fn fresh(count: u32) -> Self {
        Self {
            count: Some(count),
            stale: false,
        }
    }

    /// Last-known value after a refresh failed.
    #[must_use]
    pub const fn stale(count: u32) -> Self {
        Self {
            count: Some(count),
            stale: true,
        }
    }

    /// No sample has ever been acquired.
    pub const UNAVAILABLE: Self = Self {
        count: None,
        stale: false,
    };
}

/// Owner of a local endpoint at the moment a query arrived.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EndpointOwner {
    /// The process that established the endpoint's flow. Never zero: an event
    /// without an owner is [`EndpointOwner::Untrusted`].
    Resolved(u32),
    /// The event source is running but saw no flow for the endpoint before then.
    NotFound,
    /// The newest flow before then came with an owner the source cannot be
    /// trusted for, such as `System` on a loopback flow.
    Untrusted,
    /// The source had not caught up with the query by the deadline, and what
    /// it had recorded so far names no owner.
    Behind,
    /// No event source is running, so the caller needs another one.
    Unavailable,
}
