//! Bounded DNS redirect mappings and exclusive reservations for their alias ports.

use super::packet::stub_for;
use netmetrics_core::{LocalEndpoint, Protocol};
use socket2::{Domain, Socket, Type};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::windows::io::AsRawSocket;
use std::time::{Duration, Instant};
use windows::Win32::Networking::WinSock::{SOCKET, SOL_SOCKET, setsockopt};

const NAT_CAPACITY: usize = 4_096;
pub(super) const NAT_RETENTION: Duration = Duration::from_secs(30);
// Defined by Winsock as ~SO_REUSEADDR.
const SO_EXCLUSIVEADDRUSE: i32 = -5;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub(super) struct NatKey {
    pub(super) tcp: bool,
    pub(super) port: u16,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub(super) struct OriginalKey {
    pub(super) tcp: bool,
    pub(super) client: IpAddr,
    pub(super) port: u16,
    pub(super) server: IpAddr,
}

#[derive(Clone, Copy, Debug)]
pub(super) struct NatEntry {
    pub(super) original: OriginalKey,
    pub(super) if_idx: u32,
    pub(super) sub_if_idx: u32,
    pub(super) expires_at: Instant,
}

#[derive(Debug)]
pub(super) struct PortReservation {
    _socket: Socket,
}

impl PortReservation {
    pub(super) fn bind(tcp: bool, address: IpAddr, port: u16) -> Option<Self> {
        let (domain, wildcard) = if address.is_ipv4() {
            (Domain::IPV4, IpAddr::V4(Ipv4Addr::UNSPECIFIED))
        } else {
            (Domain::IPV6, IpAddr::V6(Ipv6Addr::UNSPECIFIED))
        };
        let socket =
            Socket::new(domain, if tcp { Type::STREAM } else { Type::DGRAM }, None).ok()?;
        if address.is_ipv6() {
            socket.set_only_v6(true).ok()?;
        }
        // Windows allows a wildcard bind alongside a specific-address bind.
        // Reserve the entire family exclusively, including against SO_REUSEADDR.
        let enabled = 1_i32.to_ne_bytes();
        let raw = usize::try_from(socket.as_raw_socket()).ok()?;
        // SAFETY: the socket is live and enabled contains the required BOOL.
        let result =
            unsafe { setsockopt(SOCKET(raw), SOL_SOCKET, SO_EXCLUSIVEADDRUSE, Some(&enabled)) };
        if result != 0 {
            return None;
        }
        socket.bind(&SocketAddr::new(wildcard, port).into()).ok()?;
        Some(Self { _socket: socket })
    }
}

#[derive(Debug)]
struct NatMapping {
    entry: NatEntry,
    _reservation: PortReservation,
}

#[derive(Debug, Default)]
pub(super) struct NatTable {
    entries: HashMap<NatKey, NatMapping>,
    originals: HashMap<OriginalKey, NatKey>,
    next_port: u16,
}

impl NatTable {
    #[cfg(test)]
    pub(super) fn with_next_port(next_port: u16) -> Self {
        Self {
            next_port,
            ..Self::default()
        }
    }

    pub(super) fn map_query(
        &mut self,
        original: OriginalKey,
        if_idx: u32,
        sub_if_idx: u32,
        now: Instant,
    ) -> Option<u16> {
        self.expire(now);
        if let Some(key) = self.originals.get(&original)
            && let Some(entry) = self.entries.get_mut(key)
        {
            entry.entry.expires_at = now + NAT_RETENTION;
            return Some(key.port);
        }
        if self.entries.len() >= NAT_CAPACITY {
            let oldest = self
                .entries
                .iter()
                .min_by_key(|(_, entry)| entry.entry.expires_at)?
                .0;
            let oldest = *oldest;
            self.entries.remove(&oldest);
            self.originals.retain(|_, key| *key != oldest);
        }
        let (port, reservation) = (0..=(u16::MAX - 49_152)).find_map(|_| {
            let port = if self.next_port < 49_152 {
                49_152
            } else {
                self.next_port
            };
            self.next_port = port.wrapping_add(1);
            let key = NatKey {
                tcp: original.tcp,
                port,
            };
            if self.entries.contains_key(&key) {
                return None;
            }
            PortReservation::bind(original.tcp, stub_for(original.client), port)
                .map(|reservation| (port, reservation))
        })?;
        let key = NatKey {
            tcp: original.tcp,
            port,
        };
        self.entries.insert(
            key,
            NatMapping {
                entry: NatEntry {
                    original,
                    if_idx,
                    sub_if_idx,
                    expires_at: now + NAT_RETENTION,
                },
                _reservation: reservation,
            },
        );
        self.originals.insert(original, key);
        Some(port)
    }

    pub(super) fn get(&mut self, key: NatKey, now: Instant) -> Option<NatEntry> {
        self.expire(now);
        let entry = self.entries.get_mut(&key)?;
        entry.entry.expires_at = now + NAT_RETENTION;
        Some(entry.entry)
    }

    pub(super) fn original_endpoint(
        &mut self,
        protocol: Protocol,
        endpoint: LocalEndpoint,
        now: Instant,
    ) -> Option<LocalEndpoint> {
        self.expire(now);
        let tcp = match protocol {
            Protocol::Tcp => true,
            Protocol::Udp => false,
        };
        let entry = self
            .entries
            .get(&NatKey {
                tcp,
                port: endpoint.port,
            })?
            .entry;
        if endpoint.address != stub_for(entry.original.client) {
            return None;
        }
        Some(LocalEndpoint {
            address: entry.original.client,
            port: entry.original.port,
        })
    }

    fn expire(&mut self, now: Instant) {
        self.entries.retain(|_, entry| entry.entry.expires_at > now);
        self.originals
            .retain(|_, key| self.entries.contains_key(key));
    }
}
