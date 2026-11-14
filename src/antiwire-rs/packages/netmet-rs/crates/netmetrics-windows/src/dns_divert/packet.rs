//! DNS packet classification and redirect rewriting.
//!
//! Only addresses and ports are edited here. The divert loop recomputes every
//! checksum with `WinDivertHelperCalcChecksums` before reinjecting.

use super::nat::{NatKey, NatTable, OriginalKey};
use super::{DNS_PORT, FLOW_OWNER_WAIT, LOOPBACK_BIT, OUTBOUND_BIT};
use crate::windivert_handle::DivertAddress;
use netmetrics_core::{LocalEndpoint, Protocol, locate_transport};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Instant;

/// What [`redirect_packet`] did with a packet.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Redirect {
    /// Not one to redirect; send it on as it is.
    Unchanged,
    /// Rewritten to or from the stub.
    Rewritten,
    /// A query or reply that should be redirected but cannot be, so it is
    /// dropped rather than sent on unfiltered or half rewritten.
    Unredirectable,
}

/// Rewrites one captured packet. `ours` says whether this process owns the
/// sending socket, which keeps the daemon's own upstream queries unchanged.
pub(super) fn redirect_packet(
    packet: &mut [u8],
    view: &PacketView,
    address: &mut DivertAddress,
    nat: &mut NatTable,
    ours: bool,
    now: Instant,
) -> Redirect {
    let outbound = address.layer_event & OUTBOUND_BIT != 0;
    let loopback = address.layer_event & LOOPBACK_BIT != 0;
    if outbound && !loopback && view.dst_port == DNS_PORT && !is_stub(view.dst) {
        if ours {
            return Redirect::Unchanged;
        }
        if !view.rewritable {
            return Redirect::Unredirectable;
        }
        let (if_idx, sub_if_idx) = interface_indices(address);
        let Some(mapped_port) = nat.map_query(
            OriginalKey {
                tcp: view.tcp,
                client: view.src,
                port: view.src_port,
                server: view.dst,
            },
            if_idx,
            sub_if_idx,
            now,
        ) else {
            return Redirect::Unredirectable;
        };
        if !rewrite_dest(packet, stub_for(view.dst))
            || !rewrite_source(packet, stub_for(view.src))
            || !rewrite_port(packet, view, true, mapped_port)
        {
            return Redirect::Unredirectable;
        }
        address.layer_event |= LOOPBACK_BIT;
        return Redirect::Rewritten;
    }
    if outbound && loopback && view.src_port == DNS_PORT && is_stub(view.src) {
        let Some(entry) = nat.get(
            NatKey {
                tcp: view.tcp,
                port: view.dst_port,
            },
            now,
        ) else {
            return Redirect::Unchanged;
        };
        if !view.rewritable
            || !rewrite_source(packet, entry.original.server)
            || !rewrite_dest(packet, entry.original.client)
            || !rewrite_port(packet, view, false, entry.original.port)
        {
            return Redirect::Unredirectable;
        }
        write_interface(address, entry.if_idx, entry.sub_if_idx);
        address.layer_event &= !LOOPBACK_BIT;
        address.layer_event &= !OUTBOUND_BIT;
        return Redirect::Rewritten;
    }
    Redirect::Unchanged
}

/// `Some(true)` when this process owns the sending socket. `None` when neither
/// source can say, so a failed lookup does not drop the daemon's own upstream.
///
/// The FLOW listener answers from memory. The socket table is read only when
/// it cannot: a full read of both tables per packet, which a process sending
/// its own DNS would otherwise cause for every packet. A `System` owner is not
/// taken as an answer: a packet this divert reinjected comes back as a
/// `System` flow, which the listener filters out, so if one gets through
/// anyway the socket table decides rather than this dropping our own upstream.
pub(super) fn owned_by_us(view: &PacketView, our_pid: u32, received_at: Instant) -> Option<bool> {
    let protocol = if view.tcp {
        Protocol::Tcp
    } else {
        Protocol::Udp
    };
    let endpoint = LocalEndpoint {
        address: view.src,
        port: view.src_port,
    };
    if let Some(pid) = crate::endpoint_owner::current_endpoint_owner_at(
        protocol,
        endpoint,
        received_at,
        FLOW_OWNER_WAIT,
    )
    .filter(|&pid| pid != crate::endpoint_owner::SYSTEM_PID)
    {
        return Some(pid == our_pid);
    }
    crate::owner_module::owns_local_endpoint(view.tcp, our_pid, |local_addr, local_port| {
        local_port == view.src_port && bound_address_covers(local_addr, view.src)
    })
    .ok()
}

/// A connected UDP socket often stays bound to the unspecified address while
/// the packet carries the interface address Windows chose. `DoQ` is that case:
/// an exact compare classifies the daemon's own upstream as foreign and the
/// divert drops it.
pub(super) fn bound_address_covers(bound: IpAddr, packet_src: IpAddr) -> bool {
    if bound == packet_src {
        return true;
    }
    match (bound, packet_src) {
        (IpAddr::V4(bound), IpAddr::V4(_)) => bound.is_unspecified(),
        // A dual-stack socket is listed as `[::]` while its IPv4 packets carry
        // the interface address.
        (IpAddr::V6(bound), IpAddr::V6(_) | IpAddr::V4(_)) => bound.is_unspecified(),
        _ => false,
    }
}

fn is_stub(addr: IpAddr) -> bool {
    match addr {
        IpAddr::V4(addr) => addr == Ipv4Addr::LOCALHOST,
        IpAddr::V6(addr) => addr == Ipv6Addr::LOCALHOST,
    }
}

pub(super) fn stub_for(addr: IpAddr) -> IpAddr {
    match addr {
        IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::LOCALHOST),
        IpAddr::V6(_) => IpAddr::V6(Ipv6Addr::LOCALHOST),
    }
}

pub(super) fn interface_indices(address: &DivertAddress) -> (u32, u32) {
    let if_idx = u32::from_ne_bytes(copy4(&address.data[0..4]));
    let sub_if_idx = u32::from_ne_bytes(copy4(&address.data[4..8]));
    (if_idx, sub_if_idx)
}

fn write_interface(address: &mut DivertAddress, if_idx: u32, sub_if_idx: u32) {
    address.data[0..4].copy_from_slice(&if_idx.to_ne_bytes());
    address.data[4..8].copy_from_slice(&sub_if_idx.to_ne_bytes());
}

fn copy4(bytes: &[u8]) -> [u8; 4] {
    let mut array = [0u8; 4];
    array.copy_from_slice(bytes);
    array
}

pub(super) struct PacketView {
    pub(super) tcp: bool,
    pub(super) src: IpAddr,
    pub(super) dst: IpAddr,
    pub(super) src_port: u16,
    pub(super) dst_port: u16,
    /// Where the TCP or UDP header starts.
    pub(super) transport_offset: usize,
    /// Whether the rewrite helpers can edit it: they find an IPv6 transport
    /// header right after the fixed header, so extension headers rule it out.
    pub(super) rewritable: bool,
}

impl PacketView {
    /// Reads a TCP or UDP packet that is not a fragment, past any IPv6
    /// extension headers, so their ports cannot hide a query.
    pub(super) fn parse(packet: &[u8]) -> Option<Self> {
        let located = locate_transport(packet)?;
        let tcp = match located.protocol {
            6 => true,
            17 => false,
            _ => return None,
        };
        let ports = packet.get(located.offset..located.offset + 4)?;
        Some(Self {
            tcp,
            src: located.source,
            dst: located.destination,
            src_port: u16::from_be_bytes([ports[0], ports[1]]),
            dst_port: u16::from_be_bytes([ports[2], ports[3]]),
            transport_offset: located.offset,
            rewritable: located.source.is_ipv4() || located.offset == 40,
        })
    }
}

fn rewrite_dest(packet: &mut [u8], dest: IpAddr) -> bool {
    rewrite_address(packet, dest, false)
}

fn rewrite_source(packet: &mut [u8], source: IpAddr) -> bool {
    rewrite_address(packet, source, true)
}

fn rewrite_port(packet: &mut [u8], view: &PacketView, source: bool, port: u16) -> bool {
    let offset = view.transport_offset + if source { 0 } else { 2 };
    write_at(packet, offset, &port.to_be_bytes())
}

fn rewrite_address(packet: &mut [u8], addr: IpAddr, source: bool) -> bool {
    match (packet.first().copied().unwrap_or(0) >> 4, addr) {
        (4, IpAddr::V4(addr)) => write_at(packet, if source { 12 } else { 16 }, &addr.octets()),
        (6, IpAddr::V6(addr)) => write_at(packet, if source { 8 } else { 24 }, &addr.octets()),
        _ => false,
    }
}

fn write_at(packet: &mut [u8], offset: usize, value: &[u8]) -> bool {
    let Some(bytes) = packet.get_mut(offset..offset + value.len()) else {
        return false;
    };
    bytes.copy_from_slice(value);
    true
}
