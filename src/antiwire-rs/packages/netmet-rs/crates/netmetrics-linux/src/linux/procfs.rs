//! Procfs socket ownership, flow snapshots, and the polling fallback.

use crate::tcp_state;
use netmetrics_core::{FlowKey, LocalEndpoint, Protocol, SocketOwnerSnapshot, TcpState};
use std::collections::HashMap;
use std::fs;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::Path;

mod listing;
#[cfg(test)]
mod tests;

pub(super) use listing::ProcfsListing;

/// Returns the number of established TCP connections in `/proc/net/tcp` and `tcp6`: the
/// rows whose state is established ([`TcpState::is_established`]), which are the rows the
/// procfs fallback opens as flows.
///
/// Listeners, handshakes, connections this end has finished sending on, time-wait rows and
/// UDP sockets are not counted. Owners are not needed to count, so this skips the walk of
/// every process's descriptors.
///
/// # Errors
///
/// Returns the reason when `/proc/net` cannot be read; that is no count, not zero.
pub fn active_socket_count() -> Result<u32, String> {
    count_established_tcp_connections(Path::new("/proc/net")).map_err(|error| error.to_string())
}

/// The TCP rows under `net_root` that are flows, which for TCP means established
/// connections.
fn count_established_tcp_connections(net_root: &Path) -> io::Result<u32> {
    let mut count = 0_u32;
    for_each_socket_row(net_root, Some(Protocol::Tcp), |row| {
        if row.flow_key().is_some() {
            count = count.saturating_add(1);
        }
    })?;
    Ok(count)
}

/// Point-in-time TCP 5-tuple, TCP listener and UDP bind owners from `/proc/net`.
pub fn socket_owner_snapshot() -> SocketOwnerSnapshot {
    socket_owners(None)
}

/// Owners of `protocol`'s sockets only, read from that protocol's `/proc/net` tables.
///
/// A lookup by local endpoint only ever matches rows of its own protocol, so it gets the
/// same answer from this as from [`socket_owner_snapshot`].
pub fn socket_owner_snapshot_for(protocol: Protocol) -> SocketOwnerSnapshot {
    socket_owners(Some(protocol))
}

fn socket_owners(protocol: Option<Protocol>) -> SocketOwnerSnapshot {
    let inode_pids = inode_pid_map(Path::new("/proc"));
    read_socket_owners(Path::new("/proc/net"), &inode_pids, protocol).unwrap_or_default()
}

/// Owners of the sockets under `net_root`, or only of `protocol`'s.
///
/// A TCP connection names its owner whatever its state: a connection's first packets
/// leave in `SYN_SENT`, before it is a flow. A row with inode zero names no
/// process, so time-wait and request sockets, and sockets their application has closed,
/// add nothing (see [`crate::tcp_state`]).
fn read_socket_owners(
    net_root: &Path,
    inode_pids: &HashMap<u64, u32>,
    protocol: Option<Protocol>,
) -> io::Result<SocketOwnerSnapshot> {
    let mut snapshot = SocketOwnerSnapshot::default();
    for_each_socket_row(net_root, protocol, |row| {
        let pid = inode_pids.get(&row.inode).copied().unwrap_or(0);
        match row.protocol {
            Protocol::Tcp => {
                if let Some(key) = row.connected_key() {
                    snapshot.insert_tcp(key, pid);
                } else if let Some(endpoint) = row.listening_endpoint() {
                    snapshot.insert_tcp_listener(endpoint, pid);
                }
            }
            Protocol::Udp => {
                if let Some(endpoint) = row.bound_endpoint() {
                    snapshot.insert_udp(endpoint, pid);
                }
            }
        }
    })?;
    Ok(snapshot)
}

/// Reads every flow the tables list ([`SocketRow::flow_key`]) as `(pid, inode)`.
///
/// This seeds the eBPF source at start, and the procfs fallback (and eBPF reconciliation,
/// on a kernel without the lifecycle tracepoint) opens a flow when its row appears here
/// and closes it when the row leaves. A TCP connection that is still being set up, or
/// that this end has finished sending on, is not here, so none of them opens a finished
/// connection, and the polls close one when it stops being established, not when its
/// time-wait row expires a minute later.
///
/// The inode is the closest thing procfs offers to a socket identity. It is unique among
/// *open* sockets but recycled after close, so a changed inode on an unchanged tuple proves
/// a new socket while an unchanged one does not fully prove continuity. That asymmetry only
/// ever costs a missed flow split, never a false one.
pub(super) fn read_proc_flows(
    net_root: &Path,
    inode_pids: &HashMap<u64, u32>,
) -> io::Result<HashMap<FlowKey, (u32, u64)>> {
    let mut flows = HashMap::new();
    for_each_socket_row(net_root, None, |row| {
        if let Some(key) = row.flow_key() {
            let pid = inode_pids.get(&row.inode).copied().unwrap_or(0);
            flows.insert(key, (pid, row.inode));
        }
    })?;
    Ok(flows)
}

/// Parses every row of `tcp`, `tcp6`, `udp`, and `udp6` under `net_root`, or only `only`'s
/// two tables. A missing file is skipped, since a kernel without IPv6 has no `tcp6`.
fn for_each_socket_row(
    net_root: &Path,
    only: Option<Protocol>,
    mut visit: impl FnMut(SocketRow),
) -> io::Result<()> {
    for (name, protocol, ipv6) in [
        ("tcp", Protocol::Tcp, false),
        ("tcp6", Protocol::Tcp, true),
        ("udp", Protocol::Udp, false),
        ("udp6", Protocol::Udp, true),
    ] {
        if only.is_some_and(|only| only != protocol) {
            continue;
        }
        let contents = match fs::read_to_string(net_root.join(name)) {
            Ok(contents) => contents,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error),
        };
        for line in contents.lines().skip(1) {
            if let Some(row) = SocketRow::parse(line, protocol, ipv6) {
                visit(row);
            }
        }
    }
    Ok(())
}

/// One line of a `/proc/net` socket table.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct SocketRow {
    protocol: Protocol,
    local_addr: IpAddr,
    local_port: u16,
    remote_addr: IpAddr,
    remote_port: u16,
    state: u8,
    inode: u64,
}

impl SocketRow {
    fn parse(line: &str, protocol: Protocol, ipv6: bool) -> Option<Self> {
        let fields: Vec<_> = line.split_ascii_whitespace().collect();
        if fields.len() < 10 {
            return None;
        }
        let (local_addr, local_port) = parse_endpoint(fields[1], ipv6)?;
        let (remote_addr, remote_port) = parse_endpoint(fields[2], ipv6)?;
        Some(Self {
            protocol,
            local_addr,
            local_port,
            remote_addr,
            remote_port,
            state: u8::from_str_radix(fields[3], 16).ok()?,
            inode: fields[9].parse().ok()?,
        })
    }

    /// The state of a TCP row. A UDP row has none.
    fn tcp_state(&self) -> Option<TcpState> {
        (self.protocol == Protocol::Tcp)
            .then(|| tcp_state::from_procfs(self.state))
            .flatten()
    }

    /// The flow this row lists: a connected UDP socket, or an established TCP connection
    /// ([`TcpState::is_established`]).
    fn flow_key(&self) -> Option<FlowKey> {
        if self.protocol == Protocol::Tcp && !self.tcp_state().is_some_and(TcpState::is_established)
        {
            return None;
        }
        self.connected_key()
    }

    /// The connected 5-tuple, whatever the connection's state. TCP listeners and sockets
    /// without a peer have none.
    fn connected_key(&self) -> Option<FlowKey> {
        if self.tcp_state() == Some(TcpState::Listen) {
            return None;
        }
        if self.remote_addr.is_unspecified() && self.remote_port == 0 {
            return None;
        }
        Some(FlowKey {
            protocol: self.protocol,
            local_addr: self.local_addr,
            local_port: self.local_port,
            remote_addr: self.remote_addr,
            remote_port: self.remote_port,
        })
    }

    /// The endpoint a TCP listener accepts on. An inbound connection whose own row has
    /// already left the table is attributed to the process listening here.
    fn listening_endpoint(&self) -> Option<LocalEndpoint> {
        (self.tcp_state() == Some(TcpState::Listen))
            .then(|| self.bound_endpoint())
            .flatten()
    }

    /// The bound local endpoint, connected or not.
    fn bound_endpoint(&self) -> Option<LocalEndpoint> {
        (self.local_port != 0).then_some(LocalEndpoint {
            address: self.local_addr,
            port: self.local_port,
        })
    }
}

fn parse_endpoint(value: &str, ipv6: bool) -> Option<(IpAddr, u16)> {
    let (address, port) = value.split_once(':')?;
    let port = u16::from_str_radix(port, 16).ok()?;
    if ipv6 {
        if address.len() != 32 {
            return None;
        }
        let mut bytes = [0_u8; 16];
        for index in 0..4 {
            let word = u32::from_str_radix(&address[index * 8..index * 8 + 8], 16).ok()?;
            bytes[index * 4..index * 4 + 4].copy_from_slice(&word.to_le_bytes());
        }
        Some((IpAddr::V6(Ipv6Addr::from(bytes)), port))
    } else {
        let raw = u32::from_str_radix(address, 16).ok()?;
        Some((IpAddr::V4(Ipv4Addr::from(raw.to_le_bytes())), port))
    }
}

pub(super) fn inode_pid_map(proc_root: &Path) -> HashMap<u64, u32> {
    let mut result = HashMap::new();
    let Ok(entries) = fs::read_dir(proc_root) else {
        return result;
    };
    for entry in entries.flatten() {
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|name| name.parse::<u32>().ok())
        else {
            continue;
        };
        let Ok(fds) = fs::read_dir(entry.path().join("fd")) else {
            continue;
        };
        for fd in fds.flatten() {
            let Ok(target) = fs::read_link(fd.path()) else {
                continue;
            };
            let Some(target) = target.to_str() else {
                continue;
            };
            let Some(inode) = target
                .strip_prefix("socket:[")
                .and_then(|value| value.strip_suffix(']'))
                .and_then(|value| value.parse::<u64>().ok())
            else {
                continue;
            };
            record_inode_owner(&mut result, inode, pid);
        }
    }
    result
}

/// Whether a procfs flow row should be reported as an open.
///
/// A changed inode on a known tuple means the port was recycled onto a new
/// socket between polls, so it is a fresh open rather than the same flow. The
/// same inode is reported again only when the previous scan could not name an
/// owner and this one can: the descriptor and socket tables are read
/// separately, so a new socket can first appear ownerless. Losing or changing
/// an owner on the same socket is not reported, since PID 0 also means shared
/// and the first owner found is kept.
pub(super) fn snapshot_row_is_news(previous: Option<&(u32, u64)>, pid: u32, inode: u64) -> bool {
    match previous {
        Some(&(previous_pid, previous_inode)) if previous_inode == inode => {
            previous_pid == 0 && pid != 0
        }
        _ => true,
    }
}

fn record_inode_owner(owners: &mut HashMap<u64, u32>, inode: u64, pid: u32) {
    owners
        .entry(inode)
        .and_modify(|owner| {
            if *owner != pid {
                // PID zero is the existing public representation for shared or unknown
                // ownership. Once ambiguous, traversal order cannot make it unique again.
                *owner = 0;
            }
        })
        .or_insert(pid);
}
