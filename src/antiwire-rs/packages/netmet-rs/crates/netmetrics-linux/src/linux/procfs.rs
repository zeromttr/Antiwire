//! Procfs socket ownership, flow snapshots, and the polling fallback.

use super::interface::{best_interface_index, emit_interface_samples};
use super::io_error;
use super::process::read_process_identity;
use netmetrics_core::{
    CookieSource, FlowKey, LocalEndpoint, ProcessIdentity, ProcessInfo, Protocol, SocketCookie,
    SocketOwnerSnapshot, unix_now_ms,
};
use netmetrics_sys::{BackendConfig, BackendError, BackendEvent, EventSink, StopFlag};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::Path;
use std::time::Duration;

#[cfg(test)]
mod tests;

pub(super) fn run_procfs(
    config: &BackendConfig,
    sink: &EventSink,
    stop: &StopFlag,
) -> Result<(), BackendError> {
    let mut previous_flows = HashMap::<FlowKey, (u32, u64)>::new();
    let mut previous_processes = HashMap::<u32, ProcessIdentity>::new();
    let interval = Duration::from_millis(config.poll_interval_ms.max(250));

    while !stop.is_stop_requested() {
        let timestamp = unix_now_ms();
        let inode_pids = inode_pid_map(Path::new("/proc"));
        let current_flows = read_proc_flows(Path::new("/proc/net"), &inode_pids)
            .map_err(|error| io_error("procfs sockets", &error))?;

        for (key, (pid, inode)) in &current_flows {
            if snapshot_row_is_news(previous_flows.get(key), *pid, *inode) {
                sink.emit(BackendEvent::Opened {
                    key: *key,
                    pid: *pid,
                    cookie: Some(SocketCookie {
                        value: *inode,
                        source: CookieSource::LinuxInode,
                    }),
                    timestamp,
                    if_index: best_interface_index(key.remote_addr),
                });
            }
        }
        for key in previous_flows.keys() {
            if !current_flows.contains_key(key) {
                sink.emit(BackendEvent::Closed {
                    pid: 0,
                    key: *key,
                    timestamp,
                });
            }
        }

        let current_pids: HashSet<_> = inode_pids.values().copied().collect();
        let mut current_processes = HashMap::new();
        for pid in current_pids {
            if let Some(identity) = read_process_identity(Path::new("/proc"), pid) {
                if previous_processes.get(&pid) != Some(&identity) {
                    sink.emit(BackendEvent::ProcessStarted(ProcessInfo {
                        pid,
                        identity: identity.clone(),
                    }));
                }
                current_processes.insert(pid, identity);
            }
        }
        for pid in previous_processes.keys() {
            if !current_processes.contains_key(pid) {
                sink.emit(BackendEvent::ProcessStopped {
                    pid: *pid,
                    timestamp,
                    identity: previous_processes.get(pid).cloned(),
                });
            }
        }

        emit_interface_samples(sink, timestamp);

        previous_flows = current_flows;
        previous_processes = current_processes;
        stop.wait_timeout(interval);
    }
    Ok(())
}

/// Returns the number of non-listen sockets in `/proc/net/{tcp,tcp6,udp,udp6}`.
///
/// Owners are not needed to count, so this skips the walk of every process's descriptors.
///
/// # Errors
///
/// Returns the reason when `/proc/net` cannot be read; that is no count, not zero.
pub fn active_socket_count() -> Result<u32, String> {
    read_proc_flows(Path::new("/proc/net"), &HashMap::new())
        .map(|flows| u32::try_from(flows.len()).unwrap_or(u32::MAX))
        .map_err(|error| error.to_string())
}

/// Point-in-time TCP 5-tuple and UDP bind owners from `/proc/net`.
pub fn socket_owner_snapshot() -> SocketOwnerSnapshot {
    let inode_pids = inode_pid_map(Path::new("/proc"));
    read_socket_owners(Path::new("/proc/net"), &inode_pids).unwrap_or_default()
}

fn read_socket_owners(
    net_root: &Path,
    inode_pids: &HashMap<u64, u32>,
) -> io::Result<SocketOwnerSnapshot> {
    let mut snapshot = SocketOwnerSnapshot::default();
    for_each_socket_row(net_root, |row| {
        let pid = inode_pids.get(&row.inode).copied().unwrap_or(0);
        match row.protocol {
            Protocol::Tcp => {
                if let Some(key) = row.flow_key() {
                    snapshot.insert_tcp(key, pid);
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

/// Reads every established socket as `(pid, inode)`.
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
    for_each_socket_row(net_root, |row| {
        if let Some(key) = row.flow_key() {
            let pid = inode_pids.get(&row.inode).copied().unwrap_or(0);
            flows.insert(key, (pid, row.inode));
        }
    })?;
    Ok(flows)
}

/// Parses every row of `tcp`, `tcp6`, `udp`, and `udp6` under `net_root`. A missing file is
/// skipped, since a kernel without IPv6 has no `tcp6`.
fn for_each_socket_row(net_root: &Path, mut visit: impl FnMut(SocketRow)) -> io::Result<()> {
    for (name, protocol, ipv6) in [
        ("tcp", Protocol::Tcp, false),
        ("tcp6", Protocol::Tcp, true),
        ("udp", Protocol::Udp, false),
        ("udp6", Protocol::Udp, true),
    ] {
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

/// `TCP_LISTEN` in the `st` column.
const TCP_LISTEN: u8 = 0x0a;

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

    /// The connected 5-tuple. TCP listeners and sockets without a peer are not flows.
    fn flow_key(&self) -> Option<FlowKey> {
        if self.protocol == Protocol::Tcp && self.state == TCP_LISTEN {
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
