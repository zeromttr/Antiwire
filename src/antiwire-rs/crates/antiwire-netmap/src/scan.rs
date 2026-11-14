use futures_util::stream::{self, StreamExt};
use std::collections::{BTreeMap, BTreeSet};
use std::io::{self, Read, Seek, SeekFrom};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use hickory_proto::op::{Message, MessageType, OpCode, Query};
use hickory_proto::rr::{Name, RData, Record, RecordType};
use hickory_resolver::TokioResolver;
use ipnet::{IpNet, Ipv4Net};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::net::UdpSocket;
use tokio_util::sync::CancellationToken;

const MAX_HOSTS_PER_RANGE: usize = 1_024;
const MAX_HOSTS_PER_SCAN: usize = 4_096;
const PROBE_PORT: u16 = 9;
const CACHE_SETTLE_TIME: Duration = Duration::from_millis(750);
const HOSTNAME_LOOKUP_TIMEOUT: Duration = Duration::from_millis(900);
const MAX_HOSTNAME_LOOKUPS: usize = 32;
const COMMAND_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_COMMAND_OUTPUT: u64 = 1024 * 1024;
const MDNS_PORT: u16 = 5_353;
const MDNS_MULTICAST_ADDRESS: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 251);

/// One observed host on the local network.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NetworkDeviceSnapshot {
    pub ip_address: String,
    pub mac_address: String,
    pub vendor: String,
    pub hostname: String,
    pub is_online: bool,
}

/// One private IPv4 network attached to a local interface.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NetworkInterfaceRange {
    pub adapter_id: String,
    pub cidr: String,
}

/// A network discovery request could not be performed.
#[derive(Debug, Error)]
pub enum ScanError {
    #[error("no private IPv4 scan ranges were found; enter a CIDR such as 192.168.1.0/24")]
    NoRanges,
    #[error("invalid CIDR range '{0}'")]
    InvalidRange(String),
    #[error("IPv6 range '{0}' is not supported for MAC address discovery")]
    Ipv6Unsupported(String),
    #[error(
        "range '{0}' is not on a local network; only private and link-local ranges can be scanned"
    )]
    NotLocal(String),
    #[error("range '{cidr}' contains {hosts} hosts; the maximum is {MAX_HOSTS_PER_RANGE}")]
    RangeTooLarge { cidr: String, hosts: usize },
    #[error("the scan contains more than {MAX_HOSTS_PER_SCAN} hosts")]
    ScanTooLarge,
    #[error("network scan was cancelled")]
    Cancelled,
    #[error("failed to inspect the operating system neighbor table: {0}")]
    NeighborTable(#[source] io::Error),
    #[error("failed to create the discovery socket: {0}")]
    Socket(#[source] io::Error),
}

/// Cross-platform active LAN scanner.
///
/// Sending a UDP datagram makes the operating system resolve the destination's
/// layer-two address. The scanner then reads the native ARP/NDP cache (`arp` on
/// Windows/macOS and `ip neigh` on Linux), so it needs no packet-capture driver.
#[derive(Debug, Default)]
pub struct SystemNetworkScanner;

impl SystemNetworkScanner {
    /// Discovers devices in the supplied IPv4 CIDR ranges.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid or excessively broad ranges, cancellation,
    /// socket setup failure, or when the platform neighbor table cannot be read.
    pub async fn scan(
        &self,
        cidr_ranges: &[String],
        cancellation: &CancellationToken,
    ) -> Result<Vec<NetworkDeviceSnapshot>, ScanError> {
        let (networks, targets) = scan_targets(cidr_ranges)?;
        if cancellation.is_cancelled() {
            return Err(ScanError::Cancelled);
        }

        let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))
            .await
            .map_err(ScanError::Socket)?;
        for (index, target) in targets.into_iter().enumerate() {
            if cancellation.is_cancelled() {
                return Err(ScanError::Cancelled);
            }

            // Closed UDP ports and unreachable hosts are expected. The send is
            // only used to ask the kernel to resolve the neighbor's MAC address.
            let _ = socket
                .send_to(&[], SocketAddr::new(IpAddr::V4(target), PROBE_PORT))
                .await;
            if index % 64 == 63 {
                tokio::task::yield_now().await;
            }
        }

        tokio::select! {
            () = tokio::time::sleep(CACHE_SETTLE_TIME) => {}
            () = cancellation.cancelled() => return Err(ScanError::Cancelled),
        }

        let table = tokio::task::spawn_blocking(read_neighbor_table)
            .await
            .map_err(|error| ScanError::NeighborTable(io::Error::other(error)))?
            .map_err(ScanError::NeighborTable)?;
        if cancellation.is_cancelled() {
            return Err(ScanError::Cancelled);
        }

        let mut devices: Vec<_> = discover_from_neighbor_table(&table)
            .into_iter()
            .filter(|device| {
                device
                    .ip_address
                    .parse::<Ipv4Addr>()
                    .is_ok_and(|ip| networks.iter().any(|network| network.contains(&ip)))
            })
            .collect();
        enrich_hostnames(&mut devices, cancellation).await;
        if cancellation.is_cancelled() {
            return Err(ScanError::Cancelled);
        }
        devices.sort_by_key(|device| {
            device
                .ip_address
                .parse::<Ipv4Addr>()
                .map_or(u32::MAX, u32::from)
        });
        Ok(devices)
    }
}

/// Discovers private IPv4 ranges and the local interfaces that own them.
///
/// # Errors
///
/// Returns [`ScanError::NoRanges`] when the platform command is unavailable or
/// no private interface range can be derived from its output.
pub async fn discover_local_ipv4_interfaces() -> Result<Vec<NetworkInterfaceRange>, ScanError> {
    let output = tokio::task::spawn_blocking(read_interface_table)
        .await
        .map_err(|error| ScanError::NeighborTable(io::Error::other(error)))?
        .map_err(ScanError::NeighborTable)?;

    let ranges = parse_interface_networks(&output);
    if ranges.is_empty() {
        Err(ScanError::NoRanges)
    } else {
        Ok(ranges)
    }
}

/// Parses native Windows `arp -a`, Linux `ip neigh`, and BSD/macOS `arp -an`
/// output into normalized device records.
pub fn discover_from_neighbor_table(table: &str) -> Vec<NetworkDeviceSnapshot> {
    let mut devices = BTreeMap::<Ipv4Addr, NetworkDeviceSnapshot>::new();

    for line in table.lines() {
        let parts: Vec<_> = line.split_whitespace().collect();
        let Some((ip_index, ip)) = parts
            .iter()
            .enumerate()
            .find_map(|(index, part)| parse_ipv4_token(part).map(|address| (index, address)))
        else {
            continue;
        };
        let Some(mac) = parts.iter().find_map(|part| normalize_mac(part)) else {
            continue;
        };

        let hostname = if ip_index > 0 {
            let candidate = parts[ip_index - 1].trim();
            if candidate == "?" || candidate.parse::<Ipv4Addr>().is_ok() {
                String::new()
            } else {
                candidate.to_owned()
            }
        } else {
            String::new()
        };

        devices.insert(
            ip,
            NetworkDeviceSnapshot {
                ip_address: ip.to_string(),
                mac_address: mac,
                vendor: String::new(),
                hostname,
                is_online: true,
            },
        );
    }

    devices.into_values().collect()
}

async fn enrich_hostnames(devices: &mut [NetworkDeviceSnapshot], cancellation: &CancellationToken) {
    let addresses: Vec<_> = devices
        .iter()
        .filter(|device| device.hostname.is_empty())
        .filter_map(|device| device.ip_address.parse::<Ipv4Addr>().ok())
        .collect();
    if addresses.is_empty() {
        return;
    }

    let (dns_names, mdns_names) = tokio::join!(
        resolve_system_hostnames(&addresses, cancellation.child_token()),
        resolve_mdns_hostnames(&addresses, cancellation.child_token()),
    );
    apply_resolved_hostnames(devices, &dns_names, &mdns_names);
}

async fn resolve_system_hostnames(
    addresses: &[Ipv4Addr],
    cancellation: CancellationToken,
) -> BTreeMap<Ipv4Addr, String> {
    let Ok(builder) = TokioResolver::builder_tokio() else {
        return BTreeMap::new();
    };
    let Ok(resolver) = builder.build() else {
        return BTreeMap::new();
    };

    let mut lookups = stream::iter(addresses.iter().copied().map(|address| {
        let resolver = resolver.clone();
        async move {
            let reverse_name = Name::from(IpAddr::V4(address));
            let lookup = tokio::time::timeout(
                HOSTNAME_LOOKUP_TIMEOUT,
                resolver.reverse_lookup(reverse_name),
            )
            .await
            .ok()?
            .ok()?;
            hostname_from_records(lookup.answers()).map(|hostname| (address, hostname))
        }
    }))
    .buffer_unordered(MAX_HOSTNAME_LOOKUPS);

    let mut names = BTreeMap::new();
    loop {
        tokio::select! {
            () = cancellation.cancelled() => break,
            result = lookups.next() => {
                let Some(result) = result else {
                    break;
                };
                if let Some((address, hostname)) = result {
                    names.insert(address, hostname);
                }
            }
        }
    }
    names
}

async fn resolve_mdns_hostnames(
    addresses: &[Ipv4Addr],
    cancellation: CancellationToken,
) -> BTreeMap<Ipv4Addr, String> {
    let Ok(socket) = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).await else {
        return BTreeMap::new();
    };

    for address in addresses.iter().copied() {
        if cancellation.is_cancelled() {
            break;
        }
        let Some(query) = mdns_reverse_query(address) else {
            continue;
        };
        // The multicast query reaches ordinary mDNS responders. The direct
        // query also covers hosts on another local interface when the OS's
        // multicast route selects only the default adapter.
        let _ = socket
            .send_to(&query, (MDNS_MULTICAST_ADDRESS, MDNS_PORT))
            .await;
        let _ = socket.send_to(&query, (address, MDNS_PORT)).await;
    }

    let deadline = tokio::time::Instant::now() + HOSTNAME_LOOKUP_TIMEOUT;
    let mut buffer = [0_u8; 4_096];
    let mut names = BTreeMap::new();
    while names.len() < addresses.len() {
        let received = tokio::select! {
            () = cancellation.cancelled() => break,
            received = tokio::time::timeout_at(deadline, socket.recv_from(&mut buffer)) => received,
        };
        let Ok(Ok((length, source))) = received else {
            break;
        };
        let Ok(message) = Message::from_vec(&buffer[..length]) else {
            continue;
        };
        // A device names only itself: any LAN host can send a reply, and one
        // naming other addresses would relabel devices it is not.
        names.extend(
            hostnames_from_message(&message)
                .into_iter()
                .filter(|(address, _)| IpAddr::V4(*address) == source.ip()),
        );
    }
    names
}

fn mdns_reverse_query(address: Ipv4Addr) -> Option<Vec<u8>> {
    let mut query = Query::query(Name::from(IpAddr::V4(address)), RecordType::PTR);
    query.set_mdns_unicast_response(true);
    let mut message = Message::new(0, MessageType::Query, OpCode::Query);
    message.add_query(query);
    message.to_vec().ok()
}

fn hostnames_from_message(message: &Message) -> BTreeMap<Ipv4Addr, String> {
    message
        .answers
        .iter()
        .chain(&message.additionals)
        .filter_map(|record| {
            let IpNet::V4(network) = record.name.parse_arpa_name().ok()? else {
                return None;
            };
            if u32::from(network.prefix_len()) != Ipv4Addr::BITS {
                return None;
            }
            hostname_from_records(std::iter::once(record))
                .map(|hostname| (network.addr(), hostname))
        })
        .collect()
}

fn hostname_from_records<'a>(records: impl IntoIterator<Item = &'a Record>) -> Option<String> {
    records.into_iter().find_map(|record| {
        let RData::PTR(ptr) = &record.data else {
            return None;
        };
        normalize_hostname(&ptr.0.to_utf8())
    })
}

fn normalize_hostname(hostname: &str) -> Option<String> {
    let hostname = hostname.trim().trim_end_matches('.');
    (!hostname.is_empty() && !hostname.to_ascii_lowercase().ends_with(".in-addr.arpa"))
        .then(|| hostname.to_owned())
}

fn apply_resolved_hostnames(
    devices: &mut [NetworkDeviceSnapshot],
    dns_names: &BTreeMap<Ipv4Addr, String>,
    mdns_names: &BTreeMap<Ipv4Addr, String>,
) {
    for device in devices
        .iter_mut()
        .filter(|device| device.hostname.is_empty())
    {
        let Ok(address) = device.ip_address.parse::<Ipv4Addr>() else {
            continue;
        };
        if let Some(hostname) = dns_names.get(&address).or_else(|| mdns_names.get(&address)) {
            device.hostname.clone_from(hostname);
        }
    }
}

/// Validates scan ranges without performing network I/O.
///
/// # Errors
///
/// Returns the same range validation errors as [`SystemNetworkScanner::scan`].
pub fn validate_scan_ranges(cidr_ranges: &[String]) -> Result<(), ScanError> {
    scan_targets(cidr_ranges).map(|_| ())
}

/// Returns a normalized colon-separated MAC address when `value` is valid.
pub fn canonical_mac(value: &str) -> Option<String> {
    normalize_mac(value)
}

fn scan_targets(cidr_ranges: &[String]) -> Result<(Vec<Ipv4Net>, Vec<Ipv4Addr>), ScanError> {
    if cidr_ranges.is_empty() {
        return Err(ScanError::NoRanges);
    }

    let mut networks = Vec::with_capacity(cidr_ranges.len());
    let mut targets = BTreeSet::new();
    for cidr in cidr_ranges {
        let network = match cidr.parse::<IpNet>() {
            Ok(IpNet::V4(network)) => network,
            Ok(IpNet::V6(_)) => return Err(ScanError::Ipv6Unsupported(cidr.clone())),
            Err(_) => return Err(ScanError::InvalidRange(cidr.clone())),
        };
        // The scan sends probes to every host in the range, so it stays on
        // networks the user's own devices can be on.
        if !is_local_range(network) {
            return Err(ScanError::NotLocal(cidr.clone()));
        }
        // Sized from the prefix before anything is collected: a request for
        // `0.0.0.0/0` must be refused, not materialized as four billion addresses.
        let hosts = usize::try_from(host_count(network)).unwrap_or(usize::MAX);
        if hosts > MAX_HOSTS_PER_RANGE {
            return Err(ScanError::RangeTooLarge {
                cidr: cidr.clone(),
                hosts,
            });
        }
        targets.extend(network.hosts());
        if targets.len() > MAX_HOSTS_PER_SCAN {
            return Err(ScanError::ScanTooLarge);
        }
        networks.push(network);
    }

    Ok((networks, targets.into_iter().collect()))
}

/// Whether all of `network` lies in a private (RFC 1918), carrier-grade NAT
/// or link-local range.
fn is_local_range(network: Ipv4Net) -> bool {
    const LOCAL: [(Ipv4Addr, u8); 5] = [
        (Ipv4Addr::new(10, 0, 0, 0), 8),
        (Ipv4Addr::new(172, 16, 0, 0), 12),
        (Ipv4Addr::new(192, 168, 0, 0), 16),
        (Ipv4Addr::new(100, 64, 0, 0), 10),
        (Ipv4Addr::new(169, 254, 0, 0), 16),
    ];
    LOCAL.iter().any(|&(address, prefix)| {
        Ipv4Net::new(address, prefix).is_ok_and(|local| local.contains(&network))
    })
}

/// Number of addresses [`Ipv4Net::hosts`] yields, without iterating it.
///
/// Below `/31` the network and broadcast addresses are excluded; `/31` and `/32`
/// yield every address.
fn host_count(network: Ipv4Net) -> u64 {
    let size = 1_u64 << (32 - u32::from(network.prefix_len()));
    if network.prefix_len() >= 31 {
        size
    } else {
        size - 2
    }
}

fn parse_ipv4_token(token: &str) -> Option<Ipv4Addr> {
    token
        .trim_matches(|character| matches!(character, '(' | ')' | ','))
        .parse()
        .ok()
}

fn normalize_mac(token: &str) -> Option<String> {
    let compact: String = token
        .trim_matches(|character| matches!(character, '(' | ')' | ','))
        .chars()
        .filter(|character| *character != ':' && *character != '-')
        .collect();
    if compact.len() != 12 || !compact.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }

    let bytes: Vec<_> = (0..6)
        .map(|index| u8::from_str_radix(&compact[index * 2..index * 2 + 2], 16))
        .collect::<Result<_, _>>()
        .ok()?;
    if bytes.iter().all(|byte| *byte == 0)
        || bytes.iter().all(|byte| *byte == u8::MAX)
        || bytes[0] & 1 != 0
    {
        return None;
    }

    Some(
        bytes
            .iter()
            .map(|byte| format!("{byte:02X}"))
            .collect::<Vec<_>>()
            .join(":"),
    )
}

fn run_command(program: &str, arguments: &[&str]) -> io::Result<String> {
    run_command_with_timeout(Command::new(program).args(arguments), COMMAND_TIMEOUT)
}

fn run_command_with_timeout(command: &mut Command, timeout: Duration) -> io::Result<String> {
    let mut output = tempfile::tempfile()?;
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(0x0800_0000); // CREATE_NO_WINDOW
    }
    let mut child = command
        .stdin(Stdio::null())
        .stdout(output.try_clone()?)
        .stderr(Stdio::null())
        .spawn()?;
    let deadline = Instant::now() + timeout;
    let status = loop {
        let status = match child.try_wait() {
            Ok(status) => status,
            Err(error) => {
                stop_command(&mut child);
                return Err(error);
            }
        };
        if let Some(status) = status {
            break status;
        }
        if output.metadata()?.len() > MAX_COMMAND_OUTPUT {
            stop_command(&mut child);
            return Err(io::Error::other("network inspection output too large"));
        }
        if Instant::now() >= deadline {
            stop_command(&mut child);
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "network inspection command timed out",
            ));
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    if !status.success() {
        return Err(io::Error::other(format!(
            "network inspection command exited with {status}"
        )));
    }
    if output.metadata()?.len() > MAX_COMMAND_OUTPUT {
        return Err(io::Error::other("network inspection output too large"));
    }
    output.seek(SeekFrom::Start(0))?;
    let mut bytes = Vec::new();
    output
        .take(MAX_COMMAND_OUTPUT + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_COMMAND_OUTPUT {
        return Err(io::Error::other("network inspection output too large"));
    }
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

fn stop_command(child: &mut std::process::Child) {
    let _ = child.kill();
    // Reap killed children on Unix instead of leaving zombies. Poll with a
    // bounded grace so even an unresponsive kernel cannot extend the deadline
    // into another unbounded wait.
    let deadline = Instant::now() + Duration::from_millis(250);
    while matches!(child.try_wait(), Ok(None)) && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[cfg(windows)]
fn read_neighbor_table() -> io::Result<String> {
    run_command("arp", &["-a"])
}

#[cfg(target_os = "linux")]
fn read_neighbor_table() -> io::Result<String> {
    run_command("ip", &["neigh", "show"]).or_else(|_| run_command("arp", &["-an"]))
}

#[cfg(target_os = "macos")]
fn read_neighbor_table() -> io::Result<String> {
    run_command("arp", &["-an"])
}

#[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
fn read_neighbor_table() -> io::Result<String> {
    run_command("arp", &["-an"])
}

#[cfg(windows)]
fn read_interface_table() -> io::Result<String> {
    run_command("ipconfig", &[])
}

#[cfg(target_os = "linux")]
fn read_interface_table() -> io::Result<String> {
    run_command("ip", &["-o", "-4", "addr", "show", "scope", "global"])
        .or_else(|_| run_command("ifconfig", &[]))
}

#[cfg(any(target_os = "macos", not(any(windows, target_os = "linux"))))]
fn read_interface_table() -> io::Result<String> {
    run_command("ifconfig", &[])
}

#[cfg(test)]
fn parse_interface_ranges(table: &str) -> Vec<String> {
    parse_interface_networks(table)
        .into_iter()
        .map(|range| range.cidr)
        .collect()
}

fn parse_interface_networks(table: &str) -> Vec<NetworkInterfaceRange> {
    let mut ranges = BTreeMap::<String, String>::new();
    let mut current_interface = String::new();
    let mut pending_ip = None;

    for line in table.lines() {
        if let Some(interface) = parse_interface_header(line) {
            current_interface = interface;
            pending_ip = None;
        }

        let parts: Vec<_> = line.split_whitespace().collect();
        let Some(inet_index) = parts.iter().position(|part| *part == "inet") else {
            // Windows ipconfig places an IPv4 address and subnet mask on
            // adjacent labelled lines.
            let lower = line.to_ascii_lowercase();
            let value = line.rsplit_once(':').map(|(_, value)| value.trim());
            if lower.contains("ipv4") {
                pending_ip = value
                    .and_then(parse_ipconfig_address)
                    .map(|ip| (ip, current_interface.clone()));
            } else if lower.contains("subnet mask") {
                if let (Some((ip, adapter)), Some(prefix)) =
                    (pending_ip.take(), value.and_then(parse_subnet_mask))
                {
                    insert_private_interface_range(&mut ranges, &adapter, ip, prefix);
                }
            }
            continue;
        };

        // Linux `ip -o -4 addr` includes a canonical CIDR token and places
        // the interface name immediately before `inet`.
        if let Some(network) = parts
            .get(inet_index + 1)
            .and_then(|value| value.parse::<Ipv4Net>().ok())
        {
            let adapter = inet_index
                .checked_sub(1)
                .and_then(|index| parts.get(index))
                .copied()
                .unwrap_or_default();
            insert_private_interface_range(
                &mut ranges,
                adapter,
                network.addr(),
                network.prefix_len(),
            );
            continue;
        }

        // macOS/BSD ifconfig emits `inet A.B.C.D netmask 0xffffff00` below
        // an interface header such as `en0: flags=...`.
        let Some(ip) = parts
            .get(inet_index + 1)
            .and_then(|value| value.parse::<Ipv4Addr>().ok())
        else {
            continue;
        };
        let Some(mask_index) = parts.iter().position(|part| *part == "netmask") else {
            continue;
        };
        let Some(prefix) = parts
            .get(mask_index + 1)
            .and_then(|mask| parse_subnet_mask(mask))
        else {
            continue;
        };
        insert_private_interface_range(&mut ranges, &current_interface, ip, prefix);
    }

    ranges
        .into_iter()
        .map(|(cidr, adapter_id)| NetworkInterfaceRange { adapter_id, cidr })
        .collect()
}

fn parse_interface_header(line: &str) -> Option<String> {
    let trimmed = line.trim();
    let lower = trimmed.to_ascii_lowercase();

    if trimmed.ends_with(':') {
        if let Some(adapter_index) = lower.find(" adapter ") {
            let label_start = adapter_index + " adapter ".len();
            return Some(trimmed[label_start..].trim_end_matches(':').to_owned());
        }
    }

    if !line.chars().next().is_some_and(char::is_whitespace) && lower.contains(": flags=") {
        return trimmed
            .split_once(':')
            .map(|(interface, _)| interface.to_owned());
    }

    None
}

fn parse_ipconfig_address(value: &str) -> Option<Ipv4Addr> {
    value
        .split_whitespace()
        .next()?
        .trim_end_matches("(Preferred)")
        .parse()
        .ok()
}

fn parse_subnet_mask(value: &str) -> Option<u8> {
    let mask = if let Some(hex) = value.strip_prefix("0x") {
        u32::from_str_radix(hex, 16).ok()?
    } else {
        u32::from(value.parse::<Ipv4Addr>().ok()?)
    };
    let prefix = u8::try_from(mask.leading_ones()).ok()?;
    (mask == u32::MAX.checked_shl(u32::from(32 - prefix)).unwrap_or(0)).then_some(prefix)
}

/// Shortest prefix of a scan range found on an adapter: a `/22` has 1,022 hosts,
/// the most that fit under [`MAX_HOSTS_PER_RANGE`].
const WIDEST_ADAPTER_RANGE_PREFIX: u8 = 22;

/// Records the network `ip` is on as a range to scan, when it is a private one.
///
/// An adapter on a network too large to scan, such as a `/16` office network or the `/20`
/// a virtual switch hands out, contributes the `/22` around its own address instead. The
/// whole network would be refused as too large, and the default scan with it.
fn insert_private_interface_range(
    ranges: &mut BTreeMap<String, String>,
    adapter: &str,
    ip: Ipv4Addr,
    prefix: u8,
) {
    if !ip.is_private() {
        return;
    }
    let prefix = prefix.max(WIDEST_ADAPTER_RANGE_PREFIX);
    if let Ok(network) = Ipv4Net::new(ip, prefix) {
        ranges
            .entry(network.trunc().to_string())
            .or_insert_with(|| adapter.trim().to_owned());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::rr::rdata::PTR;

    #[test]
    fn timeout_test_child() {
        if std::env::var_os("ANTIWIRE_NETMAP_TIMEOUT_CHILD").is_some() {
            std::thread::sleep(Duration::from_secs(30));
        }
    }

    #[test]
    fn inspection_command_has_a_deadline() {
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args(["--exact", "scan::tests::timeout_test_child", "--nocapture"])
            .env("ANTIWIRE_NETMAP_TIMEOUT_CHILD", "1");
        let started = Instant::now();
        let error = run_command_with_timeout(&mut command, Duration::from_millis(100)).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert!(started.elapsed() < Duration::from_secs(3));
    }

    #[test]
    fn stopped_inspection_command_is_reaped() {
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "scan::tests::timeout_test_child"])
            .env("ANTIWIRE_NETMAP_TIMEOUT_CHILD", "1")
            .stdout(Stdio::null())
            .spawn()
            .unwrap();
        stop_command(&mut child);
        assert!(child.try_wait().unwrap().is_some());
    }

    #[test]
    fn parses_windows_linux_and_macos_neighbor_tables() {
        let table = r"
Interface: 192.168.1.20 --- 0x9
  192.168.1.1          00-1b-63-12-34-56     dynamic
192.168.1.8 dev eth0 lladdr 3c:22:fb:01:02:03 REACHABLE
printer.local (192.168.1.9) at 10:9a:dd:aa:bb:cc on en0 ifscope [ethernet]
? (192.168.1.10) at (incomplete) on en0
";

        let devices = discover_from_neighbor_table(table);
        assert_eq!(devices.len(), 3);
        assert_eq!(devices[0].mac_address, "00:1B:63:12:34:56");
        assert_eq!(devices[2].hostname, "printer.local");
    }

    #[test]
    fn fills_blank_names_without_overwriting_neighbor_names() {
        let mut devices = vec![
            NetworkDeviceSnapshot {
                ip_address: "192.168.1.8".to_owned(),
                mac_address: "3C:22:FB:01:02:03".to_owned(),
                vendor: String::new(),
                hostname: String::new(),
                is_online: true,
            },
            NetworkDeviceSnapshot {
                ip_address: "192.168.1.9".to_owned(),
                mac_address: "10:9A:DD:AA:BB:CC".to_owned(),
                vendor: String::new(),
                hostname: "neighbor-name.local".to_owned(),
                is_online: true,
            },
        ];
        let dns_names =
            BTreeMap::from([(Ipv4Addr::new(192, 168, 1, 8), "dns-name.lan".to_owned())]);
        let mdns_names = BTreeMap::from([
            (Ipv4Addr::new(192, 168, 1, 8), "mdns-name.local".to_owned()),
            (
                Ipv4Addr::new(192, 168, 1, 9),
                "replacement.local".to_owned(),
            ),
        ]);

        apply_resolved_hostnames(&mut devices, &dns_names, &mdns_names);

        assert_eq!(devices[0].hostname, "dns-name.lan");
        assert_eq!(devices[1].hostname, "neighbor-name.local");
    }

    #[test]
    fn extracts_and_normalizes_an_mdns_ptr_name() {
        let address = Ipv4Addr::new(192, 168, 1, 9);
        let reverse_name = Name::from(IpAddr::V4(address));
        let hostname = Name::from_ascii("printer.local.").expect("valid hostname");
        let mut message = Message::new(0, MessageType::Response, OpCode::Query);
        message.add_answer(Record::from_rdata(
            reverse_name,
            120,
            RData::PTR(PTR(hostname)),
        ));

        assert_eq!(
            hostnames_from_message(&message).get(&address),
            Some(&"printer.local".to_owned())
        );
    }

    #[test]
    fn mdns_reverse_query_requests_a_unicast_ptr_response() {
        let address = Ipv4Addr::new(192, 168, 1, 9);
        let encoded = mdns_reverse_query(address).expect("serializable query");
        let message = Message::from_vec(&encoded).expect("valid DNS message");

        assert_eq!(message.queries.len(), 1);
        assert_eq!(message.queries[0].name(), &Name::from(IpAddr::V4(address)));
        assert_eq!(message.queries[0].query_type(), RecordType::PTR);
        assert!(message.queries[0].mdns_unicast_response());
    }

    #[test]
    fn rejects_non_device_mac_addresses() {
        let table = "192.168.1.1 ff-ff-ff-ff-ff-ff dynamic\n\
                     192.168.1.2 01:00:5e:00:00:01 permanent\n\
                     192.168.1.3 00:00:00:00:00:00 stale";
        assert_eq!(discover_from_neighbor_table(table), []);
    }

    #[test]
    fn validates_and_deduplicates_scan_ranges() {
        let (_, targets) =
            scan_targets(&["192.168.1.0/30".to_owned(), "192.168.1.0/31".to_owned()])
                .expect("valid ranges");
        assert_eq!(targets.len(), 3);

        assert!(matches!(
            scan_targets(&["192.168.0.0/16".to_owned()]),
            Err(ScanError::RangeTooLarge { .. })
        ));
        assert!(matches!(
            scan_targets(&["not-a-range".to_owned()]),
            Err(ScanError::InvalidRange(_))
        ));
    }

    #[test]
    fn refuses_huge_ranges_without_enumerating_them() {
        // Enumerating 10.0.0.0/8 would allocate before the size check.
        let all_hosts = usize::try_from((1_u64 << 24) - 2).unwrap_or(usize::MAX);
        assert!(matches!(
            scan_targets(&["10.0.0.0/8".to_owned()]),
            Err(ScanError::RangeTooLarge { hosts, .. }) if hosts == all_hosts
        ));
        assert!(matches!(
            scan_targets(&["0.0.0.0/0".to_owned()]),
            Err(ScanError::NotLocal(_))
        ));
        // 1,022 hosts: just under the per-range limit.
        assert!(scan_targets(&["10.0.0.0/22".to_owned()]).is_ok());
    }

    /// The regression this guards: a scan range on the internet sent probes to
    /// every host in it.
    #[test]
    fn only_local_ranges_can_be_scanned() {
        for local in [
            "192.168.1.0/24",
            "10.20.0.0/24",
            "172.16.5.0/24",
            "169.254.1.0/24",
            "100.64.0.0/24",
        ] {
            assert!(scan_targets(&[local.to_owned()]).is_ok(), "{local}");
        }
        for remote in ["8.8.8.0/24", "172.32.0.0/24", "11.0.0.0/24"] {
            assert!(
                matches!(
                    scan_targets(&[remote.to_owned()]),
                    Err(ScanError::NotLocal(_))
                ),
                "{remote}"
            );
        }
    }

    #[test]
    fn host_count_matches_the_hosts_iterator() {
        for prefix in 20..=32_u8 {
            let network = Ipv4Net::new(Ipv4Addr::new(10, 0, 0, 0), prefix).expect("prefix");
            let counted = u64::try_from(network.hosts().count()).expect("fits");
            assert_eq!(host_count(network), counted, "/{prefix}");
        }
    }

    #[test]
    fn parses_cross_platform_interface_ranges() {
        let linux = "2: eth0    inet 192.168.50.12/24 brd 192.168.50.255 scope global eth0";
        assert_eq!(parse_interface_ranges(linux), ["192.168.50.0/24"]);
        assert_eq!(parse_interface_networks(linux)[0].adapter_id, "eth0");

        let macos = "en0: flags=8863<UP,BROADCAST> mtu 1500\n\
                     \tinet 10.0.0.12 netmask 0xffffff00 broadcast 10.0.0.255";
        assert_eq!(parse_interface_ranges(macos), ["10.0.0.0/24"]);
        assert_eq!(parse_interface_networks(macos)[0].adapter_id, "en0");

        let windows = "Wireless LAN adapter Wi-Fi:\n\n\
                       IPv4 Address. . . . . . . . . . . : 172.16.4.22(Preferred)\n\
                       Subnet Mask . . . . . . . . . . . : 255.255.252.0";
        assert_eq!(parse_interface_ranges(windows), ["172.16.4.0/22"]);
        assert_eq!(parse_interface_networks(windows)[0].adapter_id, "Wi-Fi");
    }

    /// The whole `/20` holds 4,094 hosts and would be refused, failing the default scan.
    #[test]
    fn an_adapter_on_a_large_network_gives_a_range_small_enough_to_scan() {
        let large = "2: eth0    inet 172.28.9.208/20 brd 172.28.15.255 scope global eth0";
        let ranges = parse_interface_ranges(large);
        assert_eq!(ranges, ["172.28.8.0/22"]);
        validate_scan_ranges(&ranges).expect("the adapter's own range can be scanned");
    }

    #[tokio::test]
    async fn cancelled_scan_stops_before_network_io() {
        let cancellation = CancellationToken::new();
        cancellation.cancel();
        let error = SystemNetworkScanner
            .scan(&["192.168.1.0/30".to_owned()], &cancellation)
            .await
            .expect_err("cancelled");
        assert!(matches!(error, ScanError::Cancelled));
    }
}
