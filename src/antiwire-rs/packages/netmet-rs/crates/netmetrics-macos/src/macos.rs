use crate::pktap;
use libc::{O_NONBLOCK, c_int, c_ulong, close, fcntl, ioctl, open, read};
use netmetrics_core::{
    DegradeReason, DnsTransactionTracker, FlowKey, InterfaceStats, LocalEndpoint, ProcessIdentity,
    ProcessInfo, Protocol, SocketCookie, SocketOwnerSnapshot,
};
use netmetrics_core::{unix_now_ms, unspecified_address};
use netmetrics_sys::{
    Backend, BackendConfig, BackendError, BackendErrorKind, BackendEvent, EventSink, StopFlag,
};
use std::collections::{HashMap, HashSet};
use std::env;
use std::ffi::{CStr, CString};
use std::io;
use std::mem;
use std::process::Command;
use std::ptr;
use std::time::{Duration, Instant};

const F_GETFL: c_int = 3;
const F_SETFL: c_int = 4;
const BIOCSETIF: c_ulong = 0x8020_426c;
const BIOCIMMEDIATE: c_ulong = 0x8004_4270;
const BIOCGBLEN: c_ulong = 0x4004_4266;
const BIOCGDLT: c_ulong = 0x4004_426a;
const FLOW_IDLE_MS: u64 = 300_000;
const SOCKET_GONE_GRACE_MS: u64 = 2_000;

#[repr(C)]
struct IfReq {
    name: [libc::c_char; 16],
    address: [u8; 16],
}

/// PKTAP reader using a non-blocking Berkeley Packet Filter device.
#[derive(Debug, Default)]
pub struct MacosBackend;

impl Backend for MacosBackend {
    fn name(&self) -> &'static str {
        "macos-pktap"
    }

    fn run(
        &mut self,
        config: &BackendConfig,
        sink: EventSink,
        stop: StopFlag,
    ) -> Result<(), BackendError> {
        let max_flows = sink.native_capacity();
        let Some(interface) = env::var_os("NETMETRICS_PKTAP_INTERFACE") else {
            sink.emit(BackendEvent::Degraded(DegradeReason::SnapshotOnly {
                source: "macos-socket-table".to_owned(),
            }));
            if config.dns_hints {
                sink.emit(BackendEvent::Degraded(DegradeReason::SourceUnavailable {
                    source: "macos-dns-hints".to_owned(),
                    detail: "DNS side-channel requires PKTAP packet capture".to_owned(),
                }));
            }
            run_socket_snapshot(config, &sink, &stop);
            return Ok(());
        };
        let interface = interface.to_string_lossy();
        if !crate::is_safe_interface_name(&interface) {
            return Err(BackendError::new(
                BackendErrorKind::Unavailable,
                "pktap-bpf",
                "NETMETRICS_PKTAP_INTERFACE must be 1-15 ASCII letters or digits, starting with a letter",
            ));
        }
        ensure_pktap_interface(&interface)?;
        let (device, buffer_len) = open_bpf(&interface)?;
        let result = read_bpf_loop(
            device,
            buffer_len,
            max_flows,
            config.dns_hints,
            &sink,
            &stop,
            Duration::from_millis(config.poll_interval_ms.max(250)),
        );
        // SAFETY: `device` is a valid descriptor returned by `open`.
        unsafe {
            close(device);
        }
        result
    }
}

fn ensure_pktap_interface(interface: &str) -> Result<(), BackendError> {
    let exists = Command::new("/sbin/ifconfig")
        .arg(interface)
        .status()
        .is_ok_and(|status| status.success());
    if !exists {
        let created = Command::new("/sbin/ifconfig")
            .args([interface, "create"])
            .status()
            .map_err(|error| {
                BackendError::new(
                    BackendErrorKind::Unavailable,
                    "pktap-ifconfig",
                    error.to_string(),
                )
            })?;
        if !created.success() {
            return Err(BackendError::new(
                BackendErrorKind::Unavailable,
                "pktap-ifconfig",
                format!("failed to create {interface}: {created}"),
            ));
        }
    }

    let enabled = Command::new("/sbin/ifconfig")
        .args([interface, "up"])
        .status()
        .map_err(|error| {
            BackendError::new(
                BackendErrorKind::Unavailable,
                "pktap-ifconfig",
                error.to_string(),
            )
        })?;
    if enabled.success() {
        Ok(())
    } else {
        Err(BackendError::new(
            BackendErrorKind::Unavailable,
            "pktap-ifconfig",
            format!("failed to enable {interface}: {enabled}"),
        ))
    }
}

fn open_bpf(interface: &str) -> Result<(c_int, usize), BackendError> {
    let mut descriptor = None;
    for index in 0..256 {
        let path = CString::new(format!("/dev/bpf{index}")).expect("static path has no NUL");
        // SAFETY: `path` is NUL terminated and flags request read-only capture.
        let fd = unsafe { open(path.as_ptr(), libc::O_RDONLY) };
        if fd >= 0 {
            descriptor = Some(fd);
            break;
        }
    }
    let fd = descriptor.ok_or_else(|| {
        BackendError::new(
            BackendErrorKind::PermissionDenied,
            "pktap-bpf",
            "no readable /dev/bpf device; root or packet-capture entitlement is required",
        )
    })?;
    let mut request = IfReq {
        name: [0; 16],
        address: [0; 16],
    };
    if !crate::is_safe_interface_name(interface) {
        // SAFETY: descriptor is owned by this function.
        unsafe {
            close(fd);
        }
        return Err(BackendError::new(
            BackendErrorKind::Unavailable,
            "pktap-bpf",
            "interface name must be 1-15 ASCII letters or digits, starting with a letter",
        ));
    }
    for (target, source) in request.name.iter_mut().zip(interface.bytes()) {
        *target = libc::c_char::try_from(source).expect("ASCII byte fits c_char");
    }
    // SAFETY: descriptor and pointers reference initialized values of the ioctl ABI types.
    let configured = unsafe { ioctl(fd, BIOCSETIF, &request) };
    let mut immediate: u32 = 1;
    // SAFETY: descriptor and pointer reference initialized ioctl ABI values.
    let immediate_result = unsafe { ioctl(fd, BIOCIMMEDIATE, &mut immediate) };
    let mut data_link_type = 0_u32;
    // SAFETY: descriptor and pointer reference initialized ioctl ABI values.
    let dlt_result = unsafe { ioctl(fd, BIOCGDLT, &raw mut data_link_type) };
    let mut buffer_len = 0_u32;
    // SAFETY: descriptor and pointer reference initialized ioctl ABI values.
    let buffer_len_result = unsafe { ioctl(fd, BIOCGBLEN, &raw mut buffer_len) };
    // SAFETY: `fd` is valid; retrieving and restoring flags does not alias memory.
    let flags = unsafe { fcntl(fd, F_GETFL) };
    // SAFETY: `fd` is valid and `flags` came from the preceding call.
    let nonblocking = unsafe { fcntl(fd, F_SETFL, flags | O_NONBLOCK) };
    if dlt_result >= 0
        && let Err(error) = crate::bpf_records::validate_data_link(data_link_type)
    {
        // SAFETY: descriptor is owned by this function.
        unsafe {
            close(fd);
        }
        return Err(BackendError::new(
            BackendErrorKind::Unavailable,
            "pktap-bpf",
            error.to_string(),
        ));
    }
    if configured < 0
        || immediate_result < 0
        || dlt_result < 0
        || buffer_len_result < 0
        || flags < 0
        || nonblocking < 0
    {
        let error = io::Error::last_os_error();
        // SAFETY: descriptor is owned by this function.
        unsafe {
            close(fd);
        }
        return Err(BackendError::new(
            if error.kind() == io::ErrorKind::PermissionDenied {
                BackendErrorKind::PermissionDenied
            } else {
                BackendErrorKind::Unavailable
            },
            "pktap-bpf",
            error.to_string(),
        ));
    }
    let buffer_len = usize::try_from(buffer_len).unwrap_or(0);
    if buffer_len == 0 {
        // SAFETY: descriptor is owned by this function.
        unsafe {
            close(fd);
        }
        return Err(BackendError::new(
            BackendErrorKind::Unavailable,
            "pktap-bpf",
            "BIOCGBLEN returned an empty read buffer",
        ));
    }
    Ok((fd, buffer_len))
}

fn read_bpf_loop(
    fd: c_int,
    buffer_len: usize,
    max_flows: usize,
    dns_hints: bool,
    sink: &EventSink,
    stop: &StopFlag,
    interface_interval: Duration,
) -> Result<(), BackendError> {
    let owners = netmetrics_sys::endpoint_owner::EndpointOwnerSource::default();
    let mut buffer = vec![0_u8; buffer_len];
    let mut flows = HashMap::<FlowKey, (u32, u64)>::new();
    let mut processes = HashMap::<u32, ProcessIdentity>::new();
    // PKTAP captures the DNS answers themselves; they become hints only when asked for.
    let mut dns_transactions = dns_hints.then(|| DnsTransactionTracker::new(max_flows));
    let mut next_interface_poll = Instant::now();
    let mut next_socket_poll = Instant::now();
    let mut reported_socket_error = false;
    while !stop.is_stop_requested() {
        if Instant::now() >= next_interface_poll {
            emit_interface_stats(sink, unix_now_ms());
            next_interface_poll = Instant::now() + interface_interval;
        }
        if Instant::now() >= next_socket_poll {
            match socket_coverage() {
                Ok(coverage) => {
                    close_missing_flows(&mut flows, sink, unix_now_ms(), &coverage);
                    sweep_processes(&mut processes, sink, unix_now_ms());
                    reported_socket_error = false;
                }
                Err(error) => {
                    expire_udp_flows(&mut flows, sink, unix_now_ms());
                    if !reported_socket_error {
                        reported_socket_error = true;
                        sink.emit(BackendEvent::Degraded(DegradeReason::SourceUnavailable {
                            source: "macos-socket-table".to_owned(),
                            detail: error.to_string(),
                        }));
                    }
                }
            }
            next_socket_poll = Instant::now() + interface_interval;
        }
        owners.processing();
        // SAFETY: buffer is writable for its full length and `fd` remains open.
        let count = unsafe { read(fd, buffer.as_mut_ptr().cast(), buffer.len()) };
        if count < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::WouldBlock {
                owners.drained();
                netmetrics_sys::wait_readable(
                    fd,
                    next_interface_poll.min(next_socket_poll),
                    MAX_READ_WAIT,
                );
                continue;
            }
            return Err(BackendError::new(
                BackendErrorKind::SessionLost,
                "pktap-bpf",
                error.to_string(),
            ));
        }
        if count == 0 {
            owners.drained();
            netmetrics_sys::wait_readable(
                fd,
                next_interface_poll.min(next_socket_poll),
                MAX_READ_WAIT,
            );
            continue;
        }
        parse_bpf_buffer(
            &buffer[..usize::try_from(count).unwrap_or(0)],
            &owners,
            sink,
            &mut flows,
            &mut processes,
            dns_transactions.as_mut(),
            max_flows,
        );
    }
    let timestamp = unix_now_ms();
    for (key, _) in flows {
        sink.emit(BackendEvent::Closed {
            key,
            pid: 0,
            timestamp,
        });
    }
    Ok(())
}

fn emit_interface_stats(sink: &EventSink, timestamp: u64) {
    match interface_stats(timestamp) {
        Ok(samples) => {
            for sample in samples {
                sink.emit(BackendEvent::Interface(sample));
            }
        }
        Err(error) => {
            sink.emit(BackendEvent::Degraded(DegradeReason::SourceUnavailable {
                source: "macos-getifaddrs".to_owned(),
                detail: error.to_string(),
            }));
        }
    }
}

fn interface_stats(timestamp: u64) -> io::Result<Vec<InterfaceStats>> {
    let mut head = ptr::null_mut::<libc::ifaddrs>();
    // SAFETY: `getifaddrs` initializes `head` on success.
    if unsafe { libc::getifaddrs(&raw mut head) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let mut samples = Vec::new();
    let mut current = head;
    while !current.is_null() {
        // SAFETY: every node is owned by the live `head` list.
        let address = unsafe { (*current).ifa_addr };
        // SAFETY: every node is owned by the live `head` list.
        let data = unsafe { (*current).ifa_data.cast::<libc::if_data>() };
        if !address.is_null()
            && !data.is_null()
            // SAFETY: non-null `address` points to a sockaddr owned by the list.
            && unsafe { i32::from((*address).sa_family) } == libc::AF_LINK
        {
            // SAFETY: name is a NUL-terminated C string owned by the list.
            let name = unsafe { CStr::from_ptr((*current).ifa_name) }
                .to_string_lossy()
                .into_owned();
            // SAFETY: AF_LINK entries expose an `if_data` value in `ifa_data`.
            let counters = unsafe { &*data };
            // SAFETY: name is still live and NUL terminated.
            let index = unsafe { libc::if_nametoindex((*current).ifa_name) };
            samples.push(InterfaceStats {
                index,
                name,
                rx_bytes: u64::from(counters.ifi_ibytes),
                tx_bytes: u64::from(counters.ifi_obytes),
                rx_errors: u64::from(counters.ifi_ierrors),
                tx_errors: u64::from(counters.ifi_oerrors),
                rx_drops: u64::from(counters.ifi_iqdrops),
                tx_drops: 0,
                timestamp,
            });
        }
        // SAFETY: `current` is a valid node in the list.
        current = unsafe { (*current).ifa_next };
    }
    // SAFETY: `head` came from getifaddrs and is freed exactly once.
    unsafe {
        libc::freeifaddrs(head);
    }
    Ok(samples)
}

/// Longest wait for packets before the loop checks its stop flag again.
const MAX_READ_WAIT: Duration = Duration::from_millis(250);

fn parse_bpf_buffer(
    buffer: &[u8],
    owners: &netmetrics_sys::endpoint_owner::EndpointOwnerSource,
    sink: &EventSink,
    flows: &mut HashMap<FlowKey, (u32, u64)>,
    processes: &mut HashMap<u32, ProcessIdentity>,
    mut dns_transactions: Option<&mut DnsTransactionTracker>,
    max_flows: usize,
) {
    for record in crate::bpf_records::records(buffer) {
        let Ok(record) = record else {
            break;
        };
        let timestamp = unix_now_ms();
        if let Some(packet) = pktap::decode(record.packet) {
            if let Some(event_at) = record
                .timestamp
                .and_then(netmetrics_sys::endpoint_owner::realtime_event_time)
            {
                owners.record(packet.key, packet.pid, event_at);
            }
            if packet.pid != 0 {
                if let Some(mut identity) = packet.process.clone() {
                    if let Some(start_ts) = process_start_ms(packet.pid) {
                        identity.start_ts = start_ts;
                        let changed = processes
                            .get(&packet.pid)
                            .is_none_or(|current| current != &identity);
                        if changed {
                            if !processes.contains_key(&packet.pid)
                                && processes.len() >= max_flows
                                && let Some(evicted) = processes
                                    .iter()
                                    .min_by_key(|(pid, identity)| (identity.start_ts, **pid))
                                    .map(|(pid, _)| *pid)
                            {
                                let identity = processes.remove(&evicted);
                                sink.emit(BackendEvent::ProcessStopped {
                                    pid: evicted,
                                    timestamp,
                                    identity,
                                });
                            }
                            if processes.contains_key(&packet.pid) {
                                sink.emit(BackendEvent::ProcessStopped {
                                    pid: packet.pid,
                                    timestamp,
                                    identity: processes.get(&packet.pid).cloned(),
                                });
                            }
                            processes.insert(packet.pid, identity.clone());
                            sink.emit(BackendEvent::ProcessStarted(ProcessInfo {
                                pid: packet.pid,
                                identity,
                            }));
                        }
                    }
                }
            }
            if !flows.contains_key(&packet.key)
                && flows.len() >= max_flows
                && let Some(evicted) = flows
                    .iter()
                    .min_by_key(|(key, (_, last_seen))| (*last_seen, **key))
                    .map(|(key, _)| *key)
            {
                flows.remove(&evicted);
                sink.emit(BackendEvent::Closed {
                    pid: 0,
                    key: evicted,
                    timestamp,
                });
            }
            if let std::collections::hash_map::Entry::Vacant(entry) = flows.entry(packet.key) {
                entry.insert((packet.pid, timestamp));
                // PKTAP exposes no socket token, so identity is derived from the tuple, owner
                // and first-observation time. A tuple that goes idle and reappears is given a
                // fresh cookie, which is the intended reading: it is a different socket.
                sink.emit(BackendEvent::Opened {
                    key: packet.key,
                    pid: packet.pid,
                    cookie: Some(SocketCookie::synthetic(packet.key, packet.pid, timestamp)),
                    timestamp,
                    if_index: interface_index(&packet.ifname),
                });
            } else if let Some(value) = flows.get_mut(&packet.key) {
                value.1 = timestamp;
            }
            sink.emit(BackendEvent::Bytes {
                key: packet.key,
                pid: packet.pid,
                delta: packet.delta,
                timestamp,
                if_index: interface_index(&packet.ifname),
                cookie: None,
            });
            if let (Some(dns), Some(transactions)) = (packet.dns, dns_transactions.as_deref_mut()) {
                if let Some(dns) = transactions
                    .observe(dns, packet.pid, timestamp)
                    .filter(|dns| dns.ttl_ms > 0)
                {
                    sink.emit(BackendEvent::DnsResolved {
                        pid: dns.pid,
                        query: dns.query,
                        answers: dns.answers,
                        ttl_ms: dns.ttl_ms,
                        timestamp,
                    });
                }
            }
        }
    }
}

fn sweep_processes(
    processes: &mut HashMap<u32, ProcessIdentity>,
    sink: &EventSink,
    timestamp: u64,
) {
    let stale: Vec<_> = processes
        .iter()
        .filter(|(pid, identity)| process_start_ms(**pid) != Some(identity.start_ts))
        .map(|(pid, _)| *pid)
        .collect();
    for pid in stale {
        let identity = processes.remove(&pid);
        sink.emit(BackendEvent::ProcessStopped {
            pid,
            timestamp,
            identity,
        });
    }
}

struct SocketCoverage {
    tcp: HashSet<FlowKey>,
    udp_binds: HashSet<(std::net::IpAddr, u16)>,
}

fn close_missing_flows(
    flows: &mut HashMap<FlowKey, (u32, u64)>,
    sink: &EventSink,
    timestamp: u64,
    coverage: &SocketCoverage,
) {
    let stale: Vec<_> = flows
        .iter()
        .filter(|(key, (_, last_seen))| {
            let age = timestamp.saturating_sub(*last_seen);
            match key.protocol {
                Protocol::Tcp => {
                    !coverage.tcp.contains(key)
                        && !coverage.tcp.contains(&key.reverse())
                        && age >= SOCKET_GONE_GRACE_MS
                }
                Protocol::Udp => {
                    let bound = coverage
                        .udp_binds
                        .contains(&(key.local_addr, key.local_port))
                        || coverage
                            .udp_binds
                            .contains(&(unspecified_address(key.local_addr), key.local_port));
                    (!bound && age >= SOCKET_GONE_GRACE_MS) || age >= FLOW_IDLE_MS
                }
            }
        })
        .map(|(key, _)| *key)
        .collect();
    for key in stale {
        flows.remove(&key);
        sink.emit(BackendEvent::Closed {
            key,
            pid: 0,
            timestamp,
        });
    }
}

fn expire_udp_flows(flows: &mut HashMap<FlowKey, (u32, u64)>, sink: &EventSink, timestamp: u64) {
    let stale: Vec<_> = flows
        .iter()
        .filter(|(key, (_, last_seen))| {
            key.protocol == Protocol::Udp && timestamp.saturating_sub(*last_seen) >= FLOW_IDLE_MS
        })
        .map(|(key, _)| *key)
        .collect();
    for key in stale {
        flows.remove(&key);
        sink.emit(BackendEvent::Closed {
            key,
            pid: 0,
            timestamp,
        });
    }
}

fn interface_index(name: &str) -> Option<u32> {
    if !crate::is_safe_interface_name(name) {
        return None;
    }
    netmetrics_sys::interface_index_by_name(name)
}

fn process_start_ms(pid: u32) -> Option<u64> {
    let pid = i32::try_from(pid).ok()?;
    let mut info = mem::MaybeUninit::<libc::proc_bsdinfo>::uninit();
    let size = c_int::try_from(mem::size_of::<libc::proc_bsdinfo>()).ok()?;
    // SAFETY: `info` points to a buffer of `size` bytes for the requested
    // PROC_PIDTBSDINFO structure. A full-size return initializes the buffer.
    let bytes = unsafe {
        libc::proc_pidinfo(
            pid,
            libc::PROC_PIDTBSDINFO,
            0,
            info.as_mut_ptr().cast(),
            size,
        )
    };
    if bytes != size {
        return None;
    }
    // SAFETY: proc_pidinfo returned the full size of `proc_bsdinfo`.
    let info = unsafe { info.assume_init() };
    Some(
        info.pbi_start_tvsec
            .saturating_mul(1_000)
            .saturating_add(info.pbi_start_tvusec / 1_000),
    )
}

fn run_socket_snapshot(config: &BackendConfig, sink: &EventSink, stop: &StopFlag) {
    let interval = Duration::from_millis(config.poll_interval_ms.max(250));
    let mut previous = HashMap::<FlowKey, u32>::new();
    let mut reported_error = false;
    while !stop.is_stop_requested() {
        let timestamp = unix_now_ms();
        let current = match socket_table_flows() {
            Ok(current) => current,
            Err(error) => {
                if !reported_error {
                    reported_error = true;
                    sink.emit(BackendEvent::Degraded(DegradeReason::SourceUnavailable {
                        source: "macos-socket-table".to_owned(),
                        detail: error.to_string(),
                    }));
                }
                stop.wait_timeout(interval);
                continue;
            }
        };
        reported_error = false;
        for (key, pid) in &current {
            if previous.get(key) != Some(pid) {
                sink.emit(BackendEvent::Opened {
                    key: *key,
                    pid: *pid,
                    cookie: Some(SocketCookie::synthetic(*key, *pid, timestamp)),
                    timestamp,
                    if_index: None,
                });
            }
        }
        for key in previous.keys() {
            if !current.contains_key(key) {
                sink.emit(BackendEvent::Closed {
                    pid: 0,
                    key: *key,
                    timestamp,
                });
            }
        }
        emit_interface_stats(sink, timestamp);
        previous = current;
        stop.wait_timeout(interval);
    }
}

fn socket_table_flows() -> io::Result<HashMap<FlowKey, u32>> {
    use netstat2::{
        AddressFamilyFlags, ProtocolFlags, ProtocolSocketInfo, TcpState, get_sockets_info,
    };

    let sockets = get_sockets_info(
        AddressFamilyFlags::IPV4 | AddressFamilyFlags::IPV6,
        ProtocolFlags::TCP | ProtocolFlags::UDP,
    )
    .map_err(io::Error::other)?;
    let mut flows = HashMap::new();
    for socket in sockets {
        let [pid] = socket.associated_pids.as_slice() else {
            continue;
        };
        if *pid == 0 {
            continue;
        }
        match socket.protocol_socket_info {
            ProtocolSocketInfo::Tcp(tcp)
                if tcp.state != TcpState::Listen
                    && tcp.state != TcpState::TimeWait
                    && tcp.local_port != 0
                    && tcp.remote_port != 0 =>
            {
                flows.insert(
                    FlowKey {
                        protocol: Protocol::Tcp,
                        local_addr: tcp.local_addr,
                        local_port: tcp.local_port,
                        remote_addr: tcp.remote_addr,
                        remote_port: tcp.remote_port,
                    },
                    *pid,
                );
            }
            _ => {}
        }
    }
    Ok(flows)
}

fn socket_coverage() -> io::Result<SocketCoverage> {
    use netstat2::{AddressFamilyFlags, ProtocolFlags, ProtocolSocketInfo, get_sockets_info};

    let sockets = get_sockets_info(
        AddressFamilyFlags::IPV4 | AddressFamilyFlags::IPV6,
        ProtocolFlags::TCP | ProtocolFlags::UDP,
    )
    .map_err(io::Error::other)?;
    let mut tcp = HashSet::new();
    let mut udp_binds = HashSet::new();
    for socket in sockets {
        match socket.protocol_socket_info {
            ProtocolSocketInfo::Tcp(tcp_socket)
                if tcp_socket.state != netstat2::TcpState::Listen
                    && tcp_socket.local_port != 0
                    && tcp_socket.remote_port != 0 =>
            {
                tcp.insert(FlowKey {
                    protocol: Protocol::Tcp,
                    local_addr: tcp_socket.local_addr,
                    local_port: tcp_socket.local_port,
                    remote_addr: tcp_socket.remote_addr,
                    remote_port: tcp_socket.remote_port,
                });
            }
            ProtocolSocketInfo::Udp(udp) if udp.local_port != 0 => {
                udp_binds.insert((udp.local_addr, udp.local_port));
            }
            _ => {}
        }
    }
    Ok(SocketCoverage { tcp, udp_binds })
}

const _: () = assert!(mem::size_of::<IfReq>() == 32);

/// Returns the number of non-listen TCP sockets visible to the host.
///
/// # Errors
///
/// Returns the reason when the socket table cannot be read; that is no count, not zero.
pub fn active_socket_count() -> Result<u32, String> {
    tcp_snapshot_len().map(|count| u32::try_from(count).unwrap_or(u32::MAX))
}

fn tcp_snapshot_len() -> Result<usize, String> {
    use netstat2::{
        AddressFamilyFlags, ProtocolFlags, ProtocolSocketInfo, TcpState, get_sockets_info,
    };

    let sockets = get_sockets_info(
        AddressFamilyFlags::IPV4 | AddressFamilyFlags::IPV6,
        ProtocolFlags::TCP,
    )
    .map_err(|error| error.to_string())?;
    let count = sockets
        .into_iter()
        .filter(|socket| {
            let ProtocolSocketInfo::Tcp(tcp) = &socket.protocol_socket_info else {
                return false;
            };
            tcp.state != TcpState::Listen && tcp.local_port != 0 && tcp.remote_port != 0
        })
        .count();
    Ok(count)
}

/// TCP 5-tuple and UDP bind owners from the host socket table.
#[must_use]
pub fn socket_owner_snapshot() -> SocketOwnerSnapshot {
    use netstat2::{
        AddressFamilyFlags, ProtocolFlags, ProtocolSocketInfo, TcpState, get_sockets_info,
    };

    let Ok(sockets) = get_sockets_info(
        AddressFamilyFlags::IPV4 | AddressFamilyFlags::IPV6,
        ProtocolFlags::TCP | ProtocolFlags::UDP,
    ) else {
        return SocketOwnerSnapshot::default();
    };
    let mut snapshot = SocketOwnerSnapshot::default();
    for socket in sockets {
        let [pid] = socket.associated_pids.as_slice() else {
            continue;
        };
        match socket.protocol_socket_info {
            ProtocolSocketInfo::Tcp(tcp)
                if tcp.state != TcpState::Listen && tcp.local_port != 0 && tcp.remote_port != 0 =>
            {
                snapshot.insert_tcp(
                    FlowKey {
                        protocol: Protocol::Tcp,
                        local_addr: tcp.local_addr,
                        local_port: tcp.local_port,
                        remote_addr: tcp.remote_addr,
                        remote_port: tcp.remote_port,
                    },
                    *pid,
                );
            }
            ProtocolSocketInfo::Udp(udp) if udp.local_port != 0 => {
                snapshot.insert_udp(
                    LocalEndpoint {
                        address: udp.local_addr,
                        port: udp.local_port,
                    },
                    *pid,
                );
            }
            _ => {}
        }
    }
    snapshot
}
