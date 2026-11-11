use netmetrics_core::unix_now_ms;
use netmetrics_core::unspecified_address;
use netmetrics_core::{
    DnsTransactionTracker, FlowKey, Protocol, SocketOwnerSnapshot, parse_dns_packet,
};
use netmetrics_sys::{BackendEvent, EventSink};
use std::io;
use std::net::IpAddr;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

const ETH_P_IP: u16 = 0x0800;
const ETH_P_IPV6: u16 = 0x86dd;
const REFRESH: Duration = Duration::from_millis(250);
const MISS_REFRESH: Duration = Duration::from_millis(10);

/// Captures UDP/53 on a packet socket and emits [`BackendEvent::DnsResolved`].
pub(super) fn spawn(
    sink: EventSink,
    stop: Arc<AtomicBool>,
    max_flows: usize,
    filter_object: Option<&Path>,
) -> io::Result<JoinHandle<()>> {
    let filter_object = filter_object.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            "NETMETRICS_DNS_FILTER_OBJECT does not name a compiled eBPF socket filter",
        )
    })?;
    let v4 = open_packet_socket(ETH_P_IP)?;
    let v6 = open_packet_socket(ETH_P_IPV6).ok();
    let filter = load_dns_filter(filter_object, &v4, v6.as_ref())?;
    thread::Builder::new()
        .name("netmetrics-linux-dns".to_owned())
        .spawn(move || {
            let _filter = filter;
            run(&v4, v6.as_ref(), &sink, &stop, max_flows);
        })
}

fn run(v4: &OwnedFd, v6: Option<&OwnedFd>, sink: &EventSink, stop: &AtomicBool, max_flows: usize) {
    let mut buffer = vec![0_u8; 2048];
    let mut owners = DnsOwners::new();
    let mut transactions = DnsTransactionTracker::new(max_flows);
    while !stop.load(Ordering::Acquire) {
        let mut fds = [
            libc::pollfd {
                fd: v4.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: v6.map_or(-1, AsRawFd::as_raw_fd),
                events: if v6.is_some() { libc::POLLIN } else { 0 },
                revents: 0,
            },
        ];
        let count = if v6.is_some() { 2 } else { 1 };
        // SAFETY: `fds` is a valid pollfd array of `count` entries.
        let ready = unsafe { libc::poll(fds.as_mut_ptr(), count, 250) };
        if ready <= 0 {
            continue;
        }
        if fds[0].revents & libc::POLLIN != 0 {
            recv_and_emit(
                v4.as_raw_fd(),
                &mut buffer,
                sink,
                &mut owners,
                &mut transactions,
            );
        }
        if let Some(fd) = v6
            && fds[1].revents & libc::POLLIN != 0
        {
            recv_and_emit(
                fd.as_raw_fd(),
                &mut buffer,
                sink,
                &mut owners,
                &mut transactions,
            );
        }
    }
}

fn recv_and_emit(
    fd: RawFd,
    buffer: &mut [u8],
    sink: &EventSink,
    owners: &mut DnsOwners,
    transactions: &mut DnsTransactionTracker,
) {
    // SAFETY: `buffer` is writable for its length and `fd` is a live packet socket.
    let count = unsafe { libc::recv(fd, buffer.as_mut_ptr().cast(), buffer.len(), 0) };
    if count <= 0 {
        return;
    }
    let packet = &buffer[..usize::try_from(count).unwrap_or(0)];
    let Some(datagram) = parse_dns_packet(packet) else {
        return;
    };
    let query_pid = if datagram.is_response {
        0
    } else {
        owners.pid(datagram.source_addr, datagram.source_port)
    };
    let Some(response) = transactions.observe(datagram, query_pid, unix_now_ms()) else {
        return;
    };
    if response.ttl_ms == 0 {
        return;
    }
    sink.emit(BackendEvent::DnsResolved {
        pid: response.pid,
        query: response.query,
        answers: response.answers,
        ttl_ms: response.ttl_ms,
        timestamp: unix_now_ms(),
    });
}

/// Socket owners for attributing captured queries, rescanned only when a query needs them.
///
/// A scan walks every process's file descriptors, so it runs on demand rather than on a
/// timer: a snapshot older than [`REFRESH`] is rescanned before use, so a port reused by
/// another process is not attributed to the old owner, and a miss rescans after
/// [`MISS_REFRESH`] to find a socket opened since. With no DNS traffic there are no scans.
struct DnsOwners {
    snapshot: SocketOwnerSnapshot,
    refreshed: Option<Instant>,
}

impl DnsOwners {
    fn new() -> Self {
        Self {
            snapshot: SocketOwnerSnapshot::default(),
            refreshed: None,
        }
    }

    fn older_than(&self, age: Duration) -> bool {
        self.refreshed
            .is_none_or(|refreshed| refreshed.elapsed() >= age)
    }

    fn refresh(&mut self) {
        self.snapshot = super::socket_owner_snapshot();
        self.refreshed = Some(Instant::now());
    }

    fn pid(&mut self, address: IpAddr, port: u16) -> u32 {
        if self.older_than(REFRESH) {
            self.refresh();
        }
        if let Some(pid) = self.lookup(address, port) {
            return pid;
        }
        if self.older_than(MISS_REFRESH) {
            self.refresh();
            if let Some(pid) = self.lookup(address, port) {
                return pid;
            }
        }
        0
    }

    fn lookup(&self, address: IpAddr, port: u16) -> Option<u32> {
        let unspecified = unspecified_address(address);
        self.snapshot.lookup_owner_pid(&FlowKey {
            protocol: Protocol::Udp,
            local_addr: address,
            local_port: port,
            remote_addr: unspecified,
            remote_port: 0,
        })
    }
}

fn open_packet_socket(protocol: u16) -> io::Result<OwnedFd> {
    // SAFETY: socket(2) with AF_PACKET has no pointer arguments.
    let fd = unsafe {
        libc::socket(
            libc::AF_PACKET,
            libc::SOCK_DGRAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
            i32::from(protocol.to_be()),
        )
    };
    if fd < 0 {
        Err(io::Error::last_os_error())
    } else {
        // SAFETY: the successful `socket` call returned a new owned descriptor.
        Ok(unsafe { OwnedFd::from_raw_fd(fd) })
    }
}

#[cfg(feature = "ebpf")]
fn load_dns_filter(path: &Path, v4: &OwnedFd, v6: Option<&OwnedFd>) -> io::Result<aya::Ebpf> {
    use aya::programs::SocketFilter;
    let mut bpf = aya::Ebpf::load_file(path).map_err(io::Error::other)?;
    let program: &mut SocketFilter = bpf
        .program_mut("dns_packet_filter")
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing dns_packet_filter"))?
        .try_into()
        .map_err(io::Error::other)?;
    program.load().map_err(io::Error::other)?;
    program.attach(v4).map_err(io::Error::other)?;
    if let Some(v6) = v6 {
        program.attach(v6).map_err(io::Error::other)?;
    }
    Ok(bpf)
}

#[cfg(not(feature = "ebpf"))]
fn load_dns_filter(_path: &Path, _v4: &OwnedFd, _v6: Option<&OwnedFd>) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "crate built without the ebpf feature required for DNS kernel filtering",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, UdpSocket};

    #[test]
    fn owners_are_scanned_on_demand_and_reused_while_fresh() {
        let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind");
        let port = socket.local_addr().expect("addr").port();
        let mut owners = DnsOwners::new();
        assert!(
            owners.refreshed.is_none(),
            "nothing is scanned before a query needs it"
        );

        assert_eq!(
            owners.pid(IpAddr::V4(Ipv4Addr::LOCALHOST), port),
            std::process::id()
        );
        let scanned = owners.refreshed.expect("the lookup scanned");

        assert_eq!(
            owners.pid(IpAddr::V4(Ipv4Addr::LOCALHOST), port),
            std::process::id()
        );
        assert_eq!(
            owners.refreshed,
            Some(scanned),
            "a fresh snapshot is reused"
        );
    }
}
