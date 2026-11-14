use netmetrics_core::unix_now_ms;
use netmetrics_core::unspecified_address;
use netmetrics_core::{DnsCallerIdentity, DnsPacket, FlowKey, Protocol, SocketOwnerSnapshot};
use netmetrics_sys::{DnsCapture, EventSink};
use std::io;
use std::mem;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

/// `ETH_P_ALL` from `linux/if_ether.h`. packet(7): a socket opened with it receives every
/// protocol, and it is the only kind handed the packets this host sends: the kernel offers
/// those only to the taps registered for all protocols (`dev_queue_xmit_nit` in
/// `net/core/dev.c`). A socket for one protocol sees a query arrive but never leave.
const ETH_P_ALL: u16 = 0x0003;
const REFRESH: Duration = Duration::from_millis(250);
const MISS_REFRESH: Duration = Duration::from_millis(10);
/// Room for the largest packet an interface hands over: the MTU of loopback is 65,536. A
/// packet cut short by a smaller buffer is not parsed at all.
const PACKET_BUFFER_LEN: usize = 65_536;

/// Captures port 53, over UDP and TCP and in both directions, on a packet socket and
/// emits what [`DnsCapture`] makes of it. The socket filter drops everything else in the
/// kernel.
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
    let socket = open_packet_socket()?;
    let filter = load_dns_filter(filter_object, &socket)?;
    thread::Builder::new()
        .name("netmetrics-linux-dns".to_owned())
        .spawn(move || {
            let _filter = filter;
            run(&socket, &sink, &stop, max_flows);
        })
}

fn run(socket: &OwnedFd, sink: &EventSink, stop: &AtomicBool, max_flows: usize) {
    let mut buffer = vec![0_u8; PACKET_BUFFER_LEN];
    let mut owners = DnsOwners::new();
    let mut capture = DnsCapture::new(max_flows);
    while !stop.load(Ordering::Acquire) {
        let mut ready = libc::pollfd {
            fd: socket.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: `ready` is one valid pollfd for the duration of the call.
        let count = unsafe { libc::poll(&raw mut ready, 1, 250) };
        if count > 0 && ready.revents & libc::POLLIN != 0 {
            recv_and_emit(
                socket.as_raw_fd(),
                &mut buffer,
                sink,
                &mut owners,
                &mut capture,
            );
        }
    }
}

fn recv_and_emit(
    fd: RawFd,
    buffer: &mut [u8],
    sink: &EventSink,
    owners: &mut DnsOwners,
    capture: &mut DnsCapture,
) {
    // SAFETY: all-zero is a valid `sockaddr_ll`, a struct of integers and a byte array.
    let mut link: libc::sockaddr_ll = unsafe { mem::zeroed() };
    let mut link_len = libc::socklen_t::try_from(mem::size_of::<libc::sockaddr_ll>())
        .expect("sockaddr_ll fits socklen_t");
    // SAFETY: `buffer` is writable for its length, `link` for `link_len` bytes, and `fd` is
    // a live packet socket. recvfrom(2) writes at most those lengths and sets `link_len`.
    let count = unsafe {
        libc::recvfrom(
            fd,
            buffer.as_mut_ptr().cast(),
            buffer.len(),
            0,
            (&raw mut link).cast(),
            &raw mut link_len,
        )
    };
    let Ok(count) = usize::try_from(count) else {
        return;
    };
    let Some(packet) = buffer.get(..count).filter(|packet| !packet.is_empty()) else {
        return;
    };
    // packet(7): a packet socket fills a whole `sockaddr_ll`, and `sll_pkttype` is
    // `PACKET_OUTGOING` for a packet this host sent. Only those name their sender through
    // a local socket: a query from another host can share a port number with one, and on
    // loopback the same query is seen a second time, arriving, as `PACKET_HOST`.
    let sent_here = usize::try_from(link_len)
        .is_ok_and(|length| length >= mem::size_of::<libc::sockaddr_ll>())
        && link.sll_pkttype == libc::PACKET_OUTGOING;
    capture.observe(packet, unix_now_ms(), sink, |query| DnsCallerIdentity {
        requesting_pid: sent_here
            .then(|| owners.pid(&sender_socket(query)))
            .filter(|pid| *pid != 0),
        ..DnsCallerIdentity::default()
    });
}

/// The local socket that sent `query`, as the socket table keys it: a TCP socket by its
/// whole connection, a UDP one by its bind, whatever it sends to.
fn sender_socket(query: &DnsPacket) -> FlowKey {
    let (remote_addr, remote_port) = match query.protocol {
        Protocol::Tcp => (query.destination_addr, query.destination_port),
        Protocol::Udp => (unspecified_address(query.source_addr), 0),
    };
    FlowKey {
        protocol: query.protocol,
        local_addr: query.source_addr,
        local_port: query.source_port,
        remote_addr,
        remote_port,
    }
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

    /// The owner of `socket`, or zero when no process is found owning it.
    fn pid(&mut self, socket: &FlowKey) -> u32 {
        if self.older_than(REFRESH) {
            self.refresh();
        }
        if let Some(pid) = self.snapshot.lookup_owner_pid(socket) {
            return pid;
        }
        if self.older_than(MISS_REFRESH) {
            self.refresh();
            if let Some(pid) = self.snapshot.lookup_owner_pid(socket) {
                return pid;
            }
        }
        0
    }
}

/// Opens a packet socket for every protocol, in both directions. `SOCK_DGRAM` hands over
/// each packet from its network header, whichever way it travels.
fn open_packet_socket() -> io::Result<OwnedFd> {
    // SAFETY: socket(2) with AF_PACKET has no pointer arguments.
    let fd = unsafe {
        libc::socket(
            libc::AF_PACKET,
            libc::SOCK_DGRAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
            i32::from(ETH_P_ALL.to_be()),
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
fn load_dns_filter(path: &Path, socket: &OwnedFd) -> io::Result<aya::Ebpf> {
    use aya::programs::SocketFilter;
    let mut bpf = aya::Ebpf::load_file(path).map_err(io::Error::other)?;
    let program: &mut SocketFilter = bpf
        .program_mut("dns_packet_filter")
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing dns_packet_filter"))?
        .try_into()
        .map_err(io::Error::other)?;
    program.load().map_err(io::Error::other)?;
    program.attach(socket).map_err(io::Error::other)?;
    Ok(bpf)
}

#[cfg(not(feature = "ebpf"))]
fn load_dns_filter(_path: &Path, _socket: &OwnedFd) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "crate built without the ebpf feature required for DNS kernel filtering",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream, UdpSocket};

    /// A query for `example.test` from `source` to `destination`.
    fn query(protocol: Protocol, source: SocketAddr, destination: SocketAddr) -> DnsPacket {
        DnsPacket {
            protocol,
            source_addr: source.ip(),
            source_port: source.port(),
            destination_addr: destination.ip(),
            destination_port: destination.port(),
            id: 1,
            is_response: false,
            opcode: 0,
            rcode: 0,
            question: "example.test".to_owned(),
            qtype: 1,
            qclass: 1,
            answers: Vec::new(),
            ttl_ms: 0,
        }
    }

    #[test]
    fn owners_are_scanned_on_demand_and_reused_while_fresh() {
        let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind");
        let sender = sender_socket(&query(
            Protocol::Udp,
            socket.local_addr().expect("addr"),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 53)), 53),
        ));
        let mut owners = DnsOwners::new();
        assert!(
            owners.refreshed.is_none(),
            "nothing is scanned before a query needs it"
        );

        assert_eq!(owners.pid(&sender), std::process::id());
        let scanned = owners.refreshed.expect("the lookup scanned");

        assert_eq!(owners.pid(&sender), std::process::id());
        assert_eq!(
            owners.refreshed,
            Some(scanned),
            "a fresh snapshot is reused"
        );
    }

    #[test]
    fn a_tcp_query_is_owned_by_the_process_holding_its_connection() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("listen");
        let server = listener.local_addr().expect("server address");
        let client = TcpStream::connect(server).expect("connect");
        let sender = sender_socket(&query(
            Protocol::Tcp,
            client.local_addr().expect("client address"),
            server,
        ));
        assert_eq!(DnsOwners::new().pid(&sender), std::process::id());
    }
}
