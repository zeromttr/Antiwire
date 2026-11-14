use netmetrics_core::{ByteDelta, FlowKey, Protocol, locate_transport};
use std::borrow::Cow;
use std::net::IpAddr;

const PKTAP_MIN_HEADER: usize = 108;
/// Offset of `pth_flowid` in `struct pktap_header` (XNU's `bsd/net/pktap.h`), the first
/// field after those every header has.
const PTH_FLOWID_OFFSET: usize = 108;
const DLT_NULL: u32 = 0;
const DLT_EN10MB: u32 = 1;
const DLT_RAW: u32 = 12;
const PTH_FLAG_DIR_IN: u32 = 1;
const PTH_FLAG_DIR_OUT: u32 = 2;

/// `PKTP_CMD_FILTER_SET` in XNU's `bsd/net/pktap.h`.
#[cfg(target_os = "macos")]
pub(crate) const PKTP_CMD_FILTER_SET: libc::c_ulong = 3;
/// `PKTAP_MAX_FILTERS`: the driver takes exactly this many entries.
const PKTAP_MAX_FILTERS: usize = 8;
/// `sizeof(struct pktap_filter)`: two `uint32_t` and a union of a `uint32_t` interface type
/// and a `char[IF_NAMESIZE + 8]` interface name.
const PKTAP_FILTER_LEN: usize = 4 + 4 + 16 + 8;
const PKTAP_FILTER_OP_PASS: u32 = 1;
const PKTAP_FILTER_PARAM_IF_TYPE: u32 = 1;
/// The interface types a pktap interface passes, from `bsd/net/if_types.h`: macOS's own
/// default for a new pktap (`pktap_clone_create`: `IFT_ETHER`, `IFT_IEEE1394`, `IFT_OTHER`)
/// plus `IFT_LOOP`. The default leaves loopback out, so a process talking to a local
/// resolver over lo0 would never be seen owning its endpoint.
const PASSED_INTERFACE_TYPES: [u32; 4] = [0x06, 0x90, 0x01, 0x18];

/// The `PKTP_CMD_FILTER_SET` argument: `PKTAP_MAX_FILTERS` `struct pktap_filter` entries,
/// each passing one of [`PASSED_INTERFACE_TYPES`], and the rest `PKTAP_FILTER_OP_NONE` (all
/// zero), which the driver requires after every active entry.
pub(crate) fn filters() -> [u8; PKTAP_MAX_FILTERS * PKTAP_FILTER_LEN] {
    let mut filters = [0; PKTAP_MAX_FILTERS * PKTAP_FILTER_LEN];
    let (entries, _) = filters.as_chunks_mut::<PKTAP_FILTER_LEN>();
    for (entry, interface_type) in entries.iter_mut().zip(PASSED_INTERFACE_TYPES) {
        entry[0..4].copy_from_slice(&PKTAP_FILTER_OP_PASS.to_ne_bytes());
        entry[4..8].copy_from_slice(&PKTAP_FILTER_PARAM_IF_TYPE.to_ne_bytes());
        entry[8..12].copy_from_slice(&interface_type.to_ne_bytes());
    }
    filters
}

/// The control bits of a TCP segment (RFC 9293, section 3.1), for what they say about
/// the connection of the host that sent it.
///
/// A TCP sends each bit only in certain states. XNU's table of them is `tcp_outflags` in
/// `bsd/netinet/tcp_fsm.h`: SYN only from `SYN_SENT` and `SYN_RECEIVED`, FIN only from
/// `FIN_WAIT_1`, `CLOSING` and `LAST_ACK`, and RST from `CLOSED`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct TcpFlags(u8);

impl TcpFlags {
    const FIN: u8 = 0x01;
    const SYN: u8 = 0x02;
    const RST: u8 = 0x04;
    const ACK: u8 = 0x10;
    /// Where the control bits are in a TCP header.
    const HEADER_OFFSET: usize = 13;

    /// The control bits from the byte of the TCP header that holds them.
    pub(crate) const fn new(bits: u8) -> Self {
        Self(bits)
    }

    /// Whether the segment is the first of a connection its sender begins: a SYN that
    /// acknowledges nothing, which only a host in `SYN_SENT` sends. A SYN that acknowledges
    /// is the answer to one, and may be sent again.
    pub(crate) const fn begins_connection(self) -> bool {
        self.0 & Self::SYN != 0 && self.0 & Self::ACK == 0
    }

    /// Whether the sender has finished sending.
    pub(crate) const fn fin(self) -> bool {
        self.0 & Self::FIN != 0
    }

    /// Whether the segment belongs to a connection whose handshake is over: it
    /// acknowledges, and neither sets a connection up nor resets one. The third segment of
    /// a handshake is the first such segment, and the connection is established at the end
    /// that sends it and, when it arrives, at the other (RFC 9293, section 3.5).
    pub(crate) const fn past_handshake(self) -> bool {
        self.0 & Self::ACK != 0 && self.0 & (Self::SYN | Self::RST) == 0
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PktapPacket<'a> {
    pub key: FlowKey,
    /// The process the packet is attributed to: the one its socket acts for when the
    /// socket is delegated, otherwise the socket's own.
    pub pid: u32,
    /// The process whose socket carried the packet, when it did so on behalf of `pid`.
    /// mDNSResponder sends every lookup this way, for the application that asked.
    pub acting_pid: Option<u32>,
    /// The name of `pid`'s process (`comm`), empty when the header names none. It is all
    /// the header says about the process: `macos.rs` reads the rest while it still runs.
    /// Borrowed from the frame, as `ifname` is, so decoding a packet allocates nothing.
    pub command: Cow<'a, str>,
    /// The kernel's ID for the socket the packet belongs to, when the header carries one.
    /// `pktap_fill_proc_info` writes it for packets a socket sends, from the socket's
    /// `inp_flowhash`: a random number allocated per socket, unique among open sockets
    /// (`inp_calc_flowhash` in `bsd/netinet/in_pcb.c`).
    pub flow_id: Option<u32>,
    pub delta: ByteDelta,
    /// Whether this host sent the packet.
    pub outbound: bool,
    /// The control bits of a TCP segment. A UDP datagram has none.
    pub tcp_flags: Option<TcpFlags>,
    pub ifname: Cow<'a, str>,
    /// The packet from its IP header, when it is to or from port 53.
    pub dns: Option<&'a [u8]>,
}

pub(crate) fn decode(frame: &[u8]) -> Option<PktapPacket<'_>> {
    if frame.len() < PKTAP_MIN_HEADER {
        return None;
    }
    let header_len = read_u32(frame, 0)? as usize;
    let dlt = read_u32(frame, 8)?;
    let ifname = c_string(&frame[12..36]);
    let flags = read_u32(frame, 36)?;
    let pre_len = read_u32(frame, 44)? as usize;
    let post_len = read_u32(frame, 48)? as usize;
    let pid = read_i32(frame, 52)?;
    let command = c_string(&frame[56..76]);
    let effective_pid = read_i32(frame, 84)?;
    let effective_command = c_string(&frame[88..108]);
    if header_len < PKTAP_MIN_HEADER
        || header_len.checked_add(pre_len)?.checked_add(post_len)? > frame.len()
    {
        return None;
    }
    let packet_end = frame.len().checked_sub(post_len)?;
    // The link-layer frame `pth_dlt` names starts right after the header, its link header
    // included: `pth_frame_pre_length` is only that header's length. XNU's `pktap_bpf_tap`
    // hands BPF the frame from its start and, for lo0, stashes the 4-byte protocol word
    // there and counts it in the pre-length; tcpdump's print-pktap.c passes the bytes after
    // `pth_length` straight to the link-type printer.
    let packet = &frame[header_len..packet_end];
    let inbound = match (flags & PTH_FLAG_DIR_IN != 0, flags & PTH_FLAG_DIR_OUT != 0) {
        (true, false) => true,
        (false, true) => false,
        _ => return None,
    };
    let decoded = decode_ip_packet(packet, dlt)?;
    let (local_addr, local_port, remote_addr, remote_port) = if inbound {
        (
            decoded.destination,
            decoded.destination_port,
            decoded.source,
            decoded.source_port,
        )
    } else {
        (
            decoded.source,
            decoded.source_port,
            decoded.destination,
            decoded.destination_port,
        )
    };
    // `pktap_fill_proc_info` in XNU's `bsd/net/pktap.c` writes -1 for a PID it does not
    // know, and fills `pth_epid` only for a delegated socket (`PTH_FLAG_PROC_DELEGATED`).
    let socket_pid = u32::try_from(pid).ok().filter(|pid| *pid != 0);
    let delegate_pid = u32::try_from(effective_pid).ok().filter(|pid| *pid != 0);
    let (pid, name, acting_pid) = match (delegate_pid, socket_pid) {
        (Some(delegate), socket) => (
            delegate,
            effective_command,
            socket.filter(|socket| *socket != delegate),
        ),
        (None, Some(socket)) => (socket, command, None),
        (None, None) => (0, Cow::Borrowed(""), None),
    };
    let flow_id = (header_len >= PTH_FLOWID_OFFSET + 4)
        .then(|| read_u32(frame, PTH_FLOWID_OFFSET))
        .flatten()
        .filter(|flow_id| *flow_id != 0);
    let dns = decoded.dns;
    let bytes = u64::try_from(decoded.ip_len).unwrap_or(u64::MAX);
    Some(PktapPacket {
        key: FlowKey {
            protocol: decoded.protocol,
            local_addr,
            local_port,
            remote_addr,
            remote_port,
        },
        pid,
        acting_pid,
        command: name,
        flow_id,
        outbound: !inbound,
        tcp_flags: decoded.tcp_flags,
        delta: if inbound {
            ByteDelta {
                sent: 0,
                received: bytes,
            }
        } else {
            ByteDelta {
                sent: bytes,
                received: 0,
            }
        },
        ifname,
        dns,
    })
}

struct DecodedIp<'a> {
    protocol: Protocol,
    source: IpAddr,
    source_port: u16,
    destination: IpAddr,
    destination_port: u16,
    /// The control bits of a TCP segment.
    tcp_flags: Option<TcpFlags>,
    ip_len: usize,
    dns: Option<&'a [u8]>,
}

fn decode_ip_packet(packet: &[u8], dlt: u32) -> Option<DecodedIp<'_>> {
    let ip = match dlt {
        DLT_RAW => packet,
        DLT_NULL => packet.get(4..)?,
        DLT_EN10MB => {
            if packet.len() < 14 {
                return None;
            }
            let mut ether_type = u16::from_be_bytes(packet[12..14].try_into().ok()?);
            let mut offset = 14;
            if matches!(ether_type, 0x8100 | 0x88a8) {
                ether_type = u16::from_be_bytes(packet.get(16..18)?.try_into().ok()?);
                offset = 18;
            }
            if !matches!(ether_type, 0x0800 | 0x86dd) {
                return None;
            }
            packet.get(offset..)?
        }
        _ => return None,
    };
    let transport = locate_transport(ip)?;
    let protocol = parse_protocol(transport.protocol)?;
    let source_port = u16::from_be_bytes(
        ip.get(transport.offset..transport.offset + 2)?
            .try_into()
            .ok()?,
    );
    let destination_port = u16::from_be_bytes(
        ip.get(transport.offset + 2..transport.offset + 4)?
            .try_into()
            .ok()?,
    );
    // A TCP segment too short to hold its control bits is no segment.
    let tcp_flags = match protocol {
        Protocol::Tcp => Some(TcpFlags::new(
            *ip.get(..transport.total_len)?
                .get(transport.offset + TcpFlags::HEADER_OFFSET)?,
        )),
        Protocol::Udp => None,
    };
    let dns = (source_port == 53 || destination_port == 53).then_some(ip);
    Some(DecodedIp {
        protocol,
        source: transport.source,
        source_port,
        destination: transport.destination,
        destination_port,
        tcp_flags,
        ip_len: transport.total_len,
        dns,
    })
}

fn parse_protocol(protocol: u8) -> Option<Protocol> {
    match protocol {
        6 => Some(Protocol::Tcp),
        17 => Some(Protocol::Udp),
        _ => None,
    }
}

fn read_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_ne_bytes(
        bytes.get(offset..offset + 4)?.try_into().ok()?,
    ))
}

fn read_i32(bytes: &[u8], offset: usize) -> Option<i32> {
    Some(i32::from_ne_bytes(
        bytes.get(offset..offset + 4)?.try_into().ok()?,
    ))
}

/// The text of a NUL-terminated field, borrowed unless it is not UTF-8.
fn c_string(bytes: &[u8]) -> Cow<'_, str> {
    let end = bytes
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end])
}

#[cfg(test)]
mod tests {
    use super::*;
    use netmetrics_core::test_support::{ipv4_tcp, ipv4_udp, mutate};
    use proptest::prelude::*;
    use std::net::{Ipv4Addr, SocketAddrV4};

    const LOCAL: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 10), 50_000);
    const REMOTE: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::new(198, 51, 100, 20), 443);

    #[test]
    fn filters_pass_the_default_interface_types_and_loopback_then_end() {
        let filters = filters();
        assert_eq!(
            filters.len(),
            256,
            "PKTAP_MAX_FILTERS * sizeof(struct pktap_filter)"
        );
        let word = |entry: &[u8], at: usize| {
            u32::from_ne_bytes(entry[at..at + 4].try_into().expect("four bytes"))
        };
        let (entries, rest) = filters.as_chunks::<PKTAP_FILTER_LEN>();
        assert!(rest.is_empty());
        for (entry, interface_type) in entries.iter().zip([0x06, 0x90, 0x01, 0x18]) {
            assert_eq!(word(entry, 0), PKTAP_FILTER_OP_PASS);
            assert_eq!(word(entry, 4), PKTAP_FILTER_PARAM_IF_TYPE);
            assert_eq!(word(entry, 8), interface_type);
            assert!(entry[12..].iter().all(|byte| *byte == 0));
        }
        assert!(
            entries[PASSED_INTERFACE_TYPES.len()..]
                .iter()
                .all(|entry| entry.iter().all(|byte| *byte == 0)),
            "unused entries must be PKTAP_FILTER_OP_NONE"
        );
    }

    /// A PKTAP record whose link-layer frame is `link_header` followed by a 40-byte IPv4 TCP
    /// packet from 192.0.2.10:50000 to 198.51.100.20:443, as XNU writes it: the frame right
    /// after the header, with `pth_frame_pre_length` counting the link header.
    fn outgoing_fixture(dlt: u32, link_header: &[u8]) -> Vec<u8> {
        outgoing_record(dlt, link_header, &ipv4_tcp(LOCAL, REMOTE, 0, 0, &[]))
    }

    /// A PKTAP record for `ip`, an IP packet sent by PID 42, `curl`.
    fn outgoing_record(dlt: u32, link_header: &[u8], ip: &[u8]) -> Vec<u8> {
        let mut frame = vec![0_u8; PKTAP_MIN_HEADER];
        frame[0..4].copy_from_slice(
            &u32::try_from(PKTAP_MIN_HEADER)
                .expect("header length fits u32")
                .to_ne_bytes(),
        );
        frame[8..12].copy_from_slice(&dlt.to_ne_bytes());
        frame[36..40].copy_from_slice(&PTH_FLAG_DIR_OUT.to_ne_bytes());
        frame[44..48].copy_from_slice(
            &u32::try_from(link_header.len())
                .expect("link header length fits u32")
                .to_ne_bytes(),
        );
        frame[52..56].copy_from_slice(&42_i32.to_ne_bytes());
        frame[56..60].copy_from_slice(b"curl");
        frame[84..88].copy_from_slice(&(-1_i32).to_ne_bytes());
        frame.extend_from_slice(link_header);
        frame.extend_from_slice(ip);
        frame
    }

    fn outgoing_ipv4_fixture() -> Vec<u8> {
        outgoing_fixture(DLT_RAW, &[])
    }

    /// lo0 and the other interfaces without a link header get `DLT_NULL` and the protocol
    /// family stashed after the PKTAP header (`pktap_bpf_tap`'s `pre_adjust`).
    #[test]
    fn loopback_frames_skip_the_stashed_protocol_word_once() {
        let af_inet = 2_u32.to_ne_bytes();
        let frame = outgoing_fixture(DLT_NULL, &af_inet);
        let packet = decode(&frame).expect("packet");
        assert_eq!(packet.key.local_port, 50_000);
        assert_eq!(packet.key.remote_port, 443);
        assert_eq!(packet.delta.sent, 40);
    }

    #[test]
    fn ethernet_frames_skip_their_link_header_once() {
        let mut ethernet = [0_u8; 14];
        ethernet[12..14].copy_from_slice(&0x0800_u16.to_be_bytes());
        let frame = outgoing_fixture(DLT_EN10MB, &ethernet);
        let packet = decode(&frame).expect("packet");
        assert_eq!(packet.key.local_port, 50_000);
        assert_eq!(packet.key.remote_port, 443);
    }

    #[test]
    fn decodes_pid_direction_tuple_and_wire_length() {
        let frame = outgoing_ipv4_fixture();
        let packet = decode(&frame).expect("packet");
        assert_eq!(packet.pid, 42);
        assert_eq!(packet.key.local_port, 50_000);
        assert_eq!(packet.key.remote_port, 443);
        assert_eq!(packet.delta.sent, 40);
        assert_eq!(packet.command, "curl");
        assert_eq!(packet.flow_id, None, "the shortest header has no flow ID");
    }

    /// Each control bit alone and the combinations a connection sends: only a segment that
    /// acknowledges without setting a connection up or resetting one is past the handshake.
    #[test]
    fn control_bits_say_whether_the_handshake_is_over() {
        const FIN: u8 = 0x01;
        const SYN: u8 = 0x02;
        const RST: u8 = 0x04;
        const PSH: u8 = 0x08;
        const ACK: u8 = 0x10;
        for (bits, past_handshake) in [
            (0, false),
            (SYN, false),
            (SYN | ACK, false),
            (ACK, true),
            (PSH | ACK, true),
            (FIN | ACK, true),
            (RST, false),
            (RST | ACK, false),
            (FIN, false),
        ] {
            let flags = TcpFlags::new(bits);
            assert_eq!(flags.past_handshake(), past_handshake, "{bits:#04x}");
            assert_eq!(flags.begins_connection(), bits == SYN, "{bits:#04x}");
            assert_eq!(flags.fin(), bits & FIN != 0, "{bits:#04x}");
        }
    }

    #[test]
    fn a_tcp_segment_carries_its_control_bits_and_a_datagram_none() {
        let syn_ack = outgoing_record(DLT_RAW, &[], &ipv4_tcp(LOCAL, REMOTE, 0, 0x12, &[]));
        assert_eq!(
            decode(&syn_ack).expect("segment").tcp_flags,
            Some(TcpFlags::new(0x12))
        );
        let datagram = outgoing_record(DLT_RAW, &[], &ipv4_udp(LOCAL, REMOTE, b"datagram"));
        assert_eq!(decode(&datagram).expect("datagram").tcp_flags, None);
    }

    /// A header as macOS writes it runs past the fields every header has, and the flow
    /// ID is the first thing after them.
    #[test]
    fn a_full_header_carries_the_flow_id_of_the_socket() {
        let ip = ipv4_tcp(LOCAL, REMOTE, 0, 0, &[]);
        let mut frame = outgoing_record(DLT_RAW, &[], &ip);
        let full_header = 156_usize;
        let mut rest = vec![0_u8; full_header - PKTAP_MIN_HEADER];
        rest[0..4].copy_from_slice(&0xfeed_beef_u32.to_ne_bytes());
        frame.splice(PKTAP_MIN_HEADER..PKTAP_MIN_HEADER, rest);
        frame[0..4].copy_from_slice(&u32::try_from(full_header).expect("length").to_ne_bytes());
        let packet = decode(&frame).expect("packet");
        assert_eq!(packet.flow_id, Some(0xfeed_beef));
        assert_eq!(
            packet.key.remote_port, 443,
            "the packet still starts after the header"
        );

        frame[PTH_FLOWID_OFFSET..PTH_FLOWID_OFFSET + 4].fill(0);
        assert_eq!(
            decode(&frame).expect("packet").flow_id,
            None,
            "zero means the packet belongs to no socket's flow"
        );
    }

    #[test]
    fn absent_effective_pid_falls_back_to_the_real_packet_owner() {
        let mut frame = outgoing_ipv4_fixture();
        frame[84..88].copy_from_slice(&0_i32.to_ne_bytes());
        let packet = decode(&frame).unwrap();
        assert_eq!(packet.pid, 42);
        assert_eq!(packet.acting_pid, None);
        assert!(packet.outbound);
    }

    /// mDNSResponder's socket, delegated to the application whose lookup it carries.
    #[test]
    fn a_delegated_socket_names_the_process_it_acts_for_and_itself() {
        let mut frame = outgoing_ipv4_fixture();
        frame[84..88].copy_from_slice(&77_i32.to_ne_bytes());
        frame[88..94].copy_from_slice(b"Safari");
        let packet = decode(&frame).expect("packet");
        assert_eq!(packet.pid, 77);
        assert_eq!(packet.acting_pid, Some(42));
        assert_eq!(packet.command, "Safari");
    }

    #[test]
    fn port_53_packets_are_handed_on_from_their_ip_header() {
        let resolver = SocketAddrV4::new(*REMOTE.ip(), 53);
        for ip in [
            ipv4_udp(LOCAL, resolver, b"query"),
            ipv4_tcp(LOCAL, resolver, 1, 0, b"query"),
        ] {
            let frame = outgoing_record(DLT_NULL, &2_u32.to_ne_bytes(), &ip);
            assert_eq!(decode(&frame).expect("packet").dns, Some(ip.as_slice()));
        }
        assert_eq!(decode(&outgoing_ipv4_fixture()).expect("packet").dns, None);
    }

    #[test]
    fn every_truncation_is_rejected_without_panic() {
        let fixture = outgoing_ipv4_fixture();
        for length in 0..fixture.len() {
            assert!(decode(&fixture[..length]).is_none());
        }
    }

    proptest! {
        #[test]
        fn arbitrary_frames_never_panic(
            frame in proptest::collection::vec(any::<u8>(), 0..256),
        ) {
            let _ = decode(&frame);
        }

        #[test]
        fn mutated_frames_never_panic(
            edits in proptest::collection::vec((any::<usize>(), any::<u8>()), 0..8),
            keep in 0_usize..=PKTAP_MIN_HEADER + 40,
        ) {
            let _ = decode(&mutate(outgoing_ipv4_fixture(), &edits, keep));
        }
    }

    #[test]
    fn malformed_lengths_are_rejected() {
        let mut fixture = outgoing_ipv4_fixture();
        fixture[0..4].copy_from_slice(&u32::MAX.to_ne_bytes());
        assert!(decode(&fixture).is_none());
    }
}
