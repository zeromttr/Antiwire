use netmetrics_core::{
    ByteDelta, DnsPacket, FlowKey, ProcessIdentity, Protocol, locate_transport, parse_dns_packet,
};
use std::net::IpAddr;

const PKTAP_MIN_HEADER: usize = 108;
const DLT_NULL: u32 = 0;
const DLT_EN10MB: u32 = 1;
const DLT_RAW: u32 = 12;
const PTH_FLAG_DIR_IN: u32 = 1;
const PTH_FLAG_DIR_OUT: u32 = 2;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PktapPacket {
    pub key: FlowKey,
    pub pid: u32,
    pub process: Option<ProcessIdentity>,
    pub delta: ByteDelta,
    pub ifname: String,
    pub dns: Option<DnsPacket>,
}

pub(crate) fn decode(frame: &[u8]) -> Option<PktapPacket> {
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
    let packet = &frame[header_len + pre_len..packet_end];
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
    let (pid, name) = if let Some(pid) = u32::try_from(effective_pid).ok().filter(|pid| *pid != 0) {
        (pid, effective_command)
    } else if let Some(pid) = u32::try_from(pid).ok().filter(|pid| *pid != 0) {
        (pid, command)
    } else {
        (0, String::new())
    };
    let process = (!name.is_empty()).then_some(ProcessIdentity {
        executable: name.clone(),
        name,
        // PKTAP carries no process creation time. The packet timestamp is a
        // socket observation time and must never stand in for it: a bogus
        // start_ts poisons PID-reuse validation downstream. Zero means
        // unknown; `macos.rs` overwrites it with the real sysctl value when
        // the process is still alive.
        start_ts: 0,
    });
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
        process,
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

struct DecodedIp {
    protocol: Protocol,
    source: IpAddr,
    source_port: u16,
    destination: IpAddr,
    destination_port: u16,
    ip_len: usize,
    dns: Option<DnsPacket>,
}

fn decode_ip_packet(packet: &[u8], dlt: u32) -> Option<DecodedIp> {
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
    let dns = (protocol == Protocol::Udp && (source_port == 53 || destination_port == 53))
        .then(|| parse_dns_packet(ip))
        .flatten();
    Some(DecodedIp {
        protocol,
        source: transport.source,
        source_port,
        destination: transport.destination,
        destination_port,
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

fn c_string(bytes: &[u8]) -> String {
    let end = bytes
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    /// Overwrites bytes of a well-formed seed and cuts it short, so the parser sees
    /// input that is almost valid rather than only noise.
    fn mutate(mut bytes: Vec<u8>, edits: &[(usize, u8)], keep: usize) -> Vec<u8> {
        let len = bytes.len();
        for &(index, value) in edits {
            bytes[index % len] = value;
        }
        bytes.truncate(keep);
        bytes
    }

    fn outgoing_ipv4_fixture() -> Vec<u8> {
        let mut frame = vec![0_u8; PKTAP_MIN_HEADER + 40];
        frame[0..4].copy_from_slice(
            &u32::try_from(PKTAP_MIN_HEADER)
                .expect("header length fits u32")
                .to_ne_bytes(),
        );
        frame[8..12].copy_from_slice(&DLT_RAW.to_ne_bytes());
        frame[36..40].copy_from_slice(&PTH_FLAG_DIR_OUT.to_ne_bytes());
        frame[52..56].copy_from_slice(&42_i32.to_ne_bytes());
        frame[56..60].copy_from_slice(b"curl");
        frame[84..88].copy_from_slice(&(-1_i32).to_ne_bytes());
        let ip = &mut frame[PKTAP_MIN_HEADER..];
        ip[0] = 0x45;
        ip[2..4].copy_from_slice(&40_u16.to_be_bytes());
        ip[9] = 6;
        ip[12..16].copy_from_slice(&[192, 0, 2, 10]);
        ip[16..20].copy_from_slice(&[198, 51, 100, 20]);
        ip[20..22].copy_from_slice(&50_000_u16.to_be_bytes());
        ip[22..24].copy_from_slice(&443_u16.to_be_bytes());
        frame
    }

    #[test]
    fn decodes_pid_direction_tuple_and_wire_length() {
        let packet = decode(&outgoing_ipv4_fixture()).expect("packet");
        assert_eq!(packet.pid, 42);
        assert_eq!(packet.key.local_port, 50_000);
        assert_eq!(packet.key.remote_port, 443);
        assert_eq!(packet.delta.sent, 40);
        assert_eq!(packet.process.expect("process").name, "curl");
    }

    #[test]
    fn absent_effective_pid_falls_back_to_the_real_packet_owner() {
        let mut frame = outgoing_ipv4_fixture();
        frame[84..88].copy_from_slice(&0_i32.to_ne_bytes());
        assert_eq!(decode(&frame).unwrap().pid, 42);
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
