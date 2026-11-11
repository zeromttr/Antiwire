use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

const MAX_EXTENSION_HEADERS: usize = 8;
const MAX_EXTENSION_BYTES: usize = 256;

/// Bounds-checked location of an IP packet's transport header.
#[doc(hidden)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IpTransport {
    pub source: IpAddr,
    pub destination: IpAddr,
    pub protocol: u8,
    pub offset: usize,
    pub total_len: usize,
}

/// Locates TCP or UDP after a bounded set of IPv6 extension headers.
#[doc(hidden)]
#[must_use]
pub fn locate_transport(packet: &[u8]) -> Option<IpTransport> {
    match packet.first()? >> 4 {
        4 => locate_ipv4(packet),
        6 => locate_ipv6(packet),
        _ => None,
    }
}

fn locate_ipv4(packet: &[u8]) -> Option<IpTransport> {
    if packet.len() < 20 {
        return None;
    }
    let offset = usize::from(packet[0] & 0x0f).checked_mul(4)?;
    let total_len = usize::from(u16::from_be_bytes(packet[2..4].try_into().ok()?));
    if offset < 20 || total_len < offset + 4 || total_len > packet.len() {
        return None;
    }
    let fragment = u16::from_be_bytes(packet[6..8].try_into().ok()?);
    if fragment & 0x3fff != 0 {
        return None;
    }
    Some(IpTransport {
        source: IpAddr::V4(Ipv4Addr::new(
            packet[12], packet[13], packet[14], packet[15],
        )),
        destination: IpAddr::V4(Ipv4Addr::new(
            packet[16], packet[17], packet[18], packet[19],
        )),
        protocol: packet[9],
        offset,
        total_len,
    })
}

fn locate_ipv6(packet: &[u8]) -> Option<IpTransport> {
    if packet.len() < 40 {
        return None;
    }
    let payload_len = usize::from(u16::from_be_bytes(packet[4..6].try_into().ok()?));
    if payload_len == 0 {
        return None;
    }
    let total_len = 40_usize.checked_add(payload_len)?;
    if total_len > packet.len() {
        return None;
    }
    let source = IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&packet[8..24]).ok()?));
    let destination = IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&packet[24..40]).ok()?));
    let mut protocol = packet[6];
    let mut offset = 40_usize;
    let mut extension_bytes = 0_usize;
    for _ in 0..=MAX_EXTENSION_HEADERS {
        if matches!(protocol, 6 | 17) {
            return (offset.checked_add(4)? <= total_len).then_some(IpTransport {
                source,
                destination,
                protocol,
                offset,
                total_len,
            });
        }
        if matches!(protocol, 50 | 59) {
            return None;
        }
        let next = *packet.get(offset)?;
        let header_len = match protocol {
            0 | 43 | 60 => usize::from(*packet.get(offset + 1)?)
                .checked_add(1)?
                .checked_mul(8)?,
            44 => {
                let fragment =
                    u16::from_be_bytes(packet.get(offset + 2..offset + 4)?.try_into().ok()?);
                if fragment != 0 {
                    return None;
                }
                8
            }
            51 => usize::from(*packet.get(offset + 1)?)
                .checked_add(2)?
                .checked_mul(4)?,
            _ => return None,
        };
        extension_bytes = extension_bytes.checked_add(header_len)?;
        if header_len == 0
            || extension_bytes > MAX_EXTENSION_BYTES
            || offset.checked_add(header_len)? > total_len
        {
            return None;
        }
        offset += header_len;
        protocol = next;
    }
    None
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

    #[test]
    fn locates_udp_after_ipv6_destination_options() {
        let mut packet = vec![0_u8; 56];
        packet[0] = 0x60;
        packet[4..6].copy_from_slice(&16_u16.to_be_bytes());
        packet[6] = 60;
        packet[40] = 17;
        packet[48..50].copy_from_slice(&1234_u16.to_be_bytes());
        packet[50..52].copy_from_slice(&53_u16.to_be_bytes());
        let located = locate_transport(&packet).unwrap();
        assert_eq!(located.protocol, 17);
        assert_eq!(located.offset, 48);
    }

    #[test]
    fn rejects_fragments_jumbograms_and_excessive_chains() {
        let mut fragment = vec![0_u8; 56];
        fragment[0] = 0x60;
        fragment[4..6].copy_from_slice(&16_u16.to_be_bytes());
        fragment[6] = 44;
        fragment[40] = 17;
        fragment[42..44].copy_from_slice(&1_u16.to_be_bytes());
        assert!(locate_transport(&fragment).is_none());

        fragment[4..6].fill(0);
        assert!(locate_transport(&fragment).is_none());
    }

    fn ipv6_udp_seed() -> Vec<u8> {
        let mut packet = vec![0_u8; 56];
        packet[0] = 0x60;
        packet[4..6].copy_from_slice(&16_u16.to_be_bytes());
        packet[6] = 60;
        packet[40] = 17;
        packet
    }

    fn ipv4_tcp_seed() -> Vec<u8> {
        let mut packet = vec![0_u8; 40];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&40_u16.to_be_bytes());
        packet[9] = 6;
        packet
    }

    /// Any located transport header lies inside the packet.
    fn assert_in_bounds(packet: &[u8]) {
        if let Some(located) = locate_transport(packet) {
            assert!(located.offset + 4 <= located.total_len);
            assert!(located.total_len <= packet.len());
        }
    }

    proptest! {
        #[test]
        fn arbitrary_bytes_never_locate_out_of_bounds(
            packet in proptest::collection::vec(any::<u8>(), 0..128),
        ) {
            assert_in_bounds(&packet);
        }

        #[test]
        fn mutated_packets_never_locate_out_of_bounds(
            v6 in any::<bool>(),
            edits in proptest::collection::vec((any::<usize>(), any::<u8>()), 0..8),
            keep in 0_usize..64,
        ) {
            let seed = if v6 { ipv6_udp_seed() } else { ipv4_tcp_seed() };
            assert_in_bounds(&mutate(seed, &edits, keep));
        }
    }
}
