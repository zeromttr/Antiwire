//! Packet fixtures shared by this workspace's tests.

use std::net::SocketAddrV4;

/// Overwrites bytes of a well-formed seed and cuts it short, so a parser sees input that
/// is almost valid rather than only noise.
///
/// # Panics
///
/// Panics when `bytes` is empty and `edits` is not.
#[must_use]
pub fn mutate(mut bytes: Vec<u8>, edits: &[(usize, u8)], keep: usize) -> Vec<u8> {
    let len = bytes.len();
    for &(index, value) in edits {
        bytes[index % len] = value;
    }
    bytes.truncate(keep);
    bytes
}

/// `name` in DNS wire form: length-prefixed labels and the root label.
///
/// # Panics
///
/// Panics when a label is longer than 255 bytes.
#[must_use]
pub fn dns_name(name: &str) -> Vec<u8> {
    let mut encoded = Vec::new();
    for label in name.split('.') {
        encoded.push(u8::try_from(label.len()).expect("label fits a length byte"));
        encoded.extend_from_slice(label.as_bytes());
    }
    encoded.push(0);
    encoded
}

/// A DNS message asking for the A records of `name`: a query when `response` is `None`,
/// otherwise a response with that response code. The header declares `answers` answer
/// records, which the caller appends, for example with [`push_a_record`].
#[must_use]
pub fn dns_message(id: u16, name: &str, response: Option<u8>, answers: u16) -> Vec<u8> {
    let mut message = vec![0_u8; 12];
    message[0..2].copy_from_slice(&id.to_be_bytes());
    // A query with recursion desired, or its answer with recursion available.
    let flags = response.map_or(0x0100, |code| 0x8180 | u16::from(code & 0x0f));
    message[2..4].copy_from_slice(&flags.to_be_bytes());
    message[4..6].copy_from_slice(&1_u16.to_be_bytes());
    message[6..8].copy_from_slice(&answers.to_be_bytes());
    message.extend(dns_name(name));
    message.extend_from_slice(&1_u16.to_be_bytes());
    message.extend_from_slice(&1_u16.to_be_bytes());
    message
}

/// Appends an A record owned by the question name, through a pointer to it.
pub fn push_a_record(message: &mut Vec<u8>, address: [u8; 4], ttl_seconds: u32) {
    message.extend_from_slice(&0xc00c_u16.to_be_bytes());
    message.extend_from_slice(&1_u16.to_be_bytes());
    message.extend_from_slice(&1_u16.to_be_bytes());
    message.extend_from_slice(&ttl_seconds.to_be_bytes());
    message.extend_from_slice(&4_u16.to_be_bytes());
    message.extend_from_slice(&address);
}

/// `message` as DNS over TCP carries it: its length in two bytes, then the message.
///
/// # Panics
///
/// Panics when `message` is longer than a DNS message can be.
#[must_use]
pub fn dns_over_tcp(message: &[u8]) -> Vec<u8> {
    let mut framed = u16::try_from(message.len())
        .expect("message fits its length prefix")
        .to_be_bytes()
        .to_vec();
    framed.extend_from_slice(message);
    framed
}

fn ipv4_header(
    protocol: u8,
    source: SocketAddrV4,
    destination: SocketAddrV4,
    transport_len: usize,
) -> Vec<u8> {
    let mut packet = vec![0_u8; 20];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(
        &u16::try_from(20 + transport_len)
            .expect("packet fits an IPv4 total length")
            .to_be_bytes(),
    );
    packet[9] = protocol;
    packet[12..16].copy_from_slice(&source.ip().octets());
    packet[16..20].copy_from_slice(&destination.ip().octets());
    packet.extend_from_slice(&source.port().to_be_bytes());
    packet.extend_from_slice(&destination.port().to_be_bytes());
    packet
}

/// An IPv4 UDP datagram carrying `payload`.
///
/// # Panics
///
/// Panics when the datagram would not fit an IPv4 packet.
#[must_use]
pub fn ipv4_udp(source: SocketAddrV4, destination: SocketAddrV4, payload: &[u8]) -> Vec<u8> {
    let mut packet = ipv4_header(17, source, destination, 8 + payload.len());
    packet.extend_from_slice(
        &u16::try_from(8 + payload.len())
            .expect("datagram fits a UDP length")
            .to_be_bytes(),
    );
    packet.extend_from_slice(&[0, 0]);
    packet.extend_from_slice(payload);
    packet
}

/// An IPv4 TCP segment with a minimal header, carrying `payload` at `sequence`.
///
/// # Panics
///
/// Panics when the segment would not fit an IPv4 packet.
#[must_use]
pub fn ipv4_tcp(
    source: SocketAddrV4,
    destination: SocketAddrV4,
    sequence: u32,
    flags: u8,
    payload: &[u8],
) -> Vec<u8> {
    let mut packet = ipv4_header(6, source, destination, 20 + payload.len());
    packet.extend_from_slice(&sequence.to_be_bytes());
    packet.extend_from_slice(&[0; 4]);
    packet.push(5 << 4);
    packet.push(flags);
    packet.extend_from_slice(&[0; 6]);
    packet.extend_from_slice(payload);
    packet
}
