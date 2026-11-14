//! DNS messages reassembled from captured TCP port-53 segments.
//!
//! DNS over TCP prefixes every message with its length in two bytes, and one connection
//! can carry many messages (RFC 1035 section 4.2.2, RFC 7766 section 8). A message can
//! span segments and a segment can hold several messages, so each direction of a
//! connection keeps the bytes of the message it is in the middle of.
//!
//! Everything here is sized by what an unprivileged local process could send: the number
//! of connections followed and the bytes kept for each are both bounded, and a stream
//! that stops making sense is dropped rather than repaired.

#![allow(missing_docs)]

use crate::dns_transaction::{DnsEndpoints, DnsPacket, parse_dns_message};
use crate::{Protocol, locate_transport};
use std::collections::HashMap;

const DNS_PORT: u16 = 53;
const TCP: u8 = 6;
const TCP_MIN_HEADER: usize = 20;
const TCP_FIN: u8 = 0x01;
const TCP_SYN: u8 = 0x02;
const TCP_RST: u8 = 0x04;

/// Longest message kept. The protocol allows 65,535 bytes, but an address lookup is far
/// smaller: what exceeds this is a zone transfer or the like, which names no address a
/// flow goes to, and is skipped without being buffered.
const MAX_MESSAGE_LEN: usize = 16 * 1024;
/// Directions of connections followed at once.
const MAX_STREAMS: usize = 256;
/// A stream silent for this long is forgotten.
const STREAM_IDLE_MS: u64 = 30_000;

#[derive(Debug)]
struct Stream {
    /// Sequence number of the next byte not yet seen.
    next_sequence: u32,
    /// The start of a message whose rest has not arrived.
    buffered: Vec<u8>,
    /// Bytes still to pass over, the rest of a message too long to keep.
    to_skip: usize,
    /// Whether message boundaries are known: the stream was followed from its SYN, or a
    /// message has decoded since. Until then a boundary is a guess, and a message that
    /// does not decode means the guess was wrong.
    aligned: bool,
    last_seen: u64,
}

/// Follows TCP port-53 connections and returns each DNS message as it completes.
#[derive(Debug, Default)]
pub struct DnsStreamReassembler {
    streams: HashMap<DnsEndpoints, Stream>,
}

impl DnsStreamReassembler {
    /// Takes one captured packet, starting at its IP header, and returns the DNS messages
    /// it completes. Anything but a TCP segment to or from port 53 returns none.
    ///
    /// A capture can show a segment twice, leaving and arriving on loopback, and TCP can
    /// retransmit one. Bytes already seen are passed over, so neither repeats a message.
    pub fn observe(&mut self, packet: &[u8], now: u64) -> Vec<DnsPacket> {
        self.observe_segment(packet, now).unwrap_or_default()
    }

    fn observe_segment(&mut self, packet: &[u8], now: u64) -> Option<Vec<DnsPacket>> {
        let transport = locate_transport(packet)?;
        if transport.protocol != TCP {
            return None;
        }
        let segment = packet.get(transport.offset..transport.total_len)?;
        let header = segment.first_chunk::<TCP_MIN_HEADER>()?;
        let endpoints = DnsEndpoints {
            protocol: Protocol::Tcp,
            source_addr: transport.source,
            source_port: u16::from_be_bytes([header[0], header[1]]),
            destination_addr: transport.destination,
            destination_port: u16::from_be_bytes([header[2], header[3]]),
        };
        if endpoints.source_port != DNS_PORT && endpoints.destination_port != DNS_PORT {
            return None;
        }
        let header_len = usize::from(header[12] >> 4) * 4;
        if header_len < TCP_MIN_HEADER {
            return None;
        }
        let payload = segment.get(header_len..)?;
        let flags = header[13];
        let mut sequence = u32::from_be_bytes([header[4], header[5], header[6], header[7]]);
        if flags & TCP_RST != 0 {
            self.streams.remove(&endpoints);
            self.streams.remove(&endpoints.reversed());
            return None;
        }
        if flags & TCP_SYN != 0 {
            // A new connection on these endpoints. The SYN takes one sequence number, so
            // the first message starts right after it.
            sequence = sequence.wrapping_add(1);
            self.streams.remove(&endpoints);
            self.start(endpoints, sequence, true, now);
        }
        let messages = if payload.is_empty() {
            Vec::new()
        } else {
            self.accept(endpoints, sequence, payload, now)
        };
        if flags & TCP_FIN != 0 {
            // Only this direction ends: the answer to a query sent with FIN is still to come.
            self.streams.remove(&endpoints);
        }
        Some(messages)
    }

    /// Starts following a direction whose next byte is `sequence`.
    fn start(&mut self, endpoints: DnsEndpoints, sequence: u32, aligned: bool, now: u64) {
        if self.streams.len() >= MAX_STREAMS {
            self.streams
                .retain(|_, stream| now.saturating_sub(stream.last_seen) < STREAM_IDLE_MS);
        }
        if self.streams.len() >= MAX_STREAMS
            && let Some(oldest) = self
                .streams
                .iter()
                .min_by_key(|(_, stream)| stream.last_seen)
                .map(|(endpoints, _)| *endpoints)
        {
            self.streams.remove(&oldest);
        }
        self.streams.insert(
            endpoints,
            Stream {
                next_sequence: sequence,
                buffered: Vec::new(),
                to_skip: 0,
                aligned,
                last_seen: now,
            },
        );
    }

    /// Adds the bytes at `sequence` to their stream and returns the messages now complete.
    fn accept(
        &mut self,
        endpoints: DnsEndpoints,
        sequence: u32,
        payload: &[u8],
        now: u64,
    ) -> Vec<DnsPacket> {
        if !self.streams.contains_key(&endpoints) {
            // Joined after the connection opened. The first segment seen most often starts
            // a message; when it does not, the message fails to decode and the stream is
            // dropped to try again.
            self.start(endpoints, sequence, false, now);
        }
        let Some(stream) = self.streams.get_mut(&endpoints) else {
            return Vec::new();
        };
        stream.last_seen = now;
        // How many of this segment's bytes were seen before. Sequence numbers wrap, so the
        // difference is read as signed: more than half the space "behind" is ahead.
        let seen = stream.next_sequence.wrapping_sub(sequence);
        let fresh = if seen > u32::MAX / 2 {
            // Bytes are missing, and with them the position of the next message.
            stream.buffered.clear();
            stream.to_skip = 0;
            stream.aligned = false;
            payload
        } else {
            match payload.get(usize::try_from(seen).unwrap_or(usize::MAX)..) {
                Some(fresh) => fresh,
                // A retransmission that ends before anything new.
                None => return Vec::new(),
            }
        };
        let Ok(advance) = u32::try_from(payload.len()) else {
            self.streams.remove(&endpoints);
            return Vec::new();
        };
        stream.next_sequence = sequence.wrapping_add(advance);
        let skipped = stream.to_skip.min(fresh.len());
        stream.to_skip -= skipped;
        stream.buffered.extend_from_slice(&fresh[skipped..]);

        let mut messages = Vec::new();
        let mut consumed = 0;
        let mut lost = false;
        while let Some(prefix) = stream
            .buffered
            .get(consumed..)
            .and_then(<[u8]>::first_chunk::<2>)
        {
            let length = usize::from(u16::from_be_bytes(*prefix));
            let start = consumed + 2;
            if length == 0 {
                lost = true;
                break;
            }
            if length > MAX_MESSAGE_LEN {
                if !stream.aligned {
                    lost = true;
                    break;
                }
                // Pass over the whole message, the part already here and the part to come.
                let available = stream.buffered.len() - start;
                stream.to_skip = length.saturating_sub(available);
                consumed = stream.buffered.len().min(start + length);
                continue;
            }
            let Some(message) = stream.buffered.get(start..start + length) else {
                break;
            };
            match parse_dns_message(message, endpoints) {
                Some(message) => {
                    stream.aligned = true;
                    messages.push(message);
                }
                None if stream.aligned => {}
                None => {
                    lost = true;
                    break;
                }
            }
            consumed = start + length;
        }
        if lost {
            self.streams.remove(&endpoints);
        } else {
            stream.buffered.drain(..consumed);
        }
        messages
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{dns_message, dns_over_tcp, ipv4_tcp, mutate};
    use proptest::prelude::*;
    use std::net::{IpAddr, Ipv4Addr, SocketAddrV4};

    const CLIENT: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 2), 50_000);
    const SERVER: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::new(8, 8, 8, 8), DNS_PORT);

    /// A DNS query for `name`, as it travels over TCP.
    fn framed_query(id: u16, name: &str) -> Vec<u8> {
        dns_over_tcp(&dns_message(id, name, None, 0))
    }

    /// A TCP segment from the client to the server's port 53.
    fn segment(sequence: u32, flags: u8, payload: &[u8]) -> Vec<u8> {
        ipv4_tcp(CLIENT, SERVER, sequence, flags, payload)
    }

    fn names(messages: &[DnsPacket]) -> Vec<&str> {
        messages
            .iter()
            .map(|message| message.question.as_str())
            .collect()
    }

    #[test]
    fn a_query_in_one_segment_is_decoded_with_its_endpoints() {
        let mut streams = DnsStreamReassembler::default();
        assert!(streams.observe(&segment(99, TCP_SYN, &[]), 0).is_empty());
        let messages = streams.observe(&segment(100, 0, &framed_query(7, "example.test")), 1);
        assert_eq!(names(&messages), ["example.test"]);
        let query = &messages[0];
        assert_eq!(query.protocol, Protocol::Tcp);
        assert_eq!(query.id, 7);
        assert_eq!(query.source_addr, IpAddr::V4(*CLIENT.ip()));
        assert_eq!(query.source_port, CLIENT.port());
        assert_eq!(query.destination_port, DNS_PORT);
        assert!(!query.is_response);
    }

    #[test]
    fn a_message_split_across_segments_completes_with_its_last_byte() {
        let mut streams = DnsStreamReassembler::default();
        let framed = framed_query(7, "example.test");
        let (first, second) = framed.split_at(1);
        let (second, third) = second.split_at(9);
        streams.observe(&segment(99, TCP_SYN, &[]), 0);
        assert!(streams.observe(&segment(100, 0, first), 1).is_empty());
        assert!(streams.observe(&segment(101, 0, second), 2).is_empty());
        let messages = streams.observe(&segment(110, 0, third), 3);
        assert_eq!(names(&messages), ["example.test"]);
    }

    #[test]
    fn one_segment_can_carry_several_messages() {
        let mut streams = DnsStreamReassembler::default();
        let mut payload = framed_query(1, "one.test");
        payload.extend(framed_query(2, "two.test"));
        streams.observe(&segment(99, TCP_SYN, &[]), 0);
        let messages = streams.observe(&segment(100, 0, &payload), 1);
        assert_eq!(names(&messages), ["one.test", "two.test"]);
    }

    /// Loopback shows every segment leaving and arriving, and TCP retransmits.
    #[test]
    fn bytes_seen_before_do_not_repeat_a_message() {
        let mut streams = DnsStreamReassembler::default();
        let first = framed_query(1, "one.test");
        let second = framed_query(2, "two.test");
        let after_first = 100 + u32::try_from(first.len()).expect("length");
        streams.observe(&segment(99, TCP_SYN, &[]), 0);
        assert_eq!(streams.observe(&segment(100, 0, &first), 1).len(), 1);
        assert!(streams.observe(&segment(100, 0, &first), 1).is_empty());
        // A retransmission that also carries the next message yields only the new one.
        let mut both = first.clone();
        both.extend_from_slice(&second);
        let messages = streams.observe(&segment(100, 0, &both), 2);
        assert_eq!(names(&messages), ["two.test"]);
        assert!(
            streams
                .observe(&segment(after_first, 0, &second), 3)
                .is_empty()
        );
    }

    #[test]
    fn a_connection_joined_late_is_followed_from_the_first_segment_seen() {
        let mut streams = DnsStreamReassembler::default();
        let messages = streams.observe(&segment(5_000, 0, &framed_query(3, "late.test")), 0);
        assert_eq!(names(&messages), ["late.test"]);
    }

    #[test]
    fn missing_bytes_drop_what_was_buffered_and_start_again() {
        let mut streams = DnsStreamReassembler::default();
        let framed = framed_query(1, "lost.test");
        streams.observe(&segment(99, TCP_SYN, &[]), 0);
        assert!(
            streams
                .observe(&segment(100, 0, &framed[..5]), 1)
                .is_empty()
        );
        // The rest of that message never arrives; a later one does.
        let messages = streams.observe(&segment(900, 0, &framed_query(2, "next.test")), 2);
        assert_eq!(names(&messages), ["next.test"]);
    }

    #[test]
    fn a_message_too_long_to_keep_is_passed_over_without_losing_the_next() {
        let mut streams = DnsStreamReassembler::default();
        let oversized = MAX_MESSAGE_LEN + 1;
        let mut payload = u16::try_from(oversized)
            .expect("length")
            .to_be_bytes()
            .to_vec();
        payload.extend(vec![0xaa; 1_000]);
        streams.observe(&segment(99, TCP_SYN, &[]), 0);
        assert!(streams.observe(&segment(100, 0, &payload), 1).is_empty());
        assert_eq!(
            streams
                .streams
                .values()
                .map(|s| s.buffered.len())
                .sum::<usize>(),
            0,
            "nothing of the oversized message is kept"
        );
        let mut rest = vec![0xaa; oversized - 1_000];
        rest.extend(framed_query(9, "after.test"));
        let messages = streams.observe(&segment(1_102, 0, &rest), 2);
        assert_eq!(names(&messages), ["after.test"]);
    }

    #[test]
    fn a_reset_forgets_both_directions_and_a_fin_only_its_own() {
        let mut streams = DnsStreamReassembler::default();
        let framed = framed_query(1, "example.test");
        streams.observe(&segment(99, TCP_SYN, &[]), 0);
        streams.observe(&segment(100, 0, &framed[..5]), 1);
        assert_eq!(streams.streams.len(), 1);
        streams.observe(&segment(105, TCP_FIN, &[]), 2);
        assert!(streams.streams.is_empty());

        streams.observe(&segment(99, TCP_SYN, &[]), 3);
        streams.observe(&segment(100, TCP_RST, &[]), 4);
        assert!(streams.streams.is_empty());
    }

    #[test]
    fn streams_followed_are_bounded() {
        let mut streams = DnsStreamReassembler::default();
        for port in 0..u16::try_from(MAX_STREAMS + 50).expect("port") {
            let mut packet = segment(99, TCP_SYN, &[]);
            packet[20..22].copy_from_slice(&(10_000 + port).to_be_bytes());
            streams.observe(&packet, u64::from(port));
        }
        assert_eq!(streams.streams.len(), MAX_STREAMS);
    }

    proptest! {
        #[test]
        fn arbitrary_packets_never_panic_or_outgrow_their_bounds(
            packets in proptest::collection::vec(
                proptest::collection::vec(any::<u8>(), 0..128),
                0..32,
            ),
        ) {
            let mut streams = DnsStreamReassembler::default();
            for (now, packet) in (0_u64..).zip(&packets) {
                let _ = streams.observe(packet, now);
            }
            prop_assert!(streams.streams.len() <= MAX_STREAMS);
        }

        #[test]
        fn mutated_segments_never_panic_or_keep_more_than_one_message(
            segments in proptest::collection::vec(
                (
                    any::<u32>(),
                    any::<u8>(),
                    proptest::collection::vec((any::<usize>(), any::<u8>()), 0..6),
                    0_usize..96,
                ),
                0..24,
            ),
        ) {
            let mut streams = DnsStreamReassembler::default();
            for (now, (sequence, flags, edits, keep)) in (0_u64..).zip(segments) {
                let seed = segment(sequence % 512, flags, &framed_query(7, "example.test"));
                let _ = streams.observe(&mutate(seed, &edits, keep), now);
                for stream in streams.streams.values() {
                    prop_assert!(stream.buffered.len() < 2 + MAX_MESSAGE_LEN);
                }
            }
        }
    }
}
