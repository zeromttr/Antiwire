use std::fmt;

pub(crate) const DLT_PKTAP: u32 = 149;

/// The capture buffer lengths to ask the kernel for, most wanted first.
///
/// A BPF descriptor starts with a buffer of 4096 bytes (`BPF_BUFSIZE` in XNU's
/// `bsd/net/bpf.c`), and the kernel cuts a packet that does not fit the buffer down to it
/// (`catchpacket`: "transfer the whole packet (unless we hit the buffer size limit)"). A
/// cut packet cannot be decoded, so with that buffer no packet over about 3.9 KiB was
/// counted, which is every full segment on loopback, whose MTU is 16384.
///
/// The buffer also bounds what the kernel can hold while the reader is not reading: it
/// keeps two buffers of this length, and drops what arrives when both are full. On a
/// macOS runner 512 KiB, the `BPF_MAXBUFSIZE` libpcap asks for, lost 238 of the packets of
/// a 2 MiB loopback transfer. So the first length asked for is 4 MiB. `BIOCSBLEN` accepts
/// up to `BPF_BUFSIZE_CAP` since XNU 8792 (macOS 13) and writes back the length it set.
/// The shorter lengths are tried when the kernel cannot allocate the buffers.
pub(crate) const BUFFER_LENGTHS: [u32; 6] = [
    4 * 1024 * 1024,
    2 * 1024 * 1024,
    1024 * 1024,
    512 * 1024,
    256 * 1024,
    MIN_BUFFER_LEN,
];

/// The shortest buffer capture accepts: one that holds the largest IP packet, 65535
/// bytes, whole, with the headers BPF and PKTAP put before it.
pub(crate) const MIN_BUFFER_LEN: u32 = 128 * 1024;
// The largest IP packet, the PKTAP header before it and the BPF header before that, each
// rounded up generously.
const _: () = assert!(MIN_BUFFER_LEN >= 65_535 + 1_024 + 256);

const BPF_HEADER_MIN_LEN: usize = 18;
const BPF_ALIGNMENT: usize = 4;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DecodeError {
    UnsupportedDataLink(u32),
    TruncatedHeader,
    InvalidHeaderLength,
    CaptureExceedsPacket,
    TruncatedRecord,
    LengthOverflow,
}

impl fmt::Display for DecodeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedDataLink(value) => {
                write!(
                    formatter,
                    "data-link type is {value}, expected live PKTAP ({DLT_PKTAP})"
                )
            }
            Self::TruncatedHeader => formatter.write_str("truncated BPF record header"),
            Self::InvalidHeaderLength => formatter.write_str("invalid BPF record header length"),
            Self::CaptureExceedsPacket => {
                formatter.write_str("captured BPF length exceeds packet length")
            }
            Self::TruncatedRecord => formatter.write_str("truncated BPF record"),
            Self::LengthOverflow => formatter.write_str("BPF record length overflow"),
        }
    }
}

pub(crate) fn validate_data_link(value: u32) -> Result<(), DecodeError> {
    if value == DLT_PKTAP {
        Ok(())
    } else {
        Err(DecodeError::UnsupportedDataLink(value))
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct BpfRecord<'a> {
    pub(crate) packet: &'a [u8],
    pub(crate) timestamp: Option<std::time::Duration>,
}

pub(crate) struct Records<'a> {
    buffer: &'a [u8],
    offset: usize,
    done: bool,
}

pub(crate) fn records(buffer: &[u8]) -> Records<'_> {
    Records {
        buffer,
        offset: 0,
        done: false,
    }
}

impl<'a> Iterator for Records<'a> {
    type Item = Result<BpfRecord<'a>, DecodeError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done || self.offset == self.buffer.len() {
            return None;
        }
        self.done = true;
        let remaining = self.buffer.get(self.offset..)?;
        if remaining.len() < BPF_HEADER_MIN_LEN {
            return Some(Err(DecodeError::TruncatedHeader));
        }

        let caplen = u32::from_ne_bytes(remaining[8..12].try_into().unwrap()) as usize;
        let datalen = u32::from_ne_bytes(remaining[12..16].try_into().unwrap()) as usize;
        let header_len = usize::from(u16::from_ne_bytes(remaining[16..18].try_into().unwrap()));
        if header_len < BPF_HEADER_MIN_LEN {
            return Some(Err(DecodeError::InvalidHeaderLength));
        }
        if caplen > datalen {
            return Some(Err(DecodeError::CaptureExceedsPacket));
        }
        let Some(record_len) = header_len.checked_add(caplen) else {
            return Some(Err(DecodeError::LengthOverflow));
        };
        let Some(frame) = remaining.get(header_len..record_len) else {
            return Some(Err(DecodeError::TruncatedRecord));
        };
        let Some(aligned_len) = record_len
            .checked_add(BPF_ALIGNMENT - 1)
            .map(|value| value & !(BPF_ALIGNMENT - 1))
        else {
            return Some(Err(DecodeError::LengthOverflow));
        };
        if aligned_len > remaining.len() && record_len != remaining.len() {
            return Some(Err(DecodeError::TruncatedRecord));
        }

        self.offset += aligned_len.min(remaining.len());
        self.done = false;
        // Darwin BPF uses a 32-bit seconds/microseconds timeval.
        let seconds = i32::from_ne_bytes(remaining[..4].try_into().unwrap());
        let micros = i32::from_ne_bytes(remaining[4..8].try_into().unwrap());
        let timestamp = u64::try_from(seconds)
            .ok()
            .zip(u32::try_from(micros).ok())
            .filter(|(_, micros)| *micros < 1_000_000)
            .map(|(seconds, micros)| std::time::Duration::new(seconds, micros * 1_000));
        Some(Ok(BpfRecord {
            packet: frame,
            timestamp,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::{BUFFER_LENGTHS, DLT_PKTAP, MIN_BUFFER_LEN, records, validate_data_link};
    use proptest::prelude::*;

    #[test]
    fn every_buffer_length_asked_for_holds_a_whole_packet() {
        assert!(
            BUFFER_LENGTHS
                .iter()
                .all(|length| *length >= MIN_BUFFER_LEN)
        );
        assert!(BUFFER_LENGTHS.is_sorted_by(|larger, smaller| larger > smaller));
    }

    fn record(caplen: u32, datalen: u32, header_len: u16, payload: &[u8]) -> Vec<u8> {
        let mut bytes = vec![0_u8; usize::from(header_len)];
        bytes[8..12].copy_from_slice(&caplen.to_ne_bytes());
        bytes[12..16].copy_from_slice(&datalen.to_ne_bytes());
        bytes[16..18].copy_from_slice(&header_len.to_ne_bytes());
        bytes.extend_from_slice(payload);
        let aligned = bytes.len().div_ceil(4) * 4;
        bytes.resize(aligned, 0);
        bytes
    }

    #[test]
    fn capture_timestamp_is_preserved_and_invalid_microseconds_are_rejected() {
        let mut bytes = record(1, 1, 18, &[42]);
        bytes[..4].copy_from_slice(&123_i32.to_ne_bytes());
        bytes[4..8].copy_from_slice(&456_789_i32.to_ne_bytes());
        assert_eq!(
            records(&bytes).next().unwrap().unwrap().timestamp,
            Some(std::time::Duration::new(123, 456_789_000))
        );
        bytes[4..8].copy_from_slice(&1_000_000_i32.to_ne_bytes());
        assert_eq!(records(&bytes).next().unwrap().unwrap().timestamp, None);
        bytes[..4].copy_from_slice(&(-1_i32).to_ne_bytes());
        assert_eq!(records(&bytes).next().unwrap().unwrap().timestamp, None);
    }

    /// Walks every record; the iterator must end, and each packet must fit its record.
    fn drain(buffer: &[u8]) {
        for record in records(buffer).take(buffer.len() + 1) {
            let _ = record.map(|record| record.packet.len());
        }
    }

    proptest! {
        #[test]
        fn arbitrary_buffers_never_panic(
            buffer in proptest::collection::vec(any::<u8>(), 0..128),
        ) {
            drain(&buffer);
        }

        #[test]
        fn mutated_buffers_never_panic(
            edits in proptest::collection::vec((any::<usize>(), any::<u8>()), 0..8),
            keep in 0_usize..64,
        ) {
            let mut buffer = record(3, 3, 18, &[1, 2, 3]);
            buffer.extend(record(2, 2, 22, &[4, 5]));
            let len = buffer.len();
            for (index, value) in edits {
                buffer[index % len] = value;
            }
            buffer.truncate(keep);
            drain(&buffer);
        }

        #[test]
        fn well_formed_records_round_trip(
            payloads in proptest::collection::vec(
                (proptest::collection::vec(any::<u8>(), 0..40), 18_u16..32),
                0..6,
            ),
        ) {
            let mut buffer = Vec::new();
            for (payload, header_len) in &payloads {
                let len = u32::try_from(payload.len()).expect("small payload");
                buffer.extend(record(len, len, *header_len, payload));
            }
            let decoded: Vec<Vec<u8>> = records(&buffer)
                .map(|record| record.expect("valid record").packet.to_vec())
                .collect();
            let expected: Vec<Vec<u8>> = payloads.into_iter().map(|(payload, _)| payload).collect();
            prop_assert_eq!(decoded, expected);
        }
    }

    #[test]
    fn live_pktap_uses_darwin_dlt_user2() {
        assert_eq!(DLT_PKTAP, 149);
        assert!(validate_data_link(149).is_ok());
        assert!(validate_data_link(258).is_err());
    }

    #[test]
    fn decodes_timeval32_header_offsets_and_four_byte_alignment() {
        let mut buffer = record(3, 3, 18, &[1, 2, 3]);
        buffer.extend(record(2, 2, 22, &[4, 5]));

        let decoded: Vec<_> = records(&buffer)
            .map(|record| record.expect("valid record").packet.to_vec())
            .collect();

        assert_eq!(decoded, vec![vec![1, 2, 3], vec![4, 5]]);
    }

    #[test]
    fn rejects_invalid_lengths_without_panicking() {
        let mut too_short_header = record(0, 0, 18, &[]);
        too_short_header[16..18].copy_from_slice(&17_u16.to_ne_bytes());
        assert!(records(&too_short_header).next().unwrap().is_err());

        let truncated = record(4, 4, 18, &[1, 2]);
        assert!(records(&truncated[..20]).next().unwrap().is_err());

        let caplen_exceeds_datalen = record(4, 3, 18, &[1, 2, 3, 4]);
        assert!(records(&caplen_exceeds_datalen).next().unwrap().is_err());
    }
}
