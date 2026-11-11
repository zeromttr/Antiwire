use crate::BackendEvent;
use netmetrics_core::{ByteDelta, CookieSource, FlowKey, Protocol, SocketCookie};
use std::error::Error;
use std::fmt::{Display, Formatter};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

const MAGIC: u32 = u32::from_le_bytes(*b"NMT1");

/// Original layout, without a socket cookie.
const VERSION_V1: u8 = 1;
/// Adds a trailing `u64` socket cookie, where zero means "unavailable".
const VERSION_V2: u8 = 2;
/// Adds a trailing `u32` interface index after the cookie, where zero means "unavailable".
const VERSION_V3: u8 = 3;

/// Byte size of a version 1 record.
pub const WIRE_RECORD_LEN_V1: usize = 64;

/// Byte size of a version 2 record.
pub const WIRE_RECORD_LEN_V2: usize = 72;

/// Byte size of a version 3 record.
pub const WIRE_RECORD_LEN_V3: usize = 76;

/// Largest record the loader accepts, and the size to provision ring buffers for.
pub const WIRE_RECORD_LEN: usize = WIRE_RECORD_LEN_V3;

/// Offset of the version 2 cookie field.
const COOKIE_OFFSET: usize = 64;

/// Offset of the version 3 interface-index field.
const IFINDEX_OFFSET: usize = 72;

/// Smallest prefix that carries both magic and version.
const HEADER_LEN: usize = 6;

/// Native flow record operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WireFlowKind {
    /// Flow became active.
    Open,
    /// Flow ended.
    Close,
    /// Local send bytes.
    Sent,
    /// Local receive bytes.
    Received,
    /// The sending process at send entry, before the packet can be delivered.
    /// Carries no bytes.
    Owner,
}

/// Validated record decoded from an eBPF ring buffer or binary fixture.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WireFlowRecord {
    /// Operation.
    pub kind: WireFlowKind,
    /// Flow identity.
    pub key: FlowKey,
    /// Owning process.
    pub pid: u32,
    /// Native source timestamp (Linux uses `CLOCK_MONOTONIC` nanoseconds).
    pub timestamp: u64,
    /// Byte count for send/receive records.
    pub byte_count: u64,
    /// Socket cookie from `bpf_get_socket_cookie`, absent on version 1 records or when the
    /// kernel does not expose the helper.
    pub cookie: Option<u64>,
    /// Bound interface index from `skc_bound_dev_if`, absent when the socket is unbound.
    pub if_index: Option<u32>,
}

impl WireFlowRecord {
    /// Parses a fixed-width, versioned record without unaligned reads.
    ///
    /// # Errors
    ///
    /// Returns a validation error for an incorrect length, magic, version,
    /// operation, protocol, or address family.
    pub fn decode(bytes: &[u8]) -> Result<Self, WireRecordError> {
        // Magic and version are read before the length is validated, so that a stale
        // `netmetrics.bpf.o` emitting the shorter version 1 record still decodes instead of
        // failing the whole ring buffer closed.
        if bytes.len() < HEADER_LEN {
            return Err(WireRecordError::Length {
                actual: bytes.len(),
            });
        }
        let magic =
            read_array::<4>(bytes, 0)
                .map(u32::from_le_bytes)
                .ok_or(WireRecordError::Length {
                    actual: bytes.len(),
                })?;
        if magic != MAGIC {
            return Err(WireRecordError::Magic);
        }
        let expected_len = match bytes[4] {
            VERSION_V1 => WIRE_RECORD_LEN_V1,
            VERSION_V2 => WIRE_RECORD_LEN_V2,
            VERSION_V3 => WIRE_RECORD_LEN_V3,
            version => return Err(WireRecordError::Version(version)),
        };
        if bytes.len() != expected_len {
            return Err(WireRecordError::Length {
                actual: bytes.len(),
            });
        }
        let kind = match bytes[5] {
            1 => WireFlowKind::Open,
            2 => WireFlowKind::Close,
            3 => WireFlowKind::Sent,
            4 => WireFlowKind::Received,
            5 => WireFlowKind::Owner,
            value => return Err(WireRecordError::Kind(value)),
        };
        let protocol = match bytes[6] {
            6 => Protocol::Tcp,
            17 => Protocol::Udp,
            value => return Err(WireRecordError::Protocol(value)),
        };
        let family = bytes[7];
        let pid = u32::from_le_bytes(read_array::<4>(bytes, 8).ok_or(WireRecordError::Length {
            actual: bytes.len(),
        })?);
        let timestamp =
            u64::from_le_bytes(read_array::<8>(bytes, 12).ok_or(WireRecordError::Length {
                actual: bytes.len(),
            })?);
        let byte_count =
            u64::from_le_bytes(read_array::<8>(bytes, 20).ok_or(WireRecordError::Length {
                actual: bytes.len(),
            })?);
        let local_port =
            u16::from_be_bytes(read_array::<2>(bytes, 28).ok_or(WireRecordError::Length {
                actual: bytes.len(),
            })?);
        let remote_port =
            u16::from_be_bytes(read_array::<2>(bytes, 30).ok_or(WireRecordError::Length {
                actual: bytes.len(),
            })?);
        let local_addr = decode_address(family, &bytes[32..48])?;
        let remote_addr = decode_address(family, &bytes[48..64])?;
        // Zero is the wire's "unavailable" marker, so kernels without
        // `bpf_get_socket_cookie` degrade to an absent cookie rather than a bogus one.
        let cookie = read_array::<8>(bytes, COOKIE_OFFSET)
            .map(u64::from_le_bytes)
            .filter(|value| *value != 0);
        let if_index = read_array::<4>(bytes, IFINDEX_OFFSET)
            .map(u32::from_le_bytes)
            .filter(|value| *value != 0);
        Ok(Self {
            kind,
            key: FlowKey {
                protocol,
                local_addr,
                local_port,
                remote_addr,
                remote_port,
            },
            pid,
            timestamp,
            byte_count,
            cookie,
            if_index,
        })
    }

    /// Converts a byte operation into the public incremental representation.
    pub fn byte_delta(self) -> Option<ByteDelta> {
        match self.kind {
            WireFlowKind::Sent => Some(ByteDelta {
                sent: self.byte_count,
                received: 0,
            }),
            WireFlowKind::Received => Some(ByteDelta {
                sent: 0,
                received: self.byte_count,
            }),
            WireFlowKind::Open | WireFlowKind::Close | WireFlowKind::Owner => None,
        }
    }

    /// Turns a decoded ring record into a single collector ingress event.
    ///
    /// Byte records carry any already-available cookie on the observation so the
    /// collector can reconcile identity before applying the delta.
    pub fn backend_event(self, timestamp: u64) -> Option<BackendEvent> {
        let cookie = self.cookie.map(|value| SocketCookie {
            value,
            source: CookieSource::LinuxSockCookie,
        });
        match self.kind {
            WireFlowKind::Open => Some(BackendEvent::Opened {
                key: self.key,
                pid: self.pid,
                cookie,
                timestamp,
                if_index: self.if_index,
            }),
            WireFlowKind::Close => {
                if self.key.protocol == Protocol::Udp && self.key.local_port != 0 {
                    Some(BackendEvent::LocalEndpointClosed {
                        protocol: Protocol::Udp,
                        local_addr: self.key.local_addr,
                        local_port: self.key.local_port,
                        cookie,
                        timestamp,
                    })
                } else {
                    Some(BackendEvent::Closed {
                        pid: 0,
                        key: self.key,
                        timestamp,
                    })
                }
            }
            WireFlowKind::Sent | WireFlowKind::Received => {
                let delta = self.byte_delta()?;
                Some(BackendEvent::Bytes {
                    key: self.key,
                    pid: self.pid,
                    delta,
                    timestamp,
                    if_index: self.if_index,
                    cookie,
                })
            }
            WireFlowKind::Owner => None,
        }
    }

    /// Turns a decoded ring record into collector ingress events.
    ///
    /// Ordinary TCP/UDP records produce one observation. Kept as a thin wrapper around
    /// [`Self::backend_event`] for callers that iterate.
    pub fn backend_events(self, timestamp: u64) -> Vec<BackendEvent> {
        self.backend_event(timestamp).into_iter().collect()
    }
}

fn decode_address(family: u8, bytes: &[u8]) -> Result<IpAddr, WireRecordError> {
    match family {
        4 => Ok(IpAddr::V4(Ipv4Addr::new(
            bytes[0], bytes[1], bytes[2], bytes[3],
        ))),
        6 => read_array::<16>(bytes, 0)
            .map(Ipv6Addr::from)
            .map(IpAddr::V6)
            .ok_or(WireRecordError::Length {
                actual: bytes.len(),
            }),
        value => Err(WireRecordError::AddressFamily(value)),
    }
}

fn read_array<const N: usize>(bytes: &[u8], offset: usize) -> Option<[u8; N]> {
    bytes.get(offset..offset.checked_add(N)?)?.try_into().ok()
}

/// Validation error for a binary native record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WireRecordError {
    /// Record has the wrong fixed size.
    Length {
        /// Supplied byte count.
        actual: usize,
    },
    /// Magic prefix does not match.
    Magic,
    /// Unsupported record version.
    Version(u8),
    /// Unsupported event kind.
    Kind(u8),
    /// Protocol is not TCP or UDP.
    Protocol(u8),
    /// Address family is not IPv4 or IPv6.
    AddressFamily(u8),
}

impl Display for WireRecordError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Length { actual } => write!(
                formatter,
                "record length is {actual}, expected {WIRE_RECORD_LEN_V1}, {WIRE_RECORD_LEN_V2}, or {WIRE_RECORD_LEN_V3}"
            ),
            Self::Magic => formatter.write_str("invalid record magic"),
            Self::Version(version) => write!(formatter, "unsupported record version {version}"),
            Self::Kind(kind) => write!(formatter, "unsupported flow event kind {kind}"),
            Self::Protocol(protocol) => write!(formatter, "unsupported IP protocol {protocol}"),
            Self::AddressFamily(family) => {
                write!(formatter, "unsupported address family {family}")
            }
        }
    }
}

impl Error for WireRecordError {}

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

    fn write_common(bytes: &mut [u8], version: u8) {
        bytes[0..4].copy_from_slice(b"NMT1");
        bytes[4] = version;
        bytes[5] = 3;
        bytes[6] = 6;
        bytes[7] = 4;
        bytes[8..12].copy_from_slice(&42_u32.to_le_bytes());
        bytes[12..20].copy_from_slice(&123_u64.to_le_bytes());
        bytes[20..28].copy_from_slice(&999_u64.to_le_bytes());
        bytes[28..30].copy_from_slice(&50_000_u16.to_be_bytes());
        bytes[30..32].copy_from_slice(&443_u16.to_be_bytes());
        bytes[32..36].copy_from_slice(&[192, 0, 2, 1]);
        bytes[48..52].copy_from_slice(&[198, 51, 100, 2]);
    }

    fn fixture() -> [u8; WIRE_RECORD_LEN_V1] {
        let mut bytes = [0_u8; WIRE_RECORD_LEN_V1];
        write_common(&mut bytes, VERSION_V1);
        bytes
    }

    fn fixture_v3(cookie: u64, if_index: u32) -> [u8; WIRE_RECORD_LEN_V3] {
        let mut bytes = [0_u8; WIRE_RECORD_LEN_V3];
        write_common(&mut bytes, VERSION_V3);
        bytes[COOKIE_OFFSET..COOKIE_OFFSET + 8].copy_from_slice(&cookie.to_le_bytes());
        bytes[IFINDEX_OFFSET..].copy_from_slice(&if_index.to_le_bytes());
        bytes
    }

    fn fixture_v2(cookie: u64) -> [u8; WIRE_RECORD_LEN_V2] {
        let mut bytes = [0_u8; WIRE_RECORD_LEN_V2];
        write_common(&mut bytes, VERSION_V2);
        bytes[COOKIE_OFFSET..].copy_from_slice(&cookie.to_le_bytes());
        bytes
    }

    proptest! {
        #[test]
        fn arbitrary_bytes_never_panic(
            bytes in proptest::collection::vec(any::<u8>(), 0..96),
        ) {
            let _ = WireFlowRecord::decode(&bytes);
        }

        #[test]
        fn mutated_records_never_panic(
            edits in proptest::collection::vec((any::<usize>(), any::<u8>()), 0..8),
            keep in 0_usize..=WIRE_RECORD_LEN_V3,
        ) {
            let _ = WireFlowRecord::decode(&mutate(fixture_v3(7, 2).to_vec(), &edits, keep));
        }

        #[test]
        fn version_three_fields_round_trip(
            pid in any::<u32>(),
            byte_count in any::<u64>(),
            local_port in any::<u16>(),
            cookie in 1_u64..,
            if_index in 1_u32..,
        ) {
            let mut bytes = fixture_v3(cookie, if_index);
            bytes[8..12].copy_from_slice(&pid.to_le_bytes());
            bytes[20..28].copy_from_slice(&byte_count.to_le_bytes());
            bytes[28..30].copy_from_slice(&local_port.to_be_bytes());
            let record = WireFlowRecord::decode(&bytes).expect("valid record");
            prop_assert_eq!(record.pid, pid);
            prop_assert_eq!(record.byte_count, byte_count);
            prop_assert_eq!(record.key.local_port, local_port);
            prop_assert_eq!(record.cookie, Some(cookie));
            prop_assert_eq!(record.if_index, Some(if_index));
        }
    }

    #[test]
    fn decodes_golden_ipv4_record() {
        let record = WireFlowRecord::decode(&fixture()).expect("valid fixture");
        assert_eq!(record.kind, WireFlowKind::Sent);
        assert_eq!(record.pid, 42);
        assert_eq!(record.key.local_port, 50_000);
        assert_eq!(record.key.remote_addr.to_string(), "198.51.100.2");
        assert_eq!(
            record.byte_delta(),
            Some(ByteDelta {
                sent: 999,
                received: 0
            })
        );
    }

    #[test]
    fn version_one_records_still_decode_without_a_cookie() {
        let record = WireFlowRecord::decode(&fixture()).expect("v1 fixture");
        assert_eq!(record.cookie, None);
    }

    #[test]
    fn version_two_records_carry_a_cookie() {
        let record = WireFlowRecord::decode(&fixture_v2(0xdead_beef)).expect("v2 fixture");
        assert_eq!(record.cookie, Some(0xdead_beef));
        assert_eq!(record.pid, 42, "shared fields keep their v1 offsets");
        assert_eq!(record.key.local_port, 50_000);
    }

    #[test]
    fn version_three_records_carry_an_interface_index() {
        let record = WireFlowRecord::decode(&fixture_v3(7, 3)).expect("v3 fixture");
        assert_eq!(record.cookie, Some(7));
        assert_eq!(record.if_index, Some(3));
    }

    #[test]
    fn a_zero_cookie_means_unavailable() {
        let record = WireFlowRecord::decode(&fixture_v2(0)).expect("v2 fixture");
        assert_eq!(
            record.cookie, None,
            "kernels without bpf_get_socket_cookie must degrade, not report cookie zero"
        );
    }

    #[test]
    fn a_version_two_length_record_claiming_version_one_is_rejected() {
        let mut bytes = fixture_v2(7);
        bytes[4] = VERSION_V1;
        assert!(matches!(
            WireFlowRecord::decode(&bytes),
            Err(WireRecordError::Length { actual: 72 })
        ));
    }

    #[test]
    fn unknown_versions_are_rejected() {
        let mut bytes = fixture_v2(7);
        bytes[4] = 4;
        assert_eq!(
            WireFlowRecord::decode(&bytes),
            Err(WireRecordError::Version(4))
        );
    }

    #[test]
    fn every_truncated_length_is_rejected_without_panic() {
        let v1 = fixture();
        for length in 0..WIRE_RECORD_LEN_V1 {
            assert!(matches!(
                WireFlowRecord::decode(&v1[..length]),
                Err(WireRecordError::Length { actual }) if actual == length
            ));
        }
        let v2 = fixture_v2(7);
        for length in 0..WIRE_RECORD_LEN_V2 {
            assert!(matches!(
                WireFlowRecord::decode(&v2[..length]),
                Err(WireRecordError::Length { actual }) if actual == length
            ));
        }
    }

    #[test]
    fn arbitrary_records_never_panic() {
        let mut state = 0x9e37_79b9_u32;
        for _ in 0..10_000 {
            let mut bytes = [0_u8; WIRE_RECORD_LEN_V3];
            for byte in &mut bytes {
                state ^= state << 13;
                state ^= state >> 17;
                state ^= state << 5;
                *byte = state.to_le_bytes()[0];
            }
            let _ = WireFlowRecord::decode(&bytes);
            let _ = WireFlowRecord::decode(&bytes[..WIRE_RECORD_LEN_V1]);
        }
    }

    fn sample_record(kind: WireFlowKind, cookie: Option<u64>) -> WireFlowRecord {
        WireFlowRecord {
            kind,
            key: WireFlowRecord::decode(&fixture()).expect("fixture").key,
            pid: 42,
            timestamp: 123,
            byte_count: 999,
            cookie,
            if_index: None,
        }
    }

    #[test]
    fn open_records_carry_the_socket_cookie() {
        let cookie = SocketCookie {
            value: 7,
            source: CookieSource::LinuxSockCookie,
        };
        assert_eq!(
            sample_record(WireFlowKind::Open, Some(7)).backend_events(50),
            vec![BackendEvent::Opened {
                key: sample_record(WireFlowKind::Open, Some(7)).key,
                pid: 42,
                cookie: Some(cookie),
                timestamp: 50,
                if_index: None,
            }]
        );
    }

    #[test]
    fn udp_close_drains_the_local_bind() {
        let mut record = sample_record(WireFlowKind::Close, None);
        record.key.protocol = Protocol::Udp;
        assert_eq!(
            record.backend_events(50),
            vec![BackendEvent::LocalEndpointClosed {
                protocol: Protocol::Udp,
                local_addr: record.key.local_addr,
                local_port: record.key.local_port,
                cookie: None,
                timestamp: 50,
            }]
        );
    }

    #[test]
    fn byte_records_carry_cookies_on_the_observation() {
        let record = sample_record(WireFlowKind::Sent, Some(9));
        let events = record.backend_events(50);
        assert_eq!(events.len(), 1);
        assert!(matches!(
            events[0],
            BackendEvent::Bytes {
                cookie: Some(SocketCookie {
                    value: 9,
                    source: CookieSource::LinuxSockCookie
                }),
                ..
            }
        ));
    }

    #[test]
    fn owner_records_decode_but_emit_no_collector_event() {
        let mut bytes = fixture_v3(7, 1);
        bytes[5] = 5;
        let record = WireFlowRecord::decode(&bytes).expect("owner record");
        assert_eq!(record.kind, WireFlowKind::Owner);
        assert_eq!(record.byte_delta(), None);
        assert!(record.backend_events(50).is_empty());
    }

    #[test]
    fn byte_records_without_cookies_do_not_emit_identity() {
        let events = sample_record(WireFlowKind::Received, None).backend_events(50);
        assert_eq!(events.len(), 1);
        assert!(matches!(events[0], BackendEvent::Bytes { .. }));
    }
}
