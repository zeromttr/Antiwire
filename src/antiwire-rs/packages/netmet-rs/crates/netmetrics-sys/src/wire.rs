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

/// Smallest prefix that carries magic, version and kind.
const HEADER_LEN: usize = 6;

/// Offset of the kind every record carries after its magic and version.
const KIND_OFFSET: usize = 5;

/// Kind of a record reporting that a process replaced its program.
const KIND_PROCESS_EXEC: u8 = 6;
/// Kind of a record reporting that a process ended.
const KIND_PROCESS_EXIT: u8 = 7;
/// Kind of a flow record reporting that a TCP connection is no longer established. Kinds 6
/// and 7 belong to the process records, which share the ring.
const KIND_FLOW_FINISHING: u8 = 8;

/// Byte size of a process record: the six-byte header and two reserved bytes, then the
/// PID, the event time, the start time and a 16-byte name.
pub const WIRE_PROCESS_RECORD_LEN: usize = 44;

/// Offset and length of the `comm` field of a process record.
const PROCESS_NAME_OFFSET: usize = 28;
const PROCESS_NAME_LEN: usize = 16;

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
    /// The process using the socket from its own system call: at connect, when accept
    /// returns it, or at send entry, before the packet can be delivered. Carries no bytes.
    Owner,
    /// The TCP connection is no longer established, and its socket is still open.
    Finishing,
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
    /// The kernel's socket cookie, absent on version 1 records or while the kernel has not
    /// assigned one: it does so only when something first asks for the cookie, which the
    /// object's cookie programs do where the kernel lets them.
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
            KIND_FLOW_FINISHING => WireFlowKind::Finishing,
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
        // Zero is the wire's "unavailable" marker: a socket the kernel has not given a
        // cookie yet degrades to an absent cookie rather than a bogus one.
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
            WireFlowKind::Open
            | WireFlowKind::Close
            | WireFlowKind::Owner
            | WireFlowKind::Finishing => None,
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
            WireFlowKind::Finishing => Some(BackendEvent::Finishing {
                key: self.key,
                timestamp,
            }),
            // The owner is known before any byte record names it, at connect or accept. With
            // the socket's cookie it enriches the flow the lifecycle records report, and
            // never opens one: a connect that fails has an owner and no flow.
            WireFlowKind::Owner => cookie.map(|cookie| BackendEvent::CookieResolved {
                key: self.key,
                pid: self.pid,
                cookie,
                timestamp,
            }),
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

/// What a [`WireProcessRecord`] reports.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WireProcessKind {
    /// The process replaced its program, keeping its PID and start time.
    Exec,
    /// The last thread of the process exited.
    Exit,
}

/// A process changing its program or ending, from the same ring as the flow records.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WireProcessRecord {
    /// What happened.
    pub kind: WireProcessKind,
    /// The process, as `/proc` numbers it.
    pub pid: u32,
    /// Native source timestamp (`CLOCK_MONOTONIC` nanoseconds).
    pub timestamp: u64,
    /// When the process started, in nanoseconds since boot: the value
    /// `/proc/<pid>/stat` reports as `starttime`, before its conversion to clock ticks.
    pub start_boottime_ns: u64,
    /// The kernel's name for the process, as `/proc/<pid>/comm` shows it.
    pub name: String,
}

impl WireProcessRecord {
    /// Parses a fixed-width process record without unaligned reads.
    ///
    /// # Errors
    ///
    /// Returns a validation error for an incorrect length, magic, version or kind.
    pub fn decode(bytes: &[u8]) -> Result<Self, WireRecordError> {
        let short = || WireRecordError::Length {
            actual: bytes.len(),
        };
        if bytes.len() < HEADER_LEN {
            return Err(short());
        }
        let magic = read_array::<4>(bytes, 0).ok_or_else(short)?;
        if u32::from_le_bytes(magic) != MAGIC {
            return Err(WireRecordError::Magic);
        }
        let [version, kind] = read_array::<2>(bytes, 4).ok_or_else(short)?;
        if version != VERSION_V3 {
            return Err(WireRecordError::Version(version));
        }
        let kind = match kind {
            KIND_PROCESS_EXEC => WireProcessKind::Exec,
            KIND_PROCESS_EXIT => WireProcessKind::Exit,
            value => return Err(WireRecordError::Kind(value)),
        };
        if bytes.len() != WIRE_PROCESS_RECORD_LEN {
            return Err(short());
        }
        let name = read_array::<PROCESS_NAME_LEN>(bytes, PROCESS_NAME_OFFSET).ok_or_else(short)?;
        let name = name.split(|byte| *byte == 0).next().unwrap_or_default();
        Ok(Self {
            kind,
            pid: read_array::<4>(bytes, 8)
                .map(u32::from_le_bytes)
                .ok_or_else(short)?,
            timestamp: read_array::<8>(bytes, 12)
                .map(u64::from_le_bytes)
                .ok_or_else(short)?,
            start_boottime_ns: read_array::<8>(bytes, 20)
                .map(u64::from_le_bytes)
                .ok_or_else(short)?,
            name: String::from_utf8_lossy(name).into_owned(),
        })
    }
}

/// Any record the eBPF ring carries.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WireRecord {
    /// A socket's lifecycle, bytes or owner.
    Flow(WireFlowRecord),
    /// A process changing its program or ending.
    Process(WireProcessRecord),
}

impl WireRecord {
    /// Parses whichever record `bytes` holds, told apart by its kind.
    ///
    /// # Errors
    ///
    /// Returns the validation error of the record type the kind selects. A kind neither
    /// type knows is reported by the flow decoder.
    pub fn decode(bytes: &[u8]) -> Result<Self, WireRecordError> {
        match bytes.get(KIND_OFFSET) {
            Some(&(KIND_PROCESS_EXEC | KIND_PROCESS_EXIT)) => {
                WireProcessRecord::decode(bytes).map(Self::Process)
            }
            _ => WireFlowRecord::decode(bytes).map(Self::Flow),
        }
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
    use netmetrics_core::test_support::mutate;
    use proptest::prelude::*;

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

    /// An exit record for PID 4242, `curl`, started 9 seconds after boot.
    fn process_fixture() -> [u8; WIRE_PROCESS_RECORD_LEN] {
        let mut bytes = [0_u8; WIRE_PROCESS_RECORD_LEN];
        bytes[0..4].copy_from_slice(b"NMT1");
        bytes[4] = VERSION_V3;
        bytes[KIND_OFFSET] = KIND_PROCESS_EXIT;
        bytes[8..12].copy_from_slice(&4242_u32.to_le_bytes());
        bytes[12..20].copy_from_slice(&123_u64.to_le_bytes());
        bytes[20..28].copy_from_slice(&9_000_000_000_u64.to_le_bytes());
        bytes[PROCESS_NAME_OFFSET..PROCESS_NAME_OFFSET + 4].copy_from_slice(b"curl");
        bytes
    }

    proptest! {
        #[test]
        fn arbitrary_bytes_never_panic(
            bytes in proptest::collection::vec(any::<u8>(), 0..96),
        ) {
            let _ = WireFlowRecord::decode(&bytes);
            let _ = WireRecord::decode(&bytes);
        }

        #[test]
        fn mutated_records_never_panic(
            edits in proptest::collection::vec((any::<usize>(), any::<u8>()), 0..8),
            keep in 0_usize..=WIRE_RECORD_LEN_V3,
        ) {
            let _ = WireFlowRecord::decode(&mutate(fixture_v3(7, 2).to_vec(), &edits, keep));
            let _ = WireRecord::decode(&mutate(process_fixture().to_vec(), &edits, keep));
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
    fn a_process_record_carries_who_exited_and_when_it_started() {
        let record = WireRecord::decode(&process_fixture()).expect("process record");
        assert_eq!(
            record,
            WireRecord::Process(WireProcessRecord {
                kind: WireProcessKind::Exit,
                pid: 4242,
                timestamp: 123,
                start_boottime_ns: 9_000_000_000,
                name: "curl".to_owned(),
            })
        );
        let mut exec = process_fixture();
        exec[KIND_OFFSET] = KIND_PROCESS_EXEC;
        assert!(matches!(
            WireRecord::decode(&exec),
            Ok(WireRecord::Process(WireProcessRecord {
                kind: WireProcessKind::Exec,
                ..
            }))
        ));
    }

    #[test]
    fn a_process_name_filling_its_field_needs_no_terminator() {
        let mut bytes = process_fixture();
        bytes[PROCESS_NAME_OFFSET..].copy_from_slice(b"0123456789abcdef");
        let WireRecord::Process(record) = WireRecord::decode(&bytes).expect("process record")
        else {
            panic!("a process kind decodes as a process record");
        };
        assert_eq!(record.name, "0123456789abcdef");
    }

    #[test]
    fn a_process_record_of_the_wrong_length_or_version_is_rejected() {
        assert_eq!(
            WireRecord::decode(&process_fixture()[..WIRE_PROCESS_RECORD_LEN - 1]),
            Err(WireRecordError::Length { actual: 43 })
        );
        let mut older = process_fixture();
        older[4] = VERSION_V2;
        assert_eq!(
            WireRecord::decode(&older),
            Err(WireRecordError::Version(VERSION_V2))
        );
        // The flow decoder does not know the kind and says so.
        assert_eq!(
            WireFlowRecord::decode(&fixture_v3(1, 1)).map(|record| record.kind),
            Ok(WireFlowKind::Sent)
        );
        let mut flow_sized = fixture_v3(1, 1);
        flow_sized[KIND_OFFSET] = KIND_PROCESS_EXIT;
        assert_eq!(
            WireFlowRecord::decode(&flow_sized),
            Err(WireRecordError::Kind(KIND_PROCESS_EXIT))
        );
    }

    #[test]
    fn a_flow_record_decodes_as_a_flow() {
        assert_eq!(
            WireRecord::decode(&fixture_v3(7, 3)),
            WireFlowRecord::decode(&fixture_v3(7, 3)).map(WireRecord::Flow)
        );
    }

    /// An owner is known at connect or accept, before the flow carries a byte.
    #[test]
    fn an_owner_record_with_a_cookie_names_the_owner_of_a_tracked_flow() {
        let mut bytes = fixture_v3(7, 0);
        bytes[KIND_OFFSET] = 5;
        let record = WireFlowRecord::decode(&bytes).expect("owner record");
        assert_eq!(record.kind, WireFlowKind::Owner);
        assert_eq!(record.byte_delta(), None);
        assert_eq!(
            record.backend_event(9),
            Some(BackendEvent::CookieResolved {
                key: record.key,
                pid: 42,
                cookie: SocketCookie {
                    value: 7,
                    source: CookieSource::LinuxSockCookie,
                },
                timestamp: 9,
            })
        );

        let mut without_cookie = fixture_v3(0, 0);
        without_cookie[KIND_OFFSET] = 5;
        let record = WireFlowRecord::decode(&without_cookie).expect("owner record");
        assert_eq!(
            record.backend_event(9),
            None,
            "without the socket's identity an owner record cannot enrich a flow"
        );
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
            "a socket without a cookie must degrade, not report cookie zero"
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
    fn a_finishing_record_reports_the_flow_finishing() {
        let mut bytes = fixture();
        bytes[5] = KIND_FLOW_FINISHING;
        let record = WireFlowRecord::decode(&bytes).expect("finishing record");
        assert_eq!(record.kind, WireFlowKind::Finishing);
        assert_eq!(record.byte_delta(), None);
        assert_eq!(
            record.backend_events(50),
            vec![BackendEvent::Finishing {
                key: record.key,
                timestamp: 50,
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
    fn byte_records_without_cookies_do_not_emit_identity() {
        let events = sample_record(WireFlowKind::Received, None).backend_events(50);
        assert_eq!(events.len(), 1);
        assert!(matches!(events[0], BackendEvent::Bytes { .. }));
    }
}
