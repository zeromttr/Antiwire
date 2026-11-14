//! IP Helper table reads, row decoding, and direct socket-owner queries.

use super::{
    ListenerOwner, OwnedSocket, OwnedUdpEndpoint, TcpSeen, UdpBind, insert_tcp_listener,
    insert_udp_bind,
};
use netmetrics_core::{FlowKey, LocalEndpoint, Protocol, SocketOwnerSnapshot, TcpState};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::{Mutex, PoisonError};
use windows::Win32::Foundation::{ERROR_INSUFFICIENT_BUFFER, NO_ERROR};
use windows::Win32::NetworkManagement::IpHelper::{
    GetExtendedTcpTable, GetExtendedUdpTable, MIB_TCP_STATE, MIB_TCP_STATE_CLOSE_WAIT,
    MIB_TCP_STATE_CLOSED, MIB_TCP_STATE_CLOSING, MIB_TCP_STATE_ESTAB, MIB_TCP_STATE_FIN_WAIT1,
    MIB_TCP_STATE_FIN_WAIT2, MIB_TCP_STATE_LAST_ACK, MIB_TCP_STATE_LISTEN, MIB_TCP_STATE_SYN_RCVD,
    MIB_TCP_STATE_SYN_SENT, MIB_TCP_STATE_TIME_WAIT, MIB_TCP6ROW_OWNER_MODULE,
    MIB_TCP6ROW_OWNER_PID, MIB_TCP6TABLE_OWNER_MODULE, MIB_TCP6TABLE_OWNER_PID,
    MIB_TCPROW_OWNER_MODULE, MIB_TCPROW_OWNER_PID, MIB_TCPTABLE_OWNER_MODULE,
    MIB_TCPTABLE_OWNER_PID, MIB_UDP6ROW_OWNER_MODULE, MIB_UDP6TABLE_OWNER_MODULE,
    MIB_UDPROW_OWNER_MODULE, MIB_UDPTABLE_OWNER_MODULE, TCP_TABLE_OWNER_MODULE_ALL,
    TCP_TABLE_OWNER_PID_ALL, UDP_TABLE_OWNER_MODULE,
};
use windows::Win32::Networking::WinSock::{AF_INET, AF_INET6};

/// The state a TCP row carries in `dwState`, which holds a `MIB_TCP_STATE` value
/// ([`MIB_TCPROW_OWNER_PID`](https://learn.microsoft.com/windows/win32/api/tcpmib/ns-tcpmib-mib_tcprow_owner_pid)).
///
/// `None` for a value that is no state of a connection: `MIB_TCP_STATE_DELETE_TCB`, or one
/// that page does not list.
///
/// An established row ([`TcpState::is_established`]) is a flow: the first TCP poll opens
/// one for it, the IP Helper fallback lists it, and it is counted as an active connection.
/// A later ETW disconnect closes such a flow. Rows in the closing states have already
/// disconnected, so a flow opened from one would sit until idle eviction. Nor does a row
/// say whether the process still holds a connection it has sent its FIN on: closing the
/// socket leaves the row's state and its owning process as they were.
pub(super) fn tcp_state(state: u32) -> Option<TcpState> {
    Some(match MIB_TCP_STATE(i32::try_from(state).ok()?) {
        MIB_TCP_STATE_CLOSED => TcpState::Closed,
        MIB_TCP_STATE_LISTEN => TcpState::Listen,
        MIB_TCP_STATE_SYN_SENT => TcpState::SynSent,
        MIB_TCP_STATE_SYN_RCVD => TcpState::SynReceived,
        MIB_TCP_STATE_ESTAB => TcpState::Established,
        MIB_TCP_STATE_FIN_WAIT1 => TcpState::FinWait1,
        MIB_TCP_STATE_FIN_WAIT2 => TcpState::FinWait2,
        MIB_TCP_STATE_CLOSE_WAIT => TcpState::CloseWait,
        MIB_TCP_STATE_CLOSING => TcpState::Closing,
        MIB_TCP_STATE_LAST_ACK => TcpState::LastAck,
        MIB_TCP_STATE_TIME_WAIT => TcpState::TimeWait,
        _ => return None,
    })
}

/// Owner-module ports are stored host-width but hold a network-order `u16`.
fn port_from_dword(value: u32) -> u16 {
    #[allow(clippy::cast_possible_truncation)]
    u16::from_be(value as u16)
}

/// The fields read from an IP Helper row. The IPv4 and IPv6 rows differ only in how they
/// store an address, so every decoder below is written once against these traits.
///
/// # Safety
///
/// `FAMILY`, `CLASS`, and `TABLE_HEADER` must describe the table whose rows are `Self`:
/// [`fetch_rows`] reinterprets that table's bytes as `Self` on their word.
pub(super) unsafe trait OwnerRow: Sized {
    const FAMILY: u16;
    const CLASS: TableClass;
    /// Offset of the row array in the table struct.
    const TABLE_HEADER: usize;

    fn local_addr(&self) -> IpAddr;
    fn local_port(&self) -> u16;
    fn pid(&self) -> u32;
}

pub(super) trait TcpRow: OwnerRow {
    fn remote_addr(&self) -> IpAddr;
    fn remote_port(&self) -> u16;
    /// The connection's state, when `dwState` names one ([`tcp_state`]).
    fn state(&self) -> Option<TcpState>;
}

/// Rows from the owner-module table classes, which carry the socket's creation timestamp.
pub(super) trait CreatedRow: OwnerRow {
    fn created(&self) -> i64;
}

fn ipv4(address: u32) -> IpAddr {
    IpAddr::V4(Ipv4Addr::from(address.to_ne_bytes()))
}

fn ipv6(address: [u8; 16]) -> IpAddr {
    IpAddr::V6(Ipv6Addr::from(address))
}

macro_rules! owner_row {
    ($row:ty, $table:ty, $family:expr, $class:expr, $address:ident, $local:ident) => {
        // SAFETY: `$table` is the table `$class` returns for `$family`, and its rows are `$row`.
        unsafe impl OwnerRow for $row {
            const FAMILY: u16 = $family.0;
            const CLASS: TableClass = $class;
            const TABLE_HEADER: usize = std::mem::offset_of!($table, table);

            fn local_addr(&self) -> IpAddr {
                $address(self.$local)
            }
            fn local_port(&self) -> u16 {
                port_from_dword(self.dwLocalPort)
            }
            fn pid(&self) -> u32 {
                self.dwOwningPid
            }
        }
    };
}

macro_rules! tcp_row {
    (
        $row:ty,
        $table:ty,
        $family:expr,
        $class:expr,
        $address:ident,
        $local:ident,
        $remote:ident
    ) => {
        owner_row!($row, $table, $family, $class, $address, $local);
        impl TcpRow for $row {
            fn remote_addr(&self) -> IpAddr {
                $address(self.$remote)
            }
            fn remote_port(&self) -> u16 {
                port_from_dword(self.dwRemotePort)
            }
            fn state(&self) -> Option<TcpState> {
                tcp_state(self.dwState)
            }
        }
    };
}

macro_rules! created_row {
    ($($row:ty),*) => {
        $(impl CreatedRow for $row {
            fn created(&self) -> i64 {
                self.liCreateTimestamp
            }
        })*
    };
}

tcp_row!(
    MIB_TCPROW_OWNER_MODULE,
    MIB_TCPTABLE_OWNER_MODULE,
    AF_INET,
    TableClass::TcpOwnerModule,
    ipv4,
    dwLocalAddr,
    dwRemoteAddr
);
tcp_row!(
    MIB_TCP6ROW_OWNER_MODULE,
    MIB_TCP6TABLE_OWNER_MODULE,
    AF_INET6,
    TableClass::TcpOwnerModule,
    ipv6,
    ucLocalAddr,
    ucRemoteAddr
);
tcp_row!(
    MIB_TCPROW_OWNER_PID,
    MIB_TCPTABLE_OWNER_PID,
    AF_INET,
    TableClass::TcpOwnerPid,
    ipv4,
    dwLocalAddr,
    dwRemoteAddr
);
tcp_row!(
    MIB_TCP6ROW_OWNER_PID,
    MIB_TCP6TABLE_OWNER_PID,
    AF_INET6,
    TableClass::TcpOwnerPid,
    ipv6,
    ucLocalAddr,
    ucRemoteAddr
);
owner_row!(
    MIB_UDPROW_OWNER_MODULE,
    MIB_UDPTABLE_OWNER_MODULE,
    AF_INET,
    TableClass::UdpOwnerModule,
    ipv4,
    dwLocalAddr
);
owner_row!(
    MIB_UDP6ROW_OWNER_MODULE,
    MIB_UDP6TABLE_OWNER_MODULE,
    AF_INET6,
    TableClass::UdpOwnerModule,
    ipv6,
    ucLocalAddr
);
created_row!(
    MIB_TCPROW_OWNER_MODULE,
    MIB_TCP6ROW_OWNER_MODULE,
    MIB_UDPROW_OWNER_MODULE,
    MIB_UDP6ROW_OWNER_MODULE
);

/// Whether a TCP row is an owned connection: not a listener, and with both ports set.
fn is_owned_connection(row: &impl TcpRow) -> bool {
    row.state() != Some(TcpState::Listen)
        && row.pid() != 0
        && row.local_port() != 0
        && row.remote_port() != 0
}

/// Whether a TCP row's state is established ([`TcpState::is_established`]).
fn has_established_state(row: &impl TcpRow) -> bool {
    row.state().is_some_and(TcpState::is_established)
}

pub(super) fn tcp_socket<R: TcpRow + CreatedRow>(row: &R) -> Option<OwnedSocket> {
    is_owned_connection(row).then(|| OwnedSocket {
        key: FlowKey {
            protocol: Protocol::Tcp,
            local_addr: row.local_addr(),
            local_port: row.local_port(),
            remote_addr: row.remote_addr(),
            remote_port: row.remote_port(),
        },
        pid: row.pid(),
        created: row.created(),
    })
}

fn tcp_listener<R: TcpRow + CreatedRow>(row: &R) -> Option<ListenerOwner> {
    if row.state() != Some(TcpState::Listen) || row.pid() == 0 || row.local_port() == 0 {
        return None;
    }
    Some((
        (row.local_addr(), row.local_port()),
        TcpSeen {
            pid: row.pid(),
            created: row.created(),
            established: false,
        },
    ))
}

fn udp_endpoint(row: &impl CreatedRow) -> Option<OwnedUdpEndpoint> {
    if row.pid() == 0 || row.local_port() == 0 {
        return None;
    }
    Some(OwnedUdpEndpoint {
        local_addr: row.local_addr(),
        local_port: row.local_port(),
        pid: row.pid(),
        created: row.created(),
    })
}

/// Maps owner-module rows onto keyed sockets.
///
/// Listeners, unowned rows, and rows missing an endpoint are skipped: they are not flows and
/// would only add noise to the cookie stream.
pub(super) fn map_tcp_rows<R: TcpRow + CreatedRow>(rows: &[R]) -> Vec<OwnedSocket> {
    rows.iter().filter_map(tcp_socket).collect()
}

pub(super) fn map_tcp_listeners<R: TcpRow + CreatedRow>(rows: &[R]) -> Vec<ListenerOwner> {
    rows.iter().filter_map(tcp_listener).collect()
}

/// Byte buffer whose allocation satisfies the 8-byte alignment the row structs require.
///
/// A plain `Vec<u8>` has an alignment of 1. Reinterpreting one as a slice of rows would be
/// undefined behaviour even though the system allocator happens to over-align in practice.
/// Storage is zeroed only when growing so successful polls reuse the previous allocation.
#[derive(Debug)]
pub(super) struct AlignedBuffer {
    words: Vec<u64>,
    len: usize,
}

impl AlignedBuffer {
    pub(super) const fn new() -> Self {
        Self {
            words: Vec::new(),
            len: 0,
        }
    }

    pub(super) fn ensure(&mut self, len: usize) {
        let words = len.div_ceil(size_of::<u64>());
        if self.words.len() < words {
            self.words.resize(words, 0);
        }
        self.len = len;
    }

    pub(super) fn capacity_bytes(&self) -> usize {
        self.words.len() * size_of::<u64>()
    }

    pub(super) fn as_mut_ptr(&mut self) -> *mut u8 {
        self.words.as_mut_ptr().cast()
    }

    pub(super) fn as_bytes(&self) -> &[u8] {
        // SAFETY: `words` holds at least `len` bytes and `u8` has no alignment requirement.
        unsafe { std::slice::from_raw_parts(self.words.as_ptr().cast::<u8>(), self.len) }
    }
}

pub(super) const MAX_TCP_TABLE_BYTES: u32 = 32 * 1024 * 1024;

#[derive(Clone, Copy)]
pub(super) enum TableClass {
    TcpOwnerModule,
    TcpOwnerPid,
    UdpOwnerModule,
}

fn fetch_into(family: u32, class: TableClass, buffer: &mut AlignedBuffer) -> Result<(), String> {
    fetch_into_with(buffer, |table, size| {
        // SAFETY: a null table pointer with a zero size is the documented sizing probe.
        // On later attempts `buffer` is at least `size` bytes and stays alive for the call.
        unsafe {
            match class {
                TableClass::TcpOwnerModule => {
                    GetExtendedTcpTable(table, size, false, family, TCP_TABLE_OWNER_MODULE_ALL, 0)
                }
                TableClass::TcpOwnerPid => {
                    GetExtendedTcpTable(table, size, false, family, TCP_TABLE_OWNER_PID_ALL, 0)
                }
                TableClass::UdpOwnerModule => {
                    GetExtendedUdpTable(table, size, false, family, UDP_TABLE_OWNER_MODULE, 0)
                }
            }
        }
    })
}

pub(super) fn fetch_into_with(
    buffer: &mut AlignedBuffer,
    mut query: impl FnMut(Option<*mut core::ffi::c_void>, &mut u32) -> u32,
) -> Result<(), String> {
    let mut size = u32::try_from(buffer.len).unwrap_or(0);
    for _ in 0..4 {
        tcp_table_size_ok(size)?;
        if (size as usize) > buffer.capacity_bytes() {
            buffer.ensure(size as usize);
        }
        let table = if size == 0 {
            None
        } else {
            Some(buffer.as_mut_ptr().cast())
        };
        let status = query(table, &mut size);
        if status == NO_ERROR.0 {
            buffer.len = usize::try_from(size)
                .unwrap_or(buffer.len)
                .min(buffer.capacity_bytes());
            return Ok(());
        }
        if status != ERROR_INSUFFICIENT_BUFFER.0 {
            return Err(format!("socket table query failed with {status}"));
        }
        if size == 0 {
            return Err("socket table query asked for a zero-byte buffer".to_owned());
        }
        tcp_table_size_ok(size)?;
    }
    Err("socket table query kept growing beyond retry budget".to_owned())
}

/// Reads the table whose rows are `R` into `buffer` and returns those rows.
pub(super) fn fetch_rows<R: OwnerRow>(buffer: &mut AlignedBuffer) -> Result<&[R], String> {
    fetch_into(R::FAMILY.into(), R::CLASS, buffer)?;
    // SAFETY: `buffer` now holds the table `OwnerRow` ties to `R`, and `AlignedBuffer` is
    // aligned for every row struct.
    Ok(unsafe { table_rows(buffer.as_bytes(), R::TABLE_HEADER) })
}

/// Reads both families of one table class into `buffers` and passes their rows to `read`.
fn with_rows<R4: OwnerRow, R6: OwnerRow, T>(
    buffers: &Mutex<(AlignedBuffer, AlignedBuffer)>,
    read: impl FnOnce(&[R4], &[R6]) -> T,
) -> Result<T, String> {
    let mut buffers = buffers.lock().unwrap_or_else(PoisonError::into_inner);
    let (v4, v6) = &mut *buffers;
    Ok(read(fetch_rows(v4)?, fetch_rows(v6)?))
}

pub(super) fn tcp_table_size_ok(size: u32) -> Result<(), String> {
    if size > MAX_TCP_TABLE_BYTES {
        Err(format!(
            "GetExtendedTcpTable required {size} bytes, cap is {MAX_TCP_TABLE_BYTES}"
        ))
    } else {
        Ok(())
    }
}

/// Reinterprets a fetched buffer as `count` trailing rows of type `R`.
///
/// Returns an empty slice when the buffer is too short for the count the kernel reported,
/// so a malformed table degrades to "no cookies" instead of reading out of bounds.
///
/// # Safety
///
/// `buffer` must be aligned for `R`. Callers pass [`AlignedBuffer::as_bytes`], which is.
pub(super) unsafe fn table_rows<R>(buffer: &[u8], header_len: usize) -> &[R] {
    if buffer.len() < header_len {
        return &[];
    }
    // The header is `dwNumEntries` followed by the row array.
    let Ok(count_bytes) = <[u8; 4]>::try_from(&buffer[..4]) else {
        return &[];
    };
    let count = u32::from_ne_bytes(count_bytes) as usize;
    let available = (buffer.len() - header_len) / size_of::<R>();
    let count = count.min(available);
    if count == 0 {
        return &[];
    }
    // SAFETY: the pointer is within `buffer`, `count` is clamped to the bytes actually
    // present, and IP Helper lays the rows out contiguously after the header.
    unsafe { std::slice::from_raw_parts(buffer.as_ptr().add(header_len).cast::<R>(), count) }
}

/// Reads both TCP owner-module tables into `v4` and `v6`, split into sockets and listeners.
fn read_tcp_owner_tables(
    v4: &mut AlignedBuffer,
    v6: &mut AlignedBuffer,
) -> Result<(Vec<OwnedSocket>, Vec<ListenerOwner>), String> {
    let rows4 = fetch_rows::<MIB_TCPROW_OWNER_MODULE>(v4)?;
    let rows6 = fetch_rows::<MIB_TCP6ROW_OWNER_MODULE>(v6)?;
    let mut sockets = map_tcp_rows(rows4);
    sockets.extend(map_tcp_rows(rows6));
    let mut listeners = map_tcp_listeners(rows4);
    listeners.extend(map_tcp_listeners(rows6));
    Ok((sockets, listeners))
}

/// Reads every established TCP connection with its creation timestamp: the rows the IP
/// Helper fallback lists as flows.
pub(crate) fn snapshot() -> Result<Vec<OwnedSocket>, String> {
    let (mut v4, mut v6) = (AlignedBuffer::new(), AlignedBuffer::new());
    let rows4 = fetch_rows::<MIB_TCPROW_OWNER_MODULE>(&mut v4)?;
    let rows6 = fetch_rows::<MIB_TCP6ROW_OWNER_MODULE>(&mut v6)?;
    Ok(established_sockets(rows4)
        .chain(established_sockets(rows6))
        .collect())
}

/// The owned connections among `rows` whose state is established.
pub(super) fn established_sockets<R: TcpRow + CreatedRow>(
    rows: &[R],
) -> impl Iterator<Item = OwnedSocket> + '_ {
    rows.iter()
        .filter(|row| has_established_state(*row))
        .filter_map(tcp_socket)
}

/// UDP table buffers kept between [`socket_owner_snapshot_for`] and
/// [`owns_local_endpoint`] calls. A buffer already large enough reads its table
/// in one call; a fresh one first needs a sizing call, which made up a third of
/// a UDP scan.
static UDP_TABLE_BUFFERS: Mutex<(AlignedBuffer, AlignedBuffer)> =
    Mutex::new((AlignedBuffer::new(), AlignedBuffer::new()));

fn insert_tcp_owners(owners: &mut SocketOwnerSnapshot) {
    let (mut v4, mut v6) = (AlignedBuffer::new(), AlignedBuffer::new());
    if let Ok((sockets, listeners)) = read_tcp_owner_tables(&mut v4, &mut v6) {
        for socket in sockets {
            owners.insert_tcp(socket.key, socket.pid);
        }
        for ((address, port), owner) in listeners {
            owners.insert_tcp_listener(LocalEndpoint { address, port }, owner.pid);
        }
    }
}

fn insert_udp_owners(owners: &mut SocketOwnerSnapshot) {
    // A failed read leaves UDP out of the snapshot.
    let _ = with_rows(
        &UDP_TABLE_BUFFERS,
        |rows4: &[MIB_UDPROW_OWNER_MODULE], rows6: &[MIB_UDP6ROW_OWNER_MODULE]| {
            let endpoints = rows4
                .iter()
                .filter_map(udp_endpoint)
                .chain(rows6.iter().filter_map(udp_endpoint));
            for endpoint in endpoints {
                owners.insert_udp(
                    LocalEndpoint {
                        address: endpoint.local_addr,
                        port: endpoint.local_port,
                    },
                    endpoint.pid,
                );
            }
        },
    );
}

/// Owners of `protocol`'s sockets only.
///
/// A lookup by local endpoint only ever matches rows of its own protocol, so
/// it gets the same answer from this as from [`socket_owner_snapshot`] while
/// reading half the tables or fewer: a UDP scan skips the TCP tables, which
/// cost twice as much as the UDP ones.
pub fn socket_owner_snapshot_for(protocol: Protocol) -> SocketOwnerSnapshot {
    let mut owners = SocketOwnerSnapshot::default();
    match protocol {
        Protocol::Tcp => insert_tcp_owners(&mut owners),
        Protocol::Udp => insert_udp_owners(&mut owners),
    }
    owners
}

/// TCP 5-tuple, TCP listener, and UDP bind owners from the IP Helper owner-module tables.
pub fn socket_owner_snapshot() -> SocketOwnerSnapshot {
    let mut owners = SocketOwnerSnapshot::default();
    insert_tcp_owners(&mut owners);
    insert_udp_owners(&mut owners);
    owners
}

pub(super) fn ingest_tcp<R: TcpRow + CreatedRow>(rows: &[R], map: &mut HashMap<FlowKey, TcpSeen>) {
    for row in rows {
        if let Some(socket) = tcp_socket(row) {
            map.insert(
                socket.key,
                TcpSeen {
                    pid: socket.pid,
                    created: socket.created,
                    established: has_established_state(row),
                },
            );
        }
    }
}

pub(super) fn ingest_tcp_listeners<R: TcpRow + CreatedRow>(
    rows: &[R],
    map: &mut HashMap<(IpAddr, u16), Option<TcpSeen>>,
) {
    for row in rows {
        if let Some((endpoint, owner)) = tcp_listener(row) {
            insert_tcp_listener(map, endpoint, owner);
        }
    }
}

pub(super) fn ingest_udp<R: CreatedRow>(rows: &[R], map: &mut HashMap<(IpAddr, u16), UdpBind>) {
    for row in rows {
        if let Some(endpoint) = udp_endpoint(row) {
            insert_udp_bind(map, endpoint);
        }
    }
}

pub(super) static OWNER_PID_BUFFERS: Mutex<(AlignedBuffer, AlignedBuffer)> =
    Mutex::new((AlignedBuffer::new(), AlignedBuffer::new()));

/// Counts the established TCP connections in the `OWNER_PID` tables without allocating a
/// row vector.
///
/// A row counts when it is an owned connection whose state is established
/// ([`TcpState::is_established`]). Listeners, handshakes, connections this end has sent its
/// FIN on, and invalid or unowned endpoints are skipped. IPv4 and IPv6 are both included;
/// `GetExtendedTcpTable` does not support BASIC table classes for IPv6, so `OWNER_PID` is
/// used for both families. Failure is distinct from a valid zero count. The two table
/// buffers are retained across calls and grow only when a fetch reports a larger size.
pub fn count_owner_pid_tables() -> Result<u32, String> {
    with_rows(
        &OWNER_PID_BUFFERS,
        |rows4: &[MIB_TCPROW_OWNER_PID], rows6: &[MIB_TCP6ROW_OWNER_PID]| {
            count_established_connections(rows4)
                .saturating_add(count_established_connections(rows6))
        },
    )
}

/// Whether `pid` owns a local TCP or UDP socket that `matches` its bound
/// address and port.
///
/// TCP reads the `OWNER_PID` tables, which list every state: a connection's
/// first packet leaves in `SYN_SENT`, before it would appear as established.
#[cfg(target_arch = "x86_64")]
pub(crate) fn owns_local_endpoint(
    tcp: bool,
    pid: u32,
    matches: impl Fn(IpAddr, u16) -> bool,
) -> Result<bool, String> {
    if tcp {
        with_rows(
            &OWNER_PID_BUFFERS,
            |rows4: &[MIB_TCPROW_OWNER_PID], rows6: &[MIB_TCP6ROW_OWNER_PID]| {
                owned_by(rows4, pid, &matches) || owned_by(rows6, pid, &matches)
            },
        )
    } else {
        with_rows(
            &UDP_TABLE_BUFFERS,
            |rows4: &[MIB_UDPROW_OWNER_MODULE], rows6: &[MIB_UDP6ROW_OWNER_MODULE]| {
                owned_by(rows4, pid, &matches) || owned_by(rows6, pid, &matches)
            },
        )
    }
}

#[cfg(target_arch = "x86_64")]
fn owned_by<R: OwnerRow>(rows: &[R], pid: u32, matches: impl Fn(IpAddr, u16) -> bool) -> bool {
    rows.iter()
        .any(|row| row.pid() == pid && matches(row.local_addr(), row.local_port()))
}

pub(super) fn count_established_connections<R: TcpRow>(rows: &[R]) -> u32 {
    rows.iter()
        .filter(|row| is_owned_connection(*row) && has_established_state(*row))
        .count()
        .try_into()
        .unwrap_or(u32::MAX)
}
