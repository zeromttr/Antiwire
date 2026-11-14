//! Windows UDP socket setup for the loopback DNS listener.

#![allow(unsafe_code)]

use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::os::windows::io::AsRawSocket;

use tracing::warn;
use windows::Win32::Networking::WinSock::{WSAIoctl, SIO_UDP_CONNRESET, SOCKET};

/// Binds a UDP socket for the DNS listener and applies Windows-specific tuning.
pub(crate) fn bind_dns_udp_socket(addr: SocketAddr) -> io::Result<UdpSocket> {
    let socket = UdpSocket::bind(addr)?;
    disable_udp_connreset_reporting(&socket);
    Ok(socket)
}

/// Mirrors C# `DnsServer.DisableUdpConnResetReporting` (`SIO_UDP_CONNRESET = FALSE`).
///
/// Without this, a prior `send_to` that draws ICMP port-unreachable is reported on the
/// next `recv_from` as WSAECONNRESET (10054), which is benign for DNS over UDP.
fn disable_udp_connreset_reporting(socket: &UdpSocket) {
    let Ok(handle) = usize::try_from(socket.as_raw_socket()) else {
        warn!("raw dns socket handle does not fit usize; leaving conn-reset reporting on");
        return;
    };
    let handle = SOCKET(handle);
    let mut disable = 0u32; // FALSE — do not report ICMP port unreachable on recv
    let mut bytes_returned = 0u32;
    let buffer_size = u32::try_from(std::mem::size_of_val(&disable))
        .expect("a u32-sized buffer fits the u32 byte count");

    let status = unsafe {
        WSAIoctl(
            handle,
            SIO_UDP_CONNRESET,
            Some(std::ptr::from_mut(&mut disable).cast()),
            buffer_size,
            None,
            0,
            &raw mut bytes_returned,
            None,
            None,
        )
    };

    if status != 0 {
        warn!(
            error = %io::Error::last_os_error(),
            "could not disable UDP conn-reset reporting on dns socket"
        );
    }
}
