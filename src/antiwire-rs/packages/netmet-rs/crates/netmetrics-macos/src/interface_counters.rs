//! Interface counters from the kernel's generic interface MIB.
//!
//! `getifaddrs(3)` and the routing sysctls do not give usable byte counters to a program
//! Apple did not sign. `getifaddrs` returns `struct if_data`, whose counters are 32 bits
//! wide and wrap every 4 GiB. `NET_RT_IFLIST2` returns the 64-bit `struct if_data64`, but
//! the kernel first rounds its byte counters down to 1 KiB and truncates them to 32 bits
//! for every process that is not a platform binary (`ALIGN_BYTES` in `sysctl_iflist2`,
//! `bsd/net/rtsock.c` in XNU, from macOS 13 on).
//!
//! `net.link.generic.ifdata.<ifindex>.general` returns `struct ifmibdata`
//! (`<net/if_mib.h>`): the same `if_data64`, copied whole, and the send queue's drop count
//! beside it (`make_ifmibdata` in `bsd/net/if_mib.c`). Apple documents this MIB only in
//! that header, so nothing here assumes more than the header declares. A read that fails
//! is an error the backend reports, and a value of another size than the structure is
//! refused.

use libc::c_int;
use netmetrics_core::InterfaceStats;
use std::io;
use std::mem::size_of;
use std::ptr;

// `struct ifmibdata` in `<net/if_mib.h>`: a 16-byte name, nine `unsigned int`s, and a
// `struct if_data64`, which `<net/if_var.h>` packs to 4 bytes and makes 128 bytes long.
const _: () = assert!(size_of::<libc::ifmibdata>() == 16 + 9 * 4 + 128);

/// Reads the value the kernel keeps under `name` into `value`, with `sysctl(3)`.
///
/// Returns how many bytes the kernel wrote, or `None` when nothing has that name
/// (`ENOENT`), as when no interface has the index a name carries.
///
/// # Errors
///
/// Returns why the kernel refused the read. A value longer than `value` is `ENOMEM`.
fn read_sysctl(name: &mut [c_int], value: &mut [u8]) -> io::Result<Option<usize>> {
    let name_len = u32::try_from(name.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "sysctl name is too long"))?;
    let mut written = value.len();
    // SAFETY: `name` holds `name_len` integers, which the call only reads. `value` is
    // writable for `written` bytes, its whole length; the kernel writes no more than that
    // and stores the length it wrote in `written`. No new value is passed.
    let status = unsafe {
        libc::sysctl(
            name.as_mut_ptr(),
            name_len,
            value.as_mut_ptr().cast(),
            &raw mut written,
            ptr::null_mut(),
            0,
        )
    };
    if status == 0 {
        return Ok(Some(written));
    }
    let error = io::Error::last_os_error();
    if error.raw_os_error() == Some(libc::ENOENT) {
        return Ok(None);
    }
    Err(error)
}

/// The highest interface index in use, which `net.link.generic.system.ifcount` reports:
/// the kernel returns its `if_index` there (`sysctl_ifindex` in `bsd/net/if_mib.c`).
fn highest_interface_index() -> io::Result<u32> {
    let mut name = [
        libc::CTL_NET,
        libc::PF_LINK,
        libc::NETLINK_GENERIC,
        libc::IFMIB_SYSTEM,
        libc::IFMIB_IFCOUNT,
    ];
    let mut value = [0_u8; size_of::<c_int>()];
    if read_sysctl(&mut name, &mut value)? != Some(value.len()) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "the interface count is not an integer",
        ));
    }
    u32::try_from(c_int::from_ne_bytes(value)).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "the interface count is negative",
        )
    })
}

/// The general MIB entry of the interface with `index`, or `None` when no interface has
/// that index.
fn interface_mib(index: u32) -> io::Result<Option<libc::ifmibdata>> {
    let Ok(index) = c_int::try_from(index) else {
        return Ok(None);
    };
    let mut name = [
        libc::CTL_NET,
        libc::PF_LINK,
        libc::NETLINK_GENERIC,
        libc::IFMIB_IFDATA,
        index,
        libc::IFDATA_GENERAL,
    ];
    let mut value = [0_u8; size_of::<libc::ifmibdata>()];
    match read_sysctl(&mut name, &mut value)? {
        None => Ok(None),
        // SAFETY: the kernel wrote all of `value`, which is as long as the structure, and
        // every bit pattern is a valid `ifmibdata`: it holds only integers and arrays of
        // them. The bytes carry no alignment, so they are read unaligned.
        Some(written) if written == value.len() => Ok(Some(unsafe {
            ptr::read_unaligned(value.as_ptr().cast::<libc::ifmibdata>())
        })),
        Some(written) => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "the interface MIB entry is {written} bytes, not {}",
                value.len()
            ),
        )),
    }
}

/// The interface's name: the bytes before the first NUL, or all of them.
fn interface_name(mib: &libc::ifmibdata) -> String {
    let bytes: Vec<u8> = mib
        .ifmd_name
        .iter()
        .map(|byte| byte.to_ne_bytes()[0])
        .take_while(|byte| *byte != 0)
        .collect();
    String::from_utf8_lossy(&bytes).into_owned()
}

/// One sample of every attached interface's cumulative counters.
///
/// Transmit drops are the packets the interface's send queue dropped, which the kernel
/// counts in 32 bits.
///
/// # Errors
///
/// Returns why the MIB could not be read.
pub(crate) fn interface_stats(timestamp: u64) -> io::Result<Vec<InterfaceStats>> {
    let mut samples = Vec::new();
    // Indexes are not reused densely: one whose interface has gone names nothing.
    for index in 1..=highest_interface_index()? {
        let Some(mib) = interface_mib(index)? else {
            continue;
        };
        let name = interface_name(&mib);
        // The kernel leaves the entry of an interface that is not fully attached zeroed.
        if name.is_empty() {
            continue;
        }
        let counters = mib.ifmd_data;
        samples.push(InterfaceStats {
            index,
            name,
            rx_bytes: counters.ifi_ibytes,
            tx_bytes: counters.ifi_obytes,
            rx_errors: counters.ifi_ierrors,
            tx_errors: counters.ifi_oerrors,
            rx_drops: counters.ifi_iqdrops,
            tx_drops: u64::from(mib.ifmd_snd_drops),
            timestamp,
        });
    }
    Ok(samples)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, UdpSocket};
    use std::thread;
    use std::time::{Duration, Instant};

    /// The loopback interface's sample.
    fn loopback() -> InterfaceStats {
        interface_stats(7)
            .expect("interface MIB")
            .into_iter()
            .find(|sample| sample.name == "lo0")
            .expect("lo0 is listed")
    }

    #[test]
    fn every_interface_is_listed_under_the_index_the_system_gives_its_name() {
        let samples = interface_stats(7).expect("interface MIB");
        assert!(!samples.is_empty());
        for sample in &samples {
            assert_eq!(
                netmetrics_sys::interface_index_by_name(&sample.name),
                Some(sample.index),
                "{sample:?}"
            );
            assert_eq!(sample.timestamp, 7);
        }
    }

    /// The counters are the interface's own: what is sent over loopback is added to both
    /// of its byte counters, a datagram's payload at least. The kernel adds a packet to
    /// them from its input thread (`lo_output` hands its counts to `ifnet_input_extended`
    /// in `bsd/net/if_loop.c`), so they are given a moment to catch up.
    #[test]
    fn loopback_counters_grow_by_what_is_sent_over_it() {
        const DATAGRAMS: u64 = 64;
        const PAYLOAD: usize = 1_024;
        let receiver = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("receiver");
        let sender = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("sender");
        let before = loopback();
        let mut buffer = [0_u8; PAYLOAD];
        for _ in 0..DATAGRAMS {
            sender
                .send_to(&[7_u8; PAYLOAD], receiver.local_addr().expect("address"))
                .expect("send");
            receiver.recv_from(&mut buffer).expect("receive");
        }
        let sent = DATAGRAMS * PAYLOAD as u64;
        let grew = |after: &InterfaceStats| {
            after.tx_bytes.saturating_sub(before.tx_bytes) >= sent
                && after.rx_bytes.saturating_sub(before.rx_bytes) >= sent
        };
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut after = loopback();
        while !grew(&after) && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(50));
            after = loopback();
        }
        assert!(grew(&after), "{before:?} {after:?}");
    }

    #[test]
    fn an_index_no_interface_has_names_no_entry() {
        let unused = highest_interface_index().expect("interface count") + 1;
        assert!(interface_mib(unused).expect("read").is_none());
        assert!(interface_mib(0).expect("read").is_none());
    }
}
