//! Route-based interface lookup and procfs interface counters.

use netmetrics_core::{DegradeReason, InterfaceStats, expiring_map::ExpiringMap};
use netmetrics_sys::{BackendEvent, EventSink};
use std::fs;
use std::io;
use std::mem;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::raw::c_int;
use std::path::Path;
use std::ptr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

#[cfg(test)]
mod tests;

/// How long a route lookup is trusted. Routes change when the machine switches networks or
/// a VPN comes up, so an older entry is looked up again rather than kept until evicted.
const ROUTE_CACHE_TTL: Duration = Duration::from_secs(30);
const ROUTE_CACHE_CAPACITY: usize = 1_024;

/// Remote address to the interface its route uses. A failed lookup is cached too, so an
/// unroutable peer is not looked up again on every event.
type RouteCache = ExpiringMap<IpAddr, Option<u32>, ROUTE_CACHE_CAPACITY>;

static ROUTE_IFINDEX: std::sync::OnceLock<Mutex<RouteCache>> = std::sync::OnceLock::new();

#[cfg(feature = "ebpf")]
pub(super) fn enrich_if_index(remote: IpAddr, observed: Option<u32>) -> Option<u32> {
    observed.or_else(|| best_interface_index(remote))
}

pub(super) fn best_interface_index(remote: IpAddr) -> Option<u32> {
    if !routable_unicast(remote) {
        return None;
    }
    let cache = ROUTE_IFINDEX.get_or_init(|| Mutex::new(RouteCache::default()));
    let Ok(mut cache) = cache.lock() else {
        return lookup_route_ifindex(remote);
    };
    let now = Instant::now();
    cache.expire(now);
    if let Some(&index) = cache.get(&remote) {
        return index;
    }
    let index = lookup_route_ifindex(remote);
    cache.insert(remote, index, now + ROUTE_CACHE_TTL);
    index
}

fn routable_unicast(remote: IpAddr) -> bool {
    match remote {
        IpAddr::V4(address) => {
            !(address.is_unspecified() || address.is_broadcast() || address.is_multicast())
        }
        IpAddr::V6(address) => !(address.is_unspecified() || address.is_multicast()),
    }
}

fn lookup_route_ifindex(remote: IpAddr) -> Option<u32> {
    let family = match remote {
        IpAddr::V4(_) => libc::AF_INET,
        IpAddr::V6(_) => libc::AF_INET6,
    };
    // SAFETY: socket(2) with SOCK_DGRAM has no pointer arguments.
    let fd = unsafe { libc::socket(family, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        return None;
    }
    let connected = connect_probe(fd, remote);
    let local = connected.then(|| probe_local_addr(fd, remote)).flatten();
    // SAFETY: `fd` is an owned descriptor from `socket`.
    unsafe {
        libc::close(fd);
    }
    local.and_then(ifindex_for_local_addr)
}

fn sa_family(family: i32) -> libc::sa_family_t {
    libc::sa_family_t::try_from(family).unwrap_or(0)
}

fn connect_probe(fd: c_int, remote: IpAddr) -> bool {
    match remote {
        IpAddr::V4(address) => {
            let dest = libc::sockaddr_in {
                sin_family: sa_family(libc::AF_INET),
                sin_port: 443_u16.to_be(),
                sin_addr: libc::in_addr {
                    s_addr: u32::from_ne_bytes(address.octets()),
                },
                sin_zero: [0; 8],
            };
            // SAFETY: `dest` is a well-formed IPv4 sockaddr for this `fd`.
            unsafe {
                libc::connect(
                    fd,
                    ptr::from_ref(&dest).cast::<libc::sockaddr>(),
                    u32::try_from(mem::size_of_val(&dest)).unwrap_or(u32::MAX),
                ) == 0
            }
        }
        IpAddr::V6(address) => {
            let dest = libc::sockaddr_in6 {
                sin6_family: sa_family(libc::AF_INET6),
                sin6_port: 443_u16.to_be(),
                sin6_flowinfo: 0,
                sin6_addr: libc::in6_addr {
                    s6_addr: address.octets(),
                },
                sin6_scope_id: 0,
            };
            // SAFETY: `dest` is a well-formed IPv6 sockaddr for this `fd`.
            unsafe {
                libc::connect(
                    fd,
                    ptr::from_ref(&dest).cast::<libc::sockaddr>(),
                    u32::try_from(mem::size_of_val(&dest)).unwrap_or(u32::MAX),
                ) == 0
            }
        }
    }
}

fn probe_local_addr(fd: c_int, remote: IpAddr) -> Option<IpAddr> {
    match remote {
        IpAddr::V4(_) => {
            let mut local = libc::sockaddr_in {
                sin_family: sa_family(libc::AF_INET),
                sin_port: 0,
                sin_addr: libc::in_addr { s_addr: 0 },
                sin_zero: [0; 8],
            };
            let mut len = u32::try_from(mem::size_of_val(&local)).ok()?;
            // SAFETY: `local` is a sockaddr_in sized for getsockname.
            let rc = unsafe {
                libc::getsockname(
                    fd,
                    ptr::from_mut(&mut local).cast::<libc::sockaddr>(),
                    &raw mut len,
                )
            };
            (rc == 0).then(|| IpAddr::V4(Ipv4Addr::from(local.sin_addr.s_addr.to_ne_bytes())))
        }
        IpAddr::V6(_) => {
            let mut local = libc::sockaddr_in6 {
                sin6_family: sa_family(libc::AF_INET6),
                sin6_port: 0,
                sin6_flowinfo: 0,
                sin6_addr: libc::in6_addr { s6_addr: [0; 16] },
                sin6_scope_id: 0,
            };
            let mut len = u32::try_from(mem::size_of_val(&local)).ok()?;
            // SAFETY: `local` is a sockaddr_in6 sized for getsockname.
            let rc = unsafe {
                libc::getsockname(
                    fd,
                    ptr::from_mut(&mut local).cast::<libc::sockaddr>(),
                    &raw mut len,
                )
            };
            (rc == 0).then(|| IpAddr::V6(Ipv6Addr::from(local.sin6_addr.s6_addr)))
        }
    }
}

fn ifindex_for_local_addr(local: IpAddr) -> Option<u32> {
    let mut head: *mut libc::ifaddrs = ptr::null_mut();
    // SAFETY: getifaddrs writes a linked list that we free with freeifaddrs.
    if unsafe { libc::getifaddrs(&raw mut head) } != 0 || head.is_null() {
        return None;
    }
    let mut current = head;
    let mut found = None;
    while !current.is_null() {
        // SAFETY: `current` is a node in the list returned by getifaddrs.
        let iface = unsafe { &*current };
        if let Some(address) = sockaddr_to_ip(iface.ifa_addr)
            && address == local
        {
            // SAFETY: `ifa_name` is a NUL-terminated interface name.
            let index = unsafe { libc::if_nametoindex(iface.ifa_name) };
            if index != 0 {
                found = Some(index);
                break;
            }
        }
        current = iface.ifa_next;
    }
    // SAFETY: `head` came from getifaddrs and is freed exactly once.
    unsafe {
        libc::freeifaddrs(head);
    }
    found
}

fn sockaddr_to_ip(addr: *const libc::sockaddr) -> Option<IpAddr> {
    if addr.is_null() {
        return None;
    }
    // SAFETY: `addr` is a sockaddr from getifaddrs.
    let family = unsafe { (*addr).sa_family };
    match i32::from(family) {
        libc::AF_INET => {
            // SAFETY: family is AF_INET so this is a sockaddr_in.
            let sin = unsafe { &*(addr.cast::<libc::sockaddr_in>()) };
            Some(IpAddr::V4(Ipv4Addr::from(
                sin.sin_addr.s_addr.to_ne_bytes(),
            )))
        }
        libc::AF_INET6 => {
            // SAFETY: family is AF_INET6 so this is a sockaddr_in6.
            let sin6 = unsafe { &*(addr.cast::<libc::sockaddr_in6>()) };
            Some(IpAddr::V6(Ipv6Addr::from(sin6.sin6_addr.s6_addr)))
        }
        _ => None,
    }
}

pub(super) fn emit_interface_samples(sink: &EventSink, timestamp: u64) {
    match read_interface_stats(Path::new("/proc/net/dev"), timestamp) {
        Ok(samples) => {
            for sample in samples {
                sink.emit(BackendEvent::Interface(sample));
            }
        }
        Err(error) => {
            sink.emit(BackendEvent::Degraded(DegradeReason::SourceUnavailable {
                source: "procfs-interface".to_owned(),
                detail: error.to_string(),
            }));
        }
    }
}

fn read_interface_stats(path: &Path, timestamp: u64) -> io::Result<Vec<InterfaceStats>> {
    let contents = fs::read_to_string(path)?;
    let mut samples = Vec::new();
    for (index, line) in contents.lines().skip(2).enumerate() {
        let Some((name, counters)) = line.split_once(':') else {
            continue;
        };
        let values: Vec<u64> = counters
            .split_ascii_whitespace()
            .filter_map(|value| value.parse().ok())
            .collect();
        if values.len() < 12 {
            continue;
        }
        let name = name.trim();
        samples.push(InterfaceStats {
            index: netmetrics_sys::interface_index_by_name(name)
                .unwrap_or_else(|| u32::try_from(index + 1).unwrap_or(u32::MAX)),
            name: name.to_owned(),
            rx_bytes: values[0],
            tx_bytes: values[8],
            rx_errors: values[2],
            tx_errors: values[10],
            rx_drops: values[3],
            tx_drops: values[11],
            timestamp,
        });
    }
    Ok(samples)
}
