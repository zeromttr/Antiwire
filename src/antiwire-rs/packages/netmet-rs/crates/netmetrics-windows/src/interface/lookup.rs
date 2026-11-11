//! Adapter address and route lookup for interface estimation.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::ptr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use windows::Win32::Foundation::{HANDLE, WIN32_ERROR};
use windows::Win32::NetworkManagement::IpHelper::{
    CancelMibChangeNotify2, FreeMibTable, GetBestRoute2, GetUnicastIpAddressTable,
    MIB_IPFORWARD_ROW2, MIB_IPINTERFACE_ROW, MIB_NOTIFICATION_TYPE, NotifyIpInterfaceChange,
    NotifyRouteChange2,
};
use windows::Win32::Networking::WinSock::{
    AF_INET, AF_INET6, AF_UNSPEC, IN_ADDR, IN6_ADDR, SOCKADDR_IN, SOCKADDR_IN6, SOCKADDR_INET,
};

pub(super) fn lookup_interface(local: IpAddr, remote: IpAddr) -> Result<(u32, bool), ()> {
    let owning = interface_owning(local);
    let route = lookup_route(local, remote).ok();
    select_interface(local, owning, route).ok_or(())
}

/// Loopback and a bound address never take a default-route guess over the interface
/// that actually owns the address. The bool is true when the index owns `local`.
pub(crate) fn select_interface(
    local: IpAddr,
    owning: Option<u32>,
    route: Option<u32>,
) -> Option<(u32, bool)> {
    if local.is_loopback() {
        return owning.map(|index| (index, true));
    }
    if !local.is_unspecified()
        && let Some(index) = owning
    {
        return Some((index, true));
    }
    route
        .filter(|index| *index != 0)
        .map(|index| (index, false))
}

fn lookup_route(local: IpAddr, remote: IpAddr) -> Result<u32, ()> {
    let destination = sockaddr_inet(remote);
    let source = (!local.is_unspecified()).then(|| sockaddr_inet(local));
    let mut route = MIB_IPFORWARD_ROW2::default();
    let mut best_source = SOCKADDR_INET::default();
    // SAFETY: every pointer refers to a live local of the type the API expects.
    let status = unsafe {
        GetBestRoute2(
            None,
            0,
            source.as_ref().map(ptr::from_ref),
            ptr::from_ref(&destination),
            0,
            &raw mut route,
            &raw mut best_source,
        )
    };
    if status == WIN32_ERROR(0) && route.InterfaceIndex != 0 {
        Ok(route.InterfaceIndex)
    } else {
        Err(())
    }
}

fn interface_owning(local: IpAddr) -> Option<u32> {
    if local.is_unspecified() {
        return None;
    }
    let family = match local {
        IpAddr::V4(_) => AF_INET,
        IpAddr::V6(_) => AF_INET6,
    };
    let mut table = std::ptr::null_mut();
    // SAFETY: `table` is a valid out-pointer; the table is freed below.
    let status = unsafe { GetUnicastIpAddressTable(family, &raw mut table) };
    if status != WIN32_ERROR(0) || table.is_null() {
        return None;
    }
    // SAFETY: on success the table is non-null and holds `NumEntries` rows.
    let found = unsafe {
        let rows =
            std::slice::from_raw_parts((*table).Table.as_ptr(), (*table).NumEntries as usize);
        rows.iter().find_map(|row| {
            let address = ip_from_sockaddr(&row.Address)?;
            (address == local).then_some(row.InterfaceIndex)
        })
    };
    // SAFETY: `table` came from `GetUnicastIpAddressTable`, and `rows` is no longer used.
    unsafe { FreeMibTable(table.cast()) };
    found.filter(|index| *index != 0)
}

fn ip_from_sockaddr(address: &SOCKADDR_INET) -> Option<IpAddr> {
    // SAFETY: `si_family` overlaps the family field of every variant, and the variant read
    // is the one it names.
    unsafe {
        match address.si_family {
            AF_INET => Some(IpAddr::V4(Ipv4Addr::from(address.Ipv4.sin_addr))),
            AF_INET6 => Some(IpAddr::V6(Ipv6Addr::from(address.Ipv6.sin6_addr))),
            _ => None,
        }
    }
}

fn sockaddr_inet(address: IpAddr) -> SOCKADDR_INET {
    match address {
        IpAddr::V4(v4) => SOCKADDR_INET {
            Ipv4: SOCKADDR_IN {
                sin_family: AF_INET,
                sin_addr: IN_ADDR::from(v4),
                ..Default::default()
            },
        },
        IpAddr::V6(v6) => SOCKADDR_INET {
            Ipv6: SOCKADDR_IN6 {
                sin6_family: AF_INET6,
                sin6_addr: IN6_ADDR::from(v6),
                ..Default::default()
            },
        },
    }
}

pub(super) struct NetworkChangeWatch {
    interface: HANDLE,
    route: HANDLE,
    _epoch: Arc<AtomicU64>,
}

impl NetworkChangeWatch {
    pub(super) fn new(epoch: Arc<AtomicU64>) -> Option<Self> {
        let mut interface = HANDLE::default();
        let mut route = HANDLE::default();
        let ctx = Arc::as_ptr(&epoch).cast();
        // SAFETY: `ctx` points into `epoch`, which the watch keeps alive until `Drop`
        // cancels both registrations. The callbacks only read it as an `AtomicU64`.
        let interface_status = unsafe {
            NotifyIpInterfaceChange(
                AF_UNSPEC,
                Some(on_interface_change),
                Some(ctx),
                false,
                &raw mut interface,
            )
        };
        // SAFETY: as above.
        let route_status = unsafe {
            NotifyRouteChange2(AF_UNSPEC, Some(on_route_change), ctx, false, &raw mut route)
        };
        if interface_status != WIN32_ERROR(0) || route_status != WIN32_ERROR(0) {
            if interface_status == WIN32_ERROR(0) {
                // SAFETY: `interface` is a registration that succeeded and is cancelled once.
                unsafe {
                    let _ = CancelMibChangeNotify2(interface);
                }
            }
            if route_status == WIN32_ERROR(0) {
                // SAFETY: `route` is a registration that succeeded and is cancelled once.
                unsafe {
                    let _ = CancelMibChangeNotify2(route);
                }
            }
            return None;
        }
        Some(Self {
            interface,
            route,
            _epoch: epoch,
        })
    }
}

impl Drop for NetworkChangeWatch {
    fn drop(&mut self) {
        // SAFETY: both registrations succeeded in `new`. Cancelling waits for running
        // callbacks, so `_epoch` is only dropped after the last one has returned.
        unsafe {
            let _ = CancelMibChangeNotify2(self.interface);
            let _ = CancelMibChangeNotify2(self.route);
        }
    }
}

unsafe extern "system" fn on_interface_change(
    caller_context: *const core::ffi::c_void,
    _row: *const MIB_IPINTERFACE_ROW,
    _notification_type: MIB_NOTIFICATION_TYPE,
) {
    // SAFETY: registered in `NetworkChangeWatch::new` with its epoch as the context.
    unsafe { bump_epoch(caller_context) };
}

unsafe extern "system" fn on_route_change(
    caller_context: *const core::ffi::c_void,
    _row: *const MIB_IPFORWARD_ROW2,
    _notification_type: MIB_NOTIFICATION_TYPE,
) {
    // SAFETY: registered in `NetworkChangeWatch::new` with its epoch as the context.
    unsafe { bump_epoch(caller_context) };
}

/// # Safety
///
/// `caller_context` must be null or point to an `AtomicU64` that outlives the call.
unsafe fn bump_epoch(caller_context: *const core::ffi::c_void) {
    if caller_context.is_null() {
        return;
    }
    // SAFETY: guaranteed by the caller.
    let epoch = unsafe { &*(caller_context.cast::<AtomicU64>()) };
    epoch.fetch_add(1, Ordering::Release);
}
