//! Diverts outbound port 53 that bypasses the local stub.
//!
//! Dropping [`DnsDivert`] removes the platform filter: the nftables table on Linux, the pf
//! anchor on macOS, and on Windows the filters in the Windows Filtering Platform or, with
//! `WinDivert` turned on, the `WinDivert` handle.
//!
//! Linux and macOS send such DNS back to the stub, and so does Windows with `WinDivert`.
//! Windows without it cannot: redirecting needs a kernel driver there. It refuses the
//! traffic instead, so a program that names its own resolver fails to resolve where
//! elsewhere it would get the stub's answer. See [`start`].

pub use netmetrics_core::DivertEvent;
use netmetrics_core::{LocalEndpoint, Protocol};
pub use netmetrics_sys::DIVERT_CHECK_INTERVAL;

/// Returns the original local endpoint behind a Windows DNS redirect.
///
/// A mapped synthetic endpoint is reserved for its origin until expiry or
/// shutdown. Resolve ownership of the returned endpoint before answering the
/// query. Returns `None` for ordinary clients and on other platforms, whose
/// redirect rules preserve the client endpoint.
#[must_use]
pub fn original_endpoint(protocol: Protocol, endpoint: LocalEndpoint) -> Option<LocalEndpoint> {
    #[cfg(all(windows, feature = "windows"))]
    {
        netmetrics_windows::dns_divert_original_endpoint(protocol, endpoint)
    }
    #[cfg(not(all(windows, feature = "windows")))]
    {
        let _ = (protocol, endpoint);
        None
    }
}

/// Live port-53 divert. Dropping it disables the divert: the platform divert
/// it holds, kept only for its `Drop`, releases its filter once.
pub struct DnsDivert {
    #[cfg(all(windows, feature = "windows"))]
    _inner: netmetrics_windows::DnsDivert,
    #[cfg(all(target_os = "linux", feature = "linux"))]
    _inner: netmetrics_linux::DnsDivert,
    #[cfg(all(target_os = "macos", feature = "macos"))]
    _inner: netmetrics_macos::DnsDivert,
}

impl std::fmt::Debug for DnsDivert {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("DnsDivert")
    }
}

/// Installs the divert, replacing anything a previous process left behind.
///
/// `report` hears, on a thread the divert owns, each time the divert stops
/// working after a successful start ([`DivertEvent::Lost`]), each time it works
/// again ([`DivertEvent::Restored`]), and when putting it back failed
/// ([`DivertEvent::RestoreFailed`]); in between, DNS that bypasses the stub is
/// not redirected. On Windows that is the packet reader stopping and reopening.
/// On Linux and macOS, where any root process can remove kernel rules, the
/// divert checks its rules every [`DIVERT_CHECK_INTERVAL`] and puts them back
/// when they are removed, emptied or, on macOS, pf is switched off.
///
/// On Windows the form is chosen when this is called. With `WinDivert` turned on
/// ([`crate::windivert::set_enabled`]), which only `x86_64` can do, bypassing DNS is sent
/// to the stub. Otherwise filters in the Windows Filtering Platform refuse outbound TCP
/// and UDP to ports 53 and 853 for every program but this one and the service host that
/// runs the system resolver, loopback excepted; no driver is involved, and Windows deletes
/// the filters if this process ends without dropping the divert. Drop the divert and start
/// it again after turning `WinDivert` on or off. In the filter form the report hears of
/// filters that another tool deleted, checked every [`DIVERT_CHECK_INTERVAL`] as on Linux
/// and macOS.
///
/// # Errors
///
/// Returns an error when the platform filter cannot be installed. The caller should keep
/// resolving through the stub; a missing divert is not fatal.
pub fn start(report: impl Fn(DivertEvent) + Send + 'static) -> Result<DnsDivert, String> {
    clear_leftover();
    install(Box::new(report))
}

#[cfg(all(windows, feature = "windows"))]
fn install(report: netmetrics_core::DivertReport) -> Result<DnsDivert, String> {
    let inner = netmetrics_windows::install_dns_divert(report)?;
    Ok(DnsDivert { _inner: inner })
}

#[cfg(all(target_os = "linux", feature = "linux"))]
fn install(report: netmetrics_core::DivertReport) -> Result<DnsDivert, String> {
    let inner = netmetrics_linux::install_dns_divert(report)?;
    Ok(DnsDivert { _inner: inner })
}

#[cfg(all(target_os = "macos", feature = "macos"))]
fn install(report: netmetrics_core::DivertReport) -> Result<DnsDivert, String> {
    let inner = netmetrics_macos::install_dns_divert(report)?;
    Ok(DnsDivert { _inner: inner })
}

#[cfg(not(any(
    all(windows, feature = "windows"),
    all(target_os = "linux", feature = "linux"),
    all(target_os = "macos", feature = "macos")
)))]
fn install(report: netmetrics_core::DivertReport) -> Result<DnsDivert, String> {
    drop(report);
    Err("port 53 divert is not supported on this build".to_owned())
}

/// Marks `socket` as the stub's own way to its upstream resolver, which the Linux divert
/// lets through. The divert exempts nothing else there: not a user, and not root.
///
/// Call it before the socket sends anything, a TCP socket before it connects. Windows
/// exempts the process that holds the divert and macOS exempts root, so neither has this.
///
/// # Errors
///
/// `PermissionDenied` without `CAP_NET_ADMIN` or `CAP_NET_RAW`. Installing the divert needs
/// `CAP_NET_ADMIN` as well, so a process this fails for has no divert to be exempt from.
#[cfg(all(target_os = "linux", feature = "linux"))]
pub fn exempt_socket(socket: &impl std::os::fd::AsFd) -> std::io::Result<()> {
    netmetrics_linux::exempt_socket_from_dns_divert(socket)
}

/// Removes a divert left behind after a crash or an already-finished session.
pub fn clear_leftover() {
    #[cfg(all(target_os = "linux", feature = "linux"))]
    netmetrics_linux::clear_dns_divert();
    #[cfg(all(target_os = "macos", feature = "macos"))]
    netmetrics_macos::clear_dns_divert(None);
}
