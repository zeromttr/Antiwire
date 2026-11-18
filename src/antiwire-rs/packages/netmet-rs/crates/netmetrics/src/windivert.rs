//! Opting in to `WinDivert`, the third-party kernel driver the Windows backend can use.
//!
//! `WinDivert` is off until [`set_enabled`] turns it on. While it is off, nothing is
//! downloaded, loaded or run for it: the collector takes flow owners from kernel ETW and
//! the socket tables alone, [`crate::endpoint_owner`] reports
//! [`EndpointOwner::Unavailable`](crate::endpoint_owner::EndpointOwner::Unavailable), and
//! [`crate::dns_divert::start`] refuses DNS that bypasses the stub, with the Windows
//! Filtering Platform, where `WinDivert` would send it to the stub.
//!
//! It is off by default because a loaded packet-capture driver is something anti-cheat
//! software can treat as an integrity violation: a game may refuse to start, or ban the
//! account. Turn it on only when the user asked for it.
//!
//! Turning it on gives the Windows collector connect-time flow owners and lets the
//! port-53 divert redirect. The first use downloads the official package from
//! <https://reqrypt.org/download/WinDivert-2.2.2-A.zip>.
//!
//! On every other platform, and on Windows architectures `WinDivert` has no driver for,
//! the switch changes nothing.

/// Turns `WinDivert` on or off for this process. It is off until this is called with
/// `true`.
///
/// A running collector follows the switch within one poll: it starts its FLOW listener
/// when turned on, and closes it when turned off. A [`DnsDivert`](crate::dns_divert::DnsDivert)
/// that is already running keeps the form it started in, so drop it and start it again
/// when turning `WinDivert` on or off.
///
/// Turning it off closes the handles but does not unload the driver: `WinDivert` leaves
/// a running driver loaded until the next reboot, or until `sc stop WinDivert`.
pub fn set_enabled(enabled: bool) {
    #[cfg(all(windows, feature = "windows"))]
    netmetrics_windows::set_windivert_enabled(enabled);
    #[cfg(not(all(windows, feature = "windows")))]
    let _ = enabled;
}

/// Whether this build can use `WinDivert`: only the Windows backend on `x86_64` can, as
/// the official package has no driver for another architecture. Where it cannot, do not
/// offer the user the choice: [`set_enabled`] changes nothing there.
#[must_use]
pub const fn is_supported() -> bool {
    #[cfg(all(windows, feature = "windows"))]
    {
        netmetrics_windows::windivert_supported()
    }
    #[cfg(not(all(windows, feature = "windows")))]
    {
        false
    }
}

/// Whether `WinDivert` is turned on for this process. Always `false` where the Windows
/// backend is not built.
#[must_use]
pub fn is_enabled() -> bool {
    #[cfg(all(windows, feature = "windows"))]
    {
        netmetrics_windows::windivert_enabled()
    }
    #[cfg(not(all(windows, feature = "windows")))]
    {
        false
    }
}
