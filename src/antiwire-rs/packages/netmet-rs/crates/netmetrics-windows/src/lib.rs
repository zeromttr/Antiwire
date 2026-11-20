//! Windows kernel ETW backend.
//!
//! `WinDivert` (connect-time flow owners, and sending DNS that bypasses the resolver back
//! to it) is off until the application turns it on with [`set_windivert_enabled`]: until
//! then nothing downloads, installs, or loads it. The collector then runs on ETW and the
//! socket tables alone, and bypassing DNS is refused with the Windows Filtering Platform,
//! which needs no driver.
//!
//! `WinDivert` is compiled only for `x86_64`. The official 2.2.2 package ships no ARM64
//! driver, so other architectures never use it, whatever the switch says.
#![allow(unsafe_code)]

#[cfg(windows)]
mod divert_error;
#[cfg(windows)]
mod dns_block;
#[cfg(windows)]
mod dns_bypass;
#[cfg(all(windows, target_arch = "x86_64"))]
mod dns_divert;
#[cfg(windows)]
mod endpoint_owner;
#[cfg(windows)]
pub use endpoint_owner::{EndpointOwner, endpoint_owner_at, endpoint_owners_available};
#[cfg(windows)]
mod filetime;
#[cfg(windows)]
mod flow_owner;
#[cfg(windows)]
mod interface;
#[cfg(windows)]
mod owner_module;
#[cfg(windows)]
mod process_image;
#[cfg(windows)]
pub use owner_module::{
    UdpOwnerLookupStats, tcp_listener_fallback_count, tcp_owner_relaxed_match_count,
    udp_owner_lookup_stats,
};
#[cfg(windows)]
pub use process_image::{ProcessImageResolutionStats, process_image_resolution_stats};
#[cfg(windows)]
mod session_names;
#[cfg(all(windows, target_arch = "x86_64"))]
mod windivert;
#[cfg(all(windows, not(target_arch = "x86_64")))]
#[path = "windivert_unavailable.rs"]
mod windivert;
#[cfg(all(windows, target_arch = "x86_64"))]
mod windivert_handle;
#[cfg(windows)]
mod windivert_opt_in;
#[cfg(all(windows, target_arch = "x86_64"))]
mod windivert_package;
#[cfg(windows)]
mod windows;

#[cfg(windows)]
pub use dns_bypass::{
    DnsDivert, install as install_dns_divert, original_endpoint as dns_divert_original_endpoint,
};
#[cfg(windows)]
pub use interface::InterfaceEstimator;
pub use netmetrics_core::SocketCount;
#[cfg(windows)]
pub use windivert_opt_in::{set_windivert_enabled, windivert_enabled, windivert_supported};
#[cfg(windows)]
pub use windows::{
    SocketCountSample, UdpPidAttributionSample, WindowsBackend, active_socket_count,
    address_string_fallback_count, dns_caller_recovery_stats, dns_event_flush_stats, etw_clock_lag,
    owner_evidence_stats, request_dns_event_flush, socket_owner_snapshot,
    socket_owner_snapshot_for, take_owner_disagreements, tcp_owner_cookie_hit_count,
    tcp_pid_attribution_stats, udp_pid_attribution_stats,
};

#[cfg(not(windows))]
mod unsupported {
    use netmetrics_core::{
        ClockLag, DnsCallerRecoveryStats, DnsFlushStats, OwnerDisagreement, OwnerEvidenceStats,
        SocketOwnerSnapshot, TcpPidAttributionSample,
    };

    netmetrics_sys::unavailable_backend!(
        /// Placeholder that keeps explicit cross-compilation features buildable.
        pub struct WindowsBackend,
        name = "windows-etw",
        detail = "Windows backend was selected on a non-Windows target",
    );

    /// Empty snapshot used when this crate is compiled for another OS.
    #[must_use]
    pub fn socket_owner_snapshot() -> SocketOwnerSnapshot {
        SocketOwnerSnapshot::default()
    }

    /// Empty snapshot used when this crate is compiled for another OS.
    #[must_use]
    pub fn socket_owner_snapshot_for(_protocol: netmetrics_core::Protocol) -> SocketOwnerSnapshot {
        SocketOwnerSnapshot::default()
    }

    /// Empty count used when this crate is compiled for another OS.
    #[must_use]
    pub fn active_socket_count() -> netmetrics_core::SocketCount {
        netmetrics_core::SocketCount::UNAVAILABLE
    }

    /// Address-string fallbacks are a Windows ETW concern.
    #[must_use]
    pub fn address_string_fallback_count() -> u64 {
        0
    }

    /// TCP ETW attribution is unavailable on non-Windows targets.
    #[must_use]
    pub fn tcp_pid_attribution_stats() -> Vec<TcpPidAttributionSample> {
        Vec::new()
    }

    /// DNS caller recovery is unavailable on non-Windows targets.
    #[must_use]
    pub fn dns_caller_recovery_stats() -> DnsCallerRecoveryStats {
        DnsCallerRecoveryStats::default()
    }

    /// Kernel ETW clock lag is a Windows concern.
    #[must_use]
    pub fn etw_clock_lag() -> ClockLag {
        ClockLag::default()
    }

    /// DNS-Client event flushing is a Windows concern.
    pub fn request_dns_event_flush() {}

    /// DNS-Client event flushing is a Windows concern.
    #[must_use]
    pub fn dns_event_flush_stats() -> DnsFlushStats {
        DnsFlushStats::default()
    }

    /// Kernel network events are a Windows concern.
    #[must_use]
    pub fn owner_evidence_stats() -> OwnerEvidenceStats {
        OwnerEvidenceStats::default()
    }

    /// Kernel network events are a Windows concern.
    #[must_use]
    pub fn take_owner_disagreements() -> Vec<OwnerDisagreement> {
        Vec::new()
    }
}

#[cfg(not(windows))]
pub use unsupported::{
    WindowsBackend, active_socket_count, address_string_fallback_count, dns_caller_recovery_stats,
    dns_event_flush_stats, etw_clock_lag, owner_evidence_stats, request_dns_event_flush,
    socket_owner_snapshot, socket_owner_snapshot_for, take_owner_disagreements,
    tcp_pid_attribution_stats,
};
