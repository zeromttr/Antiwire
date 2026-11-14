//! Linux eBPF backend with a clearly marked procfs snapshot fallback.

#[cfg(any(target_os = "linux", test))]
mod capability;
#[cfg(any(target_os = "linux", test))]
mod load_retry;

#[cfg(any(target_os = "linux", test))]
mod dns_divert;
#[cfg(target_os = "linux")]
pub use dns_divert::exempt_socket as exempt_socket_from_dns_divert;
#[cfg(any(target_os = "linux", test))]
pub use dns_divert::{
    ActiveDivert as DnsDivert, disable as clear_dns_divert, install as install_dns_divert,
};

#[cfg(any(target_os = "linux", test))]
mod tcp_state;

#[cfg(target_os = "linux")]
mod linux;

#[cfg(target_os = "linux")]
pub use linux::{
    LinuxBackend, active_socket_count, socket_owner_snapshot, socket_owner_snapshot_for,
};

#[cfg(not(target_os = "linux"))]
mod unsupported {
    use netmetrics_core::SocketOwnerSnapshot;

    netmetrics_sys::unavailable_backend!(
        /// Placeholder that keeps explicit cross-compilation features buildable.
        pub struct LinuxBackend,
        name = "linux-ebpf",
        detail = "Linux backend was selected on a non-Linux target",
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

    /// No count when this crate is compiled for another OS.
    ///
    /// # Errors
    ///
    /// Always, since there is no socket table to read.
    pub fn active_socket_count() -> Result<u32, String> {
        Err("socket counts are not available on this target".to_owned())
    }
}

#[cfg(not(target_os = "linux"))]
pub use unsupported::{
    LinuxBackend, active_socket_count, socket_owner_snapshot, socket_owner_snapshot_for,
};
