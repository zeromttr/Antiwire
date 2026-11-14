//! macOS PKTAP backend and allocation-free packet metadata decoder.

#[cfg(any(target_os = "macos", test))]
mod bpf_records;

#[cfg(any(target_os = "macos", test))]
mod flows;

#[cfg(any(target_os = "macos", test))]
mod pktap;

#[cfg(target_os = "macos")]
mod interface_counters;
#[cfg(target_os = "macos")]
mod process_watch;
#[cfg(any(target_os = "macos", test))]
mod processes;

#[cfg(any(target_os = "macos", test))]
mod dns_divert;
#[cfg(any(target_os = "macos", test))]
pub use dns_divert::{
    ActiveDivert as DnsDivert, disable as clear_dns_divert, install as install_dns_divert,
};

#[cfg(target_os = "macos")]
mod macos;

#[cfg(target_os = "macos")]
pub use macos::{
    MacosBackend, active_socket_count, socket_owner_snapshot, socket_owner_snapshot_for,
};

#[cfg(not(target_os = "macos"))]
mod unsupported {
    use netmetrics_core::SocketOwnerSnapshot;

    netmetrics_sys::unavailable_backend!(
        /// Placeholder that keeps explicit cross-compilation features buildable.
        pub struct MacosBackend,
        name = "macos-pktap",
        detail = "macOS backend was selected on a non-macOS target",
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

#[cfg(not(target_os = "macos"))]
pub use unsupported::{
    MacosBackend, active_socket_count, socket_owner_snapshot, socket_owner_snapshot_for,
};

/// Returns true when `name` is safe to pass as an `ifconfig` operand.
///
/// Rejects empty names, flag-like leading dashes, non-ASCII, and names that
/// cannot fit in `ifr_name` (15 bytes plus NUL).
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub(crate) fn is_safe_interface_name(name: &str) -> bool {
    let Some((first, rest)) = name.as_bytes().split_first() else {
        return false;
    };
    (1..16).contains(&name.len())
        && first.is_ascii_alphabetic()
        && rest.iter().all(u8::is_ascii_alphanumeric)
}

#[cfg(test)]
mod interface_name_tests {
    use super::is_safe_interface_name;

    #[test]
    fn accepts_pktap_style_names() {
        assert!(is_safe_interface_name("pktap"));
        assert!(is_safe_interface_name("pktap0"));
        assert!(is_safe_interface_name("en0"));
    }

    #[test]
    fn rejects_flags_and_oversized_or_empty_names() {
        assert!(!is_safe_interface_name(""));
        assert!(!is_safe_interface_name("-a"));
        assert!(!is_safe_interface_name("pktap0;id"));
        assert!(!is_safe_interface_name("pktap_0"));
        assert!(!is_safe_interface_name("thisnameistoolong"));
        assert!(!is_safe_interface_name("0pktap"));
    }
}
