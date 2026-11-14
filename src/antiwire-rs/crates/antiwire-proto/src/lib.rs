//! Generated protobuf and gRPC server types for the Antiwire IPC API.

#![allow(
    clippy::all,
    clippy::derive_partial_eq_without_eq,
    clippy::large_enum_variant,
    clippy::missing_const_for_fn,
    clippy::nursery,
    clippy::pedantic
)]

pub(crate) mod antiwire {
    tonic::include_proto!("antiwire");
}

#[doc(inline)]
pub use antiwire::*;

/// Metadata key the daemon and desktop client use for the local IPC token.
pub const TOKEN_HEADER: &str = "x-antiwire-token";

/// Local group whose members may use the daemon's API.
///
/// The installers create it and add the installing user. The daemon makes the IPC
/// token, and on unix the socket, readable by this group and by administrators only.
#[cfg(windows)]
pub const IPC_CLIENT_GROUP: &str = "Antiwire Users";
/// Local group whose members may use the daemon's API.
///
/// The installers create it and add the installing user. The daemon makes the IPC
/// token, and on unix the socket, readable by this group and by administrators only.
#[cfg(not(windows))]
pub const IPC_CLIENT_GROUP: &str = "antiwire";

#[cfg(test)]
mod tests {
    use super::StatsResponse;
    use prost::Message;

    #[test]
    fn omitted_active_connections_available_means_legacy_available() {
        let legacy = StatsResponse {
            total_bytes_sent: 1,
            total_bytes_received: 2,
            active_connections_count: 9,
            blocked_connections_count: 4,
            byte_accounting_available: true,
            collector_status_detail: String::new(),
            active_connections_available: None,
            active_connections_stale: false,
            active_applications_count: None,
            daemon_version: String::new(),
            database_size_bytes: None,
        };
        let encoded = legacy.encode_to_vec();
        let decoded = StatsResponse::decode(encoded.as_slice()).expect("decode");
        assert_eq!(decoded.active_connections_count, 9);
        assert_eq!(
            decoded.active_connections_available, None,
            "an older daemon omits the field"
        );
        assert!(
            decoded.active_connections_available.unwrap_or(true),
            "absence must be treated as legacy availability"
        );
        assert!(!decoded.active_connections_stale);
        assert_eq!(
            decoded.active_applications_count, None,
            "an older daemon cannot report applications; absence is not zero"
        );
    }
}
