//! Historical local endpoint ownership from the running native backend.
//!
//! Windows uses `WinDivert` FLOW, Linux uses eBPF socket I/O, and macOS uses
//! PKTAP process metadata. History survives socket closure while the reader
//! runs. Snapshot-only modes report [`EndpointOwner::Unavailable`].

pub use netmetrics_core::EndpointOwner;
pub use netmetrics_core::endpoint_owner::{
    endpoint_owner_at as owner_at, endpoint_owners_available as available,
};
