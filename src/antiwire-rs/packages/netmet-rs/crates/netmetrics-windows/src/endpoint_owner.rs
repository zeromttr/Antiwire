//! Windows ownership policy; history and lookup live in the shared core.

pub use netmetrics_core::EndpointOwner;
#[cfg(target_arch = "x86_64")]
use netmetrics_core::LocalEndpoint;
#[cfg(target_arch = "x86_64")]
pub(crate) use netmetrics_core::endpoint_owner::{
    EndpointOwnerFeed, current_endpoint_owner_at, publish, withdraw,
};
pub use netmetrics_core::endpoint_owner::{endpoint_owner_at, endpoint_owners_available};

#[cfg(target_arch = "x86_64")]
pub(crate) const SYSTEM_PID: u32 = 4;

#[cfg(target_arch = "x86_64")]
pub(crate) fn trusted_owner(endpoint: LocalEndpoint, pid: u32) -> u32 {
    if pid == SYSTEM_PID && endpoint.address.is_loopback() {
        0
    } else {
        pid
    }
}

#[cfg(all(test, target_arch = "x86_64"))]
pub(crate) mod tests;
