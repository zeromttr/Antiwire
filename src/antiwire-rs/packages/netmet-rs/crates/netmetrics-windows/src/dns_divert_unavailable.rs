//! The port-53 divert on Windows architectures without `WinDivert`.
//!
//! The official `WinDivert` 2.2.2 package ships only x86 and x64 drivers, and an ARM64
//! process cannot load the x64 DLL. This build carries no downloader and no divert:
//! [`install`] refuses at once, and DNS that bypasses the adapter stub goes out
//! unredirected.

use netmetrics_core::{DivertReport, LocalEndpoint, Protocol};

/// Never constructed: [`install`] always fails on this architecture.
pub struct ActiveDivert {
    _never: std::convert::Infallible,
}

/// Refuses: `WinDivert` is not built for this architecture.
///
/// # Errors
///
/// Always.
pub fn install(report: DivertReport) -> Result<ActiveDivert, String> {
    drop(report);
    Err(format!(
        "port 53 divert needs WinDivert, which has no {} driver",
        std::env::consts::ARCH
    ))
}

/// No redirect ever rewrites a client endpoint here.
#[must_use]
pub fn original_endpoint(protocol: Protocol, endpoint: LocalEndpoint) -> Option<LocalEndpoint> {
    let _ = (protocol, endpoint);
    None
}
