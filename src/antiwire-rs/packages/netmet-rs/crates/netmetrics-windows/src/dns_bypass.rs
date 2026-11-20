//! What becomes of outbound DNS that bypasses the resolver, in whichever form this process
//! may use.
//!
//! With `WinDivert` turned on ([`crate::set_windivert_enabled`]) it is sent back to the
//! stub, which answers it: [`crate::dns_divert`]. That needs the driver, so it exists only
//! on `x86_64`. Otherwise it is refused with the Windows Filtering Platform, which needs
//! no driver and works on every architecture: [`crate::dns_block`].

use netmetrics_core::{DivertReport, LocalEndpoint, Protocol};

use crate::dns_block::{self, ActiveBlock};

/// The port plain DNS uses.
pub(crate) const DNS_PORT: u16 = 53;
/// The port DNS over TLS and DNS over QUIC use.
pub(crate) const ENCRYPTED_DNS_PORT: u16 = 853;

/// The live divert. Dropping it removes it.
pub struct DnsDivert {
    form: Form,
}

enum Form {
    /// Bypassing DNS is sent to the stub by `WinDivert`.
    #[cfg(target_arch = "x86_64")]
    Redirect(crate::dns_divert::ActiveDivert),
    /// Bypassing DNS is refused by the Windows Filtering Platform.
    Block(ActiveBlock),
}

impl DnsDivert {
    /// Removes the divert. Later calls do nothing.
    pub fn disable(&mut self) {
        match &mut self.form {
            #[cfg(target_arch = "x86_64")]
            Form::Redirect(redirect) => redirect.disable(),
            Form::Block(block) => block.disable(),
        }
    }
}

/// Installs the divert: the `WinDivert` redirect when `WinDivert` is turned on, and the
/// filter-platform block otherwise. Which one is decided here, once: drop the divert and
/// install it again after turning `WinDivert` on or off.
///
/// # Errors
///
/// When the form chosen cannot be installed. A redirect that fails is not replaced by a
/// block.
pub fn install(report: DivertReport) -> Result<DnsDivert, String> {
    #[cfg(target_arch = "x86_64")]
    if crate::windivert_enabled() {
        let form = Form::Redirect(crate::dns_divert::install(report)?);
        return Ok(DnsDivert { form });
    }
    let form = Form::Block(dns_block::install(report)?);
    Ok(DnsDivert { form })
}

/// Original local endpoint of a query the `WinDivert` redirect sent to the stub. `None`
/// for every other client: the block rewrites nothing.
#[must_use]
pub fn original_endpoint(protocol: Protocol, endpoint: LocalEndpoint) -> Option<LocalEndpoint> {
    #[cfg(target_arch = "x86_64")]
    {
        crate::dns_divert::original_endpoint(protocol, endpoint)
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        let _ = (protocol, endpoint);
        None
    }
}
