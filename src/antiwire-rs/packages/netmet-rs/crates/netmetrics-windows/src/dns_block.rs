//! Refuses outbound DNS that bypasses the resolver, with the Windows Filtering Platform.
//!
//! The other platforms send such DNS back to the stub. Windows can only do that from the
//! kernel: WFP changes where a connection goes in a callout at its redirect layers, and a
//! callout is part of a driver
//! (<https://learn.microsoft.com/windows-hardware/drivers/network/using-bind-or-connect-redirection>).
//! `WinDivert` is such a driver, and [`crate::dns_divert`] uses it when the application has
//! turned it on. Without a driver, WFP's management API can still refuse a connection, on
//! every architecture, and that is what this does:
//!
//! - Outbound TCP and UDP to ports 53 and 853 is blocked, loopback excepted, which is where
//!   the stub listens. A program that brings its own resolver address fails to resolve, and
//!   falls back to the system resolver if it can.
//! - This process is let through: it is the stub, and that is its way upstream.
//! - `svchost.exe` is let through: it hosts the DNS Client service, the system resolver,
//!   which asks whatever the adapters' DNS settings name. Those name the stub once they are
//!   redirected. Until then, or where that failed, the host keeps resolving.
//!
//! The filters authorize connections at `FWPM_LAYER_ALE_AUTH_CONNECT_V4` and `_V6`, which
//! see a TCP `connect` and the first UDP packet to each remote address and port
//! (<https://learn.microsoft.com/windows/win32/fwp/ale-layers>). Adding them makes Windows
//! authorize established flows again, so a connection opened earlier is refused too
//! (<https://learn.microsoft.com/windows/win32/fwp/ale-stateful-filtering>).
//!
//! They live in a dynamic session: Windows deletes them when the block drops, and when
//! this process ends without dropping it. A block left behind would leave the host without
//! DNS, and this one cannot be.

use std::ffi::OsString;
use std::os::windows::ffi::OsStringExt;
use std::path::PathBuf;

use netmetrics_core::DivertReport;
use netmetrics_sys::{DivertRules, DivertWatch};
use windows::Win32::System::SystemInformation::GetSystemDirectoryW;

use crate::dns_bypass::{DNS_PORT, ENCRYPTED_DNS_PORT};

#[cfg(test)]
mod tests;
mod wfp;

/// IANA protocol numbers, as `FWPM_CONDITION_IP_PROTOCOL` takes them.
const TCP: u8 = 6;
const UDP: u8 = 17;

/// The program that hosts the DNS Client service, in the system directory.
const SERVICE_HOST: &str = "svchost.exe";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Family {
    V4,
    V6,
}

/// One filter of the block.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct FilterSpec<'a> {
    family: Family,
    protocol: u8,
    port: u16,
    /// The WFP id of the program this filter lets through. `None` is the block itself.
    permitted_app: Option<&'a [u8]>,
}

/// Every filter of the block: for each address family, protocol and port, one that refuses
/// the traffic and one for each of `exempt` that lets that program's through.
fn filter_plan(exempt: &[Vec<u8>]) -> Vec<FilterSpec<'_>> {
    let mut plan = Vec::new();
    for family in [Family::V4, Family::V6] {
        for protocol in [TCP, UDP] {
            for port in [DNS_PORT, ENCRYPTED_DNS_PORT] {
                let spec = |permitted_app| FilterSpec {
                    family,
                    protocol,
                    port,
                    permitted_app,
                };
                plan.push(spec(None));
                plan.extend(exempt.iter().map(|app| spec(Some(app.as_slice()))));
            }
        }
    }
    plan
}

/// The system directory, as Windows reports it. The environment is not asked: whoever
/// starts this process chooses its variables.
/// <https://learn.microsoft.com/windows/win32/api/sysinfoapi/nf-sysinfoapi-getsystemdirectoryw>
fn system_directory() -> Result<PathBuf, String> {
    let mut buffer = [0_u16; 260];
    // SAFETY: the buffer is a live, writable slice, and the binding passes its length.
    let written = unsafe { GetSystemDirectoryW(Some(&mut buffer)) };
    // The call returns 0 on failure, and the size it needs when the buffer is too small.
    match usize::try_from(written) {
        Ok(length) if length > 0 && length < buffer.len() => {
            Ok(PathBuf::from(OsString::from_wide(&buffer[..length])))
        }
        _ => Err(format!(
            "GetSystemDirectoryW returned {written}: {}",
            std::io::Error::last_os_error()
        )),
    }
}

/// The WFP ids of the programs the block lets through: this one, and the service host.
fn exempt_programs() -> Result<Vec<Vec<u8>>, String> {
    let this = std::env::current_exe()
        .map_err(|error| format!("this program's path is not known: {error}"))?;
    let service_host = system_directory()?.join(SERVICE_HOST);
    Ok(vec![wfp::app_id(&this)?, wfp::app_id(&service_host)?])
}

/// The block's filters, and the session that holds them.
struct BlockRules {
    exempt: Vec<Vec<u8>>,
    installed: Option<Installed>,
}

struct Installed {
    /// Closing it, by dropping it, deletes the filters.
    engine: wfp::Engine,
    filters: Vec<u64>,
}

impl DivertRules for BlockRules {
    fn check(&mut self) -> Result<(), String> {
        let installed = self
            .installed
            .as_ref()
            .ok_or("the DNS block is not installed")?;
        installed
            .filters
            .iter()
            .try_for_each(|filter| installed.engine.filter_is_there(*filter))
    }

    fn install(&mut self) -> Result<(), String> {
        // Ends the old session first, which deletes whatever is left of its filters.
        self.installed = None;
        let engine = wfp::Engine::open()?;
        let filters = engine.add(&filter_plan(&self.exempt))?;
        self.installed = Some(Installed { engine, filters });
        Ok(())
    }
}

/// The live block. Dropping it removes its filters.
pub(crate) struct ActiveBlock {
    watch: DivertWatch<BlockRules>,
}

impl ActiveBlock {
    /// Stops watching and removes the filters. Later calls do nothing.
    pub(crate) fn disable(&mut self) {
        self.watch.stop();
    }
}

/// Installs the block, and keeps it in place until it drops.
///
/// `report` hears when the filters are gone, as after another tool deleted them or the
/// Base Filtering Engine restarted, when they are back, and when they could not be put
/// back. They are checked every [`netmetrics_sys::DIVERT_CHECK_INTERVAL`].
///
/// # Errors
///
/// When the caller is not an Administrator, the filter engine cannot be reached, or an
/// exempt program cannot be named. Nothing is installed then.
pub(crate) fn install(report: DivertReport) -> Result<ActiveBlock, String> {
    let mut rules = BlockRules {
        exempt: exempt_programs()?,
        installed: None,
    };
    rules.install()?;
    Ok(ActiveBlock {
        watch: DivertWatch::start(rules, report)?,
    })
}
