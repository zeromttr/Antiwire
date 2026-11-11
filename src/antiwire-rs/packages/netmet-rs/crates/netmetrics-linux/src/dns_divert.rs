//! nftables NAT redirect of bypassed port 53. The table is deleted on drop.

use std::io::Write;
use std::process::{Command, Stdio};

/// Live nftables divert. Dropping it deletes the table.
pub struct ActiveDivert {
    active: bool,
}

impl ActiveDivert {
    /// Deletes the nat table. Later calls do nothing, so a table installed
    /// after this one is not removed by its owner's late cleanup.
    pub fn disable(&mut self) {
        if std::mem::take(&mut self.active) {
            disable();
        }
    }
}

impl Drop for ActiveDivert {
    fn drop(&mut self) {
        self.disable();
    }
}

/// Installs the port 53 nat table.
///
/// # Errors
///
/// Returns an error when `nft` is missing or rejects the ruleset.
pub fn install() -> Result<ActiveDivert, String> {
    let mut child = Command::new("nft")
        .arg("-f")
        .arg("-")
        .stdin(Stdio::piped())
        .spawn()
        .map_err(|error| format!("nft is unavailable: {error}"))?;
    {
        let stdin = child.stdin.as_mut().ok_or("nft stdin was not piped")?;
        stdin
            .write_all(netmetrics_core::linux_dns_divert_ruleset().as_bytes())
            .map_err(|error| error.to_string())?;
    }
    let status = child.wait().map_err(|error| error.to_string())?;
    if status.success() {
        Ok(ActiveDivert { active: true })
    } else {
        Err(format!("nft refused the port 53 divert: {status}"))
    }
}

/// Removes a table left by this process or a previous one.
pub fn disable() {
    let _ = Command::new("nft")
        .args(netmetrics_core::linux_dns_divert_disable_args())
        .status();
}
