//! nftables redirect of port 53 that bypasses the stub, kept in place while it is held.
//!
//! The rules, `netmetrics_core::linux_dns_divert_ruleset`, live in a table of their own. Any
//! root process can take them away: `nft delete table` and `nft flush ruleset` delete the
//! table, `nft flush table` empties its chains but leaves them hooked, and a `dormant` flag
//! unhooks them (`nft(8)`). Each time the watch checks, it lists the table and compares that
//! with the listing taken when the table was loaded, so every one of these shows up as a
//! difference, and the table is loaded again. Dropping the divert deletes the table.

use netmetrics_core::{
    DivertReport, LINUX_NFT_PATHS, linux_dns_divert_disable_args, linux_dns_divert_install_args,
    linux_dns_divert_list_args, linux_dns_divert_ruleset,
};
use netmetrics_sys::{DivertRules, DivertWatch, run_command};
use std::path::Path;

/// Live nftables divert. Dropping it deletes the table.
pub struct ActiveDivert {
    watch: DivertWatch<NftDivert>,
}

impl ActiveDivert {
    /// Stops watching and deletes the table. Later calls do nothing, so a table installed
    /// after this one is not removed by its owner's late cleanup.
    pub fn disable(&mut self) {
        self.watch.stop();
    }
}

/// Installs the port 53 table, and keeps it in place until the divert drops.
///
/// `report` hears when the table is lost, when it is back, and when it could not be put back.
///
/// # Errors
///
/// Returns an error when `nft` is missing or rejects the ruleset.
pub fn install(report: DivertReport) -> Result<ActiveDivert, String> {
    let mut rules = NftDivert {
        nft: nft()?,
        installed: String::new(),
    };
    rules.install()?;
    Ok(ActiveDivert {
        watch: DivertWatch::start(rules, report)?,
    })
}

/// Removes a table left by this process or a previous one.
pub fn disable() {
    if let Ok(nft) = nft() {
        delete_table(nft);
    }
}

/// The installed table, and how `nft` listed it then.
struct NftDivert {
    nft: &'static Path,
    installed: String,
}

impl DivertRules for NftDivert {
    fn check(&mut self) -> Result<(), String> {
        if list_table(self.nft)? == self.installed {
            Ok(())
        } else {
            Err("the nftables table no longer holds the rules the divert loaded".to_owned())
        }
    }

    fn install(&mut self) -> Result<(), String> {
        run_command(
            self.nft,
            &linux_dns_divert_install_args(),
            Some(linux_dns_divert_ruleset()),
        )?;
        self.installed = list_table(self.nft)?;
        Ok(())
    }
}

impl Drop for NftDivert {
    fn drop(&mut self) {
        delete_table(self.nft);
    }
}

/// The divert's table as `nft list table` prints it. A missing table is an error.
fn list_table(nft: &Path) -> Result<String, String> {
    Ok(run_command(nft, &linux_dns_divert_list_args(), None)?.stdout)
}

fn delete_table(nft: &Path) {
    // nft fails when there is no table to delete, which is what a second removal finds.
    let _ = run_command(nft, &linux_dns_divert_disable_args(), None);
}

/// The installed `nft`, found in the system directories distributions put it in.
fn nft() -> Result<&'static Path, String> {
    LINUX_NFT_PATHS
        .iter()
        .map(Path::new)
        .find(|path| path.is_file())
        .ok_or_else(|| format!("nft is not installed: none of {LINUX_NFT_PATHS:?} exists"))
}
