//! Redirect of port 53 that bypasses the stub, kept in place while it is held.
//!
//! With `nft` installed the rules, `netmetrics_core::linux_dns_divert_ruleset`, live in an
//! nftables table of their own. Any root process can take them away: `nft delete table` and
//! `nft flush ruleset` delete the table, `nft flush table` empties its chains but leaves them
//! hooked, and a `dormant` flag unhooks them (`nft(8)`). Each time the watch checks, it lists
//! the table and compares that with the listing taken when the table was loaded, so every one
//! of these shows up as a difference, and the table is loaded again. Dropping the divert
//! deletes the table.
//!
//! Neither form lets a user through, root included. What they let through is a socket the
//! stub marked with [`exempt_socket`], which is how its own lookups reach an upstream.
//!
//! A host without `nft` gets the same rules through iptables,
//! `netmetrics_core::linux_iptables_divert_script`: a chain of their own in the `nat` and
//! `filter` tables of each address family, watched and put back the same way. Which of the
//! two forms a host uses is decided by whether `nft` is installed, when the divert is
//! installed and when a leftover one is cleared alike, so the form that was installed is the
//! one that is removed.

use netmetrics_core::{
    DivertReport, LINUX_IPTABLES_DIRS, LINUX_IPTABLES_DIVERT_TABLES, LINUX_NFT_PATHS,
    LinuxIptablesFamily, linux_dns_divert_disable_args, linux_dns_divert_install_args,
    linux_dns_divert_list_args, linux_dns_divert_ruleset, linux_iptables_divert_install_args,
    linux_iptables_divert_remove_args, linux_iptables_divert_rules,
    linux_iptables_divert_save_args, linux_iptables_divert_script,
};
use netmetrics_sys::{DivertRules, DivertWatch, run_command};
use std::path::{Path, PathBuf};

/// Live divert. Dropping it removes its rules.
pub struct ActiveDivert {
    watch: DivertWatch<LinuxDivert>,
}

impl ActiveDivert {
    /// Stops watching and removes the rules. Later calls do nothing, so rules installed
    /// after these are not removed by their owner's late cleanup.
    pub fn disable(&mut self) {
        self.watch.stop();
    }
}

/// Installs the port 53 rules, and keeps them in place until the divert drops.
///
/// `report` hears when the rules are lost, when they are back, and when they could not be
/// put back.
///
/// # Errors
///
/// Returns an error when neither `nft` nor the iptables programs are installed, or when the
/// one that is rejects the rules.
pub fn install(report: DivertReport) -> Result<ActiveDivert, String> {
    let mut rules = LinuxDivert::find()?;
    rules.install()?;
    Ok(ActiveDivert {
        watch: DivertWatch::start(rules, report)?,
    })
}

/// Marks `socket` as one the divert lets through, in either form: the stub's way to its
/// upstream resolver. Call it before the socket sends anything, a TCP socket before it
/// connects, because the first packet decides where the connection goes.
///
/// # Errors
///
/// What `setsockopt` reports, which is `PermissionDenied` without `CAP_NET_ADMIN` or
/// `CAP_NET_RAW`; see `netmetrics_core::LINUX_DNS_DIVERT_EXEMPT_MARK`.
#[cfg(target_os = "linux")]
pub fn exempt_socket(socket: &impl std::os::fd::AsFd) -> std::io::Result<()> {
    socket2::SockRef::from(socket).set_mark(netmetrics_core::LINUX_DNS_DIVERT_EXEMPT_MARK)
}

/// Removes rules left by this process or a previous one.
pub fn disable() {
    // Dropping the rules removes them, whether or not this process installed them.
    drop(LinuxDivert::find());
}

/// The divert in the form this host can hold.
enum LinuxDivert {
    Nft(NftDivert),
    Iptables(IptablesDivert),
}

impl LinuxDivert {
    /// The nftables form where `nft` is installed, and otherwise the iptables one.
    fn find() -> Result<Self, String> {
        let no_nft = match nft() {
            Ok(nft) => {
                return Ok(Self::Nft(NftDivert {
                    nft,
                    installed: String::new(),
                }));
            }
            Err(no_nft) => no_nft,
        };
        IptablesDivert::find()
            .map(Self::Iptables)
            .map_err(|no_iptables| format!("{no_nft}; {no_iptables}"))
    }
}

impl DivertRules for LinuxDivert {
    fn check(&mut self) -> Result<(), String> {
        match self {
            Self::Nft(rules) => rules.check(),
            Self::Iptables(rules) => rules.check(),
        }
    }

    fn install(&mut self) -> Result<(), String> {
        match self {
            Self::Nft(rules) => rules.install(),
            Self::Iptables(rules) => rules.install(),
        }
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

/// The iptables programs of both address families, and how they listed the divert's rules
/// when it was installed.
struct IptablesDivert {
    families: [IptablesFamily; 2],
    installed: String,
}

/// The programs of one address family.
struct IptablesFamily {
    family: LinuxIptablesFamily,
    rule: PathBuf,
    restore: PathBuf,
    save: PathBuf,
}

impl IptablesDivert {
    /// The programs of both families. With one family missing there is no divert: the DNS a
    /// program sends over that family would bypass the stub while the divert reported itself
    /// installed.
    fn find() -> Result<Self, String> {
        let [v4, v6] = LinuxIptablesFamily::ALL;
        Ok(Self {
            families: [IptablesFamily::find(v4)?, IptablesFamily::find(v6)?],
            installed: String::new(),
        })
    }

    /// The divert's rules in every table of both families, as `iptables-save` prints them.
    fn rules(&self) -> Result<String, String> {
        let mut rules = String::new();
        for family in &self.families {
            for table in LINUX_IPTABLES_DIVERT_TABLES {
                let listing =
                    run_command(&family.save, &linux_iptables_divert_save_args(table), None)?;
                rules.push_str(&linux_iptables_divert_rules(&listing.stdout));
            }
        }
        Ok(rules)
    }

    fn remove(&self) {
        for family in &self.families {
            family.remove();
        }
    }
}

impl DivertRules for IptablesDivert {
    fn check(&mut self) -> Result<(), String> {
        if self.rules()? == self.installed {
            Ok(())
        } else {
            Err("iptables no longer holds the rules the divert loaded".to_owned())
        }
    }

    /// Removes what is left of the chains and loads them again. A family that loads when the
    /// other does not is removed again, so the divert is in place for both or for neither.
    fn install(&mut self) -> Result<(), String> {
        self.remove();
        for family in &self.families {
            let script = linux_iptables_divert_script(family.family);
            if let Err(error) = run_command(
                &family.restore,
                &linux_iptables_divert_install_args(),
                Some(&script),
            ) {
                self.remove();
                return Err(error);
            }
        }
        self.installed = self.rules()?;
        Ok(())
    }
}

impl Drop for IptablesDivert {
    fn drop(&mut self) {
        self.remove();
    }
}

impl IptablesFamily {
    fn find(family: LinuxIptablesFamily) -> Result<Self, String> {
        Ok(Self {
            family,
            rule: iptables_program(family.rule_program())?,
            restore: iptables_program(family.restore_program())?,
            save: iptables_program(family.save_program())?,
        })
    }

    /// Removes the divert's chain from each table. Every call fails when what it removes is
    /// already gone, which is what a second removal finds.
    fn remove(&self) {
        for table in LINUX_IPTABLES_DIVERT_TABLES {
            for args in linux_iptables_divert_remove_args(table) {
                let _ = run_command(&self.rule, &args, None);
            }
        }
    }
}

/// An installed iptables program, found in the system directories distributions put it in.
fn iptables_program(name: &str) -> Result<PathBuf, String> {
    LINUX_IPTABLES_DIRS
        .iter()
        .map(|directory| Path::new(directory).join(name))
        .find(|path| path.is_file())
        .ok_or_else(|| format!("{name} is not installed: it is in none of {LINUX_IPTABLES_DIRS:?}"))
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    fn saved(family: &IptablesFamily, table: &str) -> String {
        run_command(&family.save, &linux_iptables_divert_save_args(table), None)
            .expect("iptables-save")
            .stdout
    }

    /// The iptables form on a real kernel: both families load, a chain someone empties is
    /// noticed and put back, and removal leaves no rule and no chain behind.
    #[test]
    #[ignore = "requires root; installs and removes iptables chains named ANTIWIRE_DNS"]
    fn live_iptables_divert_installs_is_watched_and_is_removed() {
        let mut divert = IptablesDivert::find().expect("the iptables programs");
        divert.install().expect("install");
        divert.check().expect("installed rules are in place");
        // Two tables in each of two families: a jump and three rules in each.
        assert_eq!(divert.installed.lines().count(), 16, "{}", divert.installed);
        for family in &divert.families {
            let nat = saved(family, "nat");
            assert!(
                nat.contains("--dport 53 -j REDIRECT --to-ports 53"),
                "{nat}"
            );
            assert!(nat.contains("-A OUTPUT -j ANTIWIRE_DNS"), "{nat}");
            let filter = saved(family, "filter");
            assert!(filter.contains("--dport 853 -j DROP"), "{filter}");
        }

        // What `iptables -F` does to the chain: it stays hooked and redirects nothing.
        let [_, empty, _] = linux_iptables_divert_remove_args("nat");
        run_command(&divert.families[0].rule, &empty, None).expect("flush the chain");
        divert
            .check()
            .expect_err("an emptied chain is a lost divert");
        divert.install().expect("install again");
        divert.check().expect("the rules are back");
        assert_eq!(divert.installed.lines().count(), 16, "{}", divert.installed);

        let families = IptablesDivert::find().expect("the iptables programs");
        drop(divert);
        assert_eq!(
            families.rules().expect("list"),
            "",
            "rules were left behind"
        );
        for family in &families.families {
            for table in LINUX_IPTABLES_DIVERT_TABLES {
                assert!(
                    !saved(family, table).contains("ANTIWIRE_DNS"),
                    "a chain was left in {table}"
                );
            }
        }
    }
}
