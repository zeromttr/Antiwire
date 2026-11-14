//! pf divert of port 53 that bypasses the stub, kept in place while it is held.
//!
//! The rules, `netmetrics_core::macos_dns_divert_rules`, route such a query to
//! `lo0` and redirect it to the stub there. `pfctl -E` returns a reference
//! token. Shutdown flushes only this anchor and releases that token, so pf is
//! not turned off for the rest of the system.
//!
//! Any root process can take the divert away. `pfctl -a <anchor> -F` flushes the anchor, and
//! pf deletes an anchor left empty. `pfctl -d` stops pf whatever references are held, and drops
//! every one of them (XNU `bsd/net/pf_ioctl.c`, `DIOCSTOP`). Loading or flushing the main
//! ruleset leaves the anchor's rules loaded, since a pf transaction replaces only the ruleset it
//! names (`pf_begin_rules`, `pf_commit_rules`), but a main ruleset without the `com.apple/*`
//! anchors never runs them. Each check looks for all three, and the anchor is loaded again.

use netmetrics_core::{DivertReport, MacosPfctlCommand};
use netmetrics_sys::{CommandOutput, DivertRules, DivertWatch, run_command};
use std::path::{Path, PathBuf};

const PFCTL: &str = "/sbin/pfctl";
const TOKEN_FILE: &str = "pf-enable-token";

/// Live pf anchor. Dropping it flushes the anchor and releases the enable token.
pub struct ActiveDivert {
    watch: DivertWatch<PfDivert>,
}

impl ActiveDivert {
    /// Stops watching, flushes the anchor and releases the pf reference. Later
    /// calls do nothing, so a divert installed after this one keeps its anchor.
    pub fn disable(&mut self) {
        self.watch.stop();
    }
}

/// Loads the port 53 divert into its anchor and takes a pf enable reference, and keeps both
/// in place until the divert drops.
///
/// `report` hears when the divert is lost, when it is back, and when it could not be put back.
///
/// # Errors
///
/// Returns an error when `pfctl` is missing, when the main ruleset would not run
/// the anchor's rules, or when `pfctl` rejects them.
pub fn install(report: DivertReport) -> Result<ActiveDivert, String> {
    check_main_ruleset()?;
    let mut rules = PfDivert {
        token: None,
        installed: String::new(),
    };
    // Owning the reference from here on means every failure below releases it
    // when `rules` drops, instead of leaving pf enabled for nobody.
    rules.take_reference()?;
    rules.load()?;
    Ok(ActiveDivert {
        watch: DivertWatch::start(rules, report)?,
    })
}

/// The loaded anchor, the reference that keeps pf enabled for it, and how pfctl listed the
/// anchor when it was loaded.
struct PfDivert {
    token: Option<String>,
    installed: String,
}

impl PfDivert {
    /// Enables pf with a reference of this divert's own (`pfctl -E`), and keeps its token
    /// where a later process can release it.
    fn take_reference(&mut self) -> Result<(), String> {
        let enabled = pfctl(MacosPfctlCommand::Enable, None)?;
        self.token = parse_token(&enabled.stderr).or_else(|| parse_token(&enabled.stdout));
        match self.token.as_deref() {
            Some(token) => persist_token(token),
            None => forget_persisted_token(),
        }
        Ok(())
    }

    /// Loads the port 53 divert rules into the divert anchor, replacing what it held, and
    /// keeps the listing of what pf loaded.
    fn load(&mut self) -> Result<(), String> {
        pfctl(
            MacosPfctlCommand::LoadAnchor,
            Some(netmetrics_core::macos_dns_divert_rules()),
        )?;
        let installed = anchor_rules()?;
        if installed.trim().is_empty() {
            return Err("pfctl lists none of the divert rules it loaded".to_owned());
        }
        self.installed = installed;
        Ok(())
    }
}

impl DivertRules for PfDivert {
    fn check(&mut self) -> Result<(), String> {
        if anchor_rules()? != self.installed {
            return Err("the pf anchor no longer holds the rules the divert loaded".to_owned());
        }
        if !pf_running()? {
            return Err("pf is disabled".to_owned());
        }
        check_main_ruleset()
    }

    fn install(&mut self) -> Result<(), String> {
        check_main_ruleset()?;
        if !pf_running()? {
            // Stopping pf dropped every reference, this divert's too, so the old token
            // cannot be released any more. A new reference replaces it.
            self.take_reference()?;
        }
        self.load()
    }
}

impl Drop for PfDivert {
    fn drop(&mut self) {
        disable(self.token.take());
    }
}

/// Refuses a main ruleset under which the anchor's rules would load but not work.
///
/// Loading an unattached anchor succeeds but never applies its rules: the
/// `rdr` rules run only through an `rdr-anchor`, and the filter rules only
/// through an `anchor`, that reaches `com.apple/*`. And pf "does not process
/// in any way" a packet on an interface the main ruleset skips (`set skip on`,
/// `pf.conf(5)`). With `lo0` skipped, every query the filter rule routes there
/// would arrive untranslated and be lost instead of answered.
fn check_main_ruleset() -> Result<(), String> {
    for (list, kind) in [
        (MacosPfctlCommand::ListTranslation, "rdr-anchor"),
        (MacosPfctlCommand::ListFilter, "anchor"),
    ] {
        if !anchor_attached(&pfctl(list, None)?.stdout, kind) {
            return Err(format!(
                "PF main ruleset does not attach {kind} for com.apple/*"
            ));
        }
    }
    match lo0_skipped(&pfctl(MacosPfctlCommand::ListLoopback, None)?.stdout) {
        Some(false) => Ok(()),
        Some(true) => Err("PF skips lo0, where the divert hands queries to the stub".to_owned()),
        None => Err("pfctl -s Interfaces did not list lo0".to_owned()),
    }
}

/// The divert anchor's translation and filter rules as pfctl lists them. pfctl fails to list
/// an anchor pf has deleted.
fn anchor_rules() -> Result<String, String> {
    let translation = pfctl(MacosPfctlCommand::ListAnchorTranslation, None)?;
    let filter = pfctl(MacosPfctlCommand::ListAnchorFilter, None)?;
    Ok(translation.stdout + &filter.stdout)
}

/// Whether pf is enabled, by `pfctl -s info`.
fn pf_running() -> Result<bool, String> {
    pf_enabled(&pfctl(MacosPfctlCommand::Status, None)?.stdout)
        .ok_or_else(|| "pfctl -s info printed no status".to_owned())
}

/// Runs `/sbin/pfctl` (`pfctl(8)`) for `command`, bounded and checked, with `input` on its
/// standard input.
fn pfctl(command: MacosPfctlCommand<'_>, input: Option<&str>) -> Result<CommandOutput, String> {
    run_command(Path::new(PFCTL), &command.args(), input)
}

/// Flushes the anchor. `token` releases a reference taken by `pfctl -E`.
///
/// A missing token is read from the data directory, so a process that did not
/// run this destructor can still release the reference.
pub fn disable(token: Option<String>) {
    // pfctl fails to flush an anchor pf has already deleted, which is what a second
    // removal finds.
    let _ = pfctl(MacosPfctlCommand::FlushAnchor, None);
    if let Some(token) = token.or_else(take_persisted_token) {
        // pfctl fails for a reference that `pfctl -d` already dropped; there is nothing
        // left to release then.
        let _ = pfctl(MacosPfctlCommand::Release(&token), None);
        forget_persisted_token();
    }
}

fn token_path() -> Option<PathBuf> {
    std::env::var_os("ANTIWIRE_DATA_DIR").map(|dir| PathBuf::from(dir).join(TOKEN_FILE))
}

fn persist_token(token: &str) {
    let Some(path) = token_path() else {
        return;
    };
    let _ = std::fs::write(path, token);
}

fn take_persisted_token() -> Option<String> {
    let path = token_path()?;
    let token = std::fs::read_to_string(&path).ok()?;
    let token = token.trim();
    is_token(token).then(|| token.to_owned())
}

fn forget_persisted_token() {
    if let Some(path) = token_path() {
        let _ = std::fs::remove_file(path);
    }
}

fn parse_token(text: &str) -> Option<String> {
    text.lines().find_map(|line| {
        let token = line
            .split_once(':')
            .filter(|(label, _)| label.trim().eq_ignore_ascii_case("token"))?
            .1
            .trim();
        is_token(token).then(|| token.to_owned())
    })
}

/// Whether `text` can be a pf enable token, which XNU keeps as a `u_int64_t`
/// (`struct pfioc_remove_token`) and pfctl prints in decimal. Nothing else reaches `pfctl -X`.
fn is_token(text: &str) -> bool {
    text.bytes().all(|byte| byte.is_ascii_digit()) && text.parse::<u64>().is_ok()
}

fn anchor_attached(rules: &str, kind: &str) -> bool {
    rules.lines().any(|line| {
        line.trim_start().starts_with(kind)
            && (line.contains("com.apple/*")
                || line.contains(netmetrics_core::MACOS_DNS_DIVERT_ANCHOR))
    })
}

/// Whether `pfctl -s Interfaces -v -i lo0` marks `lo0` as skipped, or `None`
/// when it does not list `lo0` at all.
///
/// `pfctl(8)` says that with `-v` this listing "lists which interfaces have skip
/// rules activated", but not how. Apple has not published its pfctl source; the
/// BSD pfctl it derives from prints ` (skip)` after the interface's name
/// (FreeBSD `sbin/pfctl/pfctl_table.c`, `print_iface`).
fn lo0_skipped(listing: &str) -> Option<bool> {
    listing.lines().find_map(|line| {
        let mut words = line.split_whitespace();
        (words.next() == Some("lo0")).then(|| words.any(|word| word.contains("skip")))
    })
}

/// Whether `pfctl -s info` reports pf enabled, or `None` when it prints no status.
///
/// `pfctl(8)` says only that `-s info` shows "filter information". Apple has not published its
/// pfctl source; the BSD pfctl it derives from starts the listing with `Status: Enabled` or
/// `Status: Disabled`, then how long pf has been in that state, then the debug level
/// (FreeBSD `sbin/pfctl/pfctl_parser.c`, `print_status`).
fn pf_enabled(info: &str) -> Option<bool> {
    info.lines().find_map(|line| {
        let mut words = line.split_whitespace();
        if words.next() != Some("Status:") {
            return None;
        }
        match words.next() {
            Some("Enabled") => Some(true),
            Some("Disabled") => Some(false),
            _ => None,
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enable_token_is_parsed_from_pfctl_stderr() {
        assert_eq!(
            parse_token("pf enabled\nToken : 844218394\n"),
            Some("844218394".to_owned())
        );
        assert_eq!(parse_token("no token here"), None);
    }

    /// Only a decimal `u_int64_t` is passed to `pfctl -X`; nothing that could read as an option.
    #[test]
    fn only_a_decimal_token_is_accepted() {
        assert!(is_token("18446744073709551615"));
        assert!(!is_token(""));
        assert!(!is_token("-d"));
        assert!(!is_token("+1"));
        assert!(!is_token("12 34"));
        assert!(!is_token("18446744073709551616"));
        assert_eq!(parse_token("Token : -d\n"), None);
    }

    #[test]
    fn anchor_must_be_referenced_by_the_main_ruleset() {
        assert!(anchor_attached(
            "rdr-anchor \"com.apple/*\" all",
            "rdr-anchor"
        ));
        assert!(anchor_attached("anchor \"com.apple/*\" all", "anchor"));
        assert!(!anchor_attached("anchor \"other/*\" all", "anchor"));
    }

    #[test]
    fn a_skipped_lo0_is_told_apart_from_a_missing_one() {
        assert_eq!(lo0_skipped("lo0\n"), Some(false));
        assert_eq!(lo0_skipped("lo0 (skip)\n"), Some(true));
        assert_eq!(lo0_skipped("lo (skip)\nlo0 (skip)\n"), Some(true));
        assert_eq!(lo0_skipped("lo01\nen0 (skip)\n"), None);
        assert_eq!(lo0_skipped(""), None);
    }

    /// The listing as BSD `print_status` writes it: the status line padded to 44 columns, then
    /// the debug level, and the time only once pf has been started or stopped.
    #[test]
    fn pf_status_is_read_from_the_info_listing() {
        let enabled = format!(
            "{:<44}{:>15}\n\nState Table                          Total             Rate\n",
            "Status: Enabled for 0 days 01:02:03", "Debug: Urgent"
        );
        assert_eq!(pf_enabled(&enabled), Some(true));
        let disabled = format!("{:<44}{:>15}\n\n", "Status: Disabled", "Debug: None");
        assert_eq!(pf_enabled(&disabled), Some(false));
        assert_eq!(pf_enabled("Status: Unknown\n"), None);
        assert_eq!(pf_enabled("State Table  Total  Rate\n"), None);
        assert_eq!(pf_enabled(""), None);
    }
}
