//! pf anchor and table rendering and reconstruction for macOS PF.
//!
//! Renders both Cartesian and [`AddressSetMode::Set`](firew_core::AddressSetMode::Set) rules into a single
//! unified anchor ruleset loaded via `pfctl -a <anchor> -f -`, and reconstructs
//! logical [`Rule`]s from `pfctl -a <anchor> -s rules` and `pfctl -a <anchor>
//! -t <table> -T show`.
//!
//! This module is compiled on every host — not just macOS — because the
//! ruleset rendering and reconstruction parsers are pure string work and are
//! unit-tested on every platform.

#![cfg_attr(not(target_os = "macos"), allow(dead_code))]

use std::collections::BTreeMap;
use std::io::Write as _;
use std::process::{Command, Stdio};

use firew_core::{Error, ErrorKind, Rule, RuleKey};
use firew_sys::{parse_native_net, ManagedNamespace};
use ipnet::IpNet;

mod parse;
mod render;
#[cfg(test)]
mod tests;

pub use parse::reconstruct_anchor_text;
#[cfg(test)]
pub use render::render_anchor;
pub use render::render_full_anchor;

/// Upper bound on addresses in one pf table.
pub const MAX_TABLE_ENTRIES: usize = 65_536;

/// `PF_TABLE_NAME_SIZE` is 32 bytes including the trailing NUL terminator.
pub const MAX_PF_TABLE_NAME_LEN: usize = 31;

/// Returns whether the `pfctl` binary is usable on this host.
pub fn is_available() -> bool {
    Command::new("pfctl")
        .arg("-s")
        .arg("info")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .stdin(Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

/// Derives a namespace-scoped pf table name from a rule key.
///
/// Uses `namespace.native_object_token(key)` (`fw_<16-char-token>`, 19 bytes),
/// which stays well below PF's 31-character `PF_TABLE_NAME_SIZE - 1` limit even
/// for 32-character [`RuleKey`]s and isolates distinct manager namespaces.
#[must_use]
pub fn table_name_for(namespace: &ManagedNamespace, key: &RuleKey) -> String {
    let name = format!("fw_{}", namespace.native_object_token(key));
    debug_assert!(name.len() <= MAX_PF_TABLE_NAME_LEN);
    name
}

/// Classifies `pfctl` stderr so non-privilege syntax or limit failures are not
/// misreported as [`ErrorKind::PermissionDenied`].
#[must_use]
pub fn classify_pfctl_stderr(stderr: &str) -> ErrorKind {
    firew_sys::classify_cli_failure(
        stderr,
        &[
            "syntax error",
            "invalid",
            "only applies to",
            "table name too long",
        ],
    )
}

/// Loads `ruleset` into `anchor`, replacing its previous contents atomically.
///
/// # Errors
///
/// Returns an error when `pfctl` cannot be spawned or rejects the ruleset.
pub fn load_anchor(anchor: &str, ruleset: &str) -> Result<(), Error> {
    let mut child = Command::new("pfctl")
        .args(["-a", anchor, "-f", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| {
            Error::new(
                ErrorKind::BackendUnavailable,
                format!("failed to run pfctl: {error}"),
            )
        })?;

    child
        .stdin
        .take()
        .ok_or_else(|| Error::new(ErrorKind::Internal, "pfctl stdin unavailable"))?
        .write_all(ruleset.as_bytes())
        .map_err(|error| {
            Error::new(
                ErrorKind::Internal,
                format!("failed to write pf ruleset: {error}"),
            )
        })?;

    let output = child.wait_with_output().map_err(|error| {
        Error::new(
            ErrorKind::Internal,
            format!("failed to wait for pfctl: {error}"),
        )
    })?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let trimmed = stderr.trim();
        return Err(Error::new(
            classify_pfctl_stderr(trimmed),
            format!("pfctl anchor load failed: {trimmed}"),
        ));
    }
    Ok(())
}

/// Managed rules rebuilt from an anchor listing, and the lines that were not.
#[derive(Debug, Default)]
pub struct AnchorListing {
    /// Logical rules rebuilt from complete, consistent rows.
    pub rules: BTreeMap<RuleKey, Rule>,
    /// Drift descriptions for `firew_sys::DriftTracker`.
    pub drifted: Vec<String>,
    /// Rule lines that did not rebuild into `rules`, verbatim, with the logical
    /// key whose marker they carry when one parsed.
    ///
    /// Loading an anchor replaces all of it, so a rewrite from `rules` alone
    /// would delete these: a rule edited outside the manager, or one the parser
    /// misread, would vanish on the next unrelated edit. They are written back
    /// instead, the way other backends leave drifted rows in place.
    pub unrecognized: Vec<(Option<RuleKey>, String)>,
}

/// Queries the rules and tables currently active in `anchor` via `pfctl` and
/// reconstructs the logical [`Rule`] map.
///
/// # Errors
///
/// Returns an error when `pfctl` cannot be spawned or fails. A failed listing
/// is never an empty anchor: the next edit rewrites the anchor from what this
/// returns, so treating a failure as empty would delete every rule in it.
pub fn query_anchor_rules(
    anchor: &str,
    namespace: &ManagedNamespace,
) -> Result<AnchorListing, Error> {
    let output = Command::new("pfctl")
        .args(["-a", anchor, "-s", "rules"])
        .stdin(Stdio::null())
        .output()
        .map_err(|error| {
            Error::new(
                ErrorKind::BackendUnavailable,
                format!("failed to run pfctl -s rules: {error}"),
            )
        })?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let trimmed = stderr.trim();
        return Err(Error::new(
            classify_pfctl_stderr(trimmed),
            format!("pfctl -a {anchor} -s rules failed: {trimmed}"),
        ));
    }
    let rules_text = String::from_utf8_lossy(&output.stdout);
    reconstruct_anchor_text(&rules_text, namespace, |table_name| {
        read_table_entries(anchor, table_name)
    })
}

fn read_table_entries(anchor: &str, table_name: &str) -> Result<Option<Vec<IpNet>>, Error> {
    let output = Command::new("pfctl")
        .args(["-a", anchor, "-t", table_name, "-T", "show"])
        .stdin(Stdio::null())
        .output()
        .map_err(|error| {
            Error::new(
                ErrorKind::BackendUnavailable,
                format!("failed to run pfctl table show: {error}"),
            )
        })?;
    table_show_outcome(
        table_name,
        output.status.success(),
        &String::from_utf8_lossy(&output.stdout),
        &String::from_utf8_lossy(&output.stderr),
    )
}

/// Maps a `pfctl -T show` exit to the table's entries, `None` for a table that
/// does not exist, or an error. Any other failure, such as missing privileges,
/// says nothing about whether the table is still in use.
fn table_show_outcome(
    table_name: &str,
    succeeded: bool,
    stdout: &str,
    stderr: &str,
) -> Result<Option<Vec<IpNet>>, Error> {
    if !succeeded {
        let trimmed = stderr.trim();
        if firew_sys::reports_missing_object(trimmed) {
            return Ok(None);
        }
        return Err(Error::new(
            classify_pfctl_stderr(trimmed),
            format!("pfctl table <{table_name}> show failed: {trimmed}"),
        ));
    }
    let nets: Vec<IpNet> = stdout
        .lines()
        .filter_map(|line| {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                return None;
            }
            parse_native_net(trimmed)
        })
        .collect();
    Ok(Some(nets))
}
