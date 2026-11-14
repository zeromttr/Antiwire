//! `ipset` helpers for the iptables backend.
//!
//! The `iptables` crate has no ipset support, and libipset has no maintained
//! Rust binding, so set management shells out to the `ipset` binary. That is
//! the documented, stable interface, and `ipset restore` lets a whole set be
//! populated in one process rather than one exec per address.
//!
//! Only IPv4 is handled here: the iptables backend rejects IPv6 matchers
//! outright, so an IPv6 set could never be referenced by a rule it creates.
//!
//! This module is compiled on every host — not just Linux — because the script
//! rendering and save-output parsing are pure and worth unit-testing anywhere.
//! Only the callers are Linux-gated, hence the allowance below.

#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

use firew_sys::parse_native_net;
use std::fmt::Write as _;
use std::io::Write as _;
use std::process::{Command, Stdio};

use firew_core::{Error, ErrorKind, RuleKey};
use firew_sys::ManagedNamespace;
use ipnet::IpNet;

/// `IPSET_MAXNAMELEN` is 32 including the NUL terminator.
const MAX_SET_NAME_LEN: usize = 31;

/// Upper bound on entries in one ipset.
///
/// `hash:net` sets default to a 65,536-element maxelem, which is also the
/// largest country list we expect to install.
pub const MAX_SET_ENTRIES: usize = 65_536;

/// Returns whether the `ipset` binary is usable on this host.
///
/// Probed once when the backend opens: without it the backend cannot offer
/// native address sets and reports no set capability, so callers chunk instead.
pub fn is_available() -> bool {
    Command::new("ipset")
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .stdin(Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

/// Derives an ipset name from a rule key.
pub fn set_name_for(namespace: &ManagedNamespace, key: &RuleKey) -> String {
    let name = format!("fw_{}", namespace.native_object_token(key));
    debug_assert!(name.len() <= MAX_SET_NAME_LEN);
    name
}

/// Creates `name` and fills it with `nets`, replacing any existing set.
///
/// Uses `ipset restore`, which applies the whole script as one operation, so a
/// large list costs one process rather than one per address. Building into a
/// temporary set and swapping keeps the live set intact if the load fails.
///
/// # Errors
///
/// Returns an error when `ipset` cannot be spawned or exits non-zero.
pub fn create_and_fill(name: &str, nets: &[IpNet]) -> Result<(), Error> {
    if nets.len() > MAX_SET_ENTRIES {
        return Err(Error::new(
            ErrorKind::LimitExceeded,
            format!(
                "ipset {name} would hold {} entries; maximum is {MAX_SET_ENTRIES}",
                nets.len()
            ),
        ));
    }

    let temp = temp_name(name);
    let mut script = String::with_capacity(nets.len() * 20 + 256);
    writeln!(script, "create {temp} hash:net family inet -exist")
        .expect("writing to a String cannot fail");
    writeln!(script, "flush {temp}").expect("writing to a String cannot fail");
    for net in nets {
        let canonical = net.trunc();
        writeln!(script, "add {temp} {canonical}").expect("writing to a String cannot fail");
    }
    writeln!(script, "create {name} hash:net family inet -exist")
        .expect("writing to a String cannot fail");
    writeln!(script, "swap {temp} {name}").expect("writing to a String cannot fail");
    writeln!(script, "destroy {temp}").expect("writing to a String cannot fail");

    run_restore(&script)
}

/// Removes `name`, ignoring a set that is already gone.
///
/// # Errors
///
/// Returns an error when `ipset` cannot be spawned, or when it fails for any
/// reason other than the set not existing, such as a rule still using it.
pub fn destroy(name: &str) -> Result<(), Error> {
    let output = Command::new("ipset")
        .args(["destroy", name])
        .stdout(Stdio::null())
        .stdin(Stdio::null())
        .output()
        .map_err(|error| {
            Error::new(
                ErrorKind::BackendUnavailable,
                format!("failed to run ipset destroy: {error}"),
            )
        })?;
    destroy_outcome(
        name,
        output.status.success(),
        &String::from_utf8_lossy(&output.stderr),
    )
}

/// Maps an `ipset destroy` exit to a result: success, or a set that was
/// already gone, is `Ok`; anything else is an error carrying `stderr`.
fn destroy_outcome(name: &str, succeeded: bool, stderr: &str) -> Result<(), Error> {
    if succeeded || firew_sys::reports_missing_object(stderr) {
        return Ok(());
    }
    let detail = stderr.trim();
    Err(Error::new(
        classify_cli_stderr(detail),
        format!("ipset destroy {name}: {detail}"),
    ))
}

/// Reads the entries currently stored in `name`, returning `Ok(None)` when the
/// set does not exist in the kernel.
///
/// # Errors
///
/// Returns an error when `ipset` cannot be spawned, or when it fails for any
/// reason other than the set not existing, such as missing privileges. Those
/// are not "missing": the set may still be in use by an enforcing rule.
pub fn list_entries_opt(name: &str) -> Result<Option<Vec<IpNet>>, Error> {
    let output = Command::new("ipset")
        .args(["list", name, "-o", "save"])
        .stdin(Stdio::null())
        .output()
        .map_err(|error| {
            Error::new(
                ErrorKind::BackendUnavailable,
                format!("failed to run ipset list: {error}"),
            )
        })?;
    list_outcome(
        name,
        output.status.success(),
        &String::from_utf8_lossy(&output.stdout),
        &String::from_utf8_lossy(&output.stderr),
    )
}

/// Maps an `ipset list` exit to its entries, `None` for a set that does not
/// exist, or an error carrying `stderr`.
fn list_outcome(
    name: &str,
    succeeded: bool,
    stdout: &str,
    stderr: &str,
) -> Result<Option<Vec<IpNet>>, Error> {
    if succeeded {
        return Ok(Some(parse_save_output(stdout, name)));
    }
    if firew_sys::reports_missing_object(stderr) {
        return Ok(None);
    }
    let detail = stderr.trim();
    Err(Error::new(
        classify_cli_stderr(detail),
        format!("ipset list {name}: {detail}"),
    ))
}

/// Extracts `add <name> <cidr>` entries from `ipset save` output.
pub(crate) fn parse_save_output(text: &str, name: &str) -> Vec<IpNet> {
    text.lines()
        .filter_map(|line| {
            let mut parts = line.split_whitespace();
            if parts.next()? != "add" || parts.next()? != name {
                return None;
            }
            let token = parts.next()?;
            parse_native_net(token)
        })
        .collect()
}

fn temp_name(name: &str) -> String {
    let mut temp = name.to_owned();
    if temp.len() + 2 > MAX_SET_NAME_LEN {
        temp.truncate(MAX_SET_NAME_LEN - 2);
    }
    temp.push_str("_t");
    temp
}

pub(crate) fn classify_cli_stderr(stderr: &str) -> ErrorKind {
    firew_sys::classify_cli_failure(
        stderr,
        &["syntax error", "invalid argument", "cannot be parsed"],
    )
}

fn run_restore(script: &str) -> Result<(), Error> {
    let mut child = Command::new("ipset")
        .arg("restore")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| {
            Error::new(
                ErrorKind::BackendUnavailable,
                format!("failed to run ipset restore: {error}"),
            )
        })?;

    child
        .stdin
        .take()
        .ok_or_else(|| Error::new(ErrorKind::Internal, "ipset stdin unavailable"))?
        .write_all(script.as_bytes())
        .map_err(|error| {
            Error::new(
                ErrorKind::Internal,
                format!("failed to write ipset script: {error}"),
            )
        })?;

    let output = child.wait_with_output().map_err(|error| {
        Error::new(
            ErrorKind::Internal,
            format!("failed to wait for ipset: {error}"),
        )
    })?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let trimmed = stderr.trim();
        return Err(Error::new(
            classify_cli_stderr(trimmed),
            format!("ipset restore failed: {trimmed}"),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn list_reports_failures_other_than_a_missing_set() {
        assert_eq!(
            list_outcome(
                "s",
                true,
                "add s 192.0.2.0/24
",
                ""
            )
            .expect("listed"),
            Some(vec!["192.0.2.0/24".parse::<IpNet>().expect("net")])
        );
        assert_eq!(
            list_outcome(
                "s",
                false,
                "",
                "ipset v7.17: The set with the given name does not exist"
            )
            .expect("missing set"),
            None
        );
        let error = list_outcome(
            "s",
            false,
            "",
            "ipset v7.17: Kernel error received: Operation not permitted",
        )
        .expect_err("a permission failure is not a missing set");
        assert_eq!(error.kind(), ErrorKind::PermissionDenied);
    }

    #[test]
    fn destroy_accepts_only_success_or_a_missing_set() {
        assert!(destroy_outcome("s", true, "").is_ok());
        assert!(destroy_outcome(
            "s",
            false,
            "ipset v7.17: The set with the given name does not exist\n"
        )
        .is_ok());
        let in_use = destroy_outcome(
            "s",
            false,
            "ipset v7.17: Set cannot be destroyed: it is in use by a kernel component\n",
        )
        .expect_err("a set still in use was not destroyed");
        assert_eq!(in_use.kind(), ErrorKind::Internal);
        let denied = destroy_outcome("s", false, "ipset v7.17: Operation not permitted")
            .expect_err("permission failure");
        assert_eq!(denied.kind(), ErrorKind::PermissionDenied);
    }

    #[test]
    fn set_names_are_sanitized_and_bounded() {
        let namespace = ManagedNamespace::derive("manager", "application");
        let key = RuleKey::try_from("cb0000100002").expect("key");
        let hyphenated = RuleKey::try_from("live-inetfw-block").expect("key");
        let name = set_name_for(&namespace, &key);
        let hyphenated_name = set_name_for(&namespace, &hyphenated);

        assert!(name.len() <= MAX_SET_NAME_LEN);
        assert!(hyphenated_name.len() <= MAX_SET_NAME_LEN);
        assert_ne!(name, hyphenated_name);
    }

    #[test]
    fn set_names_do_not_alias_keys_or_manager_namespaces() {
        let first = ManagedNamespace::derive("first", "");
        let second = ManagedNamespace::derive("second", "");
        let hyphen = RuleKey::try_from("a-b").expect("key");
        let underscore = RuleKey::try_from("a_b").expect("key");

        assert_ne!(
            set_name_for(&first, &hyphen),
            set_name_for(&first, &underscore)
        );
        assert_ne!(
            set_name_for(&first, &hyphen),
            set_name_for(&second, &hyphen)
        );
    }

    #[test]
    fn save_output_parsing_keeps_only_matching_entries() {
        let text = "create fw_x hash:net family inet hashsize 1024 maxelem 65536\n\
                    add fw_x 203.0.113.0/24\n\
                    add fw_x 198.51.100.7\n\
                    add fw_other 10.0.0.0/8\n\
                    add fw_x not-an-address\n";
        let entries = parse_save_output(text, "fw_x");
        assert_eq!(
            entries,
            vec![
                "203.0.113.0/24".parse::<IpNet>().expect("net"),
                "198.51.100.7/32".parse::<IpNet>().expect("net"),
            ]
        );
    }

    #[test]
    fn temp_name_stays_within_the_name_limit() {
        let long = "f".repeat(MAX_SET_NAME_LEN);
        assert!(temp_name(&long).len() <= MAX_SET_NAME_LEN);
        assert!(temp_name("fw_short").len() <= MAX_SET_NAME_LEN);
    }

    #[test]
    fn classifies_cli_errors_accurately() {
        assert_eq!(
            classify_cli_stderr("ipset v7.19: Kernel error received: Operation not permitted"),
            ErrorKind::PermissionDenied
        );
        assert_eq!(
            classify_cli_stderr("ipset v7.19: Syntax error: cannot parse 999.999.999.999"),
            ErrorKind::InvalidRule
        );
        assert_eq!(
            classify_cli_stderr("ipset v7.19: Set cannot be destroyed: it is in use"),
            ErrorKind::Internal
        );
    }
}
