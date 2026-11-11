//! pf rdr of bypassed port 53. The anchor is flushed on drop.
//!
//! `pfctl -E` returns a reference token. Shutdown flushes only this anchor and
//! releases that token, so pf is not turned off for the rest of the system.

use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};

const TOKEN_FILE: &str = "pf-enable-token";

/// Live pf anchor. Dropping it flushes the anchor and releases the enable token.
pub struct ActiveDivert {
    token: Option<String>,
    active: bool,
}

impl ActiveDivert {
    /// Flushes the anchor and releases the pf reference. Later calls do
    /// nothing, so a divert installed after this one keeps its anchor.
    pub fn disable(&mut self) {
        if std::mem::take(&mut self.active) {
            disable(self.token.take());
        }
    }
}

impl Drop for ActiveDivert {
    fn drop(&mut self) {
        self.disable();
    }
}

/// Installs the port 53 rdr anchor.
///
/// # Errors
///
/// Returns an error when `pfctl` is missing or rejects the rules.
pub fn install() -> Result<ActiveDivert, String> {
    // Loading an unattached anchor succeeds but never applies its rules.
    for args in [["-sn", "rdr-anchor"], ["-sr", "anchor"]] {
        let output = Command::new("/sbin/pfctl")
            .arg(args[0])
            .output()
            .map_err(|error| format!("pfctl {} failed: {error}", args[0]))?;
        if !output.status.success()
            || !anchor_attached(&String::from_utf8_lossy(&output.stdout), args[1])
        {
            return Err(format!(
                "PF main ruleset does not attach {} for com.apple/*",
                args[1]
            ));
        }
    }
    let enabled = Command::new("/sbin/pfctl")
        .args(["-E"])
        .output()
        .map_err(|error| format!("pfctl is unavailable: {error}"))?;
    if !enabled.status.success() {
        return Err(format!("pfctl -E failed: {}", enabled.status));
    }
    let token = parse_token(&String::from_utf8_lossy(&enabled.stderr))
        .or_else(|| parse_token(&String::from_utf8_lossy(&enabled.stdout)));
    // Owning the reference from here on means every failure below releases it
    // when `divert` drops, instead of leaving pf enabled for nobody.
    let divert = ActiveDivert {
        token,
        active: true,
    };
    load_anchor()?;
    if let Some(token) = divert.token.as_deref() {
        persist_token(token);
    }
    Ok(divert)
}

/// Loads the port 53 rdr rules into the divert anchor.
fn load_anchor() -> Result<(), String> {
    let mut child = Command::new("/sbin/pfctl")
        .args(["-a", netmetrics_core::MACOS_DNS_DIVERT_ANCHOR, "-f", "-"])
        .stdin(Stdio::piped())
        .spawn()
        .map_err(|error| error.to_string())?;
    let written = child
        .stdin
        .take()
        .ok_or_else(|| "pfctl stdin was not piped".to_owned())
        .and_then(|mut stdin| {
            stdin
                .write_all(netmetrics_core::macos_dns_divert_rules().as_bytes())
                .map_err(|error| error.to_string())
        });
    // Closing stdin above lets pfctl finish, so it is reaped even after a failed write.
    let status = child.wait().map_err(|error| error.to_string())?;
    written?;
    if !status.success() {
        return Err(format!("pfctl refused the port 53 anchor: {status}"));
    }
    Ok(())
}

/// Flushes the anchor. `token` releases a reference taken by `pfctl -E`.
///
/// A missing token is read from the data directory, so a process that did not
/// run this destructor can still release the reference.
pub fn disable(token: Option<String>) {
    let _ = Command::new("/sbin/pfctl")
        .args(["-a", netmetrics_core::MACOS_DNS_DIVERT_ANCHOR, "-F", "all"])
        .status();
    let token = token.or_else(take_persisted_token);
    if let Some(token) = token {
        let _ = Command::new("/sbin/pfctl").args(["-X", &token]).status();
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
    let token = token.trim().to_owned();
    (!token.is_empty()).then_some(token)
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
        (!token.is_empty()).then(|| token.to_owned())
    })
}

fn anchor_attached(rules: &str, kind: &str) -> bool {
    rules.lines().any(|line| {
        line.trim_start().starts_with(kind)
            && (line.contains("com.apple/*")
                || line.contains(netmetrics_core::MACOS_DNS_DIVERT_ANCHOR))
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

    #[test]
    fn anchor_must_be_referenced_by_the_main_ruleset() {
        assert!(anchor_attached(
            "rdr-anchor \"com.apple/*\" all",
            "rdr-anchor"
        ));
        assert!(anchor_attached("anchor \"com.apple/*\" all", "anchor"));
        assert!(!anchor_attached("anchor \"other/*\" all", "anchor"));
    }
}
