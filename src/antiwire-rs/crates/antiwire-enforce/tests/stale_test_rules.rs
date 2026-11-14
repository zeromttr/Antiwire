//! Removes the firewall rules Windows leaves behind for cargo test binaries
//! (elevated privileges required).
//!
//! When a test binary listens on a socket, Windows Defender Firewall asks
//! whether to allow it and records the answer as an inbound "Query User" rule
//! for that exact executable. Every rebuild gets a new hash in its file name,
//! so every rebuild leaves another rule. These are not Antiwire rules; the
//! enforcement tests clean up their own.

#![cfg(windows)]

use std::process::Command;

/// Rule IDs Windows gives prompt answers, restricted to cargo's hashed test
/// and bench executables in a `deps` directory. Anything else, including a
/// `target\debug\antiwire-daemon.exe` rule or another program's, is kept.
const STALE_RULE_ID: &str =
    r"^(TCP|UDP) Query User\{[0-9A-Fa-f-]+\}.*\\deps\\[^\\]+-[0-9a-f]{16}\.exe$";

fn powershell(script: &str) -> String {
    let output = Command::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-Command", script])
        .output()
        .expect("run powershell");
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    assert!(
        output.status.success(),
        "powershell failed:\n{stdout}\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    stdout
}

fn stale_rules_script(action: &str) -> String {
    format!(
        "$ErrorActionPreference = 'Stop'; \
         Get-NetFirewallRule | Where-Object {{ $_.Name -match '{STALE_RULE_ID}' }} | {action}"
    )
}

#[test]
#[ignore = "requires administrator; deletes firewall rules"]
fn remove_stale_test_binary_rules() {
    let removed = powershell(&stale_rules_script(
        "ForEach-Object { $_.Name; $_ | Remove-NetFirewallRule }",
    ));
    let removed: Vec<&str> = removed.lines().filter(|line| !line.is_empty()).collect();
    println!("removed {} rules", removed.len());
    for id in &removed {
        println!("  {id}");
    }

    let left = powershell(&stale_rules_script("Measure-Object | ForEach-Object Count"));
    assert_eq!(left.trim(), "0", "stale rules remain after cleanup");
}
