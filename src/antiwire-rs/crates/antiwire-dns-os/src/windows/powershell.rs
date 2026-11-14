//! PowerShell / netsh fallback for DNS capture, redirect, and restore.

use std::fmt::Write as _;
use std::io;
use std::process::ExitStatus;

use tracing::warn;

use super::state::{
    escape_ps_single_quoted, fallback_servers, parse_restore_snapshot, AdapterDnsEntry, AF_IPV6,
    CLOUDFLARE_IPV4, CLOUDFLARE_IPV6,
};
use crate::RedirectCoverage;

/// The redirect script's exit code when some adapters changed and others
/// failed. `exit 1` is kept for a redirect that changed nothing, which is
/// also what PowerShell itself returns for a script that fails.
const PARTIAL_REDIRECT_EXIT: i32 = 3;

/// The interface `Get-DnsClientServerAddress` lists for loopback itself, which
/// is never redirected or reset.
const LOOPBACK_INTERFACE: &str = "Loopback Pseudo-Interface 1";

const CAPTURE_SCRIPT: &str = r"
$ifs = Get-NetIPInterface | Where-Object { $_.ConnectionState -eq 'Connected' -and $_.InterfaceAlias -ne 'Loopback Pseudo-Interface 1' };
$ifs | ForEach-Object {
  $dns = Get-DnsClientServerAddress -InterfaceAlias $_.InterfaceAlias -AddressFamily $_.AddressFamily -ErrorAction SilentlyContinue;
  if ($dns) {
    $guid = (Get-NetAdapter -InterfaceAlias $dns.InterfaceAlias -ErrorAction SilentlyContinue).InterfaceGuid;
    $hive = if ($dns.AddressFamily -eq 23) { 'Tcpip6' } else { 'Tcpip' };
    $ns = '';
    if ($guid) { $ns = (Get-ItemProperty -Path ('HKLM:\SYSTEM\CurrentControlSet\Services\' + $hive + '\Parameters\Interfaces\' + $guid) -Name NameServer -ErrorAction SilentlyContinue).NameServer };
    [PSCustomObject]@{ InterfaceAlias = $dns.InterfaceAlias; InterfaceGuid = [string]$guid; AddressFamily = [int]$dns.AddressFamily; Dhcp = [string]::IsNullOrEmpty($ns); Servers = @($dns.ServerAddresses) }
  }
} | ConvertTo-Json -Compress -Depth 3
";

/// Current adapter DNS as a JSON snapshot, or `None` when it cannot be captured.
///
/// `None` refuses the redirect. Persisting `"[]"` for a failed capture would make
/// a later restore take the empty-snapshot path, which overwrites every
/// adapter's DNS instead of putting back what was there.
pub fn capture_state() -> Option<String> {
    normalize_capture(&execute_with_output(CAPTURE_SCRIPT)?)
}

/// Accepts a capture only if it is a non-empty snapshot that restore can apply.
///
/// `ConvertTo-Json` prints a lone object without the array brackets.
fn normalize_capture(output: &str) -> Option<String> {
    let trimmed = output.trim();
    let normalized = if trimmed.starts_with('[') {
        trimmed.to_owned()
    } else {
        format!("[{trimmed}]")
    };
    match parse_restore_snapshot(&normalized) {
        Some(entries) if !entries.is_empty() => Some(normalized),
        Some(_) => {
            warn!("powershell capture found no connected adapters; DNS left unchanged");
            None
        }
        None => {
            warn!("powershell capture returned an unrestorable snapshot; DNS left unchanged");
            None
        }
    }
}

/// Points each connected adapter family `plan` records, and no other, at
/// loopback. Returns whether every one it tried changed, or `None` when none
/// did.
pub fn redirect(redirect_v6: bool, plan: &str) -> Option<RedirectCoverage> {
    let Some(script) = build_redirect_script(redirect_v6, plan) else {
        warn!("DNS redirect plan is not a valid snapshot; no adapter was redirected");
        return None;
    };
    interpret_redirect_result(super::command::powershell(&script).map(|output| output.status))
}

pub fn restore(saved_state_json: &str) -> bool {
    let Some(script) = build_restore_script(saved_state_json) else {
        warn!("bad saved DNS state JSON; refusing restore so recovery state is kept");
        return false;
    };
    execute_script(&script)
}

/// The redirect of the adapter families `plan` records, or `None` when the
/// plan is not a snapshot restore could reverse.
///
/// Each entry names its adapter, and an adapter that appeared after the plan
/// was captured is not in it: it has no original on disk yet and waits for a
/// later plan. IPv6 entries are skipped unless `redirect_v6`.
fn build_redirect_script(redirect_v6: bool, plan: &str) -> Option<String> {
    let entries = parse_restore_snapshot(plan)?;
    let mut script = String::from("$ok = 0; $fail = 0; ");
    for entry in entries
        .iter()
        .filter(|entry| redirect_v6 || entry.address_family != AF_IPV6)
    {
        append_redirect_entry(&mut script, entry);
    }
    // Total failure ($ok -eq 0) exits 1. Partial success ($ok > 0, $fail > 0)
    // has an exit code of its own: the redirect is in place, and the plan,
    // persisted before this ran, records every adapter it changed, but the
    // adapters that failed are still unfiltered and must be tried again.
    let _ = write!(
        script,
        "Clear-DnsClientCache -ErrorAction SilentlyContinue; \
         if ($ok -eq 0) {{ exit 1 }}; \
         if ($fail -gt 0) {{ Write-Warning \"partial DNS redirect: $fail adapter update(s) failed\"; exit {PARTIAL_REDIRECT_EXIT} }}",
    );
    Some(script)
}

/// Points one recorded adapter family at loopback if that adapter is
/// connected, counting it into `$ok` or `$fail`.
///
/// The adapter is found by its GUID when the entry has one, since a friendly
/// name can move to a different adapter, whose original is not recorded.
fn append_redirect_entry(script: &mut String, entry: &AdapterDnsEntry) {
    let (family, loopback) = if entry.address_family == AF_IPV6 {
        ("IPv6", "::1")
    } else {
        ("IPv4", "127.0.0.1")
    };
    let adapter = if entry.interface_guid.is_empty() {
        ps_single_quoted(&entry.interface_alias)
    } else {
        adapter_name_by_guid(&entry.interface_guid)
    };
    let _ = write!(
        script,
        "$n = {adapter}; \
         if ($n -and (Get-NetIPInterface -InterfaceAlias $n -AddressFamily {family} -ErrorAction SilentlyContinue).ConnectionState -eq 'Connected') {{ \
           try {{ Set-DnsClientServerAddress -InterfaceAlias $n -ServerAddresses @('{loopback}') -ErrorAction Stop; $ok++ }} catch {{ $fail++ }} \
         }}; "
    );
}

fn build_restore_script(saved_state_json: &str) -> Option<String> {
    let entries = parse_restore_snapshot(saved_state_json)?;
    if entries.is_empty() {
        return Some(empty_snapshot_restore_script());
    }

    let mut script = String::from("$fail = 0; ");
    for entry in &entries {
        append_restore_entry(&mut script, entry);
    }
    append_residual_sweep(&mut script, &entries);
    script.push_str(
        "Clear-DnsClientCache -ErrorAction SilentlyContinue; if ($fail -ne 0) { exit 1 }",
    );
    Some(script)
}

fn empty_snapshot_restore_script() -> String {
    let v6 = CLOUDFLARE_IPV6.replace(',', "','");
    let v4 = CLOUDFLARE_IPV4.replace(',', "','");
    format!(
        "$fail = 0; \
         $ifs = Get-NetIPInterface | Where-Object {{ $_.InterfaceAlias -ne 'Loopback Pseudo-Interface 1' }}; \
         foreach ($if in @($ifs)) {{ \
           if (-not $if -or -not $if.InterfaceAlias) {{ $fail++; continue }}; \
           $servers = if ($if.AddressFamily -eq 'IPv6' -or [int]$if.AddressFamily -eq 23) {{ @('{v6}') }} else {{ @('{v4}') }}; \
           try {{ \
             Set-DnsClientServerAddress -InterfaceAlias $if.InterfaceAlias -ServerAddresses $servers -ErrorAction Stop \
           }} catch {{ $fail++ }} \
         }}; \
         Clear-DnsClientCache -ErrorAction SilentlyContinue; \
         if ($fail -ne 0) {{ exit 1 }}"
    )
}

fn append_restore_entry(script: &mut String, entry: &AdapterDnsEntry) {
    let alias_expr = alias_expr(entry);
    if entry.dhcp {
        append_dhcp_restore(script, entry, &alias_expr);
        return;
    }

    let servers = static_restore_servers(entry);
    let addr_array = servers
        .iter()
        .map(|ip| ps_single_quoted(ip))
        .collect::<Vec<_>>()
        .join(",");
    let _ = write!(
        script,
        "try {{ Set-DnsClientServerAddress -InterfaceAlias {alias_expr} -ServerAddresses @({addr_array}) -ErrorAction Stop }} catch {{ $fail++ }}; "
    );
}

fn static_restore_servers(entry: &AdapterDnsEntry) -> Vec<String> {
    if !entry.servers.is_empty() {
        return entry.servers.clone();
    }
    fallback_servers(entry.address_family)
        .split(',')
        .map(str::to_owned)
        .collect()
}

/// Resets to automatic DNS every adapter family the snapshot does not record
/// that still points at Antiwire's loopback address, counting a failed reset
/// into `$fail`.
///
/// Such a family was redirected with no original on disk: an adapter that
/// appeared while the redirect was applied, or one whose redirect never
/// reported back. Its original is unknown, so automatic is the only safe
/// setting; leaving it would strand it on a resolver that is going away. A
/// recorded family is skipped even on loopback, since that original is a
/// resolver the user runs, and so is a family whose servers have changed
/// since. Disconnected adapters are included, so one that returns later does
/// not come back on loopback.
fn append_residual_sweep(script: &mut String, entries: &[AdapterDnsEntry]) {
    let recorded = entries
        .iter()
        .flat_map(|entry| {
            [&entry.interface_guid, &entry.interface_alias]
                .into_iter()
                .filter(|identity| !identity.is_empty())
                .map(|identity| ps_single_quoted(&format!("{identity}|{}", entry.address_family)))
        })
        .collect::<Vec<_>>()
        .join(",");
    let _ = write!(
        script,
        "$recorded = @({recorded}); \
         foreach ($d in @(Get-DnsClientServerAddress -ErrorAction SilentlyContinue)) {{ \
           if (-not $d -or -not $d.InterfaceAlias -or $d.InterfaceAlias -eq '{LOOPBACK_INTERFACE}') {{ continue }}; \
           $af = [int]$d.AddressFamily; \
           $lo = if ($af -eq {AF_IPV6}) {{ '::1' }} else {{ '127.0.0.1' }}; \
           if (@($d.ServerAddresses) -notcontains $lo) {{ continue }}; \
           $g = [string](Get-NetAdapter -InterfaceAlias $d.InterfaceAlias -ErrorAction SilentlyContinue).InterfaceGuid; \
           if (($g -and $recorded -contains ($g + '|' + $af)) -or $recorded -contains ($d.InterfaceAlias + '|' + $af)) {{ continue }}; \
           $fam = if ($af -eq {AF_IPV6}) {{ 'ipv6' }} else {{ 'ipv4' }}; \
           $n = $d.InterfaceAlias; \
           try {{ netsh interface $fam set dnsservers name=\"$n\" source=dhcp >$null; if ($LASTEXITCODE -ne 0) {{ $fail++ }} }} catch {{ $fail++ }} \
         }}; "
    );
}

fn alias_expr(entry: &AdapterDnsEntry) -> String {
    if entry.interface_alias.is_empty() {
        adapter_name_by_guid(&entry.interface_guid)
    } else {
        ps_single_quoted(&entry.interface_alias)
    }
}

/// A script expression for the current name of the adapter with `guid`, or
/// `$null` when no adapter has it.
fn adapter_name_by_guid(guid: &str) -> String {
    let escaped = escape_ps_single_quoted(guid);
    format!(
        "(Get-NetAdapter | Where-Object {{ $_.InterfaceGuid -eq '{escaped}' }} | Select-Object -First 1 -ExpandProperty Name)"
    )
}

fn ps_single_quoted(value: &str) -> String {
    format!("'{}'", escape_ps_single_quoted(value))
}

fn append_dhcp_restore(script: &mut String, entry: &AdapterDnsEntry, alias_expr: &str) {
    let netsh_family = if entry.address_family == AF_IPV6 {
        "ipv6"
    } else {
        "ipv4"
    };
    if entry.interface_alias.is_empty() {
        let _ = write!(
            script,
            "$n = {alias_expr}; if ($n) {{ try {{ netsh interface {netsh_family} set dnsservers name=\"$n\" source=dhcp >$null; if ($LASTEXITCODE -ne 0) {{ $fail++ }} }} catch {{ $fail++ }} }} else {{ $fail++ }}; "
        );
    } else {
        let escaped = escape_ps_single_quoted(&entry.interface_alias);
        let _ = write!(
            script,
            "try {{ netsh interface {netsh_family} set dnsservers name='{escaped}' source=dhcp >$null; if ($LASTEXITCODE -ne 0) {{ $fail++ }} }} catch {{ $fail++ }}; "
        );
    }
}

fn execute_with_output(command: &str) -> Option<String> {
    match super::command::powershell(command) {
        Ok(output) if output.status.success() => {
            Some(String::from_utf8_lossy(&output.stdout).trim().to_owned())
        }
        Ok(output) => {
            warn!(
                status = %output.status,
                "powershell capture exited unsuccessfully"
            );
            None
        }
        Err(error) => {
            warn!(error = %error, "powershell capture failed");
            None
        }
    }
}

pub fn flush_cache() {
    let _ = execute_script("Clear-DnsClientCache -ErrorAction SilentlyContinue");
}

fn execute_script(command: &str) -> bool {
    interpret_powershell_result(super::command::powershell(command).map(|output| output.status))
}

/// Reads the redirect script's outcome: success is complete, its partial exit
/// code is partial, and anything else redirected nothing.
fn interpret_redirect_result(result: io::Result<ExitStatus>) -> Option<RedirectCoverage> {
    match result {
        Ok(status) if status.code() == Some(PARTIAL_REDIRECT_EXIT) => {
            warn!("some adapters' DNS could not be redirected; they are retried");
            Some(RedirectCoverage::Partial)
        }
        other => interpret_powershell_result(other).then_some(RedirectCoverage::Complete),
    }
}

fn interpret_powershell_result(result: io::Result<ExitStatus>) -> bool {
    match result {
        Ok(status) if status.success() => true,
        Ok(status) => {
            warn!(%status, "powershell DNS script exited unsuccessfully");
            false
        }
        Err(error) => {
            warn!(error = %error, "powershell DNS script failed to start");
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::windows::state::{serialize_entries, AdapterDnsEntry};
    use std::io;
    use std::os::windows::process::ExitStatusExt;
    use std::process::ExitStatus;

    fn dhcp_wifi_json() -> String {
        serialize_entries(&[AdapterDnsEntry {
            interface_alias: "Wi-Fi".to_owned(),
            interface_guid: "{aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee}".to_owned(),
            address_family: 2,
            dhcp: true,
            servers: vec!["192.168.1.1".to_owned()],
        }])
    }

    fn static_ethernet_json() -> String {
        serialize_entries(&[AdapterDnsEntry {
            interface_alias: "Ethernet".to_owned(),
            interface_guid: String::new(),
            address_family: 2,
            dhcp: false,
            servers: vec!["8.8.8.8".to_owned(), "8.8.4.4".to_owned()],
        }])
    }

    /// The regression this guards: an empty or failed capture used to be saved as
    /// `"[]"`, and restoring that pointed every adapter at Cloudflare.
    #[test]
    fn capture_without_adapters_refuses_the_redirect() {
        assert_eq!(normalize_capture(""), None);
        assert_eq!(normalize_capture("[]"), None);
        assert_eq!(normalize_capture("not json"), None);
    }

    #[test]
    fn capture_rejects_a_snapshot_restore_could_not_apply() {
        let unrestorable = r#"[{"InterfaceAlias":"Wi-Fi","AddressFamily":2,"Dhcp":false,"Servers":["not-an-ip"]}]"#;
        assert_eq!(normalize_capture(unrestorable), None);
    }

    #[test]
    fn capture_wraps_a_single_adapter_object_in_an_array() {
        let single = r#"{"InterfaceAlias":"Wi-Fi","InterfaceGuid":"","AddressFamily":2,"Dhcp":true,"Servers":[]}"#;
        let snapshot = normalize_capture(single).expect("one adapter captured");
        assert!(snapshot.starts_with('['));
        assert_eq!(
            parse_restore_snapshot(&snapshot).map(|entries| entries.len()),
            Some(1)
        );
        assert!(normalize_capture(&dhcp_wifi_json()).is_some());
    }

    #[test]
    fn empty_snapshot_restore_script_detects_numeric_ipv6_family() {
        let script = build_restore_script("[]").expect("empty snapshot is restorable");
        assert!(
            script.contains("-eq 23"),
            "Get-NetIPInterface.AddressFamily may be 23 rather than 'IPv6'"
        );
    }

    #[test]
    fn restore_script_uses_dhcp_for_automatic() {
        let script = build_restore_script(&dhcp_wifi_json()).expect("valid dhcp snapshot");
        assert!(script.contains("source=dhcp"));
        assert!(!script.contains("192.168.1.1"));
    }

    #[test]
    fn restore_script_checks_lastexitcode_after_netsh() {
        let script = build_restore_script(&dhcp_wifi_json()).expect("valid dhcp snapshot");
        assert!(
            script.contains("$LASTEXITCODE"),
            "netsh does not throw; restore must inspect $LASTEXITCODE"
        );
        let netsh_at = script.find("netsh interface").expect("netsh invocation");
        let last_exit_at = script[netsh_at..]
            .find("$LASTEXITCODE")
            .expect("$LASTEXITCODE must be checked after netsh");
        assert!(
            last_exit_at > 0,
            "$LASTEXITCODE check must follow the netsh invocation, not precede it"
        );
    }

    #[test]
    fn restore_script_fails_the_process_on_partial_restore() {
        let script = build_restore_script(&static_ethernet_json()).expect("valid snapshot");
        assert!(script.contains("$fail"), "restore must count failures");
        assert!(
            script.contains("exit 1"),
            "partial restore must exit unsuccessfully so recovery state is kept"
        );
    }

    #[test]
    fn restore_script_restores_static_servers() {
        let script = build_restore_script(&static_ethernet_json()).expect("valid snapshot");
        assert!(script.contains("'8.8.8.8'"));
        assert!(script.contains("'8.8.4.4'"));
    }

    #[test]
    fn restore_script_canonicalizes_and_escapes_server_addresses() {
        let json = serialize_entries(&[AdapterDnsEntry {
            interface_alias: "Ethernet".to_owned(),
            interface_guid: String::new(),
            address_family: 23,
            dhcp: false,
            servers: vec!["2606:4700:4700:0:0:0:0:1111".to_owned()],
        }]);
        let script = build_restore_script(&json).expect("valid ipv6 snapshot");
        assert!(script.contains("'2606:4700:4700::1111'"));
        assert!(
            !script.contains("2606:4700:4700:0:0:0:0:1111"),
            "servers must be canonicalized before interpolation"
        );
    }

    #[test]
    fn restore_script_rejects_malformed_json_instead_of_cache_flush_only() {
        assert_eq!(build_restore_script("{not json}"), None);
        assert_eq!(build_restore_script("null"), None);
        assert!(
            !restore("{not json}"),
            "malformed JSON must not claim success"
        );
        assert!(!restore("null"), "malformed JSON must not claim success");
    }

    #[test]
    fn restore_script_rejects_injected_servers_and_keeps_recovery_contract() {
        let json = serialize_entries(&[AdapterDnsEntry {
            interface_alias: "Ethernet".to_owned(),
            interface_guid: String::new(),
            address_family: 2,
            dhcp: false,
            servers: vec!["8.8.8.8'; Stop-Computer; '".to_owned()],
        }]);
        assert_eq!(build_restore_script(&json), None);
        assert!(
            !restore(&json),
            "invalid snapshot must fail restore so interceptor keeps recovery state"
        );
    }

    #[test]
    fn restore_script_rejects_mixed_valid_and_invalid_entries() {
        let json = serialize_entries(&[
            AdapterDnsEntry {
                interface_alias: "Wi-Fi".to_owned(),
                interface_guid: String::new(),
                address_family: 2,
                dhcp: false,
                servers: vec!["8.8.8.8".to_owned()],
            },
            AdapterDnsEntry {
                interface_alias: String::new(),
                interface_guid: String::new(),
                address_family: 2,
                dhcp: false,
                servers: vec!["1.1.1.1".to_owned()],
            },
        ]);
        assert_eq!(build_restore_script(&json), None);
        assert!(!restore(&json));
    }

    fn dual_stack_plan() -> String {
        serialize_entries(&[
            AdapterDnsEntry {
                interface_alias: "Wi-Fi".to_owned(),
                interface_guid: "{aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee}".to_owned(),
                address_family: 2,
                dhcp: true,
                servers: vec!["192.168.1.1".to_owned()],
            },
            AdapterDnsEntry {
                interface_alias: "Wi-Fi".to_owned(),
                interface_guid: "{aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee}".to_owned(),
                address_family: 23,
                dhcp: true,
                servers: Vec::new(),
            },
            AdapterDnsEntry {
                interface_alias: "Ethernet".to_owned(),
                interface_guid: String::new(),
                address_family: 2,
                dhcp: false,
                servers: vec!["8.8.8.8".to_owned()],
            },
        ])
    }

    #[test]
    fn redirect_script_counts_successes_and_fails_closed_when_none_change() {
        let script = build_redirect_script(true, &dual_stack_plan()).expect("valid plan");
        assert!(script.contains("$ok"));
        assert!(
            script.contains("if ($ok -eq 0)"),
            "redirect must fail when no adapter was changed"
        );
        assert!(
            script.contains("-ErrorAction Stop; $ok++"),
            "silently continuing would report success for a no-op redirect"
        );
        assert!(script.contains("@('::1')"));
    }

    /// The regression this guards: the redirect pointed every connected
    /// adapter at loopback whatever the plan held, so an adapter connected
    /// after the plan was captured was redirected with no original on disk.
    #[test]
    fn redirect_script_changes_only_the_adapters_its_plan_records() {
        let script = build_redirect_script(true, &dual_stack_plan()).expect("valid plan");
        assert_eq!(
            script.matches("Set-DnsClientServerAddress").count(),
            3,
            "one write per planned adapter family"
        );
        assert!(
            !script.contains("Get-DnsClientServerAddress"),
            "the redirect must not enumerate adapters to find more to change"
        );
        assert!(
            script.contains("$_.InterfaceGuid -eq '{aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee}'"),
            "an adapter with a recorded GUID is found by it, not by a reusable name"
        );
        assert!(script.contains("$n = 'Ethernet'"));
        assert!(
            script.contains("ConnectionState -eq 'Connected'"),
            "only a connected adapter is redirected"
        );
    }

    #[test]
    fn redirect_script_leaves_ipv6_alone_unless_it_is_served() {
        let script = build_redirect_script(false, &dual_stack_plan()).expect("valid plan");
        assert_eq!(script.matches("Set-DnsClientServerAddress").count(), 2);
        assert!(!script.contains("::1"));
        assert!(!script.contains("IPv6"));
    }

    #[test]
    fn redirect_refuses_a_plan_restore_could_not_reverse() {
        assert_eq!(build_redirect_script(true, "not json"), None);
        assert_eq!(redirect(true, "not json"), None);
        let unrestorable = r#"[{"InterfaceAlias":"Wi-Fi","AddressFamily":2,"Dhcp":false,"Servers":["not-an-ip"]}]"#;
        assert_eq!(build_redirect_script(true, unrestorable), None);
    }

    #[test]
    fn restore_script_sweeps_unrecorded_adapters_left_on_loopback() {
        let script = build_restore_script(&dual_stack_plan()).expect("valid snapshot");
        assert!(
            script.contains("foreach ($d in @(Get-DnsClientServerAddress"),
            "every adapter is checked, connected or not"
        );
        assert!(script.contains("'{aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee}|2'"));
        assert!(script.contains("'{aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee}|23'"));
        assert!(script.contains("'Wi-Fi|23'"));
        assert!(script.contains("'Ethernet|2'"));
        assert!(
            script.contains("-notcontains $lo"),
            "only an adapter still on Antiwire's loopback is reset"
        );
        let sweep_at = script.find("$recorded = ").expect("sweep");
        let exit_at = script.find("if ($fail -ne 0) { exit 1 }").expect("exit");
        assert!(
            sweep_at < exit_at,
            "a failed reset must fail the restore so recovery state is kept"
        );
    }

    #[test]
    fn restore_sweep_escapes_recorded_identities() {
        let json = serialize_entries(&[AdapterDnsEntry {
            interface_alias: "Bob's LAN".to_owned(),
            interface_guid: String::new(),
            address_family: 2,
            dhcp: true,
            servers: Vec::new(),
        }]);
        let script = build_restore_script(&json).expect("valid snapshot");
        assert!(script.contains("'Bob''s LAN|2'"));
    }

    /// The regression this guards: a redirect that changed some adapters and
    /// failed on others exited 0, so it read as complete and the adapters
    /// that failed were never tried again.
    #[test]
    fn redirect_script_reports_a_partial_redirect_apart_from_success_and_failure() {
        let script = build_redirect_script(false, &dual_stack_plan()).expect("valid plan");
        let none_changed = script
            .find("if ($ok -eq 0) { exit 1 }")
            .expect("total failure");
        let partial = script
            .find(&format!("exit {PARTIAL_REDIRECT_EXIT}"))
            .expect("partial exit");
        assert!(
            none_changed < partial,
            "a redirect that changed nothing is a failure, not a partial one"
        );
        assert!(script.contains("if ($fail -gt 0)"));
        assert!(
            !script.contains("if ($fail -ne 0) { exit 1 }"),
            "a partial redirect is in place, so it must not read as a failure"
        );
    }

    #[test]
    fn redirect_result_distinguishes_partial_from_complete() {
        assert_eq!(
            interpret_redirect_result(Ok(ExitStatus::from_raw(0))),
            Some(RedirectCoverage::Complete)
        );
        assert_eq!(
            interpret_redirect_result(Ok(ExitStatus::from_raw(3))),
            Some(RedirectCoverage::Partial)
        );
        assert_eq!(interpret_redirect_result(Ok(ExitStatus::from_raw(1))), None);
        let err = io::Error::new(io::ErrorKind::TimedOut, "powershell");
        assert_eq!(interpret_redirect_result(Err(err)), None);
    }

    #[test]
    fn powershell_start_failure_is_not_success() {
        let err = io::Error::new(io::ErrorKind::NotFound, "powershell");
        assert!(!interpret_powershell_result(Err(err)));
    }

    #[test]
    fn powershell_unsuccessful_exit_is_not_success() {
        assert!(!interpret_powershell_result(Ok(ExitStatus::from_raw(1))));
        assert!(!interpret_powershell_result(Ok(ExitStatus::from_raw(
            0xFFFF
        ))));
    }

    #[test]
    fn powershell_zero_exit_is_success() {
        assert!(interpret_powershell_result(Ok(ExitStatus::from_raw(0))));
    }
}
