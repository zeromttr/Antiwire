//! Saved DNS adapter state JSON (shared with C# daemon).

use std::net::IpAddr;

use serde::{Deserialize, Serialize};

/// Windows address-family values (`AF_INET`, `AF_INET6`) as snapshots record them.
pub(crate) const AF_IPV4: i32 = 2;
pub(crate) const AF_IPV6: i32 = 23;

pub const CLOUDFLARE_IPV4: &str = "1.1.1.1,1.0.0.1";
pub const CLOUDFLARE_IPV6: &str = "2606:4700:4700::1111,2606:4700:4700::1001";

/// Comma-separated servers to restore when a static entry recorded none, so
/// the adapter is never left pointing at the stopped loopback resolver.
pub(crate) fn fallback_servers(address_family: i32) -> &'static str {
    if address_family == AF_IPV6 {
        CLOUDFLARE_IPV6
    } else {
        CLOUDFLARE_IPV4
    }
}

/// Per-(interface, address-family) DNS configuration snapshot.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AdapterDnsEntry {
    #[serde(rename = "InterfaceAlias")]
    pub interface_alias: String,
    /// Adapter GUID (`{xxxxxxxx-...}`) when known. Preferred for restore because
    /// friendly names can change and adapters are often already *Down* during
    /// machine shutdown — `SetInterfaceDnsSettings` still works by GUID.
    #[serde(default, rename = "InterfaceGuid")]
    pub interface_guid: String,
    #[serde(rename = "AddressFamily")]
    pub address_family: i32,
    #[serde(rename = "Dhcp")]
    pub dhcp: bool,
    /// Windows PowerShell `ConvertTo-Json` unwraps a one-element collection to a
    /// bare string. Accept both forms so captured snapshots remain restorable.
    #[serde(default, deserialize_with = "deserialize_servers", rename = "Servers")]
    pub servers: Vec<String>,
}

pub fn serialize_entries(entries: &[AdapterDnsEntry]) -> String {
    serde_json::to_string(entries).unwrap_or_else(|_| "[]".to_owned())
}

pub fn deserialize_entries(json: &str) -> Option<Vec<AdapterDnsEntry>> {
    let trimmed = json.trim();
    if trimmed.is_empty() || trimmed == "[]" {
        return Some(Vec::new());
    }
    serde_json::from_str(trimmed).ok()
}

/// `prior` with the entries of `current` for adapter families it does not
/// cover, for a redirect that reuses a recovered snapshot.
///
/// An entry already on loopback is skipped: with no original recorded for it,
/// loopback is all a restore could write back. A `prior` that does not parse
/// is returned unchanged rather than rewritten.
pub fn add_new_entries(prior: &str, current: &str) -> String {
    let (Some(mut merged), Some(current)) =
        (deserialize_entries(prior), deserialize_entries(current))
    else {
        return prior.to_owned();
    };
    let covered = |candidate: &AdapterDnsEntry, recorded: &AdapterDnsEntry| {
        candidate.address_family == recorded.address_family
            && ((!candidate.interface_guid.is_empty()
                && candidate
                    .interface_guid
                    .eq_ignore_ascii_case(&recorded.interface_guid))
                || candidate
                    .interface_alias
                    .eq_ignore_ascii_case(&recorded.interface_alias))
    };
    let mut added = false;
    for entry in current {
        let on_loopback = entry.servers.iter().any(|server| {
            server
                .trim()
                .parse::<IpAddr>()
                .is_ok_and(|ip| ip.is_loopback())
        });
        if !on_loopback && !merged.iter().any(|recorded| covered(&entry, recorded)) {
            merged.push(entry);
            added = true;
        }
    }
    if added {
        serialize_entries(&merged)
    } else {
        prior.to_owned()
    }
}

/// Parse an IP for restore (PowerShell interpolation and native IP Helper).
///
/// Canonical form (`IpAddr::to_string`) is the only string later written, so
/// quote-breaking payloads cannot survive this step.
pub fn canonicalize_dns_server(raw: &str) -> Option<String> {
    raw.trim().parse::<IpAddr>().ok().map(|ip| ip.to_string())
}

/// Parse a restore snapshot.
///
/// `None` means the JSON is malformed or an entry is invalid. Callers must keep
/// recovery state rather than applying a cache-flush-only fallback or dropping
/// the bad row and restoring the rest.
pub fn parse_restore_snapshot(json: &str) -> Option<Vec<AdapterDnsEntry>> {
    let entries = deserialize_entries(json)?;
    let mut out = Vec::with_capacity(entries.len());
    for entry in entries {
        out.push(canonicalize_restorable_entry(entry)?);
    }
    Some(out)
}

fn deserialize_servers<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = serde_json::Value::deserialize(deserializer)?;
    match value {
        serde_json::Value::Null => Ok(Vec::new()),
        serde_json::Value::String(s) if s.is_empty() => Ok(Vec::new()),
        serde_json::Value::String(s) => Ok(vec![s]),
        serde_json::Value::Array(items) => {
            let mut out = Vec::with_capacity(items.len());
            for item in items {
                match item {
                    serde_json::Value::String(s) => out.push(s),
                    _ => {
                        return Err(serde::de::Error::custom(
                            "DNS server entries must be strings",
                        ));
                    }
                }
            }
            Ok(out)
        }
        _ => Err(serde::de::Error::custom(
            "Servers must be a string or an array of strings",
        )),
    }
}

fn identity_is_restorable(value: &str) -> bool {
    !value.contains('"') && !value.chars().any(char::is_control)
}

fn canonicalize_restorable_entry(mut entry: AdapterDnsEntry) -> Option<AdapterDnsEntry> {
    if entry.interface_alias.is_empty() && entry.interface_guid.is_empty() {
        return None;
    }
    if entry.address_family != AF_IPV4 && entry.address_family != AF_IPV6 {
        return None;
    }
    if !identity_is_restorable(&entry.interface_alias)
        || !identity_is_restorable(&entry.interface_guid)
    {
        return None;
    }
    let mut servers = Vec::with_capacity(entry.servers.len());
    for raw in &entry.servers {
        let canonical = canonicalize_dns_server(raw)?;
        let ip: IpAddr = canonical.parse().ok()?;
        match (ip, entry.address_family) {
            (IpAddr::V4(_), AF_IPV4) | (IpAddr::V6(_), AF_IPV6) => {}
            _ => return None,
        }
        servers.push(canonical);
    }
    entry.servers = servers;
    Some(entry)
}

/// Escape adapter alias for PowerShell single-quoted strings.
pub fn escape_ps_single_quoted(alias: &str) -> String {
    alias.replace('"', "").replace('\'', "''")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_repeat_redirect_records_adapters_added_since() {
        let prior = r#"[{"InterfaceAlias":"Wi-Fi","InterfaceGuid":"{A}","AddressFamily":2,"Dhcp":false,"Servers":["192.0.2.1"]}]"#;
        let current = r#"[
            {"InterfaceAlias":"Wi-Fi","InterfaceGuid":"{a}","AddressFamily":2,"Dhcp":false,"Servers":["127.0.0.1"]},
            {"InterfaceAlias":"Wi-Fi","InterfaceGuid":"{a}","AddressFamily":23,"Dhcp":true,"Servers":[]},
            {"InterfaceAlias":"VPN","InterfaceGuid":"{B}","AddressFamily":2,"Dhcp":false,"Servers":["198.51.100.1"]},
            {"InterfaceAlias":"Stale","InterfaceGuid":"{C}","AddressFamily":2,"Dhcp":false,"Servers":["127.0.0.1"]}
        ]"#;
        let merged = deserialize_entries(&add_new_entries(prior, current)).expect("snapshot");
        let identities: Vec<(&str, i32)> = merged
            .iter()
            .map(|entry| (entry.interface_alias.as_str(), entry.address_family))
            .collect();
        assert_eq!(
            identities,
            [("Wi-Fi", AF_IPV4), ("Wi-Fi", AF_IPV6), ("VPN", AF_IPV4)]
        );
        assert_eq!(
            merged[0].servers,
            ["192.0.2.1"],
            "the prior original is kept"
        );
        assert_eq!(add_new_entries("not json", current), "not json");
    }

    #[test]
    fn json_round_trip() {
        let entries = vec![
            AdapterDnsEntry {
                interface_alias: "Wi-Fi".to_owned(),
                interface_guid: "{11111111-1111-1111-1111-111111111111}".to_owned(),
                address_family: 2,
                dhcp: true,
                servers: vec![],
            },
            AdapterDnsEntry {
                interface_alias: "Ethernet".to_owned(),
                interface_guid: String::new(),
                address_family: 2,
                dhcp: false,
                servers: vec!["8.8.8.8".to_owned()],
            },
        ];
        let json = serialize_entries(&entries);
        let parsed = deserialize_entries(&json).expect("parse");
        assert_eq!(parsed, entries);
    }

    #[test]
    fn json_accepts_legacy_entries_without_guid() {
        let json = r#"[{"InterfaceAlias":"Wi-Fi","AddressFamily":2,"Dhcp":true,"Servers":[]}]"#;
        let parsed = deserialize_entries(json).expect("parse");
        assert_eq!(parsed.len(), 1);
        assert!(parsed[0].interface_guid.is_empty());
        assert_eq!(parsed[0].interface_alias, "Wi-Fi");
    }

    #[test]
    fn json_accepts_powershell_unwrapped_single_server() {
        let json =
            r#"[{"InterfaceAlias":"Wi-Fi","AddressFamily":2,"Dhcp":false,"Servers":"8.8.8.8"}]"#;
        let parsed = deserialize_entries(json).expect("parse single-string Servers");
        assert_eq!(parsed[0].servers, ["8.8.8.8"]);
        let restored = parse_restore_snapshot(json).expect("restorable");
        assert_eq!(restored[0].servers, ["8.8.8.8"]);
    }

    #[test]
    fn escape_ps_alias() {
        assert_eq!(escape_ps_single_quoted("Wi-Fi"), "Wi-Fi");
        assert_eq!(escape_ps_single_quoted("O'Reilly"), "O''Reilly");
        assert_eq!(escape_ps_single_quoted("bad\""), "bad");
    }

    /// The escaped value is only ever embedded inside `'...'`, where PowerShell
    /// performs no expansion. These characters are therefore literal — the test
    /// pins that so a future embedding site that drops the quotes is a visible
    /// behaviour change rather than a silent injection.
    #[test]
    fn escape_ps_alias_leaves_non_quote_metacharacters_literal() {
        for alias in [
            "$(Get-Process)",
            "a`b",
            "a;b",
            "a|b",
            "a&b",
            "a$env:PATH",
            "a\nb",
        ] {
            assert_eq!(escape_ps_single_quoted(alias), alias, "{alias:?}");
        }
    }

    #[test]
    fn escape_ps_alias_terminates_every_embedded_quote() {
        // An odd number of quotes would end the literal early; every one doubles.
        let escaped = escape_ps_single_quoted("'; Stop-Computer; '");
        assert_eq!(escaped, "''; Stop-Computer; ''");
        assert_eq!(escaped.matches('\'').count() % 2, 0);
    }

    #[test]
    fn canonicalize_dns_server_parses_and_normalizes_ips() {
        assert_eq!(
            canonicalize_dns_server("8.8.8.8").as_deref(),
            Some("8.8.8.8")
        );
        assert_eq!(
            canonicalize_dns_server("  1.0.0.1  ").as_deref(),
            Some("1.0.0.1")
        );
        assert_eq!(
            canonicalize_dns_server("2606:4700:4700:0:0:0:0:1111").as_deref(),
            Some("2606:4700:4700::1111")
        );
        assert_eq!(canonicalize_dns_server("::1").as_deref(), Some("::1"));
    }

    #[test]
    fn canonicalize_dns_server_rejects_injection_and_non_ips() {
        for raw in [
            "8.8.8.8'; Stop-Computer; '",
            "$(Get-Process)",
            "1.1.1.1; calc.exe",
            "not-an-ip",
            "",
            "2001:db8::1%eth0",
        ] {
            assert_eq!(canonicalize_dns_server(raw), None, "{raw:?}");
        }
    }

    #[test]
    fn parse_restore_snapshot_accepts_empty_as_no_entries() {
        assert_eq!(parse_restore_snapshot("").as_deref(), Some(&[][..]));
        assert_eq!(parse_restore_snapshot("[]").as_deref(), Some(&[][..]));
        assert_eq!(parse_restore_snapshot("  []  ").as_deref(), Some(&[][..]));
    }

    #[test]
    fn parse_restore_snapshot_rejects_malformed_json() {
        for json in ["{", "{not json}", "null", "{}", "[}", "not-json"] {
            assert_eq!(parse_restore_snapshot(json), None, "{json:?}");
        }
    }

    #[test]
    fn parse_restore_snapshot_rejects_invalid_entries_instead_of_dropping_them() {
        let missing_identity = r#"[{"InterfaceAlias":"","InterfaceGuid":"","AddressFamily":2,"Dhcp":false,"Servers":["8.8.8.8"]}]"#;
        assert_eq!(parse_restore_snapshot(missing_identity), None);

        let injected = serialize_entries(&[AdapterDnsEntry {
            interface_alias: "Ethernet".to_owned(),
            interface_guid: String::new(),
            address_family: 2,
            dhcp: false,
            servers: vec!["8.8.8.8".to_owned(), "1.1.1.1'; calc; '".to_owned()],
        }]);
        assert_eq!(parse_restore_snapshot(&injected), None);

        let quoted = serialize_entries(&[AdapterDnsEntry {
            interface_alias: r#"Foo"Bar"#.to_owned(),
            interface_guid: String::new(),
            address_family: 2,
            dhcp: false,
            servers: vec!["8.8.8.8".to_owned()],
        }]);
        assert_eq!(
            parse_restore_snapshot(&quoted),
            None,
            "quote in alias must reject the snapshot, not strip and retarget"
        );

        let mixed = serialize_entries(&[
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
        assert_eq!(
            parse_restore_snapshot(&mixed),
            None,
            "one invalid entry must reject the whole snapshot"
        );
    }

    #[test]
    fn parse_restore_snapshot_rejects_family_mismatched_servers() {
        let json = serialize_entries(&[AdapterDnsEntry {
            interface_alias: "Ethernet".to_owned(),
            interface_guid: String::new(),
            address_family: 23,
            dhcp: false,
            servers: vec!["8.8.8.8".to_owned()],
        }]);
        assert_eq!(parse_restore_snapshot(&json), None);
    }

    #[test]
    fn parse_restore_snapshot_canonicalizes_valid_servers() {
        let json = serialize_entries(&[AdapterDnsEntry {
            interface_alias: "Ethernet".to_owned(),
            interface_guid: String::new(),
            address_family: 23,
            dhcp: false,
            servers: vec!["2606:4700:4700:0:0:0:0:1111".to_owned()],
        }]);
        let parsed = parse_restore_snapshot(&json).expect("valid snapshot");
        assert_eq!(parsed[0].servers, ["2606:4700:4700::1111"]);
    }
}
