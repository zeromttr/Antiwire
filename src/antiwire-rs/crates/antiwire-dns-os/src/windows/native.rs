//! Native IP Helper API DNS configuration (Windows 10 2004+).

#![allow(
    clippy::borrow_as_ptr,
    clippy::cast_lossless,
    clippy::cast_possible_truncation,
    clippy::ptr_as_ptr,
    clippy::ptr_cast_constness
)]

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::process::Command;
use std::time::{Duration, Instant};

use ipconfig::{get_adapters, IfType, OperStatus};
use tracing::{debug, info, warn};
use windows::core::{w, GUID, PCWSTR};
use windows::Win32::Foundation::{
    ERROR_FILE_NOT_FOUND, ERROR_MORE_DATA, ERROR_SUCCESS, WIN32_ERROR,
};
use windows::Win32::NetworkManagement::IpHelper::{
    FreeInterfaceDnsSettings, GetInterfaceDnsSettings, SetInterfaceDnsSettings,
    DNS_INTERFACE_SETTINGS, DNS_INTERFACE_SETTINGS_VERSION1, DNS_SETTING_IPV6,
    DNS_SETTING_NAMESERVER,
};
use windows::Win32::System::Registry::{
    RegCloseKey, RegGetValueW, RegOpenKeyExW, RegSetValueExW, HKEY, HKEY_LOCAL_MACHINE,
    KEY_QUERY_VALUE, KEY_SET_VALUE, REG_SZ, RRF_RT_REG_SZ,
};
use windows::Win32::System::SystemInformation::OSVERSIONINFOEXW;

use super::state::{
    canonicalize_dns_server, deserialize_entries, fallback_servers, parse_restore_snapshot,
    serialize_entries, AdapterDnsEntry, AF_IPV4, AF_IPV6,
};
use crate::{AppliedRedirect, RedirectCoverage};

const LOOPBACK_V4: &str = "127.0.0.1";
const LOOPBACK_V6: &str = "::1";

/// How long a restore waits for the DNS client to stop using loopback on an
/// adapter whose configuration was already confirmed.
const EFFECTIVE_DNS_WAIT: Duration = Duration::from_secs(3);
const EFFECTIVE_DNS_POLL: Duration = Duration::from_millis(100);

struct AdapterInfo {
    friendly_name: String,
    guid: GUID,
    /// Operationally up. A down adapter has a configuration but no effective
    /// DNS to check.
    up: bool,
    v4_servers: Vec<String>,
    v6_servers: Vec<String>,
}

impl AdapterInfo {
    fn effective_servers(&self, ipv6: bool) -> &[String] {
        if ipv6 {
            &self.v6_servers
        } else {
            &self.v4_servers
        }
    }
}

type EntryKey = (String, i32);

pub fn is_native_supported() -> bool {
    let mut info = OSVERSIONINFOEXW {
        dwOSVersionInfoSize: std::mem::size_of::<OSVERSIONINFOEXW>() as u32,
        ..Default::default()
    };
    // `GetVersionExW` is manifest-bound: with no embedded supportedOS manifest it
    // reports 6.2 even on Windows 10/11, which would wrongly bypass the IP Helper
    // backend. `RtlGetVersion` reads the true kernel version unconditionally.
    if rtl_get_version(&mut info) != 0 {
        return false;
    }
    info.dwMajorVersion >= 10 && info.dwBuildNumber >= 19041
}

fn rtl_get_version(info: &mut OSVERSIONINFOEXW) -> i32 {
    windows::core::link!("ntdll.dll" "system" fn RtlGetVersion(version_info: *mut OSVERSIONINFOEXW) -> i32);
    // SAFETY: `info` is an initialized `OSVERSIONINFOEXW` whose
    // `dwOSVersionInfoSize` matches the layout `RtlGetVersion` expects.
    unsafe { RtlGetVersion(info) }
}

/// Every up adapter's DNS, for both families. A family whose static or
/// automatic mode cannot be read is left out: there is no original to record.
pub fn capture_state() -> String {
    let mut entries = Vec::new();
    for adapter in adapters(/* require_up */ true) {
        entries.extend(snapshot_adapter(&adapter));
    }
    serialize_entries(&entries)
}

/// The families a redirect changes: IPv4, and IPv6 only when the stub also
/// serves `[::1]:53`.
fn redirected_families(redirect_v6: bool) -> impl Iterator<Item = (i32, bool)> {
    [(AF_IPV4, false), (AF_IPV6, true)]
        .into_iter()
        .filter(move |&(_, ipv6)| !ipv6 || redirect_v6)
}

/// Point one adapter's address family at the loopback stub.
///
/// Returns `true` on success.
fn redirect_family(adapter: &AdapterInfo, ipv6: bool) -> bool {
    let (loopback, family) = if ipv6 {
        (LOOPBACK_V6, "IPv6")
    } else {
        (LOOPBACK_V4, "IPv4")
    };
    if set_name_server_api(adapter.guid, ipv6, loopback, &adapter.friendly_name) {
        true
    } else {
        warn!(
            alias = %adapter.friendly_name,
            family,
            "failed to redirect DNS; adapter left unchanged"
        );
        false
    }
}

/// Plan, then apply, in one call. The daemon persists the plan in between;
/// this is for callers that hold no durable record.
pub fn redirect_capturing(redirect_v6: bool, prior_saved_json: &str) -> Option<AppliedRedirect> {
    let plan = plan_redirect(redirect_v6, prior_saved_json)?;
    apply_redirect(redirect_v6, &plan)
}

/// The originals a redirect of the current adapters must restore, captured
/// without changing anything.
///
/// Entries of `prior_saved_json`, a snapshot recovered from an earlier run,
/// are kept as they are: those adapters may point at loopback right now.
/// Prior entries for adapters that are down or absent, or for a family not
/// redirected this time, are kept too, since they are still owed a restore:
/// an absent adapter keeps its interface key, and restore writes its original
/// there for when it returns. Only a legacy entry with no GUID is dropped once
/// its adapter is gone, since restore has no way to find it.
///
/// A family whose mode cannot be read is left out, so it is never
/// redirected. While recovering, an adapter missing from the prior snapshot
/// that already points at Antiwire's loopback is left out too: its original
/// was lost, and recording loopback as the original would make every later
/// restore write loopback back. Restore's loopback sweep resets it instead.
///
/// `None` when the adapters cannot be listed and there is no prior snapshot.
pub fn plan_redirect(redirect_v6: bool, prior_saved_json: &str) -> Option<String> {
    let recovering = !prior_saved_json.trim().is_empty();
    let Some(up) = try_adapters(/* require_up */ true) else {
        return recovering.then(|| prior_saved_json.to_owned());
    };
    let mut prior = entry_map(prior_saved_json);
    let mut plan: HashMap<EntryKey, AdapterDnsEntry> = HashMap::new();

    for adapter in &up {
        let guid_str = format_guid(adapter.guid).to_lowercase();
        for (family, _) in redirected_families(redirect_v6) {
            let key = (guid_str.clone(), family);
            if let Some(recorded) = take_prior(&mut prior, &key, &adapter.friendly_name) {
                plan.insert(key, recorded);
                continue;
            }
            let Some(original) = snapshot_family(adapter, family) else {
                continue;
            };
            if recovering && points_at_antiwire_loopback(&original) {
                warn!(
                    alias = %adapter.friendly_name,
                    family = family_label(family),
                    "adapter already uses Antiwire's loopback DNS but no original was recorded; \
                     it is not redirected, and restore will reset it to automatic DNS"
                );
                continue;
            }
            plan.insert(key, original);
        }
    }

    if !prior.is_empty() {
        let restorable = Restorable::listed();
        plan.extend(
            prior
                .into_iter()
                .filter(|(_, entry)| restorable.keeps(entry)),
        );
    }

    Some(serialize_sorted(plan.into_values()))
}

/// Redirects the up adapter families `plan` records, and no others, to the
/// loopback stub.
///
/// An adapter that appeared after the plan was made is left alone until a
/// later plan records it. Returns the snapshot restore must reverse: `plan`,
/// including entries for adapters that disappeared after being redirected,
/// since they return still pointing at loopback and only their entry holds
/// the original. `None` when no adapter was redirected, and a partial
/// redirect when some planned adapter that is up could not be.
pub fn apply_redirect(redirect_v6: bool, plan_json: &str) -> Option<AppliedRedirect> {
    let Some(plan) = deserialize_entries(plan_json) else {
        warn!("DNS redirect plan is not valid; no adapter was redirected");
        return None;
    };
    let planned = RecordedDns::from_entries(&plan);
    let mut redirected = 0u32;
    let mut failed = 0u32;
    let mut unplanned = 0u32;
    for adapter in adapters(/* require_up */ true) {
        let guid = format_guid(adapter.guid);
        for (family, ipv6) in redirected_families(redirect_v6) {
            if !planned.contains(&guid, &adapter.friendly_name, family) {
                unplanned += 1;
                continue;
            }
            if redirect_family(&adapter, ipv6) {
                redirected += 1;
            } else {
                failed += 1;
            }
        }
    }
    flush_dns_cache();

    if redirected == 0 {
        return None;
    }
    let restorable = Restorable::listed();
    let entries: Vec<AdapterDnsEntry> = plan
        .into_iter()
        .filter(|entry| restorable.keeps(entry))
        .collect();
    let coverage = if failed == 0 {
        info!(
            redirected,
            unplanned,
            recorded = entries.len(),
            "redirected adapter DNS; snapshot records every changed device"
        );
        RedirectCoverage::Complete
    } else {
        warn!(
            redirected,
            failed,
            unplanned,
            recorded = entries.len(),
            "redirected DNS on some adapters only; the rest still use their own DNS"
        );
        RedirectCoverage::Partial
    };
    Some(AppliedRedirect {
        snapshot: serialize_sorted(entries),
        coverage,
    })
}

fn serialize_sorted(entries: impl IntoIterator<Item = AdapterDnsEntry>) -> String {
    let mut entries: Vec<AdapterDnsEntry> = entries.into_iter().collect();
    entries.sort_by(|a, b| {
        a.interface_alias
            .cmp(&b.interface_alias)
            .then(a.address_family.cmp(&b.address_family))
    });
    serialize_entries(&entries)
}

/// An adapter family whose effective DNS must stop using loopback for its
/// restore to count.
struct EffectiveCheck {
    guid: GUID,
    ipv6: bool,
    alias: String,
    /// The restored servers include loopback, so it is not a leftover.
    loopback_expected: bool,
}

/// Writes every recorded adapter's original DNS back and confirms it.
///
/// An adapter family counts as restored only when the configuration read
/// back afterwards is the one written, and, for an adapter that is up, its
/// effective DNS no longer uses Antiwire's loopback. A registry write on its
/// own never counts. An adapter that is no longer present has only its
/// saved configuration, and counts once that reads back. Every unrecorded
/// adapter still on loopback is reset to automatic DNS, and a reset that
/// fails makes the restore fail.
///
/// Returns `true` only when every one of those succeeded.
pub fn restore(saved_state_json: &str) -> bool {
    let Some(entries) = saved_restore_entries(saved_state_json) else {
        warn!("bad saved DNS state JSON");
        return false;
    };

    // Down adapters are included: shutdown often marks NICs down first.
    let listed = try_adapters(/* require_up */ false);
    let enumerated = listed.is_some();
    let adapters = listed.unwrap_or_default();
    // Alias → GUID fallback for legacy snapshots that lack InterfaceGuid.
    let by_alias = adapters
        .iter()
        .map(|a| (a.friendly_name.to_lowercase(), a.guid))
        .collect::<HashMap<_, _>>();
    let up_by_guid = adapters
        .iter()
        .map(|a| (a.guid.to_u128(), a.up))
        .collect::<HashMap<_, _>>();

    let mut ok = 0u32;
    let mut fail = 0u32;
    let mut checks = Vec::new();

    for entry in &entries {
        let guid = parse_adapter_guid(entry.interface_guid.trim())
            .or_else(|| by_alias.get(&entry.interface_alias.to_lowercase()).copied());
        let Some(guid) = guid else {
            warn!(
                alias = %entry.interface_alias,
                guid = %entry.interface_guid,
                "cannot resolve adapter for DNS restore"
            );
            fail += 1;
            continue;
        };
        let ipv6 = entry.address_family == AF_IPV6;
        let label = if entry.interface_alias.is_empty() {
            entry.interface_guid.as_str()
        } else {
            entry.interface_alias.as_str()
        };
        // Empty NameServer = DHCP. NULL alone does not clear a prior static
        // value (e.g. 127.0.0.1) from the interface registry key.
        let value = if entry.dhcp {
            String::new()
        } else if entry.servers.is_empty() {
            fallback_servers(entry.address_family).to_owned()
        } else {
            entry.servers.join(",")
        };

        let restored = match up_by_guid.get(&guid.to_u128()) {
            None if enumerated => restore_absent_adapter(guid, ipv6, &value, label),
            up => {
                let restored = restore_name_server(guid, ipv6, Some(value.as_str()), label);
                if restored && up == Some(&true) {
                    checks.push(EffectiveCheck {
                        guid,
                        ipv6,
                        alias: label.to_owned(),
                        loopback_expected: contains_loopback(&server_tokens(&value), ipv6),
                    });
                }
                restored
            }
        };
        if restored {
            ok += 1;
        } else {
            fail += 1;
        }
    }

    // Safety net: any adapter still pointing at the loopback stub (including
    // devices changed after the snapshot, or missed by a partial list) is
    // forced back to DHCP so reboot never leaves residual 127.0.0.1 / ::1. A
    // loopback server recorded in the snapshot is the user's own configuration
    // (e.g. a local resolver), so it is left alone.
    let recorded = RecordedDns::from_entries(&entries);
    let residual = clear_residual_loopback_dns(&recorded, &adapters, &mut checks);

    flush_dns_cache();
    let still_loopback = confirm_effective_dns(checks);

    if !enumerated {
        warn!("network adapters could not be listed; the loopback sweep did not run");
    }
    let success = enumerated && fail == 0 && residual.failed == 0 && still_loopback == 0;
    if success {
        info!(
            ok,
            residual = residual.cleared,
            "restored DNS for every recorded device (plus residual loopback sweep)"
        );
    } else {
        warn!(
            ok,
            fail,
            residual = residual.cleared,
            residual_failed = residual.failed,
            still_loopback,
            "DNS restore incomplete; dirty flag will be kept"
        );
    }
    success
}

/// Waits for each checked adapter's effective DNS to stop using loopback.
///
/// The configuration was already read back, so this catches a DNS client
/// that has not picked the change up. Returns how many still use loopback
/// when the wait runs out. An adapter that went down or away meanwhile has
/// no effective DNS left to check, and passes on its configuration.
fn confirm_effective_dns(mut pending: Vec<EffectiveCheck>) -> u32 {
    pending.retain(|check| !check.loopback_expected);
    let deadline = Instant::now() + EFFECTIVE_DNS_WAIT;
    let mut observed: HashMap<(u128, bool), Vec<String>> = HashMap::new();
    loop {
        if pending.is_empty() {
            return 0;
        }
        let Some(adapters) = try_adapters(/* require_up */ false) else {
            warn!("could not list adapters to confirm their effective DNS");
            return u32::try_from(pending.len()).unwrap_or(u32::MAX);
        };
        let by_guid: HashMap<u128, &AdapterInfo> =
            adapters.iter().map(|a| (a.guid.to_u128(), a)).collect();
        pending.retain(|check| {
            let Some(adapter) = by_guid.get(&check.guid.to_u128()).filter(|a| a.up) else {
                return false;
            };
            let servers = adapter.effective_servers(check.ipv6);
            if contains_loopback(servers, check.ipv6) {
                observed.insert((check.guid.to_u128(), check.ipv6), servers.to_vec());
                true
            } else {
                false
            }
        });
        if pending.is_empty() || Instant::now() >= deadline {
            break;
        }
        std::thread::sleep(EFFECTIVE_DNS_POLL);
    }
    for check in &pending {
        warn!(
            alias = %check.alias,
            ipv6 = check.ipv6,
            observed = ?observed.get(&(check.guid.to_u128(), check.ipv6)),
            "configuration was restored but the adapter still resolves through Antiwire's loopback"
        );
    }
    u32::try_from(pending.len()).unwrap_or(u32::MAX)
}

/// Fail-closed snapshot gate shared with the PowerShell backend: malformed JSON
/// or invalid servers/identities reject the whole snapshot so recovery state is
/// kept instead of writing unvalidated strings into IP Helper / the registry.
fn saved_restore_entries(saved_state_json: &str) -> Option<Vec<AdapterDnsEntry>> {
    parse_restore_snapshot(saved_state_json)
}

fn entry_map(json: &str) -> HashMap<EntryKey, AdapterDnsEntry> {
    deserialize_entries(json)
        .unwrap_or_default()
        .into_iter()
        .map(|entry| {
            let key_id = if entry.interface_guid.trim().is_empty() {
                // Legacy alias-only entries still participate via alias on restore.
                entry.interface_alias.to_lowercase()
            } else {
                entry.interface_guid.to_lowercase()
            };
            ((key_id, entry.address_family), entry)
        })
        .collect()
}

/// Consume a prior snapshot entry for `adapter`, preferring the GUID key and
/// falling back to the alias key used by legacy snapshots that lack a GUID.
/// Without the fallback a re-redirect would recapture the live loopback value as
/// the "original".
fn take_prior(
    prior: &mut HashMap<EntryKey, AdapterDnsEntry>,
    guid_key: &EntryKey,
    alias: &str,
) -> Option<AdapterDnsEntry> {
    prior
        .remove(guid_key)
        .or_else(|| prior.remove(&(alias.to_lowercase(), guid_key.1)))
}

/// Adapter/family identities recorded in a restore snapshot.
///
/// The residual loopback sweep uses this to tell an Antiwire-written `127.0.0.1`
/// from a user's own local resolver: anything present in the snapshot — by GUID,
/// or by alias for legacy GUID-less entries — is restored, not swept.
#[derive(Default)]
struct RecordedDns {
    guids: HashSet<EntryKey>,
    aliases: HashSet<EntryKey>,
}

impl RecordedDns {
    fn from_entries(entries: &[AdapterDnsEntry]) -> Self {
        let mut recorded = Self::default();
        for entry in entries {
            if entry.interface_guid.trim().is_empty() {
                recorded
                    .aliases
                    .insert((entry.interface_alias.to_lowercase(), entry.address_family));
            } else {
                recorded
                    .guids
                    .insert((entry.interface_guid.to_lowercase(), entry.address_family));
            }
        }
        recorded
    }

    /// Every family of every adapter in `adapters`, by GUID and by alias.
    fn from_adapters(adapters: &[AdapterInfo]) -> Self {
        let mut recorded = Self::default();
        for adapter in adapters {
            let guid = format_guid(adapter.guid).to_lowercase();
            let alias = adapter.friendly_name.to_lowercase();
            for family in [AF_IPV4, AF_IPV6] {
                recorded.guids.insert((guid.clone(), family));
                recorded.aliases.insert((alias.clone(), family));
            }
        }
        recorded
    }

    /// Whether the adapter `entry` restores is in this set. Restore resolves an
    /// entry by its GUID when it has one, so only a GUID-less legacy entry may
    /// match by alias.
    fn has_adapter_for(&self, entry: &AdapterDnsEntry) -> bool {
        let guid = entry.interface_guid.trim();
        if guid.is_empty() {
            self.aliases
                .contains(&(entry.interface_alias.to_lowercase(), entry.address_family))
        } else {
            self.guids
                .contains(&(guid.to_lowercase(), entry.address_family))
        }
    }

    fn contains(&self, guid: &str, alias: &str, family: i32) -> bool {
        self.guids.contains(&(guid.to_lowercase(), family))
            || self.aliases.contains(&(alias.to_lowercase(), family))
    }
}

/// Which recorded entries a snapshot carries forward.
///
/// An entry stays until a restore confirms it. One with a GUID always stays:
/// restore writes an absent adapter's original to its interface key, and
/// counts an adapter whose key is gone as done. A legacy entry with no GUID
/// is resolved by alias, which only a listed adapter has, so it stays only
/// while its adapter is listed.
enum Restorable {
    Listed(RecordedDns),
    /// The adapters could not be listed, so nothing shows one is gone.
    Unknown,
}

impl Restorable {
    fn listed() -> Self {
        try_adapters(/* require_up */ false).map_or(Self::Unknown, |all| {
            Self::Listed(RecordedDns::from_adapters(&all))
        })
    }

    fn keeps(&self, entry: &AdapterDnsEntry) -> bool {
        match self {
            Self::Unknown => true,
            Self::Listed(_) if !entry.interface_guid.trim().is_empty() => true,
            Self::Listed(present) => present.has_adapter_for(entry),
        }
    }
}

fn snapshot_adapter(adapter: &AdapterInfo) -> Vec<AdapterDnsEntry> {
    [AF_IPV4, AF_IPV6]
        .into_iter()
        .filter_map(|family| snapshot_family(adapter, family))
        .collect()
}

/// The original DNS of one adapter family, or `None` when it cannot be known.
///
/// Whether DNS is static or automatic comes from the adapter's configured
/// `NameServer`. A failed read is not taken to mean automatic: restoring an
/// unknown static adapter to DHCP would leave a static-only network without
/// DNS. A static list that does not parse as addresses cannot be restored
/// either, since restore refuses the whole snapshot then.
fn snapshot_family(adapter: &AdapterInfo, family: i32) -> Option<AdapterDnsEntry> {
    let ipv6 = family == AF_IPV6;
    let label = family_label(family);
    let raw = match static_name_server(adapter.guid, ipv6) {
        Ok(raw) => raw,
        Err(code) => {
            warn!(
                alias = %adapter.friendly_name,
                family = label,
                code = code.0,
                "could not read whether this adapter's DNS is static or automatic; \
                 it is not redirected"
            );
            return None;
        }
    };
    let configured = raw_tokens(&raw);
    let statics: Option<Vec<String>> = configured
        .iter()
        .map(|token| canonicalize_dns_server(token))
        .collect();
    let Some(statics) = statics else {
        warn!(
            alias = %adapter.friendly_name,
            family = label,
            configured = %raw,
            "this adapter's static DNS servers are not addresses restore can write back; \
             it is not redirected"
        );
        return None;
    };
    let dhcp = statics.is_empty();
    Some(AdapterDnsEntry {
        interface_alias: adapter.friendly_name.clone(),
        interface_guid: format_guid(adapter.guid),
        address_family: family,
        dhcp,
        servers: if dhcp {
            adapter.effective_servers(ipv6).to_vec()
        } else {
            statics
        },
    })
}

/// A static entry whose servers include the loopback address Antiwire
/// redirects that family to.
fn points_at_antiwire_loopback(entry: &AdapterDnsEntry) -> bool {
    !entry.dhcp && contains_loopback(&entry.servers, entry.address_family == AF_IPV6)
}

/// Whether `servers` include the loopback address Antiwire uses for the family.
fn contains_loopback(servers: &[String], ipv6: bool) -> bool {
    servers.iter().any(|server| {
        let server = server.trim();
        if ipv6 {
            server.eq_ignore_ascii_case(LOOPBACK_V6)
        } else {
            server == LOOPBACK_V4
        }
    })
}

const fn family_label(family: i32) -> &'static str {
    if family == AF_IPV6 {
        "IPv6"
    } else {
        "IPv4"
    }
}

#[derive(Default)]
struct ResidualSweep {
    cleared: u32,
    failed: u32,
}

/// Clear remaining Antiwire loopback DNS on every adapter whose (interface,
/// family) pair is absent from the restore snapshot.
fn clear_residual_loopback_dns(
    recorded: &RecordedDns,
    adapters: &[AdapterInfo],
    checks: &mut Vec<EffectiveCheck>,
) -> ResidualSweep {
    let mut sweep = ResidualSweep::default();
    for adapter in adapters {
        let guid = format_guid(adapter.guid);
        for (family, ipv6) in [(AF_IPV4, false), (AF_IPV6, true)] {
            let label = family_label(family);
            if recorded.contains(&guid, &adapter.friendly_name, family) {
                continue;
            }
            match static_name_server(adapter.guid, ipv6) {
                Ok(raw) if contains_loopback(&raw_tokens(&raw), ipv6) => {}
                Ok(_) => continue,
                Err(code) => {
                    // Antiwire never redirects a family it cannot read, so an
                    // unreadable one is not taken for a leftover.
                    warn!(
                        alias = %adapter.friendly_name,
                        family = label,
                        code = code.0,
                        "could not read DNS to check for residual loopback"
                    );
                    continue;
                }
            }
            if restore_name_server(adapter.guid, ipv6, None, &adapter.friendly_name) {
                sweep.cleared += 1;
                info!(
                    alias = %adapter.friendly_name,
                    "cleared residual {label} loopback DNS"
                );
                if adapter.up {
                    checks.push(EffectiveCheck {
                        guid: adapter.guid,
                        ipv6,
                        alias: adapter.friendly_name.clone(),
                        loopback_expected: false,
                    });
                }
            } else {
                sweep.failed += 1;
                warn!(
                    alias = %adapter.friendly_name,
                    "failed to clear residual {label} loopback DNS"
                );
            }
        }
    }
    sweep
}

/// Enumerate adapters eligible for DNS management, or `None` when the
/// adapters cannot be listed.
///
/// When `require_up` is false, *Down* interfaces are included. That is required
/// for shutdown restore: Windows often takes NICs down before user processes
/// finish, but `SetInterfaceDnsSettings` still persists the static/DHCP choice.
fn try_adapters(require_up: bool) -> Option<Vec<AdapterInfo>> {
    let adapters = match get_adapters() {
        Ok(adapters) => adapters,
        Err(error) => {
            warn!(error = %error, "failed to enumerate network adapters");
            return None;
        }
    };

    Some(
        adapters
            .into_iter()
            .filter(|adapter| !require_up || adapter.oper_status() == OperStatus::IfOperStatusUp)
            .filter(|adapter| adapter.if_type() != IfType::SoftwareLoopback)
            .filter(|adapter| adapter.if_type() != IfType::Tunnel)
            .filter_map(|adapter| {
                let guid = parse_adapter_guid(adapter.adapter_name())?;
                let mut v4_servers = Vec::new();
                let mut v6_servers = Vec::new();
                for ip in adapter.dns_servers() {
                    match ip {
                        IpAddr::V4(v4) => v4_servers.push(v4.to_string()),
                        IpAddr::V6(v6) => v6_servers.push(v6.to_string()),
                    }
                }
                // Always manage both address families on non-loopback NICs so a
                // dual-stack redirect at daemon start is fully reversed later —
                // including adapters that only had one family assigned when we ran.
                Some(AdapterInfo {
                    friendly_name: adapter.friendly_name().to_owned(),
                    guid,
                    up: adapter.oper_status() == OperStatus::IfOperStatusUp,
                    v4_servers,
                    v6_servers,
                })
            })
            .collect(),
    )
}

/// [`try_adapters`], with a failed listing read as no adapters.
fn adapters(require_up: bool) -> Vec<AdapterInfo> {
    try_adapters(require_up).unwrap_or_default()
}

fn parse_adapter_guid(adapter_name: &str) -> Option<GUID> {
    let stripped = adapter_name
        .trim()
        .trim_start_matches('{')
        .trim_end_matches('}');
    if stripped.is_empty() {
        return None;
    }
    let compact = stripped.replace('-', "");
    if compact.len() != 32 {
        return None;
    }
    let value = u128::from_str_radix(&compact, 16).ok()?;
    Some(GUID::from_u128(value))
}

fn format_guid(guid: GUID) -> String {
    let value = guid.to_u128();
    let hex = format!("{value:032x}");
    format!(
        "{{{0}-{1}-{2}-{3}-{4}}}",
        &hex[0..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..32]
    )
}

/// The tokens of a `NameServer` list, which Windows separates with commas or
/// spaces.
fn raw_tokens(raw: &str) -> Vec<String> {
    raw.split([',', ' ', ';'])
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .collect()
}

/// [`raw_tokens`] in canonical address form, for comparing a written list
/// with what reads back.
fn server_tokens(raw: &str) -> Vec<String> {
    raw_tokens(raw)
        .into_iter()
        .map(|token| canonicalize_dns_server(&token).unwrap_or_else(|| token.to_ascii_lowercase()))
        .collect()
}

/// The adapter family's configured static `NameServer`: empty for automatic
/// DNS, or the API error when it cannot be read.
fn static_name_server(guid: GUID, ipv6: bool) -> Result<String, WIN32_ERROR> {
    // SAFETY: `settings` is initialized for version 1 and freed with
    // `FreeInterfaceDnsSettings` after its string is copied out.
    unsafe {
        let mut settings = DNS_INTERFACE_SETTINGS {
            Version: DNS_INTERFACE_SETTINGS_VERSION1,
            Flags: if ipv6 { DNS_SETTING_IPV6 as u64 } else { 0 },
            ..Default::default()
        };
        let result = GetInterfaceDnsSettings(guid, &mut settings);
        if result != WIN32_ERROR(0) {
            return Err(result);
        }
        let value = pwstr_to_string(settings.NameServer);
        FreeInterfaceDnsSettings(&mut settings);
        Ok(value)
    }
}

/// Writes one adapter family's DNS back and confirms it took.
///
/// `SetInterfaceDnsSettings` is the change; `netsh` stands in when it
/// fails. The registry `NameServer` is also written, because an empty value
/// is what returns a family to DHCP and a NULL API call does not reliably
/// clear a static one during shutdown. A registry write is persisted
/// configuration only: it does not tell the DNS client anything, so it never
/// counts as the change on its own. The result is whether one of the other
/// two succeeded and the configuration reads back as written.
fn restore_name_server(guid: GUID, ipv6: bool, name_server: Option<&str>, alias: &str) -> bool {
    let value = name_server.unwrap_or("");
    let api_ok = set_name_server_api(guid, ipv6, value, alias);
    let reg_ok = write_registry_name_server(guid, ipv6, value);
    let netsh_ok = !api_ok && !alias.is_empty() && netsh_restore(alias, ipv6, name_server);

    let expected = server_tokens(value);
    let observed = static_name_server(guid, ipv6).map(|raw| server_tokens(&raw));
    let confirmed = (api_ok || netsh_ok) && observed.as_ref().is_ok_and(|o| *o == expected);
    if !confirmed {
        warn!(
            alias,
            ipv6,
            api_ok,
            reg_ok,
            netsh_ok,
            expected = ?expected,
            observed = ?observed,
            "DNS restore not confirmed"
        );
    }
    confirmed
}

/// Restores the saved configuration of an adapter that is not present.
///
/// With no adapter there is nothing for the API or the DNS client to act on,
/// so the registry configuration it will use when it returns is all there is
/// to restore. It counts once it reads back as written. An adapter whose
/// interface key is gone entirely has nothing left to restore.
///
/// "Not listed" is not proof of absence: the listing skips tunnel adapters,
/// and an adapter can return just after it was taken. So the API is tried
/// first, best effort, for the DNS client to pick the change up if the
/// adapter is in fact there. Its failure is expected and not reported.
fn restore_absent_adapter(guid: GUID, ipv6: bool, value: &str, alias: &str) -> bool {
    match registry_name_server(guid, ipv6) {
        Ok(None) => {
            info!(alias, ipv6, "adapter no longer exists; nothing to restore");
            return true;
        }
        Ok(Some(_)) => {}
        Err(code) => {
            warn!(
                alias,
                ipv6,
                code = code.0,
                "could not read an absent adapter's saved DNS"
            );
            return false;
        }
    }
    let api = call_set_interface_dns(guid, ipv6, value);
    if api != WIN32_ERROR(0) {
        debug!(
            alias,
            ipv6,
            code = api.0,
            "SetInterfaceDnsSettings did not apply to an absent adapter"
        );
    }
    let written = write_registry_name_server(guid, ipv6, value);
    let observed = registry_name_server(guid, ipv6);
    let confirmed =
        written && matches!(&observed, Ok(Some(raw)) if server_tokens(raw) == server_tokens(value));
    if confirmed {
        info!(
            alias,
            ipv6,
            "adapter is not present; restored the DNS configuration it will use when it returns"
        );
    } else {
        warn!(
            alias,
            ipv6,
            written,
            observed = ?observed,
            "could not restore an absent adapter's saved DNS"
        );
    }
    confirmed
}

fn set_name_server_api(guid: GUID, ipv6: bool, name_server: &str, alias: &str) -> bool {
    let result = call_set_interface_dns(guid, ipv6, name_server);
    if result != WIN32_ERROR(0) {
        warn!(
            alias,
            ipv6,
            code = result.0,
            "SetInterfaceDnsSettings failed"
        );
        return false;
    }
    true
}

/// Sets one address family's `NameServer` through `SetInterfaceDnsSettings`
/// and returns its result.
fn call_set_interface_dns(guid: GUID, ipv6: bool, name_server: &str) -> WIN32_ERROR {
    let wide: Vec<u16> = name_server.encode_utf16().chain([0]).collect();
    let settings = DNS_INTERFACE_SETTINGS {
        Version: DNS_INTERFACE_SETTINGS_VERSION1,
        Flags: DNS_SETTING_NAMESERVER as u64 | if ipv6 { DNS_SETTING_IPV6 as u64 } else { 0 },
        NameServer: windows::core::PWSTR(wide.as_ptr().cast_mut()),
        ..Default::default()
    };
    // SAFETY: `wide` outlives the call; flags only request a NameServer
    // update for the requested address family.
    unsafe { SetInterfaceDnsSettings(guid, &settings) }
}

fn interface_subkey(guid: GUID, ipv6: bool) -> Vec<u16> {
    let service = if ipv6 { "Tcpip6" } else { "Tcpip" };
    format!(
        "SYSTEM\\CurrentControlSet\\Services\\{service}\\Parameters\\Interfaces\\{}",
        format_guid(guid)
    )
    .encode_utf16()
    .chain([0])
    .collect()
}

/// Persist `NameServer` under the interface's Tcpip(6) key.
///
/// An empty string restores DHCP for that family; a non-empty value is a static
/// list (space-separated, matching the registry convention).
fn write_registry_name_server(guid: GUID, ipv6: bool, name_server: &str) -> bool {
    let subkey_wide = interface_subkey(guid, ipv6);
    let normalized = name_server.replace(',', " ");
    let value_wide: Vec<u16> = normalized.encode_utf16().chain([0]).collect();
    let mut value_bytes = Vec::with_capacity(value_wide.len() * 2);
    for unit in &value_wide {
        value_bytes.extend_from_slice(&unit.to_le_bytes());
    }

    // SAFETY: wide/byte buffers live for the duration of the registry calls;
    // `key` is closed on every path after a successful open.
    unsafe {
        let mut key = HKEY::default();
        let open = RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            PCWSTR(subkey_wide.as_ptr()),
            Some(0),
            KEY_SET_VALUE,
            &raw mut key,
        );
        if open != ERROR_SUCCESS {
            warn!(code = open.0, ipv6, "RegOpenKeyExW NameServer failed");
            return false;
        }
        let set = RegSetValueExW(
            key,
            w!("NameServer"),
            Some(0),
            REG_SZ,
            Some(value_bytes.as_slice()),
        );
        let _ = RegCloseKey(key);
        if set != ERROR_SUCCESS {
            warn!(code = set.0, ipv6, "RegSetValueExW NameServer failed");
            return false;
        }
    }
    true
}

/// The interface key's `NameServer`, empty when the value is absent, or
/// `Ok(None)` when the interface key itself does not exist.
fn registry_name_server(guid: GUID, ipv6: bool) -> Result<Option<String>, WIN32_ERROR> {
    let subkey_wide = interface_subkey(guid, ipv6);
    // SAFETY: the subkey buffer outlives every call; `key` is closed on every
    // path after a successful open, and each read's `buffer`/`size` describe
    // one allocation in bytes.
    unsafe {
        let mut key = HKEY::default();
        let open = RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            PCWSTR(subkey_wide.as_ptr()),
            Some(0),
            KEY_QUERY_VALUE,
            &raw mut key,
        );
        if open == ERROR_FILE_NOT_FOUND {
            return Ok(None);
        }
        if open != ERROR_SUCCESS {
            return Err(open);
        }
        let read = read_registry_string(|buffer, size| {
            RegGetValueW(
                key,
                PCWSTR::null(),
                w!("NameServer"),
                RRF_RT_REG_SZ,
                None,
                Some(buffer.as_mut_ptr().cast()),
                Some(size),
            )
        });
        let _ = RegCloseKey(key);
        match read {
            Ok(text) => Ok(Some(text)),
            Err(code) if code == ERROR_FILE_NOT_FOUND => Ok(Some(String::new())),
            Err(code) => Err(code),
        }
    }
}

/// UTF-16 units a registry string read starts with: room for a typical
/// `NameServer` list in one call.
const REGISTRY_STRING_INITIAL_UNITS: usize = 1024;

/// Reads made before a value that keeps growing between them is given up on.
const REGISTRY_STRING_READ_ATTEMPTS: usize = 4;

/// Reads a registry string through `read`, which has `RegGetValueW`'s
/// contract: it fills the buffer and sets `size` to the bytes written, or,
/// when the buffer is too small, sets `size` to the bytes needed and
/// returns `ERROR_MORE_DATA`.
///
/// A fixed buffer would fail every read of a longer value, and with it every
/// restore of that adapter, so the buffer grows to the size the read asks
/// for. A value that grows again before the next read is read again, a
/// bounded number of times.
fn read_registry_string(
    mut read: impl FnMut(&mut [u16], &mut u32) -> WIN32_ERROR,
) -> Result<String, WIN32_ERROR> {
    let mut buffer = vec![0u16; REGISTRY_STRING_INITIAL_UNITS];
    for _ in 0..REGISTRY_STRING_READ_ATTEMPTS {
        let mut size = u32::try_from(buffer.len() * 2).unwrap_or(u32::MAX);
        let code = read(&mut buffer, &mut size);
        if code == ERROR_MORE_DATA {
            // Always grow, even when the reported size would not.
            let needed = (size as usize).div_ceil(2);
            buffer = vec![0u16; needed.max(buffer.len() * 2)];
            continue;
        }
        if code != ERROR_SUCCESS {
            return Err(code);
        }
        let units = (size as usize / 2).min(buffer.len());
        let text = String::from_utf16_lossy(&buffer[..units]);
        return Ok(text.trim_end_matches('\0').to_owned());
    }
    Err(ERROR_MORE_DATA)
}

fn netsh_restore(alias: &str, ipv6: bool, name_server: Option<&str>) -> bool {
    let family = if ipv6 { "ipv6" } else { "ipv4" };
    let name_arg = format!("name={alias}");
    let servers = name_server.map(raw_tokens).unwrap_or_default();
    let mut cmd = Command::new("netsh");
    cmd.args(["interface", family, "set", "dnsservers"]);
    cmd.arg(&name_arg);
    match servers.first() {
        Some(primary) => {
            cmd.arg("static").arg(primary).arg("primary");
        }
        None => {
            cmd.arg("dhcp");
        }
    }
    if !run_netsh(&mut cmd, alias, ipv6) {
        return false;
    }
    // `set` takes one server; the rest are added in order after it.
    for (index, server) in servers.iter().enumerate().skip(1) {
        let mut add = Command::new("netsh");
        add.args(["interface", family, "add", "dnsservers"])
            .arg(&name_arg)
            .arg(format!("address={server}"))
            .arg(format!("index={}", index + 1));
        if !run_netsh(&mut add, alias, ipv6) {
            return false;
        }
    }
    true
}

fn run_netsh(cmd: &mut Command, alias: &str, ipv6: bool) -> bool {
    match super::command::status(cmd) {
        Ok(status) if status.success() => true,
        Ok(status) => {
            warn!(alias, ipv6, %status, "netsh DNS restore failed");
            false
        }
        Err(error) => {
            warn!(alias, ipv6, %error, "netsh DNS restore could not start");
            false
        }
    }
}

fn pwstr_to_string(ptr: windows::core::PWSTR) -> String {
    if ptr.is_null() {
        return String::new();
    }
    // SAFETY: `GetInterfaceDnsSettings` returns a NUL-terminated wide string at
    // this pointer; `PCWSTR::to_string` reads up to the terminator.
    unsafe { PCWSTR(ptr.0).to_string().unwrap_or_default() }
}

pub(crate) fn flush_dns_cache() {
    windows::core::link!("dnsapi.dll" "system" fn DnsFlushResolverCache() -> i32);
    unsafe {
        let _ = DnsFlushResolverCache();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Serves `value` with `RegGetValueW`'s contract: NUL-terminated, and
    /// `ERROR_MORE_DATA` with the bytes needed when the buffer is too small.
    fn registry_value(value: &str) -> impl FnMut(&mut [u16], &mut u32) -> WIN32_ERROR + '_ {
        move |buffer, size| {
            let wide: Vec<u16> = value.encode_utf16().chain([0]).collect();
            let needed = u32::try_from(wide.len() * 2).expect("size");
            if (*size as usize) < wide.len() * 2 {
                *size = needed;
                return ERROR_MORE_DATA;
            }
            buffer[..wide.len()].copy_from_slice(&wide);
            *size = needed;
            ERROR_SUCCESS
        }
    }

    /// The regression this guards: the read used a fixed 2 KB buffer, so a
    /// longer `NameServer` failed every read, and with it every restore of
    /// an absent adapter, which the reaper then retried without end.
    #[test]
    fn a_registry_string_longer_than_the_first_buffer_is_read_whole() {
        let long = (0..200)
            .map(|index| format!("2001:db8::{index:x}"))
            .collect::<Vec<_>>()
            .join(" ");
        assert!(long.len() > REGISTRY_STRING_INITIAL_UNITS);
        assert_eq!(read_registry_string(registry_value(&long)), Ok(long));
    }

    #[test]
    fn a_short_registry_string_is_read_in_one_call() {
        let mut reads = 0;
        let mut value = registry_value("192.0.2.53 192.0.2.54");
        let read = read_registry_string(|buffer, size| {
            reads += 1;
            value(buffer, size)
        });
        assert_eq!(read.as_deref(), Ok("192.0.2.53 192.0.2.54"));
        assert_eq!(reads, 1);
    }

    #[test]
    fn a_registry_string_that_keeps_growing_is_given_up_on() {
        let mut reads = 0;
        let read = read_registry_string(|_, size| {
            reads += 1;
            *size = size.saturating_mul(4);
            ERROR_MORE_DATA
        });
        assert_eq!(read, Err(ERROR_MORE_DATA));
        assert_eq!(reads, REGISTRY_STRING_READ_ATTEMPTS);
    }

    #[test]
    fn a_registry_read_error_is_returned() {
        assert_eq!(
            read_registry_string(|_, _| ERROR_FILE_NOT_FOUND),
            Err(ERROR_FILE_NOT_FOUND)
        );
    }

    #[test]
    fn format_guid_round_trips_parse() {
        let original = GUID::from_u128(0x0123_4567_89ab_cdef_0123_4567_89ab_cdef);
        let text = format_guid(original);
        let parsed = parse_adapter_guid(&text).expect("parse formatted guid");
        assert_eq!(parsed.to_u128(), original.to_u128());
    }

    #[test]
    fn parse_adapter_guid_accepts_braced_and_raw() {
        let g = parse_adapter_guid("{01234567-89AB-CDEF-0123-456789ABCDEF}").expect("braced");
        let h = parse_adapter_guid("01234567-89ab-cdef-0123-456789abcdef").expect("raw");
        assert_eq!(g.to_u128(), h.to_u128());
    }

    #[test]
    fn entry_map_indexes_by_guid_and_family() {
        let json = r#"[
            {"InterfaceAlias":"Wi-Fi","InterfaceGuid":"{aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee}","AddressFamily":2,"Dhcp":true,"Servers":[]},
            {"InterfaceAlias":"Ethernet","InterfaceGuid":"{11111111-2222-3333-4444-555555555555}","AddressFamily":2,"Dhcp":false,"Servers":["8.8.8.8"]}
        ]"#;
        let map = entry_map(json);
        assert_eq!(map.len(), 2);
        assert!(map.contains_key(&("{aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee}".to_owned(), AF_IPV4)));
    }

    #[test]
    fn take_prior_falls_back_to_alias_for_legacy_snapshot() {
        let json =
            r#"[{"InterfaceAlias":"Wi-Fi","AddressFamily":2,"Dhcp":false,"Servers":["8.8.8.8"]}]"#;
        let mut prior = entry_map(json);
        let guid_key = ("{aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee}".to_owned(), AF_IPV4);
        let entry = take_prior(&mut prior, &guid_key, "Wi-Fi").expect("alias fallback");
        assert_eq!(entry.servers, ["8.8.8.8"]);
        assert!(prior.is_empty(), "the matched entry is consumed");
    }

    /// An entry matches a listed adapter by GUID when it has one, since restore
    /// resolves it that way, and by alias only when it has none.
    #[test]
    fn carried_entries_require_a_present_adapter() {
        let guid = GUID::from_u128(0x0123_4567_89ab_cdef_0123_4567_89ab_cdef);
        let present = RecordedDns::from_adapters(&[AdapterInfo {
            friendly_name: "Ethernet".to_owned(),
            guid,
            up: true,
            v4_servers: Vec::new(),
            v6_servers: Vec::new(),
        }]);
        let entry = |alias: &str, guid: &str| AdapterDnsEntry {
            interface_alias: alias.to_owned(),
            interface_guid: guid.to_owned(),
            address_family: AF_IPV6,
            dhcp: false,
            servers: vec!["2001:db8::1".to_owned()],
        };

        let present_guid = format_guid(guid).to_uppercase();
        assert!(present.has_adapter_for(&entry("Renamed", &present_guid)));
        assert!(present.has_adapter_for(&entry("Ethernet", "")));
        assert!(
            !present.has_adapter_for(&entry("Ethernet", "{ffffffff-ffff-ffff-ffff-ffffffffffff}"))
        );
        assert!(!present.has_adapter_for(&entry("Wi-Fi", "")));
    }

    /// An adapter that disappears after its redirect returns still on
    /// loopback, so its entry must outlive it; restore writes the original to
    /// its interface key. Only a GUID-less legacy entry, which restore cannot
    /// resolve without the adapter, is dropped.
    #[test]
    fn entries_for_absent_adapters_are_kept_unless_unresolvable() {
        let listed = Restorable::Listed(RecordedDns::from_adapters(&[AdapterInfo {
            friendly_name: "Ethernet".to_owned(),
            guid: GUID::from_u128(0x0123_4567_89ab_cdef_0123_4567_89ab_cdef),
            up: true,
            v4_servers: Vec::new(),
            v6_servers: Vec::new(),
        }]));
        let entry = |alias: &str, guid: &str| AdapterDnsEntry {
            interface_alias: alias.to_owned(),
            interface_guid: guid.to_owned(),
            address_family: AF_IPV4,
            dhcp: false,
            servers: vec!["192.0.2.53".to_owned()],
        };
        let gone = entry("USB Ethernet", "{ffffffff-ffff-ffff-ffff-ffffffffffff}");

        assert!(listed.keeps(&gone));
        assert!(listed.keeps(&entry("Ethernet", "")));
        assert!(!listed.keeps(&entry("Wi-Fi", "")));
        assert!(Restorable::Unknown.keeps(&gone));
        assert!(Restorable::Unknown.keeps(&entry("Wi-Fi", "")));
    }

    #[test]
    fn take_prior_prefers_guid_over_alias() {
        let json = r#"[
            {"InterfaceAlias":"Wi-Fi","InterfaceGuid":"{aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee}","AddressFamily":2,"Dhcp":false,"Servers":["8.8.8.8"]},
            {"InterfaceAlias":"Wi-Fi","AddressFamily":2,"Dhcp":false,"Servers":["1.1.1.1"]}
        ]"#;
        let mut prior = entry_map(json);
        let guid_key = ("{aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee}".to_owned(), AF_IPV4);
        let entry = take_prior(&mut prior, &guid_key, "Wi-Fi").expect("guid match");
        assert_eq!(entry.servers, ["8.8.8.8"]);
    }

    #[test]
    fn recorded_dns_matches_guid_and_legacy_alias_entries() {
        let entries = vec![
            AdapterDnsEntry {
                interface_alias: "Wi-Fi".to_owned(),
                interface_guid: "{aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee}".to_owned(),
                address_family: AF_IPV4,
                dhcp: false,
                servers: vec!["127.0.0.1".to_owned()],
            },
            AdapterDnsEntry {
                interface_alias: "Ethernet".to_owned(),
                interface_guid: String::new(),
                address_family: AF_IPV4,
                dhcp: false,
                servers: vec!["127.0.0.1".to_owned()],
            },
        ];
        let recorded = RecordedDns::from_entries(&entries);

        assert!(recorded.contains("{AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE}", "Wi-Fi", AF_IPV4));
        assert!(recorded.contains("", "Ethernet", AF_IPV4));
        assert!(!recorded.contains("", "Ethernet", AF_IPV6));
        assert!(
            !recorded.contains("{bbbbbbbb-0000-0000-0000-000000000000}", "Other", AF_IPV4),
            "a pair absent from the snapshot must still be swept"
        );
    }

    #[test]
    fn restore_entries_reject_malformed_json() {
        assert_eq!(saved_restore_entries("{not json}"), None);
        assert_eq!(saved_restore_entries("null"), None);
        assert!(!restore("{not json}"));
        assert!(!restore("null"));
    }

    #[test]
    fn restore_entries_reject_non_ip_servers_instead_of_passing_them_through() {
        let json = serialize_entries(&[AdapterDnsEntry {
            interface_alias: "Ethernet".to_owned(),
            interface_guid: "{11111111-2222-3333-4444-555555555555}".to_owned(),
            address_family: AF_IPV4,
            dhcp: false,
            servers: vec!["8.8.8.8'; calc; '".to_owned()],
        }]);
        assert!(
            deserialize_entries(&json).is_some(),
            "JSON is well-formed; the restore gate must still reject it"
        );
        assert_eq!(saved_restore_entries(&json), None);
        assert!(
            !restore(&json),
            "invalid servers must not reach IP Helper / the registry"
        );
    }

    #[test]
    fn restore_entries_reject_mixed_valid_and_invalid_rows() {
        let json = serialize_entries(&[
            AdapterDnsEntry {
                interface_alias: "Wi-Fi".to_owned(),
                interface_guid: "{aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee}".to_owned(),
                address_family: AF_IPV4,
                dhcp: false,
                servers: vec!["8.8.8.8".to_owned()],
            },
            AdapterDnsEntry {
                interface_alias: String::new(),
                interface_guid: String::new(),
                address_family: AF_IPV4,
                dhcp: false,
                servers: vec!["1.1.1.1".to_owned()],
            },
        ]);
        assert_eq!(saved_restore_entries(&json), None);
        assert!(!restore(&json));
    }

    #[test]
    fn restore_entries_canonicalize_valid_servers() {
        let json = serialize_entries(&[AdapterDnsEntry {
            interface_alias: "Ethernet".to_owned(),
            interface_guid: "{11111111-2222-3333-4444-555555555555}".to_owned(),
            address_family: AF_IPV6,
            dhcp: false,
            servers: vec!["2606:4700:4700:0:0:0:0:1111".to_owned()],
        }]);
        let entries = saved_restore_entries(&json).expect("valid snapshot");
        assert_eq!(entries[0].servers, ["2606:4700:4700::1111"]);
    }

    #[test]
    fn restore_entries_treat_empty_snapshot_as_no_recorded_devices() {
        assert_eq!(saved_restore_entries("[]").as_deref(), Some(&[][..]));
        assert_eq!(saved_restore_entries("").as_deref(), Some(&[][..]));
    }

    #[test]
    fn server_tokens_compare_lists_in_any_windows_separator() {
        assert_eq!(
            server_tokens("8.8.8.8,1.1.1.1"),
            server_tokens("8.8.8.8 1.1.1.1")
        );
        assert_eq!(
            server_tokens("2606:4700:4700:0:0:0:0:1111"),
            ["2606:4700:4700::1111"]
        );
        assert_eq!(server_tokens(""), [] as [String; 0]);
        assert_eq!(server_tokens(" , "), [] as [String; 0]);
        assert_ne!(
            server_tokens("1.1.1.1,8.8.8.8"),
            server_tokens("8.8.8.8,1.1.1.1")
        );
    }

    #[test]
    fn loopback_is_recognised_per_family() {
        let servers = |list: &[&str]| list.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>();
        assert!(contains_loopback(&servers(&["127.0.0.1"]), false));
        assert!(contains_loopback(
            &servers(&["8.8.8.8", "127.0.0.1"]),
            false
        ));
        assert!(!contains_loopback(&servers(&["::1"]), false));
        assert!(contains_loopback(&servers(&["::1"]), true));
        assert!(!contains_loopback(&servers(&["127.0.0.1"]), true));
        assert!(!contains_loopback(&[], false));
    }

    /// The entry a recovering redirect must not record as an original: it is
    /// Antiwire's own loopback, and restoring it would leave DNS broken.
    #[test]
    fn only_a_static_loopback_entry_points_at_antiwire() {
        let entry = |family, dhcp, server: &str| AdapterDnsEntry {
            interface_alias: "Ethernet".to_owned(),
            interface_guid: "{11111111-2222-3333-4444-555555555555}".to_owned(),
            address_family: family,
            dhcp,
            servers: vec![server.to_owned()],
        };
        assert!(points_at_antiwire_loopback(&entry(
            AF_IPV4,
            false,
            "127.0.0.1"
        )));
        assert!(points_at_antiwire_loopback(&entry(AF_IPV6, false, "::1")));
        assert!(!points_at_antiwire_loopback(&entry(
            AF_IPV4,
            true,
            "127.0.0.1"
        )));
        assert!(!points_at_antiwire_loopback(&entry(
            AF_IPV4, false, "8.8.8.8"
        )));
    }

    #[test]
    fn redirected_families_add_ipv6_only_when_served() {
        assert_eq!(
            redirected_families(false).collect::<Vec<_>>(),
            [(AF_IPV4, false)]
        );
        assert_eq!(
            redirected_families(true).collect::<Vec<_>>(),
            [(AF_IPV4, false), (AF_IPV6, true)]
        );
    }

    #[test]
    fn an_invalid_plan_redirects_nothing() {
        assert_eq!(apply_redirect(true, "{not json}"), None);
    }
}
