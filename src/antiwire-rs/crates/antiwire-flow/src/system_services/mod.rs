//! Attribution of OS-originated ("system") network requests.
//!
//! Some traffic belongs to the operating system rather than any one program: DHCP renewals,
//! NTP sync, multicast discovery, and the system resolver. When the collector reports these
//! flows without an owner (PID 0), the normal identity machinery — socket-table snapshots,
//! `OpenProcess` queries, SCM service enumeration — has nothing to join, so the rows
//! historically landed in the unknown application.
//!
//! This module folds those flows into the canonical `System` application identity instead,
//! with three hard rules that keep the bucket honest:
//!
//! 1. A resolvable, non-allowlisted owner is never replaced. The flow keeps its real
//!    application; at most an impersonation signal is raised.
//! 2. Ownerless folding applies only to the curated signatures below. Anything
//!    else keeps the existing unknown path.
//! 3. Takeover-capable server roles (DHCP and DNS servers) never fold when ownerless:
//!    an unattributed server stays visible as `unknown` instead of hiding in `System`.
//!    Every other server role folds ownerless, because answering time, `NetBIOS` names,
//!    or link-local discovery without an observed owner is the OS stack's normal shape.
//!
//! Wire signatures are shared across operating systems; only the owner allowlist differs per
//! OS, because services live in different places but speak the same protocols.
//!
//! Two deliberate asymmetries, both fraud-motivated:
//!
//! * NTP folds ownerless in both directions (the client and server share UDP 123 and
//!   cannot be told apart), while DHCP/DNS server roles stay unknown when ownerless.
//!   Answering time is low-risk; answering DHCP/DNS is network takeover.
//! * Unicast replies to multicast discovery (a peer answering mDNS/LLMNR/SSDP directly) do not
//!   match: the remote scope must be multicast or loopback. Tunneling data through a discovery
//!   port to a unicast peer stays attributable.

use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use moka::sync::Cache;
use netmetrics_core::{FlowKey, FlowMeta, Protocol};
use parking_lot::Mutex;

use antiwire_tuning::{IMPERSONATION_ALERT_CACHE_CAP, IMPERSONATION_ALERT_TTL_SECS};

#[cfg(any(test, target_os = "windows"))]
use crate::process_resolver::is_system_host_binary;

mod tables;

/// Whether the flow metadata names any owner at all: a nonzero PID or any
/// process evidence. Ownerless opens carry neither.
pub(crate) fn has_owner_evidence(meta: &FlowMeta) -> bool {
    meta.pid != 0
        || meta
            .process
            .as_ref()
            .is_some_and(|process| !process.executable.is_empty() || !process.name.is_empty())
}

/// Canonical `System` application identity. The path is synthetic (see
/// `process_resolver`), so it neither raises new-application alerts nor joins
/// any real program's row.
pub(crate) const SYSTEM_APP_PATH: &str = "System";
pub(crate) const SYSTEM_APP_NAME: &str = "system";

/// Returns true for the canonical `System` identity the classifier folds to.
pub(crate) fn is_system_identity(app_path: &str, app_name: &str) -> bool {
    app_path.eq_ignore_ascii_case(SYSTEM_APP_PATH) && app_name.eq_ignore_ascii_case(SYSTEM_APP_NAME)
}

/// Well-known service roles recognized by the classifier.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) enum SystemService {
    DhcpV4Client,
    DhcpV4Server,
    DhcpV6Client,
    DhcpV6Server,
    Ntp,
    SystemDns,
    Mdns,
    Llmnr,
    Ssdp,
    WsDiscovery,
    NetBiosNs,
}

impl SystemService {
    /// Short human label used in alerts and diagnostics.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::DhcpV4Client => "DHCPv4 client",
            Self::DhcpV4Server => "DHCPv4 server",
            Self::DhcpV6Client => "DHCPv6 client",
            Self::DhcpV6Server => "DHCPv6 server",
            Self::Ntp => "NTP",
            Self::SystemDns => "system DNS",
            Self::Mdns => "mDNS",
            Self::Llmnr => "LLMNR",
            Self::Ssdp => "SSDP",
            Self::WsDiscovery => "WS-Discovery",
            Self::NetBiosNs => "NetBIOS-NS",
        }
    }
}

/// What a non-allowlisted owner in the server role produces.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Impersonation {
    /// Privileged or takeover-capable role: publish an alert.
    Alert,
    /// Link-local discovery role: count only, so legitimate desktop listeners
    /// (media players, cast senders) do not raise alerts.
    Watch,
}

/// How a fold to `System` was evidenced.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum FoldEvidence {
    /// The owner resolved to an allowlisted OS component.
    VerifiedService,
    /// No owner was ever observed; the wire signature alone identified the flow.
    OwnerlessSignature,
}

/// Classifier outcome for one flow.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SystemVerdict {
    /// No signature matched, or the evidence does not support folding.
    NoMatch,
    /// Attribute the flow to the canonical `System` application.
    FoldSystem {
        service: SystemService,
        evidence: FoldEvidence,
    },
    /// Keep the resolved owner, but record the impersonation signal.
    KeepOwner {
        service: SystemService,
        impersonation: Impersonation,
    },
}

/// Owner evidence available at classification time.
///
/// The daemon's own PID is excluded by the caller before classifying (it always
/// resolves normally), so no variant is needed for it here.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum OwnerEvidence<'a> {
    /// No owner observed at all (PID 0, no process metadata).
    None,
    /// A PID was observed but resolution produced no real executable
    /// (empty path or a synthetic placeholder).
    Unresolved,
    /// Owner resolved to a real executable identity.
    Known { path: &'a str, name: &'a str },
}

impl<'a> OwnerEvidence<'a> {
    /// Evidence for a resolved identity. An empty path or a synthetic
    /// placeholder carries no executable to verify against the allowlist, so it
    /// can neither fold nor impersonate.
    pub(crate) fn from_identity(path: &'a str, name: &'a str) -> Self {
        if path.is_empty() || crate::process_resolver::is_synthetic_path(path) {
            Self::Unresolved
        } else {
            Self::Known { path, name }
        }
    }
}

/// Remote-address constraint for a signature.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AddrScope {
    /// Any address, including broadcast and unicast.
    Any,
    /// Multicast or loopback only. Unicast peers never match, so data tunneled
    /// through a discovery port to a unicast address stays attributable.
    MulticastOrLoopback,
}

impl AddrScope {
    fn allows(self, addr: IpAddr) -> bool {
        match self {
            Self::Any => true,
            Self::MulticastOrLoopback => addr.is_multicast() || addr.is_loopback(),
        }
    }
}

/// One oriented wire signature.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Signature {
    service: SystemService,
    /// `None` matches either transport (used for DNS, which runs over both).
    protocol: Option<Protocol>,
    /// `0` matches any port.
    local_port: u16,
    /// `0` matches any port.
    remote_port: u16,
    remote_scope: AddrScope,
    /// Ownerless flows with this shape fold to `System`.
    fold_ownerless: bool,
    /// Remote-address constraint for the ownerless fold. Server entries keep a
    /// wide match (so a known rogue answering unicast still signals) but fold
    /// ownerless only inside this scope, so ownerless tunneled traffic stays
    /// visible.
    ownerless_scope: AddrScope,
    /// A local port equal to this means the host acts as the server for the service.
    server_role_port: Option<u16>,
    /// Signal for a non-allowlisted owner holding the server role.
    impersonation: Option<Impersonation>,
}

impl Signature {
    fn matches(&self, key: &FlowKey) -> bool {
        // Port zero on the wire is degenerate data, never a real bind.
        if key.local_port == 0 || key.remote_port == 0 {
            return false;
        }
        if self
            .protocol
            .is_some_and(|protocol| protocol != key.protocol)
        {
            return false;
        }
        if self.local_port != 0 && self.local_port != key.local_port {
            return false;
        }
        if self.remote_port != 0 && self.remote_port != key.remote_port {
            return false;
        }
        self.remote_scope.allows(key.remote_addr)
    }

    fn is_server_role(&self, key: &FlowKey) -> bool {
        self.server_role_port
            .is_some_and(|port| port == key.local_port)
    }
}

/// How an owner is proven to be an OS component.
#[derive(Clone, Copy, Debug)]
enum OwnerKind {
    /// Executable filename that must live directly under one of the directories.
    /// A same-named binary anywhere else (temp, profile, downloads) never matches.
    DirBoundName {
        name: &'static str,
        dirs: &'static [&'static str],
    },
    /// Windows service-host identity: the disambiguated `path::{label}` form produced by
    /// SCM enumeration, so the tag names a real hosted service rather than a filename.
    #[cfg(any(test, target_os = "windows"))]
    SvchostService(&'static str),
}

/// One allowlist rule binding an OS component to the service it may serve.
#[derive(Clone, Copy, Debug)]
struct ServiceOwner {
    service: SystemService,
    kind: OwnerKind,
}

/// The classifier input: wire signatures shared across systems plus the
/// per-OS component allowlist.
#[derive(Clone, Copy, Debug)]
pub(crate) struct SystemProfile {
    /// Case-insensitive path comparison (Windows profile). A property of the
    /// profile being evaluated, never of the build host, so cross-OS unit
    /// tests are deterministic everywhere.
    case_insensitive: bool,
    signatures: &'static [Signature],
    allowlist: &'static [ServiceOwner],
}

impl SystemProfile {
    /// Signatures matching this flow, if any. First match wins; tables are
    /// ordered so server-role entries precede overlapping client entries.
    pub(crate) fn match_signature(&self, key: &FlowKey) -> Option<&Signature> {
        self.signatures.iter().find(|sig| sig.matches(key))
    }

    /// Whether the resolved identity is an allowlisted OS component for this service.
    fn allows(&self, service: SystemService, path: &str, name: &str) -> bool {
        self.allowlist
            .iter()
            .filter(|owner| owner.service == service)
            .any(|owner| owner.kind.matches(self, path, name))
    }

    fn eq(&self, left: &str, right: &str) -> bool {
        if self.case_insensitive {
            left.eq_ignore_ascii_case(right)
        } else {
            left == right
        }
    }

    /// Whether a resolved display name corroborates the image's file name.
    ///
    /// On Unix the name comes from the kernel's process name, which keeps only
    /// the first 15 bytes (Linux `comm`) or 16 (macOS `p_comm`). That is undone
    /// here, so `systemd-resolve` corroborates `systemd-resolved`.
    fn name_corroborates(&self, name: &str, file: &str) -> bool {
        if self.case_insensitive {
            return self.eq(name, file);
        }
        name == file || (name.len() >= KERNEL_NAME_MIN_BYTES && file.starts_with(name))
    }

    /// Normalizes a path for allowlist comparison: strips the Win32 `\\?\`
    /// device prefix (Windows profile only). Separators are matched exactly:
    /// forward slashes never occur in canonical Windows paths, so tolerating
    /// them would only admit spellings the resolver itself never produces.
    fn normalize<'a>(&self, path: &'a str) -> &'a str {
        if self.case_insensitive {
            path.strip_prefix(r"\\?\").unwrap_or(path)
        } else {
            path
        }
    }

    /// Whether `dir` (always stored with a trailing separator) is the immediate
    /// parent directory: subdirectories, `..` segments, and bare filenames
    /// never match.
    fn dir_is_parent(&self, normalized: &str, dir: &str) -> bool {
        parent_dir(normalized).is_some_and(|parent| self.eq(parent, dir))
    }

    /// Matches the disambiguated service-host identity (`{exe}::{label}` with
    /// name `{label} (svchost.exe)`). The executable carrying the label must be
    /// the canonical service host, and the display label must name exactly the
    /// services in the path label: a mismatched pair is a forged identity, not
    /// a service. A self-named binary smuggling a label, or a label on any
    /// other host (including `rundll32.exe`), never matches.
    ///
    /// Labels containing `", "` are rejected outright: the producer joins with
    /// `","`, so an inner space cannot come from disambiguation.
    ///
    /// Byte-safe throughout: every index derives from the ASCII suffix, and
    /// `get` refuses non-boundaries instead of panicking.
    #[cfg(any(test, target_os = "windows"))]
    fn matches_svchost_service(&self, path: &str, name: &str, tag: &str) -> bool {
        const SUFFIX: &str = "(svchost.exe)";
        let Some(split) = name.len().checked_sub(SUFFIX.len()) else {
            return false;
        };
        let (Some(prefix), Some(suffix)) = (name.get(..split), name.get(split..)) else {
            return false;
        };
        let Some(name_label) = self
            .eq(suffix, SUFFIX)
            .then(|| prefix.strip_suffix(' '))
            .flatten()
        else {
            return false;
        };
        let Some((exe, labels)) = path.rsplit_once("::") else {
            return false;
        };
        if !is_system_host_binary(exe, "svchost.exe") {
            return false;
        }
        if labels.contains(", ") {
            return false;
        }
        self.eq(name_label, labels) && labels.split(',').any(|label| self.eq(label.trim(), tag))
    }

    /// Pure classification. The caller is responsible for acting on the verdict
    /// (folding, alerting, counting) and for skipping resolution work on the
    /// ownerless path.
    pub(crate) fn classify(&self, key: &FlowKey, owner: OwnerEvidence<'_>) -> SystemVerdict {
        let Some(sig) = self.match_signature(key) else {
            return SystemVerdict::NoMatch;
        };
        match owner {
            OwnerEvidence::None => {
                if sig.fold_ownerless && sig.ownerless_scope.allows(key.remote_addr) {
                    SystemVerdict::FoldSystem {
                        service: sig.service,
                        evidence: FoldEvidence::OwnerlessSignature,
                    }
                } else {
                    SystemVerdict::NoMatch
                }
            }
            OwnerEvidence::Unresolved => SystemVerdict::NoMatch,
            OwnerEvidence::Known { path, name } if self.allows(sig.service, path, name) => {
                SystemVerdict::FoldSystem {
                    service: sig.service,
                    evidence: FoldEvidence::VerifiedService,
                }
            }
            // Only a non-allowlisted owner holding the server role signals.
            OwnerEvidence::Known { .. } => sig
                .impersonation
                .filter(|_| sig.is_server_role(key))
                .map_or(SystemVerdict::NoMatch, |impersonation| {
                    SystemVerdict::KeepOwner {
                        service: sig.service,
                        impersonation,
                    }
                }),
        }
    }
}

impl OwnerKind {
    fn matches(&self, profile: &SystemProfile, path: &str, name: &str) -> bool {
        match self {
            Self::DirBoundName {
                name: expected,
                dirs,
            } => {
                let normalized = profile.normalize(path);
                // The display name must corroborate the path: a mismatched pair
                // is a forged or confused identity, never a verified service.
                file_name(normalized).is_some_and(|file| {
                    profile.eq(file, expected)
                        && profile.name_corroborates(name, file)
                        && dirs
                            .iter()
                            .any(|dir| profile.dir_is_parent(normalized, dir))
                })
            }
            #[cfg(any(test, target_os = "windows"))]
            Self::SvchostService(tag) => profile.matches_svchost_service(path, name, tag),
        }
    }
}

/// Shortest name a Unix kernel truncates a process name to (Linux `comm`).
const KERNEL_NAME_MIN_BYTES: usize = 15;

/// Parent directory of a normalized path, with trailing separator.
fn parent_dir(normalized: &str) -> Option<&str> {
    let index = normalized.rfind(['\\', '/'])?;
    normalized.get(..=index)
}

/// Executable filename of a normalized path.
fn file_name(normalized: &str) -> Option<&str> {
    let file = normalized.rsplit(['\\', '/']).next()?;
    (!file.is_empty()).then_some(file)
}

/// Profile for the host OS. All three profiles stay compiled and testable on
/// every host; only the selection is platform-gated.
pub(crate) fn current() -> &'static SystemProfile {
    #[cfg(target_os = "windows")]
    {
        windows()
    }
    #[cfg(target_os = "linux")]
    {
        linux()
    }
    #[cfg(target_os = "macos")]
    {
        macos()
    }
    #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
    {
        &tables::FALLBACK_PROFILE
    }
}

/// Fallback profile for targets without a dedicated allowlist.
#[cfg(any(
    test,
    not(any(target_os = "windows", target_os = "linux", target_os = "macos"))
))]
pub(crate) fn fallback() -> &'static SystemProfile {
    &tables::FALLBACK_PROFILE
}

/// Windows service allowlist. Pure data; safe to exercise on any host.
#[cfg(any(test, target_os = "windows"))]
pub(crate) fn windows() -> &'static SystemProfile {
    &tables::WINDOWS_PROFILE
}

/// Linux service allowlist. Pure data; safe to exercise on any host.
#[cfg(any(test, target_os = "linux"))]
pub(crate) fn linux() -> &'static SystemProfile {
    &tables::LINUX_PROFILE
}

/// macOS service allowlist. Pure data; safe to exercise on any host.
#[cfg(any(test, target_os = "macos"))]
pub(crate) fn macos() -> &'static SystemProfile {
    &tables::MACOS_PROFILE
}

/// Cumulative classification outcomes.
///
/// Loads are independent `Relaxed` reads, so under concurrent updates the
/// fields may reflect slightly different moments: treat snapshots as
/// approximate, never as an exact ledger.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SystemAttributionStats {
    /// Signature matches of any kind.
    pub matched: u64,
    /// Ownerless flows folded to `System`.
    pub folded_ownerless: u64,
    /// Verified service owners folded to `System`.
    pub folded_verified: u64,
    /// Impersonation alerts published (privileged/server roles).
    pub impersonation_alert: u64,
    /// Watch-tier responder matches counted without alerting.
    pub impersonation_watch: u64,
    /// Signature matched but no rule applied (daemon flows, already-`System`
    /// identities, responder-ownerless on privileged ports, unresolved owners,
    /// disabled mode).
    pub no_rule: u64,
}

/// What one system-attribution decision did, for [`SystemAttributionStats`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AttributionOutcome {
    /// A system-service signature matched the flow.
    Matched,
    FoldedOwnerless,
    FoldedVerified,
    ImpersonationAlert,
    ImpersonationWatch,
    /// A signature matched but no rule applied.
    NoRule,
}

/// Running totals behind [`SystemAttributionStats`].
#[derive(Default)]
struct AttributionCounters {
    matched: AtomicU64,
    folded_ownerless: AtomicU64,
    folded_verified: AtomicU64,
    impersonation_alert: AtomicU64,
    impersonation_watch: AtomicU64,
    no_rule: AtomicU64,
}

impl AttributionCounters {
    fn counter(&self, outcome: AttributionOutcome) -> &AtomicU64 {
        match outcome {
            AttributionOutcome::Matched => &self.matched,
            AttributionOutcome::FoldedOwnerless => &self.folded_ownerless,
            AttributionOutcome::FoldedVerified => &self.folded_verified,
            AttributionOutcome::ImpersonationAlert => &self.impersonation_alert,
            AttributionOutcome::ImpersonationWatch => &self.impersonation_watch,
            AttributionOutcome::NoRule => &self.no_rule,
        }
    }

    fn snapshot(&self) -> SystemAttributionStats {
        SystemAttributionStats {
            matched: self.matched.load(Ordering::Relaxed),
            folded_ownerless: self.folded_ownerless.load(Ordering::Relaxed),
            folded_verified: self.folded_verified.load(Ordering::Relaxed),
            impersonation_alert: self.impersonation_alert.load(Ordering::Relaxed),
            impersonation_watch: self.impersonation_watch.load(Ordering::Relaxed),
            no_rule: self.no_rule.load(Ordering::Relaxed),
        }
    }
}

/// Rate-limited impersonation alert gate, owned by the flow processor.
pub(crate) struct SystemAttributor {
    /// Serializes claim check-and-set: `Cache::get` plus `insert` is not
    /// atomic on its own, and a duplicate HIGH notification is worse than a
    /// few microseconds of contention on an already-rare path.
    claim_gate: Mutex<()>,
    impersonation_seen: Cache<(String, String, SystemService), ()>,
    counters: AttributionCounters,
}

impl SystemAttributor {
    pub(crate) fn new() -> Self {
        Self {
            claim_gate: Mutex::new(()),
            impersonation_seen: Cache::builder()
                .max_capacity(
                    u64::try_from(IMPERSONATION_ALERT_CACHE_CAP)
                        .unwrap_or(1_024)
                        .max(1),
                )
                .time_to_live(Duration::from_secs(
                    u64::try_from(IMPERSONATION_ALERT_TTL_SECS)
                        .unwrap_or(3_600)
                        .max(1),
                ))
                .build(),
            counters: AttributionCounters::default(),
        }
    }

    /// Counts one attribution decision.
    pub(crate) fn note(&self, outcome: AttributionOutcome) {
        self.counters
            .counter(outcome)
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Totals since this attributor was built.
    pub(crate) fn stats(&self) -> SystemAttributionStats {
        self.counters.snapshot()
    }

    /// Returns true when an impersonation alert for this application and service
    /// may fire now; repeat sightings inside the TTL stay silent.
    ///
    /// Keyed by executable identity rather than application id so unrelated
    /// applications never share suppression — notably the transient `app_id 0`
    /// rows produced while the store is failing. Suppression stays best-effort
    /// under memory pressure: past the cache capacity, an evicted entry may
    /// alert again inside its TTL.
    pub(crate) fn claim_impersonation_alert(
        &self,
        app_path: &str,
        app_name: &str,
        service: SystemService,
    ) -> bool {
        let _guard = self.claim_gate.lock();
        let key = (app_path.to_owned(), app_name.to_owned(), service);
        if self.impersonation_seen.get(&key).is_some() {
            return false;
        }
        self.impersonation_seen.insert(key, ());
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    fn udp_key(local: &str, local_port: u16, remote: &str, remote_port: u16) -> FlowKey {
        FlowKey {
            protocol: Protocol::Udp,
            local_addr: local.parse::<IpAddr>().expect("local addr"),
            local_port,
            remote_addr: remote.parse::<IpAddr>().expect("remote addr"),
            remote_port,
        }
    }

    fn tcp_key(local: &str, local_port: u16, remote: &str, remote_port: u16) -> FlowKey {
        FlowKey {
            protocol: Protocol::Tcp,
            local_addr: local.parse::<IpAddr>().expect("local addr"),
            local_port,
            remote_addr: remote.parse::<IpAddr>().expect("remote addr"),
            remote_port,
        }
    }

    fn dhcp_client_key() -> FlowKey {
        udp_key("192.168.68.50", 68, "192.168.68.1", 67)
    }

    fn ownerless(profile: &SystemProfile, key: &FlowKey) -> SystemVerdict {
        profile.classify(key, OwnerEvidence::None)
    }

    fn fold_ownerless(profile: &SystemProfile, key: &FlowKey, service: SystemService) {
        assert_eq!(
            ownerless(profile, key),
            SystemVerdict::FoldSystem {
                service,
                evidence: FoldEvidence::OwnerlessSignature,
            },
            "ownerless {key:?} must fold to {service:?}"
        );
    }

    fn stays_unknown(profile: &SystemProfile, key: &FlowKey) {
        assert_eq!(
            ownerless(profile, key),
            SystemVerdict::NoMatch,
            "ownerless {key:?} must not fold"
        );
    }

    #[test]
    fn profiles_are_selectable_per_host() {
        assert!(!std::ptr::eq(windows(), linux()));
        assert!(!std::ptr::eq(windows(), macos()));
        assert!(!std::ptr::eq(linux(), macos()));
        #[cfg(target_os = "windows")]
        assert!(std::ptr::eq(current(), windows()));
        #[cfg(target_os = "linux")]
        assert!(std::ptr::eq(current(), linux()));
        #[cfg(target_os = "macos")]
        assert!(std::ptr::eq(current(), macos()));
    }

    #[test]
    fn fallback_profile_verifies_nothing() {
        let dhcp = dhcp_client_key();
        // Wire signatures still match without an allowlist...
        assert_eq!(
            fallback().classify(&dhcp, OwnerEvidence::None),
            SystemVerdict::FoldSystem {
                service: SystemService::DhcpV4Client,
                evidence: FoldEvidence::OwnerlessSignature,
            }
        );
        // ...but no owner verifies, so nothing folds on a verified basis.
        assert_eq!(
            fallback().classify(
                &dhcp,
                OwnerEvidence::Known {
                    path: r"C:\Windows\System32\svchost.exe::Dhcp",
                    name: "Dhcp (svchost.exe)",
                }
            ),
            SystemVerdict::NoMatch
        );
    }

    #[test]
    fn ordinary_traffic_matches_nothing_on_any_profile() {
        let key = tcp_key("192.168.68.50", 50_000, "93.184.216.34", 443);
        for profile in [windows(), linux(), macos()] {
            assert_eq!(ownerless(profile, &key), SystemVerdict::NoMatch);
            assert_eq!(
                profile.classify(
                    &key,
                    OwnerEvidence::Known {
                        path: r"C:\apps\browser.exe",
                        name: "browser.exe",
                    }
                ),
                SystemVerdict::NoMatch
            );
        }
    }

    #[test]
    fn dhcp_client_shapes_fold_ownerless_on_every_profile() {
        let renew = dhcp_client_key();
        let discover = udp_key("0.0.0.0", 68, "255.255.255.255", 67);
        let v6 = FlowKey {
            protocol: Protocol::Udp,
            local_addr: "fe80::1".parse().unwrap(),
            local_port: 546,
            remote_addr: "ff02::1:2".parse().unwrap(),
            remote_port: 547,
        };
        for profile in [windows(), linux(), macos()] {
            fold_ownerless(profile, &renew, SystemService::DhcpV4Client);
            fold_ownerless(profile, &discover, SystemService::DhcpV4Client);
            fold_ownerless(profile, &v6, SystemService::DhcpV6Client);
        }
    }

    #[test]
    fn dhcp_server_role_never_folds_ownerless() {
        let server = udp_key("192.168.68.1", 67, "192.168.68.50", 68);
        let server_v6 = FlowKey {
            protocol: Protocol::Udp,
            local_addr: "fe80::1".parse().unwrap(),
            local_port: 547,
            remote_addr: "fe80::2".parse().unwrap(),
            remote_port: 546,
        };
        for profile in [windows(), linux(), macos()] {
            stays_unknown(profile, &server);
            stays_unknown(profile, &server_v6);
        }
    }

    #[test]
    fn dhcp_over_tcp_is_not_dhcp() {
        let key = tcp_key("192.168.68.50", 68, "192.168.68.1", 67);
        for profile in [windows(), linux(), macos()] {
            stays_unknown(profile, &key);
        }
    }

    #[test]
    fn server_entry_wins_overlapping_client_shape() {
        // Local 67 matches the server entry first, never the client entry.
        let key = udp_key("192.168.68.1", 67, "192.168.68.50", 67);
        assert_eq!(
            ownerless(windows(), &key),
            SystemVerdict::NoMatch,
            "local 67 must resolve to the server role"
        );
    }

    #[test]
    fn unix_services_verify_with_the_names_the_resolver_produces() {
        let ntp = udp_key("192.168.68.50", 51_234, "9.9.9.9", 123);
        let path = "/usr/lib/systemd/systemd-timesyncd";
        let classify = |name| linux().classify(&ntp, OwnerEvidence::Known { path, name });
        let verified = SystemVerdict::FoldSystem {
            service: SystemService::Ntp,
            evidence: FoldEvidence::VerifiedService,
        };
        // Linux `comm` keeps 15 bytes.
        assert_eq!(classify("systemd-timesyn"), verified);
        assert_eq!(classify("systemd-timesyncd"), verified);
        // A shorter prefix is not a truncation, and a different name is a mismatch.
        assert_ne!(classify("systemd"), verified);
        assert_ne!(classify("chronyd"), verified);

        let dhcp = dhcp_client_key();
        assert_eq!(
            linux().classify(
                &dhcp,
                OwnerEvidence::Known {
                    path: "/usr/lib/systemd/systemd-networkd",
                    name: "systemd-network",
                }
            ),
            SystemVerdict::FoldSystem {
                service: SystemService::DhcpV4Client,
                evidence: FoldEvidence::VerifiedService,
            }
        );
    }

    #[test]
    fn ntp_folds_ownerless_in_both_directions() {
        let client = udp_key("192.168.68.50", 51_234, "9.9.9.9", 123);
        let windows_client = udp_key("192.168.68.50", 123, "9.9.9.9", 123);
        for profile in [windows(), linux(), macos()] {
            fold_ownerless(profile, &client, SystemService::Ntp);
            fold_ownerless(profile, &windows_client, SystemService::Ntp);
        }
    }

    #[test]
    fn dns_folds_ownerless_requests_but_not_responder_binds() {
        let query = udp_key("192.168.68.50", 51_234, "9.9.9.9", 53);
        let query_tcp = tcp_key("192.168.68.50", 51_235, "9.9.9.9", 53);
        let responder = udp_key("192.168.68.50", 53, "192.168.68.60", 51_234);
        for profile in [windows(), linux(), macos()] {
            fold_ownerless(profile, &query, SystemService::SystemDns);
            fold_ownerless(profile, &query_tcp, SystemService::SystemDns);
            stays_unknown(profile, &responder);
        }
    }

    #[test]
    fn discovery_folds_multicast_and_loopback_but_not_unicast() {
        let mdns = udp_key("192.168.68.50", 51_234, "224.0.0.251", 5353);
        let mdns_loopback = udp_key("127.0.0.1", 51_234, "127.0.0.1", 5353);
        let mdns_unicast = udp_key("192.168.68.50", 51_234, "203.0.113.7", 5353);
        let llmnr = udp_key("192.168.68.50", 51_234, "224.0.0.252", 5355);
        let ssdp = udp_key("192.168.68.50", 51_234, "239.255.255.250", 1900);
        let wsd = udp_key("192.168.68.50", 51_234, "239.255.255.250", 3702);
        let wsd_v6 = FlowKey {
            protocol: Protocol::Udp,
            local_addr: "fe80::1".parse().unwrap(),
            local_port: 51_234,
            remote_addr: "ff02::c".parse().unwrap(),
            remote_port: 3702,
        };
        for profile in [windows(), linux(), macos()] {
            fold_ownerless(profile, &mdns, SystemService::Mdns);
            fold_ownerless(profile, &mdns_loopback, SystemService::Mdns);
            stays_unknown(profile, &mdns_unicast);
            fold_ownerless(profile, &llmnr, SystemService::Llmnr);
            fold_ownerless(profile, &ssdp, SystemService::Ssdp);
            fold_ownerless(profile, &wsd, SystemService::WsDiscovery);
            fold_ownerless(profile, &wsd_v6, SystemService::WsDiscovery);
        }
    }

    #[test]
    fn netbios_ns_folds_ownerless() {
        let query = udp_key("192.168.68.50", 137, "192.168.68.255", 137);
        for profile in [windows(), linux(), macos()] {
            fold_ownerless(profile, &query, SystemService::NetBiosNs);
        }
    }

    #[test]
    fn verified_windows_services_fold() {
        let dhcp = dhcp_client_key();
        assert_eq!(
            windows().classify(
                &dhcp,
                OwnerEvidence::Known {
                    path: r"C:\Windows\System32\svchost.exe::Dhcp",
                    name: "Dhcp (svchost.exe)",
                }
            ),
            SystemVerdict::FoldSystem {
                service: SystemService::DhcpV4Client,
                evidence: FoldEvidence::VerifiedService,
            }
        );

        // A service group also hosting Dhcp still verifies.
        assert_eq!(
            windows().classify(
                &dhcp,
                OwnerEvidence::Known {
                    path: r"C:\Windows\System32\svchost.exe::BITS,Dhcp",
                    name: "BITS,Dhcp (svchost.exe)",
                }
            ),
            SystemVerdict::FoldSystem {
                service: SystemService::DhcpV4Client,
                evidence: FoldEvidence::VerifiedService,
            }
        );

        // A group without Dhcp does not verify for DHCP traffic.
        assert_eq!(
            windows().classify(
                &dhcp,
                OwnerEvidence::Known {
                    path: r"C:\Windows\System32\svchost.exe::BITS",
                    name: "BITS (svchost.exe)",
                }
            ),
            SystemVerdict::NoMatch
        );

        // A self-named binary has no service label and never verifies.
        assert_eq!(
            windows().classify(
                &dhcp,
                OwnerEvidence::Known {
                    path: r"C:\Users\me\AppData\Local\Temp\svchost.exe",
                    name: "svchost.exe",
                }
            ),
            SystemVerdict::NoMatch
        );

        // The plain image without a disambiguated label does not verify either.
        assert_eq!(
            windows().classify(
                &dhcp,
                OwnerEvidence::Known {
                    path: r"C:\Windows\System32\svchost.exe",
                    name: "svchost.exe",
                }
            ),
            SystemVerdict::NoMatch
        );

        // DNS via the system resolver folds.
        let dns = udp_key("192.168.68.50", 51_234, "9.9.9.9", 53);
        assert_eq!(
            windows().classify(
                &dns,
                OwnerEvidence::Known {
                    path: r"C:\Windows\System32\svchost.exe::Dnscache",
                    name: "Dnscache (svchost.exe)",
                }
            ),
            SystemVerdict::FoldSystem {
                service: SystemService::SystemDns,
                evidence: FoldEvidence::VerifiedService,
            }
        );
    }

    #[test]
    fn verified_linux_and_macos_services_fold() {
        let dhcp = dhcp_client_key();
        let resolved = OwnerEvidence::Known {
            path: "/usr/lib/systemd/systemd-networkd",
            name: "systemd-networkd",
        };
        assert_eq!(
            linux().classify(&dhcp, resolved),
            SystemVerdict::FoldSystem {
                service: SystemService::DhcpV4Client,
                evidence: FoldEvidence::VerifiedService,
            }
        );
        // Same binary name outside the system location proves nothing.
        assert_eq!(
            linux().classify(
                &dhcp,
                OwnerEvidence::Known {
                    path: "/tmp/systemd-networkd",
                    name: "systemd-networkd",
                }
            ),
            SystemVerdict::NoMatch
        );

        let mdns = udp_key("192.168.68.50", 51_234, "224.0.0.251", 5353);
        assert_eq!(
            linux().classify(
                &mdns,
                OwnerEvidence::Known {
                    path: "/usr/sbin/avahi-daemon",
                    name: "avahi-daemon",
                }
            ),
            SystemVerdict::FoldSystem {
                service: SystemService::Mdns,
                evidence: FoldEvidence::VerifiedService,
            }
        );
        assert_eq!(
            macos().classify(
                &mdns,
                OwnerEvidence::Known {
                    path: "/usr/sbin/mDNSResponder",
                    name: "mDNSResponder",
                }
            ),
            SystemVerdict::FoldSystem {
                service: SystemService::Mdns,
                evidence: FoldEvidence::VerifiedService,
            }
        );
        assert_eq!(
            macos().classify(
                &dhcp,
                OwnerEvidence::Known {
                    path: "/usr/libexec/configd",
                    name: "configd",
                }
            ),
            SystemVerdict::FoldSystem {
                service: SystemService::DhcpV4Client,
                evidence: FoldEvidence::VerifiedService,
            }
        );
        // Cross-OS allowlists do not leak: avahi is not a macOS component.
        assert_eq!(
            macos().classify(
                &mdns,
                OwnerEvidence::Known {
                    path: "/usr/sbin/avahi-daemon",
                    name: "avahi-daemon",
                }
            ),
            SystemVerdict::NoMatch
        );
    }

    #[test]
    fn ownerless_discovery_responder_folds_only_to_multicast() {
        // Our announcement sent to the group: folds.
        let announce = udp_key("192.168.68.50", 5353, "224.0.0.251", 5353);
        // Our socket answering a unicast peer: stays visible, but a known
        // rogue there still signals (see the tiers test).
        let answer = udp_key("192.168.68.50", 5353, "203.0.113.7", 43_210);
        let ssdp_answer = udp_key("192.168.68.50", 1900, "203.0.113.7", 43_211);
        for profile in [windows(), linux(), macos()] {
            fold_ownerless(profile, &announce, SystemService::Mdns);
            stays_unknown(profile, &answer);
            stays_unknown(profile, &ssdp_answer);
        }
    }

    #[test]
    fn ownerless_dns_responder_stays_unknown_but_verified_folds() {
        // A :53 -> :53 flow matches the server entry first: ownerless it must
        // stay visible (takeover shape); verified it folds.
        let both = udp_key("192.168.68.50", 53, "192.168.68.60", 53);
        stays_unknown(windows(), &both);
        assert_eq!(
            windows().classify(
                &both,
                OwnerEvidence::Known {
                    path: r"C:\Windows\System32\svchost.exe::SharedAccess",
                    name: "SharedAccess (svchost.exe)",
                }
            ),
            SystemVerdict::FoldSystem {
                service: SystemService::SystemDns,
                evidence: FoldEvidence::VerifiedService,
            }
        );
    }

    #[test]
    fn forged_service_identities_never_verify() {
        let dhcp = dhcp_client_key();
        // A label smuggled outside the canonical service host.
        assert_eq!(
            windows().classify(
                &dhcp,
                OwnerEvidence::Known {
                    path: r"C:\Temp\svchost.exe::Dhcp",
                    name: "Dhcp (svchost.exe)",
                }
            ),
            SystemVerdict::NoMatch
        );
        // A label on a different host entirely.
        assert_eq!(
            windows().classify(
                &dhcp,
                OwnerEvidence::Known {
                    path: r"C:\Windows\System32\rundll32.exe::Dnscache",
                    name: "Dnscache (svchost.exe)",
                }
            ),
            SystemVerdict::NoMatch
        );
        // A display label that does not name the path's services.
        let dns_query = udp_key("192.168.68.50", 51_234, "9.9.9.9", 53);
        assert_eq!(
            windows().classify(
                &dns_query,
                OwnerEvidence::Known {
                    path: r"C:\Windows\System32\svchost.exe::Dnscache",
                    name: "Evil (svchost.exe)",
                }
            ),
            SystemVerdict::NoMatch
        );
        // Same-named binary one directory deeper than the allowlist.
        let dns = udp_key("192.168.68.50", 51_234, "9.9.9.9", 53);
        assert_eq!(
            windows().classify(
                &dns,
                OwnerEvidence::Known {
                    path: r"C:\Windows\System32\drivers\dns.exe",
                    name: "dns.exe",
                }
            ),
            SystemVerdict::NoMatch
        );
        assert_eq!(
            linux().classify(
                &dhcp,
                OwnerEvidence::Known {
                    path: "/usr/sbin/evil/dhclient",
                    name: "dhclient",
                }
            ),
            SystemVerdict::NoMatch
        );
        // Dot-dot traversal past the system directory.
        assert_eq!(
            linux().classify(
                &dhcp,
                OwnerEvidence::Known {
                    path: "/usr/sbin/../tmp/systemd-networkd",
                    name: "systemd-networkd",
                }
            ),
            SystemVerdict::NoMatch
        );
        assert_eq!(
            windows().classify(
                &dns,
                OwnerEvidence::Known {
                    path: r"C:\Windows\System32\..\Temp\dns.exe",
                    name: "dns.exe",
                }
            ),
            SystemVerdict::NoMatch
        );
        // A display name that does not corroborate the path.
        let mdns = udp_key("192.168.68.50", 51_234, "224.0.0.251", 5353);
        assert_eq!(
            linux().classify(
                &mdns,
                OwnerEvidence::Known {
                    path: "/usr/sbin/avahi-daemon",
                    name: "evil",
                }
            ),
            SystemVerdict::NoMatch
        );
    }

    #[test]
    fn allowlist_matching_tolerates_device_prefix_but_not_slashes() {
        let dns = udp_key("192.168.68.50", 51_234, "9.9.9.9", 53);
        // The Win32 device prefix names the same file.
        assert_eq!(
            windows().classify(
                &dns,
                OwnerEvidence::Known {
                    path: r"\\?\C:\Windows\System32\dns.exe",
                    name: "dns.exe",
                }
            ),
            SystemVerdict::FoldSystem {
                service: SystemService::SystemDns,
                evidence: FoldEvidence::VerifiedService,
            }
        );
        // Forward slashes never occur in canonical Windows paths, so they do
        // not verify: tolerating them would admit spellings the resolver
        // itself never produces.
        assert_eq!(
            windows().classify(
                &dns,
                OwnerEvidence::Known {
                    path: r"C:/Windows/System32/dns.exe",
                    name: "dns.exe",
                }
            ),
            SystemVerdict::NoMatch
        );
    }

    #[test]
    fn rundll32_identities_never_verify_but_still_signal() {
        let rundll32 = OwnerEvidence::Known {
            path: r"C:\Windows\System32\rundll32.exe::shell32.dll,Control_RunDLL",
            name: "shell32.dll,Control_RunDLL (rundll32.exe)",
        };
        // mDNS responder role: watched, never folded, never alerted.
        let mdns = udp_key("192.168.68.50", 5353, "224.0.0.251", 5353);
        assert_eq!(
            windows().classify(&mdns, rundll32),
            SystemVerdict::KeepOwner {
                service: SystemService::Mdns,
                impersonation: Impersonation::Watch,
            }
        );
        // DNS responder role: alerts like any other non-allowlisted owner.
        let dns = udp_key("192.168.68.50", 53, "192.168.68.60", 51_234);
        assert_eq!(
            windows().classify(&dns, rundll32),
            SystemVerdict::KeepOwner {
                service: SystemService::SystemDns,
                impersonation: Impersonation::Alert,
            }
        );
        // Client shape: ordinary traffic.
        assert_eq!(
            windows().classify(&dhcp_client_key(), rundll32),
            SystemVerdict::NoMatch
        );
    }

    #[test]
    fn linux_allowlist_matching_is_exact() {
        let mdns = udp_key("192.168.68.50", 51_234, "224.0.0.251", 5353);
        assert_eq!(
            linux().classify(
                &mdns,
                OwnerEvidence::Known {
                    path: "/USR/SBIN/AVAHI-DAEMON",
                    name: "AVAHI-DAEMON",
                }
            ),
            SystemVerdict::NoMatch,
            "linux matching must stay exact"
        );
    }

    #[test]
    fn dhcpv6_server_matches_ics_like_v4() {
        let server_v6 = FlowKey {
            protocol: Protocol::Udp,
            local_addr: "fe80::1".parse().unwrap(),
            local_port: 547,
            remote_addr: "fe80::2".parse().unwrap(),
            remote_port: 546,
        };
        stays_unknown(windows(), &server_v6);
        assert_eq!(
            windows().classify(
                &server_v6,
                OwnerEvidence::Known {
                    path: r"C:\Windows\System32\svchost.exe::SharedAccess",
                    name: "SharedAccess (svchost.exe)",
                }
            ),
            SystemVerdict::FoldSystem {
                service: SystemService::DhcpV6Server,
                evidence: FoldEvidence::VerifiedService,
            }
        );
    }

    #[test]
    fn impersonation_tiers_follow_the_role() {
        let user = OwnerEvidence::Known {
            path: r"C:\apps\evil.exe",
            name: "evil.exe",
        };
        // Hard-alert roles: takeover-capable responders.
        for (key, service) in [
            (
                udp_key("192.168.68.50", 67, "192.168.68.60", 68),
                SystemService::DhcpV4Server,
            ),
            (
                udp_key("192.168.68.50", 53, "192.168.68.60", 51_234),
                SystemService::SystemDns,
            ),
            (
                udp_key("192.168.68.50", 137, "192.168.68.60", 137),
                SystemService::NetBiosNs,
            ),
        ] {
            assert_eq!(
                windows().classify(&key, user),
                SystemVerdict::KeepOwner {
                    service,
                    impersonation: Impersonation::Alert,
                },
                "responder {key:?} must alert"
            );
        }
        // Watch-tier roles: counted, never alerted. NTP joins this tier because
        // source port 123 is also the Windows client default, so a bound port
        // cannot distinguish server impersonation from an ordinary client.
        for (key, service) in [
            (
                udp_key("192.168.68.50", 123, "192.168.68.60", 51_234),
                SystemService::Ntp,
            ),
            (
                udp_key("192.168.68.50", 5353, "224.0.0.251", 5353),
                SystemService::Mdns,
            ),
            (
                udp_key("192.168.68.50", 5355, "224.0.0.252", 5355),
                SystemService::Llmnr,
            ),
            (
                udp_key("192.168.68.50", 1900, "239.255.255.250", 1900),
                SystemService::Ssdp,
            ),
            (
                udp_key("192.168.68.50", 3702, "239.255.255.250", 3702),
                SystemService::WsDiscovery,
            ),
        ] {
            assert_eq!(
                windows().classify(&key, user),
                SystemVerdict::KeepOwner {
                    service,
                    impersonation: Impersonation::Watch,
                },
                "responder {key:?} must watch, not alert"
            );
        }
        // Client shapes with a known owner are ordinary traffic: no signal.
        let client_shapes = [
            dhcp_client_key(),
            udp_key("192.168.68.50", 51_234, "9.9.9.9", 53),
            udp_key("192.168.68.50", 51_234, "224.0.0.251", 5353),
        ];
        for key in client_shapes {
            assert_eq!(
                windows().classify(&key, user),
                SystemVerdict::NoMatch,
                "client {key:?} must stay ordinary traffic"
            );
        }
    }

    #[test]
    fn unresolved_owners_never_fold_or_flag() {
        // The daemon's own PID is excluded by the caller before classifying;
        // anything unresolvable stays on the existing unknown path.
        let key = dhcp_client_key();
        for profile in [windows(), linux(), macos()] {
            assert_eq!(
                profile.classify(&key, OwnerEvidence::Unresolved),
                SystemVerdict::NoMatch
            );
        }
    }

    #[test]
    fn degenerate_ports_never_match() {
        let local_zero = udp_key("192.168.68.50", 0, "9.9.9.9", 123);
        let remote_zero = udp_key("192.168.68.50", 51_234, "9.9.9.9", 0);
        for profile in [windows(), linux(), macos()] {
            stays_unknown(profile, &local_zero);
            stays_unknown(profile, &remote_zero);
        }
    }

    #[test]
    fn impersonation_claims_are_deduplicated() {
        let attributor = SystemAttributor::new();
        let dns = SystemService::SystemDns;
        assert!(attributor.claim_impersonation_alert("/a/evil.exe", "evil.exe", dns));
        assert!(!attributor.claim_impersonation_alert("/a/evil.exe", "evil.exe", dns));
        // A different service is a different claim.
        assert!(attributor.claim_impersonation_alert(
            "/a/evil.exe",
            "evil.exe",
            SystemService::Ntp
        ));
        // A different application is a different claim — including transient
        // store-failure rows, which must never share suppression.
        assert!(attributor.claim_impersonation_alert("/b/evil.exe", "evil.exe", dns));
    }

    #[test]
    fn each_outcome_moves_its_own_counter() {
        let attributor = SystemAttributor::new();
        for outcome in [
            AttributionOutcome::Matched,
            AttributionOutcome::Matched,
            AttributionOutcome::FoldedOwnerless,
            AttributionOutcome::FoldedVerified,
            AttributionOutcome::ImpersonationAlert,
            AttributionOutcome::ImpersonationWatch,
            AttributionOutcome::NoRule,
        ] {
            attributor.note(outcome);
        }
        assert_eq!(
            attributor.stats(),
            SystemAttributionStats {
                matched: 2,
                folded_ownerless: 1,
                folded_verified: 1,
                impersonation_alert: 1,
                impersonation_watch: 1,
                no_rule: 1,
            }
        );
    }

    #[test]
    fn windows_allowlist_matching_ignores_case_on_any_host() {
        let dhcp = dhcp_client_key();
        assert_eq!(
            windows().classify(
                &dhcp,
                OwnerEvidence::Known {
                    path: r"C:\WINDOWS\System32\svchost.exe::DHCP",
                    name: "DHCP (svchost.exe)",
                }
            ),
            SystemVerdict::FoldSystem {
                service: SystemService::DhcpV4Client,
                evidence: FoldEvidence::VerifiedService,
            }
        );
        assert!(windows().allows(
            SystemService::SystemDns,
            r"c:\windows\system32\dns.exe",
            "dns.exe"
        ));
    }
}
