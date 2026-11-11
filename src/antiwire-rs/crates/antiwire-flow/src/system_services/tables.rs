//! The data behind system attribution: the wire signatures every profile
//! shares, each OS's allowlist of service owners, and the profiles built from
//! them.

use netmetrics_core::Protocol;

use super::{
    AddrScope, Impersonation, OwnerKind, ServiceOwner, Signature, SystemProfile, SystemService,
};

const UDP: Option<Protocol> = Some(Protocol::Udp);
const EITHER: Option<Protocol> = None;

/// Wire signatures shared by all three profiles. Matching is first-hit: every
/// server-role entry precedes its client entry, so server-shaped flows never
/// reach the client shape. Client entries therefore leave the server-role
/// fields empty; only server entries signal, and each entry decides the
/// ownerless fold for exactly its own shape.
static SIGNATURES: &[Signature] = &[
    // DHCPv4 server role (e.g. ICS): never folded ownerless, always an alert.
    Signature {
        service: SystemService::DhcpV4Server,
        protocol: UDP,
        local_port: 67,
        remote_port: 0,
        remote_scope: AddrScope::Any,
        fold_ownerless: false,
        ownerless_scope: AddrScope::Any,
        server_role_port: Some(67),
        impersonation: Some(Impersonation::Alert),
    },
    // DHCPv4 client: fixed source port, broadcast discovery or unicast renewal.
    Signature {
        service: SystemService::DhcpV4Client,
        protocol: UDP,
        local_port: 68,
        remote_port: 67,
        remote_scope: AddrScope::Any,
        fold_ownerless: true,
        ownerless_scope: AddrScope::Any,
        server_role_port: None,
        impersonation: None,
    },
    Signature {
        service: SystemService::DhcpV6Server,
        protocol: UDP,
        local_port: 547,
        remote_port: 0,
        remote_scope: AddrScope::Any,
        fold_ownerless: false,
        ownerless_scope: AddrScope::Any,
        server_role_port: Some(547),
        impersonation: Some(Impersonation::Alert),
    },
    Signature {
        service: SystemService::DhcpV6Client,
        protocol: UDP,
        local_port: 546,
        remote_port: 547,
        remote_scope: AddrScope::Any,
        fold_ownerless: true,
        ownerless_scope: AddrScope::Any,
        server_role_port: None,
        impersonation: None,
    },
    // NTP server role. Ownerless folds either way (client and server share the
    // port and cannot be told apart). Counted, not alerted: source port 123 is
    // also the Windows client default, so a bound port cannot distinguish
    // server impersonation from an ordinary client.
    Signature {
        service: SystemService::Ntp,
        protocol: UDP,
        local_port: 123,
        remote_port: 0,
        remote_scope: AddrScope::Any,
        fold_ownerless: true,
        ownerless_scope: AddrScope::Any,
        server_role_port: Some(123),
        impersonation: Some(Impersonation::Watch),
    },
    Signature {
        service: SystemService::Ntp,
        protocol: UDP,
        local_port: 0,
        remote_port: 123,
        remote_scope: AddrScope::Any,
        fold_ownerless: true,
        ownerless_scope: AddrScope::Any,
        server_role_port: None,
        impersonation: None,
    },
    // System DNS server role: ownerless responders stay unknown, because
    // answering DNS without an owner is the takeover shape.
    Signature {
        service: SystemService::SystemDns,
        protocol: EITHER,
        local_port: 53,
        remote_port: 0,
        remote_scope: AddrScope::Any,
        fold_ownerless: false,
        ownerless_scope: AddrScope::Any,
        server_role_port: Some(53),
        impersonation: Some(Impersonation::Alert),
    },
    Signature {
        service: SystemService::SystemDns,
        protocol: EITHER,
        local_port: 0,
        remote_port: 53,
        remote_scope: AddrScope::Any,
        fold_ownerless: true,
        ownerless_scope: AddrScope::Any,
        server_role_port: None,
        impersonation: None,
    },
    // Link-local discovery, server role first: a responder answering from the
    // service port is the same signature family as the query. Watch tier:
    // legitimate desktop listeners exist. Ownerless folds require a
    // multicast/loopback peer even on server entries, so tunneled traffic to
    // unicast stays visible while known rogues answering unicast still signal.
    Signature {
        service: SystemService::Mdns,
        protocol: UDP,
        local_port: 5353,
        remote_port: 0,
        remote_scope: AddrScope::Any,
        fold_ownerless: true,
        ownerless_scope: AddrScope::MulticastOrLoopback,
        server_role_port: Some(5353),
        impersonation: Some(Impersonation::Watch),
    },
    Signature {
        service: SystemService::Mdns,
        protocol: UDP,
        local_port: 0,
        remote_port: 5353,
        remote_scope: AddrScope::MulticastOrLoopback,
        fold_ownerless: true,
        ownerless_scope: AddrScope::MulticastOrLoopback,
        server_role_port: None,
        impersonation: None,
    },
    Signature {
        service: SystemService::Llmnr,
        protocol: UDP,
        local_port: 5355,
        remote_port: 0,
        remote_scope: AddrScope::Any,
        fold_ownerless: true,
        ownerless_scope: AddrScope::MulticastOrLoopback,
        server_role_port: Some(5355),
        impersonation: Some(Impersonation::Watch),
    },
    Signature {
        service: SystemService::Llmnr,
        protocol: UDP,
        local_port: 0,
        remote_port: 5355,
        remote_scope: AddrScope::MulticastOrLoopback,
        fold_ownerless: true,
        ownerless_scope: AddrScope::MulticastOrLoopback,
        server_role_port: None,
        impersonation: None,
    },
    Signature {
        service: SystemService::Ssdp,
        protocol: UDP,
        local_port: 1900,
        remote_port: 0,
        remote_scope: AddrScope::Any,
        fold_ownerless: true,
        ownerless_scope: AddrScope::MulticastOrLoopback,
        server_role_port: Some(1900),
        impersonation: Some(Impersonation::Watch),
    },
    Signature {
        service: SystemService::Ssdp,
        protocol: UDP,
        local_port: 0,
        remote_port: 1900,
        remote_scope: AddrScope::MulticastOrLoopback,
        fold_ownerless: true,
        ownerless_scope: AddrScope::MulticastOrLoopback,
        server_role_port: None,
        impersonation: None,
    },
    Signature {
        service: SystemService::WsDiscovery,
        protocol: UDP,
        local_port: 3702,
        remote_port: 0,
        remote_scope: AddrScope::Any,
        fold_ownerless: true,
        ownerless_scope: AddrScope::MulticastOrLoopback,
        server_role_port: Some(3702),
        impersonation: Some(Impersonation::Watch),
    },
    Signature {
        service: SystemService::WsDiscovery,
        protocol: UDP,
        local_port: 0,
        remote_port: 3702,
        remote_scope: AddrScope::MulticastOrLoopback,
        fold_ownerless: true,
        ownerless_scope: AddrScope::MulticastOrLoopback,
        server_role_port: None,
        impersonation: None,
    },
    // NetBIOS-NS: the Windows stack is kernel-resident, so ownerless folds;
    // a user-mode responder still alerts.
    Signature {
        service: SystemService::NetBiosNs,
        protocol: UDP,
        local_port: 137,
        remote_port: 0,
        remote_scope: AddrScope::Any,
        fold_ownerless: true,
        ownerless_scope: AddrScope::Any,
        server_role_port: Some(137),
        impersonation: Some(Impersonation::Alert),
    },
    Signature {
        service: SystemService::NetBiosNs,
        protocol: UDP,
        local_port: 0,
        remote_port: 137,
        remote_scope: AddrScope::Any,
        fold_ownerless: true,
        ownerless_scope: AddrScope::Any,
        server_role_port: None,
        impersonation: None,
    },
];

#[cfg(any(test, target_os = "windows"))]
static WINDOWS_ALLOWLIST: &[ServiceOwner] = &[
    ServiceOwner {
        service: SystemService::DhcpV4Client,
        kind: OwnerKind::SvchostService("Dhcp"),
    },
    ServiceOwner {
        service: SystemService::DhcpV6Client,
        kind: OwnerKind::SvchostService("Dhcp"),
    },
    ServiceOwner {
        service: SystemService::DhcpV4Server,
        kind: OwnerKind::SvchostService("SharedAccess"),
    },
    ServiceOwner {
        service: SystemService::DhcpV6Server,
        kind: OwnerKind::SvchostService("SharedAccess"),
    },
    ServiceOwner {
        service: SystemService::Ntp,
        kind: OwnerKind::SvchostService("W32Time"),
    },
    ServiceOwner {
        service: SystemService::SystemDns,
        kind: OwnerKind::SvchostService("Dnscache"),
    },
    ServiceOwner {
        service: SystemService::SystemDns,
        kind: OwnerKind::SvchostService("SharedAccess"),
    },
    ServiceOwner {
        service: SystemService::SystemDns,
        kind: OwnerKind::DirBoundName {
            name: "dns.exe",
            dirs: &["C:\\Windows\\System32\\"],
        },
    },
    ServiceOwner {
        service: SystemService::Mdns,
        kind: OwnerKind::SvchostService("Dnscache"),
    },
    ServiceOwner {
        service: SystemService::Mdns,
        kind: OwnerKind::DirBoundName {
            name: "mDNSResponder.exe",
            dirs: &["C:\\Windows\\System32\\", "C:\\Windows\\SysWOW64\\"],
        },
    },
    ServiceOwner {
        service: SystemService::Llmnr,
        kind: OwnerKind::SvchostService("Dnscache"),
    },
    ServiceOwner {
        service: SystemService::Ssdp,
        kind: OwnerKind::SvchostService("SSDPSRV"),
    },
    ServiceOwner {
        service: SystemService::WsDiscovery,
        kind: OwnerKind::SvchostService("fdPHost"),
    },
    ServiceOwner {
        service: SystemService::NetBiosNs,
        kind: OwnerKind::SvchostService("lmhsvc"),
    },
];

#[cfg(any(test, target_os = "linux"))]
static LINUX_ALLOWLIST: &[ServiceOwner] = &[
    ServiceOwner {
        service: SystemService::DhcpV4Client,
        kind: OwnerKind::DirBoundName {
            name: "dhclient",
            dirs: &["/usr/sbin/", "/sbin/"],
        },
    },
    ServiceOwner {
        service: SystemService::DhcpV6Client,
        kind: OwnerKind::DirBoundName {
            name: "dhclient",
            dirs: &["/usr/sbin/", "/sbin/"],
        },
    },
    ServiceOwner {
        service: SystemService::DhcpV4Client,
        kind: OwnerKind::DirBoundName {
            name: "NetworkManager",
            dirs: &["/usr/sbin/"],
        },
    },
    ServiceOwner {
        service: SystemService::DhcpV6Client,
        kind: OwnerKind::DirBoundName {
            name: "NetworkManager",
            dirs: &["/usr/sbin/"],
        },
    },
    ServiceOwner {
        service: SystemService::DhcpV4Client,
        kind: OwnerKind::DirBoundName {
            name: "systemd-networkd",
            dirs: &["/usr/lib/systemd/", "/lib/systemd/"],
        },
    },
    ServiceOwner {
        service: SystemService::DhcpV6Client,
        kind: OwnerKind::DirBoundName {
            name: "systemd-networkd",
            dirs: &["/usr/lib/systemd/", "/lib/systemd/"],
        },
    },
    ServiceOwner {
        service: SystemService::DhcpV4Server,
        kind: OwnerKind::DirBoundName {
            name: "dhcpd",
            dirs: &["/usr/sbin/"],
        },
    },
    ServiceOwner {
        service: SystemService::Ntp,
        kind: OwnerKind::DirBoundName {
            name: "systemd-timesyncd",
            dirs: &["/usr/lib/systemd/", "/lib/systemd/"],
        },
    },
    ServiceOwner {
        service: SystemService::Ntp,
        kind: OwnerKind::DirBoundName {
            name: "chronyd",
            dirs: &["/usr/sbin/"],
        },
    },
    ServiceOwner {
        service: SystemService::Ntp,
        kind: OwnerKind::DirBoundName {
            name: "ntpd",
            dirs: &["/usr/sbin/"],
        },
    },
    ServiceOwner {
        service: SystemService::SystemDns,
        kind: OwnerKind::DirBoundName {
            name: "systemd-resolved",
            dirs: &["/usr/lib/systemd/", "/lib/systemd/"],
        },
    },
    ServiceOwner {
        service: SystemService::Mdns,
        kind: OwnerKind::DirBoundName {
            name: "avahi-daemon",
            dirs: &["/usr/sbin/"],
        },
    },
    ServiceOwner {
        service: SystemService::Llmnr,
        kind: OwnerKind::DirBoundName {
            name: "systemd-resolved",
            dirs: &["/usr/lib/systemd/", "/lib/systemd/"],
        },
    },
    ServiceOwner {
        service: SystemService::NetBiosNs,
        kind: OwnerKind::DirBoundName {
            name: "nmbd",
            dirs: &["/usr/sbin/"],
        },
    },
];

#[cfg(any(test, target_os = "macos"))]
static MACOS_ALLOWLIST: &[ServiceOwner] = &[
    ServiceOwner {
        service: SystemService::DhcpV4Client,
        kind: OwnerKind::DirBoundName {
            name: "configd",
            dirs: &["/usr/libexec/"],
        },
    },
    ServiceOwner {
        service: SystemService::DhcpV6Client,
        kind: OwnerKind::DirBoundName {
            name: "configd",
            dirs: &["/usr/libexec/"],
        },
    },
    ServiceOwner {
        service: SystemService::DhcpV4Server,
        kind: OwnerKind::DirBoundName {
            name: "bootpd",
            dirs: &["/usr/libexec/"],
        },
    },
    ServiceOwner {
        service: SystemService::Ntp,
        kind: OwnerKind::DirBoundName {
            name: "ntpd",
            dirs: &["/usr/sbin/"],
        },
    },
    ServiceOwner {
        service: SystemService::Ntp,
        kind: OwnerKind::DirBoundName {
            name: "timed",
            dirs: &["/usr/libexec/"],
        },
    },
    ServiceOwner {
        service: SystemService::SystemDns,
        kind: OwnerKind::DirBoundName {
            name: "mDNSResponder",
            dirs: &["/usr/sbin/"],
        },
    },
    ServiceOwner {
        service: SystemService::Mdns,
        kind: OwnerKind::DirBoundName {
            name: "mDNSResponder",
            dirs: &["/usr/sbin/"],
        },
    },
    ServiceOwner {
        service: SystemService::NetBiosNs,
        kind: OwnerKind::DirBoundName {
            name: "netbiosd",
            dirs: &["/usr/sbin/"],
        },
    },
];

#[cfg(any(test, target_os = "windows"))]
pub(super) static WINDOWS_PROFILE: SystemProfile = SystemProfile {
    case_insensitive: true,
    signatures: SIGNATURES,
    allowlist: WINDOWS_ALLOWLIST,
};
#[cfg(any(test, target_os = "linux"))]
pub(super) static LINUX_PROFILE: SystemProfile = SystemProfile {
    case_insensitive: false,
    signatures: SIGNATURES,
    allowlist: LINUX_ALLOWLIST,
};
#[cfg(any(test, target_os = "macos"))]
pub(super) static MACOS_PROFILE: SystemProfile = SystemProfile {
    case_insensitive: false,
    signatures: SIGNATURES,
    allowlist: MACOS_ALLOWLIST,
};
#[cfg(any(
    test,
    not(any(target_os = "windows", target_os = "linux", target_os = "macos"))
))]
static EMPTY_ALLOWLIST: &[ServiceOwner] = &[];
/// Fallback for targets without a dedicated profile: signatures still match
/// (wire shapes are OS-agnostic), but nothing verifies, so nothing folds on a
/// verified basis and every non-allowlisted owner keeps its identity.
#[cfg(any(
    test,
    not(any(target_os = "windows", target_os = "linux", target_os = "macos"))
))]
pub(super) static FALLBACK_PROFILE: SystemProfile = SystemProfile {
    case_insensitive: false,
    signatures: SIGNATURES,
    allowlist: EMPTY_ALLOWLIST,
};
