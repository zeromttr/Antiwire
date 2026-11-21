//! Which network addresses a client may connect to.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// The addresses a client is allowed to reach.
///
/// Link-local addresses (including every cloud metadata service), unspecified,
/// multicast, broadcast, documentation, local-use NAT64, deprecated tunneling,
/// and other non-global reserved ranges are refused under every policy. The
/// policies differ only in how far into the local network a request may go.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Destinations {
    /// Globally routable addresses only. For servers on the internet: registries,
    /// download mirrors, APIs.
    Public,
    /// Public addresses plus private networks (RFC 1918, carrier-grade NAT,
    /// unique local IPv6). For servers a user may run on their own network.
    PublicAndPrivate,
    /// Public and private addresses plus loopback. For a collector that may run
    /// on this machine, and for local test servers.
    PublicPrivateAndLoopback,
}

/// Where an address leads, for deciding whether a policy allows it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AddressClass {
    Public,
    Private,
    Loopback,
    Forbidden,
}

impl Destinations {
    /// Whether this policy allows connecting to `ip`.
    #[must_use]
    pub fn allows(self, ip: IpAddr) -> bool {
        match classify(ip) {
            AddressClass::Public => true,
            AddressClass::Private => matches!(
                self,
                Self::PublicAndPrivate | Self::PublicPrivateAndLoopback
            ),
            AddressClass::Loopback => self == Self::PublicPrivateAndLoopback,
            AddressClass::Forbidden => false,
        }
    }

    /// Narrows this policy after a request reaches an address in `reached`, so
    /// a redirect cannot pivot from a wider zone into a more local one
    /// (`Public` -> `Private`, or `Private` -> `Loopback`).
    #[must_use]
    pub(crate) const fn narrow(self, reached: AddressClass) -> Self {
        match (self, reached) {
            (_, AddressClass::Public | AddressClass::Forbidden) | (Self::Public, _) => Self::Public,
            (Self::PublicAndPrivate | Self::PublicPrivateAndLoopback, AddressClass::Private)
            | (Self::PublicAndPrivate, AddressClass::Loopback) => Self::PublicAndPrivate,
            (Self::PublicPrivateAndLoopback, AddressClass::Loopback) => {
                Self::PublicPrivateAndLoopback
            }
        }
    }
}

/// Classifies `ip`, looking through IPv6 forms that legitimately deliver to an
/// IPv4 address (`::ffff:a.b.c.d` and well-known NAT64 `64:ff9b::/96`).
pub(crate) fn classify(ip: IpAddr) -> AddressClass {
    match ip {
        IpAddr::V4(v4) => classify_v4(v4),
        IpAddr::V6(v6) => embedded_v4(v6).map_or_else(|| classify_v6(v6), classify_v4),
    }
}

fn classify_v4(ip: Ipv4Addr) -> AddressClass {
    let [a, b, c, _] = ip.octets();
    if ip.is_loopback() {
        return AddressClass::Loopback;
    }
    let forbidden = a == 0                                  // 0.0.0.0/8 "this network"
        || ip.is_link_local()                               // 169.254.0.0/16, incl. cloud metadata
        || ip.is_multicast()                                // 224.0.0.0/4
        || ip.is_broadcast()                                // 255.255.255.255
        || a >= 240                                         // 240.0.0.0/4 reserved
        || (a, b, c) == (192, 0, 0)                         // IETF assignments, incl. Oracle metadata
        || (a, b, c) == (192, 0, 2)                         // TEST-NET-1 documentation
        || (a, b, c) == (192, 88, 99)                       // deprecated 6to4 relay anycast (RFC 7526)
        || (a, b, c) == (198, 51, 100)                      // TEST-NET-2 documentation
        || (a, b, c) == (203, 0, 113)                       // TEST-NET-3 documentation
        || (a == 198 && (b & 0xfe) == 18)                   // 198.18.0.0/15 benchmarking
        || ip == Ipv4Addr::new(100, 100, 100, 200)          // Alibaba Cloud metadata
        || ip == Ipv4Addr::new(168, 63, 129, 16); // Azure WireServer platform VIP
    if forbidden {
        return AddressClass::Forbidden;
    }
    if ip.is_private() || (a == 100 && (b & 0xc0) == 64) {
        // RFC 1918, and 100.64.0.0/10 carrier-grade NAT (also Tailscale and similar).
        return AddressClass::Private;
    }
    AddressClass::Public
}

/// Cloud metadata endpoints that sit inside unique local space (`fc00::/7`),
/// where a policy allowing private addresses would otherwise reach them.
const ULA_METADATA: [Ipv6Addr; 2] = [
    // AWS Instance Metadata Service.
    Ipv6Addr::new(0xfd00, 0x0ec2, 0, 0, 0, 0, 0, 0x0254),
    // Google Compute Engine metadata server, on IPv6-only instances.
    Ipv6Addr::new(0xfd20, 0x00ce, 0, 0, 0, 0, 0, 0x0254),
];

fn classify_v6(ip: Ipv6Addr) -> AddressClass {
    let segments = ip.segments();
    if ip.is_loopback() {
        return AddressClass::Loopback;
    }
    if ULA_METADATA.contains(&ip) {
        return AddressClass::Forbidden;
    }
    if (segments[0] & 0xfe00) == 0xfc00 || (segments[0] & 0xffc0) == 0xfec0 {
        // Unique local (fc00::/7) and the deprecated site-local range (fec0::/10).
        return AddressClass::Private;
    }
    // Only IANA Global Unicast space (2000::/3) can be public, minus reserved
    // and non-globally-routable sub-blocks. Everything outside 2000::/3 (link-local,
    // multicast, unspecified, discard, SRv6 5f00::/16, local-use NAT64
    // 64:ff9b:1::/48, deprecated IPv4-compatible/SIIT, and unallocated space)
    // is forbidden.
    let is_global_unicast = (segments[0] & 0xe000) == 0x2000;
    let special_in_gua = (segments[0] == 0x2001
        && (segments[1] < 0x0200 || segments[1] == 0x0db8)) // 2001::/23 (Teredo, benchmarking, ORCHID, DRIP) & 2001:db8::/32
        || segments[0] == 0x2002                            // 2002::/16 deprecated 6to4
        || (segments[0] == 0x3fff && segments[1] < 0x1000); // 3fff::/20 documentation (RFC 9637)
    if is_global_unicast && !special_in_gua {
        return AddressClass::Public;
    }
    AddressClass::Forbidden
}

/// The IPv4 address an IPv6 address delivers to, for the fixed-layout forms
/// used on dual-stack sockets and well-known DNS64/NAT64 networks.
///
/// Local-use NAT64 (`64:ff9b:1::/48`, RFC 8215) is deliberately excluded: its
/// prefix length may be `/48`, `/56`, `/64`, or `/96` (RFC 6052), so assuming
/// `/96` would misclassify non-`/96` encodings of local IPv4 addresses, and the
/// prefix itself is never globally routable. Deprecated tunneling/translation
/// forms (IPv4-compatible `::/96`, SIIT `::ffff:0:0:0/96`, Teredo `2001::/32`,
/// 6to4 `2002::/16`) are likewise refused by [`classify_v6`].
fn embedded_v4(ip: Ipv6Addr) -> Option<Ipv4Addr> {
    if let Some(v4) = ip.to_ipv4_mapped() {
        return Some(v4);
    }
    let segments = ip.segments();
    // NAT64 well-known prefix 64:ff9b::/96 (RFC 6052 §2.1): fixed /96 layout.
    if segments[..6] == [0x0064, 0xff9b, 0, 0, 0, 0] {
        return Some(Ipv4Addr::from(
            (u32::from(segments[6]) << 16) | u32::from(segments[7]),
        ));
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(text: &str) -> IpAddr {
        text.parse().expect("ip")
    }

    #[test]
    fn classifies_ipv4() {
        for (address, class) in [
            ("8.8.8.8", AddressClass::Public),
            ("1.1.1.1", AddressClass::Public),
            ("10.0.0.5", AddressClass::Private),
            ("172.16.4.1", AddressClass::Private),
            ("192.168.1.10", AddressClass::Private),
            ("100.64.0.1", AddressClass::Private),
            ("127.0.0.1", AddressClass::Loopback),
            ("127.8.9.10", AddressClass::Loopback),
            ("169.254.169.254", AddressClass::Forbidden),
            ("100.100.100.200", AddressClass::Forbidden),
            ("168.63.129.16", AddressClass::Forbidden),
            ("192.0.0.192", AddressClass::Forbidden),
            ("192.88.99.1", AddressClass::Forbidden),
            ("0.0.0.0", AddressClass::Forbidden),
            ("224.0.0.1", AddressClass::Forbidden),
            ("255.255.255.255", AddressClass::Forbidden),
            ("198.18.0.1", AddressClass::Forbidden),
            ("203.0.113.9", AddressClass::Forbidden),
        ] {
            assert_eq!(classify(ip(address)), class, "{address}");
        }
    }

    #[test]
    fn classifies_ipv6() {
        for (address, class) in [
            ("2606:4700:4700::1111", AddressClass::Public),
            ("2001:4860:4860::8888", AddressClass::Public),
            ("2001:200::1", AddressClass::Public),
            ("3fff:1000::1", AddressClass::Public),
            ("::1", AddressClass::Loopback),
            ("fd12:3456::1", AddressClass::Private),
            ("fec0::1", AddressClass::Private),
            ("fe80::1", AddressClass::Forbidden),
            ("fe00::1", AddressClass::Forbidden),
            ("::", AddressClass::Forbidden),
            ("ff02::1", AddressClass::Forbidden),
            ("100::1", AddressClass::Forbidden),
            ("100:0:0:1::1", AddressClass::Forbidden),
            ("2001:db8::1", AddressClass::Forbidden),
            ("2001:2::1", AddressClass::Forbidden),
            ("2001:10::1", AddressClass::Forbidden),
            ("2001:20::1", AddressClass::Forbidden),
            ("2001:30::1", AddressClass::Forbidden),
            ("3fff::1", AddressClass::Forbidden),
            ("3fff:0fff::1", AddressClass::Forbidden),
            ("5f00::1", AddressClass::Forbidden),
            ("4000::1", AddressClass::Forbidden),
            ("8000::1", AddressClass::Forbidden),
            ("fd00:ec2::254", AddressClass::Forbidden),
            ("fd20:ce::254", AddressClass::Forbidden),
            ("fd20:ce::253", AddressClass::Private),
        ] {
            assert_eq!(classify(ip(address)), class, "{address}");
        }
    }

    /// Dual-stack IPv4-mapped and well-known NAT64 addresses are classified as
    /// the IPv4 address they reach; local-use NAT64 (`64:ff9b:1::/48`) and
    /// deprecated tunneling/translation prefixes are always forbidden.
    #[test]
    fn ipv6_forms_of_ipv4_and_transition_prefixes() {
        for (address, class) in [
            ("::ffff:127.0.0.1", AddressClass::Loopback),
            ("::ffff:169.254.169.254", AddressClass::Forbidden),
            ("::ffff:168.63.129.16", AddressClass::Forbidden),
            ("::ffff:10.0.0.1", AddressClass::Private),
            ("::ffff:8.8.8.8", AddressClass::Public),
            ("64:ff9b::7f00:1", AddressClass::Loopback),
            ("64:ff9b::a9fe:a9fe", AddressClass::Forbidden),
            ("64:ff9b::a00:1", AddressClass::Private),
            ("64:ff9b::808:808", AddressClass::Public),
            // Local-use NAT64 (RFC 8215), including RFC 6052 /64 zero-suffix
            // 127.0.0.1 and /48 169.254.169.254 with a public-looking suffix.
            ("64:ff9b:1::808:808", AddressClass::Forbidden),
            ("64:ff9b:1::a9fe:a9fe", AddressClass::Forbidden),
            ("64:ff9b:1::7f:0:100:0", AddressClass::Forbidden),
            ("64:ff9b:1::a:0:100:0", AddressClass::Forbidden),
            ("64:ff9b:1:a9fe:a9:fe00:808:808", AddressClass::Forbidden),
            ("64:ff9b:2::808:808", AddressClass::Forbidden),
            // Deprecated IPv4-compatible, SIIT, 6to4, and Teredo (including
            // Teredo carrying a metadata server IPv4 with a public client IPv4).
            ("::169.254.169.254", AddressClass::Forbidden),
            ("::8.8.8.8", AddressClass::Forbidden),
            ("::ffff:0:7f00:1", AddressClass::Forbidden),
            ("::ffff:0:808:808", AddressClass::Forbidden),
            ("2002:7f00:1::", AddressClass::Forbidden),
            ("2002:0808:0808::1", AddressClass::Forbidden),
            (
                "2001:0:4136:e378:8000:63bf:80ff:fffe",
                AddressClass::Forbidden,
            ),
            (
                "2001:0:4136:e378:8000:63bf:f7f7:f7f7",
                AddressClass::Forbidden,
            ),
            ("2001:0:a9fe:a9fe:0:0:f7f7:f7f7", AddressClass::Forbidden),
        ] {
            assert_eq!(classify(ip(address)), class, "{address}");
        }
    }

    #[test]
    fn policies_widen_one_step_at_a_time() {
        let public = ip("8.8.8.8");
        let private = ip("192.168.1.1");
        let loopback = ip("127.0.0.1");
        let metadata = ip("169.254.169.254");
        let wire_server = ip("168.63.129.16");
        let gce_metadata_v6 = ip("fd20:ce::254");

        assert!(Destinations::Public.allows(public));
        assert!(!Destinations::Public.allows(private));
        assert!(!Destinations::Public.allows(loopback));

        assert!(Destinations::PublicAndPrivate.allows(private));
        assert!(!Destinations::PublicAndPrivate.allows(loopback));

        assert!(Destinations::PublicPrivateAndLoopback.allows(loopback));
        for policy in [
            Destinations::Public,
            Destinations::PublicAndPrivate,
            Destinations::PublicPrivateAndLoopback,
        ] {
            assert!(!policy.allows(metadata), "{policy:?}");
            assert!(!policy.allows(wire_server), "{policy:?}");
            assert!(!policy.allows(gce_metadata_v6), "{policy:?}");
        }
    }

    #[test]
    fn narrowing_prevents_pivoting_into_more_local_zones() {
        assert_eq!(
            Destinations::Public.narrow(AddressClass::Public),
            Destinations::Public
        );
        assert_eq!(
            Destinations::PublicAndPrivate.narrow(AddressClass::Public),
            Destinations::Public
        );
        assert_eq!(
            Destinations::PublicAndPrivate.narrow(AddressClass::Private),
            Destinations::PublicAndPrivate
        );
        assert_eq!(
            Destinations::PublicPrivateAndLoopback.narrow(AddressClass::Public),
            Destinations::Public
        );
        assert_eq!(
            Destinations::PublicPrivateAndLoopback.narrow(AddressClass::Private),
            Destinations::PublicAndPrivate
        );
        assert_eq!(
            Destinations::PublicPrivateAndLoopback.narrow(AddressClass::Loopback),
            Destinations::PublicPrivateAndLoopback
        );
        assert_eq!(
            Destinations::PublicPrivateAndLoopback.narrow(AddressClass::Forbidden),
            Destinations::Public
        );
    }
}
