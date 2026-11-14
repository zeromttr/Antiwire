//! Which network addresses a client may connect to.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// The addresses a client is allowed to reach.
///
/// Link-local addresses (including every cloud metadata service), unspecified,
/// multicast, broadcast, documentation and other reserved ranges are refused
/// under every policy. The policies differ only in how far into the local
/// network a request may go.
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
}

/// Classifies `ip`, looking through IPv6 forms that carry an IPv4 address.
///
/// An IPv4-mapped (`::ffff:a.b.c.d`), IPv4-translated (`::ffff:0:a.b.c.d`),
/// IPv4-compatible (`::a.b.c.d`), NAT64 (`64:ff9b::/96`, `64:ff9b:1::/48`),
/// 6to4 (`2002::/16`) or Teredo (`2001::/32`) address reaches the IPv4 address
/// it embeds, so it is classified as that address. Otherwise
/// `::ffff:127.0.0.1` would pass as a public IPv6 address.
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
    let forbidden = a == 0                                  // "this network"
        || ip.is_link_local()                               // 169.254/16, incl. cloud metadata
        || ip.is_multicast()
        || ip.is_broadcast()
        || a >= 240                                         // reserved
        || (a, b, c) == (192, 0, 0)                         // IETF assignments, incl. Oracle metadata
        || (a, b, c) == (192, 0, 2)                         // documentation
        || (a, b, c) == (198, 51, 100)
        || (a, b, c) == (203, 0, 113)
        || (a == 198 && (b & 0xfe) == 18)                   // 198.18/15 benchmarking
        || ip == Ipv4Addr::new(100, 100, 100, 200); //         Alibaba Cloud metadata
    if forbidden {
        return AddressClass::Forbidden;
    }
    if ip.is_private() || (a == 100 && (b & 0xc0) == 64) {
        // RFC 1918, and 100.64/10 carrier-grade NAT (also Tailscale and similar).
        return AddressClass::Private;
    }
    AddressClass::Public
}

fn classify_v6(ip: Ipv6Addr) -> AddressClass {
    let segments = ip.segments();
    if ip.is_loopback() {
        return AddressClass::Loopback;
    }
    let forbidden = ip.is_unspecified()
        || ip.is_multicast()
        || (segments[0] & 0xffc0) == 0xfe80                  // link-local
        || (segments[0], segments[1]) == (0x2001, 0x0db8)   // documentation
        || (segments[0], segments[1], segments[2]) == (0x2001, 0x0002, 0) // benchmarking
        || (segments[0] == 0x0100 && segments[1..4] == [0, 0, 0]) // discard-only
        || ip == Ipv6Addr::new(0xfd00, 0x0ec2, 0, 0, 0, 0, 0, 0x0254); // AWS metadata
    if forbidden {
        return AddressClass::Forbidden;
    }
    if (segments[0] & 0xfe00) == 0xfc00 || (segments[0] & 0xffc0) == 0xfec0 {
        // Unique local, and the deprecated site-local range.
        return AddressClass::Private;
    }
    AddressClass::Public
}

/// The IPv4 address an IPv6 address delivers to, when it embeds one.
fn embedded_v4(ip: Ipv6Addr) -> Option<Ipv4Addr> {
    if let Some(v4) = ip.to_ipv4_mapped() {
        return Some(v4);
    }
    let segments = ip.segments();
    let low = || Ipv4Addr::from((u32::from(segments[6]) << 16) | u32::from(segments[7]));
    // IPv4-compatible (deprecated), excluding :: and ::1, which are not IPv4.
    if segments[..6] == [0, 0, 0, 0, 0, 0] && !ip.is_unspecified() && !ip.is_loopback() {
        return Some(low());
    }
    // IPv4-translated (SIIT): ::ffff:0:a.b.c.d.
    if segments[..6] == [0, 0, 0, 0, 0xffff, 0] {
        return Some(low());
    }
    // NAT64 well-known prefix 64:ff9b::/96, and the local-use 64:ff9b:1::/48,
    // whose prefixes carry the IPv4 address in the last 32 bits as RFC 6052
    // lays out for a /96 translator.
    if segments[..2] == [0x0064, 0xff9b] && (segments[2..6] == [0, 0, 0, 0] || segments[2] == 1) {
        return Some(low());
    }
    // Teredo: 2001:0::/32 carries the client's IPv4 address, bit-inverted, last.
    if segments[..2] == [0x2001, 0x0000] {
        return Some(Ipv4Addr::from(
            !((u32::from(segments[6]) << 16) | u32::from(segments[7])),
        ));
    }
    // 6to4: 2002:AABB:CCDD::/48 carries AA.BB.CC.DD.
    if segments[0] == 0x2002 {
        return Some(Ipv4Addr::from(
            (u32::from(segments[1]) << 16) | u32::from(segments[2]),
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
            ("192.0.0.192", AddressClass::Forbidden),
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
            ("::1", AddressClass::Loopback),
            ("fd12:3456::1", AddressClass::Private),
            ("fe80::1", AddressClass::Forbidden),
            ("::", AddressClass::Forbidden),
            ("ff02::1", AddressClass::Forbidden),
            ("2001:db8::1", AddressClass::Forbidden),
            ("fd00:ec2::254", AddressClass::Forbidden),
        ] {
            assert_eq!(classify(ip(address)), class, "{address}");
        }
    }

    /// The regression this guards: an IPv6 spelling of a local IPv4 address
    /// slipped past checks that only looked at IPv4.
    #[test]
    fn ipv6_forms_of_ipv4_are_classified_as_the_ipv4_address() {
        for (address, class) in [
            ("::ffff:127.0.0.1", AddressClass::Loopback),
            ("::ffff:169.254.169.254", AddressClass::Forbidden),
            ("::ffff:10.0.0.1", AddressClass::Private),
            ("::ffff:8.8.8.8", AddressClass::Public),
            ("::169.254.169.254", AddressClass::Forbidden),
            ("64:ff9b::7f00:1", AddressClass::Loopback),
            ("64:ff9b::a9fe:a9fe", AddressClass::Forbidden),
            ("2002:7f00:1::", AddressClass::Loopback),
            ("2002:0808:0808::1", AddressClass::Public),
            ("::ffff:0:7f00:1", AddressClass::Loopback),
            ("64:ff9b:1::a9fe:a9fe", AddressClass::Forbidden),
            // Teredo with client 127.0.0.1, inverted: 0x80ff:0xfffe.
            (
                "2001:0:4136:e378:8000:63bf:80ff:fffe",
                AddressClass::Loopback,
            ),
            ("2001:0:4136:e378:8000:63bf:f7f7:f7f7", AddressClass::Public),
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
        }
    }
}
