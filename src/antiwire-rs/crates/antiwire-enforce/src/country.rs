//! Splitting a country's networks across native firewall rules.
//!
//! Backends that can hold many addresses in one native object (a Windows
//! `RemoteAddresses` string, an nftables set, a pf table, an ipset) report a
//! ceiling; those that emit one native row per address report none. Either way
//! the address list is divided here so the rest of enforcement does not care
//! which kind of backend it is talking to.

use firew_rs::MAX_MATCHERS_PER_FIELD;
use ipnet::IpNet;

/// What the active backend can hold in one native object.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct BackendCaps {
    /// `None` when the backend cannot represent an address set natively.
    pub(crate) max_address_set_entries: Option<usize>,
    /// True when the backend refuses every rule with an IPv6 address, as iptables does.
    pub(crate) ipv4_only: bool,
}

impl BackendCaps {
    /// The addresses of a block Antiwire builds itself that this backend can hold: all of
    /// them, or only the IPv4 ones on a backend with no IPv6 rules.
    ///
    /// Such a block, on public `DoH` resolvers or on a country, names addresses of both
    /// families. Passed whole to an IPv4-only backend it was refused whole, which left the
    /// IPv4 addresses open too. What is left out is logged, because traffic to it over IPv6
    /// is not blocked. A rule the user writes for an IPv6 address is not handled here: it is
    /// refused, and the user is told.
    pub(crate) fn enforceable<T: Clone>(
        self,
        block: &str,
        addresses: &[T],
        is_ipv6: impl Fn(&T) -> bool,
    ) -> Vec<T> {
        if !self.ipv4_only {
            return addresses.to_vec();
        }
        let kept: Vec<T> = addresses
            .iter()
            .filter(|address| !is_ipv6(address))
            .cloned()
            .collect();
        let left_out = addresses.len() - kept.len();
        if left_out > 0 {
            tracing::warn!(
                block,
                left_out,
                "this firewall backend has no IPv6 rules; the block covers IPv4 only"
            );
        }
        kept
    }

    /// Whether rules should be built in address-set mode.
    #[must_use]
    pub(crate) fn supports_sets(self) -> bool {
        self.max_address_set_entries.is_some()
    }

    /// Networks per native rule.
    ///
    /// Without set support this is the portable per-field matcher cap, which
    /// also keeps the native marker's part counter well inside its limit.
    #[must_use]
    pub(crate) fn chunk_size(self) -> usize {
        self.max_address_set_entries
            .unwrap_or(MAX_MATCHERS_PER_FIELD)
            .max(1)
    }
}

/// Divides `networks` into per-rule chunks.
///
/// Returns an empty vector for an empty list: a rule with no matchers is
/// invalid, so there is nothing to install.
#[must_use]
pub(crate) fn plan_country_chunks(networks: &[IpNet], caps: BackendCaps) -> Vec<&[IpNet]> {
    networks.chunks(caps.chunk_size()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn caps(limit: Option<usize>) -> BackendCaps {
        BackendCaps {
            max_address_set_entries: limit,
            ipv4_only: false,
        }
    }

    #[test]
    fn an_ipv4_only_backend_is_given_the_ipv4_addresses_of_a_block() {
        let both = ["192.0.2.1", "2001:db8::1", "198.51.100.7"];
        let is_ipv6 = |address: &&str| address.contains(':');
        assert_eq!(caps(None).enforceable("test", &both, is_ipv6), both);
        let ipv4_only = BackendCaps {
            ipv4_only: true,
            ..caps(None)
        };
        assert_eq!(
            ipv4_only.enforceable("test", &both, is_ipv6),
            ["192.0.2.1", "198.51.100.7"]
        );
    }

    fn nets(count: usize) -> Vec<IpNet> {
        (0..count)
            .map(|index| {
                let octets = u32::try_from(index).expect("index").to_be_bytes();
                IpNet::new(
                    std::net::Ipv4Addr::new(10, octets[1], octets[2], octets[3]).into(),
                    32,
                )
                .expect("net")
            })
            .collect()
    }

    #[test]
    fn an_empty_list_installs_nothing() {
        assert_eq!(plan_country_chunks(&[], caps(None)), [] as [&[IpNet]; 0]);
        assert_eq!(
            plan_country_chunks(&[], caps(Some(2_000))),
            [] as [&[IpNet]; 0]
        );
    }

    #[test]
    fn a_set_capable_backend_holds_the_whole_country_in_one_rule() {
        let networks = nets(29_319);
        let chunks = plan_country_chunks(&networks, caps(Some(65_536)));
        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0].len(), 29_319);
    }

    #[test]
    fn a_limited_ceiling_splits_into_the_fewest_rules() {
        let networks = nets(29_319);
        let chunks = plan_country_chunks(&networks, caps(Some(2_000)));
        assert_eq!(chunks.len(), 15);
        assert_eq!(chunks.iter().map(|c| c.len()).sum::<usize>(), 29_319);
    }

    #[test]
    fn a_backend_without_sets_falls_back_to_the_matcher_cap() {
        let networks = nets(200);
        let chunks = plan_country_chunks(&networks, caps(None));
        assert_eq!(caps(None).chunk_size(), MAX_MATCHERS_PER_FIELD);
        assert_eq!(chunks.len(), 200_usize.div_ceil(MAX_MATCHERS_PER_FIELD));
    }

    #[test]
    fn boundary_sizes_do_not_emit_an_empty_trailing_chunk() {
        for count in [1, 63, 64, 65, 128] {
            let networks = nets(count);
            let chunks = plan_country_chunks(&networks, caps(None));
            assert!(chunks.iter().all(|chunk| !chunk.is_empty()));
            assert_eq!(chunks.iter().map(|c| c.len()).sum::<usize>(), count);
        }
    }

    #[test]
    fn chunking_stays_within_the_native_marker_part_budget() {
        // pf and nftables encode `part`/`total` into an ownership marker capped
        // at 1295 parts, and a bidirectional rule doubles the row count.
        assert!(caps(None).chunk_size() * 2 <= 1295);
    }
}
