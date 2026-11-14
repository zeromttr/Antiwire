//! Matcher expansion shared by backends that emit one native row per combination.

use firew_core::Rule;
use ipnet::IpNet;

/// Each value as `Some`, or a single `None` meaning "any" when there are none.
#[must_use]
pub fn alternatives<T>(values: &[T]) -> Vec<Option<&T>> {
    if values.is_empty() {
        vec![None]
    } else {
        values.iter().map(Some).collect()
    }
}

/// Every remote/local address pair one native row can match.
///
/// A row cannot mix address families, so pairs with one IPv4 and one IPv6
/// address are left out. An absent side matches either family.
#[must_use]
pub fn address_pairs(rule: &Rule) -> Vec<(Option<&IpNet>, Option<&IpNet>)> {
    family_compatible_pairs(
        &alternatives(rule.remote_addresses()),
        &alternatives(rule.local_addresses()),
    )
}

/// Every pair from `remote` × `local` whose addresses share a family.
#[must_use]
pub fn family_compatible_pairs<'a>(
    remote: &[Option<&'a IpNet>],
    local: &[Option<&'a IpNet>],
) -> Vec<(Option<&'a IpNet>, Option<&'a IpNet>)> {
    remote
        .iter()
        .flat_map(|&r| local.iter().map(move |&l| (r, l)))
        .filter(|(r, l)| match (r, l) {
            (Some(rem), Some(loc)) => rem.addr().is_ipv4() == loc.addr().is_ipv4(),
            _ => true,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alternatives_stand_in_for_an_empty_list() {
        assert_eq!(alternatives::<u8>(&[]), vec![None]);
        assert_eq!(alternatives(&[1, 2]), vec![Some(&1), Some(&2)]);
    }

    #[test]
    fn pairs_skip_mixed_families() {
        let v4: IpNet = "192.0.2.0/24".parse().expect("v4");
        let v6: IpNet = "2001:db8::/32".parse().expect("v6");
        let pairs = family_compatible_pairs(&[Some(&v4), Some(&v6)], &[Some(&v4), None]);
        assert_eq!(
            pairs,
            vec![(Some(&v4), Some(&v4)), (Some(&v4), None), (Some(&v6), None)]
        );
    }
}
