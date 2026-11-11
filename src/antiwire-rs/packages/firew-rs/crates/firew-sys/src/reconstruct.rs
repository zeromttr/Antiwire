//! Helpers for rebuilding logical rules from native rows.

use std::collections::HashSet;
use std::net::IpAddr;

use firew_core::{Action, Direction, Error, ErrorKind, PortRange, Protocol, Rule, RuleKey};
use ipnet::IpNet;

use crate::marker::ManagedMarker;

/// Sorts one key's native rows by part and returns their part count when complete.
///
/// Complete means every row agrees on a non-zero total and the parts run
/// `0..total` with none missing or repeated. `None` means the group is drifted.
pub fn complete_parts<R>(rows: &mut [R], marker: impl Fn(&R) -> &ManagedMarker) -> Option<usize> {
    rows.sort_by_key(|row| marker(row).part);
    let total = rows.first().map_or(0, |row| usize::from(marker(row).total));
    let complete = total != 0
        && total == rows.len()
        && rows.iter().enumerate().all(|(index, row)| {
            let marker = marker(row);
            usize::from(marker.part) == index && usize::from(marker.total) == total
        });
    complete.then_some(total)
}

/// The direction a rule's native rows add up to, or `None` when there are none.
#[must_use]
pub fn merged_direction(directions: impl IntoIterator<Item = Direction>) -> Option<Direction> {
    let (mut inbound, mut outbound) = (false, false);
    for direction in directions {
        match direction {
            Direction::Inbound => inbound = true,
            Direction::Outbound => outbound = true,
            Direction::Both => (inbound, outbound) = (true, true),
        }
    }
    match (inbound, outbound) {
        (true, true) => Some(Direction::Both),
        (true, false) => Some(Direction::Inbound),
        (false, true) => Some(Direction::Outbound),
        (false, false) => None,
    }
}

/// The matchers one parsed native row contributes to its logical rule.
///
/// Implement it with [`impl_native_row!`](crate::impl_native_row) for a row
/// struct that has fields of the same names.
pub trait NativeRow {
    /// Ownership marker naming the row's key and part.
    fn marker(&self) -> &ManagedMarker;
    /// The row's verdict.
    fn action(&self) -> Action;
    /// The direction this row matches.
    fn direction(&self) -> Direction;
    /// The row's protocol.
    fn protocol(&self) -> Protocol;
    /// The remote address this row matches, when it matches one directly.
    fn remote_address(&self) -> Option<IpNet>;
    /// The local address this row matches.
    fn local_address(&self) -> Option<IpNet>;
    /// The remote port range this row matches.
    fn remote_port(&self) -> Option<PortRange>;
    /// The local port range this row matches.
    fn local_port(&self) -> Option<PortRange>;
    /// The named address set this row matches remote addresses against, when
    /// it uses one instead of a direct address.
    fn remote_set(&self) -> Option<&str>;
}

/// Implements [`NativeRow`] for a struct with the fields `marker`, `action`,
/// `direction`, `protocol`, `remote_address`, `local_address`, `remote_port`,
/// and `local_port`, of the types the trait returns, plus the named
/// `Option<String>` field holding the row's remote address set.
#[macro_export]
macro_rules! impl_native_row {
    ($row:ty, remote_set = $set:ident) => {
        impl $crate::NativeRow for $row {
            fn remote_set(&self) -> ::core::option::Option<&str> {
                self.$set.as_deref()
            }
            fn marker(&self) -> &$crate::ManagedMarker {
                &self.marker
            }
            fn action(&self) -> $crate::__private::Action {
                self.action
            }
            fn direction(&self) -> $crate::__private::Direction {
                self.direction
            }
            fn protocol(&self) -> $crate::__private::Protocol {
                self.protocol
            }
            fn remote_address(&self) -> ::core::option::Option<$crate::__private::IpNet> {
                self.remote_address
            }
            fn local_address(&self) -> ::core::option::Option<$crate::__private::IpNet> {
                self.local_address
            }
            fn remote_port(&self) -> ::core::option::Option<$crate::__private::PortRange> {
                self.remote_port
            }
            fn local_port(&self) -> ::core::option::Option<$crate::__private::PortRange> {
                self.local_port
            }
        }
    };
}

/// Rebuilds the logical rule that one key's native rows add up to. The rows
/// end up sorted by part.
///
/// `remote_set` runs once the rows are known to be complete and consistent. It
/// returns the entries of the address set they reference, or `None` when the
/// rows match remote addresses directly; an empty set counts as missing.
///
/// Every row must be a distinct matcher combination. The logical rule is
/// rebuilt from the union of the rows' matchers, so two rows matching the same
/// combination would claim coverage of one that no row matches: rows
/// `(A, 80) (A, 443) (B, 80) (A, 80)` rebuild to `{A, B} x {80, 443}` while
/// `(B, 443)` is not enforced. And there must be as many rows as the rebuilt
/// rule expands to, or a combination is missing.
///
/// # Errors
///
/// [`ErrorKind::CorruptNativeState`] when the parts are incomplete, disagree,
/// repeat a matcher combination, pair addresses of different families, or do
/// not cover the rule's expansion, when the address set is missing or empty,
/// or when the result is not a valid rule. An error from `remote_set` is
/// returned unchanged.
pub fn rebuild_rule<R: NativeRow>(
    key: &RuleKey,
    rows: &mut [R],
    remote_set: impl FnOnce(&[R]) -> Result<Option<Vec<IpNet>>, Error>,
) -> Result<Rule, Error> {
    let corrupt =
        |message: String| Error::new(ErrorKind::CorruptNativeState, message).with_logical_key(key);
    let Some(total) = complete_parts(rows, NativeRow::marker) else {
        return Err(corrupt(
            "native rule parts are duplicate, missing, or inconsistent".to_owned(),
        ));
    };
    let first = &rows[0];
    if rows
        .iter()
        .any(|row| row.action() != first.action() || row.protocol() != first.protocol())
    {
        return Err(corrupt(
            "native rule parts disagree on action or protocol".to_owned(),
        ));
    }
    let Some(direction) = merged_direction(rows.iter().map(NativeRow::direction)) else {
        return Err(corrupt("native rule has no rows".to_owned()));
    };
    let mut combinations = HashSet::with_capacity(rows.len());
    for row in rows.iter() {
        if let (Some(remote), Some(local)) = (row.remote_address(), row.local_address()) {
            if remote.addr().is_ipv4() != local.addr().is_ipv4() {
                return Err(corrupt(
                    "a native rule part pairs addresses of different families".to_owned(),
                ));
            }
        }
        let combination = (
            row.direction(),
            row.remote_address(),
            row.remote_set(),
            row.local_address(),
            row.remote_port(),
            row.local_port(),
        );
        if !combinations.insert(combination) {
            return Err(corrupt(
                "native rule parts repeat a matcher combination".to_owned(),
            ));
        }
    }

    let mut builder =
        Rule::builder(key.as_str(), first.action(), direction).protocol(first.protocol());
    match remote_set(rows)? {
        Some(entries) if entries.is_empty() => {
            return Err(corrupt(
                "the address set behind a managed rule is missing or empty".to_owned(),
            ));
        }
        Some(entries) => builder = builder.remote_address_set(entries),
        None => {
            for net in rows.iter().filter_map(NativeRow::remote_address) {
                builder = builder.remote_address(net);
            }
        }
    }
    for net in rows.iter().filter_map(NativeRow::local_address) {
        builder = builder.local_address(net);
    }
    for port in rows.iter().filter_map(NativeRow::remote_port) {
        builder = builder.remote_port(port);
    }
    for port in rows.iter().filter_map(NativeRow::local_port) {
        builder = builder.local_port(port);
    }
    let rule = builder
        .build()
        .map_err(|error| corrupt(format!("invalid reconstructed rule: {error}")))?;
    if installed_rows(&rule, rows)? != total {
        return Err(corrupt(
            "native rule parts do not cover the rule's matcher expansion".to_owned(),
        ));
    }
    Ok(rule)
}

/// How many rows `rule` installs: its native expansion, written once per
/// address set `rows` reference when no local address already splits them by
/// family (nftables keeps one set per address family).
fn installed_rows<R: NativeRow>(rule: &Rule, rows: &[R]) -> Result<usize, Error> {
    let expansion = rule.native_expansion()?;
    if !rule.local_addresses().is_empty() {
        return Ok(expansion);
    }
    let sets: HashSet<&str> = rows.iter().filter_map(NativeRow::remote_set).collect();
    Ok(expansion.saturating_mul(sets.len().max(1)))
}

/// Parses an address or network from native text, normalized to its network address.
///
/// A bare address becomes a host network (`/32` or `/128`).
#[must_use]
pub fn parse_native_net(text: &str) -> Option<IpNet> {
    text.parse::<IpNet>()
        .ok()
        .or_else(|| text.parse::<IpAddr>().ok().map(IpNet::from))
        .map(|net| net.trunc())
}

#[cfg(test)]
mod tests {
    use firew_core::RuleKey;

    use super::*;

    fn marker(part: u16, total: u16) -> ManagedMarker {
        ManagedMarker {
            key: "k".parse::<RuleKey>().expect("key"),
            part,
            total,
        }
    }

    struct Row {
        marker: ManagedMarker,
        action: Action,
        direction: Direction,
        protocol: Protocol,
        remote_address: Option<IpNet>,
        local_address: Option<IpNet>,
        remote_port: Option<PortRange>,
        local_port: Option<PortRange>,
        remote_set: Option<String>,
    }

    crate::impl_native_row!(Row, remote_set = remote_set);

    fn row(part: u16, total: u16, remote: &str, remote_port: u16) -> Row {
        Row {
            marker: marker(part, total),
            action: Action::Block,
            direction: Direction::Outbound,
            protocol: Protocol::Tcp,
            remote_address: remote.parse().ok(),
            local_address: None,
            remote_port: PortRange::single(remote_port).ok(),
            local_port: None,
            remote_set: None,
        }
    }

    fn rebuild(rows: &mut [Row]) -> Result<Rule, Error> {
        let key = "k".parse::<RuleKey>().expect("key");
        rebuild_rule(&key, rows, |_| Ok(None))
    }

    #[test]
    fn rebuild_rule_accepts_a_complete_expansion() {
        let mut rows = [
            row(0, 4, "192.0.2.1/32", 80),
            row(1, 4, "192.0.2.1/32", 443),
            row(2, 4, "192.0.2.2/32", 80),
            row(3, 4, "192.0.2.2/32", 443),
        ];
        let rule = rebuild(&mut rows).expect("complete");
        assert_eq!(rule.remote_addresses().len(), 2);
        assert_eq!(rule.remote_ports().len(), 2);
    }

    #[test]
    fn rebuild_rule_refuses_a_repeated_combination_that_hides_a_missing_one() {
        // (192.0.2.2, 443) was rewritten into a copy of (192.0.2.1, 80): the
        // union of matchers still reads as the full 2 x 2 rule.
        let mut rows = [
            row(0, 4, "192.0.2.1/32", 80),
            row(1, 4, "192.0.2.1/32", 443),
            row(2, 4, "192.0.2.2/32", 80),
            row(3, 4, "192.0.2.1/32", 80),
        ];
        let error = rebuild(&mut rows).expect_err("duplicate combination");
        assert_eq!(error.kind(), ErrorKind::CorruptNativeState);
    }

    #[test]
    fn rebuild_rule_tells_set_rows_apart_by_set() {
        let set_row = |part: u16, set: &str| Row {
            remote_address: None,
            remote_set: Some(set.to_owned()),
            ..row(part, 2, "", 80)
        };
        let key = "k".parse::<RuleKey>().expect("key");
        let net: IpNet = "192.0.2.0/24".parse().expect("net");
        let mut rows = [set_row(0, "fw_k_v4"), set_row(1, "fw_k_v6")];
        assert!(rebuild_rule(&key, &mut rows, |_| Ok(Some(vec![net]))).is_ok());
        let mut rows = [set_row(0, "fw_k_v4"), set_row(1, "fw_k_v4")];
        assert!(rebuild_rule(&key, &mut rows, |_| Ok(Some(vec![net]))).is_err());
    }

    #[test]
    fn rebuild_rule_refuses_a_part_mixing_address_families() {
        let mut rows = [Row {
            local_address: "2001:db8::1/128".parse().ok(),
            ..row(0, 1, "192.0.2.1/32", 80)
        }];
        assert!(rebuild(&mut rows).is_err());
    }

    #[test]
    fn complete_parts_sorts_and_counts() {
        let mut rows = vec![marker(1, 2), marker(0, 2)];
        assert_eq!(complete_parts(&mut rows, |row| row), Some(2));
        assert_eq!(rows[0].part, 0);
    }

    #[test]
    fn complete_parts_rejects_gaps_repeats_and_disagreement() {
        assert_eq!(complete_parts(&mut [marker(0, 2)], |row| row), None);
        assert_eq!(
            complete_parts(&mut [marker(0, 2), marker(0, 2)], |row| row),
            None
        );
        assert_eq!(
            complete_parts(&mut [marker(0, 2), marker(1, 3)], |row| row),
            None
        );
        assert_eq!(complete_parts(&mut [marker(0, 0)], |row| row), None);
        assert_eq!(complete_parts::<ManagedMarker>(&mut [], |row| row), None);
    }

    #[test]
    fn merged_direction_combines_rows() {
        use Direction::{Both, Inbound, Outbound};
        assert_eq!(merged_direction([Inbound, Outbound]), Some(Both));
        assert_eq!(merged_direction([Inbound, Inbound]), Some(Inbound));
        assert_eq!(merged_direction([Outbound]), Some(Outbound));
        assert_eq!(merged_direction([]), None);
    }

    #[test]
    fn parse_native_net_accepts_addresses_and_networks() {
        assert_eq!(
            parse_native_net("192.0.2.7/24"),
            "192.0.2.0/24".parse().ok()
        );
        assert_eq!(parse_native_net("192.0.2.7"), "192.0.2.7/32".parse().ok());
        assert_eq!(
            parse_native_net("2001:db8::1"),
            "2001:db8::1/128".parse().ok()
        );
        assert_eq!(parse_native_net("nope"), None);
    }
}
