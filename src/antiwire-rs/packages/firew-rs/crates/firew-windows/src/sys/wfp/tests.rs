use firew_core::{Action, RuleKey};
use firew_sys::{ManagedMarker, ManagedNamespace};
use windows::Win32::NetworkManagement::WindowsFilteringPlatform::{
    FWP_ACTION_BLOCK, FWP_ACTION_PERMIT, FWP_BYTE_BLOB_TYPE, FWP_MATCH_EQUAL, FWP_MATCH_RANGE,
    FWP_RANGE_TYPE, FWP_UINT16, FWP_UINT8, FWP_V4_ADDR_MASK,
};

use super::conditions::{match_type_for, FilterShape, ListedCondition};
use super::listing::{group_filters, ListedFilter};
use super::*;

/// No application in these tests has an id.
fn no_app_id(_: &std::path::Path) -> Option<Vec<u8>> {
    None
}

/// The shape `rule` installs as `part`.
fn shape_of(rule: &Rule, part: usize) -> FilterShape {
    expected_filter_shape(rule, part, Vec::new()).expect("part exists")
}

fn marker_name(namespace: &ManagedNamespace, key: &str, part: u16, total: u16) -> String {
    ManagedMarker {
        key: RuleKey::try_from(key).expect("key"),
        part,
        total,
    }
    .encode(namespace)
    .expect("marker")
}

#[test]
fn icmp_protocols_select_only_their_matching_ip_family_layer() {
    assert_eq!(layers_for_empty_remote(Protocol::IcmpV4), &[false]);
    assert_eq!(layers_for_empty_remote(Protocol::IcmpV6), &[true]);
    assert_eq!(layers_for_empty_remote(Protocol::Tcp), &[false, true]);
}

#[test]
fn grouping_keeps_complete_rules_and_quarantines_the_rest() {
    let namespace = ManagedNamespace::derive("wfp-test", "app");
    // Bidirectional, so each rule installs the two filters the markers name.
    let rule = |key: &str| {
        Rule::builder(key, Action::Block, Direction::Both)
            .remote_address("192.0.2.1/32".parse().expect("net"))
            .build()
            .expect("rule")
    };
    let named = |key: &str, part: u16, total: u16, id: u64| ListedFilter {
        filter_id: id,
        name: marker_name(&namespace, key, part, total),
        rule: Some(rule(key)),
        shape: shape_of(&rule(key), usize::from(part)),
    };
    let listed = vec![
        named("whole", 1, 2, 11),
        named("whole", 0, 2, 10),
        named("half", 0, 2, 20),
        ListedFilter {
            filter_id: 30,
            name: "renamed by hand".to_owned(),
            rule: None,
            shape: FilterShape::new(windows_core::GUID::zeroed(), FWP_ACTION_BLOCK, Vec::new()),
        },
    ];

    let state = group_filters(listed, &namespace, no_app_id);

    let whole = RuleKey::try_from("whole").expect("key");
    let half = RuleKey::try_from("half").expect("key");
    assert_eq!(state.rules.get(&whole), Some(&rule("whole")));
    assert_eq!(state.filter_ids.get(&whole), Some(&vec![10, 11]));
    assert_eq!(state.orphan_ids.get(&half), Some(&vec![20]));
    assert_eq!(state.unkeyed_orphan_ids, vec![30]);
    assert!(!state.rules.contains_key(&half));
}

#[test]
fn port_ranges_use_the_range_match_and_everything_else_equality() {
    assert_eq!(match_type_for(FWP_RANGE_TYPE), FWP_MATCH_RANGE);
    for value_type in [FWP_UINT16, FWP_UINT8, FWP_V4_ADDR_MASK, FWP_BYTE_BLOB_TYPE] {
        assert_eq!(match_type_for(value_type), FWP_MATCH_EQUAL);
    }
}

fn tcp_https_block(direction: Direction) -> Rule {
    Rule::builder("shaped", Action::Block, direction)
        .protocol(Protocol::Tcp)
        .remote_address("192.0.2.1/32".parse().expect("net"))
        .remote_port(firew_core::PortRange::single(443).expect("port"))
        .build()
        .expect("rule")
}

/// Groups one filter per part of `rule`, the part `edited` given `shape`.
fn group_with_edited_part(rule: &Rule, edited: usize, shape: &FilterShape) -> bool {
    let namespace = ManagedNamespace::derive("wfp-test", "app");
    let total = filter_slots(rule).len();
    let listed = (0..total)
        .map(|part| ListedFilter {
            filter_id: 100 + u64::try_from(part).expect("id"),
            name: marker_name(
                &namespace,
                "shaped",
                u16::try_from(part).expect("part"),
                u16::try_from(total).expect("total"),
            ),
            rule: Some(rule.clone()),
            shape: if part == edited {
                shape.clone()
            } else {
                shape_of(rule, part)
            },
        })
        .collect();
    let state = group_filters(listed, &namespace, no_app_id);
    state
        .rules
        .contains_key(&RuleKey::try_from("shaped").expect("key"))
}

/// `shape` with its conditions passed through `edit`.
fn edited(shape: &FilterShape, edit: impl FnOnce(&mut Vec<ListedCondition>)) -> FilterShape {
    let mut conditions = shape.conditions.clone();
    edit(&mut conditions);
    FilterShape::new(shape.layer, shape.action, conditions)
}

#[test]
fn filters_with_their_installed_shape_group_into_the_rule() {
    let rule = tcp_https_block(Direction::Both);
    assert_eq!(filter_slots(&rule).len(), 2);
    assert!(group_with_edited_part(&rule, 0, &shape_of(&rule, 0)));
}

#[test]
fn a_filter_whose_conditions_were_edited_is_not_trusted_by_name() {
    let rule = tcp_https_block(Direction::Outbound);
    let installed = shape_of(&rule, 0);

    // The remote port condition was removed: the filter now blocks every port.
    let widened = edited(&installed, |conditions| {
        conditions.retain(|condition| !matches!(condition, ListedCondition::RemotePort(_)));
    });
    assert!(!group_with_edited_part(&rule, 0, &widened));

    // Another remote address.
    let moved = edited(&installed, |conditions| {
        for condition in conditions {
            if let ListedCondition::RemoteV4 { addr, .. } = condition {
                *addr = 0xC000_0263;
            }
        }
    });
    assert!(!group_with_edited_part(&rule, 0, &moved));

    // An extra condition the backend never writes.
    let narrowed = edited(&installed, |conditions| {
        conditions.push(ListedCondition::Foreign);
    });
    assert!(!group_with_edited_part(&rule, 0, &narrowed));
}

#[test]
fn a_filter_moved_to_another_layer_or_action_is_not_trusted_by_name() {
    let rule = tcp_https_block(Direction::Both);
    let outbound = shape_of(&rule, 0);
    let inbound = shape_of(&rule, 1);
    assert_ne!(outbound.layer, inbound.layer);

    // Both filters on the outbound layer: inbound traffic is not filtered.
    assert!(!group_with_edited_part(&rule, 1, &outbound));
    let permitted = FilterShape {
        action: FWP_ACTION_PERMIT,
        ..outbound
    };
    assert!(!group_with_edited_part(&rule, 0, &permitted));
}

#[test]
fn an_application_id_that_cannot_be_computed_matches_any_id_bytes() {
    let rule = Rule::builder("shaped", Action::Block, Direction::Outbound)
        .application_path(r"C:\missing\app.exe")
        .build()
        .expect("rule");
    let installed = expected_filter_shape(&rule, 0, b"\\device\\x".to_vec()).expect("shape");
    assert!(group_with_edited_part(&rule, 0, &installed));
}
