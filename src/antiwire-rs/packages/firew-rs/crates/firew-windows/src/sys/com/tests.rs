use super::decode::parse_address;
use super::*;

fn key() -> RuleKey {
    RuleKey::try_from("test").expect("valid key")
}

#[test]
fn parses_cidr_and_windows_ipv4_subnet_masks() {
    assert_eq!(
        parse_address("203.0.113.7/32", &key()).expect("CIDR"),
        "203.0.113.7/32".parse().expect("network")
    );
    assert_eq!(
        parse_address("203.0.113.7/255.255.255.255", &key()).expect("host mask"),
        "203.0.113.7/32".parse().expect("network")
    );
    assert_eq!(
        parse_address("203.0.113.0/255.255.255.0", &key()).expect("subnet mask"),
        "203.0.113.0/24".parse().expect("network")
    );
}

#[test]
fn parses_windows_ipv6_subnet_masks() {
    assert_eq!(
        parse_address("2001:db8::/ffff:ffff:ffff:ffff:0000:0000:0000:0000", &key())
            .expect("IPv6 mask"),
        "2001:db8::/64".parse().expect("network")
    );
}

#[test]
fn rejects_non_contiguous_and_mismatched_subnet_masks() {
    assert!(
        parse_address("203.0.113.0/255.0.255.0", &key()).is_err(),
        "non-contiguous mask"
    );
    assert!(
        parse_address("203.0.113.0/ffff:ffff::", &key()).is_err(),
        "address family mismatch"
    );
}

#[test]
fn sub_cap_set_rule_crossing_cartesian_expansion_selects_set_mode() {
    assert!(needs_set_mode(false, Direction::Both, 30, 1, 5, 1));
    assert!(needs_set_mode(true, Direction::Outbound, 2, 0, 1, 0));
    assert!(!needs_set_mode(false, Direction::Outbound, 2, 0, 1, 0));
}

#[test]
fn maps_hresults_to_accurate_error_kinds() {
    let k = key();
    let denied = windows_core::Error::from_hresult(E_ACCESSDENIED);
    assert_eq!(
        map_com_mutation_err(&denied, "Rules.Add", &k).kind(),
        ErrorKind::PermissionDenied
    );
    let bound = windows_core::Error::from_hresult(HRESULT_RPC_S_INVALID_BOUND);
    assert_eq!(
        map_com_mutation_err(&bound, "Rules.Add", &k).kind(),
        ErrorKind::LimitExceeded
    );
    let invalid = windows_core::Error::from_hresult(E_INVALIDARG);
    assert_eq!(
        map_com_mutation_err(&invalid, "Rules.Add", &k).kind(),
        ErrorKind::InvalidRule
    );
}
