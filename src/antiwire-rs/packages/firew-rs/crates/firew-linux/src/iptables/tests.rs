use firew_core::{Action, Direction};

use super::parse::parse_address;
use super::*;
use std::cell::RefCell;

#[derive(Default)]
struct MockIptables {
    chains: RefCell<HashMap<String, Vec<String>>>,
}

impl MockIptables {
    fn new_with_parents() -> Self {
        let mock = Self::default();
        mock.chains
            .borrow_mut()
            .insert("INPUT".to_owned(), vec!["-P INPUT ACCEPT".to_owned()]);
        mock.chains
            .borrow_mut()
            .insert("OUTPUT".to_owned(), vec!["-P OUTPUT ACCEPT".to_owned()]);
        mock
    }
}

impl IptablesOps for MockIptables {
    fn chain_exists(&self, _table: &str, chain: &str) -> Result<bool, Error> {
        Ok(self.chains.borrow().contains_key(chain))
    }

    fn new_chain(&self, _table: &str, chain: &str) -> Result<(), Error> {
        self.chains
            .borrow_mut()
            .entry(chain.to_owned())
            .or_insert_with(|| vec![format!("-N {chain}")]);
        Ok(())
    }

    fn list(&self, _table: &str, chain: &str) -> Result<Vec<String>, Error> {
        Ok(self.chains.borrow().get(chain).cloned().unwrap_or_default())
    }

    fn insert(&self, _table: &str, chain: &str, rule: &str, _pos: i32) -> Result<(), Error> {
        self.chains
            .borrow_mut()
            .entry(chain.to_owned())
            .or_default()
            .insert(1, format!("-A {chain} {rule}"));
        Ok(())
    }

    fn append(&self, _table: &str, chain: &str, rule: &str) -> Result<(), Error> {
        self.chains
            .borrow_mut()
            .entry(chain.to_owned())
            .or_default()
            .push(format!("-A {chain} {rule}"));
        Ok(())
    }

    fn delete(&self, _table: &str, chain: &str, rule: &str) -> Result<(), Error> {
        let target = format!("-A {chain} {rule}");
        if let Some(lines) = self.chains.borrow_mut().get_mut(chain) {
            if let Some(pos) = lines.iter().position(|l| l == &target) {
                lines.remove(pos);
                return Ok(());
            }
        }
        Err(Error::new(ErrorKind::RuleNotFound, "rule not found"))
    }

    /// As `iptables -X` does, refuses a chain that still holds a rule.
    fn delete_chain(&self, _table: &str, chain: &str) -> Result<(), Error> {
        let mut chains = self.chains.borrow_mut();
        let holds_rules = chains
            .get(chain)
            .is_some_and(|lines| lines.iter().any(|line| line.starts_with("-A ")));
        if holds_rules {
            return Err(Error::new(ErrorKind::Internal, "chain is not empty"));
        }
        chains.remove(chain);
        Ok(())
    }
}

/// An emptied chain goes, with the jump to it, and comes back with its jump when a rule is
/// to be installed again.
#[test]
fn an_emptied_chain_is_released_and_ensured_again() {
    let ipt = MockIptables::new_with_parents();
    IptablesBackend::ensure_chain_with(&ipt, "FWO_test", "OUTPUT").expect("ensure");
    assert!(ipt.chain_exists("filter", "FWO_test").expect("exists"));

    IptablesBackend::release_chain_with(&ipt, "FWO_test", "OUTPUT");
    assert!(!ipt.chain_exists("filter", "FWO_test").expect("exists"));
    assert_eq!(
        ipt.list("filter", "OUTPUT").expect("list"),
        ["-P OUTPUT ACCEPT"]
    );

    IptablesBackend::ensure_chain_with(&ipt, "FWO_test", "OUTPUT").expect("ensure again");
    assert!(ipt
        .list("filter", "OUTPUT")
        .expect("list")
        .contains(&"-A OUTPUT -j FWO_test".to_owned()));
}

/// A rule someone else added keeps the chain, and the chain keeps its jump: unhooked, it
/// would stop deciding the traffic that rule was written for.
#[test]
fn a_chain_that_still_holds_a_rule_is_not_released() {
    let ipt = MockIptables::new_with_parents();
    IptablesBackend::ensure_chain_with(&ipt, "FWO_test", "OUTPUT").expect("ensure");
    ipt.append("filter", "FWO_test", "-d 192.0.2.1/32 -j DROP")
        .expect("append");

    IptablesBackend::release_chain_with(&ipt, "FWO_test", "OUTPUT");
    assert!(ipt.chain_exists("filter", "FWO_test").expect("exists"));
    assert!(ipt
        .list("filter", "OUTPUT")
        .expect("list")
        .contains(&"-A OUTPUT -j FWO_test".to_owned()));
}

fn test_backend() -> IptablesBackend {
    let config = BackendConfig::new("ipt-test");
    let ns = config.managed_namespace();
    IptablesBackend {
        in_chain: format!("FWI_{}", ns.as_str()),
        out_chain: format!("FWO_{}", ns.as_str()),
        config,
        rules: HashMap::new(),
        broken_records: HashMap::new(),
        orphan_rows: Vec::new(),
        drift: DriftTracker::new(),
        ipset_available: true,
    }
}

#[test]
fn ensure_chain_repairs_missing_parent_jump_and_deduplicates() {
    let mock = MockIptables::new_with_parents();
    let backend = test_backend();

    // Pre-create chain WITHOUT parent jump.
    mock.new_chain("filter", &backend.in_chain)
        .expect("new chain");
    mock.new_chain("filter", &backend.out_chain)
        .expect("new chain");
    assert!(
        !IptablesBackend::chains_attached_with(&mock, &backend.in_chain, &backend.out_chain)
            .expect("check")
    );

    // ensure_chain_with must attach the missing jumps.
    IptablesBackend::ensure_chain_with(&mock, &backend.in_chain, "INPUT").expect("ensure in");
    IptablesBackend::ensure_chain_with(&mock, &backend.out_chain, "OUTPUT").expect("ensure out");
    assert!(
        IptablesBackend::chains_attached_with(&mock, &backend.in_chain, &backend.out_chain)
            .expect("attached")
    );

    // Inject a duplicate jump and verify ensure_chain_with removes the duplicate.
    mock.append("filter", "INPUT", &format!("-j {}", backend.in_chain))
        .expect("dup");
    IptablesBackend::ensure_chain_with(&mock, &backend.in_chain, "INPUT").expect("dedup");
    let input_lines = mock.list("filter", "INPUT").expect("list");
    let jump_line = format!("-A INPUT -j {}", backend.in_chain);
    assert_eq!(input_lines.iter().filter(|l| *l == &jump_line).count(), 1);
}

#[test]
fn set_rule_rows_expand_local_addresses_and_all_ports_and_round_trip() {
    let backend = test_backend();
    let mock = MockIptables::new_with_parents();
    IptablesBackend::ensure_chain_with(&mock, &backend.in_chain, "INPUT").expect("in");
    IptablesBackend::ensure_chain_with(&mock, &backend.out_chain, "OUTPUT").expect("out");

    let nets = vec![
        "198.51.100.1/32".parse::<ipnet::IpNet>().expect("net"),
        "203.0.113.0/24".parse::<ipnet::IpNet>().expect("net"),
    ];
    let rule = Rule::builder("set-ipt", Action::Block, Direction::Both)
        .protocol(Protocol::Tcp)
        .remote_address_set(nets.clone())
        .local_address("10.0.0.1/32".parse().expect("local 1"))
        .local_address("10.0.0.2/32".parse().expect("local 2"))
        .remote_port(PortRange::single(80).expect("80"))
        .remote_port(PortRange::single(443).expect("443"))
        .local_port(PortRange::single(8080).expect("8080"))
        .build()
        .expect("rule");

    let set_name =
        crate::ipset::set_name_for(&backend.config.managed_namespace(), rule.logical_key());
    let rows = backend.build_set_rule_rows(&rule, &set_name).expect("rows");
    // 2 directions * 2 local addresses * 2 remote ports * 1 local port = 8 rows.
    assert_eq!(rows.len(), 8);
    for (chain, spec) in &rows {
        mock.append("filter", chain, spec).expect("append");
    }

    let enumerated = backend
        .enumerate_with(&mock, |queried| {
            assert_eq!(queried, set_name);
            Ok(Some(nets.clone()))
        })
        .expect("enumerate");
    assert!(enumerated.broken_records.is_empty());
    let recovered = enumerated
        .rules
        .get(rule.logical_key())
        .expect("recovered rule");
    assert_eq!(recovered.rule, rule);
}

#[test]
fn parses_named_protocols_bare_host_ips_and_isolates_foreign_or_missing_ipset_rows() {
    let key = RuleKey::try_from("proto").expect("key");
    assert_eq!(
        parse_protocol(Some("gre"), &key).expect("gre"),
        Protocol::Other(47)
    );
    assert_eq!(
        parse_protocol(Some("sctp"), &key).expect("sctp"),
        Protocol::Other(132)
    );
    assert_eq!(
        parse_protocol(Some("esp"), &key).expect("esp"),
        Protocol::Other(50)
    );
    assert_eq!(
        parse_address(Some("192.0.2.9"), &key).expect("bare ip"),
        "192.0.2.9/32".parse::<ipnet::IpNet>().expect("cidr")
    );

    let backend = test_backend();
    let mock = MockIptables::new_with_parents();
    IptablesBackend::ensure_chain_with(&mock, &backend.in_chain, "INPUT").expect("in");
    IptablesBackend::ensure_chain_with(&mock, &backend.out_chain, "OUTPUT").expect("out");

    // Add one healthy rule, one set rule whose ipset is missing, and one foreign comment row.
    let healthy = Rule::builder("healthy", Action::Block, Direction::Outbound)
        .protocol(Protocol::Other(47))
        .remote_address("192.0.2.10/32".parse().expect("ip"))
        .build()
        .expect("healthy");
    for (chain, spec) in backend.build_rule_rows(&healthy).expect("rows") {
        // Simulate `iptables -S` rendering `-p 47` as `-p gre` and omitting `/32`!
        let rendered = spec
            .replace("-p 47", "-p gre")
            .replace("192.0.2.10/32", "192.0.2.10");
        mock.append("filter", &chain, &rendered).expect("append");
    }

    let missing_set_rule = Rule::builder("missing-set", Action::Block, Direction::Outbound)
        .remote_address_set(["198.51.100.1/32".parse().expect("ip")])
        .build()
        .expect("set rule");
    for (chain, spec) in backend
        .build_set_rule_rows(&missing_set_rule, "fw_missing")
        .expect("rows")
    {
        mock.append("filter", &chain, &spec).expect("append");
    }

    mock.append(
        "filter",
        &backend.out_chain,
        "-d 192.0.2.99 -m comment --comment \"third-party-rule\" -j DROP",
    )
    .expect("foreign");

    // Enumeration must succeed for `healthy` while isolating `missing-set` and the foreign row.
    let enumerated = backend
        .enumerate_with(&mock, |_| Ok(None))
        .expect("enumerate must not fail namespace-wide");
    assert_eq!(
        enumerated.rules.get(healthy.logical_key()).map(|r| &r.rule),
        Some(&healthy)
    );
    assert!(enumerated
        .broken_records
        .contains_key(missing_set_rule.logical_key()));
    assert_eq!(enumerated.orphan_rows.len(), 1);
}

#[test]
fn failing_to_read_an_ipset_fails_enumeration_instead_of_quarantining() {
    let backend = test_backend();
    let mock = MockIptables::new_with_parents();
    IptablesBackend::ensure_chain_with(&mock, &backend.in_chain, "INPUT").expect("in");
    IptablesBackend::ensure_chain_with(&mock, &backend.out_chain, "OUTPUT").expect("out");
    let rule = Rule::builder("set-live", Action::Block, Direction::Outbound)
        .remote_address_set(["198.51.100.1/32".parse().expect("ip")])
        .build()
        .expect("set rule");
    for (chain, spec) in backend.build_set_rule_rows(&rule, "fw_live").expect("rows") {
        mock.append("filter", &chain, &spec).expect("append");
    }

    let Err(error) = backend.enumerate_with(&mock, |_| {
        Err(Error::new(ErrorKind::PermissionDenied, "ipset list denied"))
    }) else {
        panic!("an unreadable set must not look like a broken rule");
    };
    assert_eq!(error.kind(), ErrorKind::PermissionDenied);
}

#[test]
fn a_broken_row_that_cannot_be_deleted_blocks_reinstalling_the_key() {
    let mut backend = test_backend();
    let mock = MockIptables::new_with_parents();
    let key = RuleKey::try_from("stuck").expect("key");
    // The mock refuses to delete a row it does not hold, like a failed delete.
    backend.broken_records.insert(
        key.clone(),
        BrokenIptablesRecord {
            rows: vec![(backend.out_chain.clone(), "-j ACCEPT".to_owned())],
            set_name: None,
        },
    );

    assert!(backend.cleanup_broken_key(&mock, &key).is_err());
}

#[test]
fn a_set_match_against_the_local_end_is_not_read_as_the_rule() {
    let backend = test_backend();
    let mock = MockIptables::new_with_parents();
    IptablesBackend::ensure_chain_with(&mock, &backend.out_chain, "OUTPUT").expect("out");

    let nets = vec!["198.51.100.0/24".parse::<ipnet::IpNet>().expect("net")];
    let rule = Rule::builder("set-end", Action::Block, Direction::Outbound)
        .remote_address_set(nets.clone())
        .build()
        .expect("rule");
    let set_name =
        crate::ipset::set_name_for(&backend.config.managed_namespace(), rule.logical_key());
    let rows = backend.build_set_rule_rows(&rule, &set_name).expect("rows");
    assert_eq!(rows.len(), 1);
    let (chain, spec) = &rows[0];
    assert!(
        spec.contains(" dst"),
        "outbound rows match the destination: {spec}"
    );
    // Matched against the source, the set filters this host's own address.
    let flipped = spec.replace(&format!("{set_name} dst"), &format!("{set_name} src"));
    mock.append("filter", chain, &flipped).expect("append");

    let enumerated = backend
        .enumerate_with(&mock, |_| Ok(Some(nets.clone())))
        .expect("enumerate");
    assert!(!enumerated.rules.contains_key(rule.logical_key()));
    assert!(enumerated.broken_records.contains_key(rule.logical_key()));
}
