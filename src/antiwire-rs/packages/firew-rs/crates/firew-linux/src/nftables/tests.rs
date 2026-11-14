use std::collections::HashMap;

use firew_core::{Action, Direction, ErrorKind, PortRange, Protocol, Rule, RuleKey};
use firew_sys::{Backend, BackendConfig, DriftTracker};
use ipnet::IpNet;
use nftables::expr::{Expression, MetaKey, NamedExpression};
use nftables::schema::{NfListObject, NfObject, Nftables};
use nftables::stmt::Statement;

use super::*;

fn test_backend() -> NftablesBackend {
    let config = BackendConfig::new("nft-test");
    let suffix = config.managed_namespace();
    NftablesBackend {
        out_chain: format!("firew_out_{}", suffix.as_str()),
        in_chain: format!("firew_in_{}", suffix.as_str()),
        config,
        rules: HashMap::new(),
        orphan_handles: HashMap::new(),
        orphan_sets: HashMap::new(),
        unkeyed_orphans: Vec::new(),
        drift: DriftTracker::new(),
        in_transaction: false,
        transaction_snapshot: None,
        staged_orphans: Vec::new(),
    }
}

/// A listing of `sets` and `rows`, the rows given handles from 100 the way
/// `nft -a` lists them.
fn listing(sets: Vec<Set<'static>>, rows: Vec<NftRule<'static>>) -> Nftables<'static> {
    let sets = sets
        .into_iter()
        .map(|set| NfObject::ListObject(NfListObject::Set(Box::new(set))));
    let rows = rows.into_iter().zip(100..).map(|(mut row, handle)| {
        row.handle = Some(handle);
        NfObject::ListObject(NfListObject::Rule(row))
    });
    Nftables {
        objects: Cow::Owned(sets.chain(rows).collect()),
    }
}

/// Opens a transaction by hand: `begin_transaction` lists the kernel, and
/// these tests run without `nft`.
fn open_transaction(backend: &mut NftablesBackend) {
    backend.transaction_snapshot = Some(backend.rules.clone());
    backend.in_transaction = true;
}

/// Handles of the rules committing the open transaction deletes.
fn commit_deletions(backend: &mut NftablesBackend) -> Vec<u64> {
    let snapshot = backend.transaction_snapshot.clone().expect("snapshot");
    let (batch, _) = backend.build_commit_batch(&snapshot).expect("commit batch");
    let json = serde_json::to_value(batch.to_nftables()).expect("serialize batch");
    json["nftables"]
        .as_array()
        .expect("command list")
        .iter()
        .filter_map(|command| command["delete"]["rule"]["handle"].as_u64())
        .collect()
}

/// A backend whose table holds only the first of a bidirectional rule's two
/// rows, as handle 100, and that rule.
fn backend_with_damaged_rule() -> (NftablesBackend, Rule) {
    let mut backend = test_backend();
    let rule = Rule::builder("damaged", Action::Block, Direction::Both)
        .remote_address("192.0.2.9/32".parse::<IpNet>().expect("net"))
        .build()
        .expect("rule");
    let mut rows = backend.build_cartesian_rules(&rule).expect("rows");
    rows.truncate(1);
    backend.apply_reconstructed_ruleset(&listing(Vec::new(), rows));
    (backend, rule)
}

#[test]
fn reinstalling_a_damaged_rule_in_a_transaction_deletes_its_orphan_rows() {
    let (mut backend, rule) = backend_with_damaged_rule();
    let key = rule.logical_key().clone();
    assert!(
        !backend.rules.contains_key(&key),
        "half a rule is not a rule"
    );

    open_transaction(&mut backend);
    assert_eq!(backend.incomplete_keys().expect("keys"), vec![key]);
    backend.add_rule(&rule).expect("reinstall");

    assert_eq!(
        commit_deletions(&mut backend),
        vec![100],
        "the surviving old row must be deleted with the reinstall"
    );
}

#[test]
fn removing_a_damaged_rule_in_a_transaction_deletes_its_orphan_rows() {
    let (mut backend, rule) = backend_with_damaged_rule();
    let key = rule.logical_key().clone();

    open_transaction(&mut backend);
    backend
        .remove_rule(&NativeRuleRef::from_handles("nftables", Vec::new(), key))
        .expect("remove");

    assert_eq!(commit_deletions(&mut backend), vec![100]);
}

#[test]
fn an_aborted_transaction_hands_staged_orphans_back() {
    let (mut backend, rule) = backend_with_damaged_rule();
    let key = rule.logical_key().clone();

    open_transaction(&mut backend);
    backend.add_rule(&rule).expect("reinstall");
    backend.abort_transaction().expect("abort");

    assert!(!backend.rules.contains_key(&key));
    assert_eq!(
        backend.orphan_handles.get(&key).map(Vec::len),
        Some(1),
        "an abort must not forget rows that are still installed"
    );
    assert!(backend.staged_orphans.is_empty());
}

#[test]
fn set_mode_expands_local_addresses_and_ports_with_or_semantics() {
    let backend = test_backend();
    let rule = Rule::builder("set-expand", Action::Block, Direction::Outbound)
        .protocol(Protocol::Tcp)
        .remote_address_set([
            "203.0.113.0/24".parse::<IpNet>().expect("net"),
            "198.51.100.1/32".parse::<IpNet>().expect("net"),
        ])
        .local_address("10.0.0.1/32".parse::<IpNet>().expect("local 1"))
        .local_address("10.0.0.2/32".parse::<IpNet>().expect("local 2"))
        .remote_port(PortRange::single(80).expect("80"))
        .remote_port(PortRange::single(443).expect("443"))
        .build()
        .expect("rule");

    let install = backend.build_set_objects(&rule).expect("set objects");
    assert_eq!(install.sets.len(), 1);
    // 1 direction * 2 local addresses * 2 remote ports = 4 rules (each with 1 port, not ANDed).
    assert_eq!(install.rules.len(), 4);
    for nft_rule in &install.rules {
        let json = serde_json::to_string(nft_rule).expect("json");
        assert!(
            json.contains("saddr"),
            "outbound local address must match saddr: {json}"
        );
        // Each rule must only have one dport match (not both 80 and 443 ANDed).
        assert_eq!(
            json.matches("dport").count(),
            1,
            "ports must not be ANDed: {json}"
        );
    }
}

#[test]
fn set_elements_keep_neighbours_and_drop_nested_networks() {
    let net = |text: &str| text.parse::<IpNet>().expect("net");
    let backend = test_backend();
    let rule = Rule::builder("neighbours", Action::Block, Direction::Outbound)
        .remote_address_set([net("10.0.0.0/32"), net("10.0.0.1/32")])
        .build()
        .expect("rule");
    let install = backend.build_set_objects(&rule).expect("set objects");
    let elements = install.sets[0].elem.as_ref().expect("elements");
    assert_eq!(
        elements.len(),
        2,
        "adjacent hosts must not merge into a /31"
    );

    let nested = Rule::builder("nested", Action::Block, Direction::Outbound)
        .remote_address_set([net("10.1.0.0/16"), net("10.0.0.0/8"), net("11.0.0.1/32")])
        .build()
        .expect("rule");
    let install = backend.build_set_objects(&nested).expect("set objects");
    let elements = install.sets[0].elem.as_ref().expect("elements");
    assert_eq!(
        elements.len(),
        2,
        "a nested network would overlap in an interval set"
    );
}

#[test]
fn listings_without_rule_handles_are_refused() {
    let backend = test_backend();
    let rule = Rule::builder("unhandled", Action::Block, Direction::Outbound)
        .remote_address("192.0.2.1/32".parse::<IpNet>().expect("net"))
        .build()
        .expect("rule");
    let objects: Vec<NfObject<'static>> = backend
        .build_cartesian_rules(&rule)
        .expect("rules")
        .into_iter()
        .map(|r| NfObject::ListObject(NfListObject::Rule(r)))
        .collect();
    let without = Nftables {
        objects: Cow::Owned(objects.clone()),
    };
    assert_eq!(
        ensure_rule_handles(&without).expect_err("no handle").kind(),
        ErrorKind::CorruptNativeState
    );

    let with = Nftables {
        objects: Cow::Owned(
            objects
                .into_iter()
                .map(|obj| match obj {
                    NfObject::ListObject(NfListObject::Rule(mut r)) => {
                        r.handle = Some(7);
                        NfObject::ListObject(NfListObject::Rule(r))
                    }
                    other => other,
                })
                .collect(),
        ),
    };
    ensure_rule_handles(&with).expect("handles present");
}

#[test]
fn repeated_updates_in_one_transaction_coalesce_to_final_rule() {
    let mut backend = test_backend();
    let key = RuleKey::try_from("coalesce").expect("key");
    let rule_a = Rule::builder("coalesce", Action::Block, Direction::Outbound)
        .remote_address("192.0.2.1/32".parse::<IpNet>().expect("a"))
        .build()
        .expect("a");
    let rule_b = Rule::builder("coalesce", Action::Block, Direction::Outbound)
        .remote_address("192.0.2.2/32".parse::<IpNet>().expect("b"))
        .build()
        .expect("b");
    let rule_c = Rule::builder("coalesce", Action::Allow, Direction::Outbound)
        .remote_address("192.0.2.3/32".parse::<IpNet>().expect("c"))
        .build()
        .expect("c");

    // Seed rule A as already installed in the kernel with handle 42.
    backend.rules.insert(
        key.clone(),
        RuleRecord {
            rule: rule_a,
            handles: vec![NftHandle {
                chain: backend.out_chain.clone(),
                handle: 42,
            }],
            sets: Vec::new(),
            dirty: false,
        },
    );
    let id = backend.native_ref_for(&key);

    open_transaction(&mut backend);
    backend.update_rule(&id, &rule_b).expect("update to b");
    backend.update_rule(&id, &rule_c).expect("update to c");

    let snapshot = backend.transaction_snapshot.clone().expect("snapshot");
    let (batch, want_handles) = backend.build_commit_batch(&snapshot).expect("commit batch");
    assert!(want_handles);

    let json = serde_json::to_string(&batch.to_nftables()).expect("serialize batch");
    assert!(
        json.contains("42"),
        "must delete original handle 42: {json}"
    );
    assert!(
        !json.contains("192.0.2.2"),
        "superseded rule B must not be in batch: {json}"
    );
    assert!(
        json.contains("192.0.2.3"),
        "final rule C must be in batch: {json}"
    );
}

#[test]
fn reconstructs_rules_from_table_ruleset_json() {
    let mut backend = test_backend();
    let rule = Rule::builder("recover", Action::Block, Direction::Both)
        .protocol(Protocol::Tcp)
        .remote_address("198.51.100.0/24".parse::<IpNet>().expect("net"))
        .remote_port(PortRange::single(443).expect("port"))
        .build()
        .expect("rule");

    let built_rules = backend.build_cartesian_rules(&rule).expect("build rules");
    backend.apply_reconstructed_ruleset(&listing(Vec::new(), built_rules));
    let key = RuleKey::try_from("recover").expect("key");
    let recovered = backend.rules.get(&key).expect("recovered rule");
    assert_eq!(recovered.rule, rule);
    assert_eq!(recovered.handles.len(), 2);
}

#[test]
fn reconstructs_l4proto_when_nft_lists_it_by_name() {
    let mut backend = test_backend();
    let rule = Rule::builder("linux-block", Action::Block, Direction::Outbound)
        .protocol(Protocol::Tcp)
        .remote_address("203.0.113.90/32".parse::<IpNet>().expect("net"))
        .build()
        .expect("rule");

    let mut built = backend
        .build_cartesian_rules(&rule)
        .expect("build rules")
        .into_iter()
        .next()
        .expect("one rule");
    for stmt in built.expr.to_mut() {
        let Statement::Match(m) = stmt else {
            continue;
        };
        let Expression::Named(NamedExpression::Meta(meta)) = &m.left else {
            continue;
        };
        if meta.key == MetaKey::L4proto {
            m.right = Expression::String(Cow::Borrowed("tcp"));
        }
    }
    backend.apply_reconstructed_ruleset(&listing(Vec::new(), vec![built]));
    let key = RuleKey::try_from("linux-block").expect("key");
    let recovered = backend.rules.get(&key).expect("recovered rule");
    assert_eq!(recovered.rule, rule);
}

#[test]
fn addressless_icmp_rules_emit_nfproto_constraint() {
    let icmp4 = Rule::builder("icmp4", Action::Block, Direction::Outbound)
        .protocol(Protocol::IcmpV4)
        .application_path("/usr/bin/ping")
        .build()
        .expect("icmp4");
    let stmts4 = NftablesBackend::build_statements(&icmp4, false, None, None, None, None);
    let json4 = serde_json::to_string(&stmts4).expect("json");
    assert!(
        json4.contains("ipv4"),
        "ICMPv4 without addresses must bind nfproto ipv4: {json4}"
    );

    let icmp6 = Rule::builder("icmp6", Action::Block, Direction::Outbound)
        .protocol(Protocol::IcmpV6)
        .application_path("/usr/bin/ping6")
        .build()
        .expect("icmp6");
    let stmts6 = NftablesBackend::build_statements(&icmp6, false, None, None, None, None);
    let json6 = serde_json::to_string(&stmts6).expect("json");
    assert!(
        json6.contains("ipv6"),
        "ICMPv6 without addresses must bind nfproto ipv6: {json6}"
    );
}

#[test]
fn a_negated_address_match_is_not_read_as_a_positive_one() {
    let mut backend = test_backend();
    let rule = Rule::builder("negated", Action::Block, Direction::Outbound)
        .remote_address("203.0.113.5/32".parse::<IpNet>().expect("net"))
        .build()
        .expect("rule");
    let mut rows = backend.build_cartesian_rules(&rule).expect("rows");
    for stmt in rows[0].expr.to_mut() {
        if let Statement::Match(m) = stmt {
            if matches!(m.left, Expression::Named(NamedExpression::Payload(_))) {
                m.op = nftables::stmt::Operator::NEQ;
            }
        }
    }
    backend.apply_reconstructed_ruleset(&listing(Vec::new(), rows));

    let key = RuleKey::try_from("negated").expect("key");
    assert!(
        !backend.rules.contains_key(&key),
        "`daddr != X` blocks everything but X; it is not the rule that blocks X"
    );
    assert!(backend.orphan_handles.contains_key(&key));
}

#[test]
fn rows_that_no_longer_cover_the_expansion_are_quarantined() {
    let net = |text: &str| text.parse::<IpNet>().expect("net");
    let mut backend = test_backend();
    let rule = Rule::builder("coverage", Action::Block, Direction::Outbound)
        .protocol(Protocol::Tcp)
        .remote_address(net("192.0.2.1/32"))
        .remote_address(net("192.0.2.2/32"))
        .remote_port(PortRange::single(80).expect("80"))
        .remote_port(PortRange::single(443).expect("443"))
        .build()
        .expect("rule");
    // The (192.0.2.2, 443) row was rewritten to match 192.0.2.3 instead. The
    // union of matchers would read back as a 3 x 2 rule enforced by 4 rows.
    let edited = Rule::builder("coverage", Action::Block, Direction::Outbound)
        .protocol(Protocol::Tcp)
        .remote_address(net("192.0.2.3/32"))
        .remote_port(PortRange::single(443).expect("443"))
        .build()
        .expect("edited");
    let mut rows = backend.build_cartesian_rules(&rule).expect("rows");
    let replacement = backend.build_cartesian_rules(&edited).expect("edited row");
    let last = rows.len() - 1;
    rows[last].expr = replacement[0].expr.clone();
    backend.apply_reconstructed_ruleset(&listing(Vec::new(), rows));

    let key = RuleKey::try_from("coverage").expect("key");
    assert!(!backend.rules.contains_key(&key));
    assert!(backend.orphan_handles.contains_key(&key));
}

#[test]
fn a_set_rule_holding_both_families_reads_back() {
    let net = |text: &str| text.parse::<IpNet>().expect("net");
    let mut backend = test_backend();
    let rule = Rule::builder("dual-set", Action::Block, Direction::Both)
        .remote_address_set([net("192.0.2.0/24"), net("2001:db8::/32")])
        .build()
        .expect("rule");
    let install = backend.build_set_objects(&rule).expect("set objects");
    backend.apply_reconstructed_ruleset(&listing(install.sets, install.rules));

    let key = RuleKey::try_from("dual-set").expect("key");
    let recovered = backend
        .rules
        .get(&key)
        .expect("one row per family and direction");
    assert_eq!(recovered.rule, rule);
    assert_eq!(recovered.handles.len(), 4);
}
