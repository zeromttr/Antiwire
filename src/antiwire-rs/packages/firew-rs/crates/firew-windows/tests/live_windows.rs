//! Live Windows firewall tests (Administrator / sudo required).
#![cfg(windows)]

use std::net::IpAddr;
use std::time::Duration;

use firew_core::{
    Action, BulkOperation, BulkOutcome, BulkRead, BulkRequest, Direction, ExecutionAtomicity,
    PortRange, Protocol, Rule, RuleKey, TransactionMode,
};
use firew_rs::{Firewall, HealthMonitorConfig, ReconcileStatus, RuleFilter, RuleId};
use firew_sys::BackendPreference;
use ipnet::IpNet;

const TEST_PREFIX: &str = "firew_live_test";

fn host_net(host: &str) -> IpNet {
    IpNet::from(host.parse::<IpAddr>().expect("ip"))
}

fn test_firewall() -> Firewall {
    Firewall::builder()
        .name_prefix(TEST_PREFIX)
        .application_name("firew_test")
        .memory_mode(true)
        .build()
        .expect("open windows firewall backend")
}

#[test]
#[ignore = "requires Administrator or sudo; native INetFw access"]
fn live_inetfw_add_list_remove() {
    let mut fw = test_firewall();
    let key = "live-inetfw-block";
    let rule = Rule::builder(key, Action::Block, Direction::Outbound)
        .remote_address(host_net("203.0.113.77"))
        .protocol(Protocol::Tcp)
        .remote_port(PortRange::single(443).expect("port"))
        .build()
        .expect("rule");

    let id = fw.add_rule(rule.clone()).expect("add");
    assert_eq!(id.key(), key);
    assert_eq!(fw.get_rule(&id).expect("get"), rule);

    let listed = fw
        .list_rules(&RuleFilter::new().with_key_prefix(RuleKey::try_from(key).expect("key")))
        .expect("list");
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].1, rule);

    fw.remove_rule(&id).expect("remove");
    assert!(fw
        .list_rules(&RuleFilter::new().with_key_prefix(RuleKey::try_from(key).expect("key")))
        .expect("list after remove")
        .is_empty());
    fw.close().expect("close");
}

#[test]
#[ignore = "requires Administrator or sudo; native INetFw access"]
fn live_inetfw_namespace_isolation_and_sub_cap_set_reconstruction() {
    let mut fw_a = Firewall::builder()
        .name_prefix("firew_iso_a")
        .application_name("app_a")
        .memory_mode(true)
        .build()
        .expect("open fw_a");
    let mut fw_b = Firewall::builder()
        .name_prefix("firew_iso_b")
        .application_name("app_b")
        .memory_mode(true)
        .build()
        .expect("open fw_b");

    // Two distinct namespaces using the exact same RuleKey must never delete each other's rules (#1).
    // Also exercise a sub-cap (30 addresses) Set-mode rule with Direction::Both and 5 ports (#26).
    let shared_key = "shared-key";
    let nets_a: Vec<IpNet> = (1..=30)
        .map(|i| host_net(&format!("203.0.113.{i}")))
        .collect();
    let mut builder_a = Rule::builder(shared_key, Action::Block, Direction::Both)
        .protocol(Protocol::Tcp)
        .remote_address_set(nets_a);
    for port in [80, 443, 8080, 8443, 9000] {
        builder_a = builder_a.remote_port(PortRange::single(port).expect("port"));
    }
    let rule_a = builder_a.build().expect("rule_a");
    let rule_b = Rule::builder(shared_key, Action::Allow, Direction::Outbound)
        .remote_address(host_net("198.51.100.42"))
        .build()
        .expect("rule_b");

    let id_a = fw_a.add_rule(rule_a.clone()).expect("add a");
    let id_b = fw_b.add_rule(rule_b.clone()).expect("add b");

    // Remove rule from namespace B and verify namespace A's rule is still intact!
    fw_b.remove_rule(&id_b).expect("remove b");
    assert_eq!(fw_a.get_rule(&id_a).expect("a still intact"), rule_a);

    fw_a.remove_rule(&id_a).expect("remove a");
    fw_a.close().expect("close a");
    fw_b.close().expect("close b");
}

#[test]
#[ignore = "requires Administrator or sudo; native INetFw access"]
fn live_bulk_create_read_delete() {
    let mut fw = test_firewall();
    let keys = ["bulk-a", "bulk-b"];
    let rules: Vec<Rule> = keys
        .iter()
        .map(|k| {
            Rule::builder(*k, Action::Block, Direction::Outbound)
                .remote_address(host_net("203.0.113.80"))
                .build()
                .expect("rule")
        })
        .collect();

    let results = fw
        .execute_bulk(&BulkRequest::prefer_native(vec![
            BulkOperation::Create(rules.clone()),
            BulkOperation::Read(BulkRead {
                key_prefix: Some(RuleKey::try_from("bulk-").expect("key")),
                direction: None,
            }),
        ]))
        .expect("bulk");
    assert_eq!(results.results.len(), 3);
    assert_eq!(
        results.results[0].outcome.as_ref().expect("create bulk-a"),
        &BulkOutcome::Created(RuleKey::try_from("bulk-a").expect("key"))
    );
    assert_eq!(
        results.results[1].outcome.as_ref().expect("create bulk-b"),
        &BulkOutcome::Created(RuleKey::try_from("bulk-b").expect("key"))
    );
    match results.results[2].outcome.as_ref().expect("bulk read") {
        BulkOutcome::Read(read_rules) => assert_eq!(read_rules.len(), 2),
        other => panic!("unexpected read outcome: {other:?}"),
    }

    let del = fw
        .execute_bulk(&BulkRequest::new(vec![BulkOperation::Delete(
            keys.iter()
                .map(|key| RuleKey::try_from(*key).expect("key"))
                .collect(),
        )]))
        .expect("delete bulk");
    for item in &del.results {
        assert!(matches!(item.outcome, Ok(BulkOutcome::Deleted(_))));
    }
    fw.close().expect("close");
}

#[test]
#[ignore = "requires Administrator or sudo; native INetFw access"]
fn live_memory_mode_cleanup_on_close() {
    let mut fw = test_firewall();
    let rule = Rule::builder("mem-close", Action::Block, Direction::Outbound)
        .remote_address(host_net("203.0.113.81"))
        .build()
        .expect("rule");
    let id = fw.add_rule(rule).expect("add");
    fw.close().expect("close");

    let mut fw2 = test_firewall();
    let listed = fw2
        .list_rules(
            &RuleFilter::new().with_key_prefix(RuleKey::try_from("mem-close").expect("key")),
        )
        .expect("list");
    assert!(listed.is_empty());
    let _ = id;
    fw2.close().expect("close2");
}

#[test]
#[ignore = "requires Administrator or sudo; WFP engine access"]
fn live_wfp_backend_open_and_transaction() {
    let mut fw = Firewall::builder()
        .name_prefix(TEST_PREFIX)
        .application_name("wfp_tx_test")
        .memory_mode(true)
        .prefer_backend(BackendPreference::Wfp)
        .build()
        .expect("open wfp");

    let rule_a = Rule::builder("wfp-tx-a", Action::Block, Direction::Outbound)
        .remote_address(host_net("203.0.113.82"))
        .build()
        .expect("rule a");
    let rule_b = Rule::builder("wfp-tx-b", Action::Block, Direction::Inbound)
        .remote_address(host_net("203.0.113.83"))
        .build()
        .expect("rule b");

    let exec = fw
        .execute_bulk(
            &BulkRequest::new(vec![BulkOperation::Create(vec![
                rule_a.clone(),
                rule_b.clone(),
            ])])
            .with_transaction_mode(TransactionMode::RequireNative),
        )
        .expect("wfp native transaction");
    assert_eq!(exec.atomicity, ExecutionAtomicity::NativeAtomic);
    for item in &exec.results {
        assert!(matches!(item.outcome, Ok(BulkOutcome::Created(_))));
    }

    // Verify native WFP filter enumeration recovers the committed rules across a fresh session (#9).
    let fw_observer = Firewall::builder()
        .name_prefix(TEST_PREFIX)
        .application_name("wfp_tx_test")
        .memory_mode(false)
        .prefer_backend(BackendPreference::Wfp)
        .build()
        .expect("open observer wfp");
    let observed = fw_observer
        .list_rules(&RuleFilter::new())
        .expect("list from native wfp");
    assert_eq!(observed.len(), 2);

    // Exercise native rollback on duplicate key failure inside a WFP transaction.
    let rollback_exec = fw
        .execute_bulk(
            &BulkRequest::new(vec![BulkOperation::Create(vec![
                Rule::builder("wfp-tx-c", Action::Block, Direction::Outbound)
                    .remote_address(host_net("203.0.113.84"))
                    .build()
                    .expect("rule c"),
                rule_a.clone(),
            ])])
            .with_transaction_mode(TransactionMode::RequireNative),
        )
        .expect("rollback execution");
    assert!(matches!(
        rollback_exec.results[0].outcome,
        Ok(BulkOutcome::RolledBack)
    ));
    assert!(rollback_exec.results[1].outcome.is_err());

    fw.close().expect("close wfp");
}

#[test]
#[ignore = "requires Administrator or sudo; WFP engine access"]
fn live_wfp_remote_port_range_installs_and_round_trips() {
    let mut fw = Firewall::builder()
        .name_prefix(TEST_PREFIX)
        .application_name("wfp_range_test")
        .memory_mode(true)
        .prefer_backend(BackendPreference::Wfp)
        .build()
        .expect("open wfp");
    // A range condition needs FWP_MATCH_RANGE; an equality match is refused.
    let rule = Rule::builder("wfp-range", Action::Block, Direction::Outbound)
        .protocol(Protocol::Tcp)
        .remote_address(host_net("203.0.113.86"))
        .remote_port(PortRange::range(8000, 8100).expect("range"))
        .build()
        .expect("rule");

    let id = fw.add_rule(rule.clone()).expect("add a port-range rule");
    assert_eq!(fw.get_rule(&id).expect("get"), rule);
    fw.remove_rule(&id).expect("remove");
    fw.close().expect("close wfp");
}

#[test]
#[ignore = "requires Administrator or sudo; native INetFw access"]
fn live_inetfw_shrinking_both_to_one_direction_leaves_no_stale_half() {
    let mut fw = test_firewall();
    let key = RuleKey::try_from("shrink-dir").expect("key");
    let both = Rule::builder(key.as_str(), Action::Block, Direction::Both)
        .remote_address(host_net("203.0.113.87"))
        .build()
        .expect("both");
    let outbound = Rule::builder(key.as_str(), Action::Block, Direction::Outbound)
        .remote_address(host_net("203.0.113.87"))
        .build()
        .expect("outbound");
    let id = fw.add_rule(both.clone()).expect("add both");

    // A both-direction rule covers either direction filter.
    for direction in [Direction::Inbound, Direction::Outbound] {
        let listed = fw
            .list_rules(
                &RuleFilter::new()
                    .with_key_prefix(key.clone())
                    .with_direction(direction),
            )
            .expect("list by direction");
        assert_eq!(listed.len(), 1, "{direction:?} filter must include Both");
    }

    fw.update_rule(&id, outbound.clone())
        .expect("shrink to outbound");
    assert_eq!(fw.get_rule(&id).expect("get"), outbound);
    assert!(
        fw.take_drift().expect("drift").is_empty(),
        "the old inbound half must be gone, not quarantined"
    );
    assert!(fw
        .list_rules(
            &RuleFilter::new()
                .with_key_prefix(key)
                .with_direction(Direction::Inbound),
        )
        .expect("list inbound")
        .is_empty());
    fw.close().expect("close");
}

#[test]
#[ignore = "requires Administrator or sudo; native INetFw access"]
fn live_health_monitor_cycle() {
    let mut fw = test_firewall();
    let rule = Rule::builder("health-live", Action::Block, Direction::Outbound)
        .remote_address(host_net("203.0.113.85"))
        .build()
        .expect("rule");
    let _id = fw.add_rule(rule.clone()).expect("add rule");

    let config = HealthMonitorConfig {
        interval: Duration::from_millis(200),
        auto_repair: true,
    };
    let mut handle = fw.spawn_health_monitor(&config).expect("spawn health");
    let report = handle
        .recv_report_timeout(Duration::from_secs(5))
        .expect("recv report")
        .expect("report present");
    assert!(
        report.errors.is_empty(),
        "unexpected health errors: {:?}",
        report.errors
    );
    assert!(report.missing_keys.is_empty());
    assert!(report.extra_keys.is_empty());

    let rec = fw
        .reconcile(std::slice::from_ref(&rule))
        .expect("reconcile");
    assert!(matches!(rec.items[0].status, ReconcileStatus::Unchanged));

    handle.stop();
    fw.close().expect("close");
}

/// Generates `count` distinct /32s from the reserved, unroutable 240.0.0.0/4.
fn probe_nets(count: usize) -> Vec<IpNet> {
    (0..count)
        .map(|index| {
            let octets = u32::try_from(index).expect("index").to_be_bytes();
            let addr = std::net::Ipv4Addr::new(240 + octets[0], octets[1], octets[2], octets[3]);
            IpNet::new(addr.into(), 32).expect("net")
        })
        .collect()
}

/// Measures how many addresses one native `INetFw` rule accepts.
#[test]
#[ignore = "requires Administrator; measures the native INetFw address ceiling"]
fn live_inetfw_address_set_ceiling() {
    let sizes: Vec<usize> = std::env::var("FIREW_CEILING_SIZES")
        .ok()
        .map(|raw| {
            raw.split(',')
                .filter_map(|part| part.trim().parse::<usize>().ok())
                .collect()
        })
        .filter(|parsed: &Vec<usize>| !parsed.is_empty())
        .unwrap_or_else(|| vec![1_000, 5_000, 10_000, 12_000, 20_000, 29_319, 40_000]);
    let mut best = 0usize;

    for size in sizes {
        let mut fw = Firewall::builder()
            .name_prefix(TEST_PREFIX)
            .application_name("firew_ceiling")
            .memory_mode(true)
            .max_address_set_entries(usize::MAX)
            .build()
            .expect("open windows firewall backend");

        let key = "ceiling-probe";
        let nets = probe_nets(size);
        let rule = match Rule::builder(key, Action::Block, Direction::Outbound)
            .remote_address_set(nets.iter().copied())
            .build()
        {
            Ok(rule) => rule,
            Err(error) => {
                println!("size {size:>6}: BUILD REJECTED: {error}");
                break;
            }
        };

        let started = std::time::Instant::now();
        let id = match fw.add_rule(rule) {
            Ok(id) => id,
            Err(error) => {
                println!(
                    "size {size:>6}: ADD FAILED after {:?}: {error}",
                    started.elapsed()
                );
                let _ = fw.close();
                break;
            }
        };
        let add_elapsed = started.elapsed();

        let read_started = std::time::Instant::now();
        let round_trip = fw.get_rule(&id);
        let read_elapsed = read_started.elapsed();

        match round_trip {
            Ok(back) => {
                let same_count = back.remote_addresses().len() == size;
                let mut expected = nets.clone();
                expected.sort_unstable();
                let mut actual = back.remote_addresses().to_vec();
                actual.sort_unstable();
                let same_set = expected == actual;
                let ordered = back.remote_addresses() == expected.as_slice();

                println!(
                    "size {size:>6}: add {add_elapsed:>8.2?}  read {read_elapsed:>8.2?}  \
                     count={} set={} ordered={}",
                    if same_count { "ok" } else { "MISMATCH" },
                    if same_set { "ok" } else { "LOST" },
                    if ordered { "ok" } else { "reordered" },
                );
                if same_count && same_set {
                    best = size;
                }
            }
            Err(error) => {
                println!("size {size:>6}: READ-BACK FAILED: {error}");
                let _ = fw.remove_rule(&id);
                let _ = fw.close();
                break;
            }
        }

        fw.remove_rule(&id).expect("remove probe rule");
        fw.close().expect("close");
    }

    println!("\nhighest fully-verified native address set: {best}");
    assert!(best > 0, "INetFw accepted no address set at all");
}

/// Runs a `NetSecurity` PowerShell command against this test's native rules.
fn powershell(script: &str) -> String {
    let output = std::process::Command::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-Command", script])
        .output()
        .expect("run powershell");
    assert!(
        output.status.success(),
        "powershell failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).trim().to_owned()
}

/// A PowerShell pipeline start selecting the native `INetFw` rows of `key`.
fn native_rows(key: &str) -> String {
    format!("Get-NetFirewallRule -DisplayName '*:{key} `[*' -ErrorAction SilentlyContinue")
}

/// How many native `INetFw` rows carry `key`'s managed name.
fn native_row_count(key: &str) -> usize {
    powershell(&format!("@({}).Count", native_rows(key)))
        .parse()
        .expect("row count")
}

/// Installs a bidirectional rule for `key`, then deletes its inbound row
/// natively, leaving the outbound half enforcing on its own.
fn install_half_deleted_rule(fw: &mut Firewall, key: &str, host: &str) -> RuleId {
    let rule = Rule::builder(key, Action::Block, Direction::Both)
        .remote_address(host_net(host))
        .build()
        .expect("rule");
    let id = fw.add_rule(rule).expect("add");
    assert_eq!(native_row_count(key), 2);
    powershell(&format!(
        "{} | Where-Object Direction -eq Inbound | Remove-NetFirewallRule",
        native_rows(key)
    ));
    assert_eq!(native_row_count(key), 1, "only the outbound row is left");
    id
}

#[test]
#[ignore = "requires Administrator; native INetFw access"]
fn live_inetfw_failed_update_restores_a_partly_rewritten_row() {
    let mut fw = Firewall::builder()
        .name_prefix(TEST_PREFIX)
        .application_name("firew_rollback")
        .memory_mode(true)
        .max_address_set_entries(usize::MAX)
        .build()
        .expect("open windows firewall backend");
    let key = "rollback-partial";
    let block = Rule::builder(key, Action::Block, Direction::Outbound)
        .remote_address(host_net("203.0.113.90"))
        .build()
        .expect("block");
    let id = fw.add_rule(block.clone()).expect("add block");

    // More addresses than one native rule holds: COM accepts the new action,
    // then rejects the address list.
    let oversized_allow = Rule::builder(key, Action::Allow, Direction::Outbound)
        .remote_address_set(probe_nets(60_000))
        .build()
        .expect("oversized allow");
    let error = fw
        .update_rule(&id, oversized_allow)
        .expect_err("native rule cannot hold the address list");
    println!("update failed as expected: {error}");

    assert_eq!(
        fw.get_rule(&id).expect("rule still installed"),
        block,
        "a failed update must leave the previous Block rule enforcing"
    );
    fw.remove_rule(&id).expect("remove");
    fw.close().expect("close");
}

#[test]
#[ignore = "requires Administrator; native INetFw access"]
fn live_inetfw_remove_deletes_the_surviving_half_of_a_bidirectional_rule() {
    let mut fw = test_firewall();
    let key = "frag-remove";
    let id = install_half_deleted_rule(&mut fw, key, "203.0.113.91");

    fw.remove_rule(&id)
        .expect("removing a damaged rule removes what is left");
    assert_eq!(native_row_count(key), 0, "the outbound row must be gone");
    fw.close().expect("close");
}

#[test]
#[ignore = "requires Administrator; native INetFw access"]
fn live_inetfw_reconcile_removes_the_surviving_half_of_an_undesired_rule() {
    let mut fw = test_firewall();
    let key = "frag-reconcile";
    install_half_deleted_rule(&mut fw, key, "203.0.113.92");

    let report = fw.reconcile(&[]).expect("reconcile");
    println!("{:?}", report.items);
    assert!(!report.has_errors(), "{:?}", report.items);
    assert_eq!(native_row_count(key), 0, "the outbound row must be gone");
    fw.close().expect("close");
}

#[test]
#[ignore = "requires Administrator; native INetFw access"]
fn live_inetfw_profile_restriction_is_not_reported_unchanged() {
    let mut fw = test_firewall();
    let key = "profile-drift";
    let rule = Rule::builder(key, Action::Block, Direction::Outbound)
        .remote_address(host_net("203.0.113.93"))
        .build()
        .expect("rule");
    fw.add_rule(rule.clone()).expect("add");

    powershell(&format!(
        "{} | Set-NetFirewallRule -Profile Domain",
        native_rows(key)
    ));

    let report = fw
        .reconcile(std::slice::from_ref(&rule))
        .expect("reconcile");
    println!("{:?}", report.items);
    assert!(!report.has_errors(), "{:?}", report.items);
    assert!(
        !matches!(report.items[0].status, ReconcileStatus::Unchanged),
        "a rule restricted to the Domain profile does not match on other networks"
    );
    let profile = powershell(&format!("({}).Profile", native_rows(key)));
    assert_eq!(profile, "Any", "reconcile must restore every profile");
    fw.close().expect("close");
}

#[test]
#[ignore = "requires Administrator; WFP engine access"]
fn live_wfp_filters_of_every_shape_read_back_as_their_rules() {
    let mut fw = Firewall::builder()
        .name_prefix(TEST_PREFIX)
        .application_name("wfp_shape_test")
        .memory_mode(true)
        .prefer_backend(BackendPreference::Wfp)
        .build()
        .expect("open wfp");
    let net = |text: &str| text.parse::<IpNet>().expect("net");
    let this_exe = std::env::current_exe().expect("current exe");
    let rules = [
        Rule::builder("wfp-shape-v4", Action::Block, Direction::Both)
            .protocol(Protocol::Udp)
            .remote_address(net("198.51.100.0/24"))
            .remote_address(host_net("203.0.113.88"))
            .remote_port(PortRange::single(53).expect("port"))
            .build(),
        Rule::builder("wfp-shape-v6", Action::Block, Direction::Outbound)
            .protocol(Protocol::Tcp)
            .remote_address(net("2001:db8:1::/64"))
            .remote_address(host_net("2001:db8::88"))
            .build(),
        Rule::builder("wfp-shape-any", Action::Allow, Direction::Inbound)
            .protocol(Protocol::Tcp)
            .remote_port(PortRange::range(9000, 9010).expect("range"))
            .build(),
        Rule::builder("wfp-shape-icmp", Action::Block, Direction::Outbound)
            .protocol(Protocol::IcmpV4)
            .remote_address(host_net("203.0.113.89"))
            .build(),
        Rule::builder("wfp-shape-app", Action::Block, Direction::Outbound)
            .remote_address(host_net("203.0.113.90"))
            .application_path(this_exe)
            .build(),
    ]
    .map(|rule| rule.expect("rule"));

    for rule in &rules {
        let id = fw.add_rule(rule.clone()).expect("add");
        assert_eq!(&fw.get_rule(&id).expect("read back"), rule);
    }
    assert!(
        fw.take_drift().expect("drift").is_empty(),
        "no filter this backend wrote may be quarantined"
    );
    let report = fw.reconcile(&rules).expect("reconcile");
    assert!(
        report
            .items
            .iter()
            .all(|item| matches!(item.status, ReconcileStatus::Unchanged)),
        "{:?}",
        report.items
    );
    fw.close().expect("close wfp");
}
