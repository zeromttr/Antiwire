use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::{AtomicUsize, Ordering};

use firew_core::{Action, Direction};
use ipnet::IpNet;

use super::*;
use crate::test_support::{BackendCall, ScriptedBackend};

fn rule(key: &str, host: u8, action: Action) -> Rule {
    Rule::builder(key, action, Direction::Outbound)
        .remote_address(
            IpNet::new(IpAddr::V4(Ipv4Addr::new(198, 51, 100, host)), 32).expect("host network"),
        )
        .build()
        .expect("valid rule")
}

fn firewall(backend: ScriptedBackend, memory_mode: bool) -> Firewall {
    let mut config = BackendConfig::new("facade-test");
    config.memory_mode = memory_mode;
    let mut state = FirewallState {
        backend: Box::new(backend),
        config,
        registry: RuleRegistry::new(),
        native_rules: HashMap::new(),
        desired_initialized: false,
        desired_generation: 0,
        closed: false,
        monitors: Vec::new(),
        dns_resolver: None,
    };
    for (native, _) in state
        .backend
        .list_rules(&RuleFilter::new())
        .expect("initial enumeration")
    {
        state
            .native_rules
            .insert(native.logical_key().clone(), native);
    }
    let state = Arc::new(Mutex::new(state));
    Firewall {
        domain_manager: DomainSetManager::new(Duration::from_secs(60), Arc::downgrade(&state))
            .expect("domain manager"),
        state,
        dns_timeout: Duration::from_secs(1),
        closed: false,
    }
}

fn status<'a>(report: &'a ReconcileReport, key: &str) -> &'a ReconcileStatus {
    &report
        .items
        .iter()
        .find(|item| item.key == key)
        .expect("reported key")
        .status
}

#[test]
fn reconcile_covers_create_update_remove_and_unchanged_in_one_pass() {
    let (backend, control) = ScriptedBackend::new(true);
    control.seed(rule("extra", 1, Action::Block));
    control.seed(rule("same", 2, Action::Block));
    control.seed(rule("update", 3, Action::Block));
    let mut firewall = firewall(backend, false);
    control.clear_calls();

    let desired = vec![
        rule("create", 4, Action::Allow),
        rule("same", 2, Action::Block),
        rule("update", 5, Action::Allow),
    ];
    let report = firewall.reconcile(&desired).expect("reconcile");

    assert!(matches!(
        status(&report, "create"),
        ReconcileStatus::Created
    ));
    assert!(matches!(
        status(&report, "same"),
        ReconcileStatus::Unchanged
    ));
    assert!(matches!(
        status(&report, "update"),
        ReconcileStatus::Updated
    ));
    assert!(matches!(status(&report, "extra"), ReconcileStatus::Removed));
    assert_eq!(
        control.calls(),
        vec![
            BackendCall::List,
            BackendCall::Add("create".to_owned()),
            BackendCall::Update("update".to_owned()),
            BackendCall::Remove("extra".to_owned()),
        ]
    );
    assert_eq!(control.rules(), desired);
}

#[test]
fn duplicate_reconcile_input_fails_before_native_enumeration_or_mutation() {
    let (backend, control) = ScriptedBackend::new(true);
    let mut firewall = firewall(backend, false);
    control.clear_calls();
    let duplicate = rule("duplicate", 6, Action::Block);

    let error = firewall
        .reconcile(&[duplicate.clone(), duplicate])
        .expect_err("duplicate desired key");

    assert_eq!(error.kind(), ErrorKind::InvalidRule);
    assert!(control.calls().is_empty());
    assert!(control.rules().is_empty());
}

#[test]
fn close_obeys_persistent_memory_and_idempotent_lifecycle_contracts() {
    let persistent_rule = rule("persistent", 7, Action::Block);
    let (backend, persistent_control) = ScriptedBackend::new(true);
    persistent_control.seed(persistent_rule.clone());
    let mut persistent = firewall(backend, false);
    persistent_control.clear_calls();

    persistent.close().expect("persistent close");
    assert_eq!(persistent_control.rules(), vec![persistent_rule]);
    assert!(persistent_control.calls().is_empty());
    assert_eq!(
        persistent
            .list_rules(&RuleFilter::new())
            .expect_err("closed owner")
            .kind(),
        ErrorKind::InvalidConfiguration
    );

    let memory_rule = rule("memory", 8, Action::Block);
    let (backend, memory_control) = ScriptedBackend::new(true);
    memory_control.seed(memory_rule);
    let mut memory = firewall(backend, true);
    memory_control.clear_calls();

    memory.close().expect("memory close");
    memory.close().expect("idempotent close");
    assert!(memory_control.rules().is_empty());
    assert_eq!(memory_control.calls(), vec![BackendCall::RemoveAll]);
}

#[test]
fn replacing_a_domain_rule_unregisters_background_refresh() {
    let domain_rule = Rule::builder("domain", Action::Block, Direction::Outbound)
        .remote_domain("example.com")
        .expect("domain")
        .build()
        .expect("domain rule");
    let replacement = rule("domain", 9, Action::Block);
    let (backend, control) = ScriptedBackend::new(true);
    control.seed(domain_rule.clone());
    let mut firewall = firewall(backend, true);
    let resolved = Arc::from(["192.0.2.1/32".parse::<IpNet>().expect("resolved network")]);
    firewall
        .domain_manager
        .register_resolved(&domain_rule, resolved)
        .expect("register domain refresh");
    assert!(firewall
        .domain_manager
        .is_registered(domain_rule.logical_key()));
    let id = firewall
        .list_rules(&RuleFilter::new())
        .expect("list")
        .remove(0)
        .0;

    firewall
        .update_rule(&id, replacement)
        .expect("replace domain rule");

    assert!(!firewall
        .domain_manager
        .is_registered(domain_rule.logical_key()));
}

#[test]
fn close_reports_cleanup_failure_and_remains_retryable() {
    let memory_rule = rule("memory-failure", 10, Action::Block);
    let (backend, control) = ScriptedBackend::new(true);
    control.seed(memory_rule.clone());
    control.fail_remove_all();
    let mut firewall = firewall(backend, true);

    let error = firewall.close().expect_err("cleanup failure");

    assert_eq!(error.kind(), ErrorKind::PartialMutation);
    assert!(!firewall.is_closed());
    assert_eq!(control.rules(), vec![memory_rule]);
    assert_eq!(
        control.calls(),
        vec![BackendCall::List, BackendCall::RemoveAll]
    );
}

#[test]
fn external_deletion_does_not_block_reconciliation_or_re_add() {
    let (backend, control) = ScriptedBackend::new(true);
    let mut firewall = firewall(backend, true);
    let target = rule("ext-del", 11, Action::Block);
    let _id = firewall.add_rule(target.clone()).expect("initial add");

    // Simulate external deletion directly in the backend while `native_rules` still caches it.
    control.remove_external("ext-del");

    let report = firewall
        .reconcile(std::slice::from_ref(&target))
        .expect("reconcile after external deletion");
    assert!(matches!(
        status(&report, "ext-del"),
        ReconcileStatus::Created
    ));
    assert_eq!(control.rules(), vec![target]);
}

#[test]
fn failed_update_restores_previous_rule_when_backend_deleted_it() {
    let (backend, control) = ScriptedBackend::new(false);
    let mut firewall = firewall(backend, true);
    let original = rule("restore-me", 12, Action::Block);
    let replacement = rule("restore-me", 13, Action::Allow);
    let id = firewall.add_rule(original.clone()).expect("add original");

    control.fail_update_removing_old("restore-me");
    let err = firewall
        .update_rule(&id, replacement)
        .expect_err("update must fail");
    assert_eq!(err.kind(), ErrorKind::Internal);
    // Original rule must have been restored automatically.
    assert_eq!(control.rules(), vec![original.clone()]);
    assert_eq!(firewall.get_rule(&id).expect("get restored"), original);
}

#[test]
fn health_monitor_preserves_recovered_persistent_rules_before_desired_initialization() {
    let (backend, control) = ScriptedBackend::new(true);
    let recovered = rule("recovered", 14, Action::Block);
    control.seed(recovered.clone());
    let mut firewall = firewall(backend, false);

    let mut monitor = firewall
        .spawn_health_monitor(&HealthMonitorConfig {
            interval: Duration::from_millis(20),
            auto_repair: true,
        })
        .expect("spawn monitor");

    let report = monitor
        .recv_report_timeout(Duration::from_secs(1))
        .expect("recv")
        .expect("report");
    assert!(report.extra_keys.is_empty());
    assert_eq!(control.rules(), vec![recovered]);
    monitor.stop();
    firewall.close().expect("close");
}

#[test]
fn health_monitor_detects_and_repairs_content_drift_and_merges_unread_reports() {
    let (backend, control) = ScriptedBackend::new(true);
    let mut firewall = firewall(backend, true);
    let desired = rule("guarded", 15, Action::Block);
    firewall.add_rule(desired.clone()).expect("add");

    // Externally alter the rule's action from Block to Allow!
    control.seed(rule("guarded", 15, Action::Allow));

    let mut monitor = firewall
        .spawn_health_monitor(&HealthMonitorConfig {
            interval: Duration::from_millis(25),
            auto_repair: true,
        })
        .expect("spawn monitor");

    // Wait across multiple intervals without reading so report merging is exercised.
    std::thread::sleep(Duration::from_millis(80));
    let report = monitor
        .recv_report_timeout(Duration::from_secs(1))
        .expect("recv")
        .expect("report");
    assert_eq!(
        report.repaired_keys,
        vec![RuleKey::try_from("guarded").expect("key")]
    );
    assert_eq!(control.rules(), vec![desired]);
    monitor.stop();
    firewall.close().expect("close");
}

#[test]
fn close_stops_running_health_monitor_so_no_writes_occur_afterward() {
    let (backend, control) = ScriptedBackend::new(false);
    let mut firewall = firewall(backend, false);
    let desired = rule("monitored", 16, Action::Block);
    firewall.add_rule(desired).expect("add");

    let handle = firewall
        .spawn_health_monitor(&HealthMonitorConfig {
            interval: Duration::from_millis(20),
            auto_repair: true,
        })
        .expect("spawn monitor");
    let _ = handle.recv_report_timeout(Duration::from_secs(1));

    firewall.close().expect("close");
    control.remove_external("monitored");
    control.clear_calls();

    std::thread::sleep(Duration::from_millis(60));
    assert!(
        control.calls().is_empty(),
        "monitor must not perform backend calls after close"
    );
}

#[test]
fn reconcile_resolves_domain_once_recognizes_unchanged_and_purges_stale_registry() {
    let (backend, control) = ScriptedBackend::new(true);
    control.set_supports_ipv6(false);
    let mut firewall = firewall(backend, true);
    let lookups = Arc::new(AtomicUsize::new(0));
    let lookups_clone = lookups.clone();
    firewall.state.lock().dns_resolver = Some(Arc::new(move |_domain| {
        lookups_clone.fetch_add(1, Ordering::SeqCst);
        Ok(vec![
            "192.0.2.50/32".parse::<IpNet>().expect("v4"),
            "2001:db8::50/128".parse::<IpNet>().expect("v6"),
        ])
    }));

    let stale = rule("stale-rule", 20, Action::Block);
    firewall.add_rule(stale).expect("add stale");
    control.remove_external("stale-rule");

    let domain_rule = Rule::builder("dom-rec", Action::Block, Direction::Outbound)
        .remote_domain("dual.example.com")
        .expect("domain")
        .build()
        .expect("domain rule");

    // First reconcile: creates `dom-rec` (filtering out IPv6 for IPv4-only backend) and purges `stale-rule`.
    let report1 = firewall
        .reconcile(std::slice::from_ref(&domain_rule))
        .expect("reconcile 1");
    assert!(matches!(
        status(&report1, "dom-rec"),
        ReconcileStatus::Created
    ));
    assert_eq!(
        lookups.load(Ordering::SeqCst),
        1,
        "must resolve DNS only once per reconcile"
    );
    assert!(
        firewall
            .state
            .lock()
            .registry
            .get(&RuleKey::try_from("stale-rule").expect("key"))
            .is_none(),
        "externally deleted rule omitted from desired must be purged from registry"
    );

    // `get_rule` and `list_rules` must preserve `remote_domains` on the logical rule!
    let listed = firewall.list_rules(&RuleFilter::new()).expect("list");
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].1, domain_rule);

    // Second reconcile with identical domain rule and resolution must report `Unchanged`.
    let report2 = firewall
        .reconcile(std::slice::from_ref(&domain_rule))
        .expect("reconcile 2");
    assert!(matches!(
        status(&report2, "dom-rec"),
        ReconcileStatus::Unchanged
    ));
    assert_eq!(lookups.load(Ordering::SeqCst), 2);
    firewall.close().expect("close");
}

#[test]
fn single_add_does_not_let_health_delete_recovered_rules() {
    let (backend, control) = ScriptedBackend::new(true);
    let recovered = rule("recovered-a", 30, Action::Block);
    control.seed(recovered.clone());
    let mut firewall = firewall(backend, false);
    let added = rule("added", 31, Action::Block);
    firewall.add_rule(added.clone()).expect("add");
    // A bulk read must not declare the desired set either.
    firewall
        .execute_bulk(&BulkRequest::new(vec![firew_core::BulkOperation::Read(
            firew_core::BulkRead::default(),
        )]))
        .expect("bulk read");

    let mut monitor = firewall
        .spawn_health_monitor(&HealthMonitorConfig {
            interval: Duration::from_millis(20),
            auto_repair: true,
        })
        .expect("spawn monitor");
    let report = monitor
        .recv_report_timeout(Duration::from_secs(1))
        .expect("recv")
        .expect("report");

    assert!(report.extra_keys.is_empty());
    let mut rules = control.rules();
    rules.sort_by(|a, b| a.logical_key().cmp(b.logical_key()));
    assert_eq!(rules, vec![added, recovered]);
    monitor.stop();
    firewall.close().expect("close");
}

#[test]
fn removing_an_already_deleted_rule_drops_it_from_desired_state() {
    let (backend, control) = ScriptedBackend::new(true);
    let mut firewall = firewall(backend, true);
    let target = rule("gone", 32, Action::Block);
    let id = firewall.add_rule(target).expect("add");
    control.remove_external("gone");

    let error = firewall.remove_rule(&id).expect_err("already gone");
    assert_eq!(error.kind(), ErrorKind::RuleNotFound);
    assert!(firewall.state.lock().registry.get(id.key()).is_none());

    let mut monitor = firewall
        .spawn_health_monitor(&HealthMonitorConfig {
            interval: Duration::from_millis(20),
            auto_repair: true,
        })
        .expect("spawn monitor");
    let report = monitor
        .recv_report_timeout(Duration::from_secs(1))
        .expect("recv")
        .expect("report");
    assert!(report.repaired_keys.is_empty());
    assert!(control.rules().is_empty(), "health must not re-add it");
    monitor.stop();
    firewall.close().expect("close");
}

#[test]
fn health_repair_keeps_a_live_rule_when_its_update_fails() {
    let (backend, control) = ScriptedBackend::new(false);
    let mut firewall = firewall(backend, true);
    firewall
        .add_rule(rule("live", 33, Action::Block))
        .expect("add");
    let drifted = rule("live", 33, Action::Allow);
    control.seed(drifted.clone());
    control.fail_update("live");

    let mut monitor = firewall
        .spawn_health_monitor(&HealthMonitorConfig {
            interval: Duration::from_millis(20),
            auto_repair: true,
        })
        .expect("spawn monitor");
    let report = monitor
        .recv_report_timeout(Duration::from_secs(1))
        .expect("recv")
        .expect("report");

    assert!(!report.errors.is_empty());
    assert!(report.repaired_keys.is_empty());
    assert_eq!(
        control.rules(),
        vec![drifted],
        "a failed update must not delete the rule that is still installed"
    );
    assert!(!control
        .calls()
        .contains(&BackendCall::Remove("live".to_owned())));
    monitor.stop();
    firewall.close().expect("close");
}

#[test]
fn reconcile_report_surfaces_item_failures() {
    let (backend, control) = ScriptedBackend::new(true);
    control.fail_add("broken");
    let mut firewall = firewall(backend, false);

    let report = firewall
        .reconcile(&[
            rule("broken", 34, Action::Block),
            rule("fine", 35, Action::Block),
        ])
        .expect("reconcile tries every change");

    assert!(report.has_errors());
    assert_eq!(
        report
            .errors()
            .map(|(key, _)| key.as_str())
            .collect::<Vec<_>>(),
        vec!["broken"]
    );
    let error = report.into_result().expect_err("partial apply");
    assert_eq!(error.kind(), ErrorKind::PartialMutation);
    assert_eq!(error.logical_key().map(RuleKey::as_str), Some("broken"));
}

#[test]
fn drop_falls_back_to_removing_rules_one_at_a_time() {
    let (backend, control) = ScriptedBackend::new(true);
    let mut firewall = firewall(backend, true);
    firewall
        .add_rule(rule("one", 36, Action::Block))
        .expect("one");
    firewall
        .add_rule(rule("two", 37, Action::Block))
        .expect("two");
    control.fail_remove_all();

    drop(firewall);

    assert!(control.rules().is_empty());
}

#[test]
fn update_that_cannot_register_its_domain_restores_the_previous_rule() {
    let (backend, control) = ScriptedBackend::new(true);
    let mut firewall = firewall(backend, true);
    firewall.state.lock().dns_resolver = Some(Arc::new(|domain: &str| {
        let host = if domain == "old.example" { 1 } else { 2 };
        Ok(vec![IpNet::new(
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, host)),
            32,
        )
        .expect("network")])
    }));
    let domain_rule = |domain: &str| {
        Rule::builder("dom", Action::Block, Direction::Outbound)
            .remote_domain(domain)
            .expect("domain")
            .build()
            .expect("domain rule")
    };
    let id = firewall.add_rule(domain_rule("old.example")).expect("add");
    let installed = control.rules();

    // With the refresh worker gone, registering the replacement fails after
    // the native update already succeeded.
    firewall.domain_manager.shutdown();
    let error = firewall
        .update_rule(&id, domain_rule("new.example"))
        .expect_err("registration fails");

    assert_eq!(error.kind(), ErrorKind::DnsResolutionFailed);
    assert_eq!(control.rules(), installed);
    assert_eq!(
        firewall.state.lock().registry.get(id.key()),
        Some(&domain_rule("old.example"))
    );
}

#[test]
fn removing_a_damaged_rule_deletes_its_remaining_rows() {
    let (backend, control) = ScriptedBackend::new(false);
    let mut firewall = firewall(backend, false);
    let id = firewall
        .add_rule(rule("damaged", 1, Action::Block))
        .expect("add");
    control.damage("damaged");

    firewall
        .remove_rule(&id)
        .expect("the remaining rows are removed, not reported missing");
    assert!(control.fragments().is_empty());
    let error = firewall.remove_rule(&id).expect_err("nothing is left");
    assert_eq!(error.kind(), ErrorKind::RuleNotFound);
}

#[test]
fn reconcile_removes_damaged_undesired_rules_and_reinstalls_desired_ones() {
    let (backend, control) = ScriptedBackend::new(false);
    let mut firewall = firewall(backend, false);
    let kept = rule("kept", 1, Action::Block);
    firewall.add_rule(kept.clone()).expect("add kept");
    firewall
        .add_rule(rule("dropped", 2, Action::Block))
        .expect("add dropped");
    control.damage("kept");
    control.damage("dropped");

    let report = firewall
        .reconcile(std::slice::from_ref(&kept))
        .expect("reconcile");

    assert!(!report.has_errors(), "{:?}", report.items);
    assert!(matches!(status(&report, "kept"), ReconcileStatus::Created));
    assert!(matches!(
        status(&report, "dropped"),
        ReconcileStatus::Removed
    ));
    assert!(control.fragments().is_empty());
    assert_eq!(control.rules(), vec![kept]);
}
