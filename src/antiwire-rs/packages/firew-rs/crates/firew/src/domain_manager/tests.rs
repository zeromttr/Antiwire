use super::*;
use firew_core::{Action, Direction, RuleRegistry};
use firew_sys::{BackendConfig, NativeRuleRef};

use crate::test_support::ScriptedBackend;

fn host(last: u8) -> IpNet {
    IpNet::new(std::net::Ipv4Addr::new(192, 0, 2, last).into(), 32).expect("network")
}

fn domain_rule() -> Rule {
    Rule::builder("refreshed", Action::Block, Direction::Outbound)
        .remote_domain("refresh.example")
        .expect("domain")
        .build()
        .expect("rule")
}

#[test]
fn queued_unregister_keeps_a_newer_resolution_of_the_same_key() {
    let manager = DomainSetManager::new(Duration::from_secs(60), Weak::new()).expect("manager");
    let rule = domain_rule();
    let key = rule.logical_key().clone();
    manager
        .register_resolved(&rule, Arc::from([host(1)]))
        .expect("first registration");
    manager.unregister(&key);
    manager
        .register_resolved(&rule, Arc::from([host(2)]))
        .expect("second registration");

    // Give the worker time to drain the queued commands.
    thread::sleep(Duration::from_millis(100));

    assert_eq!(manager.resolved_for(&key).as_deref(), Some(&[host(2)][..]));
    manager.shutdown();
}

#[test]
fn slow_refresh_neither_blocks_initial_lookups_nor_overwrites_newer_intent() {
    let rule = domain_rule();
    let key = rule.logical_key().clone();
    let installed =
        |last: u8| expand_with_networks(&rule, &[host(last)], Some(65_536)).expect("expanded rule");

    let (backend, control) = ScriptedBackend::new(false);
    control.seed(installed(1));
    let mut native_rules = HashMap::new();
    native_rules.insert(
        key.clone(),
        NativeRuleRef::new("scripted", key.to_string(), key.clone()),
    );

    // The first refresh lookup blocks until released and then returns a
    // stale address; every later lookup returns the newest one.
    let (started_tx, started_rx) = mpsc::channel::<()>();
    let (release_tx, release_rx) = mpsc::channel::<()>();
    let first_call = Arc::new(Mutex::new(Some((started_tx, release_rx))));
    let resolver: CustomDnsResolver = Arc::new(move |_domain: &str| {
        if let Some((started, release)) = first_call.lock().take() {
            let _ = started.send(());
            let _ = release.recv();
            return Ok(vec![host(2)]);
        }
        Ok(vec![host(3)])
    });

    let state = Arc::new(Mutex::new(FirewallState {
        backend: Box::new(backend),
        config: BackendConfig::new("refresh-test"),
        registry: RuleRegistry::new(),
        native_rules,
        desired_initialized: false,
        desired_generation: 0,
        closed: false,
        monitors: Vec::new(),
        dns_resolver: Some(resolver),
    }));
    let manager =
        DomainSetManager::new(Duration::from_millis(10), Arc::downgrade(&state)).expect("manager");
    manager
        .register_resolved(&rule, Arc::from([host(1)]))
        .expect("register");

    started_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("refresh pass started");

    // While the refresh lookup is stuck, an initial lookup still answers.
    let lookup = Rule::builder("initial", Action::Block, Direction::Outbound)
        .remote_domain("localhost")
        .expect("domain")
        .build()
        .expect("rule");
    manager
        .resolve_initial_for_family(
            &lookup,
            Duration::from_secs(3),
            FamilySupport::default(),
            None,
        )
        .expect("initial lookup must not wait behind the refresh pass");

    // Newer intent lands while the stale lookup is in flight.
    {
        let _guard = state.lock();
        control.seed(installed(3));
        manager
            .register_resolved(&rule, Arc::from([host(3)]))
            .expect("newer registration");
    }
    release_tx.send(()).expect("release refresh");
    thread::sleep(Duration::from_millis(150));

    assert_eq!(control.rules(), vec![installed(3)]);
    assert_eq!(manager.resolved_for(&key).as_deref(), Some(&[host(3)][..]));
    state.lock().closed = true;
    manager.shutdown();
}

#[test]
fn resolved_network_reads_share_the_snapshot() {
    let manager = DomainSetManager::new(Duration::from_secs(60), Weak::new()).expect("manager");
    let key = RuleKey::try_from("key").expect("key");
    let networks: ResolvedNetworks = Arc::from([
        "192.0.2.1/32".parse::<IpNet>().expect("network"),
        "2001:db8::1/128".parse::<IpNet>().expect("network"),
    ]);
    manager
        .inner
        .bookkeeping
        .lock()
        .resolutions
        .insert(key.clone(), networks);

    let first = manager
        .inner
        .bookkeeping
        .lock()
        .resolutions
        .get(&key)
        .cloned()
        .expect("resolution");
    let second = manager
        .inner
        .bookkeeping
        .lock()
        .resolutions
        .get(&key)
        .cloned()
        .expect("resolution");

    assert!(Arc::ptr_eq(&first, &second));
}

#[test]
fn expand_with_networks_preserves_explicit_set_mode_above_cartesian_cap() {
    let explicit_nets: Vec<IpNet> = (0..80)
        .map(|i| {
            let b = u32::try_from(i).expect("idx").to_be_bytes();
            IpNet::new(std::net::Ipv4Addr::new(10, b[1], b[2], b[3]).into(), 32).expect("net")
        })
        .collect();
    let rule = Rule::builder("set-domain", Action::Block, Direction::Outbound)
        .remote_address_set(explicit_nets)
        .remote_domain("example.com")
        .expect("domain")
        .build()
        .expect("set domain rule");

    let resolved = ["203.0.113.5/32".parse::<IpNet>().expect("resolved")];
    let expanded =
        expand_with_networks(&rule, &resolved, Some(65_536)).expect("must preserve set mode");
    assert_eq!(expanded.address_set_mode(), AddressSetMode::Set);
    assert_eq!(expanded.remote_addresses().len(), 81);
}

#[test]
fn dual_stack_resolution_filters_to_ipv4_on_ipv4_only_backend() {
    let rule = Rule::builder("v4-only", Action::Block, Direction::Outbound)
        .remote_domain("dual.example")
        .expect("domain")
        .build()
        .expect("rule");
    let support = FamilySupport::for_rule(&rule, false);
    let raw = [
        "192.0.2.1/32".parse::<IpNet>().expect("v4"),
        "2001:db8::1/128".parse::<IpNet>().expect("v6"),
    ];
    let filtered = support.filter(&raw);
    assert_eq!(filtered, vec!["192.0.2.1/32".parse::<IpNet>().expect("v4")]);
}
