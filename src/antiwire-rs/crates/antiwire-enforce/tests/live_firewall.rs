//! Live firewall integration tests (elevated privileges required).

use antiwire_enforce::EnforcementClient;
use antiwire_policy::{EnforcementOp, RuleDirection, Verdict};

#[test]
#[ignore = "requires administrator and native firewall access"]
fn live_doh_block_rules() {
    let client = EnforcementClient::try_new().expect("firewall worker");
    client.start().expect("start");
    client
        .apply(EnforcementOp::AddDohBlock {
            doh_ips: vec!["1.1.1.1".to_owned()],
            port: 443,
        })
        .expect("doh block");
    client
        .apply(EnforcementOp::RemoveDohBlocks)
        .expect("remove");
    client.stop().expect("stop");
}

/// Installs a country block that must split, so the resulting native rules can
/// be inspected in the Windows firewall UI.
#[test]
#[ignore = "requires administrator and native firewall access"]
fn live_country_block_names_are_readable() {
    use std::sync::Arc;

    // Shrink the ceiling to exercise the multi-part path without generating
    // tens of thousands of networks.
    let networks: Arc<[ipnet::IpNet]> = (0..7u32)
        .map(|index| {
            let octets = index.to_be_bytes();
            ipnet::IpNet::new(
                std::net::Ipv4Addr::new(240, octets[1], octets[2], octets[3]).into(),
                32,
            )
            .expect("net")
        })
        .collect();

    std::env::set_var("FIREW_MAX_ADDRESS_SET_ENTRIES", "3");
    let client = EnforcementClient::try_new().expect("firewall worker");
    client.start().expect("start");
    let installed = client.apply(EnforcementOp::AddCountryBlock {
        rule_id: 1,
        code: "US".to_owned(),
        networks: Arc::clone(&networks),
        verdict: Verdict::Block,
        direction: RuleDirection::Both,
    });
    println!("install result: {installed:?}");

    // Optionally hold the rules so the OS view can be inspected before cleanup.
    if std::env::var("FIREW_KEEP_RULES").is_ok() {
        println!("holding rules for 20s for inspection...");
        std::thread::sleep(std::time::Duration::from_secs(20));
    }

    let _ = client.apply(EnforcementOp::RemoveCountryBlock {
        rule_id: 1,
        code: "US".to_owned(),
    });
    let _ = client.stop();
}

/// Replaces a multi-part country block in place, then removes it. The re-add at
/// the end fails on a duplicate key if the removal left any native rule behind.
#[test]
#[ignore = "requires administrator and native firewall access"]
fn live_country_block_replace_then_remove_leaves_nothing() {
    use std::sync::Arc;

    let networks = |count: u32| -> Arc<[ipnet::IpNet]> {
        (0..count)
            .map(|index| {
                let octets = index.to_be_bytes();
                ipnet::IpNet::new(
                    std::net::Ipv4Addr::new(240, octets[1], octets[2], octets[3]).into(),
                    32,
                )
                .expect("net")
            })
            .collect()
    };
    let add = |count: u32| EnforcementOp::AddCountryBlock {
        rule_id: 7,
        code: "ZZ".to_owned(),
        networks: networks(count),
        verdict: Verdict::Block,
        direction: RuleDirection::Both,
    };
    let remove = EnforcementOp::RemoveCountryBlock {
        rule_id: 7,
        code: "ZZ".to_owned(),
    };

    std::env::set_var("FIREW_MAX_ADDRESS_SET_ENTRIES", "3");
    let client = EnforcementClient::try_new().expect("firewall worker");
    client.start().expect("start");

    // Three parts, then two: one part is updated in place, one is retired.
    client.apply(add(7)).expect("install three parts");
    client.apply(add(5)).expect("replace with two parts");
    // And back up to three: an existing part is updated, a new one created.
    client.apply(add(8)).expect("replace with three parts");

    client.apply(remove.clone()).expect("remove");
    client.apply(add(7)).expect("re-add after a clean removal");
    client.apply(remove).expect("final remove");
    client.stop().expect("stop");
}
