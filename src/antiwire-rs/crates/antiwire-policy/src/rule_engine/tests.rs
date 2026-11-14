use super::*;
use crate::rule::{RuleSnapshot, TargetType, Verdict};
use crate::{normalize_rule, EnforcementOp, RuleDirection};

#[test]
fn public_evaluators_match_dns_rules_with_a_trailing_root_dot() {
    for verdict in [Verdict::Block, Verdict::Allow] {
        for (target, names) in [
            (
                "example.test",
                vec!["example.test.", "EXAMPLE.TEST.", "sub.example.test."],
            ),
            (
                "*.example.test",
                vec!["sub.example.test.", "SUB.EXAMPLE.TEST."],
            ),
            ("bücher.test", vec!["BÜCHER.test.", "xn--bcher-kva.test."]),
        ] {
            let mut engine = RuleEngine::new();
            let rule =
                normalize_rule(TargetType::Dns, target, verdict, RuleDirection::Both).unwrap();
            let _ = engine.upsert_rule(RuleSnapshot { id: 1, ..rule });
            for name in names {
                assert_eq!(engine.evaluate_domain(name), Some(verdict), "{name}");
                assert_eq!(
                    engine.evaluate("", "203.0.113.1", name),
                    Some(verdict),
                    "{name}"
                );
                assert_eq!(
                    engine.evaluate_with_ip("", "203.0.113.1".parse().unwrap(), name),
                    Some(verdict),
                    "{name}"
                );
            }
            assert_eq!(engine.evaluate_domain("."), None);
            assert_eq!(engine.evaluate("", "", "."), None);
            assert_eq!(engine.evaluate_domain("unrelated.test."), None);
        }
    }
}

#[test]
fn upsert_dns_rule_emits_no_native_op() {
    let mut engine = RuleEngine::new();
    let first = normalize_rule(
        TargetType::Dns,
        "example.test",
        Verdict::Block,
        RuleDirection::Both,
    )
    .expect("first rule");
    let first = RuleSnapshot { id: 1, ..first };
    assert_eq!(engine.upsert_rule(first), []);
    assert_eq!(engine.evaluate_domain("example.test"), Some(Verdict::Block));

    let replacement = normalize_rule(
        TargetType::Dns,
        "example.test",
        Verdict::Allow,
        RuleDirection::Outbound,
    )
    .expect("replacement rule");
    let replacement = RuleSnapshot {
        id: 2,
        ..replacement
    };
    assert_eq!(engine.upsert_rule(replacement), []);
    assert_eq!(engine.evaluate_domain("example.test"), Some(Verdict::Allow));
}

#[test]
fn upsert_moves_an_existing_id_between_targets_and_types() {
    let mut engine = RuleEngine::new();

    let app = RuleSnapshot::new(
        7,
        TargetType::App,
        "old.exe",
        Verdict::Block,
        RuleDirection::Outbound,
    );
    let _ = engine.upsert_rule(app);
    let dns = RuleSnapshot::new(
        7,
        TargetType::Dns,
        "new.example",
        Verdict::Allow,
        RuleDirection::Outbound,
    );
    let ops = engine.upsert_rule(dns.clone());

    assert!(matches!(
        ops.as_slice(),
        [EnforcementOp::RemoveAppRule { rule_id: 7, .. }]
    ));
    assert_eq!(engine.evaluate("old.exe", "", ""), None);
    assert_eq!(engine.evaluate_domain("new.example"), Some(Verdict::Allow));
    assert_eq!(engine.rule_count(), 1);

    let ip = RuleSnapshot::new(
        7,
        TargetType::Ip,
        "203.0.113.0/24",
        Verdict::Block,
        RuleDirection::Outbound,
    );
    let _ = engine.upsert_rule(ip);
    assert_eq!(engine.evaluate_domain("new.example"), None);
    assert_eq!(engine.evaluate("", "203.0.113.4", ""), Some(Verdict::Block));
    assert_eq!(engine.rule_count(), 1);

    let removed = engine.remove_rule(&dns);
    assert!(matches!(
        removed.as_slice(),
        [EnforcementOp::RemoveIpRule { rule_id: 7, .. }]
    ));
    assert_eq!(engine.evaluate("", "203.0.113.4", ""), None);
    assert_eq!(engine.rule_count(), 0);
}

#[test]
fn removing_duplicate_dns_rule_restores_previous_rule() {
    let mut engine = RuleEngine::new();
    let first = RuleSnapshot::new(
        1,
        TargetType::Dns,
        "duplicate.test",
        Verdict::Block,
        RuleDirection::Outbound,
    );
    let second = RuleSnapshot::new(
        2,
        TargetType::Dns,
        "duplicate.test",
        Verdict::Allow,
        RuleDirection::Outbound,
    );

    let _ = engine.upsert_rule(first);
    let _ = engine.upsert_rule(second.clone());
    assert_eq!(
        engine.evaluate_domain("duplicate.test"),
        Some(Verdict::Allow)
    );

    assert!(matches!(
        engine.remove_rule(&second).as_slice(),
        [EnforcementOp::RemoveDnsRule { rule_id: 2, .. }]
    ));

    assert_eq!(
        engine.evaluate_domain("duplicate.test"),
        Some(Verdict::Block)
    );
    assert_eq!(engine.rule_count(), 1);
}

#[test]
fn ip_rules_use_longest_prefix_match() {
    let mut engine = RuleEngine::new();
    let broad = normalize_rule(
        TargetType::Ip,
        "10.0.0.0/8",
        Verdict::Block,
        RuleDirection::Both,
    )
    .expect("broad rule");
    let narrow = normalize_rule(
        TargetType::Ip,
        "10.1.0.0/16",
        Verdict::Allow,
        RuleDirection::Both,
    )
    .expect("narrow rule");
    let _ = engine.upsert_rule(RuleSnapshot { id: 1, ..broad });
    let _ = engine.upsert_rule(RuleSnapshot { id: 2, ..narrow });

    assert_eq!(engine.evaluate("", "10.1.2.3", ""), Some(Verdict::Allow));
    assert_eq!(engine.evaluate("", "10.2.2.3", ""), Some(Verdict::Block));
    assert_eq!(engine.evaluate("", "192.0.2.1", ""), None);
}

#[test]
fn normalizes_host_addresses_to_full_length_prefixes() {
    let ipv4 = normalize_rule(
        TargetType::Ip,
        "192.0.2.1",
        Verdict::Block,
        RuleDirection::Outbound,
    )
    .expect("IPv4 rule");
    let ipv6 = normalize_rule(
        TargetType::Ip,
        "2001:db8::1",
        Verdict::Block,
        RuleDirection::Outbound,
    )
    .expect("IPv6 rule");

    assert_eq!(ipv4.target, "192.0.2.1/32");
    assert_eq!(ipv6.target, "2001:db8::1/128");
}

#[test]
fn typed_ip_evaluation_matches_text_evaluation() {
    let mut engine = RuleEngine::new();
    let rule = normalize_rule(
        TargetType::Ip,
        "203.0.113.0/24",
        Verdict::Block,
        RuleDirection::Outbound,
    )
    .expect("IP rule");
    let _ = engine.upsert_rule(RuleSnapshot { id: 1, ..rule });

    assert_eq!(
        engine.evaluate_with_ip("", "203.0.113.42".parse().expect("address"), ""),
        engine.evaluate("", "203.0.113.42", "")
    );
}

#[test]
fn published_dns_view_matches_engine_and_does_not_need_the_writer() {
    let mut engine = RuleEngine::new();
    let rule = normalize_rule(
        TargetType::Dns,
        "blocked.example",
        Verdict::Block,
        RuleDirection::Both,
    )
    .expect("rule");
    let _ = engine.upsert_rule(RuleSnapshot { id: 1, ..rule });
    let handle = engine.dns_policy_handle();
    assert_eq!(
        handle
            .load()
            .evaluate_normalized_domain_with_source("blocked.example")
            .map(|decision| decision.verdict),
        Some(Verdict::Block)
    );
    assert_eq!(
        handle
            .load()
            .evaluate_normalized_domain_with_source("blocked.example"),
        engine.evaluate_normalized_domain_with_source("blocked.example")
    );
}

fn dns_block_rule(id: i32, domain: &str) -> RuleSnapshot {
    let rule = normalize_rule(TargetType::Dns, domain, Verdict::Block, RuleDirection::Both)
        .expect("dns rule");
    RuleSnapshot { id, ..rule }
}

fn view_blocks(handle: &PublishedDnsPolicyHandle, domain: &str) -> bool {
    handle
        .load()
        .evaluate_normalized_domain_with_source(domain)
        .is_some_and(|decision| decision.verdict == Verdict::Block)
}

fn ruleset_is_complete(handle: &PublishedDnsPolicyHandle, prefix: &str, other: &str) -> bool {
    (0..8).all(|index| {
        view_blocks(handle, &format!("{prefix}{index}.example"))
            && !view_blocks(handle, &format!("{other}{index}.example"))
    })
}

#[test]
fn replace_user_rules_publishes_once_and_never_shows_a_partial_view() {
    let mut engine = RuleEngine::new();
    let old: Vec<_> = (0..8)
        .map(|index| dns_block_rule(index + 1, &format!("old{index}.example")))
        .collect();
    for rule in old {
        let _ = engine.upsert_rule(rule);
    }
    let handle = engine.dns_policy_handle();
    let generation_before = handle.generation();
    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let saw_partial = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let saw_new = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let reads_after_ready = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
    let ready = std::sync::Arc::new(std::sync::Barrier::new(2));
    std::thread::scope(|scope| {
        let reader_handle = handle.clone();
        let reader_stop = std::sync::Arc::clone(&stop);
        let reader_partial = std::sync::Arc::clone(&saw_partial);
        let reader_new = std::sync::Arc::clone(&saw_new);
        let reader_reads = std::sync::Arc::clone(&reads_after_ready);
        let reader_gate = std::sync::Arc::clone(&ready);
        scope.spawn(move || {
            while !ruleset_is_complete(&reader_handle, "old", "new") {
                std::thread::yield_now();
            }
            reader_gate.wait();
            while !reader_stop.load(std::sync::atomic::Ordering::Acquire) {
                reader_reads.fetch_add(1, std::sync::atomic::Ordering::AcqRel);
                let old_complete = ruleset_is_complete(&reader_handle, "old", "new");
                let new_complete = ruleset_is_complete(&reader_handle, "new", "old");
                if new_complete {
                    reader_new.store(true, std::sync::atomic::Ordering::Release);
                }
                if !old_complete && !new_complete {
                    reader_partial.store(true, std::sync::atomic::Ordering::Release);
                }
            }
        });
        ready.wait();
        while reads_after_ready.load(std::sync::atomic::Ordering::Acquire) == 0 {
            std::thread::yield_now();
        }
        let replacement: Vec<_> = (0..8)
            .map(|index| dns_block_rule(index + 101, &format!("new{index}.example")))
            .collect();
        engine.replace_user_rules(replacement, Vec::new());
        while !saw_new.load(std::sync::atomic::Ordering::Acquire) {
            std::thread::yield_now();
        }
        stop.store(true, std::sync::atomic::Ordering::Release);
    });
    assert!(
        reads_after_ready.load(std::sync::atomic::Ordering::Acquire) > 0,
        "the reader must evaluate the published view during replacement"
    );
    assert!(
        !saw_partial.load(std::sync::atomic::Ordering::Acquire),
        "DNS readers must only observe the previous complete ruleset or the replacement"
    );
    assert_eq!(handle.generation(), generation_before + 1);
    assert!(view_blocks(&handle, "new0.example"));
    assert!(!view_blocks(&handle, "old0.example"));
}

#[test]
fn a_stale_publisher_cannot_overwrite_a_newer_dns_view() {
    let mut engine = RuleEngine::new();
    let _ = engine.upsert_rule(dns_block_rule(1, "kept.example"));
    let handle = engine.dns_policy_handle();
    let stale_generation = handle.generation();
    let _ = engine.upsert_rule(dns_block_rule(2, "newer.example"));
    assert!(view_blocks(&handle, "newer.example"));

    handle.install_stale_empty_for_test(stale_generation);

    assert!(
        view_blocks(&handle, "newer.example"),
        "an older generation must not replace a newer published view"
    );
    assert!(view_blocks(&handle, "kept.example"));
}

fn app_rule(id: i32, target: &str, verdict: Verdict) -> RuleSnapshot {
    RuleSnapshot::new(
        id,
        TargetType::App,
        target,
        verdict,
        RuleDirection::Outbound,
    )
}

#[test]
fn bare_host_rule_covers_disambiguated_identities() {
    let mut engine = RuleEngine::new();
    let _ = engine.upsert_rule(app_rule(
        1,
        r"C:\Windows\System32\rundll32.exe",
        Verdict::Block,
    ));
    let _ = engine.upsert_rule(app_rule(
        2,
        r"C:\Windows\System32\svchost.exe",
        Verdict::Block,
    ));
    // Both disambiguated shapes share the `exe::label` convention, so one
    // host-prefix fallback covers svchost rows and rundll32 rows alike.
    assert_eq!(
        engine.evaluate(
            r"C:\Windows\System32\rundll32.exe::shell32.dll,Control_RunDLL",
            "",
            "",
        ),
        Some(Verdict::Block)
    );
    assert_eq!(
        engine.evaluate(r"C:\Windows\System32\svchost.exe::Dnscache", "", "",),
        Some(Verdict::Block)
    );
    // The bare host itself still matches, and unrelated hosts are unaffected.
    assert_eq!(
        engine.evaluate(r"C:\Windows\System32\rundll32.exe", "", "",),
        Some(Verdict::Block)
    );
    assert_eq!(
        engine.evaluate(r"C:\Windows\System32\curl.exe", "", "",),
        None
    );
}

#[test]
fn disambiguated_identity_rule_beats_the_host_rule() {
    let mut engine = RuleEngine::new();
    let _ = engine.upsert_rule(app_rule(
        1,
        r"C:\Windows\System32\svchost.exe",
        Verdict::Block,
    ));
    let _ = engine.upsert_rule(app_rule(
        2,
        r"C:\Windows\System32\svchost.exe::Dnscache",
        Verdict::Allow,
    ));
    // The exact identity wins, so one service can be exempted while the host
    // rule still covers every other disambiguated row.
    assert_eq!(
        engine.evaluate(r"C:\Windows\System32\svchost.exe::Dnscache", "", "",),
        Some(Verdict::Allow)
    );
    assert_eq!(
        engine.evaluate(r"C:\Windows\System32\svchost.exe::BITS", "", "",),
        Some(Verdict::Block)
    );
}

#[test]
fn an_app_rule_covers_later_versions_of_the_same_install() {
    let mut engine = RuleEngine::new();
    let _ = engine.upsert_rule(app_rule(
        1,
        r"c:\users\me\appdata\local\githubdesktop\app-3.6.5\githubdesktop.exe",
        Verdict::Block,
    ));
    assert_eq!(
        engine.evaluate(
            r"C:\Users\me\AppData\Local\GitHubDesktop\app-3.6.6\GitHubDesktop.exe",
            "",
            "",
        ),
        Some(Verdict::Block)
    );
    // A copy outside the install root is still a different application.
    assert_eq!(
        engine.evaluate(r"C:\Users\me\Desktop\GitHubDesktop.exe", "", ""),
        None
    );
}

/// The regression this guards: an executable dropped into a new version folder
/// of a user-writable install inherited the app's allow rule.
#[test]
fn a_family_allow_is_not_inherited_by_a_new_version() {
    let mut engine = RuleEngine::new();
    let _ = engine.upsert_rule(app_rule(
        1,
        r"c:\users\me\appdata\local\discord\app-1.0.9\discord.exe",
        Verdict::Allow,
    ));
    assert_eq!(
        engine.evaluate(
            r"C:\Users\me\AppData\Local\Discord\app-9.9.9\Discord.exe",
            "",
            "",
        ),
        None
    );
    assert_eq!(
        engine.evaluate(
            r"C:\Users\me\AppData\Local\Discord\app-1.0.9\Discord.exe",
            "",
            "",
        ),
        Some(Verdict::Allow),
        "the exact path keeps its rule"
    );
}

#[test]
fn an_exact_app_rule_beats_the_family_rule_for_the_same_path() {
    let mut engine = RuleEngine::new();
    let _ = engine.upsert_rule(app_rule(1, r"c:\apps\app-1.0\app.exe", Verdict::Block));
    let _ = engine.upsert_rule(app_rule(2, r"c:\apps\app-2.0\app.exe", Verdict::Allow));

    // Exactly on 2.0, the most recently added exact rule wins.
    assert_eq!(
        engine.evaluate(r"C:\apps\app-2.0\app.exe", "", ""),
        Some(Verdict::Allow)
    );
    // On an unruled 3.0, the family's latest rule is an allow, which a sibling
    // executable does not inherit: its publisher has not been checked.
    assert_eq!(engine.evaluate(r"C:\apps\app-3.0\app.exe", "", ""), None);

    // Removing the latest family rule restores the earlier one.
    let removed = RuleSnapshot::new(
        2,
        TargetType::App,
        r"c:\apps\app-2.0\app.exe",
        Verdict::Allow,
        RuleDirection::Outbound,
    );
    let _ = engine.remove_rule(&removed);
    assert_eq!(
        engine.evaluate(r"C:\apps\app-3.0\app.exe", "", ""),
        Some(Verdict::Block)
    );
}

#[test]
fn host_prefix_lookup_needs_a_non_empty_executable() {
    assert_eq!(super::evaluate::host_exe_prefix(""), None);
    assert_eq!(super::evaluate::host_exe_prefix("::Dnscache"), None);
    assert_eq!(
        super::evaluate::host_exe_prefix(r"C:\Windows\System32\curl.exe"),
        None
    );
    assert_eq!(
        super::evaluate::host_exe_prefix(r"C:\Windows\System32\svchost.exe::Dnscache"),
        Some(r"C:\Windows\System32\svchost.exe")
    );
}

/// The regression this guards: a DLL run through rundll32 rewrote its own
/// command line to claim a module that had an allow rule, and inherited it.
#[test]
fn an_allow_on_a_rundll32_module_is_not_trusted_but_a_block_is() {
    let allowed_module = r"c:\windows\system32\rundll32.exe::shell32.dll,control_rundll";
    let blocked_module = r"c:\windows\system32\rundll32.exe::evil.dll,run";
    let mut engine = RuleEngine::new();
    let _ = engine.upsert_rule(app_rule(1, allowed_module, Verdict::Allow));
    let _ = engine.upsert_rule(app_rule(2, blocked_module, Verdict::Block));

    assert_eq!(engine.evaluate(allowed_module, "", ""), None);
    assert_eq!(
        engine.evaluate(blocked_module, "", ""),
        Some(Verdict::Block)
    );

    // svchost service names come from the Service Control Manager and keep
    // their allows.
    let service = r"c:\windows\system32\svchost.exe::dnscache";
    let _ = engine.upsert_rule(app_rule(3, service, Verdict::Allow));
    assert_eq!(engine.evaluate(service, "", ""), Some(Verdict::Allow));
}
