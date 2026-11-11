use antiwire_policy::{
    normalize_rule, BlocklistBuilder, DomainBlockSource, RuleDirection, RuleEngine, RuleSnapshot,
    TargetType, Verdict,
};

fn load_blocklist(engine: &mut RuleEngine, domains: &[&str]) {
    let mut builder = BlocklistBuilder::new(domains.len());
    for domain in domains {
        builder.add_domain(domain);
    }
    engine.publish_blocklist(builder.prepare().expect("prepare blocklist"));
}

fn snapshot(
    id: i32,
    target_type: TargetType,
    target: impl Into<String>,
    verdict: Verdict,
    direction: RuleDirection,
) -> RuleSnapshot {
    RuleSnapshot {
        id,
        target_type,
        target: target.into(),
        verdict,
        direction,
    }
}

#[test]
fn golden_no_rules_returns_no_opinion() {
    let engine = RuleEngine::new();
    assert_eq!(
        engine.evaluate("unknown.exe", "9.9.9.9", "unknown.example"),
        None
    );
    assert_eq!(engine.evaluate_domain("unknown.example"), None);
}

#[test]
fn golden_app_rule_blocks_matching_executable() {
    let mut engine = RuleEngine::new();
    let rule = snapshot(
        1,
        TargetType::App,
        r"C:\Path\To\BlockMe.exe",
        Verdict::Block,
        RuleDirection::Outbound,
    );
    let _ = engine.upsert_rule(rule);

    assert_eq!(
        engine.evaluate(r"C:\Path\To\BlockMe.exe", "8.8.8.8", "dns.google"),
        Some(Verdict::Block)
    );
    assert_eq!(
        engine.evaluate(r"C:\Path\To\Other.exe", "8.8.8.8", "dns.google"),
        None
    );
}

#[test]
fn golden_ip_rule_blocks_destination() {
    let mut engine = RuleEngine::new();
    let _ = engine.upsert_rule(snapshot(
        2,
        TargetType::Ip,
        "1.2.3.4",
        Verdict::Block,
        RuleDirection::Outbound,
    ));

    assert_eq!(
        engine.evaluate("chrome.exe", "1.2.3.4", ""),
        Some(Verdict::Block)
    );
    assert_eq!(engine.evaluate("chrome.exe", "1.2.3.5", ""), None);
}

#[test]
fn golden_dns_rule_blocks_domain_case_insensitively() {
    let mut engine = RuleEngine::new();
    let _ = engine.upsert_rule(snapshot(
        3,
        TargetType::Dns,
        "badsite.com",
        Verdict::Block,
        RuleDirection::Outbound,
    ));

    assert_eq!(
        engine.evaluate("chrome.exe", "1.1.1.1", "badsite.com"),
        Some(Verdict::Block)
    );
    assert_eq!(
        engine.evaluate("chrome.exe", "1.1.1.1", "BadSite.Com"),
        Some(Verdict::Block)
    );
    assert_eq!(
        engine.evaluate("chrome.exe", "1.1.1.1", "goodsite.com"),
        None
    );
}

#[test]
fn golden_dns_allow_overrides_blocklist() {
    let mut engine = RuleEngine::new();
    load_blocklist(&mut engine, &["tracker.example"]);

    assert_eq!(
        engine.evaluate("app.exe", "1.1.1.1", "tracker.example"),
        Some(Verdict::Block)
    );

    let _ = engine.upsert_rule(snapshot(
        4,
        TargetType::Dns,
        "tracker.example",
        Verdict::Allow,
        RuleDirection::Outbound,
    ));

    assert_eq!(
        engine.evaluate("app.exe", "1.1.1.1", "tracker.example"),
        Some(Verdict::Allow)
    );
    assert_eq!(
        engine.evaluate_domain("tracker.example"),
        Some(Verdict::Allow)
    );
}

/// An address block wins over an application allow: the host firewall enforces
/// it that way, so the verdict says what actually happens.
#[test]
fn golden_ip_block_takes_precedence_over_app_allow() {
    let mut engine = RuleEngine::new();
    let _ = engine.upsert_rule(snapshot(
        5,
        TargetType::Ip,
        "2.2.2.2",
        Verdict::Block,
        RuleDirection::Outbound,
    ));
    let _ = engine.upsert_rule(snapshot(
        6,
        TargetType::App,
        r"C:\trusted.exe",
        Verdict::Allow,
        RuleDirection::Outbound,
    ));

    assert_eq!(
        engine.evaluate(r"C:\trusted.exe", "2.2.2.2", ""),
        Some(Verdict::Block)
    );
    assert_eq!(
        engine.evaluate(r"C:\trusted.exe", "3.3.3.3", ""),
        Some(Verdict::Allow)
    );
    assert_eq!(
        engine.evaluate(r"C:\other.exe", "2.2.2.2", ""),
        Some(Verdict::Block)
    );
}

#[test]
fn golden_blocklist_subdomain_enforcement() {
    let mut engine = RuleEngine::new();
    load_blocklist(&mut engine, &["adserver.net", "tracker.co.uk"]);

    assert_eq!(
        engine.evaluate("chrome.exe", "1.1.1.1", "adserver.net"),
        Some(Verdict::Block)
    );
    assert_eq!(
        engine.evaluate("chrome.exe", "1.1.1.1", "sub.adserver.net"),
        Some(Verdict::Block)
    );
    assert_eq!(
        engine.evaluate("chrome.exe", "1.1.1.1", "deep.sub.adserver.net"),
        Some(Verdict::Block)
    );
    assert_eq!(
        engine.evaluate("chrome.exe", "1.1.1.1", "TRACKER.CO.UK"),
        Some(Verdict::Block)
    );
}

#[test]
fn golden_evaluate_domain_matches_dns_then_blocklist() {
    let mut engine = RuleEngine::new();
    load_blocklist(&mut engine, &["blocked.example"]);

    assert_eq!(
        engine.evaluate_domain("blocked.example"),
        Some(Verdict::Block)
    );

    let _ = engine.upsert_rule(snapshot(
        7,
        TargetType::Dns,
        "blocked.example",
        Verdict::Allow,
        RuleDirection::Outbound,
    ));
    assert_eq!(
        engine.evaluate_domain("blocked.example"),
        Some(Verdict::Allow)
    );
}

#[test]
fn golden_domain_block_source_prefers_dns_rule() {
    let mut engine = RuleEngine::new();
    load_blocklist(&mut engine, &["blocked.example"]);
    assert_eq!(
        engine
            .evaluate_domain_with_source("blocked.example")
            .and_then(|decision| decision.source),
        Some(DomainBlockSource::Blocklist)
    );

    let _ = engine.upsert_rule(snapshot(
        8,
        TargetType::Dns,
        "blocked.example",
        Verdict::Block,
        RuleDirection::Outbound,
    ));
    assert_eq!(
        engine
            .evaluate_domain_with_source("blocked.example")
            .and_then(|decision| decision.source),
        Some(DomainBlockSource::DnsRule)
    );
}

#[test]
fn golden_rule_normalization_matches_csharp() {
    let normalized = normalize_rule(
        TargetType::Dns,
        "Mixed.Example.",
        Verdict::Allow,
        RuleDirection::Outbound,
    )
    .expect("valid dns rule");
    assert_eq!(normalized.target, "mixed.example");
    assert_eq!(normalized.verdict, Verdict::Allow);

    let wildcard = normalize_rule(
        TargetType::Dns,
        "*.Mixed.Example.",
        Verdict::Allow,
        RuleDirection::Outbound,
    )
    .expect("valid wildcard dns rule");
    assert_eq!(wildcard.target, "*.mixed.example");
}

#[test]
fn golden_bare_domain_covers_host_and_subdomains() {
    let mut engine = RuleEngine::new();
    let allow = normalize_rule(
        TargetType::Dns,
        "example.com",
        Verdict::Allow,
        RuleDirection::Outbound,
    )
    .expect("bare allow");
    let _ = engine.upsert_rule(RuleSnapshot { id: 1, ..allow });
    load_blocklist(&mut engine, &["ads.example.com", "a.b.example.com"]);

    assert_eq!(engine.evaluate_domain("example.com"), Some(Verdict::Allow));
    assert_eq!(
        engine.evaluate_domain("ads.example.com"),
        Some(Verdict::Allow)
    );
    assert_eq!(
        engine.evaluate_domain("a.b.example.com"),
        Some(Verdict::Allow)
    );
}

#[test]
fn golden_wildcard_allow_covers_nested_subdomains_not_apex() {
    let mut engine = RuleEngine::new();
    let allow = normalize_rule(
        TargetType::Dns,
        "*.example.com",
        Verdict::Allow,
        RuleDirection::Outbound,
    )
    .expect("wildcard allow");
    let _ = engine.upsert_rule(RuleSnapshot { id: 1, ..allow });
    load_blocklist(
        &mut engine,
        &["example.com", "ads.example.com", "a.b.example.com"],
    );

    assert_eq!(
        engine.evaluate_domain("ads.example.com"),
        Some(Verdict::Allow)
    );
    assert_eq!(
        engine.evaluate_domain("a.b.example.com"),
        Some(Verdict::Allow)
    );
    assert_eq!(engine.evaluate_domain("example.com"), Some(Verdict::Block));
}

#[test]
fn golden_more_specific_user_dns_rule_wins() {
    let mut engine = RuleEngine::new();
    let wildcard_allow = normalize_rule(
        TargetType::Dns,
        "*.example.com",
        Verdict::Allow,
        RuleDirection::Outbound,
    )
    .expect("wildcard allow");
    let exact_block = normalize_rule(
        TargetType::Dns,
        "ads.example.com",
        Verdict::Block,
        RuleDirection::Outbound,
    )
    .expect("exact block");
    let nested_allow = normalize_rule(
        TargetType::Dns,
        "*.ads.example.com",
        Verdict::Allow,
        RuleDirection::Outbound,
    )
    .expect("nested wildcard allow");
    let _ = engine.upsert_rule(RuleSnapshot {
        id: 1,
        ..wildcard_allow
    });
    let _ = engine.upsert_rule(RuleSnapshot {
        id: 2,
        ..exact_block
    });
    let _ = engine.upsert_rule(RuleSnapshot {
        id: 3,
        ..nested_allow
    });

    assert_eq!(
        engine.evaluate_domain("ads.example.com"),
        Some(Verdict::Block)
    );
    assert_eq!(
        engine.evaluate_domain("cdn.ads.example.com"),
        Some(Verdict::Allow)
    );
    assert_eq!(
        engine.evaluate_domain("www.example.com"),
        Some(Verdict::Allow)
    );
}

#[test]
fn golden_tld_wildcard_allow_loses_to_exact_block() {
    let mut engine = RuleEngine::new();
    load_blocklist(&mut engine, &["ads.other.test"]);
    let tld_allow = normalize_rule(
        TargetType::Dns,
        "*.com",
        Verdict::Allow,
        RuleDirection::Outbound,
    )
    .expect("tld allow");
    let exact_block = normalize_rule(
        TargetType::Dns,
        "example.com",
        Verdict::Block,
        RuleDirection::Outbound,
    )
    .expect("exact block");
    let _ = engine.upsert_rule(RuleSnapshot { id: 1, ..tld_allow });
    let _ = engine.upsert_rule(RuleSnapshot {
        id: 2,
        ..exact_block
    });

    assert_eq!(engine.evaluate_domain("example.com"), Some(Verdict::Block));
    assert_eq!(engine.evaluate_domain("google.com"), Some(Verdict::Allow));
    assert_eq!(
        engine.evaluate_domain("ads.example.com"),
        Some(Verdict::Block)
    );
    assert_eq!(
        engine.evaluate_domain("ads.other.test"),
        Some(Verdict::Block)
    );
}

#[test]
fn golden_bare_tld_covers_deep_names() {
    let mut engine = RuleEngine::new();
    let tld_block = normalize_rule(
        TargetType::Dns,
        ".com",
        Verdict::Block,
        RuleDirection::Outbound,
    )
    .expect("leading-dot TLD");
    let _ = engine.upsert_rule(RuleSnapshot { id: 1, ..tld_block });

    assert_eq!(engine.evaluate_domain("com"), Some(Verdict::Block));
    assert_eq!(engine.evaluate_domain("evil.com"), Some(Verdict::Block));
    assert_eq!(engine.evaluate_domain("a.b.evil.com"), Some(Verdict::Block));
    assert_eq!(engine.evaluate_domain("example.org"), None);
}

#[test]
fn golden_tld_wildcard_skips_apex_and_covers_deep_names() {
    let mut engine = RuleEngine::new();
    let tld_block = normalize_rule(
        TargetType::Dns,
        "*.com",
        Verdict::Block,
        RuleDirection::Outbound,
    )
    .expect("tld wildcard");
    let _ = engine.upsert_rule(RuleSnapshot { id: 1, ..tld_block });

    assert_eq!(engine.evaluate_domain("com"), None);
    assert_eq!(engine.evaluate_domain("evil.com"), Some(Verdict::Block));
    assert_eq!(engine.evaluate_domain("a.b.evil.com"), Some(Verdict::Block));
}

#[test]
fn golden_idn_tld_wildcard_matches_punycode_and_unicode_queries() {
    let mut engine = RuleEngine::new();
    let tld_block = normalize_rule(
        TargetType::Dns,
        "*.рф",
        Verdict::Block,
        RuleDirection::Outbound,
    )
    .expect("idn wildcard");
    let _ = engine.upsert_rule(RuleSnapshot { id: 1, ..tld_block });

    assert_eq!(engine.evaluate_domain("xn--p1ai"), None);
    assert_eq!(
        engine.evaluate_domain("xn--e1afmkfd.xn--p1ai"),
        Some(Verdict::Block)
    );
    assert_eq!(engine.evaluate_domain("пример.рф"), Some(Verdict::Block));
}

#[test]
fn golden_children_wildcard_overrides_bare_parent_for_subdomains() {
    let mut engine = RuleEngine::new();
    let parent_block = normalize_rule(
        TargetType::Dns,
        "example.com",
        Verdict::Block,
        RuleDirection::Outbound,
    )
    .expect("bare block");
    let children_allow = normalize_rule(
        TargetType::Dns,
        "*.example.com",
        Verdict::Allow,
        RuleDirection::Outbound,
    )
    .expect("children allow");
    let _ = engine.upsert_rule(RuleSnapshot {
        id: 1,
        ..parent_block
    });
    let _ = engine.upsert_rule(RuleSnapshot {
        id: 2,
        ..children_allow
    });

    assert_eq!(engine.evaluate_domain("example.com"), Some(Verdict::Block));
    assert_eq!(
        engine.evaluate_domain("ads.example.com"),
        Some(Verdict::Allow)
    );
}

#[test]
fn golden_precedence_matrix() {
    let mut engine = RuleEngine::new();
    let _ = engine.upsert_rule(snapshot(
        10,
        TargetType::Ip,
        "5.5.5.5",
        Verdict::Block,
        RuleDirection::Outbound,
    ));
    let _ = engine.upsert_rule(snapshot(
        11,
        TargetType::App,
        r"C:\app\ok.exe",
        Verdict::Allow,
        RuleDirection::Outbound,
    ));
    load_blocklist(&mut engine, &["listed.example", "other-listed.example"]);
    let _ = engine.upsert_rule(snapshot(
        12,
        TargetType::Dns,
        "listed.example",
        Verdict::Allow,
        RuleDirection::Outbound,
    ));

    let cases = [
        ("x.exe", "5.5.5.5", "", Some(Verdict::Block)),
        (r"C:\app\ok.exe", "5.5.5.5", "", Some(Verdict::Block)),
        (r"C:\app\ok.exe", "1.1.1.1", "", Some(Verdict::Allow)),
        ("x.exe", "1.1.1.1", "listed.example", Some(Verdict::Allow)),
        (
            "x.exe",
            "1.1.1.1",
            "other-listed.example",
            Some(Verdict::Block),
        ),
    ];

    for (app, ip, domain, expected) in cases {
        assert_eq!(
            engine.evaluate(app, ip, domain),
            expected,
            "case app={app} ip={ip} domain={domain}"
        );
    }
}

#[test]
fn internationalized_blocklist_entries_block_queries_in_either_form() {
    let mut engine = RuleEngine::new();
    let mut builder = BlocklistBuilder::new(1);
    assert!(builder.add_from_list("idn_list", "пример.рф"));
    engine.publish_blocklist(builder.prepare().expect("prepare blocklist"));

    for query in [
        "xn--e1afmkfd.xn--p1ai",
        "ads.xn--e1afmkfd.xn--p1ai.",
        "ads.пример.рф",
    ] {
        assert_eq!(
            engine
                .evaluate_domain_with_source(query)
                .map(|decision| decision.source),
            Some(Some(DomainBlockSource::Blocklist)),
            "{query}"
        );
        assert_eq!(engine.matching_blocklists(query), ["idn_list"], "{query}");
    }
}

#[test]
fn blocklist_engine_isolated_from_rule_tables() {
    let mut engine = RuleEngine::new();
    load_blocklist(&mut engine, &["clean.com", "doubleclick.net"]);
    assert_eq!(engine.rule_count(), 0);
    assert_eq!(
        engine.evaluate_domain("doubleclick.net"),
        Some(Verdict::Block)
    );
}
