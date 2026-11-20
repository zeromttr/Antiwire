// Manual Binary Fuse performance harness. `AHashSet` is retained only as the
// pre-migration baseline used for before/after measurements. The benchmark
// needs allocator-wide visibility to report live and peak bytes.
#![allow(unsafe_code)]

use std::alloc::{GlobalAlloc, Layout, System};
use std::hint::black_box;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Barrier};
use std::time::{Duration, Instant};

use ahash::{AHashMap, AHashSet};
use antiwire_policy::{
    BlocklistBuilder, RuleDirection, RuleEngine, RuleSnapshot, TargetType, Verdict,
};
use parking_lot::RwLock;

struct TrackingAllocator;

static LIVE_BYTES: AtomicUsize = AtomicUsize::new(0);
static PEAK_BYTES: AtomicUsize = AtomicUsize::new(0);
static ALLOCATION_COUNT: AtomicUsize = AtomicUsize::new(0);

unsafe impl GlobalAlloc for TrackingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let pointer = unsafe { System.alloc(layout) };
        if !pointer.is_null() {
            ALLOCATION_COUNT.fetch_add(1, Ordering::Relaxed);
            record_allocation(layout.size());
        }
        pointer
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        unsafe { System.dealloc(pointer, layout) };
        LIVE_BYTES.fetch_sub(layout.size(), Ordering::Relaxed);
    }

    unsafe fn realloc(&self, pointer: *mut u8, old: Layout, new_size: usize) -> *mut u8 {
        let new_pointer = unsafe { System.realloc(pointer, old, new_size) };
        if !new_pointer.is_null() {
            ALLOCATION_COUNT.fetch_add(1, Ordering::Relaxed);
            if new_size >= old.size() {
                record_allocation(new_size - old.size());
            } else {
                LIVE_BYTES.fetch_sub(old.size() - new_size, Ordering::Relaxed);
            }
        }
        new_pointer
    }
}

#[global_allocator]
static ALLOCATOR: TrackingAllocator = TrackingAllocator;

fn record_allocation(bytes: usize) {
    let live = LIVE_BYTES.fetch_add(bytes, Ordering::Relaxed) + bytes;
    PEAK_BYTES.fetch_max(live, Ordering::Relaxed);
}

fn reverse_hash_pair(domain: &str) -> u64 {
    let mut h1 = 2_166_136_261_u32;
    let mut h2 = 5_381_u32;
    for byte in domain.as_bytes().iter().rev() {
        let c = byte.to_ascii_lowercase();
        h1 = h1.wrapping_mul(16_777_619) ^ u32::from(c);
        h2 = h2
            .wrapping_shl(5)
            .wrapping_add(h2)
            .wrapping_add(u32::from(c));
    }
    (u64::from(h1) << 32) | u64::from(h2)
}

fn baseline_lookup(domain: &str, dns_rules: &AHashMap<String, ()>, set: &AHashSet<u64>) -> bool {
    if dns_rules.contains_key(domain) {
        return true;
    }
    let bytes = domain.as_bytes();
    let mut h1 = 2_166_136_261_u32;
    let mut h2 = 5_381_u32;
    let mut at_tld_boundary = true;
    for i in (0..bytes.len()).rev() {
        let c = bytes[i].to_ascii_lowercase();
        h1 = h1.wrapping_mul(16_777_619) ^ u32::from(c);
        h2 = h2
            .wrapping_shl(5)
            .wrapping_add(h2)
            .wrapping_add(u32::from(c));
        if i == 0 || bytes[i - 1] == b'.' {
            if at_tld_boundary {
                at_tld_boundary = false;
                continue;
            }
            if set.contains(&((u64::from(h1) << 32) | u64::from(h2))) {
                return true;
            }
        }
    }
    false
}

fn build_baseline(domains: &[String]) -> AHashSet<u64> {
    domains
        .iter()
        .map(|domain| reverse_hash_pair(domain))
        .collect()
}

fn publish_candidate(mut engine: RuleEngine, domains: &[String]) -> RuleEngine {
    let mut builder = BlocklistBuilder::new(domains.len());
    for domain in domains {
        builder.add_domain(domain);
    }
    engine.publish_blocklist(builder.prepare().expect("construct BinaryFuse16"));
    engine
}

fn publish_named_candidate(list_count: usize, domains_per_list: usize) -> RuleEngine {
    let mut builder = BlocklistBuilder::new(list_count * domains_per_list);
    for list_index in 0..list_count {
        let name = format!("source{list_index}");
        for domain_index in 0..domains_per_list {
            builder.add_from_list(
                &name,
                &format!("d{domain_index}.source{list_index}.example"),
            );
        }
    }
    let mut engine = RuleEngine::new();
    engine.publish_blocklist(builder.prepare().expect("construct named blocklist"));
    engine
}

fn measure_build<T>(build: impl FnOnce() -> T) -> (T, Duration, usize, usize) {
    let before = LIVE_BYTES.load(Ordering::Relaxed);
    PEAK_BYTES.store(before, Ordering::Relaxed);
    let started = Instant::now();
    let value = build();
    let elapsed = started.elapsed();
    let after = LIVE_BYTES.load(Ordering::Relaxed);
    let peak = PEAK_BYTES.load(Ordering::Relaxed);
    (value, elapsed, after - before, peak - before)
}

fn measure_lookups(queries: &[String], mut lookup: impl FnMut(&str) -> bool) -> (f64, usize) {
    let repeats = (10_000_000 / queries.len()).max(1);
    let started = Instant::now();
    let mut hits = 0;
    for _ in 0..repeats {
        for query in queries {
            hits += usize::from(black_box(lookup(black_box(query))));
        }
    }
    let count = repeats * queries.len();
    let count_f64 = f64::from(u32::try_from(count).expect("lookup count fits in u32"));
    (
        started.elapsed().as_secs_f64() * 1_000_000_000.0 / count_f64,
        hits,
    )
}

fn wilson_upper_95(successes: usize, trials: usize) -> f64 {
    let trials = f64::from(u32::try_from(trials).expect("trial count fits in u32"));
    let successes = f64::from(u32::try_from(successes).expect("success count fits in u32"));
    let z = 1.644_853_626_951_472_2_f64;
    let rate = successes / trials;
    let z2 = z * z;
    (rate + z2 / (2.0 * trials) + z * ((rate * (1.0 - rate) + z2 / (4.0 * trials)) / trials).sqrt())
        / (1.0 + z2 / trials)
}

fn measure_false_positives(engine: &RuleEngine, trials: usize) -> usize {
    (0..trials)
        .filter(|i| {
            engine
                .evaluate_normalized_domain_with_source(&format!("allowed{i}.a.b.c.d.example"))
                .is_some()
        })
        .count()
}

fn measure_app_path_lookup() {
    let mut engine = RuleEngine::new();
    let _ = engine.upsert_rule(RuleSnapshot {
        id: 1,
        target_type: TargetType::App,
        target: r"c:\program files\antiwire\browser.exe".to_owned(),
        verdict: Verdict::Block,
        direction: RuleDirection::Outbound,
    });
    // An exact hit, and the usual case: a flow from another application, which
    // the block rule sends through the version-family lookup.
    for (case, path) in [
        ("exact_hit", r"C:\Program Files\Antiwire\Browser.exe"),
        (
            "family_miss",
            r"C:\Users\me\AppData\Local\Discord\app-1.0.9172\Discord.exe",
        ),
    ] {
        let queries = vec![path.to_owned()];
        let before = ALLOCATION_COUNT.load(Ordering::Relaxed);
        let (ns, hits) = measure_lookups(&queries, |app_path| {
            engine.evaluate(app_path, "", "").is_some()
        });
        let allocations = ALLOCATION_COUNT.load(Ordering::Relaxed) - before;
        println!("app_path case={case} ns_lookup={ns:.2} hits={hits} allocations={allocations}");
    }
}

fn measure_typed_ip_lookup() {
    let mut engine = RuleEngine::new();
    let _ = engine.upsert_rule(RuleSnapshot {
        id: 1,
        target_type: TargetType::Ip,
        target: "203.0.113.0/24".to_owned(),
        verdict: Verdict::Block,
        direction: RuleDirection::Outbound,
    });
    let address = "203.0.113.42".parse().expect("address");
    let queries = vec!["typed-ip".to_owned()];
    let (ns, hits) = measure_lookups(&queries, |_| {
        engine.evaluate_with_ip("", address, "").is_some()
    });
    println!("typed_ip ns_lookup={ns:.2} hits={hits}");
}

fn measure_attribution_lookup() {
    const LOOKUPS: u32 = 200_000;
    for list_count in [8, 32, 128] {
        let engine = publish_named_candidate(list_count, 100);
        let before = ALLOCATION_COUNT.load(Ordering::Relaxed);
        let started = Instant::now();
        let mut names_found = 0;
        for _ in 0..LOOKUPS {
            names_found +=
                black_box(engine.matching_blocklists(black_box("sub.d0.source0.example"))).len();
        }
        let elapsed = started.elapsed();
        let allocations = ALLOCATION_COUNT.load(Ordering::Relaxed) - before;
        let ns = elapsed.as_secs_f64() * 1_000_000_000.0 / f64::from(LOOKUPS);
        println!(
            "attribution lists={list_count} ns_lookup={ns:.2} allocations={allocations} names_found={names_found}"
        );
    }
}

fn measure_dns_attribution_flow() {
    const LOOKUPS: u32 = 200_000;
    let engine = publish_named_candidate(32, 100);

    // Eager models the old query path plus its admitted-event queue clone.
    // Lazy models resolving normalized names only after throttle admission and
    // moving that owned result directly into the queue.
    for admit_every in [1, 10, 100] {
        for lazy in [false, true] {
            let before = ALLOCATION_COUNT.load(Ordering::Relaxed);
            let started = Instant::now();
            let mut names_found = 0;
            for lookup in 0..LOOKUPS {
                let domain = black_box("sub.d0.source0.example");
                black_box(
                    engine
                        .evaluate_normalized_domain_with_source(domain)
                        .expect("blocked benchmark domain"),
                );

                let admitted = lookup % admit_every == 0;
                if lazy {
                    if admitted {
                        let names = engine.matching_normalized_blocklists(domain);
                        names_found += names.len();
                        black_box(names);
                    }
                } else {
                    let names = engine.matching_blocklists(domain);
                    names_found += names.len();
                    if admitted {
                        black_box(names.clone());
                    }
                    black_box(names);
                }
            }
            let elapsed = started.elapsed();
            let allocations = ALLOCATION_COUNT.load(Ordering::Relaxed) - before;
            let ns = elapsed.as_secs_f64() * 1_000_000_000.0 / f64::from(LOOKUPS);
            let flow = if lazy { "lazy" } else { "eager" };
            println!(
                "dns_attribution flow={flow} admit_every={admit_every} ns_query={ns:.2} allocations={allocations} names_found={names_found}"
            );
        }
    }
}

fn measure_named_build() {
    const RELATIONSHIPS: usize = 1_000_000;
    for list_count in [8, 32, 128] {
        let domains_per_list = RELATIONSHIPS / list_count;
        let (engine, elapsed, live, peak) =
            measure_build(|| publish_named_candidate(list_count, domains_per_list));
        println!(
            "named_build lists={list_count} relationships={} build_ms={:.2} live_bytes={live} peak_bytes={peak}",
            list_count * domains_per_list,
            elapsed.as_secs_f64() * 1_000.0
        );
        drop(engine);
    }
}

fn measure_deep_lookup() {
    let ordinary: Vec<String> = (0..100_000)
        .map(|index| format!("d{index}.ads.example"))
        .collect();
    let ordinary_engine = publish_candidate(RuleEngine::new(), &ordinary);

    let mut deep: Vec<String> = (0..100_000)
        .map(|index| format!("d{index}.a.b.c.d.e.deep.example"))
        .collect();
    deep.extend(ordinary);
    let deep_engine = publish_candidate(RuleEngine::new(), &deep);

    let query = format!("{}.allowed.example", vec!["x"; 100].join("."));
    let queries = [query];
    for (label, engine) in [("ordinary", ordinary_engine), ("deep", deep_engine)] {
        let (ns, hits) = measure_lookups(&queries, |domain| {
            engine
                .evaluate_normalized_domain_with_source(domain)
                .is_some()
        });
        println!("deep_lookup table={label} ns_lookup={ns:.2} hits={hits}");
    }
}

fn measure_build_scenario(label: &str, domains: &[String]) {
    let (set, set_time, set_live, set_peak) = measure_build(|| build_baseline(domains));
    println!(
        "scenario={label} AHashSet n={} build_ms={:.2} live_bytes={set_live} peak_bytes={set_peak}",
        domains.len(),
        set_time.as_secs_f64() * 1_000.0
    );
    drop(set);

    let empty_engine = RuleEngine::new();
    let (engine, filter_time, filter_live, filter_peak) =
        measure_build(|| publish_candidate(empty_engine, domains));
    println!(
        "scenario={label} BinaryFuse16 n={} build_ms={:.2} live_bytes={filter_live} peak_bytes={filter_peak}",
        domains.len(),
        filter_time.as_secs_f64() * 1_000.0
    );
    drop(engine);
}

fn measure_concurrent_rebuild() {
    let initial: Vec<String> = (0..100_000)
        .map(|i| format!("initial{i}.ads.example"))
        .collect();
    let replacement: Vec<String> = (0..1_000_000)
        .map(|i| format!("replacement{i}.ads.example"))
        .collect();
    let engine = Arc::new(RwLock::new(publish_candidate(RuleEngine::new(), &initial)));
    let barrier = Arc::new(Barrier::new(2));
    let stop = Arc::new(AtomicBool::new(false));
    let reader_engine = Arc::clone(&engine);
    let reader_barrier = Arc::clone(&barrier);
    let reader_stop = Arc::clone(&stop);
    let reader = std::thread::spawn(move || {
        let mut latencies = Vec::with_capacity(200_000);
        reader_barrier.wait();
        while !reader_stop.load(Ordering::Acquire) || latencies.len() < 200_000 {
            let started = Instant::now();
            black_box(
                reader_engine
                    .read()
                    .evaluate_normalized_domain_with_source("allowed.concurrent.example"),
            );
            latencies.push(started.elapsed().as_nanos());
        }
        latencies
    });
    barrier.wait();

    let mut builder = BlocklistBuilder::new(replacement.len());
    for domain in &replacement {
        builder.add_domain(domain);
    }
    let prepared = builder.prepare().expect("prepare concurrent replacement");
    let publish_started = Instant::now();
    engine.write().publish_blocklist(prepared);
    let publish_ns = publish_started.elapsed().as_nanos();
    stop.store(true, Ordering::Release);

    let mut latencies = reader.join().expect("join concurrent reader");
    latencies.sort_unstable();
    let p99 = latencies[latencies.len() * 99 / 100];
    let max = *latencies.last().expect("latency sample");
    println!(
        "concurrent_rebuild samples={} p99_ns={p99} max_ns={max} publish_ns={publish_ns}",
        latencies.len()
    );
}

fn main() {
    const ACCURACY_TRIALS: usize = 10_000_000;

    if std::env::args().any(|argument| argument == "--app-path") {
        measure_app_path_lookup();
        return;
    }
    if std::env::args().any(|argument| argument == "--ip-address") {
        measure_typed_ip_lookup();
        return;
    }
    if std::env::args().any(|argument| argument == "--attribution") {
        measure_attribution_lookup();
        return;
    }
    if std::env::args().any(|argument| argument == "--dns-attribution") {
        measure_dns_attribution_flow();
        return;
    }
    if std::env::args().any(|argument| argument == "--named-build") {
        measure_named_build();
        return;
    }
    if std::env::args().any(|argument| argument == "--deep-lookup") {
        measure_deep_lookup();
        return;
    }

    println!(
        "blocklist benchmark; rustc={}",
        option_env!("RUSTC_VERSION").unwrap_or("record with `rustc --version`")
    );
    for size in [1_000_usize, 100_000, 300_000, 1_000_000, 1_048_577] {
        let mut domains: Vec<String> = (0..size).map(|i| format!("d{i}.ads.example")).collect();
        domains.push("localhost".to_owned());
        let queries: Vec<String> = (0..size.min(100_000))
            .map(|i| {
                if i % 2 == 0 {
                    format!("sub.d{}.ads.example", i % size)
                } else {
                    format!("allowed{i}.example.org")
                }
            })
            .collect();

        let dns_rules = AHashMap::new();
        let (set, build, live, peak) = measure_build(|| build_baseline(&domains));
        let (ns, hits) =
            measure_lookups(&queries, |domain| baseline_lookup(domain, &dns_rules, &set));
        println!(
            "AHashSet n={size} build_ms={:.2} live_bytes={live} peak_bytes={peak} ns_lookup={ns:.2} hits={hits}",
            build.as_secs_f64() * 1_000.0
        );
        drop(set);

        let empty_engine = RuleEngine::new();
        let (engine, build, live, peak) =
            measure_build(|| publish_candidate(empty_engine, &domains));
        let (ns, hits) = measure_lookups(&queries, |domain| {
            engine
                .evaluate_normalized_domain_with_source(domain)
                .is_some()
        });
        println!(
            "BinaryFuse16 integrated n={size} build_ms={:.2} live_bytes={live} peak_bytes={peak} ns_lookup={ns:.2} hits={hits}",
            build.as_secs_f64() * 1_000.0
        );
        drop(engine);
    }

    for build_number in 1..=3 {
        let mut domains: Vec<String> = (0..1_000_000)
            .map(|i| format!("d{i}.ads.example"))
            .collect();
        domains.push("localhost".to_owned());
        let engine = publish_candidate(RuleEngine::new(), &domains);
        let false_positives = measure_false_positives(&engine, ACCURACY_TRIALS);
        let upper = wilson_upper_95(false_positives, ACCURACY_TRIALS);
        println!(
            "accuracy build={build_number} trials={ACCURACY_TRIALS} false_positives={false_positives} one_sided_95_upper={upper:.8}"
        );
    }

    let duplicate_heavy: Vec<String> = (0..1_000_000)
        .map(|i| format!("d{}.duplicate.example", i % 100_000))
        .collect();
    measure_build_scenario("duplicate-heavy", &duplicate_heavy);
    let deep_heavy: Vec<String> = (0..1_000_000)
        .map(|i| format!("d{i}.a.b.c.d.e.example"))
        .collect();
    measure_build_scenario("deep-heavy", &deep_heavy);
    measure_concurrent_rebuild();
}
