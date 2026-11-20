//! Rewriting saved AI verdicts after a settings change, with a lookup that
//! reads the store running beside it.
//!
//! Turning AI off clears every saved block verdict, and turning it back on
//! restores them, so each toggle rewrites every row. The lookup is the one a
//! DNS query makes when the decision it needs is not in memory: it takes the
//! same lock the rewrite does.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use antiwire_store::{DaemonSetting, Store};
use time::OffsetDateTime;

use crate::ai::decision::{
    recompute_saved_verdicts, AiEvaluation, AiPolicySnapshot, CategoryScores,
};

const ROWS: usize = 20_000;

pub(super) fn run() {
    let dir = std::env::temp_dir().join(format!("antiwire-verdicts-bench-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("bench directory");
    let store = Arc::new(Store::open(dir.join("antiwire.libsql")).expect("bench store"));
    let on = policy(true);
    seed(&store, &on);
    println!("verdicts: {ROWS} saved decisions, every verdict rewritten by each toggle");
    for (label, policy) in [("ai_off", policy(false)), ("ai_on", on)] {
        rewrite(&store, label, &policy);
    }
    drop(store);
    let _ = std::fs::remove_dir_all(&dir);
}

/// AI on or off, blocking malicious domains when on.
fn policy(enabled: bool) -> AiPolicySnapshot {
    let settings = DaemonSetting {
        ai_enabled: enabled,
        ai_malicious_action: "block".to_owned(),
        ..DaemonSetting::default()
    };
    AiPolicySnapshot::from_settings(&settings, 1)
}

/// Saves `ROWS` malicious domains, each blocked under `policy`.
fn seed(store: &Store, policy: &AiPolicySnapshot) {
    let scores = CategoryScores {
        scores: [0.0, 0.0, 0.0, 0.0, 0.99, 0.0, 0.0, 0.0],
    };
    let evaluation = AiEvaluation::evaluate(&scores, policy);
    assert!(evaluation.should_block(), "the seeded rows are blocked");
    let now = OffsetDateTime::now_utc();
    for index in 0..ROWS {
        let stored = evaluation.to_stored(&domain(index), "bench", &scores, now, None);
        store
            .upsert_domain_decision(&stored)
            .expect("seed decision");
    }
}

fn domain(index: usize) -> String {
    format!("d{index}.verdicts.bench")
}

/// Rewrites the verdicts for `policy` while another thread reads decisions
/// from the store, and reports both.
fn rewrite(store: &Arc<Store>, label: &str, policy: &AiPolicySnapshot) {
    let stop = Arc::new(AtomicBool::new(false));
    let reader = {
        let store = Arc::clone(store);
        let stop = Arc::clone(&stop);
        std::thread::spawn(move || {
            let mut waits = Vec::new();
            let mut index = 0;
            while !stop.load(Ordering::Relaxed) {
                index = (index + 7_919) % ROWS;
                let started = Instant::now();
                store
                    .reload_domain_decision(&domain(index))
                    .expect("lookup");
                waits.push(started.elapsed());
            }
            waits
        })
    };
    let started = Instant::now();
    let changed = recompute_saved_verdicts(store, policy).expect("rewrite verdicts");
    let elapsed = started.elapsed();
    stop.store(true, Ordering::Relaxed);
    let mut waits = reader.join().expect("reader thread");
    waits.sort_unstable();
    let at = |permille| super::percentile(&waits, permille).map_or(f64::NAN, micros);
    println!(
        "verdicts_{label} changed={changed} ms={:.0} rows_per_s={:.0} \
         lookups_beside={} lookup_us p50={:.0} p99={:.0} max={:.0}",
        elapsed.as_secs_f64() * 1e3,
        f64::from(u32::try_from(changed).unwrap_or(u32::MAX)) / elapsed.as_secs_f64(),
        waits.len(),
        at(500),
        at(990),
        at(1_000),
    );
}

fn micros(duration: Duration) -> f64 {
    duration.as_secs_f64() * 1e6
}
