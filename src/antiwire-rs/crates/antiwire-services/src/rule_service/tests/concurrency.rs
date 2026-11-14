//! Concurrent changes: the gate serializes them end to end.

use std::sync::{Arc, Barrier};

use antiwire_policy::EnforcementOp;

use super::{country, harness, is_country, Harness};
use crate::rule_service::CountrySelector;

/// Runs `work` on `threads` threads released at once, returning each result.
fn race<T: Send + 'static>(threads: usize, work: impl Fn() -> T + Send + Sync + 'static) -> Vec<T> {
    let work = Arc::new(work);
    let barrier = Arc::new(Barrier::new(threads));
    let workers: Vec<_> = (0..threads)
        .map(|_| {
            let work = Arc::clone(&work);
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                barrier.wait();
                work()
            })
        })
        .collect();
    workers
        .into_iter()
        .map(|worker| worker.join().expect("worker"))
        .collect()
}

#[test]
fn concurrent_adds_of_one_country_save_one_rule() {
    let Harness { store, service, .. } = harness();
    let service = Arc::new(service);

    let added = race(4, move || {
        service
            .add_country_rule(&country("KP", &["175.45.176.0/22"]))
            .is_ok()
    });

    assert_eq!(added.iter().filter(|added| **added).count(), 1);
    assert_eq!(store.list_rules().expect("rules").len(), 1);
}

#[test]
fn concurrent_removals_of_one_country_leave_nothing_enforced() {
    // The losing remover used to find the row already deleted and roll back,
    // reinstalling a block no saved rule described.
    let Harness {
        store,
        engine,
        firewall,
        service,
        ..
    } = harness();
    let summary = service
        .add_country_rule(&country("KP", &["175.45.176.0/22"]))
        .expect("add");
    let service = Arc::new(service);

    let removed = race(2, move || {
        service
            .remove_country_rule(&CountrySelector::Id(summary.id))
            .expect("remove")
    });

    assert_eq!(removed.iter().filter(|removed| **removed).count(), 1);
    assert_eq!(store.list_rules().expect("rules"), []);
    assert_eq!(engine.read().rule_count(), 0);
    let last = firewall.applied().into_iter().rev().find(is_country);
    assert!(
        matches!(last, Some(EnforcementOp::RemoveCountryBlock { .. })),
        "the block must end removed, got {last:?}"
    );
}
