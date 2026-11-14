use super::*;

#[test]
fn a_new_flow_does_not_take_a_process_created_after_it_opened() {
    let mut table = FlowTable::new(4);
    let later = ProcessIdentity {
        executable: "/bin/later".to_owned(),
        name: "later".to_owned(),
        start_ts: 200,
    };
    table.open(key(1), 42, Some(later.clone()), None, 100);
    assert_eq!(table.get(&key(1)).expect("flow").meta.process, None);
    // Inferred opens from bytes take the same path.
    table.add_attributed_bytes(
        key(2),
        42,
        Some(later.clone()),
        ByteDelta {
            sent: 1,
            received: 0,
        },
        100,
    );
    assert_eq!(table.get(&key(2)).expect("flow").meta.process, None);

    let earlier = ProcessIdentity {
        start_ts: 50,
        ..later
    };
    table.open(key(3), 42, Some(earlier.clone()), None, 100);
    assert_eq!(
        table.get(&key(3)).expect("flow").meta.process,
        Some(earlier)
    );
}

#[test]
fn process_identity_can_arrive_after_flow_open() {
    let mut table = FlowTable::new(2);
    table.open(key(1), 42, None, None, 10);
    let identity = ProcessIdentity {
        executable: "/bin/example".to_owned(),
        name: "example".to_owned(),
        start_ts: 5,
    };
    assert_eq!(table.update_process(42, &identity), 1);
    assert_eq!(
        table.get(&key(1)).expect("flow").meta.process,
        Some(identity)
    );
}

#[test]
fn manifest_identity_enriches_a_basename_with_unknown_creation_time() {
    let mut table = FlowTable::new(2);
    let bare = ProcessIdentity {
        executable: "example".into(),
        name: "example".into(),
        start_ts: 0,
    };
    table.open(key(1), 42, Some(bare.clone()), None, 10);
    let full = ProcessIdentity {
        executable: "/bin/example".into(),
        name: "example".into(),
        start_ts: 5,
    };
    assert_eq!(table.update_process(42, &full), 1);
    assert_eq!(
        table.get(&key(1)).expect("flow").meta.process,
        Some(full.clone())
    );
    assert_eq!(
        table.update_process(42, &bare),
        0,
        "late incomplete evidence must not downgrade it"
    );
    table.open(key(2), 43, Some(bare.clone()), None, 4);
    assert_eq!(
        table.update_process(43, &full),
        0,
        "a process born after the flow cannot own it"
    );
    assert!(!FlowTable::should_update_process(
        &table.get(&key(2)).unwrap().meta,
        42,
        Some(&full)
    ));
}

#[test]
fn pid_reuse_does_not_relabel_an_existing_flow() {
    let old = ProcessIdentity {
        executable: "/bin/old".to_owned(),
        name: "old".to_owned(),
        start_ts: 5,
    };
    let replacement = ProcessIdentity {
        executable: "/bin/new".to_owned(),
        name: "new".to_owned(),
        start_ts: 20,
    };
    let mut table = FlowTable::new(2);
    table.open(key(1), 42, Some(old.clone()), None, 10);

    assert_eq!(table.update_process(42, &replacement), 0);
    table.open(key(1), 42, Some(replacement.clone()), None, 21);
    table.add_attributed_bytes(
        key(1),
        42,
        Some(replacement),
        ByteDelta {
            sent: 1,
            received: 0,
        },
        22,
    );

    assert_eq!(table.get(&key(1)).unwrap().meta.process, Some(old));
}

#[test]
fn unknown_process_start_attaches_only_to_compatible_pid() {
    let mut table = FlowTable::new(2);
    table.open(key(1), 42, None, None, 10);
    let identity = ProcessIdentity {
        executable: "/bin/process".to_owned(),
        name: "process".to_owned(),
        start_ts: 0,
    };
    let meta = &table.get(&key(1)).unwrap().meta;
    assert!(!FlowTable::should_update_process(meta, 43, Some(&identity)));
    assert!(!FlowTable::should_update_process(meta, 0, Some(&identity)));
    assert_eq!(table.update_process(42, &identity), 1);
    assert_eq!(table.get(&key(1)).unwrap().meta.process, Some(identity));
}

#[test]
fn process_enrichment_requires_compatible_lifetime_evidence() {
    let mut table = FlowTable::new(3);
    table.open(key(1), 42, None, None, 10);
    table.open(key(2), 42, None, None, 10);
    let compatible = ProcessIdentity {
        executable: "/bin/process".to_owned(),
        name: "process".to_owned(),
        start_ts: 5,
    };
    assert_eq!(table.update_process(42, &compatible), 2);

    table.open(key(3), 43, None, None, 10);
    let too_new = ProcessIdentity {
        executable: "/bin/reused".to_owned(),
        name: "reused".to_owned(),
        start_ts: 20,
    };
    assert_eq!(table.update_process(43, &too_new), 0);
    assert!(table.get(&key(3)).unwrap().meta.process.is_none());
}

#[test]
fn attributed_bytes_create_flow_with_pid() {
    let mut table = FlowTable::new(2);
    let outcome = table.add_attributed_bytes(
        key(1),
        42,
        None,
        ByteDelta {
            sent: 128,
            received: 0,
        },
        10,
    );

    assert!(outcome.inserted);
    assert_eq!(outcome.key, key(1));
    assert_eq!(table.get(&key(1)).expect("flow").meta.pid, 42);
}

#[test]
fn attributed_bytes_upgrade_inferred_flow() {
    let mut table = FlowTable::new(2);
    table.add_bytes(
        key(1),
        ByteDelta {
            sent: 1,
            received: 0,
        },
        10,
    );
    let outcome = table.add_attributed_bytes(
        key(1).reverse(),
        42,
        None,
        ByteDelta {
            sent: 0,
            received: 2,
        },
        11,
    );

    assert!(!outcome.inserted);
    assert!(outcome.attribution_changed);
    assert_eq!(outcome.key, key(1));
    let flow = table.get(&key(1)).expect("flow");
    assert_eq!(flow.meta.pid, 42);
    assert_eq!(flow.bytes_sent, 1);
    assert_eq!(flow.bytes_received, 2);
}

#[test]
fn repeated_borrowed_attribution_reuses_identity_storage() {
    let mut table = FlowTable::new(2);
    let identity = ProcessIdentity {
        executable: "/bin/high-rate-process".to_owned(),
        name: "high-rate-process".to_owned(),
        start_ts: 1,
    };
    table.open(key(1), 42, Some(identity.clone()), None, 1);
    let original = table
        .entries
        .get(&key(1))
        .and_then(|entry| entry.meta.process.as_ref())
        .map(|process| process.executable.as_ptr())
        .expect("stored identity");
    for timestamp in 2..10_000 {
        table.add_attributed_bytes_ref(
            key(1),
            42,
            Some(&identity),
            ByteDelta {
                sent: 1,
                received: 0,
            },
            timestamp,
            None,
        );
    }
    let current = table
        .entries
        .get(&key(1))
        .and_then(|entry| entry.meta.process.as_ref())
        .map(|process| process.executable.as_ptr())
        .expect("stored identity");
    assert_eq!(original, current);
}

#[test]
fn zero_pid_never_downgrades_existing_attribution() {
    let mut table = FlowTable::new(2);
    table.open(key(1), 42, None, None, 10);
    let outcome = table.open(key(1), 0, None, None, 11);

    assert!(!outcome.attribution_changed);
    assert_eq!(table.get(&key(1)).expect("flow").meta.pid, 42);
}
