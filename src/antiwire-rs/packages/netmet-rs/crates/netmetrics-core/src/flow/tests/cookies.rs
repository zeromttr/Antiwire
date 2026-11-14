use super::*;

#[test]
fn matching_cookie_bytes_reuse_process_identity_storage() {
    let mut table = FlowTable::new(2);
    let identity = ProcessIdentity {
        executable: "/bin/udp-client".to_owned(),
        name: "udp-client".to_owned(),
        start_ts: 1,
    };
    table.open(key(1), 42, Some(identity.clone()), Some(cookie(7)), 1);
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
            Some(cookie(7)),
        );
    }
    let current = table
        .entries
        .get(&key(1))
        .and_then(|entry| entry.meta.process.as_ref())
        .map(|process| process.executable.as_ptr())
        .expect("stored identity");
    assert_eq!(original, current);
    assert_eq!(table.get(&key(1)).expect("flow").bytes_sent, 9_998);
}

#[test]
fn contradicting_cookie_supersedes_flow_and_zeroes_totals() {
    let mut table = FlowTable::new(4);
    table.open(key(1), 42, None, Some(cookie(7)), 10);
    table.add_bytes(
        key(1),
        ByteDelta {
            sent: 100,
            received: 200,
        },
        11,
    );

    let outcome = table.open(key(1), 43, None, Some(cookie(8)), 20);

    let superseded = outcome
        .superseded
        .expect("recycled tuple must close the old row");
    assert_eq!(superseded.state, FlowState::Closed);
    assert_eq!(superseded.bytes_sent, 100);
    assert_eq!(superseded.bytes_received, 200);
    assert_eq!(superseded.meta.cookie, Some(cookie(7)));
    assert!(outcome.inserted);

    let row = table.get(&key(1)).expect("replacement flow");
    assert_eq!(
        row.bytes_sent, 0,
        "the new socket must not inherit byte totals"
    );
    assert_eq!(row.bytes_received, 0);
    assert_eq!(row.meta.cookie, Some(cookie(8)));
    assert_eq!(row.meta.pid, 43);
    assert_eq!(row.meta.open_ts, 20);
    assert_eq!(table.len(), 1);
}

#[test]
fn matching_cookie_refreshes_flow_in_place() {
    let mut table = FlowTable::new(4);
    table.open(key(1), 42, None, Some(cookie(7)), 10);
    table.add_bytes(
        key(1),
        ByteDelta {
            sent: 5,
            received: 0,
        },
        11,
    );

    let outcome = table.open(key(1), 42, None, Some(cookie(7)), 12);

    assert!(outcome.superseded.is_none());
    assert!(!outcome.inserted);
    assert!(!outcome.cookie_learned);
    assert_eq!(table.get(&key(1)).expect("flow").bytes_sent, 5);
}

#[test]
fn absent_cookie_never_supersedes_a_flow() {
    let mut table = FlowTable::new(4);
    table.open(key(1), 42, None, Some(cookie(7)), 10);
    table.add_bytes(
        key(1),
        ByteDelta {
            sent: 5,
            received: 0,
        },
        11,
    );

    // A backend that cannot resolve a cookie must never look like a new socket.
    let outcome = table.open(key(1), 42, None, None, 12);

    assert!(outcome.superseded.is_none());
    assert!(!outcome.inserted);
    let row = table.get(&key(1)).expect("flow survives");
    assert_eq!(row.bytes_sent, 5);
    assert_eq!(
        row.meta.cookie,
        Some(cookie(7)),
        "a known cookie is never cleared"
    );
}

#[test]
fn absent_stored_cookie_is_adopted_and_reported_once() {
    let mut table = FlowTable::new(4);
    table.open(key(1), 42, None, None, 10);

    let outcome = table.open(key(1), 42, None, Some(cookie(9)), 11);
    assert!(
        outcome.cookie_learned,
        "adoption must be republished downstream"
    );
    assert!(!outcome.inserted);
    assert!(outcome.superseded.is_none());
    assert_eq!(
        table.get(&key(1)).expect("flow").meta.cookie,
        Some(cookie(9))
    );

    let outcome = table.open(key(1), 42, None, Some(cookie(9)), 12);
    assert!(
        !outcome.cookie_learned,
        "re-observing a cookie is not a fresh learn"
    );
}

#[test]
fn learning_a_cookie_never_creates_an_untracked_flow() {
    let mut table = FlowTable::new(4);
    // The Windows owner-module poller sees every socket on the machine, including ones
    // ETW never reported. Those must not become flows.
    assert!(table.learn_cookie(key(1), 42, cookie(5), 10).is_none());
    assert_eq!(table.len(), 0);
}

#[test]
fn learning_a_cookie_enriches_a_tracked_flow_without_reopening_it() {
    let mut table = FlowTable::new(4);
    table.open(key(1), 42, None, None, 10);
    table.add_bytes(
        key(1),
        ByteDelta {
            sent: 8,
            received: 0,
        },
        11,
    );

    let outcome = table
        .learn_cookie(key(1), 42, cookie(5), 12)
        .expect("tracked");
    assert!(outcome.cookie_learned);
    assert!(!outcome.inserted);
    let row = table.get(&key(1)).expect("flow");
    assert_eq!(row.meta.cookie, Some(cookie(5)));
    assert_eq!(row.bytes_sent, 8, "enrichment must not reset counters");
    assert_eq!(row.meta.pid, 42, "enrichment must not clear attribution");
}

#[test]
fn learning_a_contradicting_cookie_still_splits_a_tracked_flow() {
    let mut table = FlowTable::new(4);
    table.open(key(1), 42, None, Some(cookie(5)), 10);
    table.add_bytes(
        key(1),
        ByteDelta {
            sent: 8,
            received: 0,
        },
        11,
    );

    let outcome = table
        .learn_cookie(key(1), 42, cookie(6), 12)
        .expect("tracked");
    let superseded = outcome
        .superseded
        .expect("recycled tuple closes the old row");
    assert_eq!(superseded.bytes_sent, 8);
    assert_eq!(table.get(&key(1)).expect("replacement").bytes_sent, 0);
}

#[test]
fn cookie_from_a_differing_source_neither_splits_nor_displaces() {
    let mut table = FlowTable::new(4);
    table.open(key(1), 42, None, Some(cookie(7)), 10);

    let foreign = Some(SocketCookie {
        value: 999,
        source: CookieSource::Synthetic,
    });
    let outcome = table.open(key(1), 42, None, foreign, 11);

    assert!(
        outcome.superseded.is_none(),
        "differing sources are not comparable"
    );
    assert!(!outcome.cookie_learned);
    assert_eq!(
        table.get(&key(1)).expect("flow").meta.cookie,
        Some(cookie(7))
    );
}

#[test]
fn kernel_cookie_upgrades_provisional_linux_inode_without_resetting_bytes() {
    let mut table = FlowTable::new(4);
    let inode = SocketCookie {
        value: 88,
        source: CookieSource::LinuxInode,
    };
    let kernel = SocketCookie {
        value: 999,
        source: CookieSource::LinuxSockCookie,
    };
    table.open(key(1), 42, None, Some(inode), 10);
    table.add_bytes(
        key(1),
        ByteDelta {
            sent: 8,
            received: 0,
        },
        11,
    );
    let outcome = table.open(key(1), 42, None, Some(kernel), 12);
    assert!(outcome.cookie_learned);
    assert!(outcome.superseded.is_none());
    let flow = table.get(&key(1)).expect("flow");
    assert_eq!(flow.meta.cookie, Some(kernel));
    assert_eq!(flow.bytes_sent, 8);
}

#[test]
fn byte_cookie_splits_before_charging_new_bytes() {
    let mut table = FlowTable::new(4);
    table.open(key(1), 42, None, Some(cookie(1)), 10);
    table.add_bytes(
        key(1),
        ByteDelta {
            sent: 10,
            received: 0,
        },
        11,
    );
    let outcome = table.add_attributed_bytes_ref(
        key(1),
        43,
        None,
        ByteDelta {
            sent: 5,
            received: 0,
        },
        12,
        Some(cookie(2)),
    );
    assert!(outcome.superseded.is_some());
    assert_eq!(outcome.superseded.as_ref().expect("old").bytes_sent, 10);
    assert_eq!(table.get(&key(1)).expect("new").bytes_sent, 5);
    assert_eq!(
        table.get(&key(1)).expect("new").meta.cookie,
        Some(cookie(2))
    );
}
