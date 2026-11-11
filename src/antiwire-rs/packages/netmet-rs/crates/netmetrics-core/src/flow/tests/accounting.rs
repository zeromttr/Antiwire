use super::*;

#[test]
fn evicts_oldest_and_never_exceeds_capacity() {
    let mut table = FlowTable::new(2);
    table.open(key(1), 1, None, None, 10);
    table.open(key(2), 2, None, None, 20);
    let outcome = table.open(key(3), 3, None, None, 30);

    assert_eq!(table.len(), 2);
    assert_eq!(outcome.evicted.map(|row| row.key), Some(key(1)));
    assert!(table.get(&key(1)).is_none());
    assert_eq!(table.stats().evicted, 1);
}

#[test]
fn byte_totals_saturate_and_out_of_order_events_create_flow() {
    let mut table = FlowTable::new(1);
    let outcome = table.add_bytes(
        key(1),
        ByteDelta {
            sent: u64::MAX,
            received: 2,
        },
        10,
    );
    assert!(outcome.inserted);
    table.add_bytes(
        key(1),
        ByteDelta {
            sent: 10,
            received: 3,
        },
        11,
    );
    let row = table.get(&key(1)).expect("flow should exist");
    assert_eq!(row.bytes_sent, u64::MAX);
    assert_eq!(row.bytes_received, 5);
    assert_eq!(table.stats().inferred_opens, 1);
}

#[test]
fn close_returns_cumulative_terminal_record() {
    let mut table = FlowTable::new(2);
    table.open(key(1), 42, None, None, 10);
    table.add_bytes(
        key(1),
        ByteDelta {
            sent: 3,
            received: 4,
        },
        12,
    );
    let closed = table.close(&key(1), 15).expect("close record");
    assert_eq!(closed.state, FlowState::Closed);
    assert_eq!(closed.bytes_sent, 3);
    assert_eq!(closed.last_seen_ts, 15);
    assert!(table.is_empty());
}

#[test]
fn byte_events_merge_when_tuple_orientation_is_reversed() {
    let mut table = FlowTable::new(4);
    table.open(key(1), 42, None, None, 10);
    table.add_bytes(
        key(1),
        ByteDelta {
            sent: 128,
            received: 0,
        },
        11,
    );
    let reversed = key(1).reverse();
    table.add_bytes(
        reversed,
        ByteDelta {
            sent: 0,
            received: 4_096,
        },
        12,
    );
    let row = table.get(&key(1)).expect("flow");
    assert_eq!(row.bytes_sent, 128);
    assert_eq!(row.bytes_received, 4_096);
    assert!(table.get(&reversed).is_none());
}

#[test]
fn snapshots_remain_sorted_after_closes_and_evictions() {
    let mut table = FlowTable::new(2);
    table.open(key(2), 2, None, None, 1);
    table.open(key(1), 1, None, None, 2);
    assert_eq!(
        table
            .snapshot(3)
            .flows
            .into_iter()
            .map(|flow| flow.key)
            .collect::<Vec<_>>(),
        vec![key(1), key(2)]
    );

    table.close(&key(1), 4);
    table.open(key(3), 3, None, None, 5);
    assert_eq!(
        table
            .snapshot(6)
            .flows
            .into_iter()
            .map(|flow| flow.key)
            .collect::<Vec<_>>(),
        vec![key(2), key(3)]
    );
}

#[test]
fn close_resolves_reversed_tuple() {
    let mut table = FlowTable::new(2);
    table.open(key(1), 42, None, None, 10);
    let closed = table.close(&key(1).reverse(), 15).expect("closed");
    assert_eq!(closed.bytes_sent, 0);
    assert_eq!(closed.bytes_received, 0);
    assert!(table.is_empty());
}

#[test]
fn recent_activity_updates_lru_order() {
    let mut table = FlowTable::new(2);
    table.open(key(1), 1, None, None, 1);
    table.open(key(2), 2, None, None, 2);
    table.add_bytes(
        key(1),
        ByteDelta {
            sent: 1,
            received: 0,
        },
        3,
    );
    let outcome = table.open(key(3), 3, None, None, 4);
    assert_eq!(outcome.evicted.map(|row| row.key), Some(key(2)));
}
