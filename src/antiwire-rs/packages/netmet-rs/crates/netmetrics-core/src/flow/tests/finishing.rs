use super::*;
use crate::FlowState;

const RECEIVED: ByteDelta = ByteDelta {
    sent: 0,
    received: 7,
};

/// A finishing flow stays in the table under its new state, takes the bytes that follow,
/// and closes with all of them.
#[test]
fn a_finishing_flow_keeps_its_bytes_until_it_closes() {
    let mut table = FlowTable::new(4);
    table.open(key(1), 42, None, Some(cookie(7)), 1);
    assert_eq!(
        table.get(&key(1)).expect("open flow").state,
        FlowState::Open
    );

    assert_eq!(table.finish(&key(1), 2), Some(key(1)));
    assert!(table.is_finishing(&key(1)));
    let outcome = table.add_bytes(key(1), RECEIVED, 3);
    assert!(!outcome.inserted, "the bytes belong to the finishing flow");

    let finishing = table.get(&key(1)).expect("finishing flow");
    assert_eq!(finishing.state, FlowState::Finishing);
    assert_eq!(finishing.bytes_received, 7);
    assert_eq!(table.snapshot(4).flows[0].state, FlowState::Finishing);

    let closed = table.close(&key(1), 5).expect("closed flow");
    assert_eq!(closed.state, FlowState::Closed);
    assert_eq!(closed.bytes_received, 7);
    assert!(!table.is_finishing(&key(1)));
}

#[test]
fn a_flow_is_reported_finishing_once() {
    let mut table = FlowTable::new(4);
    table.open(key(1), 42, None, None, 1);
    assert_eq!(table.finish(&key(1), 2), Some(key(1)));
    assert_eq!(table.finish(&key(1), 3), None);
    assert_eq!(table.finish(&key(2), 3), None, "an untracked flow");
}

/// A backend may name the flow from its peer's side, as for a close.
#[test]
fn a_reversed_key_finishes_the_flow_it_names() {
    let mut table = FlowTable::new(4);
    table.open(key(1), 42, None, None, 1);
    assert_eq!(table.finish(&key(1).reverse(), 2), Some(key(1)));
    assert!(table.is_finishing(&key(1)));
}

/// An open for a tracked flow refreshes it and leaves its state alone: only the collector,
/// which sees the backend's own open, takes one for a new connection.
#[test]
fn refreshing_a_finishing_flow_leaves_it_finishing() {
    let mut table = FlowTable::new(4);
    table.open(key(1), 0, None, None, 1);
    table.finish(&key(1), 2);
    let outcome = table.open(key(1), 42, None, None, 3);
    assert!(!outcome.inserted);
    assert!(table.is_finishing(&key(1)));
}
