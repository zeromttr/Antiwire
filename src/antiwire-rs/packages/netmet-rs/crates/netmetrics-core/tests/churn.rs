//! Deterministic high-churn accounting and memory-bound tests.

use netmetrics_core::{ByteDelta, FlowKey, FlowTable, IngressCoalescer, Protocol};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, Instant};

fn key(index: u32) -> FlowKey {
    FlowKey {
        protocol: if index.is_multiple_of(2) {
            Protocol::Tcp
        } else {
            Protocol::Udp
        },
        local_addr: IpAddr::V4(Ipv4Addr::new(
            192,
            0,
            2,
            u8::try_from(index % 250 + 1).expect("bounded octet"),
        )),
        local_port: u16::try_from(index % 60_000 + 1024).expect("bounded port"),
        remote_addr: IpAddr::V4(Ipv4Addr::new(
            198,
            51,
            u8::try_from(index / 250 % 250).expect("bounded octet"),
            u8::try_from(index % 250 + 1).expect("bounded octet"),
        )),
        remote_port: u16::try_from(index % 1024 + 1).expect("bounded port"),
    }
}

#[test]
fn scan_storm_stays_at_capacity() {
    const CAPACITY: usize = 1024;
    const INSERTS: u32 = 100_000;
    let mut table = FlowTable::new(CAPACITY);
    for index in 0..INSERTS {
        table.open(key(index), index, None, None, u64::from(index));
        assert!(table.len() <= CAPACITY);
    }
    assert_eq!(table.len(), CAPACITY);
    assert_eq!(table.stats().evicted, u64::from(INSERTS) - CAPACITY as u64);
    assert_eq!(table.snapshot(u64::from(INSERTS)).flows.len(), CAPACITY);
}

#[test]
fn coalescer_conserves_every_byte_under_churn() {
    let mut coalescer = IngressCoalescer::new(250, 4096);
    let mut expected = HashMap::<FlowKey, ByteDelta>::new();
    let mut emitted = HashMap::<FlowKey, ByteDelta>::new();
    let mut random = 0x1234_5678_u32;
    let start = Instant::now();

    for index in 0..100_000_u64 {
        random ^= random << 13;
        random ^= random >> 17;
        random ^= random << 5;
        let flow = key(random % 512);
        let delta = ByteDelta {
            sent: u64::from(random & 0xff),
            received: u64::from((random >> 8) & 0xff),
        };
        expected
            .entry(flow)
            .or_default()
            .saturating_add_assign(delta);
        if let Some((flow, delta)) =
            coalescer.push(flow, delta, start + Duration::from_millis(index))
        {
            emitted
                .entry(flow)
                .or_default()
                .saturating_add_assign(delta);
        }
        if index % 251 == 0 {
            for (flow, delta) in coalescer.drain_due(start + Duration::from_millis(index)) {
                emitted
                    .entry(flow)
                    .or_default()
                    .saturating_add_assign(delta);
            }
        }
    }
    for (flow, delta) in coalescer.drain_all() {
        emitted
            .entry(flow)
            .or_default()
            .saturating_add_assign(delta);
    }
    assert_eq!(emitted, expected);
}
