//! Golden serialization contract consumed by daemon mocks.

use netmetrics::{
    ByteDelta, CookieSource, DegradeReason, FlowEvent, FlowKey, FlowMeta, InterfaceStats,
    ProcessIdentity, ProcessInfo, Protocol, SocketCookie,
};
use netmetrics_core::{DnsCallerIdentity, DnsCorrelationId, DnsQueryEvent};
use std::net::{IpAddr, Ipv4Addr};

fn contract_events() -> Vec<FlowEvent> {
    let key = FlowKey {
        protocol: Protocol::Tcp,
        local_addr: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
        local_port: 50_000,
        remote_addr: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 20)),
        remote_port: 443,
    };
    let identity = ProcessIdentity {
        executable: "C:\\Program Files\\Example\\example.exe".to_owned(),
        name: "example.exe".to_owned(),
        start_ts: 1_700_000_000_000,
    };
    vec![
        FlowEvent::ProcessStarted(ProcessInfo {
            pid: 42,
            identity: identity.clone(),
        }),
        FlowEvent::Opened(
            key,
            FlowMeta {
                pid: 42,
                process: Some(identity),
                open_ts: 1_700_000_000_010,
                cookie: None,
                if_index: None,
            },
        ),
        FlowEvent::Bytes(
            key,
            ByteDelta {
                sent: 1_024,
                received: 2_048,
            },
        ),
        FlowEvent::Closed(
            key,
            FlowMeta {
                pid: 42,
                process: None,
                open_ts: 1_700_000_000_010,
                cookie: None,
                if_index: None,
            },
        ),
        FlowEvent::ProcessStopped {
            pid: 42,
            stop_ts: 1_700_000_000_015,
        },
        FlowEvent::DnsResolved {
            pid: 42,
            query: "example.test".to_owned(),
            answers: vec!["198.51.100.20".to_owned()],
        },
        FlowEvent::Interface(InterfaceStats {
            index: 7,
            name: "Ethernet".to_owned(),
            rx_bytes: 20,
            tx_bytes: 10,
            rx_errors: 1,
            tx_errors: 2,
            rx_drops: 3,
            tx_drops: 4,
            timestamp: 1_700_000_000_020,
        }),
        FlowEvent::Degraded {
            reason: DegradeReason::BufferOverflow { dropped: 3 },
        },
    ]
}

#[test]
fn public_event_json_matches_v1_golden_contract() {
    let actual = serde_json::to_string_pretty(&contract_events()).expect("serialize events");
    let expected = include_str!("fixtures/flow_events_v1.json").replace("\r\n", "\n");
    let expected = expected.trim();
    assert_eq!(actual, expected);
}

#[test]
fn golden_contract_deserializes_back_to_equal_events() {
    let decoded: Vec<FlowEvent> =
        serde_json::from_str(include_str!("fixtures/flow_events_v1.json")).expect("golden JSON");
    assert_eq!(decoded, contract_events());
}

/// Events carrying a socket cookie. Kept separate from the v1 contract so that fixture keeps
/// proving an absent cookie serializes to nothing at all.
fn cookie_contract_events() -> Vec<FlowEvent> {
    let key = FlowKey {
        protocol: Protocol::Tcp,
        local_addr: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
        local_port: 50_000,
        remote_addr: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 20)),
        remote_port: 443,
    };
    vec![
        FlowEvent::Opened(
            key,
            FlowMeta {
                pid: 42,
                process: None,
                open_ts: 1_700_000_000_010,
                cookie: Some(SocketCookie {
                    value: 1_234_567_890,
                    source: CookieSource::LinuxSockCookie,
                }),
                if_index: None,
            },
        ),
        FlowEvent::Closed(
            key,
            FlowMeta {
                pid: 42,
                process: None,
                open_ts: 1_700_000_000_010,
                cookie: Some(SocketCookie {
                    value: 9_876_543_210,
                    source: CookieSource::WindowsCreateTimestamp,
                }),
                if_index: None,
            },
        ),
    ]
}

#[test]
fn cookie_json_matches_v2_golden_contract() {
    let actual = serde_json::to_string_pretty(&cookie_contract_events()).expect("serialize events");
    let expected = include_str!("fixtures/flow_events_v2.json").replace("\r\n", "\n");
    assert_eq!(actual, expected.trim());
}

#[test]
fn v2_golden_contract_deserializes_back_to_equal_events() {
    let decoded: Vec<FlowEvent> =
        serde_json::from_str(include_str!("fixtures/flow_events_v2.json")).expect("golden JSON");
    assert_eq!(decoded, cookie_contract_events());
}

/// A snapshot-only fallback and the event that ends it. Kept apart from the v1 and v2
/// contracts, which predate `Restored`, so those fixtures keep proving that what was stored
/// before it still reads back.
fn fallback_contract_events() -> Vec<FlowEvent> {
    vec![
        FlowEvent::Degraded {
            reason: DegradeReason::SnapshotOnly {
                source: "macos-socket-table".to_owned(),
            },
        },
        FlowEvent::Restored {
            source: "macos-socket-table".to_owned(),
        },
    ]
}

/// A connection that stops being established before it closes. Kept apart from the
/// earlier contracts, which predate `Finishing`.
fn finishing_contract_events() -> Vec<FlowEvent> {
    vec![FlowEvent::Finishing(FlowKey {
        protocol: Protocol::Tcp,
        local_addr: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
        local_port: 50_000,
        remote_addr: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 20)),
        remote_port: 443,
    })]
}

#[test]
fn finishing_json_matches_v4_golden_contract() {
    let actual =
        serde_json::to_string_pretty(&finishing_contract_events()).expect("serialize events");
    let expected = include_str!("fixtures/flow_events_v4.json").replace("\r\n", "\n");
    assert_eq!(actual, expected.trim());
}

#[test]
fn v4_golden_contract_deserializes_back_to_equal_events() {
    let decoded: Vec<FlowEvent> =
        serde_json::from_str(include_str!("fixtures/flow_events_v4.json")).expect("golden JSON");
    assert_eq!(decoded, finishing_contract_events());
}

#[test]
fn fallback_json_matches_v3_golden_contract() {
    let actual =
        serde_json::to_string_pretty(&fallback_contract_events()).expect("serialize events");
    let expected = include_str!("fixtures/flow_events_v3.json").replace("\r\n", "\n");
    assert_eq!(actual, expected.trim());
}

#[test]
fn v3_golden_contract_deserializes_back_to_equal_events() {
    let decoded: Vec<FlowEvent> =
        serde_json::from_str(include_str!("fixtures/flow_events_v3.json")).expect("golden JSON");
    assert_eq!(decoded, fallback_contract_events());
}

#[test]
fn v1_events_deserialize_without_a_cookie_field() {
    let without_cookie = r#"{"pid":42,"process":null,"open_ts":1700000000010}"#;
    let meta: FlowMeta = serde_json::from_str(without_cookie).expect("v1 metadata");
    assert_eq!(meta.cookie, None);
}

#[test]
fn legacy_dns_query_json_deserializes_without_source_provenance() {
    let legacy = r#"{
        "name":"example.test",
        "query_type":1,
        "status":0,
        "caller":{"requesting_pid":42,"resolver_pid":null},
        "correlation":{"activity_id":null,"query_blob":null},
        "timestamp":1700000000020
    }"#;
    let query: DnsQueryEvent = serde_json::from_str(legacy).expect("legacy DNS query");
    assert_eq!(query.event_id, None);
    assert_eq!(query.event_version, None);
    assert_eq!(query.caller.logging_pid, None);
    assert_eq!(query.caller.requesting_pid, Some(42));
}

#[test]
fn dns_query_json_preserves_native_event_provenance() {
    let query = DnsQueryEvent {
        event_id: Some(3008),
        event_version: Some(0),
        name: "example.test".to_owned(),
        query_type: 1,
        status: 0,
        caller: DnsCallerIdentity {
            logging_pid: Some(42),
            requesting_pid: Some(42),
            resolver_pid: None,
        },
        correlation: DnsCorrelationId::default(),
        timestamp: 1_700_000_000_020,
    };
    let encoded = serde_json::to_string(&query).expect("serialize DNS query");
    let decoded: DnsQueryEvent = serde_json::from_str(&encoded).expect("deserialize DNS query");
    assert_eq!(decoded, query);
}
