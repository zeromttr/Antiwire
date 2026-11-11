//! Compile-level coverage for public APIs retained during reliability repairs.

use netmetrics_core::{FlowEvent, FlowKey, IpCache, Protocol, ip_aliases};
use netmetrics_sys::{BackendConfig, BackendEvent, WireFlowKind, WireFlowRecord};

#[test]
fn retained_public_apis_compile_for_a_downstream_crate() {
    let address = "192.0.2.1".parse().unwrap();
    let mut cache = IpCache::new(2);
    assert_eq!(cache.intern(address), Some(0));
    assert_eq!(ip_aliases(address).len(), 2);

    let key = FlowKey {
        protocol: Protocol::Udp,
        local_addr: "192.0.2.2".parse().unwrap(),
        local_port: 50_000,
        remote_addr: address,
        remote_port: 53,
    };
    let wire = WireFlowRecord {
        kind: WireFlowKind::Sent,
        key,
        pid: 7,
        timestamp: 1,
        byte_count: 12,
        cookie: None,
        if_index: None,
    };
    assert_eq!(wire.backend_events(2).len(), 1);

    let legacy = FlowEvent::DnsResolved {
        pid: 7,
        query: "example.test".to_owned(),
        answers: vec![address.to_string()],
    };
    assert!(matches!(legacy, FlowEvent::DnsResolved { .. }));

    let backend_config = BackendConfig {
        session_name: "downstream-adapter".to_owned(),
        buffer_mb: 8,
        poll_interval_ms: 250,
        dns_hints: true,
    };
    assert!(backend_config.dns_hints);
    let native_dns = BackendEvent::DnsResolved {
        pid: 7,
        query: "example.test".to_owned(),
        answers: vec![address],
        ttl_ms: 1_000,
        timestamp: 1,
    };
    assert!(matches!(native_dns, BackendEvent::DnsResolved { .. }));
}
