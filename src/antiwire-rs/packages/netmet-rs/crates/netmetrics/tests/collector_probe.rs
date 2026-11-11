//! Collector live probe integration tests.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use netmetrics::{CollectorBuilder, tcp_pid_attribution_stats};
use netmetrics_core::FlowEvent;

#[test]
#[ignore = "live kernel ETW capture; run manually on Windows with elevated permissions"]
fn probe_live_collector_events() {
    let counts = Arc::new(Mutex::new(HashMap::<&'static str, u64>::new()));
    let degraded = Arc::new(Mutex::new(Vec::<String>::new()));
    let bytes = Arc::new(Mutex::new((0_u64, 0_u64)));

    let c = Arc::clone(&counts);
    let d = Arc::clone(&degraded);
    let b = Arc::clone(&bytes);

    let mut collector = CollectorBuilder::new()
        .session_name("netmetrics-probe".to_owned())
        .ignore_loopback(false)
        .coalesce_interval_ms(200)
        .build()
        .expect("collector");

    collector
        .start(Box::new(move |event| {
            let name = match &event {
                FlowEvent::Opened(..) => "opened",
                FlowEvent::Closed(..) => "closed",
                FlowEvent::Bytes(_, delta) => {
                    let mut totals = b.lock().unwrap();
                    totals.0 += delta.sent;
                    totals.1 += delta.received;
                    "bytes"
                }
                FlowEvent::ProcessStarted(..) => "process_started",
                FlowEvent::ProcessStopped { .. } => "process_stopped",
                FlowEvent::DnsResolved { .. } | FlowEvent::DnsResolvedWithMetadata { .. } => "dns",
                FlowEvent::DnsQuery(..) => "dns_query",
                FlowEvent::Interface(..) => "interface",
                FlowEvent::Degraded { reason } => {
                    d.lock().unwrap().push(format!("{reason:?}"));
                    "degraded"
                }
            };
            *c.lock().unwrap().entry(name).or_default() += 1;
        }))
        .expect("start");

    thread::sleep(Duration::from_secs(10));
    let stats = collector.stats();
    collector.stop().ok();

    println!("counts: {:?}", counts.lock().unwrap());
    println!("degraded: {:?}", degraded.lock().unwrap());
    println!("bytes: {:?}", bytes.lock().unwrap());
    println!("stats: {stats:?}");
    println!("tcp_pid_attribution: {:?}", tcp_pid_attribution_stats());
    #[cfg(all(windows, feature = "windows"))]
    {
        println!(
            "udp_pid_attribution: {:?}",
            netmetrics_windows::udp_pid_attribution_stats()
        );
        println!(
            "udp_owner_lookup: {:?}",
            netmetrics_windows::udp_owner_lookup_stats()
        );
        println!(
            "tcp_owner_cookie_hits: {}",
            netmetrics_windows::tcp_owner_cookie_hit_count()
        );
        println!(
            "process_image_resolution: {:?}",
            netmetrics_windows::process_image_resolution_stats()
        );
        println!(
            "tcp_owner_relaxed_matches: {}",
            netmetrics_windows::tcp_owner_relaxed_match_count()
        );
        println!(
            "tcp_listener_fallbacks: {}",
            netmetrics_windows::tcp_listener_fallback_count()
        );
        println!(
            "address_string_fallbacks: {}",
            netmetrics_windows::address_string_fallback_count()
        );
        println!(
            "dns_caller_recovery: {:?}",
            netmetrics_windows::dns_caller_recovery_stats()
        );
    }
}
