//! Elevated diagnostic: does live traffic reach the store as byte deltas?
//!
//! Runs the production path — real collector, real bridge, real `FlowTracker` — and reports
//! what actually lands in the store, so a byte loss can be pinned to a specific layer.
#![allow(missing_docs)]
#![cfg(windows)]

use antiwire_events::{AlertPublisher, NotificationHub, TrafficStreamingHub};
use antiwire_flow::{AppIdResolver, FlowProcessor, FlowTracker, NetmetBridge};
use antiwire_store::NewConnectionLog;
use antiwire_tuning::{FLOW_EVENT_QUEUE_CAPACITY, UNKNOWN_SOCKET_ATTRIBUTION_DELAY};
use std::sync::{Arc, Mutex};
use std::time::Duration;

#[test]
#[ignore = "requires Windows sudo; starts a real kernel ETW session"]
fn live_traffic_reaches_the_store_with_byte_deltas() {
    let writes: Arc<Mutex<Vec<NewConnectionLog>>> = Arc::new(Mutex::new(Vec::new()));
    let captured = Arc::clone(&writes);

    // A production processor (not the bare tracker) so the System-service
    // attribution path runs exactly as the daemon runs it.
    let dir = tempfile::tempdir().expect("tempdir");
    let keystore = antiwire_secrets::UnixSecureFileKeyProvider::new(dir.path().join("key"));
    let store = Arc::new(
        antiwire_store::Store::open_with_keystore(dir.path().join("db.sqlite"), &keystore)
            .expect("open"),
    );
    let traffic_hub = TrafficStreamingHub::with_capacity(16);
    let alerts = AlertPublisher::unsaved(NotificationHub::with_capacity(16), None);
    let processor = Arc::new(FlowProcessor::new(
        Arc::new(AppIdResolver::new(
            Arc::clone(&store),
            alerts.clone(),
            antiwire_platform::SiemExporter::new(antiwire_platform::SiemConfig::default()),
        )),
        None,
        Arc::new(parking_lot::RwLock::new(antiwire_policy::RuleEngine::new())),
        Arc::clone(&store),
        traffic_hub.clone(),
        alerts,
        antiwire_platform::SiemExporter::new(antiwire_platform::SiemConfig::default()),
    ));

    let tracker = Arc::new(FlowTracker::with_processor(
        move |logs: &[NewConnectionLog]| {
            captured.lock().unwrap().extend_from_slice(logs);
            Ok(())
        },
        Some(Arc::clone(&processor)),
    ));

    let mut bridge = NetmetBridge::new();
    let rx = bridge
        .start(FLOW_EVENT_QUEUE_CAPACITY)
        .expect("bridge start");

    // Drain the bridge here rather than via `run`, so the events the tracker actually sees
    // can be counted alongside what ends up in the store.
    let runner = Arc::clone(&tracker);
    let counts: Arc<Mutex<std::collections::BTreeMap<&'static str, usize>>> =
        Arc::new(Mutex::new(std::collections::BTreeMap::new()));
    let seen = Arc::clone(&counts);
    let byte_totals = Arc::new(Mutex::new((0_u64, 0_u64)));
    let totals = Arc::clone(&byte_totals);

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("runtime");

    let handle = runtime.spawn(async move {
        let mut rx = rx;
        while let Some(event) = rx.recv().await {
            let name = match &event {
                netmetrics_core::FlowEvent::Opened(..) => "opened",
                netmetrics_core::FlowEvent::Closed(..) => "closed",
                netmetrics_core::FlowEvent::Bytes(_, delta) => {
                    let mut t = totals.lock().unwrap();
                    t.0 += delta.sent;
                    t.1 += delta.received;
                    "bytes"
                }
                netmetrics_core::FlowEvent::ProcessStarted(..) => "process_started",
                netmetrics_core::FlowEvent::ProcessStopped { .. } => "process_stopped",
                netmetrics_core::FlowEvent::DnsResolved { .. }
                | netmetrics_core::FlowEvent::DnsResolvedWithMetadata { .. } => "dns",
                netmetrics_core::FlowEvent::DnsQuery(..) => "dns_query",
                netmetrics_core::FlowEvent::Interface(..) => "interface",
                netmetrics_core::FlowEvent::Degraded { .. } => "degraded",
            };
            *seen.lock().unwrap().entry(name).or_default() += 1;
            runner.handle_event(&event);
        }
    });

    std::thread::sleep(Duration::from_secs(15));

    drain_bridge(&mut bridge, &runtime, handle);
    // Include the collector's final window, including recently opened unknown
    // flows whose normal attribution grace would otherwise defer the last write.
    std::thread::sleep(UNKNOWN_SOCKET_ATTRIBUTION_DELAY + Duration::from_millis(10));

    // Force the periodic active-flow persist rather than waiting on its timer.
    tracker.flush_active_flows().expect("flush active flows");
    tracker.flush().expect("flush");

    let writes = writes.lock().unwrap();
    let total_sent: i64 = writes.iter().map(|log| log.bytes_sent).sum();
    let total_received: i64 = writes.iter().map(|log| log.bytes_received).sum();
    let nonzero = writes
        .iter()
        .filter(|log| log.bytes_sent > 0 || log.bytes_received > 0)
        .count();

    println!("=== events delivered to tracker ===");
    for (name, count) in counts.lock().unwrap().iter() {
        println!("  {name}: {count}");
    }
    let observed = *byte_totals.lock().unwrap();
    println!(
        "=== bytes seen by tracker: sent={} received={} ===",
        observed.0, observed.1
    );
    println!("=== store writes: {} ===", writes.len());
    println!("=== rows with bytes: {nonzero} ===");
    println!("=== totals: sent={total_sent} received={total_received} ===");
    println!("=== tracked flows: {} ===", tracker.tracked_flow_count());
    println!(
        "=== system attribution: {:?} ===",
        processor.system_attribution_stats()
    );
    print_app_breakdown(&writes, &store);
    print_top_rows(&writes);
}

fn drain_bridge(
    bridge: &mut NetmetBridge,
    runtime: &tokio::runtime::Runtime,
    handle: tokio::task::JoinHandle<()>,
) {
    bridge.stop().expect("bridge stop");
    runtime.block_on(async {
        tokio::time::timeout(Duration::from_secs(10), handle)
            .await
            .expect("forwarding worker must drain and close the channel")
            .expect("event consumer");
    });
}

/// Prints the largest rows so a live run shows what actually carried bytes.
fn print_top_rows(writes: &std::sync::MutexGuard<'_, Vec<NewConnectionLog>>) {
    for log in writes
        .iter()
        .filter(|l| l.bytes_sent > 0 || l.bytes_received > 0)
        .take(5)
    {
        println!(
            "  {} {}:{} -> {}:{} sent={} recv={} app={}",
            log.protocol,
            log.src_ip,
            log.src_port,
            log.dst_ip,
            log.dst_port,
            log.bytes_sent,
            log.bytes_received,
            log.app_id
        );
    }
    for log in writes.iter().take(5) {
        println!(
            "  ZERO? {} {}:{} sent={} recv={} app={}",
            log.protocol, log.dst_ip, log.dst_port, log.bytes_sent, log.bytes_received, log.app_id
        );
    }
}

/// Groups captured rows by application so a live run shows which bucket —
/// `System` included — actually received the traffic.
fn print_app_breakdown(
    writes: &std::sync::MutexGuard<'_, Vec<NewConnectionLog>>,
    store: &Arc<antiwire_store::Store>,
) {
    let apps: std::collections::HashMap<i32, (String, String)> = store
        .list_applications()
        .map(|apps| {
            apps.into_iter()
                .map(|app| (app.id, (app.app_name, app.app_path)))
                .collect()
        })
        .unwrap_or_default();
    let mut by_app: std::collections::BTreeMap<i32, (u64, i64, i64)> =
        std::collections::BTreeMap::new();
    for log in writes.iter() {
        let entry = by_app.entry(log.app_id).or_insert((0, 0, 0));
        entry.0 += 1;
        entry.1 += log.bytes_sent;
        entry.2 += log.bytes_received;
    }
    println!("=== rows by application ===");
    for (app_id, (rows, sent, received)) in &by_app {
        let (name, path) = apps
            .get(app_id)
            .cloned()
            .unwrap_or_else(|| ("<missing>".to_owned(), String::new()));
        println!("  app_id={app_id} {name} [{path}] rows={rows} sent={sent} received={received}");
    }
}
