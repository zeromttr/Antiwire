use super::attribution::closed_owner_kind;
use super::*;
use crate::test_support::{allocations, fixture, processor};
use antiwire_events::TrafficStreamingHub;

fn key(port: u16) -> FlowKey {
    FlowKey {
        protocol: Protocol::Tcp,
        local_addr: "127.0.0.1".parse().unwrap(),
        local_port: port,
        remote_addr: "203.0.113.1".parse().unwrap(),
        remote_port: 443,
    }
}

#[cfg(windows)]
#[test]
fn delayed_native_results_cannot_overwrite_changed_flow_evidence() {
    use crate::test_support::install_native_probe;
    use netmetrics_core::CookieSource;
    use std::sync::mpsc;
    let child = NativeTestProcess::new();
    let pid = child.0.id();
    let system = sysinfo::System::new_all();
    let start = system
        .process(sysinfo::Pid::from_u32(pid))
        .unwrap()
        .start_time()
        * 1000;
    for change in ["connection", "pid", "start", "cookie", "identity"] {
        let f = fixture();
        let traffic = TrafficStreamingHub::with_capacity(4);
        let tracker = Arc::new(FlowTracker::with_processor(
            |_logs: &[NewConnectionLog]| Ok(()),
            Some(processor(&f, traffic)),
        ));
        let k = key(59104);
        prepare_recovery(&tracker, k, pid, start);
        let (entered_tx, entered_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let a_tracker = tracker.clone();
        let a = std::thread::spawn(move || {
            install_native_probe("process", move || {
                entered_tx.send(()).unwrap();
                release_rx.recv_timeout(Duration::from_secs(5)).unwrap();
            });
            a_tracker.on_bytes(
                k,
                ByteDelta {
                    sent: 1,
                    received: 2,
                },
            );
        });
        entered_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("native query reached");
        if change == "connection" {
            tracker.on_closed(k, &metadata(pid, "", "", start));
            tracker.on_opened(
                k,
                &metadata(
                    991_207,
                    r"C:\Validation\replacement.exe",
                    "replacement.exe",
                    20_000,
                ),
            );
        }
        let expected = {
            let mut active = tracker.active.lock();
            let flow = active.get_mut(&k).unwrap();
            match change {
                "connection" => {}
                "pid" => flow.pid += 1,
                "start" => flow.process_start_ts = Some(start + 10_000),
                "cookie" => {
                    flow.cookie = Some(SocketCookie {
                        value: 123,
                        source: CookieSource::LinuxSockCookie,
                    });
                }
                "identity" => {
                    flow.app_id = 987;
                    flow.app_path = r"C:\Validation\new.exe".to_owned();
                    flow.app_name = "new.exe".to_owned();
                }
                _ => unreachable!(),
            }
            // Concurrent deltas and persisted baselines must survive a lookup.
            flow.bytes_sent = 42;
            flow.bytes_received = 43;
            flow.persisted_sent = 11;
            flow.persisted_received = 12;
            AttributionVersion::capture(flow)
        };
        let recoveries_before_release = tracker.identity_recoveries.load(Ordering::Relaxed);
        release_tx.send(()).unwrap();
        a.join().unwrap();
        let active = tracker.active.lock();
        let flow = active.get(&k).unwrap();
        assert!(
            expected.matches(flow),
            "late lookup overwrote changed {change}"
        );
        assert_eq!(flow.attribution_lookup, AttributionLookup::Idle);
        assert_eq!((flow.bytes_sent, flow.bytes_received), (42, 43));
        assert_eq!((flow.persisted_sent, flow.persisted_received), (11, 12));
        assert_eq!(
            tracker.identity_recoveries.load(Ordering::Relaxed),
            recoveries_before_release
        );
    }
}

fn metadata(pid: u32, path: &str, name: &str, start_ts: u64) -> FlowMeta {
    FlowMeta {
        pid,
        process: Some(ProcessIdentity {
            executable: path.to_owned(),
            name: name.to_owned(),
            start_ts,
        }),
        open_ts: 0,
        cookie: None,
        if_index: None,
    }
}

#[cfg(windows)]
fn prepare_recovery<S: FlowStore>(tracker: &FlowTracker<S>, k: FlowKey, pid: u32, start: u64) {
    tracker.on_opened(k, &metadata(pid, r"C:\Validation\seed.exe", "seed.exe", 1));
    let mut active = tracker.active.lock();
    let flow = active.get_mut(&k).unwrap();
    flow.app_path = "Unknown (Exited)".to_owned();
    flow.app_name = "unknown.exe".to_owned();
    flow.process_start_ts = Some(start);
    flow.next_identity_retry = None;
    flow.identity_lookup_attempts = 0;
}

#[test]
fn byte_deltas_without_subscribers_allocate_no_identity_strings() {
    let f = fixture();
    let traffic = TrafficStreamingHub::with_capacity(4);
    let p = processor(&f, traffic.clone());
    let tracker = FlowTracker::with_processor(|_logs: &[NewConnectionLog]| Ok(()), Some(p));
    let name = format!("{}.exe", "n".repeat(83));
    let path = format!(r"C:\AllocationValidation\{}\{name}", "p".repeat(257));
    let k = key(59101);
    tracker.on_opened(k, &metadata(991_205, &path, &name, 10_000));
    tracker.on_bytes(
        k,
        ByteDelta {
            sent: 1,
            received: 2,
        },
    );
    assert!(!traffic.has_subscribers());
    let counts = allocations(name.len(), path.len(), || {
        for _ in 0..1000 {
            tracker.on_bytes(
                k,
                ByteDelta {
                    sent: 1,
                    received: 2,
                },
            );
        }
    });
    assert_eq!(
        counts,
        [0, 0, 0],
        "unobserved byte events should allocate nothing"
    );
    assert_eq!(traffic.total_bytes_sent(), 1001);
    assert_eq!(traffic.total_bytes_received(), 2002);
}

#[cfg(windows)]
/// Returns a service host whose start time and image path this process can read.
///
/// Unelevated, Windows reports a protected service's start time as 0, but
/// per-user service hosts run under the caller's own account and stay readable.
fn service_pid(system: &sysinfo::System) -> Option<u32> {
    system
        .processes()
        .values()
        .find(|p| {
            p.name()
                .to_string_lossy()
                .eq_ignore_ascii_case("svchost.exe")
                && p.start_time() > 0
                && p.exe().is_some()
        })
        .map(|p| p.pid().as_u32())
}

#[cfg(windows)]
/// The native queries to exercise: the child process, plus SCM when a service
/// host is readable.
fn native_query_cases(system: &sysinfo::System, process_pid: u32) -> Vec<(&'static str, u32)> {
    let mut cases = vec![("process", process_pid)];
    match service_pid(system) {
        Some(pid) => cases.push(("scm", pid)),
        None => println!(
            "skipping native scm query: no svchost.exe with a readable start time \
             and path (run elevated to cover it)"
        ),
    }
    cases
}

#[cfg(windows)]
struct NativeTestProcess(std::process::Child);

#[cfg(windows)]
impl NativeTestProcess {
    fn new() -> Self {
        Self(
            std::process::Command::new("ping.exe")
                .args(["-n", "60", "127.0.0.1"])
                .stdout(std::process::Stdio::null())
                .spawn()
                .unwrap(),
        )
    }
}

#[cfg(windows)]
impl Drop for NativeTestProcess {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[cfg(windows)]
#[test]
fn forced_lifecycle_refresh_survives_an_in_flight_failed_lookup_at_the_retry_cap() {
    use crate::test_support::install_native_probe;
    use std::sync::mpsc;
    let child = NativeTestProcess::new();
    let pid = child.0.id();
    let system = sysinfo::System::new_all();
    let live_start = system
        .process(sysinfo::Pid::from_u32(pid))
        .unwrap()
        .start_time()
        * 1000;
    let old_start = live_start.checked_sub(60_000).unwrap();
    let f = fixture();
    let tracker = Arc::new(FlowTracker::with_processor(
        |_logs: &[NewConnectionLog]| Ok(()),
        Some(processor(&f, TrafficStreamingHub::with_capacity(4))),
    ));
    let k = key(59105);
    prepare_recovery(&tracker, k, pid, old_start);
    tracker
        .active
        .lock()
        .get_mut(&k)
        .unwrap()
        .identity_lookup_attempts = MAX_IDENTITY_LOOKUP_ATTEMPTS;
    let (entered_tx, entered_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let a_tracker = tracker.clone();
    let a = std::thread::spawn(move || {
        install_native_probe("process", move || {
            entered_tx.send(()).unwrap();
            release_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        });
        a_tracker.refresh_active_attribution(&k, true, None);
    });
    entered_rx.recv_timeout(Duration::from_secs(5)).unwrap();
    // The native lookup sees a different generation. Meanwhile a delayed,
    // authoritative lifecycle event supplies the original flow's real path.
    let event = FlowEvent::ProcessStarted(netmetrics_core::ProcessInfo {
        pid,
        identity: ProcessIdentity {
            executable: r"C:\Validation\captured.exe".to_owned(),
            name: "captured.exe".to_owned(),
            start_ts: old_start,
        },
    });
    // The production dispatcher registers lifecycle evidence before the tracker.
    tracker.processor.as_ref().unwrap().handle_event(&event);
    tracker.handle_event(&event);
    release_tx.send(()).unwrap();
    a.join().unwrap();
    let active = tracker.active.lock();
    let flow = active.get(&k).unwrap();
    assert_eq!(flow.app_path, r"C:\Validation\captured.exe");
    assert_eq!(flow.app_name, "captured.exe");
    assert_eq!(flow.process_start_ts, Some(old_start));
    assert_eq!(flow.attribution_lookup, AttributionLookup::Idle);
    assert_eq!(
        tracker.identity_recovery_attempts.load(Ordering::Relaxed),
        2
    );
    assert_eq!(tracker.identity_recoveries.load(Ordering::Relaxed), 1);
}

#[cfg(windows)]
#[test]
#[expect(
    clippy::too_many_lines,
    reason = "exercise process and SCM query stalls during both recovery and flush"
)]
fn native_queries_allow_other_flow_bytes_during_recovery_and_flush() {
    use crate::test_support::install_native_probe;
    use std::sync::mpsc;
    let child = NativeTestProcess::new();
    let system = sysinfo::System::new_all();
    for (query, pid) in native_query_cases(&system, child.0.id()) {
        for flush in [false, true] {
            let start = system
                .process(sysinfo::Pid::from_u32(pid))
                .unwrap()
                .start_time()
                * 1000;
            assert!(start > 0);
            let f = fixture();
            let traffic = TrafficStreamingHub::with_capacity(4);
            let tracker = Arc::new(FlowTracker::with_processor(
                |_logs: &[NewConnectionLog]| Ok(()),
                Some(processor(&f, traffic)),
            ));
            let recovering = key(59102);
            let other = key(59103);
            prepare_recovery(&tracker, recovering, pid, start);
            tracker.on_opened(
                other,
                &metadata(991_206, r"C:\Validation\other.exe", "other.exe", 10_000),
            );
            let (entered_tx, entered_rx) = mpsc::channel();
            let (release_tx, release_rx) = mpsc::channel();
            let a_tracker = tracker.clone();
            let a = std::thread::spawn(move || {
                let probe_tracker = a_tracker.clone();
                install_native_probe(query, move || {
                    assert!(
                        probe_tracker.active.try_lock().is_some(),
                        "native queries must run without the active-flow lock"
                    );
                    assert!(
                        probe_tracker.flush_gate.try_lock().is_some(),
                        "native queries must not hold the lifecycle gate"
                    );
                    entered_tx.send(()).unwrap();
                    release_rx.recv_timeout(Duration::from_secs(5)).unwrap();
                });
                if flush {
                    a_tracker.flush_active_flows().unwrap();
                } else {
                    a_tracker.on_bytes(
                        recovering,
                        ByteDelta {
                            sent: 1,
                            received: 0,
                        },
                    );
                }
            });
            entered_rx
                .recv_timeout(Duration::from_secs(5))
                .expect("native query reached");
            let (done_tx, done_rx) = mpsc::channel();
            let b_tracker = tracker.clone();
            let b = std::thread::spawn(move || {
                b_tracker.on_opened(
                    other,
                    &metadata(991_206, r"C:\Validation\other.exe", "other.exe", 10_000),
                );
                b_tracker.on_bytes(
                    other,
                    ByteDelta {
                        sent: 9,
                        received: 0,
                    },
                );
                b_tracker.on_bytes(
                    recovering,
                    ByteDelta {
                        sent: 7,
                        received: 3,
                    },
                );
                done_tx.send(()).unwrap();
            });
            let completed = done_rx.recv_timeout(Duration::from_millis(250)).is_ok();
            release_tx.send(()).unwrap();
            a.join().unwrap();
            b.join().unwrap();
            assert!(
                completed,
                "other byte update must complete before query release"
            );
            assert_eq!(tracker.active.lock().get(&other).unwrap().bytes_sent, 9);
            let active = tracker.active.lock();
            let recovered = active.get(&recovering).unwrap();
            assert_eq!(recovered.bytes_sent, if flush { 7 } else { 8 });
            assert_eq!(recovered.bytes_received, 3);
            assert_eq!(
                tracker.identity_recovery_attempts.load(Ordering::Relaxed),
                1
            );
            assert_eq!(tracker.identity_recoveries.load(Ordering::Relaxed), 1);
            println!("native {query} query allows unrelated bytes; flush={flush}");
        }
    }
}

#[test]
fn a_closed_connection_is_counted_by_the_kind_of_owner_it_ended_with() {
    let system_path = crate::system_services::SYSTEM_APP_PATH;
    let system_name = crate::system_services::SYSTEM_APP_NAME;
    for (path, name, kind) in [
        (r"C:\Program Files\Apppp.exe", "app.exe", 0),
        (system_path, system_name, 1),
        ("Path unavailable", "app.exe", 2),
        ("", "", 3),
        ("Unknown (No Owner)", "unknown.exe", 3),
        ("Unknown (Exited)", "unknown.exe", 4),
        ("Unknown (Access Denied)", "unknown.exe", 5),
    ] {
        assert_eq!(closed_owner_kind(path, name), kind, "{path:?}");
    }
}
