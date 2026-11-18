//! Collector lifecycle, retries, and polling for the Windows ETW backend.

use crate::owner_module::{self, CookiePoller, TcpOwnerSnapshot, UdpOwnerSnapshot};
use crate::session_names::SessionNames;
use arc_swap::ArcSwap;
use dns_trace::start_dns_trace;
use fallback::{IP_HELPER_SOURCE, IpHelperFallback, interface_stats};
use ferrisetw::trace::KernelTrace;
use flow_listener::FlowListening;
use kernel_trace::{KernelTraceState, start_kernel_trace};
use netmetrics_core::{DegradeReason, Protocol, SocketCount, unix_now_ms};
use netmetrics_sys::{
    Backend, BackendConfig, BackendError, BackendErrorKind, BackendEvent, EventSink, FallbackExit,
    NATIVE_RETRY_INTERVAL, SnapshotFallback, StopFlag,
};
use network::{ETW_CLOCK_LAG, TCP_PID_METRICS};
use session::{RunningTrace, SessionOwners, classify_trace_error, start_clearing_stale_session};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, LazyLock, Mutex};
use std::time::{Duration, Instant};

mod dns_flush;
mod dns_trace;
mod fallback;
mod flow_listener;
mod kernel_trace;
mod network;
mod process_trace;
mod session;
#[cfg(test)]
mod tests;

pub use dns_flush::{dns_event_flush_stats, request_dns_event_flush};
pub use dns_trace::dns_caller_recovery_stats;
pub use network::{
    UdpPidAttributionSample, address_string_fallback_count, etw_clock_lag, owner_evidence_stats,
    take_owner_disagreements, tcp_owner_cookie_hit_count, tcp_pid_attribution_stats,
    udp_pid_attribution_stats,
};
/// Count plus sample time from a successful TCP owner-table poll.
pub use owner_module::SocketCountSample;

/// How often each running ETW session is asked what it has lost.
const LOSS_POLL_INTERVAL: Duration = Duration::from_secs(1);

/// Kernel TCP/IP, process, and optional DNS-Client ETW collector.
#[derive(Debug, Default)]
pub struct WindowsBackend;

impl Backend for WindowsBackend {
    fn name(&self) -> &'static str {
        "windows-etw"
    }

    #[allow(clippy::too_many_lines)]
    fn run(
        &mut self,
        config: &BackendConfig,
        sink: EventSink,
        stop: StopFlag,
    ) -> Result<(), BackendError> {
        // ETW session names are global. A process-owned named mutex distinguishes an orphaned
        // trace from a live collector using the same configured name, so stale recovery never
        // tears down another running instance. Failure here must not skip the IP Helper
        // fallback: creating `Global\` mutexes requires the same elevation as kernel ETW, and
        // a live owner of this name must not be displaced.
        let names = match SessionNames::new(&config.session_name, config.dns_hints) {
            Ok(names) => names,
            Err(detail) => {
                return Err(BackendError::new(
                    BackendErrorKind::Unavailable,
                    "windows-etw-session",
                    detail,
                ));
            }
        };
        // A start can fail for reasons that pass: another run still tearing down its
        // session, or a transient ETW error. Snapshot polling covers the gap and gives ETW
        // another chance every `NATIVE_RETRY_INTERVAL`, so one bad start does not cost byte
        // accounting for the life of the daemon. Only the first failure is reported.
        let poll_interval = Duration::from_millis(config.poll_interval_ms.max(250));
        let mut fallback = SnapshotFallback::new(IP_HELPER_SOURCE);
        let mut ip_helper = IpHelperFallback::default();
        let EtwStart {
            session_owners,
            mut kernel_trace,
            tcp_owners,
            udp_owners,
            flow_owners,
            image_stops,
        } = loop {
            if let Some(etw) = self.start_etw(config, &names, &sink, !fallback.is_active()) {
                fallback.native_started(&sink);
                break etw;
            }
            match fallback.run(&sink, &stop, poll_interval, NATIVE_RETRY_INTERVAL, || {
                ip_helper.poll(&sink)
            })? {
                FallbackExit::Stopped => return Ok(()),
                FallbackExit::RetryNative => {}
            }
        };

        let mut flow_listening = FlowListening::new(flow_owners);

        let mut process_trace =
            match process_trace::start(config, names.process(), &session_owners, &sink) {
                Ok(trace) => Some(trace),
                Err(error) => {
                    sink.emit(BackendEvent::Degraded(
                        error.degrade_reason("windows-process-image"),
                    ));
                    None
                }
            };
        image_stops.store(process_trace.is_some(), Ordering::Release);
        let mut next_process_retry = process_trace
            .is_none()
            .then(|| Instant::now() + Duration::from_secs(1));

        let mut dns_trace = if config.dns_hints {
            match start_dns_trace(
                config,
                names.dns().expect("DNS logger name"),
                &session_owners,
                &sink,
            ) {
                Ok(trace) => Some(trace),
                Err(error) => {
                    sink.emit(BackendEvent::Degraded(error.degrade_reason(self.name())));
                    None
                }
            }
        } else {
            None
        };

        // The poller takes over the connections the fallback announced, and closes the ones
        // that ended while neither it nor ETW was watching.
        let mut cookie_poller = CookiePoller::new(
            tcp_owners,
            udp_owners,
            poll_interval,
            ip_helper.into_announced(),
        );
        let mut next_cookie_poll = Instant::now();
        let mut reported_cookie_error = false;
        let mut next_interface_poll = Instant::now();
        let mut reported_interface_error = false;
        let mut next_dns_retry = (config.dns_hints && dns_trace.is_none())
            .then(|| Instant::now() + Duration::from_secs(1));
        let mut next_loss_poll = Instant::now() + LOSS_POLL_INTERVAL;
        while !stop.is_stop_requested() {
            flow_listening.poll(&sink);
            if let Some(trace) = process_trace.as_ref()
                && let Some(result) = trace.processing_result()
            {
                let detail = format!("process image ETW processing ended: {result:?}");
                image_stops.store(false, Ordering::Release);
                let _ = process_trace.take().expect("process trace").stop();
                sink.emit(BackendEvent::Degraded(DegradeReason::SourceUnavailable {
                    source: "windows-process-image".to_owned(),
                    detail,
                }));
                next_process_retry = Some(Instant::now() + Duration::from_secs(1));
            }
            if process_trace.is_none()
                && next_process_retry.is_some_and(|deadline| Instant::now() >= deadline)
            {
                match process_trace::start(config, names.process(), &session_owners, &sink) {
                    Ok(trace) => {
                        process_trace = Some(trace);
                        image_stops.store(true, Ordering::Release);
                        next_process_retry = None;
                    }
                    Err(_) => {
                        next_process_retry = Some(Instant::now() + Duration::from_secs(5));
                    }
                }
            }
            if let Some(result) = kernel_trace.processing_result() {
                let detail = match result {
                    Ok(()) => "kernel ETW processing exited unexpectedly".to_owned(),
                    Err(detail) => format!("kernel ETW processing failed: {detail}"),
                };
                let _ = kernel_trace.stop();
                return Err(BackendError::new(
                    BackendErrorKind::SessionLost,
                    "windows-kernel-etw",
                    detail,
                ));
            }
            if let Some(trace) = dns_trace.as_ref()
                && let Some(result) = trace.processing_result()
            {
                let detail = match result {
                    Ok(()) => "DNS ETW processing exited unexpectedly".to_owned(),
                    Err(detail) => format!("DNS ETW processing failed: {detail}"),
                };
                let trace = dns_trace.take().expect("DNS trace");
                let _ = trace.stop();
                sink.emit(BackendEvent::Degraded(DegradeReason::SourceUnavailable {
                    source: "windows-dns-client".to_owned(),
                    detail,
                }));
                next_dns_retry = Some(Instant::now() + Duration::from_secs(1));
            }
            if dns_trace.is_none()
                && let Some(deadline) = next_dns_retry
                && Instant::now() >= deadline
            {
                match start_dns_trace(
                    config,
                    names.dns().expect("DNS logger name"),
                    &session_owners,
                    &sink,
                ) {
                    Ok(trace) => {
                        dns_trace = Some(trace);
                        next_dns_retry = None;
                    }
                    Err(error) => {
                        sink.emit(BackendEvent::Degraded(error.degrade_reason(self.name())));
                        next_dns_retry = Some(Instant::now() + Duration::from_secs(5));
                    }
                }
            }
            let now = Instant::now();
            // ETW carries no socket handle, so identity is joined on from the owner-module
            // tables. A failure here costs cookies, never the event stream.
            if now >= next_cookie_poll {
                match cookie_poller.poll(&sink, unix_now_ms()) {
                    Ok(()) => reported_cookie_error = false,
                    Err(detail) if !reported_cookie_error => {
                        reported_cookie_error = true;
                        sink.emit(BackendEvent::Degraded(DegradeReason::SourceUnavailable {
                            source: "windows-owner-module".to_owned(),
                            detail,
                        }));
                    }
                    Err(_) => {}
                }
                next_cookie_poll = Instant::now() + poll_interval;
            }
            if Instant::now() >= next_interface_poll {
                match interface_stats(unix_now_ms()) {
                    Ok(samples) => {
                        reported_interface_error = false;
                        for sample in samples {
                            sink.emit(BackendEvent::Interface(sample));
                        }
                    }
                    Err(detail) if !reported_interface_error => {
                        reported_interface_error = true;
                        sink.emit(BackendEvent::Degraded(DegradeReason::SourceUnavailable {
                            source: "windows-ip-helper-interface".to_owned(),
                            detail,
                        }));
                    }
                    Err(_) => {}
                }
                next_interface_poll = Instant::now() + poll_interval;
            }
            if Instant::now() >= next_loss_poll {
                kernel_trace.report_losses(&sink);
                if let Some(trace) = process_trace.as_mut() {
                    trace.report_losses(&sink);
                }
                if let Some(trace) = dns_trace.as_mut() {
                    trace.report_losses(&sink);
                }
                next_loss_poll = Instant::now() + LOSS_POLL_INTERVAL;
            }
            let deadline = next_cookie_poll
                .min(next_interface_poll)
                .min(next_loss_poll);
            stop.wait_deadline(deadline);
        }

        if let Some(trace) = dns_trace {
            let _ = trace.stop();
        }
        if let Some(trace) = process_trace {
            let _ = trace.stop();
        }
        kernel_trace
            .stop()
            .map_err(|error| classify_trace_error("kernel ETW", &error))
    }
}

/// A started kernel ETW session and the owner state its callbacks share.
struct EtwStart {
    session_owners: SessionOwners,
    kernel_trace: RunningTrace<KernelTrace>,
    tcp_owners: Arc<ArcSwap<TcpOwnerSnapshot>>,
    udp_owners: Arc<ArcSwap<UdpOwnerSnapshot>>,
    flow_owners: Arc<Mutex<crate::flow_owner::FlowOwnerCache>>,
    image_stops: Arc<AtomicBool>,
}

impl WindowsBackend {
    /// Acquires the session names and starts kernel ETW, clearing a stale session once.
    ///
    /// Returns `None` when ETW is unavailable; the failure is reported only when `report`.
    fn start_etw(
        &self,
        config: &BackendConfig,
        names: &SessionNames,
        sink: &EventSink,
        report: bool,
    ) -> Option<EtwStart> {
        let degraded = |reason: DegradeReason| {
            if report {
                sink.emit(BackendEvent::Degraded(reason));
            }
        };
        let session_owners = match SessionOwners::acquire(names) {
            Ok(owner) => owner,
            Err(detail) => {
                degraded(DegradeReason::SourceUnavailable {
                    source: "windows-etw-session".to_owned(),
                    detail,
                });
                return None;
            }
        };
        // Allocate diagnostic counters before callbacks begin; callback updates are atomic only.
        LazyLock::force(&TCP_PID_METRICS);
        let tcp_owners = Arc::new(ArcSwap::from_pointee(TcpOwnerSnapshot::default()));
        let udp_owners = Arc::new(ArcSwap::from_pointee(UdpOwnerSnapshot::default()));
        let flow_owners = Arc::new(Mutex::new(crate::flow_owner::FlowOwnerCache::default()));
        let image_stops = Arc::new(AtomicBool::new(false));
        // A new session converts its timestamps from a new reference.
        ETW_CLOCK_LAG.reset(unix_now_ms());
        let state = KernelTraceState {
            tcp_owners: &tcp_owners,
            udp_owners: &udp_owners,
            flow_owners: &flow_owners,
            image_stops: &image_stops,
        };
        let kernel_trace =
            match start_clearing_stale_session(&session_owners, names.kernel(), || {
                start_kernel_trace(config, names.kernel(), &session_owners, sink, &state)
            }) {
                Ok(trace) => trace,
                Err(detail) => {
                    let error = classify_trace_error("kernel ETW", &detail);
                    degraded(error.degrade_reason(self.name()));
                    return None;
                }
            };
        Some(EtwStart {
            session_owners,
            kernel_trace,
            tcp_owners,
            udp_owners,
            flow_owners,
            image_stops,
        })
    }
}

/// Returns the number of established TCP connections, IPv4 and IPv6.
///
/// Prefers a fresh owner-module poll sample so a running collector does not
/// issue another table syscall. Stale samples (older than five seconds) and a
/// missing cache fall through to the `OWNER_PID` walker. Walker failure keeps the
/// last-known count and marks it stale; never sampled and walker failure is
/// unavailable, not a valid zero.
///
/// A row counts when its state is established (`TcpState::is_established`) and it
/// names an owning process and both ports. Listeners, handshakes and connections this
/// end has sent its FIN on are skipped.
#[must_use]
pub fn active_socket_count() -> SocketCount {
    owner_module::active_tcp_socket_count()
}

/// TCP 5-tuple and UDP bind owners from the IP Helper owner-module tables.
#[must_use]
pub fn socket_owner_snapshot() -> netmetrics_core::SocketOwnerSnapshot {
    owner_module::socket_owner_snapshot()
}

/// [`socket_owner_snapshot`] limited to the tables of `protocol`.
#[must_use]
pub fn socket_owner_snapshot_for(protocol: Protocol) -> netmetrics_core::SocketOwnerSnapshot {
    owner_module::socket_owner_snapshot_for(protocol)
}
