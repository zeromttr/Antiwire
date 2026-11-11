//! eBPF capability groups and transactional attachment of kernel probes.

use crate::capability::CapabilityMatrix;
use aya::Ebpf;
use aya::programs::kprobe::KProbeLinkId;
use aya::programs::{KProbe, TracePoint};
use netmetrics_core::DegradeReason;
use netmetrics_sys::{BackendError, BackendErrorKind, BackendEvent, EventSink};

struct AttachReport {
    attached: usize,
    failures: Vec<String>,
}

/// Attaches every probe group, reporting each one's outcome to `sink`.
pub(super) fn attach_probes(bpf: &mut Ebpf, sink: &EventSink) -> CapabilityMatrix {
    let lifecycle = report_capability(
        sink,
        "tcp-lifecycle",
        attach_tracepoint(bpf, "inet_sock_set_state", "sock", "inet_sock_set_state"),
    );
    let tcp_send = report_capability(
        sink,
        "tcp-send",
        attach_kprobe_pair(
            bpf,
            "trace_tcp_sendmsg",
            "complete_tcp_sendmsg",
            &["tcp_sendmsg"],
        ),
    );
    let tcp_receive = report_capability(
        sink,
        "tcp-receive",
        attach_single_kprobe(bpf, "trace_tcp_cleanup_rbuf", &["tcp_cleanup_rbuf"]),
    );
    let udp_send = report_capability(
        sink,
        "udp-send",
        attach_kprobe_pair(
            bpf,
            "trace_udp_sendmsg",
            "complete_udp_sendmsg",
            &["udp_sendmsg", "udpv6_sendmsg"],
        ),
    );
    let udp_receive = report_capability(
        sink,
        "udp-receive",
        attach_kprobe_pair(
            bpf,
            "track_udp_recvmsg",
            "trace_udp_recvmsg",
            &["udp_recvmsg", "udpv6_recvmsg"],
        ),
    );
    let _udp_lifecycle = report_capability(
        sink,
        "udp-lifecycle",
        attach_single_kprobe(
            bpf,
            "trace_udp_destroy_sock",
            &["udp_destroy_sock", "udpv6_destroy_sock"],
        ),
    );
    CapabilityMatrix {
        lifecycle,
        tcp_send,
        tcp_receive,
        udp_send,
        udp_receive,
    }
}

fn report_capability(
    sink: &EventSink,
    capability: &str,
    result: Result<AttachReport, BackendError>,
) -> bool {
    match result {
        Ok(report) if report.attached > 0 => {
            if !report.failures.is_empty() {
                sink.emit(BackendEvent::Degraded(DegradeReason::SourceUnavailable {
                    source: format!("linux-ebpf-{capability}"),
                    detail: format!(
                        "partial capability; unavailable symbols: {}",
                        report.failures.join("; ")
                    ),
                }));
            }
            true
        }
        Ok(_) => {
            sink.emit(BackendEvent::Degraded(DegradeReason::SourceUnavailable {
                source: format!("linux-ebpf-{capability}"),
                detail: "no supported kernel symbol attached".to_owned(),
            }));
            false
        }
        Err(error) => {
            sink.emit(BackendEvent::Degraded(DegradeReason::SourceUnavailable {
                source: format!("linux-ebpf-{capability}"),
                detail: error.to_string(),
            }));
            false
        }
    }
}

fn load_kprobe(bpf: &mut Ebpf, program_name: &str) -> Result<(), BackendError> {
    let program: &mut KProbe = bpf
        .program_mut(program_name)
        .ok_or_else(|| missing_program(program_name))?
        .try_into()
        .map_err(|error: aya::programs::ProgramError| loader_error(error.to_string()))?;
    program
        .load()
        .map_err(|error| loader_error(error.to_string()))
}

fn attach_single_kprobe(
    bpf: &mut Ebpf,
    program_name: &str,
    functions: &[&str],
) -> Result<AttachReport, BackendError> {
    load_kprobe(bpf, program_name)?;
    let mut attached = 0;
    let mut errors = Vec::new();
    for function in functions {
        let program = kprobe(bpf, program_name)?;
        match program.attach(function, 0) {
            Ok(_) => attached += 1,
            Err(error) => errors.push(format!("{function}: {error}")),
        }
    }
    if attached == 0 {
        Err(loader_error(errors.join("; ")))
    } else {
        Ok(AttachReport {
            attached,
            failures: errors,
        })
    }
}

fn attach_kprobe_pair(
    bpf: &mut Ebpf,
    entry_name: &str,
    return_name: &str,
    functions: &[&str],
) -> Result<AttachReport, BackendError> {
    load_kprobe(bpf, entry_name)?;
    load_kprobe(bpf, return_name)?;
    let mut attached = 0;
    let mut errors = Vec::new();
    for function in functions {
        match attach_pair_symbol(bpf, entry_name, return_name, function) {
            Ok(()) => attached += 1,
            Err(error) => errors.push(format!("{function}: {error}")),
        }
    }
    if attached == 0 {
        Err(loader_error(errors.join("; ")))
    } else {
        Ok(AttachReport {
            attached,
            failures: errors,
        })
    }
}

fn attach_pair_symbol(
    bpf: &mut Ebpf,
    entry_name: &str,
    return_name: &str,
    function: &str,
) -> Result<(), BackendError> {
    let entry_link = kprobe(bpf, entry_name)?
        .attach(function, 0)
        .map_err(|error| loader_error(error.to_string()))?;
    match kprobe(bpf, return_name)?.attach(function, 0) {
        Ok(_) => Ok(()),
        Err(error) => {
            detach_quietly(bpf, entry_name, entry_link);
            Err(loader_error(error.to_string()))
        }
    }
}

fn kprobe<'a>(bpf: &'a mut Ebpf, program_name: &str) -> Result<&'a mut KProbe, BackendError> {
    bpf.program_mut(program_name)
        .ok_or_else(|| missing_program(program_name))?
        .try_into()
        .map_err(|error: aya::programs::ProgramError| loader_error(error.to_string()))
}

fn detach_quietly(bpf: &mut Ebpf, program_name: &str, link: KProbeLinkId) {
    if let Ok(program) = kprobe(bpf, program_name) {
        let _ = program.detach(link);
    }
}

fn attach_tracepoint(
    bpf: &mut Ebpf,
    program_name: &str,
    category: &str,
    event: &str,
) -> Result<AttachReport, BackendError> {
    let program: &mut TracePoint = bpf
        .program_mut(program_name)
        .ok_or_else(|| missing_program(program_name))?
        .try_into()
        .map_err(|error: aya::programs::ProgramError| loader_error(error.to_string()))?;
    program
        .load()
        .and_then(|()| {
            program.attach(category, event).map(|_| AttachReport {
                attached: 1,
                failures: Vec::new(),
            })
        })
        .map_err(|error| loader_error(error.to_string()))
}

fn missing_program(name: &str) -> BackendError {
    loader_error(format!("BPF object does not contain program {name}"))
}

pub(super) fn loader_error(detail: String) -> BackendError {
    BackendError::new(BackendErrorKind::Unavailable, "aya-loader", detail)
}
