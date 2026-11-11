//! Linux backend selection, optional DNS capture, and BPF object discovery.

use netmetrics_core::DegradeReason;
use netmetrics_sys::{
    Backend, BackendConfig, BackendError, BackendErrorKind, BackendEvent, EventSink, StopFlag,
};
use std::env;
use std::fs;
use std::io;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

#[cfg(feature = "ebpf")]
mod ebpf;
mod interface;
mod process;
mod procfs;

use procfs::run_procfs;
pub use procfs::{active_socket_count, socket_owner_snapshot};

const CAP_SYS_ADMIN: u32 = 21;
const CAP_BPF: u32 = 39;

#[path = "dns_sniffer.rs"]
mod dns_sniffer;

/// Aya eBPF collector with an automatic procfs lifecycle fallback.
#[derive(Debug, Default)]
pub struct LinuxBackend;

impl Backend for LinuxBackend {
    fn name(&self) -> &'static str {
        "linux-ebpf"
    }

    fn run(
        &mut self,
        config: &BackendConfig,
        sink: EventSink,
        stop: StopFlag,
    ) -> Result<(), BackendError> {
        let dns_stop = Arc::new(AtomicBool::new(false));
        let dns_thread = if config.dns_hints {
            match dns_sniffer::spawn(
                sink.clone(),
                Arc::clone(&dns_stop),
                sink.native_capacity(),
                find_dns_filter_object().as_deref(),
            ) {
                Ok(handle) => Some(handle),
                Err(error) => {
                    sink.emit(BackendEvent::Degraded(DegradeReason::SourceUnavailable {
                        source: "linux-dns-hints".to_owned(),
                        detail: error.to_string(),
                    }));
                    None
                }
            }
        } else {
            None
        };
        let result = self.run_sources(config, &sink, &stop);
        dns_stop.store(true, Ordering::Release);
        if let Some(handle) = dns_thread {
            let _ = handle.join();
        }
        result
    }
}

impl LinuxBackend {
    fn run_sources(
        &mut self,
        config: &BackendConfig,
        sink: &EventSink,
        stop: &StopFlag,
    ) -> Result<(), BackendError> {
        if let Some(object) = find_bpf_object() {
            #[cfg(feature = "ebpf")]
            {
                match ebpf::run(&object, config, sink, stop) {
                    Ok(()) => return Ok(()),
                    Err(error) => {
                        sink.emit(BackendEvent::Degraded(error.degrade_reason(self.name())));
                    }
                }
            }
            #[cfg(not(feature = "ebpf"))]
            {
                let _ = object;
                sink.emit(BackendEvent::Degraded(DegradeReason::SourceUnavailable {
                    source: "aya".to_owned(),
                    detail: "crate built without the ebpf feature".to_owned(),
                }));
            }
        } else {
            let detail = if has_bpf_capability() {
                "NETMETRICS_BPF_OBJECT does not name a compiled CO-RE object"
            } else {
                "CAP_BPF/CAP_SYS_ADMIN is unavailable and no BPF object was configured"
            };
            sink.emit(BackendEvent::Degraded(DegradeReason::SourceUnavailable {
                source: "linux-ebpf".to_owned(),
                detail: detail.to_owned(),
            }));
        }

        sink.emit(BackendEvent::Degraded(DegradeReason::SnapshotOnly {
            source: "procfs".to_owned(),
        }));
        run_procfs(config, sink, stop)
    }
}

fn find_bpf_object() -> Option<PathBuf> {
    if let Some(path) = env::var_os("NETMETRICS_BPF_OBJECT").map(PathBuf::from) {
        return path.is_file().then_some(path);
    }
    let mut candidates = vec![
        PathBuf::from("/usr/lib/netmetrics/netmetrics.bpf.o"),
        PathBuf::from("/usr/local/lib/netmetrics/netmetrics.bpf.o"),
    ];
    if let Ok(executable) = env::current_exe()
        && let Some(parent) = executable.parent()
    {
        candidates.push(parent.join("netmetrics.bpf.o"));
    }
    candidates.into_iter().find(|path| path.is_file())
}

fn find_dns_filter_object() -> Option<PathBuf> {
    if let Some(path) = env::var_os("NETMETRICS_DNS_FILTER_OBJECT").map(PathBuf::from) {
        return path.is_file().then_some(path);
    }
    let mut candidates = vec![
        PathBuf::from("/usr/lib/netmetrics/dns_filter.bpf.o"),
        PathBuf::from("/usr/local/lib/netmetrics/dns_filter.bpf.o"),
    ];
    if let Ok(executable) = env::current_exe()
        && let Some(parent) = executable.parent()
    {
        candidates.push(parent.join("dns_filter.bpf.o"));
    }
    candidates.into_iter().find(|path| path.is_file())
}

fn has_bpf_capability() -> bool {
    let Ok(status) = fs::read_to_string("/proc/self/status") else {
        return false;
    };
    let Some(value) = status
        .lines()
        .find_map(|line| line.strip_prefix("CapEff:\t"))
        .and_then(|value| u64::from_str_radix(value, 16).ok())
    else {
        return false;
    };
    value & ((1_u64 << CAP_SYS_ADMIN) | (1_u64 << CAP_BPF)) != 0
}

fn io_error(source: &str, error: &io::Error) -> BackendError {
    let kind = if error.kind() == io::ErrorKind::PermissionDenied {
        BackendErrorKind::PermissionDenied
    } else {
        BackendErrorKind::Io
    };
    BackendError::new(kind, source, error.to_string())
}
