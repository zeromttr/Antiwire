//! Linux backend selection, optional DNS capture, and BPF object discovery.

use crate::load_retry::LoadRetry;
use netmetrics_core::DegradeReason;
use netmetrics_sys::{
    Backend, BackendConfig, BackendError, BackendErrorKind, BackendEvent, EventSink, FlowSources,
    NATIVE_RETRY_INTERVAL, StopFlag, run_with_fallback,
};
use std::env;
use std::fs;
use std::io;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

#[cfg(feature = "ebpf")]
mod ebpf;
#[cfg(not(feature = "ebpf"))]
#[path = "linux/ebpf_unavailable.rs"]
mod ebpf;
mod interface;
mod process;
mod procfs;

use procfs::ProcfsListing;
pub use procfs::{active_socket_count, socket_owner_snapshot, socket_owner_snapshot_for};

const CAP_SYS_ADMIN: u32 = 21;
const CAP_BPF: u32 = 39;

/// The backend's name in the events it reports.
const BACKEND_NAME: &str = "linux-ebpf";

#[path = "dns_sniffer.rs"]
mod dns_sniffer;

/// Aya eBPF collector with an automatic procfs lifecycle fallback.
#[derive(Debug, Default)]
pub struct LinuxBackend;

impl Backend for LinuxBackend {
    fn name(&self) -> &'static str {
        BACKEND_NAME
    }

    fn run(
        &mut self,
        config: &BackendConfig,
        sink: EventSink,
        stop: StopFlag,
    ) -> Result<(), BackendError> {
        // The sniffer reads its own socket with its own filter and names a query's sender
        // from /proc, so it runs once for the whole run, whichever flow source is up.
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
        let poll_interval = Duration::from_millis(config.poll_interval_ms.max(250));
        let mut sources = LinuxSources {
            poll_interval,
            retry: LoadRetry::default(),
        };
        let result = run_with_fallback(
            &mut sources,
            &mut ProcfsListing::default(),
            &sink,
            &stop,
            poll_interval,
            NATIVE_RETRY_INTERVAL,
        );
        dns_stop.store(true, Ordering::Release);
        if let Some(handle) = dns_thread {
            let _ = handle.join();
        }
        result
    }
}

/// eBPF, and the procfs fallback that stands in while it cannot start.
struct LinuxSources {
    /// How often the fallback polls, and the eBPF source samples interfaces and reconciles.
    poll_interval: Duration,
    /// Whether a retry would load the object again.
    retry: LoadRetry<ObjectFile>,
}

impl FlowSources for LinuxSources {
    const BACKEND_NAME: &'static str = BACKEND_NAME;
    const SNAPSHOT_SOURCE: &'static str = "procfs";
    type Native = ebpf::Probes;
    /// The connections the fallback last listed and the processes it reported. The eBPF
    /// source takes them over when it starts, and the fallback never runs after it.
    type Flows = ProcfsListing;

    /// Loads the object only when the load could end differently from the last one that
    /// failed, so a retry costs a file check while nothing has changed.
    ///
    /// A retry finds the object again, since an upgrade may install or replace it. A load
    /// that failed for a reason that passes ([`StartFailure::passes`]) is tried again at
    /// every retry. Any other failure, such as a missing privilege, a verifier rejection, a
    /// kernel without BTF or a missing kernel function, fails the same way for as long as
    /// the object and the kernel stay the same, so the object is loaded again only once it
    /// has changed. The object pins nothing and names no kernel object another instance
    /// could hold, so a start cannot fail for an instance that is still stopping.
    fn start_native(&mut self, sink: &EventSink) -> Result<ebpf::Probes, BackendError> {
        let Some(object) = find_bpf_object() else {
            let detail = if has_bpf_capability() {
                "NETMETRICS_BPF_OBJECT does not name a compiled CO-RE object"
            } else {
                "CAP_BPF/CAP_SYS_ADMIN is unavailable and no BPF object was configured"
            };
            return Err(BackendError::new(
                BackendErrorKind::Unavailable,
                BACKEND_NAME,
                detail,
            ));
        };
        let file = ObjectFile::of(&object);
        if let Some(error) = self.retry.repeated_failure(file.as_ref()) {
            return Err(error);
        }
        match ebpf::start(&object, sink) {
            Ok(probes) => {
                self.retry.succeeded();
                Ok(probes)
            }
            Err(failure) => {
                self.retry.failed(file, &failure.error, failure.passes);
                Err(failure.error)
            }
        }
    }

    /// Reads until stop is requested. Once started, nothing else ends the eBPF source (see
    /// [`ebpf::read`]), so the fallback never takes over from it.
    fn read_native(
        &mut self,
        probes: ebpf::Probes,
        listing: &mut ProcfsListing,
        sink: &EventSink,
        stop: &StopFlag,
    ) -> Result<(), BackendError> {
        ebpf::read(probes, listing, self.poll_interval, sink, stop);
        Ok(())
    }

    fn poll_snapshot(
        &mut self,
        listing: &mut ProcfsListing,
        sink: &EventSink,
    ) -> Result<(), BackendError> {
        listing.poll(sink)
    }
}

/// Why the eBPF source could not start.
struct StartFailure {
    error: BackendError,
    /// Whether loading the same object again could succeed: the cause was a lack of memory or
    /// a verification a signal interrupted, which `bpf(2)` documents as `ENOMEM` and
    /// `EAGAIN`.
    passes: bool,
}

/// The file an object path names, as `stat(2)` describes it. Installing an object, or
/// replacing it with one that has another inode (`inode(7)`), size or modification time,
/// changes it.
#[derive(Debug, Eq, PartialEq)]
struct ObjectFile {
    path: PathBuf,
    device: u64,
    inode: u64,
    size: u64,
    modified_seconds: i64,
    modified_nanoseconds: i64,
}

impl ObjectFile {
    /// `path`'s file, or `None` when it cannot be read: its object is then loaded again.
    fn of(path: &Path) -> Option<Self> {
        let metadata = fs::metadata(path).ok()?;
        Some(Self {
            path: path.to_owned(),
            device: metadata.dev(),
            inode: metadata.ino(),
            size: metadata.size(),
            modified_seconds: metadata.mtime(),
            modified_nanoseconds: metadata.mtime_nsec(),
        })
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replacing_an_object_changes_its_file() {
        let directory = env::temp_dir().join(format!("netmetrics-object-{}", std::process::id()));
        fs::create_dir_all(&directory).expect("create directory");
        let object = directory.join("netmetrics.bpf.o");
        fs::write(&object, b"first").expect("write object");
        let first = ObjectFile::of(&object);
        assert!(first.is_some());
        assert_eq!(
            ObjectFile::of(&object),
            first,
            "an unchanged object is the same file"
        );

        // An upgrade writes the new object beside the old one and renames it into place.
        let staged = directory.join("netmetrics.bpf.o.new");
        fs::write(&staged, b"first").expect("write staged object");
        fs::rename(&staged, &object).expect("replace object");
        let replaced = ObjectFile::of(&object);
        fs::remove_dir_all(&directory).expect("remove directory");

        assert_ne!(replaced, first, "a replaced object is another file");
        assert_eq!(
            ObjectFile::of(&object),
            None,
            "a missing object has no file"
        );
    }
}
