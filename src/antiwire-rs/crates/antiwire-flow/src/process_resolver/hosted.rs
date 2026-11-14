//! Splits generic Windows host processes into one identity per hosted workload.
//!
//! ETW attributes a flow to a process, so every service sharing one
//! `svchost.exe` and every DLL run through `rundll32.exe` would otherwise land
//! in one opaque application row. Each [`Host`] names such a binary and how to
//! ask an instance what it hosts. This module owns the rest: which identities
//! qualify, the per-PID caches, and the stored `exe::label` identity shape.

mod rundll32;
mod svchost;

use moka::sync::Cache;

use super::path::{
    has_path_separators, is_synthetic_path, is_system_host_binary, path_ends_with_ignore_ascii_case,
};
use super::{start_ts_compatible, ResolvedIdentity};

#[cfg(test)]
use std::sync::atomic::{AtomicU64, Ordering};

/// The labelled host identities of one [`super::ProcessIdentities`].
pub(super) struct HostedIdentities {
    hosts: [Host; 2],
}

impl HostedIdentities {
    pub(super) fn new() -> Self {
        Self {
            hosts: [
                Host::new("svchost.exe", svchost::hosted_services),
                Host::new("rundll32.exe", rundll32::hosted_module),
            ],
        }
    }

    /// Gives a host process the identity of what it hosts. Any other identity
    /// is returned unchanged.
    pub(super) fn disambiguate(&self, pid: u32, identity: ResolvedIdentity) -> ResolvedIdentity {
        match self.hosts.iter().find(|host| host.names(&identity)) {
            Some(host) => host.disambiguate(pid, identity),
            None => identity,
        }
    }

    /// Drops every cached host identity for a PID that stopped or was reused.
    pub(super) fn forget(&self, pid: u32) {
        for host in &self.hosts {
            host.cache.invalidate(&pid);
        }
    }
}

/// A Windows binary that runs other code on its behalf.
struct Host {
    /// Image file name, as installed under the Windows directory.
    file: &'static str,
    /// Names what the instance with this PID hosts, or `None` when that cannot
    /// be read or the instance hosts nothing identifiable.
    label: fn(u32) -> Option<String>,
    /// Labelled identities by PID. Each host keeps its own, so a recycled PID
    /// whose creation time is unknown cannot take another host's label.
    cache: Cache<u32, ResolvedIdentity>,
    /// How many times `label` ran, so tests can prove a query was skipped.
    #[cfg(test)]
    queries: AtomicU64,
}

impl Host {
    fn new(file: &'static str, label: fn(u32) -> Option<String>) -> Self {
        Self {
            file,
            label,
            cache: super::cache::identity_cache(),
            #[cfg(test)]
            queries: AtomicU64::new(0),
        }
    }

    /// Whether `identity` is this host, by process name or by image path.
    fn names(&self, identity: &ResolvedIdentity) -> bool {
        let stem = self.file.strip_suffix(".exe").unwrap_or(self.file);
        identity.name.eq_ignore_ascii_case(self.file)
            || identity.name.eq_ignore_ascii_case(stem)
            || path_ends_with_ignore_ascii_case(&identity.path, self.file)
    }

    fn disambiguate(&self, pid: u32, identity: ResolvedIdentity) -> ResolvedIdentity {
        // Only a real image path can be checked against the Windows directory. A
        // placeholder keeps its identity: looking the PID up again here would skip
        // the creation-time check the resolver already applied, and could label a
        // recycled PID's new occupant.
        if !has_path_separators(&identity.path) || is_synthetic_path(&identity.path) {
            return identity;
        }
        if let Some(cached) = self.cached(pid, identity.start_ts) {
            return cached;
        }
        let resolved = self.labelled(pid, identity);
        self.cache.insert(pid, resolved.clone());
        resolved
    }

    fn cached(&self, pid: u32, start_ts: u64) -> Option<ResolvedIdentity> {
        let cached = self.cache.get(&pid)?;
        if start_ts_compatible(cached.start_ts, Some(start_ts)) {
            return Some(cached);
        }
        // The PID was recycled onto a new process; the label belongs to the
        // previous one.
        self.cache.invalidate(&pid);
        None
    }

    fn labelled(&self, pid: u32, identity: ResolvedIdentity) -> ResolvedIdentity {
        // Only the copy installed under the Windows directory is asked what it
        // hosts. Asking every self-named binary would let any process make the
        // daemon walk the service database or read its command line.
        let label = if is_system_host_binary(&identity.path, self.file) {
            #[cfg(test)]
            self.queries.fetch_add(1, Ordering::Relaxed);
            (self.label)(pid)
        } else {
            None
        };
        match label {
            Some(label) => hosted_identity(&identity, self.file, &label),
            // A failed disambiguation must never be worse than none, so the
            // host keeps its plain name.
            None => ResolvedIdentity {
                name: self.file.to_owned(),
                ..identity
            },
        }
    }

    #[cfg(test)]
    fn query_count(&self) -> u64 {
        self.queries.load(Ordering::Relaxed)
    }
}

/// The identity of one workload inside a host. The `exe::label` path keeps the
/// executable recoverable for icon lookup, and `label (host.exe)` names the
/// row. Both are stored, so changing either renames existing applications.
fn hosted_identity(plain: &ResolvedIdentity, file: &str, label: &str) -> ResolvedIdentity {
    let label = label.trim();
    ResolvedIdentity {
        path: format!("{}::{label}", plain.path),
        name: format!("{label} ({file})"),
        start_ts: plain.start_ts,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity(path: &str, name: &str) -> ResolvedIdentity {
        ResolvedIdentity {
            path: path.to_owned(),
            name: name.to_owned(),
            start_ts: 0,
        }
    }

    impl HostedIdentities {
        fn host(&self, file: &str) -> &Host {
            self.hosts
                .iter()
                .find(|host| host.file == file)
                .expect("host")
        }
    }

    fn system_path(file: &str) -> String {
        let root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".to_owned());
        format!(r"{root}\System32\{file}")
    }

    #[test]
    fn hosted_identities_keep_their_stored_shape() {
        let (svchost, rundll32) = (
            hosted_identity(
                &identity(r"C:\Windows\System32\svchost.exe", "svchost.exe"),
                "svchost.exe",
                " BITS,Dnscache ",
            ),
            hosted_identity(
                &identity(r"C:\Windows\System32\rundll32.exe", "rundll32.exe"),
                "rundll32.exe",
                "shell32.dll,Control_RunDLL",
            ),
        );
        assert_eq!(
            svchost.path,
            r"C:\Windows\System32\svchost.exe::BITS,Dnscache"
        );
        assert_eq!(svchost.name, "BITS,Dnscache (svchost.exe)");
        assert_eq!(
            rundll32.path,
            r"C:\Windows\System32\rundll32.exe::shell32.dll,Control_RunDLL"
        );
        assert_eq!(rundll32.name, "shell32.dll,Control_RunDLL (rundll32.exe)");
    }

    #[test]
    fn hosts_are_named_by_process_name_or_image_path() {
        for host in &HostedIdentities::new().hosts {
            let stem = host.file.trim_end_matches(".exe");
            assert!(host.names(&identity("", host.file)));
            assert!(host.names(&identity("", &stem.to_ascii_uppercase())));
            assert!(host.names(&identity(&system_path(host.file), "renamed.exe")));
            assert!(!host.names(&identity(r"C:\Tools\tool.exe", "tool.exe")));
        }
    }

    #[test]
    fn other_processes_pass_through_even_with_multibyte_paths() {
        // Five three-byte characters: 15 bytes, so a host-name suffix window
        // starting at byte 3 or 4 lands inside a character.
        let path = "€€€€€";
        let result = HostedIdentities::new().disambiguate(0, identity(path, "tool.exe"));
        assert_eq!(result, identity(path, "tool.exe"));
    }

    #[test]
    fn self_named_hosts_outside_the_windows_directory_are_not_queried() {
        let pid = 51_500;
        for host in &HostedIdentities::new().hosts {
            let path = format!(r"C:\Users\me\AppData\Local\Temp\{}", host.file);
            let result = host.disambiguate(pid, identity(&path, host.file));
            assert_eq!(result, identity(&path, host.file));
            assert_eq!(
                host.query_count(),
                0,
                "a self-named {} must not be asked what it hosts",
                host.file
            );
        }
    }

    #[test]
    fn placeholder_paths_are_not_looked_up_again_by_pid() {
        // A live PID whose image is not a host: querying it would label this
        // test binary under the host's name.
        let pid = std::process::id();
        let placeholder = super::super::placeholder_path();
        for host in &HostedIdentities::new().hosts {
            let result = host.disambiguate(pid, identity(placeholder, host.file));
            assert_eq!(result, identity(placeholder, host.file));
            assert_eq!(host.query_count(), 0);
        }
    }

    #[test]
    fn an_unreadable_label_keeps_the_plain_identity() {
        let hosted = HostedIdentities::new();
        let rundll32 = hosted.host("rundll32.exe");
        // PID 0 can never be opened, so its command line cannot be read.
        let path = system_path(rundll32.file);
        let result = rundll32.disambiguate(0, identity(&path, "RUNDLL32"));
        assert_eq!(result, identity(&path, "rundll32.exe"));
        assert_eq!(
            rundll32.query_count(),
            1,
            "the system host is still asked once"
        );
    }

    #[test]
    fn a_cached_label_is_dropped_when_the_pid_is_recycled() {
        let hosted = HostedIdentities::new();
        let rundll32 = hosted.host("rundll32.exe");
        let pid = 51_501;
        let path = system_path(rundll32.file);
        let previous = hosted_identity(
            &ResolvedIdentity {
                start_ts: 10_000,
                ..identity(&path, "rundll32.exe")
            },
            rundll32.file,
            "old.dll,Entry",
        );
        rundll32.cache.insert(pid, previous.clone());
        assert_eq!(rundll32.cached(pid, 10_000), Some(previous));
        assert_eq!(rundll32.cached(pid, 90_000), None);
        assert_eq!(rundll32.cache.get(&pid), None);
    }
}
