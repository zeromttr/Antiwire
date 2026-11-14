//! DNS answers and hints: naming connections, and confirming a name for
//! the process that asked for it.

use std::net::IpAddr;

use super::FlowProcessor;
use crate::domain_stats::{executable_key, HintOwner, HintProcess, HintSource};
use crate::sanitize;

impl FlowProcessor {
    /// Records a stub answer against the querying process.
    ///
    /// Records `answers` as addresses of `query` for naming connections,
    /// without attributing them to any process.
    pub fn record_stub_resolution(&self, query: &str, answers: &[IpAddr]) {
        let answers: Vec<String> = answers.iter().map(ToString::to_string).collect();
        self.record_dns_resolution(query, &answers);
    }

    /// Records a stub answer served to `pid` at `answered_at_ms`, in Unix
    /// epoch milliseconds, and valid for `ttl_ms` from then. Pid zero is a
    /// shared hint, the same shape as an answer whose client socket had no owner.
    ///
    /// The time is when the client was given the address, not when this is
    /// called: the client's owner is found afterwards, and a connection the
    /// client opened in between must still find the hint valid at its opening.
    pub fn record_stub_hint(
        &self,
        pid: u32,
        query: &str,
        answers: &[IpAddr],
        ttl_ms: u64,
        answered_at_ms: u64,
    ) {
        let answers: Vec<String> = answers.iter().map(ToString::to_string).collect();
        self.record_hint(
            HintSource::Stub,
            pid,
            query,
            &answers,
            ttl_ms,
            answered_at_ms,
        );
    }

    /// Records an answer for naming connections, and as a hint for `pid`.
    pub(super) fn record_hint(
        &self,
        source: HintSource,
        pid: u32,
        query: &str,
        answers: &[String],
        ttl_ms: u64,
        observed_at: u64,
    ) {
        // The hint map feeds connection-log domains directly, so the
        // name must be cleaned before it enters either store.
        let query = sanitize::trimmed(query, sanitize::MAX_DOMAIN_CHARS);
        self.record_dns_resolution(&query, answers);
        let addresses: Vec<IpAddr> = answers
            .iter()
            .filter_map(|answer| answer.parse().ok())
            .collect();
        let process = self.hint_process(pid, observed_at);
        // The stub saw the DNS Client service ask on an application's behalf.
        // Only that service's own events name the application, and they wait
        // on a one-second timer unless asked for.
        if source == HintSource::Stub && process.owner == HintOwner::DnsClient {
            netmetrics::request_dns_event_flush();
        }
        self.domain_stats.record_hint(
            source,
            process,
            addresses.iter().copied(),
            observed_at,
            observed_at.saturating_add(ttl_ms),
        );
        // How long the hint took to get here says how long a connection's
        // name has to stay correctable.
        if observed_at > 0 {
            self.domain_stats.record_hint_delay(
                source,
                netmetrics_core::unix_now_ms().saturating_sub(observed_at),
            );
        }
        // A hint from a process that asks on others' behalf, such as the DNS
        // Client service, is not evidence about that process's application.
        let shared_with = if process.owner == HintOwner::Application {
            process.executable
        } else {
            0
        };
        self.dns_hints
            .write()
            .insert(pid, shared_with, &query, &addresses, observed_at, ttl_ms);
        // The hint is now where a lookup reads it. The connections it may
        // name, open or closed, are looked up on the tracker's next flush.
        self.note_named(addresses);
    }

    /// The kind of process `pid` was at `at_ms`, when it was given an answer,
    /// and which executable it ran.
    fn hint_process(&self, pid: u32, at_ms: u64) -> HintProcess {
        let (owner, executable) = if pid == 0 {
            (HintOwner::Unowned, 0)
        } else if pid == 4 {
            (HintOwner::System, 0)
        } else if pid == std::process::id() {
            (HintOwner::Daemon, 0)
        } else {
            let image = self.hint_image(pid, at_ms);
            let owner = if image.hosts_dns_client {
                HintOwner::DnsClient
            } else {
                HintOwner::Application
            };
            (owner, image.executable)
        };
        HintProcess {
            owner,
            pid,
            executable,
        }
    }

    /// What the image `pid` ran at `at_ms` says about it, remembered until
    /// the process stops. An image that cannot be established yet is asked for
    /// again next time.
    ///
    /// The process is identified as of the answer, not as of now. A hint can
    /// arrive after a short-lived process has exited, and an ordinary lookup
    /// then fails, or finds whichever process has the PID since.
    pub(super) fn hint_image(&self, pid: u32, at_ms: u64) -> HintImage {
        if let Some(image) = self.hint_images.lock().get(&pid) {
            return *image;
        }
        let Some(identity) = self.app_resolver.processes().identity_at(pid, at_ms) else {
            return HintImage::default();
        };
        let image = HintImage {
            hosts_dns_client: path_hosts_dns_client(&identity.path),
            executable: executable_key(&identity.path),
        };
        // A placeholder path says the image could not be read this time.
        if image.executable != 0 {
            self.hint_images.lock().put(pid, image);
        }
        image
    }
}

/// What a hinting process's image path says about it.
#[derive(Clone, Copy, Debug, Default)]
pub(super) struct HintImage {
    /// Whether it is the service host running the Windows DNS Client
    /// (`Dnscache`), which resolves names on applications' behalf.
    hosts_dns_client: bool,
    /// [`executable_key`] of the image, zero when it names no real executable.
    pub(super) executable: u64,
}

/// Whether a resolved identity path names a service host running `Dnscache`.
/// Service hosts are labelled `svchost.exe::<service>[,<service>...]`.
fn path_hosts_dns_client(path: &str) -> bool {
    path.rsplit_once("::").is_some_and(|(_, services)| {
        services
            .split(',')
            .any(|service| service.trim().eq_ignore_ascii_case("Dnscache"))
    })
}
