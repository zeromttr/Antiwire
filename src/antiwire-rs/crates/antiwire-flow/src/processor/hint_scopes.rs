//! DNS hints by process, and by application.
//!
//! A hint says a process asked for a name and was given an address. A
//! connection that process then opens to the address is confirmed as going to
//! the name. An application that runs as several processes can ask in one and
//! connect from another, so each hint is also kept for the executable, and
//! names a connection from any process running it when that process has no
//! live hint of its own.
//!
//! A hint is judged at the time the connection opened, not at the time it is
//! looked up, and is kept for a while after it expires. A process goes on
//! using an address from its own cache after the answer that gave it has
//! expired, and a long-lived connection is looked up again long after it
//! opened; neither changes what the address was to the process.

use std::net::IpAddr;

use netmetrics_core::{DnsHintAt, DnsHintMap, NearestHint};

use crate::domain_stats::OPEN_SLACK_MS;

/// Bound on PID/address pairs with hints.
const PROCESS_HINT_CAP: usize = 10_000;
/// Bound on executable/address pairs with hints.
const APPLICATION_HINT_CAP: usize = 10_000;
/// How long a hint is kept after it expires. Browsers and connection pools
/// reuse an address for minutes after its answer's TTL, which is often under
/// a minute; past half an hour the address has more likely been handed to
/// another site.
const HINT_RETENTION_MS: u64 = 30 * 60 * 1_000;
/// How much earlier than its process's recorded start a hint may be recorded
/// and still be that process's: the clocks the two times come from can differ
/// by this much.
const START_SKEW_MS: u64 = 1_000;

/// When one of several names a process holds for an address is taken as the
/// one its connection went to: the process asked for it within two seconds
/// before connecting, and at least 750 ms after any other. A process asks and
/// then connects at once, so a name that recent is very likely the one;
/// names asked for together, as a page's resources are, stay untold.
const NEAREST: NearestHint = NearestHint {
    within_ms: 2_000,
    lead_ms: 750,
};

/// When a connection opened, as far as naming it needs.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct Opening {
    /// When it opened, in Unix epoch milliseconds.
    pub(crate) at_ms: u64,
    /// When its process started, in Unix epoch milliseconds, or zero when
    /// unknown. Hints from before then belong to an earlier process that had
    /// the same PID.
    pub(crate) process_started_ms: u64,
}

impl Opening {
    /// An opening at `at_ms` by a process whose start time is unknown.
    #[cfg(test)]
    pub(crate) fn at(at_ms: u64) -> Self {
        Self {
            at_ms,
            process_started_ms: 0,
        }
    }
}

/// What the hints say an address is, for one connection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum HintedName<'a> {
    /// The connection's own process asked for this name and no other, and
    /// the answer was valid when the connection opened.
    Process(&'a str),
    /// Another process running the same executable did.
    Application(&'a str),
    /// The connection's own process was given this name and no other, but
    /// the answer was not valid when the connection opened.
    RetainedProcess(&'a str),
    /// Likewise for another process running the same executable.
    RetainedApplication(&'a str),
    /// The connection's own process held several names for the address
    /// when it opened, and asked for this one just before. A likely guess.
    Likeliest(&'a str),
    /// A hint recorded without a process names it.
    Shared(&'a str),
    /// The connection's own process held several names for the address
    /// when it opened, and none can be chosen.
    Ambiguous,
    /// Several hints recorded without a process compete. A hint for the
    /// connection's own process, when one arrives, still decides.
    SharedAmbiguous,
    /// No live hint names the address.
    Unknown,
}

/// DNS hints keyed by process, with PID zero for hints no process is known
/// for, and the same hints keyed by executable.
#[derive(Debug)]
pub(super) struct HintScopes {
    processes: DnsHintMap,
    applications: DnsHintMap,
}

impl HintScopes {
    pub(super) fn new() -> Self {
        Self {
            processes: DnsHintMap::with_retention(PROCESS_HINT_CAP, HINT_RETENTION_MS),
            applications: DnsHintMap::with_retention(APPLICATION_HINT_CAP, HINT_RETENTION_MS),
        }
    }

    /// Records that `pid` was given `answers` for `query` at `now`, valid for
    /// `ttl_ms`. `executable` is the key of the application the hint is shared
    /// with, or zero to keep it to the process: a process that asks on
    /// others' behalf says nothing about its own application.
    pub(super) fn insert(
        &mut self,
        pid: u32,
        executable: u64,
        query: &str,
        answers: &[IpAddr],
        now: u64,
        ttl_ms: u64,
    ) {
        self.processes
            .insert(pid, query, answers.iter().copied(), now, ttl_ms);
        if let Some(scope) = application_scope(executable) {
            self.applications
                .insert(scope, query, answers.iter().copied(), now, ttl_ms);
        }
    }

    /// Names `remote` for a connection of `pid`, which runs `executable`
    /// and opened at `opening`.
    ///
    /// The names valid when the connection opened decide first: the
    /// process's own, then its application's. Where the process's own
    /// compete, the one it asked for just before connecting is the likeliest,
    /// and otherwise the address is left unnamed. Failing those, a single name kept for the process
    /// or its application from another time is used, and last a hint no
    /// process is known for.
    pub(super) fn name(
        &self,
        pid: u32,
        executable: u64,
        remote: IpAddr,
        opening: Opening,
    ) -> HintedName<'_> {
        let from = opening.at_ms;
        let until = from.saturating_add(OPEN_SLACK_MS);
        let since = opening.process_started_ms.saturating_sub(START_SKEW_MS);
        let own = if pid == 0 {
            DnsHintAt::None
        } else {
            self.processes.name_at(pid, remote, from, until, since)
        };
        match own {
            DnsHintAt::Live(name) => return HintedName::Process(name),
            DnsHintAt::Ambiguous => {
                return self
                    .processes
                    .nearest_at(pid, remote, from, until, since, NEAREST)
                    .map_or(HintedName::Ambiguous, HintedName::Likeliest);
            }
            DnsHintAt::Retained(_) | DnsHintAt::None => {}
        }
        let application = application_scope(executable).map_or(DnsHintAt::None, |scope| {
            self.applications.name_at(scope, remote, from, until, 0)
        });
        if let DnsHintAt::Live(name) = application {
            return HintedName::Application(name);
        }
        if let DnsHintAt::Retained(name) = own {
            return HintedName::RetainedProcess(name);
        }
        if let DnsHintAt::Retained(name) = application {
            return HintedName::RetainedApplication(name);
        }
        match self.processes.name_at(0, remote, from, until, 0) {
            DnsHintAt::Live(name) => HintedName::Shared(name),
            DnsHintAt::Ambiguous => HintedName::SharedAmbiguous,
            DnsHintAt::Retained(_) | DnsHintAt::None => HintedName::Unknown,
        }
    }

    /// Forgets the hints `pid` recorded before `started_at`: an earlier
    /// process had that PID. What its application was given is kept, since
    /// the application is the same whichever process runs it.
    pub(super) fn forget_before(&mut self, pid: u32, started_at: u64) {
        self.processes.forget_before(pid, started_at);
    }

    /// The hints keyed by process.
    #[cfg(test)]
    pub(super) fn processes(&self) -> &DnsHintMap {
        &self.processes
    }
}

/// The key an executable's hints are kept under, or `None` for an unknown
/// executable. Zero is left out: the hint map reads it as "no process".
fn application_scope(executable: u64) -> Option<u32> {
    if executable == 0 {
        return None;
    }
    let folded =
        u32::try_from((executable >> 32) ^ (executable & u64::from(u32::MAX))).unwrap_or(u32::MAX);
    Some(folded.max(1))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    const IP: IpAddr = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9));
    const BROWSER: u64 = 0x1111_2222_3333_4444;
    const OTHER: u64 = 0x5555_6666_7777_8888;

    #[test]
    fn a_sibling_process_of_the_same_executable_confirms_the_name() {
        let mut hints = HintScopes::new();
        hints.insert(10, BROWSER, "site.example", &[IP], 0, 100);

        assert_eq!(
            hints.name(10, BROWSER, IP, Opening::at(1)),
            HintedName::Process("site.example")
        );
        assert_eq!(
            hints.name(11, BROWSER, IP, Opening::at(1)),
            HintedName::Application("site.example")
        );
        assert_eq!(
            hints.name(12, OTHER, IP, Opening::at(1)),
            HintedName::Unknown
        );
        assert_eq!(
            hints.name(11, 0, IP, Opening::at(1)),
            HintedName::Unknown,
            "a connection whose executable is unknown has no siblings"
        );
        assert_eq!(
            hints.name(11, BROWSER, IP, Opening::at(101)),
            HintedName::RetainedApplication("site.example"),
            "the application may still be using the address from its cache"
        );
        assert_eq!(
            hints.name(11, BROWSER, IP, Opening::at(101 + HINT_RETENTION_MS)),
            HintedName::Unknown
        );
    }

    #[test]
    fn a_name_valid_at_the_opening_outranks_a_retained_one() {
        let mut hints = HintScopes::new();
        hints.insert(11, 0, "earlier.example", &[IP], 0, 100);
        assert_eq!(
            hints.name(11, BROWSER, IP, Opening::at(5_000)),
            HintedName::RetainedProcess("earlier.example")
        );
        // A sibling asked just before the connection opened.
        hints.insert(10, BROWSER, "current.example", &[IP], 4_990, 100);
        assert_eq!(
            hints.name(11, BROWSER, IP, Opening::at(5_000)),
            HintedName::Application("current.example")
        );
        // With no application, the process's own kept name is all there is.
        assert_eq!(
            hints.name(11, 0, IP, Opening::at(5_000)),
            HintedName::RetainedProcess("earlier.example")
        );
    }

    #[test]
    fn a_long_lived_connection_keeps_the_name_it_opened_with() {
        let mut hints = HintScopes::new();
        hints.insert(11, 0, "opened-with.example", &[IP], 0, 100);
        // Looked up again much later, after the process asked for another
        // name at the same address: what was valid at the opening decides.
        hints.insert(11, 0, "asked-later.example", &[IP], 60_000, 100);
        assert_eq!(
            hints.name(11, 0, IP, Opening::at(50)),
            HintedName::Process("opened-with.example")
        );
        assert_eq!(
            hints.name(11, 0, IP, Opening::at(60_050)),
            HintedName::Process("asked-later.example")
        );
        assert_eq!(
            hints.name(11, 0, IP, Opening::at(30_000)),
            HintedName::Unknown,
            "between the two, neither name can be told from the other"
        );
    }

    #[test]
    fn a_hint_an_earlier_process_with_the_pid_left_is_not_this_process_own() {
        let mut hints = HintScopes::new();
        hints.insert(11, 0, "earlier-process.example", &[IP], 1_000, 100);
        let opening = Opening {
            at_ms: 10_000,
            process_started_ms: 9_000,
        };
        assert_eq!(hints.name(11, 0, IP, opening), HintedName::Unknown);
        assert_eq!(
            hints.name(11, 0, IP, Opening::at(10_000)),
            HintedName::RetainedProcess("earlier-process.example"),
            "with no start time there is nothing to rule it out by"
        );
    }

    #[test]
    fn a_shared_hint_names_only_while_it_is_valid() {
        let mut hints = HintScopes::new();
        hints.insert(0, 0, "shared.example", &[IP], 0, 100);
        assert_eq!(
            hints.name(11, BROWSER, IP, Opening::at(50)),
            HintedName::Shared("shared.example")
        );
        assert_eq!(
            hints.name(11, BROWSER, IP, Opening::at(500)),
            HintedName::Unknown
        );
    }

    #[test]
    fn a_hint_kept_to_its_process_names_no_sibling() {
        let mut hints = HintScopes::new();
        hints.insert(10, 0, "private.example", &[IP], 0, 100);
        assert_eq!(
            hints.name(11, BROWSER, IP, Opening::at(1)),
            HintedName::Unknown
        );
    }

    #[test]
    fn the_process_own_hints_outrank_its_application() {
        let mut hints = HintScopes::new();
        hints.insert(10, BROWSER, "sibling.example", &[IP], 0, 100);
        hints.insert(11, BROWSER, "own.example", &[IP], 0, 100);
        assert_eq!(
            hints.name(11, BROWSER, IP, Opening::at(1)),
            HintedName::Process("own.example")
        );
        // Two names of its own compete, and the application's are not asked.
        hints.insert(11, BROWSER, "own-too.example", &[IP], 0, 100);
        assert_eq!(
            hints.name(11, BROWSER, IP, Opening::at(1)),
            HintedName::Ambiguous
        );
    }

    #[test]
    fn of_competing_own_names_the_one_just_asked_for_is_the_likeliest() {
        let mut hints = HintScopes::new();
        hints.insert(11, 0, "earlier.example", &[IP], 1_000, 60_000);
        hints.insert(11, 0, "just-asked.example", &[IP], 9_950, 60_000);
        assert_eq!(
            hints.name(11, 0, IP, Opening::at(10_000)),
            HintedName::Likeliest("just-asked.example")
        );
        assert_eq!(
            hints.name(11, 0, IP, Opening::at(30_000)),
            HintedName::Ambiguous,
            "long after either was asked for, there is no telling"
        );
    }

    #[test]
    fn competing_application_names_fall_back_to_the_shared_hint() {
        let mut hints = HintScopes::new();
        hints.insert(10, BROWSER, "first.example", &[IP], 0, 100);
        hints.insert(12, BROWSER, "second.example", &[IP], 0, 100);
        assert_eq!(
            hints.name(11, BROWSER, IP, Opening::at(1)),
            HintedName::Unknown
        );
        hints.insert(0, 0, "shared.example", &[IP], 0, 100);
        assert_eq!(
            hints.name(11, BROWSER, IP, Opening::at(1)),
            HintedName::Shared("shared.example")
        );
        hints.insert(0, 0, "shared-too.example", &[IP], 0, 100);
        assert_eq!(
            hints.name(11, BROWSER, IP, Opening::at(1)),
            HintedName::SharedAmbiguous
        );
        // The process's own hint, arriving late, still decides.
        hints.insert(11, 0, "own.example", &[IP], 1, 100);
        assert_eq!(
            hints.name(11, BROWSER, IP, Opening::at(1)),
            HintedName::Process("own.example")
        );
    }

    #[test]
    fn a_reused_pid_forgets_its_own_hints_but_not_its_application() {
        let mut hints = HintScopes::new();
        hints.insert(10, BROWSER, "old.example", &[IP], 100, 10_000);
        hints.forget_before(10, 200);
        assert_eq!(
            hints.name(10, BROWSER, IP, Opening::at(300)),
            HintedName::Application("old.example")
        );
        assert_eq!(
            hints.name(10, OTHER, IP, Opening::at(300)),
            HintedName::Unknown
        );
    }

    #[test]
    fn every_known_executable_has_a_nonzero_scope() {
        assert_eq!(application_scope(0), None);
        assert_eq!(application_scope(0x1234_5678_1234_5678), Some(1));
        assert_eq!(application_scope(1), Some(1));
        assert_ne!(application_scope(BROWSER), application_scope(OTHER));
    }
}
