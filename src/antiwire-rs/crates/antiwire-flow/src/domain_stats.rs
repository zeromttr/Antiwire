//! Counters explaining why connection domains end up confirmed or inferred.
//!
//! A connection's domain is confirmed only when a DNS answer was recorded for the
//! same process. These counters show which lookup step named each connection, which
//! process kind each DNS hint was recorded under, and, for an inferred name, whether
//! another process or the connection's own process held a live hint for the address,
//! or the hint had already expired.
//!
//! Lookups are counted every time they run, so a long-lived connection that is
//! retried weighs more than a short one. The `first_inferred` and
//! `closed_unconfirmed` breakdowns count each connection once, by the process
//! hint that best explains its address.

use std::hash::{Hash, Hasher};
use std::net::IpAddr;
use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicU64, Ordering};

use lru::LruCache;
use netmetrics_core::canonicalize_ip;
use parking_lot::Mutex;

use crate::process_resolver;

/// Addresses whose latest process-scoped hint is remembered for the inferred
/// breakdown; past this, the address hinted least recently is forgotten.
const LAST_OWNER_CAP: usize = 16_384;

/// Processes whose latest hint is remembered per address; past this, the one
/// that hinted least recently is forgotten.
const HOLDERS_PER_ADDRESS: usize = 4;

/// How far after a connection opened a hint may be stamped and still count as
/// covering its opening. A hint carries the time its answer was given and a
/// connection the time its open event was logged; the two come from different
/// clocks and code paths, and can disagree by a little.
pub(crate) const OPEN_SLACK_MS: u64 = 250;

/// The delays past which a late hint is counted, in milliseconds. A
/// connection's name stays correctable for as long as a hint from before it
/// opened can still arrive, and these say how long that is in practice.
pub(crate) const HINT_DELAY_STEPS_MS: [u64; 4] = [1_000, 2_000, 3_000, 5_000];

/// Which step of the domain lookup named a connection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum LookupOutcome {
    /// A live hint recorded for the connection's own process: confirmed.
    ProcessHint,
    /// A live hint recorded for another process of the same executable: confirmed.
    ApplicationHint,
    /// A hint for the connection's own process that was not valid when the
    /// connection opened, and is the only one kept: confirmed.
    RetainedProcessHint,
    /// Likewise for another process of the same executable: confirmed.
    RetainedApplicationHint,
    /// Of several live hints for the connection's own process, the one
    /// recorded just before the connection opened: inferred.
    NearestHint,
    /// A live hint recorded without a process: inferred.
    SharedHint,
    /// An answer buffered for the store, keyed by address only: inferred.
    Pending,
    /// The persisted address-to-name cache: inferred.
    Store,
    /// Several live names compete for the address: left blank.
    Ambiguous,
    /// Nothing named the address.
    Unresolved,
}

impl LookupOutcome {
    /// Whether the hints decided the answer, by a name or by names that
    /// competed, and not the address-only tables.
    pub(crate) fn decided_by_hints(self) -> bool {
        !matches!(self, Self::Pending | Self::Store | Self::Unresolved)
    }
}

/// Where a DNS hint came from.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum HintSource {
    /// The Antiwire DNS stub, attributed by the client socket's owner.
    Stub,
    /// The ETW DNS-Client provider, attributed by its caller fields.
    Etw,
}

/// The kind of process a DNS hint was recorded under.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum HintOwner {
    /// No process: a shared hint.
    Unowned,
    /// The Windows DNS Client service host, resolving on an application's behalf.
    DnsClient,
    /// This daemon.
    Daemon,
    /// Any other process.
    Application,
    /// The kernel's `System` process, PID 4, which makes no user connections.
    System,
}

/// The process a DNS hint is recorded under.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct HintProcess {
    /// What kind of process it is.
    pub owner: HintOwner,
    /// Its PID, zero for a shared hint.
    pub pid: u32,
    /// [`executable_key`] of its image, zero when unknown.
    pub executable: u64,
}

/// How the process behind a hint relates to a connection. The most telling
/// relation comes first.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum HolderKind {
    /// The connection's own process.
    Own,
    /// Another process running the same executable.
    SameApplication,
    /// The DNS Client service host.
    DnsClient,
    /// Any other process.
    Other,
}

/// When a hint was valid, relative to the moment a connection is judged at.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum HintTiming {
    /// It had expired by then.
    Expired,
    /// It was live then.
    Live,
    /// It was recorded later.
    Later,
}

/// A stable key for the executable at `path`, to tell whether two processes
/// run the same one. Zero when `path` names no real executable.
pub(crate) fn executable_key(path: &str) -> u64 {
    let path = path.trim();
    if path.is_empty() || process_resolver::is_synthetic_path(path) {
        return 0;
    }
    let mut hasher = std::hash::DefaultHasher::new();
    // Windows paths are case-insensitive; elsewhere case distinguishes files.
    if cfg!(windows) {
        path.to_ascii_lowercase().hash(&mut hasher);
    } else {
        path.hash(&mut hasher);
    }
    hasher.finish().max(1)
}

/// Point-in-time copy of [`DomainLookupStats`].
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct DomainLookupSnapshot {
    /// Lookups answered by a hint for the connection's own process.
    pub process_hint: u64,
    /// Lookups answered by a hint for another process of the same executable.
    pub application_hint: u64,
    /// Lookups answered by the only hint kept for the connection's own
    /// process, which was not valid when the connection opened.
    pub retained_process_hint: u64,
    /// Likewise for another process of the same executable.
    pub retained_application_hint: u64,
    /// Lookups answered by the nearest of the process's competing hints.
    pub nearest_hint: u64,
    /// Lookups answered by a shared hint.
    pub shared_hint: u64,
    /// Lookups answered by the pending store buffer.
    pub pending: u64,
    /// Lookups answered by the persisted cache.
    pub store: u64,
    /// Lookups left blank because several names compete.
    pub ambiguous: u64,
    /// Lookups nothing answered.
    pub unresolved: u64,
    /// Lookups for a connection with no process yet.
    pub unattributed_flow: u64,
    /// Inferred lookups where another process held a live hint for the address.
    pub inferred_other_process_live: u64,
    /// Of those, the other process was the DNS Client service host.
    pub inferred_other_process_dns_client: u64,
    /// Inferred lookups where the connection's own process held a live hint.
    pub inferred_own_process_live: u64,
    /// Inferred lookups where the address's latest process hint had expired.
    pub inferred_hint_expired: u64,
    /// Inferred lookups for an address no process hint ever named.
    pub inferred_never_hinted: u64,
    /// Stub hints by owner kind: unowned, DNS Client, daemon, application, System.
    pub stub_hints: [u64; 5],
    /// ETW hints by owner kind: unowned, DNS Client, daemon, application, System.
    pub etw_hints: [u64; 5],
    /// Names written to closed connections' rows after they closed.
    pub late_upgrades: u64,
    /// Closed connections whose name could still change but which were not
    /// held, because as many as are held at once already were.
    pub closed_names_shed: u64,
    /// Lookups whose answer replaced a name the store would have kept, on a
    /// connection that was open, by what the name became: none, inferred,
    /// confirmed. A hint from before the connection opened arrived after its
    /// name was first written. A lookup made again after a failed write is
    /// counted again.
    pub corrected_open: [u64; 3],
    /// The same for connections that had closed.
    pub corrected_closed: [u64; 3],
    /// The longest a hint took to arrive after the time it is stamped with,
    /// in milliseconds: stub hints, ETW hints.
    pub hint_delay_max_ms: [u64; 2],
    /// Hints that took longer than each of [`HINT_DELAY_STEPS_MS`] to arrive.
    /// Rows: stub hints, ETW hints.
    pub hints_late: [[u64; 4]; 2],
    /// Closed connection rows by domain when queued: none, inferred, confirmed.
    pub closed_rows: [u64; 3],
    /// Connections by the process hint that best explained their address when
    /// they were first named inferred. Rows: the connection's own process,
    /// another process of the same executable, the DNS Client service host,
    /// any other process. Columns: the hint had expired, was live.
    pub first_inferred: [[u64; 2]; 4],
    /// Connections first named inferred for an address no process hint named.
    pub first_inferred_never_hinted: u64,
    /// Closed rows left unconfirmed, by the process hint that best explains
    /// their address. Rows as in `first_inferred`. Columns: the hint expired
    /// before the connection opened, was live when it opened, was recorded
    /// after it. A row a late hint confirms afterwards is counted here too.
    pub closed_unconfirmed: [[u64; 3]; 4],
    /// Closed unconfirmed rows for an address no process hint named: none, inferred.
    pub closed_never_hinted: [u64; 2],
    /// DNS answers dropped because the store was failing and the buffer was full.
    pub dns_answers_shed: u64,
}

/// Lock-free counters, plus the latest process hint per address.
#[derive(Debug, Default)]
pub(crate) struct DomainLookupStats {
    outcomes: [AtomicU64; 10],
    unattributed_flow: AtomicU64,
    inferred_other_process_live: AtomicU64,
    inferred_other_process_dns_client: AtomicU64,
    inferred_own_process_live: AtomicU64,
    inferred_hint_expired: AtomicU64,
    inferred_never_hinted: AtomicU64,
    hints: [[AtomicU64; 5]; 2],
    late_upgrades: AtomicU64,
    closed_names_shed: AtomicU64,
    corrected: [[AtomicU64; 3]; 2],
    hint_delay_max_ms: [AtomicU64; 2],
    hints_late: [[AtomicU64; 4]; 2],
    closed_rows: [AtomicU64; 3],
    first_inferred: [[AtomicU64; 2]; 4],
    first_inferred_never_hinted: AtomicU64,
    closed_unconfirmed: [[AtomicU64; 3]; 4],
    closed_never_hinted: [AtomicU64; 2],
    dns_answers_shed: AtomicU64,
    /// Latest process-scoped hints per address.
    last_owner: Mutex<LastOwners>,
}

/// One process's latest hint for an address. Times are Unix epoch milliseconds.
#[derive(Clone, Copy, Debug)]
struct Holder {
    pid: u32,
    dns_client: bool,
    executable: u64,
    recorded_at: u64,
    expires_at: u64,
}

impl Holder {
    fn kind(&self, pid: u32, executable: u64) -> HolderKind {
        if pid != 0 && self.pid == pid {
            HolderKind::Own
        } else if executable != 0 && self.executable == executable {
            HolderKind::SameApplication
        } else if self.dns_client {
            HolderKind::DnsClient
        } else {
            HolderKind::Other
        }
    }

    /// Whether the hint was valid at `at`, with `slack` for one recorded just after.
    fn timing(&self, at: u64, slack: u64) -> HintTiming {
        if self.expires_at < at {
            HintTiming::Expired
        } else if self.recorded_at > at.saturating_add(slack) {
            HintTiming::Later
        } else {
            HintTiming::Live
        }
    }
}

/// The hints of up to [`HOLDERS_PER_ADDRESS`] processes per address, oldest
/// first, for the most recently hinted [`LAST_OWNER_CAP`] addresses.
#[derive(Debug)]
struct LastOwners(LruCache<IpAddr, Vec<Holder>>);

impl LastOwners {
    /// The hint that best explains a connection of `pid`, running
    /// `executable`, to `ip`: the closest relation, then the newest.
    fn best(&self, ip: IpAddr, pid: u32, executable: u64) -> Option<(HolderKind, Holder)> {
        self.0
            .peek(&canonicalize_ip(ip))?
            .iter()
            .map(|holder| (holder.kind(pid, executable), *holder))
            .min_by_key(|(kind, holder)| (*kind, std::cmp::Reverse(holder.recorded_at)))
    }
}

impl Default for LastOwners {
    fn default() -> Self {
        Self(LruCache::new(
            NonZeroUsize::new(LAST_OWNER_CAP).expect("last-owner capacity is nonzero"),
        ))
    }
}

impl DomainLookupStats {
    /// Counts a hint `process` recorded for `answers` at `recorded_at`, valid
    /// until `expires_at`, both in Unix epoch milliseconds.
    pub(crate) fn record_hint<I>(
        &self,
        source: HintSource,
        process: HintProcess,
        answers: I,
        recorded_at: u64,
        expires_at: u64,
    ) where
        I: IntoIterator<Item = IpAddr>,
    {
        self.hints[source as usize][process.owner as usize].fetch_add(1, Ordering::Relaxed);
        if process.pid == 0 {
            return;
        }
        let holder = Holder {
            pid: process.pid,
            dns_client: process.owner == HintOwner::DnsClient,
            executable: process.executable,
            recorded_at,
            expires_at,
        };
        let mut last = self.last_owner.lock();
        for ip in answers {
            let holders = last.0.get_or_insert_mut(canonicalize_ip(ip), Vec::new);
            holders.retain(|existing| existing.pid != holder.pid);
            if holders.len() >= HOLDERS_PER_ADDRESS {
                holders.remove(0);
            }
            holders.push(holder);
        }
    }

    /// Counts a connection of `pid`, running `executable`, to `ip` whose name
    /// has just become inferred at `now_ms`.
    pub(crate) fn record_first_inferred(&self, pid: u32, executable: u64, ip: IpAddr, now_ms: u64) {
        let best = self.last_owner.lock().best(ip, pid, executable);
        let counter = match best {
            Some((kind, holder)) => {
                let live = holder.timing(now_ms, u64::MAX) != HintTiming::Expired;
                &self.first_inferred[kind as usize][usize::from(live)]
            }
            None => &self.first_inferred_never_hinted,
        };
        counter.fetch_add(1, Ordering::Relaxed);
    }

    /// Counts a closed connection's row by the evidence behind its domain. An
    /// unconfirmed row of `pid`, running `executable`, to `ip` is also counted
    /// by the hint that best explains it, judged at `opened_at_ms`.
    pub(crate) fn record_closed_row(
        &self,
        evidence: antiwire_store::DomainEvidence,
        pid: u32,
        executable: u64,
        ip: IpAddr,
        opened_at_ms: u64,
    ) {
        let index = match evidence {
            antiwire_store::DomainEvidence::None => 0,
            antiwire_store::DomainEvidence::Inferred => 1,
            antiwire_store::DomainEvidence::Confirmed => 2,
        };
        self.closed_rows[index].fetch_add(1, Ordering::Relaxed);
        if evidence == antiwire_store::DomainEvidence::Confirmed {
            return;
        }
        let best = self.last_owner.lock().best(ip, pid, executable);
        let counter = match best {
            Some((kind, holder)) => {
                let timing = holder.timing(opened_at_ms, OPEN_SLACK_MS);
                &self.closed_unconfirmed[kind as usize][timing as usize]
            }
            None => &self.closed_never_hinted[index],
        };
        counter.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn record_late_upgrade(&self) {
        self.late_upgrades.fetch_add(1, Ordering::Relaxed);
    }

    /// Counts a closed connection that could not be held for a later name.
    pub(crate) fn record_closed_name_shed(&self) {
        self.closed_names_shed.fetch_add(1, Ordering::Relaxed);
    }

    /// Counts a lookup whose answer, of evidence `became`, replaced a name
    /// the store would have kept, on a connection that was open or `closed`.
    pub(crate) fn record_correction(&self, closed: bool, became: antiwire_store::DomainEvidence) {
        let index = match became {
            antiwire_store::DomainEvidence::None => 0,
            antiwire_store::DomainEvidence::Inferred => 1,
            antiwire_store::DomainEvidence::Confirmed => 2,
        };
        self.corrected[usize::from(closed)][index].fetch_add(1, Ordering::Relaxed);
    }

    /// Counts a hint from `source` that arrived `delay_ms` after the time it
    /// is stamped with.
    pub(crate) fn record_hint_delay(&self, source: HintSource, delay_ms: u64) {
        self.hint_delay_max_ms[source as usize].fetch_max(delay_ms, Ordering::Relaxed);
        for (late, step) in self.hints_late[source as usize]
            .iter()
            .zip(HINT_DELAY_STEPS_MS)
        {
            if delay_ms > step {
                late.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    /// Counts DNS answers dropped instead of buffered, returning the new total.
    pub(crate) fn record_dns_answers_shed(&self, count: u64) -> u64 {
        self.dns_answers_shed.fetch_add(count, Ordering::Relaxed) + count
    }

    /// Counts one lookup for `flow_pid` and `ip` that ended in `outcome`.
    pub(crate) fn record_lookup(
        &self,
        flow_pid: u32,
        ip: IpAddr,
        outcome: LookupOutcome,
        now_ms: u64,
    ) {
        self.outcomes[outcome as usize].fetch_add(1, Ordering::Relaxed);
        if flow_pid == 0 {
            self.unattributed_flow.fetch_add(1, Ordering::Relaxed);
        }
        if !matches!(
            outcome,
            LookupOutcome::SharedHint | LookupOutcome::Pending | LookupOutcome::Store
        ) {
            return;
        }
        // The process that hinted the address most recently.
        let last = self
            .last_owner
            .lock()
            .0
            .peek(&canonicalize_ip(ip))
            .and_then(|holders| holders.last().copied());
        let counter = match last {
            Some(holder) if holder.pid != flow_pid && now_ms <= holder.expires_at => {
                if holder.dns_client {
                    self.inferred_other_process_dns_client
                        .fetch_add(1, Ordering::Relaxed);
                }
                &self.inferred_other_process_live
            }
            Some(holder) if now_ms <= holder.expires_at => &self.inferred_own_process_live,
            Some(_) => &self.inferred_hint_expired,
            None => &self.inferred_never_hinted,
        };
        counter.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn snapshot(&self) -> DomainLookupSnapshot {
        let load = |counter: &AtomicU64| counter.load(Ordering::Relaxed);
        let row = |source: HintSource| self.hints[source as usize].each_ref().map(load);
        DomainLookupSnapshot {
            process_hint: load(&self.outcomes[LookupOutcome::ProcessHint as usize]),
            application_hint: load(&self.outcomes[LookupOutcome::ApplicationHint as usize]),
            retained_process_hint: load(
                &self.outcomes[LookupOutcome::RetainedProcessHint as usize],
            ),
            retained_application_hint: load(
                &self.outcomes[LookupOutcome::RetainedApplicationHint as usize],
            ),
            nearest_hint: load(&self.outcomes[LookupOutcome::NearestHint as usize]),
            shared_hint: load(&self.outcomes[LookupOutcome::SharedHint as usize]),
            pending: load(&self.outcomes[LookupOutcome::Pending as usize]),
            store: load(&self.outcomes[LookupOutcome::Store as usize]),
            ambiguous: load(&self.outcomes[LookupOutcome::Ambiguous as usize]),
            unresolved: load(&self.outcomes[LookupOutcome::Unresolved as usize]),
            unattributed_flow: load(&self.unattributed_flow),
            inferred_other_process_live: load(&self.inferred_other_process_live),
            inferred_other_process_dns_client: load(&self.inferred_other_process_dns_client),
            inferred_own_process_live: load(&self.inferred_own_process_live),
            inferred_hint_expired: load(&self.inferred_hint_expired),
            inferred_never_hinted: load(&self.inferred_never_hinted),
            stub_hints: row(HintSource::Stub),
            etw_hints: row(HintSource::Etw),
            late_upgrades: load(&self.late_upgrades),
            closed_names_shed: load(&self.closed_names_shed),
            corrected_open: self.corrected[0].each_ref().map(load),
            corrected_closed: self.corrected[1].each_ref().map(load),
            hint_delay_max_ms: self.hint_delay_max_ms.each_ref().map(load),
            hints_late: self
                .hints_late
                .each_ref()
                .map(|row| row.each_ref().map(load)),
            closed_rows: self.closed_rows.each_ref().map(load),
            first_inferred: self
                .first_inferred
                .each_ref()
                .map(|row| row.each_ref().map(load)),
            first_inferred_never_hinted: load(&self.first_inferred_never_hinted),
            closed_unconfirmed: self
                .closed_unconfirmed
                .each_ref()
                .map(|row| row.each_ref().map(load)),
            closed_never_hinted: self.closed_never_hinted.each_ref().map(load),
            dns_answers_shed: load(&self.dns_answers_shed),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    const IP: IpAddr = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7));
    const NONE: antiwire_store::DomainEvidence = antiwire_store::DomainEvidence::None;
    const INFERRED: antiwire_store::DomainEvidence = antiwire_store::DomainEvidence::Inferred;
    const CONFIRMED: antiwire_store::DomainEvidence = antiwire_store::DomainEvidence::Confirmed;

    fn process(owner: HintOwner, pid: u32, executable: u64) -> HintProcess {
        HintProcess {
            owner,
            pid,
            executable,
        }
    }

    #[test]
    fn an_inferred_lookup_is_explained_by_the_latest_process_hint() {
        let stats = DomainLookupStats::default();
        stats.record_lookup(5, IP, LookupOutcome::Store, 10);
        stats.record_hint(
            HintSource::Stub,
            process(HintOwner::DnsClient, 9, 0),
            [IP],
            0,
            100,
        );
        stats.record_lookup(5, IP, LookupOutcome::Pending, 50);
        stats.record_lookup(5, IP, LookupOutcome::SharedHint, 101);
        stats.record_lookup(9, IP, LookupOutcome::ProcessHint, 50);

        let snapshot = stats.snapshot();
        assert_eq!(snapshot.inferred_never_hinted, 1);
        assert_eq!(snapshot.inferred_other_process_live, 1);
        assert_eq!(snapshot.inferred_other_process_dns_client, 1);
        assert_eq!(snapshot.inferred_hint_expired, 1);
        assert_eq!(snapshot.process_hint, 1);
        assert_eq!(snapshot.stub_hints, [0, 1, 0, 0, 0]);
    }

    #[test]
    fn an_own_live_hint_is_not_counted_as_expired() {
        let stats = DomainLookupStats::default();
        stats.record_hint(
            HintSource::Etw,
            process(HintOwner::Application, 5, 0),
            [IP],
            0,
            100,
        );
        stats.record_lookup(5, IP, LookupOutcome::SharedHint, 50);
        stats.record_lookup(5, IP, LookupOutcome::Store, 101);

        let snapshot = stats.snapshot();
        assert_eq!(snapshot.inferred_own_process_live, 1);
        assert_eq!(snapshot.inferred_hint_expired, 1);
        assert_eq!(snapshot.inferred_other_process_live, 0);
    }

    #[test]
    fn a_first_inferred_connection_is_explained_by_its_closest_hint() {
        let stats = DomainLookupStats::default();
        stats.record_first_inferred(5, 77, IP, 10);
        // The DNS Client host, an unrelated process, then a sibling of the
        // connection's own executable all hint the address.
        stats.record_hint(
            HintSource::Stub,
            process(HintOwner::DnsClient, 9, 11),
            [IP],
            0,
            100,
        );
        stats.record_first_inferred(5, 77, IP, 50);
        stats.record_hint(
            HintSource::Etw,
            process(HintOwner::Application, 8, 22),
            [IP],
            20,
            100,
        );
        stats.record_first_inferred(5, 77, IP, 50);
        stats.record_hint(
            HintSource::Etw,
            process(HintOwner::Application, 6, 77),
            [IP],
            30,
            60,
        );
        stats.record_first_inferred(5, 77, IP, 50);
        stats.record_first_inferred(5, 77, IP, 61);
        // A connection whose executable is unknown has no sibling.
        stats.record_first_inferred(4, 0, IP, 50);

        let snapshot = stats.snapshot();
        assert_eq!(snapshot.first_inferred_never_hinted, 1);
        assert_eq!(
            snapshot.first_inferred,
            [[0, 0], [1, 1], [0, 3], [0, 0]],
            "own, same application, DNS Client, other; expired then live"
        );
    }

    #[test]
    fn an_unconfirmed_closed_row_is_judged_at_its_opening() {
        let stats = DomainLookupStats::default();
        stats.record_closed_row(NONE, 5, 77, IP, 1_000);
        stats.record_hint(
            HintSource::Etw,
            process(HintOwner::Application, 5, 77),
            [IP],
            1_000,
            2_000,
        );
        stats.record_closed_row(INFERRED, 5, 77, IP, 2_001);
        stats.record_closed_row(INFERRED, 5, 77, IP, 1_500);
        stats.record_closed_row(INFERRED, 5, 77, IP, 1_000 - OPEN_SLACK_MS);
        stats.record_closed_row(NONE, 5, 77, IP, 1_000 - OPEN_SLACK_MS - 1);
        stats.record_closed_row(CONFIRMED, 5, 77, IP, 1_500);

        let snapshot = stats.snapshot();
        assert_eq!(snapshot.closed_rows, [2, 3, 1]);
        assert_eq!(snapshot.closed_never_hinted, [1, 0]);
        assert_eq!(
            snapshot.closed_unconfirmed,
            [[1, 2, 1], [0, 0, 0], [0, 0, 0], [0, 0, 0]],
            "the own hint expired before, covered, and followed the opening"
        );
    }

    #[test]
    fn only_the_latest_hinting_processes_are_remembered_per_address() {
        let stats = DomainLookupStats::default();
        for pid in 1..=5 {
            let hinted = process(HintOwner::Application, pid, u64::from(pid));
            stats.record_hint(HintSource::Etw, hinted, [IP], u64::from(pid), 100);
        }
        // A repeat replaces that process's earlier hint instead of adding one.
        stats.record_hint(
            HintSource::Etw,
            process(HintOwner::Application, 3, 3),
            [IP],
            9,
            100,
        );
        let last = stats.last_owner.lock();
        let pids: Vec<u32> = last
            .0
            .peek(&IP)
            .expect("hinted")
            .iter()
            .map(|holder| holder.pid)
            .collect();
        assert_eq!(pids, [2, 4, 5, 3]);
    }

    #[test]
    fn a_late_hint_is_counted_at_every_delay_it_exceeds() {
        let stats = DomainLookupStats::default();
        stats.record_hint_delay(HintSource::Etw, 40);
        stats.record_hint_delay(HintSource::Etw, 1_000);
        stats.record_hint_delay(HintSource::Etw, 2_500);
        stats.record_hint_delay(HintSource::Stub, 6_000);
        let snapshot = stats.snapshot();
        assert_eq!(snapshot.hint_delay_max_ms, [6_000, 2_500]);
        assert_eq!(
            snapshot.hints_late,
            [[1, 1, 1, 1], [1, 1, 0, 0]],
            "a hint exactly at a step is not later than it"
        );
    }

    #[test]
    fn a_correction_is_counted_by_what_the_name_became() {
        let stats = DomainLookupStats::default();
        stats.record_correction(false, INFERRED);
        stats.record_correction(true, NONE);
        stats.record_correction(true, CONFIRMED);
        let snapshot = stats.snapshot();
        assert_eq!(snapshot.corrected_open, [0, 1, 0]);
        assert_eq!(snapshot.corrected_closed, [1, 0, 1]);
    }

    #[test]
    fn an_executable_key_ignores_placeholders() {
        assert_eq!(executable_key(""), 0);
        assert_eq!(executable_key("Unknown (Exited)"), 0);
        assert_ne!(executable_key(r"C:\apps\browser.exe"), 0);
        assert_ne!(
            executable_key(r"C:\apps\browser.exe"),
            executable_key(r"C:\apps\other.exe")
        );
        if cfg!(windows) {
            assert_eq!(
                executable_key(r"C:\Apps\Browser.EXE"),
                executable_key(r"C:\apps\browser.exe")
            );
        }
    }
}
