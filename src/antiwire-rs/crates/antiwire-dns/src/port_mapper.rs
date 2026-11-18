//! Maps a query's client socket to its owning process id.
//!
//! A lookup on the reply path runs while the client is still waiting for its
//! answer, so its socket is still bound and the live socket table can name the
//! owner. Scanning that table stalls the receive loop, so the reply path scans
//! at most once per refresh interval and hands any other lookup to a worker.

use crate::block::DnsQueryContext;
use std::sync::atomic::{AtomicU64, Ordering};

pub(crate) use netmetrics::Ownership;

mod socket_table {
    use super::Ownership;
    use netmetrics::owner_cache::{Pending, Wait};
    use netmetrics::{LocalEndpoint, Protocol, SocketOwnerCache};
    use std::time::Instant;

    /// Owner of the client socket at `endpoint`, already mapped back from any
    /// DNS redirect by [`super::client_endpoint`], from the process-wide
    /// [`SocketOwnerCache`]. Its refresh interval keeps attribution bursts of
    /// missing (often already closed) ports from scanning the socket table per
    /// query: lookups start at most four scans a second, of one protocol's
    /// tables on Windows and of every table elsewhere.
    ///
    /// `wait_for_scan` waits behind a running scan or for the next slot, until
    /// the query's deadline; only callers off the reply path may wait. Without
    /// it, `None` means the lookup needs a scan the reply path may not run now.
    pub(crate) fn lookup_socket_owner(
        protocol: Protocol,
        endpoint: LocalEndpoint,
        received_at: Instant,
        wait_for_scan: bool,
    ) -> Option<Ownership> {
        // Past the deadline the client has given up and its port may belong to
        // another process, so a scan then would name the wrong owner.
        let wait = if wait_for_scan {
            Wait::Until(
                received_at
                    .checked_add(antiwire_tuning::DNS_QUERY_DEADLINE)
                    .unwrap_or(received_at),
            )
        } else {
            Wait::Never
        };
        match SocketOwnerCache::shared().owner(protocol, endpoint, received_at, wait) {
            Ok(owner) => Some(owner),
            Err(Pending::Busy) => None,
            Err(_) => Some(Ownership::NotFound),
        }
    }

    /// What [`lookup_socket_owner`] would do, found without blocking.
    #[derive(Debug, PartialEq, Eq)]
    pub(crate) enum WithoutScan {
        /// The newest snapshot names the owner.
        Owner(Ownership),
        /// It needs a scan that cannot start now, and the caller may not
        /// wait: the lookup's answer is `None`.
        Busy,
        /// It would scan, or wait for a scan. Only this blocks.
        Blocks,
    }

    /// Decides [`lookup_socket_owner`]'s outcome where that takes no scan, so
    /// only a lookup that will block has to be moved somewhere it may.
    pub(crate) fn lookup_without_scan<S>(
        cache: &SocketOwnerCache<S>,
        protocol: Protocol,
        endpoint: LocalEndpoint,
        received_at: Instant,
        wait_for_scan: bool,
    ) -> WithoutScan
    where
        S: Fn(Protocol) -> netmetrics::SocketOwnerSnapshot,
    {
        match cache.owner_without_scan(protocol, endpoint, received_at) {
            Some(Ok(owner)) => WithoutScan::Owner(owner),
            Some(Err(_)) if !wait_for_scan => WithoutScan::Busy,
            Some(Err(_)) | None => WithoutScan::Blocks,
        }
    }

    /// Bench support: times `samples` socket-table captures of every table
    /// and of each protocol's alone, and prints the observed scan cost.
    /// Windows-only: a scan reads one protocol's tables only there.
    #[cfg(all(windows, feature = "bench-internals"))]
    pub(crate) fn run_snapshot_benchmark() {
        const SAMPLES: u32 = 25;
        type Scan = fn() -> netmetrics::SocketOwnerSnapshot;
        let scans: [(&str, Scan); 3] = [
            ("all", netmetrics::socket_owner_snapshot),
            ("udp", || {
                netmetrics::socket_owner_snapshot_for(netmetrics::Protocol::Udp)
            }),
            ("tcp", || {
                netmetrics::socket_owner_snapshot_for(netmetrics::Protocol::Tcp)
            }),
        ];
        for (tables, scan) in scans {
            std::hint::black_box(scan());
            let started = Instant::now();
            for _ in 0..SAMPLES {
                std::hint::black_box(scan());
            }
            println!(
                "socket_owner_snapshot tables={tables} samples={SAMPLES} us/scan={}",
                started.elapsed().as_micros() / u128::from(SAMPLES)
            );
        }
    }
}

/// What a client lookup is for, which decides whether it may scan the socket
/// tables.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Purpose {
    /// The history row of a blocked query.
    BlockedQuery,
    /// The hint that names the connections a served answer leads to.
    ServedAnswer,
}

impl Purpose {
    /// Whether a lookup for this may scan the socket tables.
    ///
    /// On Windows a scan reads one protocol's tables in well under a
    /// millisecond, and any lookup may ask for one. Elsewhere it walks every
    /// process's descriptors, which takes tens of milliseconds, and the
    /// receive loop that asked answers nothing meanwhile. A blocked query's
    /// row is worth that: it is what the user reads, and the client loses
    /// nothing when a refusal comes late. A served answer's hint is not: every
    /// client waiting on that loop would pay for it.
    fn may_scan(self) -> bool {
        cfg!(windows) || self == Self::BlockedQuery
    }
}

/// Owner of the socket `context`'s query came from, if the reply path can
/// tell it now.
///
/// Call it before the answer is sent, while the client's socket is still
/// bound. A lookup can scan the whole socket table, which stalls the receive
/// loop, so at most one such scan runs per refresh interval. `None` means this
/// lookup needed another: finish it with [`deferred_query_owner`] off the
/// reply path. On a multi-threaded runtime the scan steps off the async worker
/// so other tasks keep running; a lookup that does not scan stays where it is.
///
/// A lookup whose `purpose` is not worth a scan ([`Purpose::may_scan`]) is
/// answered [`Ownership::NotFound`] without one.
pub(crate) fn reply_path_query_owner(
    context: &DnsQueryContext,
    purpose: Purpose,
) -> Option<Ownership> {
    table_query_owner(context, purpose, false)
}

/// [`reply_path_query_owner`], or with `wait_for_scan` a lookup that waits
/// behind a scan already running and always answers.
fn table_query_owner(
    context: &DnsQueryContext,
    purpose: Purpose,
    wait_for_scan: bool,
) -> Option<Ownership> {
    if !purpose.may_scan() {
        return Some(Ownership::NotFound);
    }
    let (protocol, endpoint) = client_endpoint(context);
    // Nearly every lookup is answered by the snapshot already taken, or
    // needs a scan that is not due. Neither blocks, and stepping off an
    // async worker for them cost each answer more than the lookup itself:
    // it hands the worker's tasks to another thread, which has to wake.
    match socket_table::lookup_without_scan(
        netmetrics::SocketOwnerCache::shared(),
        protocol,
        endpoint,
        context.received_at,
        wait_for_scan,
    ) {
        socket_table::WithoutScan::Owner(owner) => return Some(owner),
        socket_table::WithoutScan::Busy => return None,
        socket_table::WithoutScan::Blocks => {}
    }
    let lookup = || {
        socket_table::lookup_socket_owner(protocol, endpoint, context.received_at, wait_for_scan)
    };
    match tokio::runtime::Handle::try_current() {
        Ok(handle) if handle.runtime_flavor() != tokio::runtime::RuntimeFlavor::CurrentThread => {
            tokio::task::block_in_place(lookup)
        }
        _ => lookup(),
    }
}

/// How long deferred attribution waits for the event source to catch up with
/// a query. It normally has within a millisecond; this bounds a stalled one.
pub(crate) const RECORDED_OWNER_TIMEOUT: std::time::Duration = std::time::Duration::from_millis(50);

/// Whether an event source records client owners, so attribution can be
/// finished off the reply path with [`deferred_query_owner`].
pub(crate) fn recorded_owners_available() -> bool {
    netmetrics::endpoint_owner::available()
}

/// Owner of the socket `context`'s query came from, as the event source
/// recorded it for the client endpoint when the query arrived.
///
/// The recorded owner is exact even after the client's socket has closed or
/// its port has gone to another process, so this runs after the answer is
/// sent. Only when the source has no answer, such as for a socket opened
/// before it started, does it fall back to a socket table lookup, which then
/// sees the socket only if it is still bound. Blocks for up to
/// [`RECORDED_OWNER_TIMEOUT`] plus that lookup; call it off the reply path.
///
/// A job that waited in a backlog past the query deadline skips the table
/// fallback: the client has given up by then and its port may belong to
/// another process, so the table would name the wrong owner.
pub(crate) fn deferred_query_owner(context: &DnsQueryContext, purpose: Purpose) -> Ownership {
    let (protocol, endpoint) = client_endpoint(context);
    let recorded = recorded_owner(protocol, endpoint, context.received_at);
    STATS.count_recorded(recorded, endpoint.address.is_loopback());
    // Off the reply path, so the fallback can wait for a scan in progress.
    let owner = prefer_recorded(recorded, || {
        if port_may_be_reused(context.received_at) {
            STATS.table_skipped.fetch_add(1, Ordering::Relaxed);
            return Ownership::NotFound;
        }
        let owner = table_query_owner(context, purpose, true).unwrap_or(Ownership::NotFound);
        let answered = if owner.resolved_pid().is_some() {
            &STATS.table_resolved
        } else {
            &STATS.table_unresolved
        };
        answered.fetch_add(1, Ordering::Relaxed);
        owner
    });
    STATS.log_periodically();
    owner
}

/// How deferred client attribution was answered, so the share of lookups that
/// fall through to a socket-table scan, and why, shows in the debug log.
struct AttributionStats {
    recorded: AtomicU64,
    not_found: AtomicU64,
    untrusted: AtomicU64,
    behind: AtomicU64,
    unavailable: AtomicU64,
    /// Lookups the event source did not answer for a loopback client.
    loopback_misses: AtomicU64,
    table_resolved: AtomicU64,
    table_unresolved: AtomicU64,
    /// Fallbacks skipped because the query was already past its deadline.
    table_skipped: AtomicU64,
    last_log: parking_lot::Mutex<Option<std::time::Instant>>,
}

const STATS_LOG_INTERVAL: std::time::Duration = std::time::Duration::from_secs(60);

static STATS: AttributionStats = AttributionStats {
    recorded: AtomicU64::new(0),
    not_found: AtomicU64::new(0),
    untrusted: AtomicU64::new(0),
    behind: AtomicU64::new(0),
    unavailable: AtomicU64::new(0),
    loopback_misses: AtomicU64::new(0),
    table_resolved: AtomicU64::new(0),
    table_unresolved: AtomicU64::new(0),
    table_skipped: AtomicU64::new(0),
    last_log: parking_lot::Mutex::new(None),
};

impl AttributionStats {
    fn count_recorded(&self, recorded: netmetrics::endpoint_owner::EndpointOwner, loopback: bool) {
        use netmetrics::endpoint_owner::EndpointOwner;
        let counter = match recorded {
            EndpointOwner::Resolved(_) => {
                self.recorded.fetch_add(1, Ordering::Relaxed);
                return;
            }
            EndpointOwner::NotFound => &self.not_found,
            EndpointOwner::Untrusted => &self.untrusted,
            EndpointOwner::Behind => &self.behind,
            EndpointOwner::Unavailable => &self.unavailable,
        };
        counter.fetch_add(1, Ordering::Relaxed);
        if loopback {
            self.loopback_misses.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn log_periodically(&self) {
        let now = std::time::Instant::now();
        {
            let mut last = self.last_log.lock();
            if last.is_some_and(|at| now.duration_since(at) < STATS_LOG_INTERVAL) {
                return;
            }
            *last = Some(now);
        }
        let load = |counter: &AtomicU64| counter.load(Ordering::Relaxed);
        tracing::debug!(
            recorded = load(&self.recorded),
            not_found = load(&self.not_found),
            untrusted = load(&self.untrusted),
            behind = load(&self.behind),
            unavailable = load(&self.unavailable),
            loopback_misses = load(&self.loopback_misses),
            table_resolved = load(&self.table_resolved),
            table_unresolved = load(&self.table_unresolved),
            table_skipped = load(&self.table_skipped),
            shared_table_scans = shared_table_scans(),
            "dns client attribution totals"
        );
    }
}

/// Socket-table scans the process-wide owner cache has run, for DNS lookups
/// and for every other user of it.
fn shared_table_scans() -> u64 {
    netmetrics::SocketOwnerCache::shared().scans()
}

/// Whether a query received at `received_at` is past its deadline, after which
/// the client's port may have gone to another process.
fn port_may_be_reused(received_at: std::time::Instant) -> bool {
    received_at.elapsed() > antiwire_tuning::DNS_QUERY_DEADLINE
}

fn prefer_recorded(
    recorded: netmetrics::endpoint_owner::EndpointOwner,
    fallback: impl FnOnce() -> Ownership,
) -> Ownership {
    match recorded {
        netmetrics::endpoint_owner::EndpointOwner::Resolved(pid) => Ownership::Resolved(pid),
        _ => fallback(),
    }
}

/// The client endpoint `context`'s query came from. A redirected query
/// arrives from a synthetic endpoint; its flow belongs to the one it replaced.
fn client_endpoint(context: &DnsQueryContext) -> (netmetrics::Protocol, netmetrics::LocalEndpoint) {
    let protocol = match context.protocol {
        hickory_server::net::xfer::Protocol::Tcp => netmetrics::Protocol::Tcp,
        _ => netmetrics::Protocol::Udp,
    };
    let endpoint = netmetrics::LocalEndpoint {
        address: context.client_addr,
        port: context.client_port,
    };
    let endpoint =
        netmetrics::dns_divert::original_endpoint(protocol, endpoint).unwrap_or(endpoint);
    (protocol, endpoint)
}

fn recorded_owner(
    protocol: netmetrics::Protocol,
    endpoint: netmetrics::LocalEndpoint,
    received_at: std::time::Instant,
) -> netmetrics::endpoint_owner::EndpointOwner {
    netmetrics::endpoint_owner::owner_at(protocol, endpoint, received_at, RECORDED_OWNER_TIMEOUT)
}

#[cfg(all(windows, feature = "bench-internals"))]
pub(crate) fn run_snapshot_benchmark() {
    socket_table::run_snapshot_benchmark();
}

#[cfg(test)]
mod refine_tests {
    use super::*;
    use netmetrics::endpoint_owner::EndpointOwner;

    #[test]
    fn a_recorded_owner_skips_the_socket_table() {
        assert_eq!(
            prefer_recorded(EndpointOwner::Resolved(2222), || {
                panic!("a recorded owner needs no lookup")
            }),
            Ownership::Resolved(2222)
        );
    }

    #[test]
    fn the_socket_table_answers_without_a_recorded_owner() {
        for recorded in [
            EndpointOwner::NotFound,
            EndpointOwner::Untrusted,
            EndpointOwner::Behind,
            EndpointOwner::Unavailable,
        ] {
            assert_eq!(
                prefer_recorded(recorded, || Ownership::Resolved(1111)),
                Ownership::Resolved(1111)
            );
        }
    }

    /// A scan off Windows stalls the receive loop for tens of milliseconds, so only a
    /// blocked query's row may ask for one there.
    #[test]
    fn a_served_answer_is_worth_a_scan_only_where_one_is_cheap() {
        assert!(Purpose::BlockedQuery.may_scan());
        assert_eq!(Purpose::ServedAnswer.may_scan(), cfg!(windows));
        if !Purpose::ServedAnswer.may_scan() {
            let socket = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind");
            let local = socket.local_addr().expect("local address");
            let context = DnsQueryContext {
                client_addr: local.ip(),
                client_port: local.port(),
                protocol: hickory_server::net::xfer::Protocol::Udp,
                received_at: std::time::Instant::now(),
            };
            let scans = shared_table_scans();
            assert_eq!(
                reply_path_query_owner(&context, Purpose::ServedAnswer),
                Some(Ownership::NotFound)
            );
            assert_eq!(
                deferred_query_owner(&context, Purpose::ServedAnswer),
                Ownership::NotFound
            );
            assert_eq!(shared_table_scans(), scans, "neither lookup scanned");
        }
    }

    #[test]
    fn only_a_query_past_its_deadline_may_have_lost_its_port() {
        assert!(!port_may_be_reused(std::time::Instant::now()));
        let late = std::time::Instant::now()
            .checked_sub(antiwire_tuning::DNS_QUERY_DEADLINE + std::time::Duration::from_secs(1))
            .expect("instant supports subtraction");
        assert!(port_may_be_reused(late));
    }
}

#[cfg(test)]
mod reply_path_tests {
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Instant;

    use netmetrics::owner_cache::{Wait, DEFAULT_REFRESH};
    use netmetrics::{LocalEndpoint, Protocol, SocketOwnerCache, SocketOwnerSnapshot};

    use super::socket_table::{lookup_without_scan, WithoutScan};
    use super::Ownership;

    fn local(port: u16) -> LocalEndpoint {
        LocalEndpoint {
            address: IpAddr::V4(Ipv4Addr::LOCALHOST),
            port,
        }
    }

    /// The regression this guards: every reply-path lookup stepped off its
    /// async worker, though only a scan blocks and one is due at most once
    /// per refresh interval.
    #[test]
    fn a_lookup_blocks_only_for_a_scan_it_will_run_or_wait_for() {
        let scans = AtomicUsize::new(0);
        let cache = SocketOwnerCache::with_scanner(DEFAULT_REFRESH, |_| {
            scans.fetch_add(1, Ordering::Relaxed);
            let mut owners = SocketOwnerSnapshot::default();
            owners.insert_udp(local(50_000), 7);
            owners
        });
        let without_scan = |port, wait_for_scan| {
            lookup_without_scan(
                &cache,
                Protocol::Udp,
                local(port),
                Instant::now(),
                wait_for_scan,
            )
        };

        assert_eq!(
            without_scan(50_000, false),
            WithoutScan::Blocks,
            "nothing is scanned yet, so the lookup has to scan"
        );
        assert_eq!(
            cache.owner(Protocol::Udp, local(50_000), Instant::now(), Wait::Never),
            Ok(Ownership::Resolved(7))
        );

        assert_eq!(
            without_scan(50_000, false),
            WithoutScan::Owner(Ownership::Resolved(7)),
            "a socket in the snapshot is answered from it"
        );
        assert_eq!(
            without_scan(50_001, false),
            WithoutScan::Busy,
            "the reply path does not wait for a scan that is not due"
        );
        assert_eq!(
            without_scan(50_001, true),
            WithoutScan::Blocks,
            "a caller that may wait blocks for that scan"
        );
        assert_eq!(scans.load(Ordering::Relaxed), 1, "asking scans nothing");
    }
}
