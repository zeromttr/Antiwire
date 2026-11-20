//! Maps a query's client socket to its owning process id.
//!
//! A lookup on the reply path runs while the client is still waiting for its
//! answer, so its socket is still bound and the live socket table can name the
//! owner. A scan of that table is due at most once per refresh interval, and
//! any other lookup goes to a worker. The scan itself runs off the UDP receive
//! loop, before the reply it holds back is sent, so it stalls no other query:
//! each caller says where a scan may run ([`Scans`]).

use crate::block::DnsQueryContext;
use crate::listener::Transport;
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
            Wait::Until(super::query_deadline(received_at))
        } else {
            Wait::Never
        };
        match SocketOwnerCache::shared().owner(protocol, endpoint, received_at, wait) {
            Ok(owner) => Some(owner),
            Err(Pending::Busy) => None,
            Err(_) => Some(Ownership::NotFound),
        }
    }

    /// Owner of the client socket at `endpoint` in a snapshot taken after its
    /// query arrived at `received_at`, which shows every socket bound before
    /// the query and still open. For a lookup handed off the receive loop,
    /// whose reply is held back until it answers.
    ///
    /// Unlike [`lookup_socket_owner`] it never waits for the refresh interval,
    /// only for a scan already running, and then scans. A lookup is handed off
    /// when a scan is due, so one started since began after the query arrived
    /// and its snapshot answers; only when that scan left none would the
    /// interval apply. `None` once the query's deadline has passed.
    pub(crate) fn fresh_socket_owner<S>(
        cache: &SocketOwnerCache<S>,
        protocol: Protocol,
        endpoint: LocalEndpoint,
        received_at: Instant,
    ) -> Option<Ownership>
    where
        S: Fn(Protocol) -> netmetrics::SocketOwnerSnapshot,
    {
        cache
            .snapshot_since(
                protocol,
                received_at,
                Wait::Until(super::query_deadline(received_at)),
            )
            .ok()
            .map(|snapshot| snapshot.owners().local_endpoint_owner(protocol, endpoint))
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

/// Where a reply-path owner lookup runs when it has to scan the socket tables.
#[derive(Clone, Copy)]
pub(crate) enum Scans<'a> {
    /// On this thread, stepping off its async worker where it can: for a
    /// query answered on a task of its own, a TCP connection's or a miss's.
    Here,
    /// Handed to the reply of a query a UDP receive loop answers itself, so a
    /// scan never stalls that loop.
    HandedOff(&'a HandedOffLookups),
}

/// The client a query came from, and where the reply path's lookup of its
/// owner may scan.
#[derive(Clone, Copy)]
pub(crate) struct QueryClient<'a> {
    pub(crate) context: DnsQueryContext,
    pub(crate) scans: Scans<'a>,
}

impl QueryClient<'_> {
    /// A client whose owner is looked up on this thread ([`Scans::Here`]).
    pub(crate) fn scanned_here(context: DnsQueryContext) -> Self {
        Self {
            context,
            scans: Scans::Here,
        }
    }
}

/// What the reply path knows of the owner of the socket a query came from.
pub(crate) enum ReplyPathOwner {
    /// The newest socket-table snapshot names the owner, or says there is none.
    Known(Ownership),
    /// A lookup handed off the receive loop names it before the reply goes
    /// out (see [`Scans::HandedOff`]).
    Promised(PromisedOwner),
    /// Naming it needs a scan that may not start now: finish it with
    /// [`deferred_query_owner`] off the reply path.
    Busy,
}

/// The owner of a query's client socket, promised by a lookup that runs off
/// the receive loop before the query's reply is sent.
pub(crate) struct PromisedOwner(std::sync::mpsc::Receiver<Ownership>);

impl PromisedOwner {
    /// Waits for the lookup, until `context`'s query deadline at the latest.
    /// `None` when it was not run, as when the receive loop already held as
    /// many replies as it may: look the owner up with
    /// [`deferred_query_owner`] instead.
    pub(crate) fn wait(self, context: &DnsQueryContext) -> Option<Ownership> {
        let deadline = query_deadline(context.received_at);
        self.0
            .recv_timeout(deadline.saturating_duration_since(std::time::Instant::now()))
            .ok()
    }
}

/// Owner lookups a receive loop hands off while it answers one query, to run
/// before that query's reply is sent, on a thread that may block (see
/// [`Self::run`]). They have to see the client's socket, and the client closes
/// it once the reply arrives.
#[derive(Default)]
pub(crate) struct HandedOffLookups(std::cell::RefCell<Vec<HandedOff>>);

struct HandedOff {
    protocol: netmetrics::Protocol,
    endpoint: netmetrics::LocalEndpoint,
    received_at: std::time::Instant,
    promise: std::sync::mpsc::SyncSender<Ownership>,
}

impl HandedOffLookups {
    /// These lookups, or `None` when nothing was handed off.
    pub(crate) fn any(mut self) -> Option<Self> {
        (!self.0.get_mut().is_empty()).then_some(self)
    }

    /// Hands off a lookup and returns its promise.
    fn hand_off(
        &self,
        protocol: netmetrics::Protocol,
        endpoint: netmetrics::LocalEndpoint,
        received_at: std::time::Instant,
    ) -> PromisedOwner {
        let (promise, owner) = std::sync::mpsc::sync_channel(1);
        self.0.borrow_mut().push(HandedOff {
            protocol,
            endpoint,
            received_at,
            promise,
        });
        PromisedOwner(owner)
    }

    /// Runs the lookups, scanning the socket tables when they must, and keeps
    /// each promise. Blocks for the scan; run it where that may.
    pub(crate) fn run(self) {
        for lookup in self.0.into_inner() {
            let owner = socket_table::fresh_socket_owner(
                netmetrics::SocketOwnerCache::shared(),
                lookup.protocol,
                lookup.endpoint,
                lookup.received_at,
            )
            .unwrap_or(Ownership::NotFound);
            // The caller may have stopped waiting; the owner is then not needed.
            let _ = lookup.promise.send(owner);
        }
    }
}

/// Owner of the socket `client`'s query came from, as far as the reply path
/// can tell it.
///
/// Call it before the answer is sent, while the client's socket is still
/// bound. Most lookups are answered by the snapshot already taken, or need a
/// scan that is not due, and either is answered at once. One that may start a
/// scan, at most once per refresh interval, goes where `client.scans` says.
///
/// A lookup whose `purpose` is not worth a scan ([`Purpose::may_scan`]) is
/// answered [`Ownership::NotFound`] without one.
pub(crate) fn reply_path_query_owner(client: QueryClient<'_>, purpose: Purpose) -> ReplyPathOwner {
    if !purpose.may_scan() {
        return ReplyPathOwner::Known(Ownership::NotFound);
    }
    let context = &client.context;
    let (protocol, endpoint) = client_endpoint(context);
    match lookup_without_scan(protocol, endpoint, context, false) {
        socket_table::WithoutScan::Owner(owner) => ReplyPathOwner::Known(owner),
        socket_table::WithoutScan::Busy => ReplyPathOwner::Busy,
        socket_table::WithoutScan::Blocks => match client.scans {
            Scans::HandedOff(lookups) => {
                ReplyPathOwner::Promised(lookups.hand_off(protocol, endpoint, context.received_at))
            }
            Scans::Here => scan_here(protocol, endpoint, context.received_at, false)
                .map_or(ReplyPathOwner::Busy, ReplyPathOwner::Known),
        },
    }
}

/// [`reply_path_query_owner`] off the reply path: it waits behind a scan
/// already running, or for the next one, and always answers.
fn table_query_owner(context: &DnsQueryContext, purpose: Purpose) -> Ownership {
    if !purpose.may_scan() {
        return Ownership::NotFound;
    }
    let (protocol, endpoint) = client_endpoint(context);
    match lookup_without_scan(protocol, endpoint, context, true) {
        socket_table::WithoutScan::Owner(owner) => owner,
        socket_table::WithoutScan::Busy | socket_table::WithoutScan::Blocks => {
            scan_here(protocol, endpoint, context.received_at, true).unwrap_or(Ownership::NotFound)
        }
    }
}

/// What a lookup would do without blocking. Nearly every lookup is answered by
/// the snapshot already taken, or needs a scan that is not due. Neither
/// blocks, and stepping off an async worker for them cost each answer more
/// than the lookup itself: it hands the worker's tasks to another thread,
/// which has to wake.
fn lookup_without_scan(
    protocol: netmetrics::Protocol,
    endpoint: netmetrics::LocalEndpoint,
    context: &DnsQueryContext,
    wait_for_scan: bool,
) -> socket_table::WithoutScan {
    socket_table::lookup_without_scan(
        netmetrics::SocketOwnerCache::shared(),
        protocol,
        endpoint,
        context.received_at,
        wait_for_scan,
    )
}

/// Runs a lookup that may scan on this thread, first stepping off the async
/// worker on a multi-threaded runtime so its other tasks keep running.
fn scan_here(
    protocol: netmetrics::Protocol,
    endpoint: netmetrics::LocalEndpoint,
    received_at: std::time::Instant,
    wait_for_scan: bool,
) -> Option<Ownership> {
    let lookup =
        || socket_table::lookup_socket_owner(protocol, endpoint, received_at, wait_for_scan);
    match tokio::runtime::Handle::try_current() {
        Ok(handle) if handle.runtime_flavor() != tokio::runtime::RuntimeFlavor::CurrentThread => {
            tokio::task::block_in_place(lookup)
        }
        _ => lookup(),
    }
}

/// How long after a query arrived deferred attribution waits for the event
/// source to catch up with it. It normally has within a millisecond; this
/// bounds a stalled one.
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
/// sees the socket only if it is still bound. Blocks until
/// [`RECORDED_OWNER_TIMEOUT`] after the query arrived at the latest, plus that
/// lookup; call it off the reply path.
///
/// A job that waited in a backlog past the query deadline skips the table
/// fallback: the client has given up by then and its port may belong to
/// another process, so the table would name the wrong owner.
pub(crate) fn deferred_query_owner(context: &DnsQueryContext, purpose: Purpose) -> Ownership {
    deferred_query_owner_from(context, purpose, recorded_owner)
}

/// [`deferred_query_owner`], reading recorded owners from `recorded`, which
/// is given how long it may wait for the event source to catch up.
fn deferred_query_owner_from(
    context: &DnsQueryContext,
    purpose: Purpose,
    recorded: impl FnOnce(
        netmetrics::Protocol,
        netmetrics::LocalEndpoint,
        std::time::Instant,
        std::time::Duration,
    ) -> netmetrics::endpoint_owner::EndpointOwner,
) -> Ownership {
    let (protocol, endpoint) = client_endpoint(context);
    // The wait is counted from when the query arrived, not from now: the
    // worker runs lookups one after another, so a fresh wait each would let a
    // stalled source hold every queued lookup up by the whole timeout again.
    let wait = RECORDED_OWNER_TIMEOUT.saturating_sub(context.received_at.elapsed());
    let recorded = recorded(protocol, endpoint, context.received_at, wait);
    STATS.count_recorded(recorded, endpoint.address.is_loopback());
    // Off the reply path, so the fallback can wait for a scan in progress.
    let owner = prefer_recorded(recorded, || {
        if port_may_be_reused(context.received_at) {
            STATS.table_skipped.fetch_add(1, Ordering::Relaxed);
            return Ownership::NotFound;
        }
        let owner = table_query_owner(context, purpose);
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
pub(crate) fn shared_table_scans() -> u64 {
    netmetrics::SocketOwnerCache::shared().scans()
}

/// When a query received at `received_at` reaches its deadline.
fn query_deadline(received_at: std::time::Instant) -> std::time::Instant {
    received_at
        .checked_add(antiwire_tuning::DNS_QUERY_DEADLINE)
        .unwrap_or(received_at)
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
    let protocol = match context.transport {
        Transport::Tcp => netmetrics::Protocol::Tcp,
        Transport::Udp => netmetrics::Protocol::Udp,
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
    wait: std::time::Duration,
) -> netmetrics::endpoint_owner::EndpointOwner {
    netmetrics::endpoint_owner::owner_at(protocol, endpoint, received_at, wait)
}

#[cfg(all(windows, feature = "bench-internals"))]
pub(crate) fn run_snapshot_benchmark() {
    socket_table::run_snapshot_benchmark();
}

#[cfg(test)]
mod refine_tests {
    use super::*;
    use netmetrics::endpoint_owner::EndpointOwner;

    fn context_for(
        socket: &std::net::UdpSocket,
        received_at: std::time::Instant,
    ) -> DnsQueryContext {
        let local = socket.local_addr().expect("local address");
        DnsQueryContext {
            client_addr: local.ip(),
            client_port: local.port(),
            transport: crate::listener::Transport::Udp,
            received_at,
        }
    }

    /// A lookup handed off a receive loop comes back with its reply, to run
    /// elsewhere, and names the owner to whoever waits on its promise.
    #[test]
    fn a_lookup_handed_off_the_receive_loop_keeps_its_promise() {
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").expect("client socket");
        let context = context_for(&socket, std::time::Instant::now());
        let (protocol, endpoint) = client_endpoint(&context);
        assert!(
            HandedOffLookups::default().any().is_none(),
            "a reply with nothing handed off carries no lookups"
        );
        let lookups = HandedOffLookups::default();
        let promise = lookups.hand_off(protocol, endpoint, context.received_at);
        lookups.any().expect("the lookup comes back").run();
        assert_eq!(
            promise.wait(&context),
            Some(Ownership::Resolved(std::process::id()))
        );
    }

    /// A lookup that is never run, as when the receive loop holds as many
    /// replies as it may, breaks its promise, and the waiter looks the owner
    /// up itself instead of waiting out the query deadline.
    #[test]
    fn a_dropped_hand_off_lets_the_waiter_look_the_owner_up_itself() {
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").expect("client socket");
        let context = context_for(&socket, std::time::Instant::now());
        let (protocol, endpoint) = client_endpoint(&context);
        let lookups = HandedOffLookups::default();
        let promise = lookups.hand_off(protocol, endpoint, context.received_at);
        drop(lookups);
        let started = std::time::Instant::now();
        assert_eq!(promise.wait(&context), None);
        assert!(started.elapsed() < std::time::Duration::from_millis(100));
    }

    /// The regression this guards: the attribution worker runs its lookups
    /// one after another, and each gave the event source a fresh
    /// [`RECORDED_OWNER_TIMEOUT`] to catch up. With the source stalled, every
    /// queued lookup waited that long again, so the backlog grew by 50 ms a
    /// job. A query is owed that wait once, counted from when it arrived.
    #[test]
    fn a_stalled_event_source_delays_queued_lookups_once_not_once_each() {
        use std::sync::atomic::AtomicUsize;
        use std::sync::Arc;
        const JOBS: usize = 10;
        // Each waits out what it is given, as a source that never catches up does.
        fn stalled(
            _: netmetrics::Protocol,
            _: netmetrics::LocalEndpoint,
            _: std::time::Instant,
            wait: std::time::Duration,
        ) -> EndpointOwner {
            std::thread::sleep(wait);
            EndpointOwner::Behind
        }
        // Past the deadline, so no lookup goes on to the socket table.
        let received_at = std::time::Instant::now()
            .checked_sub(antiwire_tuning::DNS_QUERY_DEADLINE + std::time::Duration::from_secs(1))
            .expect("instant supports subtraction");
        let context = DnsQueryContext {
            client_addr: std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            client_port: 50_000,
            transport: crate::listener::Transport::Udp,
            received_at,
        };
        let worker = crate::owner_worker::OwnerWorker::default();
        let done = Arc::new(AtomicUsize::new(0));
        let started = std::time::Instant::now();
        for _ in 0..JOBS {
            let done = Arc::clone(&done);
            assert!(worker
                .submit(Box::new(move || {
                    let owner = deferred_query_owner_from(&context, Purpose::BlockedQuery, stalled);
                    assert_eq!(owner, Ownership::NotFound);
                    done.fetch_add(1, Ordering::Relaxed);
                }))
                .is_ok());
        }
        while done.load(Ordering::Relaxed) < JOBS {
            assert!(
                started.elapsed() < std::time::Duration::from_secs(10),
                "worker stuck"
            );
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        let drained = started.elapsed();
        worker.shutdown();
        eprintln!("{JOBS} lookups behind a stalled event source drained in {drained:?}");
        assert!(
            drained < RECORDED_OWNER_TIMEOUT,
            "lookups past their wait must not wait again: {drained:?}"
        );
    }

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
                transport: crate::listener::Transport::Udp,
                received_at: std::time::Instant::now(),
            };
            let scans = shared_table_scans();
            assert!(matches!(
                reply_path_query_owner(QueryClient::scanned_here(context), Purpose::ServedAnswer),
                ReplyPathOwner::Known(Ownership::NotFound)
            ));
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

    use super::socket_table::{fresh_socket_owner, lookup_without_scan, WithoutScan};
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

    /// The regression this guards: a lookup handed off the receive loop
    /// waited as one off the reply path does, for the refresh interval to
    /// allow its scan, though its reply is held back until it answers. It is
    /// handed off when a scan is due, so a scan started since usually answers
    /// it; when the one that took the slot left nothing newer than its query,
    /// as a scan that panicked does, the reply waited out the interval.
    #[test]
    fn a_handed_off_lookup_never_waits_for_the_refresh_interval() {
        let scans = AtomicUsize::new(0);
        let cache = SocketOwnerCache::with_scanner(DEFAULT_REFRESH, |_| {
            scans.fetch_add(1, Ordering::Relaxed);
            SocketOwnerSnapshot::default()
        });
        // This scan takes the slot but predates the query, so it cannot say
        // whether the client's socket, bound later, is open.
        let _ = cache.owner(Protocol::Udp, local(50_001), Instant::now(), Wait::Never);
        std::thread::sleep(std::time::Duration::from_millis(5));
        let received_at = Instant::now();

        let started = Instant::now();
        assert_eq!(
            fresh_socket_owner(&cache, Protocol::Udp, local(50_000), received_at),
            Some(Ownership::NotFound)
        );
        assert!(
            started.elapsed() < DEFAULT_REFRESH / 2,
            "the lookup scanned at once: {:?}",
            started.elapsed()
        );
        assert_eq!(scans.load(Ordering::Relaxed), 2);
    }
}
