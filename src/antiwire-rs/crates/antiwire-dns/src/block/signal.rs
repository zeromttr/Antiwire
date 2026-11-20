//! Throttled logging when the DNS policy filter blocks a query.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{self, SyncSender, TrySendError};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use antiwire_policy::RecentLru;
use antiwire_tuning::{BLOCK_SIGNAL_THROTTLE_MS, DNS_BLOCK_SIGNAL_QUEUE_CAPACITY};
use hickory_proto::rr::RecordType;
use parking_lot::Mutex;
use tracing::{info, warn};

use super::response::BlockResponseMode;
use super::sink::DnsBlockSink;
use crate::listener::Transport;
use crate::port_mapper::{
    deferred_query_owner, recorded_owners_available, reply_path_query_owner, Ownership,
    PromisedOwner, Purpose, QueryClient, ReplyPathOwner,
};
use std::net::IpAddr;

/// Optional per-query client metadata for block attribution.
#[derive(Debug, Clone, Copy)]
pub(crate) struct DnsQueryContext {
    pub(crate) client_addr: IpAddr,
    pub(crate) client_port: u16,
    pub(crate) transport: Transport,
    pub(crate) received_at: Instant,
}

struct BlockSignalEvent {
    domain: String,
    owner: BlockOwner,
    timestamp: time::OffsetDateTime,
    blocklist_names: Vec<String>,
}

/// Owner of a blocked query's client socket.
enum BlockOwner {
    /// Resolved from the socket table before the block response was sent. A
    /// later lookup misses the short-lived UDP socket that a blocked query
    /// closes as soon as it receives the answer.
    Resolved(Ownership),
    /// Resolved from the socket table off the receive loop, before the block
    /// response was sent, as `Resolved` is; the worker waits for it.
    Promised(PromisedOwner, DnsQueryContext),
    /// Resolved on the worker from the owner an event source recorded, which
    /// outlives the socket (see `port_mapper::deferred_query_owner`), or from
    /// a socket-table scan the reply path could not run itself.
    Deferred(DnsQueryContext),
}

enum BlockSignalCommand {
    Record(BlockSignalEvent),
    /// Wake a worker parked in `recv()` so it observes `worker_stop`; unlike an
    /// empty-domain event, it can never be mistaken for a real record.
    Stop,
}

/// Rate-limits block log lines and dispatches persistence off the query hot path.
pub(crate) struct BlockSignalLogger {
    recent: Mutex<RecentBlockSignals>,
    /// `None` without a sink, or when its worker could not be started.
    event_tx: Option<SyncSender<BlockSignalCommand>>,
    worker_stop: Arc<AtomicBool>,
    worker: Mutex<Option<JoinHandle<()>>>,
    dropped: AtomicU64,
}

struct RecentBlockSignals {
    entries: RecentLru<String>,
}

impl RecentBlockSignals {
    fn new(capacity: usize) -> Self {
        Self {
            entries: RecentLru::new(capacity),
        }
    }

    fn should_signal(&mut self, domain: &str, now: Instant, throttle: Duration) -> bool {
        // Borrowed probe: a throttled repeat of the same domain allocates
        // nothing; the owned key is created only when it is admitted.
        self.entries.should_admit_borrowed(domain, now, throttle)
    }
}

impl BlockSignalLogger {
    #[must_use]
    pub(crate) fn new(sink: Option<Arc<dyn DnsBlockSink>>) -> Self {
        let worker_stop = Arc::new(AtomicBool::new(false));
        let (event_tx, worker) = sink.map_or((None, None), |worker_sink| {
            let (event_tx, event_rx) = mpsc::sync_channel(DNS_BLOCK_SIGNAL_QUEUE_CAPACITY as usize);
            let worker_stop = Arc::clone(&worker_stop);
            match std::thread::Builder::new()
                .name("antiwire-dns-block-signal".to_owned())
                .spawn(move || {
                    block_signal_worker(&event_rx, worker_sink.as_ref(), &worker_stop);
                }) {
                Ok(worker) => (Some(event_tx), Some(worker)),
                Err(error) => {
                    warn!(
                        %error,
                        "failed to start dns block attribution worker; blocked queries will not be recorded"
                    );
                    (None, None)
                }
            }
        });

        Self {
            recent: Mutex::new(RecentBlockSignals::new(
                antiwire_tuning::RECENT_BLOCK_SIGNALS_CAP as usize,
            )),
            event_tx,
            worker_stop,
            worker: Mutex::new(worker),
            dropped: AtomicU64::new(0),
        }
    }

    /// Stops the attribution worker and joins it.
    ///
    /// The worker checks the stop flag before each event, so this abandons
    /// anything still queued rather than draining it. Blocks on the in-progress
    /// event; call it from a blocking thread.
    pub(crate) fn shutdown(&self) {
        let Some(worker) = self.worker.lock().take() else {
            return;
        };
        self.worker_stop.store(true, Ordering::Release);
        // The sender stays alive until `Drop`, so wake a worker parked in
        // `recv()`; it discards the command after re-checking the flag.
        if let Some(tx) = &self.event_tx {
            if let Err(error) = tx.try_send(BlockSignalCommand::Stop) {
                // A full queue means the worker is mid-event and will observe
                // the stop flag next; only a disconnected worker is a fault.
                if !matches!(error, TrySendError::Full(_)) {
                    warn!(%error, "dns block attribution worker stopped before shutdown");
                }
            }
        }
        if let Err(error) = worker.join() {
            warn!(?error, "dns block attribution worker panicked");
        }
    }

    /// Logs a blocked DNS query when the domain has not been logged recently.
    pub(crate) fn signal_block<F>(
        &self,
        domain: &str,
        qtype: RecordType,
        source: Option<&str>,
        mode: BlockResponseMode,
        client: Option<QueryClient<'_>>,
        resolve_blocklist_names: F,
    ) where
        F: FnOnce() -> Vec<String>,
    {
        if domain.is_empty() {
            return;
        }

        // Throttling logs by domain before attribution suppressed other applications
        // requests for that same domain. Separate log throttling from per-caller persistence.
        let should_log = self.should_signal(domain);
        let has_sink = self.event_tx.is_some();
        if !should_log && !has_sink {
            return;
        }

        let blocklist_names = resolve_blocklist_names();
        if should_log {
            let mode = mode.as_str();
            let source = source.unwrap_or("policy");
            if let Some(ctx) = client
                .map(|client| client.context)
                .filter(|ctx| ctx.client_port > 0)
            {
                info!(
                    domain,
                    ?qtype,
                    source,
                    blocklists = ?blocklist_names,
                    mode,
                    client_port = ctx.client_port,
                    "blocked dns query"
                );
            } else {
                info!(
                    domain,
                    ?qtype,
                    source,
                    blocklists = ?blocklist_names,
                    mode,
                    "blocked dns query"
                );
            }
        }

        if !has_sink {
            return;
        }

        // Without recorded owners, resolve while the client is still waiting
        // for this response. The socket is gone once the block answer is
        // delivered, and a lookup on the worker then records Unknown (No Owner).
        // A lookup that has to scan the socket table still runs before the
        // answer goes out, but off the UDP receive loop (see
        // `port_mapper::Scans`). One whose scan is not due yet is the
        // exception: the worker scans when it is, racing the client's close,
        // rather than stall every other query behind it.
        let owner = match client {
            Some(client) if recorded_owners_available() => BlockOwner::Deferred(client.context),
            Some(client) => match reply_path_query_owner(client, Purpose::BlockedQuery) {
                ReplyPathOwner::Known(owner) => BlockOwner::Resolved(owner),
                ReplyPathOwner::Promised(owner) => BlockOwner::Promised(owner, client.context),
                ReplyPathOwner::Busy => BlockOwner::Deferred(client.context),
            },
            None => BlockOwner::Resolved(Ownership::NotFound),
        };
        let timestamp = time::OffsetDateTime::now_utc();

        if let Some(tx) = &self.event_tx {
            match tx.try_send(BlockSignalCommand::Record(BlockSignalEvent {
                domain: domain.to_owned(),
                owner,
                timestamp,
                blocklist_names,
            })) {
                Ok(()) => {}
                Err(TrySendError::Full(_)) => {
                    let dropped = self.dropped.fetch_add(1, Ordering::Relaxed) + 1;
                    if dropped.is_power_of_two() {
                        warn!(
                            domain,
                            dropped, "dns block attribution queue full; dropping events"
                        );
                    }
                }
                Err(TrySendError::Disconnected(_)) => {
                    let dropped = self.dropped.fetch_add(1, Ordering::Relaxed) + 1;
                    if dropped.is_power_of_two() {
                        warn!(
                            domain,
                            dropped, "dns block attribution worker stopped; dropping events"
                        );
                    }
                }
            }
        }
    }

    fn should_signal(&self, domain: &str) -> bool {
        let throttle = Duration::from_millis(BLOCK_SIGNAL_THROTTLE_MS as u64);
        let now = Instant::now();
        self.recent.lock().should_signal(domain, now, throttle)
    }
}

impl Drop for BlockSignalLogger {
    fn drop(&mut self) {
        // Ordered teardown goes through `shutdown`; this only has to make sure
        // the worker is not leaked. The logger is shared by `Arc` with every
        // in-flight fetch future, so the last holder may be a cancelled
        // request dropping on a runtime thread — never park that thread on the
        // join. Off the runtime, joining inline is the useful behaviour.
        self.worker_stop.store(true, Ordering::Release);
        self.event_tx.take();
        let Some(worker) = self.worker.lock().take() else {
            return;
        };
        match tokio::runtime::Handle::try_current() {
            Ok(handle) => {
                handle.spawn_blocking(move || {
                    if let Err(error) = worker.join() {
                        warn!(?error, "dns block attribution worker panicked");
                    }
                });
            }
            Err(_) => {
                if let Err(error) = worker.join() {
                    warn!(?error, "dns block attribution worker panicked");
                }
            }
        }
    }
}

fn block_signal_worker(
    rx: &mpsc::Receiver<BlockSignalCommand>,
    sink: &dyn DnsBlockSink,
    stop: &AtomicBool,
) {
    while let Ok(command) = rx.recv() {
        let BlockSignalCommand::Record(event) = command else {
            return;
        };
        // Re-check after waking: `shutdown` may have parked the stop command
        // behind records that must not reach the sink.
        if stop.load(Ordering::Acquire) {
            return;
        }
        let ownership = match event.owner {
            BlockOwner::Resolved(ownership) => ownership,
            BlockOwner::Promised(owner, context) => owner
                .wait(&context)
                .unwrap_or_else(|| deferred_query_owner(&context, Purpose::BlockedQuery)),
            BlockOwner::Deferred(context) => deferred_query_owner(&context, Purpose::BlockedQuery),
        };
        sink.record_blocked_query_with_ownership(
            &event.domain,
            ownership,
            &event.blocklist_names,
            Some(event.timestamp),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct OwnershipSink {
        ownership: Mutex<Option<crate::port_mapper::Ownership>>,
    }

    impl DnsBlockSink for OwnershipSink {
        fn record_blocked_query(&self, _domain: &str, _pid: u32, _blocklist_names: &[String]) {}

        fn record_blocked_query_with_ownership(
            &self,
            _domain: &str,
            ownership: crate::port_mapper::Ownership,
            _blocklist_names: &[String],
            _timestamp: Option<time::OffsetDateTime>,
        ) {
            *self.ownership.lock() = Some(ownership);
        }
    }

    #[derive(Default)]
    struct CountingSink {
        recorded: AtomicU64,
    }

    #[test]
    fn worker_keeps_the_owner_captured_before_the_socket_closes() {
        let sink = OwnershipSink::default();
        let (tx, rx) = mpsc::sync_channel(1);
        let stop = AtomicBool::new(false);
        tx.send(BlockSignalCommand::Record(BlockSignalEvent {
            domain: "blocked.example".to_owned(),
            owner: BlockOwner::Resolved(Ownership::Resolved(4242)),
            timestamp: time::OffsetDateTime::now_utc(),
            blocklist_names: Vec::new(),
        }))
        .expect("queue the captured owner");
        drop(tx);

        block_signal_worker(&rx, &sink, &stop);

        assert_eq!(*sink.ownership.lock(), Some(Ownership::Resolved(4242)));
    }

    /// The regression this guards, off Windows: the lookup was compiled only there, and
    /// everywhere else answered that the socket had no owner without looking.
    #[test]
    fn signal_block_records_the_sender_even_after_its_socket_closes() {
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind");
        let addr = socket.local_addr().expect("local addr");
        let sink = Arc::new(OwnershipSink::default());
        let logger = BlockSignalLogger::new(Some(Arc::clone(&sink) as Arc<dyn DnsBlockSink>));

        logger.signal_block(
            "cursor.example",
            RecordType::A,
            Some("blocklist"),
            BlockResponseMode::NxDomain,
            Some(QueryClient::scanned_here(DnsQueryContext {
                client_addr: addr.ip(),
                client_port: addr.port(),
                transport: Transport::Udp,
                received_at: Instant::now(),
            })),
            Vec::new,
        );
        drop(socket);
        // `shutdown` discards records the worker has not picked up yet, so
        // wait for delivery first; the owner was captured before the drop.
        let deadline = Instant::now() + Duration::from_secs(5);
        while sink.ownership.lock().is_none() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(5));
        }
        logger.shutdown();

        assert_eq!(
            *sink.ownership.lock(),
            Some(Ownership::Resolved(std::process::id()))
        );
    }

    #[test]
    fn sink_contract_preserves_ambiguous_socket_ownership() {
        let sink = OwnershipSink::default();
        sink.record_blocked_query_with_ownership(
            "shared.example",
            crate::port_mapper::Ownership::Ambiguous,
            &[],
            None,
        );

        assert_eq!(
            *sink.ownership.lock(),
            Some(crate::port_mapper::Ownership::Ambiguous)
        );
    }

    impl DnsBlockSink for CountingSink {
        fn record_blocked_query(&self, _domain: &str, _pid: u32, _blocklist_names: &[String]) {
            self.recorded.fetch_add(1, Ordering::Relaxed);
        }
    }

    #[test]
    fn shutdown_joins_the_worker_and_the_wake_up_never_reaches_the_sink() {
        let sink = Arc::new(CountingSink::default());
        let logger = BlockSignalLogger::new(Some(Arc::clone(&sink) as Arc<dyn DnsBlockSink>));
        assert!(logger.worker.lock().is_some(), "worker starts with a sink");

        // Worker is parked in `recv()` with nothing queued.
        logger.shutdown();
        assert!(logger.worker.lock().is_none(), "shutdown joins the worker");
        assert_eq!(
            sink.recorded.load(Ordering::Relaxed),
            0,
            "the wake-up event is discarded, not recorded"
        );

        // Idempotent, and the final drop has nothing left to join.
        logger.shutdown();
        drop(logger);
    }

    #[tokio::test]
    async fn dropping_on_a_runtime_thread_releases_the_worker() {
        let sink = Arc::new(CountingSink::default());
        let logger = BlockSignalLogger::new(Some(sink as Arc<dyn DnsBlockSink>));
        // Runs the detached-join branch; must neither panic nor deadlock.
        drop(logger);
        tokio::task::yield_now().await;
    }

    #[test]
    fn throttles_repeated_domain_within_window() {
        let logger = BlockSignalLogger::new(None);
        assert!(logger.should_signal("ads.example"));
        assert!(!logger.should_signal("ads.example"));
        assert!(logger.should_signal("other.example"));
    }

    #[test]
    fn resolves_blocklist_names_only_for_admitted_events() {
        let logger = BlockSignalLogger::new(None);
        let resolutions = AtomicU64::new(0);

        logger.signal_block(
            "ads.example",
            RecordType::A,
            Some("blocklist"),
            BlockResponseMode::NxDomain,
            None,
            || {
                resolutions.fetch_add(1, Ordering::Relaxed);
                vec!["catalog-one".to_owned()]
            },
        );
        logger.signal_block(
            "ads.example",
            RecordType::A,
            Some("blocklist"),
            BlockResponseMode::NxDomain,
            None,
            || {
                resolutions.fetch_add(1, Ordering::Relaxed);
                vec!["catalog-one".to_owned()]
            },
        );

        assert_eq!(resolutions.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn recent_block_signals_remain_hard_bounded() {
        let mut recent = RecentBlockSignals::new(2);
        let now = Instant::now();
        let throttle = Duration::from_secs(30);

        assert!(recent.should_signal("one.example", now, throttle));
        assert!(recent.should_signal("two.example", now, throttle));
        assert!(recent.should_signal("three.example", now, throttle));

        // Capacity two evicts the oldest entry, while the newest remains
        // throttled.
        assert!(recent.should_signal("one.example", now, throttle));
        assert!(!recent.should_signal("three.example", now, throttle));
    }

    #[test]
    fn forwards_to_sink_even_when_log_is_throttled() {
        let sink = Arc::new(CountingSink::default());
        let logger = BlockSignalLogger::new(Some(Arc::clone(&sink) as Arc<dyn DnsBlockSink>));

        logger.signal_block(
            "ads.example",
            RecordType::A,
            Some("blocklist"),
            BlockResponseMode::NxDomain,
            None,
            || vec!["catalog-one".to_owned()],
        );
        logger.signal_block(
            "ads.example",
            RecordType::A,
            Some("blocklist"),
            BlockResponseMode::NxDomain,
            None,
            || vec!["catalog-one".to_owned()],
        );

        std::thread::sleep(Duration::from_millis(50));
        assert_eq!(sink.recorded.load(Ordering::Relaxed), 2);
    }
}
