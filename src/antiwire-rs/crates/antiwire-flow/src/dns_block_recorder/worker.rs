//! The writer thread: batching blocked queries, retrying failed writes,
//! settling what is left at shutdown, and announcing each saved block.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::time::{Duration, Instant};

use antiwire_events::{Alert, AlertKind, Severity};
use antiwire_tuning::RECENT_DNS_BLOCKS_CAP;
use time::OffsetDateTime;
use tracing::warn;

use super::attribution::{
    attributed_owner_pid, attributed_requesting_pid, correlate_block, started_after,
};
use super::{
    dns_dedup_window, is_daemon_executable, BatchRetry, DnsBlockKey, DnsBlockWorker, DnsWriteBatch,
    PendingBlock, PreparedBlock, ReceiveResult, RecentLru, RetryState, ShutdownState,
    SHUTDOWN_WRITE_RETRY_ATTEMPTS, WORKER_STOP_POLL, WRITE_BATCH_SIZE, WRITE_QUEUE_CAPACITY,
    WRITE_RETRY_BACKOFF,
};
use crate::correlator::{DnsAttributionStatus, DnsCorrelationResult};
use crate::timestamps::unix_secs;

impl DnsBlockWorker {
    pub(super) fn run(self, rx: &mpsc::Receiver<PendingBlock>, stop: &AtomicBool) {
        let dedup_window = dns_dedup_window();
        let capacity = usize::try_from(RECENT_DNS_BLOCKS_CAP)
            .unwrap_or(100_000)
            .max(1);
        let mut recent = RecentLru::new(capacity);
        let mut pending: VecDeque<(Instant, PendingBlock)> =
            VecDeque::with_capacity(WRITE_QUEUE_CAPACITY);

        let mut batch = DnsWriteBatch::with_capacity(WRITE_BATCH_SIZE);
        let mut retry = RetryState::default();
        let mut shutdown = ShutdownState::default();
        'worker: loop {
            match self.retry_batch(&mut batch, &mut retry, stop, &mut shutdown) {
                BatchRetry::Ready => {}
                BatchRetry::Wait => continue 'worker,
                BatchRetry::Stop => break 'worker,
            }

            if stop.load(Ordering::Acquire) || shutdown.connection_logs_failed {
                break 'worker;
            }

            if self.persist_ready_pending(
                &mut pending,
                &mut recent,
                dedup_window,
                &mut batch,
                &mut retry,
            ) {
                continue 'worker;
            }

            if batch.len() >= WRITE_BATCH_SIZE
                && !self.flush_batch_with_retry(&mut batch, &mut retry)
            {
                continue 'worker;
            }

            let mut received = None;
            match self.receive_next(rx, stop, &pending, &mut batch, &mut retry, &mut received) {
                ReceiveResult::Item => self.process_received(
                    received.expect("item result carried no pending block"),
                    &mut pending,
                    &mut recent,
                    dedup_window,
                    &mut batch,
                ),
                ReceiveResult::Timeout | ReceiveResult::Retry => {}
                ReceiveResult::Stop | ReceiveResult::Disconnected => break 'worker,
            }
        }

        if shutdown.connection_logs_failed {
            self.shed_pending_and_queued(rx, &mut pending);
            return;
        }

        // Admission is closed before the stop flag is set by the recorder.
        // Drain anything that was accepted before closure, including an item
        // that arrived after the worker's last empty `try_recv`.
        self.drain_queued(
            rx,
            &mut pending,
            &mut recent,
            &mut batch,
            &mut retry,
            &mut shutdown,
        );
        self.finish_pending_shutdown(
            pending,
            &mut recent,
            dedup_window,
            &mut batch,
            &mut shutdown,
        );
    }

    fn receive_next(
        &self,
        rx: &mpsc::Receiver<PendingBlock>,
        stop: &AtomicBool,
        pending: &VecDeque<(Instant, PendingBlock)>,
        batch: &mut DnsWriteBatch,
        retry: &mut RetryState,
        received: &mut Option<PendingBlock>,
    ) -> ReceiveResult {
        if let Ok(item) = rx.try_recv() {
            *received = Some(item);
            return ReceiveResult::Item;
        }
        if stop.load(Ordering::Acquire) {
            return ReceiveResult::Stop;
        }
        if !batch.is_empty() && !self.flush_batch_with_retry(batch, retry) {
            return ReceiveResult::Retry;
        }
        // Bound the wait so the stop flag is observed within one poll interval
        // even while the channel sender is still alive.
        let wait = pending.front().map_or(WORKER_STOP_POLL, |(ready_at, _)| {
            ready_at
                .saturating_duration_since(Instant::now())
                .min(WORKER_STOP_POLL)
        });
        match rx.recv_timeout(wait) {
            Ok(item) => {
                *received = Some(item);
                ReceiveResult::Item
            }
            Err(RecvTimeoutError::Timeout) => ReceiveResult::Timeout,
            Err(RecvTimeoutError::Disconnected) => ReceiveResult::Disconnected,
        }
    }

    fn process_received(
        &self,
        item: PendingBlock,
        pending: &mut VecDeque<(Instant, PendingBlock)>,
        recent: &mut RecentLru,
        dedup_window: Duration,
        batch: &mut DnsWriteBatch,
    ) {
        let correlation = correlate_block(&self.correlator, &item);
        if attributed_requesting_pid(correlation).is_some() {
            self.persist_item_with_correlation(&item, correlation, recent, dedup_window, batch);
        } else {
            self.enqueue_pending(item, pending, recent, dedup_window, batch);
        }
    }

    fn retry_batch(
        &self,
        batch: &mut DnsWriteBatch,
        retry: &mut RetryState,
        stop: &AtomicBool,
        shutdown: &mut ShutdownState,
    ) -> BatchRetry {
        if batch.is_empty() {
            let Some(next_attempt) = retry.at else {
                retry.attempt = 0;
                return BatchRetry::Ready;
            };
            if stop.load(Ordering::Acquire) {
                return BatchRetry::Stop;
            }
            if Instant::now() < next_attempt {
                let wait = next_attempt
                    .saturating_duration_since(Instant::now())
                    .min(WORKER_STOP_POLL);
                std::thread::sleep(wait);
                return BatchRetry::Wait;
            }
            retry.at = None;
            retry.attempt = 0;
            return BatchRetry::Ready;
        }
        let Some(next_attempt) = retry.at else {
            return BatchRetry::Ready;
        };
        if stop.load(Ordering::Acquire) {
            if shutdown.connection_logs_failed {
                self.shed_batch(batch);
                shutdown.records_shed = true;
                retry.at = None;
                retry.attempt = 0;
                BatchRetry::Ready
            } else if self.flush_batch_for_shutdown(batch, !shutdown.records_shed, shutdown) {
                retry.at = None;
                retry.attempt = 0;
                BatchRetry::Ready
            } else {
                self.salvage_shutdown_batch(batch, shutdown);
                retry.at = None;
                retry.attempt = 0;
                BatchRetry::Ready
            }
        } else if Instant::now() < next_attempt {
            // Keep the failed batch at the head of the stream. Do not receive
            // newer blocks while waiting, so the bounded channel absorbs the
            // outage and preserves event order once the database recovers.
            let wait = next_attempt
                .saturating_duration_since(Instant::now())
                .min(WORKER_STOP_POLL);
            std::thread::sleep(wait);
            BatchRetry::Wait
        } else if self.flush_batch_with_retry(batch, retry) {
            BatchRetry::Ready
        } else {
            BatchRetry::Wait
        }
    }

    fn flush_batch_with_retry(&self, batch: &mut DnsWriteBatch, retry: &mut RetryState) -> bool {
        if self.flush_batch(batch) {
            retry.at = None;
            retry.attempt = 0;
            true
        } else {
            retry.attempt = retry.attempt.saturating_add(1);
            retry.at = Some(Instant::now() + WRITE_RETRY_BACKOFF.delay(retry.attempt));
            false
        }
    }

    fn persist_ready_pending(
        &self,
        pending: &mut VecDeque<(Instant, PendingBlock)>,
        recent: &mut RecentLru,
        dedup_window: Duration,
        batch: &mut DnsWriteBatch,
        retry: &mut RetryState,
    ) -> bool {
        let now = Instant::now();
        while pending
            .front()
            .is_some_and(|(ready_at, _)| *ready_at <= now)
        {
            let (_, item) = pending.pop_front().expect("front was present");
            self.pending_reconciliations.fetch_sub(1, Ordering::Relaxed);
            self.persist_item(&item, recent, dedup_window, batch);
            if batch.len() >= WRITE_BATCH_SIZE && !self.flush_batch_with_retry(batch, retry) {
                return true;
            }
        }
        false
    }

    pub(super) fn enqueue_pending(
        &self,
        item: PendingBlock,
        pending: &mut VecDeque<(Instant, PendingBlock)>,
        recent: &mut RecentLru,
        dedup_window: Duration,
        batch: &mut DnsWriteBatch,
    ) {
        if pending.len() >= WRITE_QUEUE_CAPACITY {
            if let Some((_, oldest)) = pending.pop_front() {
                self.pending_reconciliations.fetch_sub(1, Ordering::Relaxed);
                self.note_early_reconciliation();
                self.persist_item(&oldest, recent, dedup_window, batch);
            }
        }
        pending.push_back((Instant::now() + self.reconciliation_delay, item));
        self.pending_reconciliations.fetch_add(1, Ordering::Relaxed);
    }

    /// Counts a block written before late evidence could reach it. The record
    /// is kept, so this is not shedding, but its attribution may be weaker.
    fn note_early_reconciliation(&self) {
        let early = self.early_reconciliations.fetch_add(1, Ordering::Relaxed) + 1;
        if early.is_power_of_two() {
            warn!(
                early,
                "dns block reconciliation queue full; recording blocks before late evidence arrives"
            );
        }
    }

    fn finish_pending_shutdown(
        &self,
        mut pending: VecDeque<(Instant, PendingBlock)>,
        recent: &mut RecentLru,
        dedup_window: Duration,
        batch: &mut DnsWriteBatch,
        shutdown: &mut ShutdownState,
    ) {
        while !pending.is_empty() {
            if shutdown.connection_logs_failed {
                self.shed_pending(&mut pending);
                break;
            }
            let (_, item) = pending.pop_front().expect("pending was not empty");
            self.pending_reconciliations.fetch_sub(1, Ordering::Relaxed);
            self.persist_item(&item, recent, dedup_window, batch);
            if batch.len() >= WRITE_BATCH_SIZE
                && !self.flush_batch_for_shutdown(batch, !shutdown.records_shed, shutdown)
            {
                self.salvage_shutdown_batch(batch, shutdown);
            }
        }
        if shutdown.connection_logs_failed {
            self.shed_batch(batch);
        } else if !batch.is_empty()
            && !self.flush_batch_for_shutdown(batch, !shutdown.records_shed, shutdown)
        {
            self.salvage_shutdown_batch(batch, shutdown);
        }
    }

    fn flush_batch(&self, batch: &mut DnsWriteBatch) -> bool {
        self.flush_batch_with_health_recovery(batch, true)
    }

    fn flush_batch_with_health_recovery(
        &self,
        batch: &mut DnsWriteBatch,
        recover_health: bool,
    ) -> bool {
        if batch.is_empty() {
            return true;
        }
        if !self.resolve_unresolved_apps(batch) {
            warn!(
                count = batch.len(),
                "dns block batch is waiting for application persistence"
            );
            return false;
        }
        if !self.persist_prepared_items(batch) {
            // Keep the prepared rows intact. `run` owns the bounded retry
            // schedule, and fan-out happens only after this transaction
            // commits successfully.
            self.shed.report();
            return false;
        }
        if recover_health {
            self.shed.recovered();
        }
        batch.clear();
        true
    }

    /// Application creation is part of the same bounded batch retry as the
    /// connection-log write. The prepared path/name and correlation stay in
    /// `batch`, so an outage cannot cause a recycled PID to be resolved for an
    /// older blocked query.
    fn resolve_unresolved_apps(&self, batch: &mut DnsWriteBatch) -> bool {
        let mut all_resolved = true;
        for item in batch.iter_mut().filter(|item| item.app_id <= 0) {
            let app_id = self
                .app_resolver
                .get_or_create_app_id(&item.app_path, &item.app_name);
            if app_id <= 0 {
                self.shed.report();
                all_resolved = false;
            } else {
                item.app_id = app_id;
            }
        }
        all_resolved
    }

    fn flush_batch_for_shutdown(
        &self,
        batch: &mut DnsWriteBatch,
        recover_health: bool,
        shutdown: &mut ShutdownState,
    ) -> bool {
        for attempt in 0..SHUTDOWN_WRITE_RETRY_ATTEMPTS {
            if self.flush_batch_with_health_recovery(batch, recover_health) {
                return true;
            }
            let has_unresolved_app = batch.iter().any(|item| item.app_id <= 0);
            if has_unresolved_app && shutdown.application_retry_exhausted {
                break;
            }
            if attempt + 1 < SHUTDOWN_WRITE_RETRY_ATTEMPTS {
                std::thread::sleep(WRITE_RETRY_BACKOFF.delay(attempt + 1));
            }
        }
        if batch.iter().any(|item| item.app_id <= 0) {
            shutdown.application_retry_exhausted = true;
        }
        false
    }

    fn persist_prepared_items(&self, items: &[PreparedBlock]) -> bool {
        let rows = items
            .iter()
            .map(|item| {
                (
                    item.app_id,
                    item.domain.clone(),
                    item.timestamp,
                    item.encoded_names.clone(),
                    item.app_path.clone(),
                )
            })
            .collect::<Vec<_>>();
        match self.store.insert_dns_block_logs(&rows) {
            Ok(first_sightings) => {
                for (item, first_sighting) in items.iter().zip(first_sightings) {
                    self.publish_persisted_block(item, first_sighting);
                }
                true
            }
            Err(error) => {
                warn!(%error, count = items.len(), "dns block batch persistence failed");
                false
            }
        }
    }

    fn salvage_shutdown_batch(&self, batch: &mut DnsWriteBatch, shutdown: &mut ShutdownState) {
        if batch.is_empty() {
            return;
        }

        let unresolved_count = batch.iter().filter(|item| item.app_id <= 0).count();
        if unresolved_count == 0 {
            self.shed_batch(batch);
            shutdown.records_shed = true;
            shutdown.connection_logs_failed = true;
            return;
        }

        let resolved = batch
            .iter()
            .filter(|item| item.app_id > 0)
            .cloned()
            .collect::<DnsWriteBatch>();
        if resolved.is_empty() {
            let count = batch.len();
            batch.clear();
            shutdown.records_shed = true;
            self.shed.report();
            warn!(
                count,
                "shedding dns blocks with unresolved applications on shutdown"
            );
            return;
        }

        if self.persist_prepared_items(&resolved) {
            let resolved_count = resolved.len();
            batch.clear();
            shutdown.records_shed = true;
            self.shed.report();
            warn!(
                resolved_count,
                unresolved_count,
                "shedding dns blocks with unresolved applications after persisting resolved subset"
            );
        } else {
            self.shed_batch(batch);
            shutdown.records_shed = true;
            shutdown.connection_logs_failed = true;
        }
    }

    fn shed_batch(&self, batch: &mut DnsWriteBatch) {
        if batch.is_empty() {
            return;
        }
        let count = batch.len();
        batch.clear();
        self.shed.report();
        warn!(
            count,
            "shedding unrecoverable dns block batch during shutdown"
        );
    }

    fn shed_item(&self, item: &PendingBlock) {
        self.shed.report();
        warn!(domain = %item.domain, "shedding unresolved dns block");
    }

    fn drain_queued(
        &self,
        rx: &mpsc::Receiver<PendingBlock>,
        pending: &mut VecDeque<(Instant, PendingBlock)>,
        recent: &mut RecentLru,
        batch: &mut DnsWriteBatch,
        retry: &mut RetryState,
        shutdown: &mut ShutdownState,
    ) {
        let dedup_window = dns_dedup_window();
        while let Ok(item) = rx.try_recv() {
            if retry.at.is_some() {
                self.defer_shutdown_item(item, pending, shutdown);
            } else {
                self.process_received(item, pending, recent, dedup_window, batch);
            }
        }
    }

    fn defer_shutdown_item(
        &self,
        item: PendingBlock,
        pending: &mut VecDeque<(Instant, PendingBlock)>,
        shutdown: &mut ShutdownState,
    ) {
        if pending.len() >= WRITE_QUEUE_CAPACITY {
            self.shed_item(&item);
            shutdown.records_shed = true;
            return;
        }
        pending.push_back((Instant::now(), item));
        self.pending_reconciliations.fetch_add(1, Ordering::Relaxed);
    }

    fn shed_pending_and_queued(
        &self,
        rx: &mpsc::Receiver<PendingBlock>,
        pending: &mut VecDeque<(Instant, PendingBlock)>,
    ) {
        let mut count = 0usize;
        while rx.try_recv().is_ok() {
            count = count.saturating_add(1);
        }
        for _ in pending.drain(..) {
            self.pending_reconciliations.fetch_sub(1, Ordering::Relaxed);
            count = count.saturating_add(1);
        }
        if count > 0 {
            self.shed.report();
            warn!(
                count,
                "shedding queued dns blocks after unrecoverable write failure"
            );
        }
    }

    fn shed_pending(&self, pending: &mut VecDeque<(Instant, PendingBlock)>) {
        let count = pending.len();
        for _ in pending.drain(..) {
            self.pending_reconciliations.fetch_sub(1, Ordering::Relaxed);
        }
        if count > 0 {
            self.shed.report();
            warn!(
                count,
                "shedding pending dns blocks after unrecoverable shutdown write failure"
            );
        }
    }

    fn persist_item(
        &self,
        item: &PendingBlock,
        recent: &mut RecentLru,
        dedup_window: Duration,
        batch: &mut DnsWriteBatch,
    ) {
        let correlation = correlate_block(&self.correlator, item);
        self.persist_item_with_correlation(item, correlation, recent, dedup_window, batch);
    }

    fn persist_item_with_correlation(
        &self,
        item: &PendingBlock,
        correlation: DnsCorrelationResult,
        recent: &mut RecentLru,
        dedup_window: Duration,
        batch: &mut DnsWriteBatch,
    ) {
        let key = DnsBlockKey {
            pid: attributed_owner_pid(correlation, item.ownership),
            domain: item.domain.clone(),
        };
        let mut prepared = self.prepare_dns_block(item, correlation);
        // History keeps every event: the dedup window only throttles the user
        // notification, never the persisted row, SIEM event, or sighting.
        let notify_admitted = recent.should_admit(key, Instant::now(), dedup_window);
        prepared.suppress_notification |= !notify_admitted;
        batch.push(prepared);
    }

    pub(super) fn prepare_dns_block(
        &self,
        item: &PendingBlock,
        correlation: DnsCorrelationResult,
    ) -> PreparedBlock {
        let domain = item.domain.as_str();
        let blocklist_names = &item.blocklist_names;
        let timestamp = item.timestamp;
        let ownership = item.ownership;
        let resolver_pid = correlation.resolver_pid.unwrap_or(0);
        let owner_pid = attributed_owner_pid(correlation, ownership);

        // The owner is resolved after the reconciliation delay. By then the PID
        // may belong to a process that started after the query, which must not
        // be credited with it.
        let identity =
            (owner_pid > 0).then(|| self.app_resolver.peek_identity(owner_pid, None, None, None));
        let (app_id, app_path, app_name) = if let Some(identity) =
            identity.filter(|identity| !started_after(identity.start_ts, timestamp))
        {
            let (id, path, name) = self.app_resolver.resolve_pid(
                owner_pid,
                Some(&identity.path)
                    .filter(|path| !path.is_empty())
                    .map(String::as_str),
                Some(&identity.name)
                    .filter(|name| !name.is_empty())
                    .map(String::as_str),
                Some(identity.start_ts),
            );
            if id > 0 {
                (id, path, name)
            } else if path.is_empty() || name.is_empty() {
                self.app_resolver.unknown_exited()
            } else {
                // `resolve_pid` already attempted the application write. Keep
                // its captured identity with the block and retry only this
                // app key during batch flush; resolving the PID again could
                // adopt a recycled process.
                (id, path, name)
            }
        } else if owner_pid > 0 {
            self.app_resolver.unknown_exited()
        } else {
            self.app_resolver.unknown_no_owner()
        };
        // The daemon's own lookups are persisted either way; `log_daemon_connections`
        // only decides whether they notify the user. Suppressing the row itself let a
        // process that adopted the daemon's file name erase its blocked-DNS history.
        let suppress_notification = !self.settings.log_daemon_connections.load(Ordering::Relaxed)
            && is_daemon_executable(self.daemon_path.as_deref(), &app_path);

        // A resolver description only adds information when the record's owner
        // is a different process; the fallback owner *is* the resolver. It is only
        // a label, so it is peeked rather than registered as an application, and a
        // process that started after the query is not named, as for the owner.
        let resolver_desc = (resolver_pid > 0 && resolver_pid != owner_pid)
            .then(|| {
                self.app_resolver
                    .peek_identity(resolver_pid, None, None, None)
            })
            .filter(|identity| !started_after(identity.start_ts, timestamp))
            .map(|identity| identity.name)
            .filter(|name| {
                !name.is_empty()
                    && !name.eq_ignore_ascii_case(crate::process_resolver::UNKNOWN_APP_NAME)
            });

        let now = timestamp;
        let encoded_names = antiwire_store::encode_blocklist_names(blocklist_names);
        PreparedBlock {
            app_id,
            app_path,
            app_name,
            domain: domain.to_owned(),
            blocklist_names: blocklist_names.clone(),
            encoded_names,
            timestamp: now,
            correlation,
            attributed: owner_pid > 0,
            resolver_desc,
            suppress_notification,
        }
    }

    fn publish_persisted_block(&self, item: &PreparedBlock, first_sighting: bool) {
        self.publish_block_notification(
            &item.domain,
            &item.blocklist_names,
            item.attributed,
            item.correlation,
            &item.app_name,
            item.resolver_desc.as_deref(),
            item.suppress_notification,
            item.timestamp,
        );

        let log = antiwire_store::NewConnectionLog {
            is_close: true,
            replace_domain: false,
            conn_pid: 0,
            conn_id: 0,
            timestamp: item.timestamp,
            app_id: item.app_id,
            app_path: item.app_path.clone(),
            protocol: "DNS".to_owned(),
            src_ip: String::new(),
            src_port: 0,
            dst_ip: String::new(),
            dst_port: 0,
            dst_domain: item.domain.clone(),
            bytes_sent: 0,
            bytes_received: 0,
            action_taken: "BLOCKED".to_owned(),
            last_seen: item.timestamp,
            country_code: String::new(),
            isp: String::new(),
            blocklist_names: item.encoded_names.clone(),
        };
        self.siem
            .queue_connection_event(&log, &item.app_name, &item.app_path);
        if first_sighting {
            self.siem
                .queue_new_domain_event(&item.domain, &item.app_name, &item.app_path);
        }
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "notification composition needs the block's identity, attribution, and settings"
    )]
    fn publish_block_notification(
        &self,
        domain: &str,
        blocklist_names: &[String],
        attributed: bool,
        correlation: DnsCorrelationResult,
        app_name: &str,
        resolver_desc: Option<&str>,
        suppress_notification: bool,
        now: OffsetDateTime,
    ) {
        if !self.settings.notify_threat_detected.load(Ordering::Relaxed) || suppress_notification {
            return;
        }

        let caller = if attributed {
            format!("'{app_name}'")
        } else {
            match correlation.status {
                DnsAttributionStatus::Ambiguous => "an ambiguous caller".to_owned(),
                DnsAttributionStatus::Correlated | DnsAttributionStatus::Inferred => {
                    format!("'{app_name}'")
                }
                DnsAttributionStatus::Unattributed => "an unknown application".to_owned(),
            }
        };
        let message = match (blocklist_names.is_empty(), resolver_desc) {
            (true, Some(res)) => {
                format!("Blocked DNS request to '{domain}' from {caller} (via {res}).")
            }
            (false, Some(res)) => format!(
                "Blocked DNS request to '{domain}' from {caller} (via {res}) ({lists}).",
                lists = blocklist_names.join(", ")
            ),
            (true, None) => format!("Blocked DNS request to '{domain}' from {caller}."),
            (false, None) => format!(
                "Blocked DNS request to '{domain}' from {caller} ({lists}).",
                lists = blocklist_names.join(", ")
            ),
        };
        self.alerts.publish(
            Alert::new(
                AlertKind::MaliciousFlow,
                Severity::Critical,
                "Blocked DNS Request",
                message,
            )
            .at(unix_secs(now)),
        );
    }
}
