//! Batched connection-log persistence: pending queues, flush passes, and attribution writes.

use super::attribution::SocketTables;
use super::attribution::{needs_socket_attribution, should_retry_socket_lookup};
use super::FlowTracker;
use super::{ActiveFlow, AttributionVersion};
use crate::store::FlowStore;
use crate::Result;
use antiwire_store::{ConnectionLogAttribution, NewConnectionLog};
use antiwire_tuning::{FLOW_FLUSH_FAILURES_BEFORE_DEGRADED, UNKNOWN_SOCKET_ATTRIBUTION_DELAY};
use netmetrics_core::{FlowKey, Protocol};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Instant;
use time::OffsetDateTime;

impl<S: FlowStore> FlowTracker<S> {
    /// Flushes queued re-attributions and closed connection logs.
    ///
    /// Returns `true` when at least one half actually contacted the store, so callers
    /// can distinguish "nothing to do" from a real recovery. Both halves are attempted
    /// even when the first fails, so one re-attribution the store keeps rejecting cannot
    /// starve connection-log writes behind it.
    ///
    /// # Errors
    ///
    /// Returns the store failure when the connection-log or re-attribution write is
    /// rejected. The affected records stay queued for the next attempt.
    pub fn flush(&self) -> Result<bool> {
        let _persist = self.persistence_gate.lock();
        let attributions = self.flush_attributions();
        let logs = self.flush_pending_logs();
        match (attributions, logs) {
            (Ok(a), Ok(b)) => Ok(a || b),
            (Err(error), _) | (_, Err(error)) => Err(error),
        }
    }

    fn flush_pending_logs(&self) -> Result<bool> {
        let batch = std::mem::take(&mut *self.pending.lock());
        if batch.is_empty() {
            return Ok(false);
        }
        // A chunk is one transaction, so a single row the store always rejects
        // fails every retry of the chunk it sits in, and everything queued behind
        // it waits forever. Once failures have lasted long enough to report an
        // outage, a failed chunk is retried a row at a time to find that row.
        let isolate = self.queue_flush_failures.load(Ordering::Relaxed) + 1
            >= FLOW_FLUSH_FAILURES_BEFORE_DEGRADED;
        let mut remaining = batch.into_iter();
        loop {
            let chunk: Vec<_> = remaining.by_ref().take(128).collect();
            if chunk.is_empty() {
                return Ok(true);
            }
            let failed = match self.store.insert_batch(&chunk) {
                Ok(()) => None,
                Err(_) if isolate => self.insert_rows_isolating(chunk).err(),
                Err(error) => Some((chunk, error)),
            };
            if let Some((unwritten, error)) = failed {
                // Only failed/unattempted rows return to the front. Written rows
                // must not be replayed because their byte writes are additive.
                let mut requeued = unwritten;
                requeued.extend(remaining);
                let mut pending = self.pending.lock();
                requeued.append(&mut pending);
                *pending = requeued;
                return Err(error);
            }
            std::thread::yield_now();
        }
    }

    /// Writes `rows` one transaction each, in order.
    ///
    /// A rejected row is dropped once the row after it is accepted, since the
    /// store is evidently writable. Two rejections in a row read as an outage
    /// rather than bad rows, so the rest is handed back unwritten.
    fn insert_rows_isolating(
        &self,
        mut rows: Vec<NewConnectionLog>,
    ) -> std::result::Result<(), (Vec<NewConnectionLog>, crate::FlowError)> {
        let mut rejected: Option<(usize, crate::FlowError)> = None;
        for index in 0..rows.len() {
            match self.store.insert_batch(std::slice::from_ref(&rows[index])) {
                Ok(()) => {
                    if let Some((bad, error)) = rejected.take() {
                        tracing::warn!(
                            error = %error,
                            conn_id = rows[bad].conn_id,
                            "dropping a connection log the store keeps rejecting"
                        );
                    }
                }
                Err(error) => {
                    if let Some((bad, _)) = rejected {
                        return Err((rows.split_off(bad), error));
                    }
                    rejected = Some((index, error));
                }
            }
        }
        match rejected {
            Some((bad, error)) => Err((rows.split_off(bad), error)),
            None => Ok(()),
        }
    }

    /// Whether both write paths last succeeded, gating the opportunistic flush paths.
    pub(super) fn store_is_healthy(&self) -> bool {
        self.queue_flush_failures.load(Ordering::Relaxed) == 0
            && self.active_flush_failures.load(Ordering::Relaxed) == 0
    }

    /// Records a flush outcome and keeps the tracker running across failures.
    ///
    /// Returning the error from [`Self::run`] used to end the event loop for good:
    /// the task logged one line and exited, and from then on every connection went
    /// unrecorded while the UI showed zeros with nothing to explain them. Flush
    /// failures are usually transient — a busy database, a momentarily full disk —
    /// and the batch is retained for the next attempt, so the loop keeps going and
    /// reports a sustained outage instead of dying on the first one.
    ///
    /// `Ok(false)` means the flush had nothing to persist and never touched the store.
    /// That must not be read as recovery: a tick with an empty backlog would otherwise
    /// clear an outage that a still-pending `flush()` keeps re-reporting, making the
    /// health signal flap while records are being shed.
    ///
    /// This counts the queued-write flush; [`Self::note_active_flush_outcome`] counts
    /// the active-flow flush. Each path clears only its own streak, and recovery is
    /// reported once neither is failing, so a successful active-flow write cannot
    /// keep resetting an outage the queued writes are still in.
    pub(super) fn note_flush_outcome(&self, phase: &'static str, result: Result<bool>) {
        self.note_streak_outcome(&self.queue_flush_failures, phase, result);
    }

    /// Records an active-flow flush outcome; see [`Self::note_flush_outcome`].
    pub(super) fn note_active_flush_outcome(&self, result: Result<bool>) {
        self.note_streak_outcome(&self.active_flush_failures, "active-flows", result);
    }

    fn note_streak_outcome(&self, streak: &AtomicU32, phase: &'static str, result: Result<bool>) {
        match result {
            Ok(false) => {}
            Ok(true) => {
                if streak.swap(0, Ordering::Relaxed) > 0 && self.store_is_healthy() {
                    tracing::info!(phase, "flow store writes recovered");
                    self.report_store_recovered();
                }
            }
            Err(error) => {
                let failures = streak.fetch_add(1, Ordering::Relaxed) + 1;
                tracing::warn!(
                    phase,
                    failures,
                    error = %error,
                    "flow store flush failed; retrying on the next tick"
                );

                // Reporting is idempotent, and a tick can charge more than one failure,
                // so this is a threshold rather than an equality check.
                if failures >= FLOW_FLUSH_FAILURES_BEFORE_DEGRADED {
                    self.report_store_unavailable(
                        "Traffic could not be written to the local database. Connection history \
                         and sent/received totals will stay incomplete until the daemon can write \
                         again.",
                    );
                }
            }
        }
    }

    /// Queues a finished connection log, shedding it when the backlog is at its cap.
    pub(super) fn push_pending_log(&self, log: NewConnectionLog) {
        let mut pending = self.pending.lock();
        if pending.len() < self.pending_cap {
            pending.push(log);
            return;
        }
        drop(pending);
        self.note_shed_record("connection log");
    }

    fn note_shed_record(&self, kind: &'static str) {
        let shed = self.shed_records.fetch_add(1, Ordering::Relaxed) + 1;
        if shed.is_power_of_two() {
            tracing::warn!(
                shed,
                kind,
                "flow write backlog is at capacity; shedding records until the store recovers"
            );
        }
    }

    /// Persists byte deltas for still-active flows on the periodic flush.
    ///
    /// Returns `true` when the store was actually contacted. A re-attribution rejection
    /// is reported but does not abort the byte persistence behind it: the two halves are
    /// independent, and a single permanently-rejected attribution must not freeze every
    /// active flow's byte totals. The attribution stays queued for the next attempt.
    ///
    /// # Errors
    ///
    /// Returns the store failure when a re-attribution or byte-delta write is rejected.
    /// A rejected re-attribution is returned only after the byte persistence behind it
    /// has been attempted.
    pub fn flush_active_flows(&self) -> Result<bool> {
        self.persist_active_flows(true)
    }

    /// Persists every active flow's byte deltas once more at shutdown.
    ///
    /// Unlike the periodic flush, an unattributed flow still inside its socket-lookup
    /// window is written as it stands: there is no later tick to wait for, so deferring
    /// it would lose its bytes.
    ///
    /// # Errors
    ///
    /// As [`Self::flush_active_flows`].
    pub(super) fn flush_active_flows_final(&self) -> Result<bool> {
        self.persist_active_flows(false)
    }

    #[expect(
        clippy::too_many_lines,
        reason = "attribution, enrichment, and validated byte checkpoints share one persistence pass"
    )]
    fn persist_active_flows(&self, defer_unknown: bool) -> Result<bool> {
        let _persist = self.persistence_gate.lock();
        let keys: Vec<_> = self.active.lock().keys().copied().collect();
        for key in &keys {
            self.refresh_active_attribution(key, false, None);
        }

        let needs_snapshot = self.active.lock().values().any(should_retry_socket_lookup);
        if needs_snapshot {
            let tables = SocketTables::since(Instant::now());
            for key in &keys {
                self.refresh_active_attribution(key, false, Some(&tables));
            }
        }

        let attributions: Vec<(FlowKey, ConnectionLogAttribution)> = self
            .active
            .lock()
            .iter()
            .filter_map(|(key, flow)| {
                attribution_update(flow).map(|attribution| (*key, attribution))
            })
            .collect();
        let mut reattribute_error: Option<crate::FlowError> = None;
        let mut touched_store = false;
        for (key, attribution) in attributions {
            match self.store.reattribute(&attribution) {
                Ok(()) => {
                    touched_store = true;
                    if let Some(flow) = self.active.lock().get_mut(&key) {
                        if conn_id_to_i64(flow.conn_id) == attribution.conn_id
                            && pid_to_i32(flow.open_pid) == attribution.conn_pid
                            && flow.opened_at == attribution.conn_start
                            && flow.persisted_app_id == attribution.from_app_id
                            && flow.app_id == attribution.to_app_id
                        {
                            flow.persisted_app_id = attribution.to_app_id;
                        }
                    }
                }
                Err(error) => {
                    reattribute_error.get_or_insert(error);
                }
            }
        }

        // A connection whose address DNS evidence has just arrived for may
        // now be named, or named better. Nothing else prompts another lookup.
        // Closed connections are looked up here and now; open ones as their
        // rows are written, below.
        if let Some(processor) = &self.processor {
            let named = processor.take_newly_named();
            processor.settle_closed_names(&named);
            if !named.is_empty() {
                let now_ms = netmetrics_core::unix_now_ms();
                for (key, flow) in self.active.lock().iter_mut() {
                    if named.names(key.remote_addr) {
                        flow.name_lookup.note_evidence(now_ms);
                    }
                }
            }
        }

        let pending: Vec<(FlowKey, u64, u64, ActiveFlow)> = {
            let active = self.active.lock();
            active
                .iter()
                .filter_map(|(key, flow)| {
                    let delta_sent = flow.bytes_sent.saturating_sub(flow.persisted_sent);
                    let delta_received =
                        flow.bytes_received.saturating_sub(flow.persisted_received);
                    // Decide before cloning and enriching. The previous shape cloned
                    // every active flow and ran the full enrich pipeline only to hit
                    // the skip check below, which discarded most of the work.
                    if !flow_may_need_active_persist(flow, delta_sent, delta_received) {
                        return None;
                    }
                    Some((*key, delta_sent, delta_received, flow.clone()))
                })
                .collect()
        };

        let mut batch = Vec::new();
        let mut flushed = Vec::new();
        for (key, delta_sent, delta_received, flow) in pending {
            if defer_unknown && should_defer_unknown_persist(&flow) {
                continue;
            }
            let mut log = Self::build_connection_log(&flow);
            let request = flow
                .name_lookup
                .request(flow.pid, flow.app_id, opening(&flow));
            // What a lookup made on this pass said of its answer, if one was made.
            let looked_up = self.processor.as_ref().and_then(|processor| {
                processor.enrich_connection_log(
                    &key,
                    flow.pid,
                    &flow.app_path,
                    &flow.app_name,
                    request,
                    &mut log,
                )
            });
            // Enrichment leaves the log with the name the row should have,
            // and marks it where the store would not take that name unasked.
            let accepted_domain = log.dst_domain.clone();
            let domain_changed = accepted_domain != flow.persisted_domain;
            if let Some(live) = self
                .active
                .lock()
                .get_mut(&key)
                .filter(|live| live.conn_id == flow.conn_id)
            {
                // A name that changed is settled once its row is written, below.
                if let Some(naming) = looked_up.filter(|_| !domain_changed) {
                    live.name_lookup.made(flow.pid, flow.app_id, naming);
                }
            }
            if delta_sent == 0 && delta_received == 0 && flow.db_row_created && !domain_changed {
                continue;
            }
            flushed.push((
                key,
                flow.bytes_sent,
                flow.bytes_received,
                log.app_id,
                accepted_domain,
                AttributionVersion::capture(&flow),
                looked_up,
            ));
            // Enrichment uses lifetime totals to distinguish transferred traffic
            // from a blocked attempt. The additive store receives only new bytes.
            log.bytes_sent = i64::try_from(delta_sent).unwrap_or(i64::MAX);
            log.bytes_received = i64::try_from(delta_received).unwrap_or(i64::MAX);
            batch.push(log);
        }

        let mut planned = batch.into_iter().zip(flushed);
        loop {
            let chunk: Vec<_> = planned.by_ref().take(128).collect();
            if chunk.is_empty() {
                break;
            }
            // Resolve and enrich off the lifecycle gate, then validate the session
            // before writing. Only this bounded transaction excludes open/close.
            let gate = self.flush_gate.lock();
            let mut logs = Vec::with_capacity(chunk.len());
            let mut checkpoints = Vec::with_capacity(chunk.len());
            {
                let active = self.active.lock();
                for (log, checkpoint) in chunk {
                    if active
                        .get(&checkpoint.0)
                        .is_some_and(|flow| checkpoint.5.matches(flow))
                    {
                        logs.push(log);
                        checkpoints.push(checkpoint);
                    }
                }
            }
            if !logs.is_empty() {
                self.store.insert_batch(&logs)?;
                touched_store = true;
                let mut active = self.active.lock();
                for (key, sent, received, app_id, domain, version, looked_up) in checkpoints {
                    if let Some(flow) = active
                        .get_mut(&key)
                        .filter(|flow| flow.conn_id == version.conn_id)
                    {
                        if let Some(naming) = looked_up {
                            flow.name_lookup.made(version.pid, version.app_id, naming);
                        }
                        flow.persisted_sent = sent;
                        flow.persisted_received = received;
                        flow.db_row_created = true;
                        flow.persisted_app_id = app_id;
                        flow.persisted_domain = domain;
                    }
                }
            }
            drop(gate);
            std::thread::yield_now();
        }

        match reattribute_error {
            Some(error) => Err(error),
            None => Ok(touched_store),
        }
    }

    pub(super) fn queue_log(&self, key: FlowKey, flow: &ActiveFlow, closing: bool) {
        if let Some(attribution) = attribution_update(flow) {
            self.queue_attribution(attribution);
        }
        let delta_sent = flow.bytes_sent.saturating_sub(flow.persisted_sent);
        let delta_received = flow.bytes_received.saturating_sub(flow.persisted_received);
        let mut log = Self::build_connection_log(flow);
        log.is_close = closing;

        if let Some(processor) = &self.processor {
            // The last log for the row: look once more unless the name is final.
            let request = flow.name_lookup.closing_request(
                flow.pid,
                flow.app_id,
                opening(flow),
                netmetrics_core::unix_now_ms(),
            );
            let naming = processor.enrich_connection_log(
                &key,
                flow.pid,
                &flow.app_path,
                &flow.app_name,
                request,
                &mut log,
            );
            processor.publish_closed_flow(&flow.app_path, &flow.app_name, &log);
            if closing {
                processor.await_final_name(
                    flow.pid,
                    key.remote_addr,
                    &flow.app_name,
                    opening(flow),
                    naming,
                    &log,
                );
            }
        }

        let domain_changed = log.dst_domain != flow.persisted_domain;
        // A close always queues: a fully flushed connection still has to record
        // its end, even when the final delta is empty.
        if delta_sent == 0
            && delta_received == 0
            && flow.db_row_created
            && !domain_changed
            && !closing
        {
            return;
        }

        log.bytes_sent = i64::try_from(delta_sent).unwrap_or(i64::MAX);
        log.bytes_received = i64::try_from(delta_received).unwrap_or(i64::MAX);
        self.push_pending_log(log);
    }

    pub(super) fn queue_attribution(&self, attribution: ConnectionLogAttribution) -> bool {
        let mut pending = self.pending_attributions.lock();
        if pending.contains(&attribution) {
            return true;
        }
        if pending.len() >= self.attribution_cap {
            drop(pending);
            self.note_shed_record("re-attribution");
            return false;
        }
        pending.push(attribution);
        true
    }

    /// Drains queued re-attributions, bounding one pass by the entries present at its
    /// start so a producer that keeps enqueueing cannot extend the loop indefinitely.
    /// Anything queued during the pass waits for the next flush.
    ///
    /// Once failures have lasted long enough to report an outage, a rejected entry
    /// is skipped and the next one tried, as connection logs are: if that one is
    /// accepted, the rejected entry is dropped instead of blocking the queue.
    fn flush_attributions(&self) -> Result<bool> {
        let isolate = self.queue_flush_failures.load(Ordering::Relaxed) + 1
            >= FLOW_FLUSH_FAILURES_BEFORE_DEGRADED;
        let mut flushed = false;
        let mut rejected: Option<(ConnectionLogAttribution, crate::FlowError)> = None;
        let limit = self.pending_attributions.lock().len();
        for _ in 0..limit {
            let index = usize::from(rejected.is_some());
            let Some(attribution) = self.pending_attributions.lock().get(index).cloned() else {
                break;
            };
            match self.store.reattribute(&attribution) {
                Ok(()) => {
                    flushed = true;
                    self.remove_pending_attribution(&attribution);
                    if let Some((bad, error)) = rejected.take() {
                        tracing::warn!(
                            error = %error,
                            conn_id = bad.conn_id,
                            "dropping a re-attribution the store keeps rejecting"
                        );
                        self.remove_pending_attribution(&bad);
                    }
                }
                Err(error) if isolate && rejected.is_none() => {
                    rejected = Some((attribution, error));
                }
                Err(error) => return Err(error),
            }
        }
        match rejected {
            Some((_, error)) => Err(error),
            None => Ok(flushed),
        }
    }

    fn remove_pending_attribution(&self, attribution: &ConnectionLogAttribution) {
        let mut pending = self.pending_attributions.lock();
        if pending.first() == Some(attribution) {
            pending.remove(0);
        } else if let Some(index) = pending.iter().position(|item| item == attribution) {
            pending.remove(index);
        }
    }

    pub(super) fn evict_idle(&self) {
        // Removal snapshots the final persisted baseline under the lifecycle gate;
        // native liveness checks and finalization run outside it.
        let cutoff = OffsetDateTime::now_utc() - self.idle_timeout;
        let stale_keys: Vec<FlowKey> = self
            .active
            .lock()
            .iter()
            .filter_map(|(key, flow)| (flow.last_seen < cutoff).then_some(*key))
            .collect();

        // Read on first use: TCP for the liveness check, either protocol for a
        // flow that still needs an owner when it is finalized.
        let tables = SocketTables::since(Instant::now());
        for key in stale_keys {
            if key.protocol == Protocol::Tcp
                && self
                    .socket_table(&tables, Protocol::Tcp)
                    .contains_established_tcp(&key)
            {
                continue;
            }
            // In edition 2021 an if-let temporary would retain this guard
            // throughout native close-time resolution in the body.
            let removed = {
                let _flush = self.flush_gate.lock();
                let mut active = self.active.lock();
                let removed = if active.get(&key).is_some_and(|flow| flow.last_seen < cutoff) {
                    active.remove(&key)
                } else {
                    None
                };
                drop(active);
                if removed.is_some() {
                    self.port_pid_cache.lock().forget(&key);
                }
                removed
            };
            if let Some(flow) = removed {
                self.finalize_and_queue_log(key, flow, Some(&tables));
            }
        }
    }

    /// Builds a lifetime-total log for enrichment and close publication.
    /// Convert bytes to persistence deltas only after those steps.
    pub(super) fn build_connection_log(flow: &ActiveFlow) -> NewConnectionLog {
        NewConnectionLog {
            timestamp: flow.opened_at,
            app_id: flow.app_id,
            app_path: flow.app_path.clone(),
            protocol: flow.protocol.clone(),
            src_ip: flow.src_ip.clone(),
            src_port: flow.src_port,
            dst_ip: flow.dst_ip.clone(),
            dst_port: flow.dst_port,
            // Seed the stored value, which enrichment weighs a newly judged
            // name against.
            dst_domain: flow.persisted_domain.clone(),
            bytes_sent: i64::try_from(flow.bytes_sent).unwrap_or(i64::MAX),
            bytes_received: i64::try_from(flow.bytes_received).unwrap_or(i64::MAX),
            action_taken: "ALLOWED".to_owned(),
            last_seen: flow.last_seen,
            country_code: String::new(),
            isp: String::new(),
            blocklist_names: String::new(),
            conn_id: conn_id_to_i64(flow.conn_id),
            conn_pid: pid_to_i32(flow.open_pid),
            // Set by `queue_log` when this flush finalizes a closed flow.
            is_close: false,
            replace_domain: false,
        }
    }
}

fn attribution_update(flow: &ActiveFlow) -> Option<ConnectionLogAttribution> {
    (flow.db_row_created
        && flow.persisted_app_id != flow.app_id
        && flow.persisted_app_id > 0
        && flow.app_id > 0)
        .then(|| ConnectionLogAttribution {
            from_app_id: flow.persisted_app_id,
            to_app_id: flow.app_id,
            protocol: flow.protocol.clone(),
            src_ip: flow.src_ip.clone(),
            dst_ip: flow.dst_ip.clone(),
            dst_port: flow.dst_port,
            conn_id: conn_id_to_i64(flow.conn_id),
            conn_pid: pid_to_i32(flow.open_pid),
            conn_start: flow.opened_at,
        })
}

/// Maps a tracker session id onto the store's `conn_id` column.
///
/// The store reserves 0 for legacy/unattributed rows that must never match,
/// and session ids start at one, so the mapping is exact in practice.
pub(super) fn conn_id_to_i64(conn_id: u64) -> i64 {
    i64::try_from(conn_id).unwrap_or(i64::MAX)
}

/// Maps a pid onto the store's `conn_pid` identity component.
pub(super) fn pid_to_i32(pid: u32) -> i32 {
    i32::try_from(pid).unwrap_or(0)
}

/// Whether an active flow can still produce a writable row change.
///
/// Any real update requires new bytes, a row that does not exist yet, or a
/// name that a lookup could now judge differently. Enrichment on a zero-delta
/// tick is otherwise discarded by the post-enrich skip.
fn flow_may_need_active_persist(flow: &ActiveFlow, delta_sent: u64, delta_received: u64) -> bool {
    delta_sent > 0
        || delta_received > 0
        || !flow.db_row_created
        || flow.name_lookup.due(flow.pid, flow.app_id)
}

pub(super) fn should_defer_unknown_persist(flow: &ActiveFlow) -> bool {
    needs_socket_attribution(flow)
        && flow
            .unknown_since
            .is_some_and(|since| since.elapsed() < UNKNOWN_SOCKET_ATTRIBUTION_DELAY)
}

pub(super) fn protocol_label(protocol: Protocol) -> &'static str {
    match protocol {
        Protocol::Tcp => "TCP",
        Protocol::Udp => "UDP",
    }
}

/// When `flow` opened and its process started, for judging the DNS hints that
/// name it. The open event's own time is used when it carried one; the
/// tracker first saw the flow a little later than that.
fn opening(flow: &ActiveFlow) -> crate::processor::Opening {
    let at_ms = if flow.open_ts > 0 {
        flow.open_ts
    } else {
        u64::try_from(flow.opened_at.unix_timestamp_nanos() / 1_000_000).unwrap_or(0)
    };
    crate::processor::Opening {
        at_ms,
        process_started_ms: flow.process_start_ts.unwrap_or(0),
    }
}
