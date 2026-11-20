//! Flow lifecycle: event intake, the receive loop, open/byte/close handling, and the supervised task.

use super::attribution::SocketTables;
use super::attribution::{
    application_identity, attributable_process_start_ts, closed_owner_kind,
    identity_upgrade_acceptable, is_unknown_attribution, needs_socket_attribution,
    should_upgrade_cookie, touch_unknown_state,
};
use super::persistence::protocol_label;
use super::FlowTracker;
use super::{ActiveFlow, AttributionLookup, NameLookup, CLOSED_APP_BYTES_CAP, RECEIVE_BATCH_LIMIT};
use crate::app_resolver::ResolvedApplication;
use crate::process_resolver;
use crate::processor::FlowProcessor;
use crate::store::FlowStore;
use crate::system_services;
use crate::Result;
use antiwire_events::CollectorHealth;
use antiwire_tuning::{FLOW_ACTIVE_FLOWS_HARD_CAP, FLOW_FLUSH_INTERVAL, FLOW_MAINTENANCE_INTERVAL};
use futures_util::FutureExt;
use netmetrics_core::{ByteDelta, FlowEvent, FlowKey, FlowMeta, SocketCookie};
use std::panic::AssertUnwindSafe;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Instant;
use time::OffsetDateTime;
use tokio::sync::mpsc;
use tokio::time::{self as tokio_time, Instant as TokioInstant};
use tokio_util::sync::CancellationToken;

impl<S: FlowStore> FlowTracker<S> {
    pub fn handle_event(&self, event: &FlowEvent) {
        match event {
            FlowEvent::Opened(key, meta) => self.on_opened(*key, meta),
            FlowEvent::Bytes(key, delta) => self.on_bytes(*key, *delta),
            FlowEvent::Finishing(key) => self.on_finishing(*key),
            FlowEvent::Closed(key, meta) => self.on_closed(*key, meta),
            FlowEvent::ProcessStarted(info) => {
                self.refresh_active_flows_for_pid(info.pid, info.identity.start_ts);
                self.recover_closed_identities(info);
                self.recover_closed_unstarted(info.pid);
            }
            // A stop completes what is known of a process that exited before
            // its connections were looked at: its start and stop now bracket them.
            FlowEvent::ProcessStopped { pid, .. } => self.recover_closed_unstarted(*pid),
            FlowEvent::Degraded { reason } => self.on_degraded(reason),
            FlowEvent::Restored { source } => self.on_restored(source),
            _ => {}
        }
    }

    /// Drives the tracker until the event channel closes, flushing on a coalescing
    /// deadline, a periodic timer, and a maintenance tick.
    ///
    /// Store writes and OS socket-table enumeration are dispatched to the blocking pool,
    /// so a slow `SQLite` transaction cannot park an async runtime worker.
    ///
    /// Flush failures are reported through collector health and retried rather than
    /// ending the loop. Only the final flush after the channel closes is returned.
    ///
    /// # Errors
    ///
    /// Returns the store failure from the final drain. The event loop itself keeps
    /// running across transient failures until the sender is dropped.
    ///
    /// # Panics
    ///
    /// Panics if the final drain panics. Earlier work that panics is logged and
    /// skipped, but the final drain has no later pass to recover in.
    pub async fn run(self: &Arc<Self>, mut rx: mpsc::Receiver<FlowEvent>) -> Result<()>
    where
        S: 'static,
    {
        let mut flush_deadline = TokioInstant::now() + self.coalesce;
        let mut maintenance = tokio_time::interval(FLOW_MAINTENANCE_INTERVAL);
        maintenance.set_missed_tick_behavior(tokio_time::MissedTickBehavior::Skip);
        let mut db_flush = tokio_time::interval(FLOW_FLUSH_INTERVAL);
        db_flush.set_missed_tick_behavior(tokio_time::MissedTickBehavior::Skip);
        // Drain a bounded batch per wake-up. This amortizes Tokio channel and select!
        // overhead during bursts while retaining a hard upper bound so flush and
        // maintenance deadlines remain responsive under sustained ingress.
        let mut events = Vec::with_capacity(RECEIVE_BATCH_LIMIT);

        loop {
            self.progress.fetch_add(1, Ordering::Relaxed);
            tokio::select! {
                event_count = rx.recv_many(&mut events, RECEIVE_BATCH_LIMIT) => {
                    if event_count == 0 {
                        break;
                    }
                    // Event handling resolves processes, walks the OS socket table, and
                    // writes application sightings; running the batch on the blocking
                    // pool keeps all of that off the async worker.
                    let batch = std::mem::take(&mut events);
                    let handled = self
                        .offload_blocking(move |tracker| {
                            let mut batch = batch;
                            for event in batch.drain(..) {
                                if let Some(processor) = &tracker.processor {
                                    processor.handle_event(&event);
                                }
                                tracker.handle_event(&event);
                            }
                            batch
                        })
                        .await;
                    events = handled.unwrap_or_else(|| Vec::with_capacity(RECEIVE_BATCH_LIMIT));
                    if self.pending.lock().len() >= self.batch_size
                        && self.store_is_healthy()
                    {
                        if let Some(flushed) = self.offload_blocking(FlowTracker::flush).await {
                            self.note_flush_outcome("batch", flushed);
                        }
                        flush_deadline = TokioInstant::now() + self.coalesce;
                    }
                }
                () = tokio_time::sleep_until(flush_deadline) => {
                    if self.store_is_healthy() {
                        if let Some(flushed) = self.offload_blocking(FlowTracker::flush).await {
                            self.note_flush_outcome("coalesce", flushed);
                        }
                    }
                    flush_deadline = TokioInstant::now() + self.coalesce;
                }
                _ = db_flush.tick() => {
                    self.offload_blocking(|tracker| {
                        // Coalesced DNS answers ride the same tick, keeping their
                        // SQLite transaction off the per-event path.
                        if let Some(processor) = &tracker.processor {
                            processor.flush_dns_cache();
                        }
                        tracker.note_active_flush_outcome(tracker.flush_active_flows());
                        // The opportunistic paths above stand down while the store is
                        // failing — a backlog stuck above the batch threshold would
                        // otherwise re-clone and re-submit itself on every single event.
                        // This slower tick is the retry.
                        if !tracker.store_is_healthy() {
                            tracker.note_flush_outcome("retry", tracker.flush());
                        }
                    })
                    .await;
                }
                _ = maintenance.tick() => {
                    self.offload_blocking(FlowTracker::evict_idle).await;
                    self.log_identity_telemetry();
                }
            }
        }

        // The final flush does surface its error: the loop is over, so there is no
        // later retry and the caller is entitled to know the last window was lost.
        // Both halves run regardless, so a failure in one cannot skip the other.
        self.offload_blocking(|tracker| {
            if let Some(processor) = &tracker.processor {
                processor.flush_dns_cache();
            }
            let active = tracker.flush_active_flows_final();
            let pending = tracker.flush();
            // A closed connection's later name waits for its row, which the
            // flush above may just have written.
            if let Some(processor) = &tracker.processor {
                processor.write_name_upgrades();
            }
            active.and(pending).map(|_| ())
        })
        .await
        .expect("final flow tracker flush panicked")
    }

    #[expect(
        clippy::too_many_lines,
        reason = "supersede, cap-evict, adopt, and insert must stay in one place to keep their ordering auditable"
    )]
    pub(super) fn on_opened(&self, key: FlowKey, meta: &FlowMeta) {
        let observed = Instant::now();
        // Native resolution runs before taking the lifecycle gate. Creation and
        // supersession then exclude only active-flow transaction checkpoints, so
        // a replacement cannot inherit persisted bytes from its previous session.
        let resolved_key = self.resolve_active_key(key);
        let now = OffsetDateTime::now_utc();
        let ResolvedApplication {
            app_id,
            app_path,
            app_name,
            start_ts,
        } = self
            .processor
            .as_ref()
            .map(|processor| processor.resolve_flow_app(&resolved_key, meta))
            .unwrap_or(ResolvedApplication {
                app_id: i32::try_from(meta.pid).unwrap_or(0),
                app_path: String::new(),
                app_name: String::new(),
                start_ts: 0,
            });
        let resolved_start_ts = (meta.pid > 0 && start_ts > 0).then_some(start_ts);
        let incoming_start_ts = attributable_process_start_ts(meta).or(resolved_start_ts);
        let (app_id, app_path, app_name) = self.normalize_unattributed(app_id, app_path, app_name);
        let lifecycle = self.flush_gate.lock();
        let mut retired = Vec::new();

        // A contradicting cookie proves the tuple was recycled onto a different socket. Close
        // the previous flow first so the two never share byte totals or attribution.
        if let Some(superseded) = self.take_superseded_flow(&resolved_key, meta.cookie) {
            retired.push((resolved_key, superseded));
            self.port_pid_cache.lock().forget(&resolved_key);
        }

        let mut adopted_pid = false;
        {
            let mut active = self.active.lock();
            if let Some(flow) = active.get_mut(&resolved_key) {
                // A known non-zero PID is sticky: a later open carrying a different PID is a
                // different socket reusing the tuple, not a correction. Mirrors `FlowTable`.
                if meta.pid > 0 && flow.pid == 0 {
                    flow.pid = meta.pid;
                    flow.process_start_ts = incoming_start_ts;
                    adopted_pid = true;
                }
                if should_upgrade_cookie(flow.cookie, meta.cookie) {
                    flow.cookie = meta.cookie;
                }
                flow.last_seen = now;
                if !app_path.is_empty()
                    && !app_name.eq_ignore_ascii_case(process_resolver::UNKNOWN_APP_NAME)
                {
                    // An ownerless System inference is late evidence for an unknown
                    // flow, never a downgrade: a stale duplicate open (e.g. after a
                    // backend restart re-emits opens without PIDs) must not rewind
                    // a resolved owner back to System.
                    let displaces_named = !system_services::has_owner_evidence(meta)
                        && system_services::is_system_identity(&app_path, &app_name)
                        && !is_unknown_attribution(flow);
                    if !displaces_named {
                        // Adopt only same-instance evidence: when both sides carry
                        // a creation timestamp they must agree, or a recycled
                        // PID's new occupant would rename the previous instance's
                        // flow. Missing timestamps learn rather than block.
                        let incoming_ts = incoming_start_ts;
                        let placeholder_upgrade =
                            process_resolver::is_recoverable_placeholder(&flow.app_path)
                                && (!process_resolver::is_synthetic_path(&app_path)
                                    || system_services::is_system_identity(&app_path, &app_name));
                        let same_instance = if placeholder_upgrade {
                            start_ts > 0
                                && flow.process_start_ts.is_some_and(|known| {
                                    process_resolver::start_ts_compatible(start_ts, Some(known))
                                })
                        } else {
                            match (flow.process_start_ts, incoming_ts) {
                                (Some(known), Some(incoming)) => {
                                    process_resolver::start_ts_compatible(known, Some(incoming))
                                }
                                _ => true,
                            }
                        };
                        if same_instance {
                            flow.app_id = app_id;
                            flow.app_path = app_path;
                            flow.app_name = app_name;
                            if flow.process_start_ts.is_none() {
                                flow.process_start_ts = incoming_ts;
                            }
                        }
                    }
                }
                Self::mark_lookup_resolved(flow);
                touch_unknown_state(flow);
                drop(active);
                if adopted_pid {
                    self.port_pid_cache.lock().remember(&resolved_key, meta.pid);
                }
                drop(lifecycle);
                for (key, flow) in retired {
                    self.finalize_and_queue_log(key, flow, None);
                }
                self.refresh_active_attribution(&resolved_key, false, None);
                return;
            }
        }

        let capacity = FLOW_ACTIVE_FLOWS_HARD_CAP;
        let evicted = {
            let mut active = self.active.lock();
            if active.len() < capacity {
                None
            } else {
                let oldest = active
                    .iter()
                    .min_by_key(|(_, flow)| flow.last_seen)
                    .map(|(key, _)| *key);
                oldest.and_then(|key| active.remove(&key).map(|flow| (key, flow)))
            }
        };
        if let Some((evicted_key, flow)) = evicted {
            retired.push((evicted_key, flow));
            self.port_pid_cache.lock().forget(&evicted_key);
        }

        let mut flow = ActiveFlow {
            conn_id: self.next_conn_id.fetch_add(1, Ordering::Relaxed),
            open_pid: meta.pid,
            app_id,
            app_path,
            app_name,
            pid: meta.pid,
            protocol: protocol_label(resolved_key.protocol).to_owned(),
            src_ip: resolved_key.local_addr.to_string(),
            src_port: i32::from(resolved_key.local_port),
            dst_ip: resolved_key.remote_addr.to_string(),
            dst_port: i32::from(resolved_key.remote_port),
            bytes_sent: 0,
            bytes_received: 0,
            persisted_sent: 0,
            persisted_received: 0,
            db_row_created: false,
            persisted_app_id: app_id,
            persisted_domain: String::new(),
            name_lookup: NameLookup::default(),
            traffic_template: None,
            unknown_since: None,
            unknown_socket_lookup_done: false,
            socket_lookup_attempts: 0,
            next_socket_lookup: None,
            identity_lookup_attempts: 0,
            attribution_lookup: AttributionLookup::Idle,
            next_identity_retry: None,
            cookie: meta.cookie,
            process_start_ts: incoming_start_ts,
            open_ts: meta.open_ts,
            finishing: false,
            opened_at: now,
            last_seen: now,
        };
        touch_unknown_state(&mut flow);
        let needs_initial_socket_lookup = needs_socket_attribution(&flow);
        self.active.lock().insert(resolved_key, flow);

        if meta.pid > 0 {
            self.port_pid_cache.lock().remember(&resolved_key, meta.pid);
        }
        drop(lifecycle);
        for (key, flow) in retired {
            self.finalize_and_queue_log(key, flow, None);
        }
        self.refresh_active_attribution(&resolved_key, false, None);
        // The pass above may have found a cached or recorded owner.
        let needs_initial_socket_lookup = needs_initial_socket_lookup
            && self
                .active
                .lock()
                .get(&resolved_key)
                .is_some_and(needs_socket_attribution);
        if needs_initial_socket_lookup {
            // The socket was open when this handler began.
            let tables = SocketTables::since(observed);
            self.refresh_active_attribution(&resolved_key, true, Some(&tables));
        }
    }

    fn byte_template(
        &self,
        flow: &mut ActiveFlow,
        key: &FlowKey,
    ) -> Option<Arc<antiwire_events::TrafficEvent>> {
        self.processor.as_ref().filter(|p| p.wants_byte_updates())?;
        let matching = flow.traffic_template.as_ref().is_some_and(|template| {
            template.app_name == flow.app_name && template.app_path == flow.app_path
        });
        if !matching {
            flow.traffic_template = Some(FlowProcessor::byte_update_template(
                key,
                &flow.app_name,
                &flow.app_path,
            ));
        }
        flow.traffic_template.clone()
    }

    pub(super) fn on_bytes(&self, key: FlowKey, delta: ByteDelta) {
        let resolved_key = self.ensure_active_flow(key);
        let now = OffsetDateTime::now_utc();
        let (conn_id, refresh, mut template) = {
            let mut active = self.active.lock();
            let Some(flow) = active.get_mut(&resolved_key) else {
                return;
            };
            flow.bytes_sent = flow.bytes_sent.saturating_add(delta.sent);
            flow.bytes_received = flow.bytes_received.saturating_add(delta.received);
            flow.last_seen = now;
            let refresh = is_unknown_attribution(flow);
            (
                flow.conn_id,
                refresh,
                if refresh {
                    None
                } else {
                    self.byte_template(flow, &resolved_key)
                },
            )
        };
        if refresh {
            self.refresh_active_attribution(&resolved_key, false, None);
            template = self
                .active
                .lock()
                .get_mut(&resolved_key)
                .filter(|flow| flow.conn_id == conn_id)
                .and_then(|flow| self.byte_template(flow, &resolved_key));
        }
        // Publishing and protobuf construction never hold the active-flow mutex.
        if let Some(processor) = &self.processor {
            if let Some(template) = template {
                processor.publish_byte_update_shared(&delta, template, now);
            } else {
                processor.record_byte_delta(&delta);
            }
        }
    }

    /// Credits a finished flow's bytes to its application's running total.
    pub(super) fn record_closed_bytes(&self, flow: &ActiveFlow) {
        if flow.bytes_sent == 0 && flow.bytes_received == 0 {
            return;
        }
        let Some(key) = application_identity(&flow.app_path, &flow.app_name) else {
            return;
        };
        let mut closed = self.closed_app_bytes.lock();
        if closed.len() >= CLOSED_APP_BYTES_CAP && !closed.contains_key(&key) {
            return;
        }
        let entry = closed.entry(key).or_default();
        entry.0 = entry.0.saturating_add(flow.bytes_sent);
        entry.1 = entry.1.saturating_add(flow.bytes_received);
    }

    /// Removes the active flow at `key` when `cookie` proves it is a different socket.
    ///
    /// Mirrors [`netmetrics_core::FlowTable`]: an absent cookie on either side is never a
    /// mismatch, so a backend that cannot resolve one can never split a flow.
    fn take_superseded_flow(
        &self,
        key: &FlowKey,
        cookie: Option<SocketCookie>,
    ) -> Option<ActiveFlow> {
        let incoming = cookie?;
        let mut active = self.active.lock();
        let stored = active.get(key)?.cookie?;
        if !stored.contradicts(incoming) {
            return None;
        }
        active.remove(key)
    }

    /// Maps ETW byte events to an active flow when send/recv tuples disagree.
    fn resolve_active_key(&self, key: FlowKey) -> FlowKey {
        let active = self.active.lock();
        if active.contains_key(&key) {
            return key;
        }
        let reversed = key.reverse();
        if active.contains_key(&reversed) {
            return reversed;
        }
        key
    }

    /// Opens a flow on first byte when the open event was missed or reordered.
    fn ensure_active_flow(&self, key: FlowKey) -> FlowKey {
        // Fast path: resolve orientation and presence under one lock acquisition.
        // `resolve_active_key` followed by a second `contains_key` paid two.
        let resolved = {
            let active = self.active.lock();
            if active.contains_key(&key) {
                return key;
            }
            let reversed = key.reverse();
            if active.contains_key(&reversed) {
                return reversed;
            }
            key
        };
        // An inferred open has no cookie: absent is the only honest value here, and it also
        // guarantees this path can never look like a socket change.
        self.on_opened(
            resolved,
            &FlowMeta {
                pid: 0,
                process: None,
                open_ts: 0,
                cookie: None,
                if_index: None,
            },
        );
        self.resolve_active_key(key)
    }

    /// The flow's connection is no longer established. It stays tracked, and what it
    /// still carries is added to it, until it closes.
    fn on_finishing(&self, key: FlowKey) {
        let resolved_key = self.resolve_active_key(key);
        if let Some(flow) = self.active.lock().get_mut(&resolved_key) {
            flow.finishing = true;
        }
    }

    pub(super) fn on_closed(&self, key: FlowKey, meta: &FlowMeta) {
        let (resolved_key, flow) = {
            let _flush = self.flush_gate.lock();
            let resolved_key = self.resolve_active_key(key);
            let Some(flow) = self.active.lock().remove(&resolved_key) else {
                return;
            };
            self.port_pid_cache.lock().forget(&resolved_key);
            (resolved_key, flow)
        };
        let flow = self.maybe_reresolve_flow(flow, &resolved_key, meta);
        self.finalize_and_queue_log(resolved_key, flow, None);
    }

    /// Finalizes a completed flow and queues its connection log.
    ///
    /// `socket_snapshot` is a capture shared by the surrounding eviction batch, when
    /// one was already taken. Known flows never consult it — or capture a new one:
    /// enumerating the whole OS socket table on every close, idle eviction, cap
    /// eviction, and cookie supersession was pure waste for attributed flows.
    pub(super) fn finalize_and_queue_log(
        &self,
        key: FlowKey,
        mut flow: ActiveFlow,
        socket_tables: Option<&SocketTables>,
    ) {
        // This flow has left the active map; an older speculative lookup can
        // no longer merge into it. Close-time recovery owns this local value.
        flow.attribution_lookup = AttributionLookup::Idle;
        if needs_socket_attribution(&flow) && !flow.unknown_socket_lookup_done {
            self.maybe_attempt_port_cache_attribution(&mut flow, &key);
        }
        if needs_socket_attribution(&flow) && !flow.unknown_socket_lookup_done {
            let own;
            let tables = if let Some(tables) = socket_tables {
                tables
            } else {
                own = SocketTables::after(flow.last_seen);
                &own
            };
            let snapshot = self.socket_table(tables, key.protocol);
            self.maybe_attempt_socket_attribution(&mut flow, &key, snapshot, true);
        }
        self.normalize_active_flow(&mut flow);
        self.record_closed_bytes(&flow);
        // The close was observed now: stamp it so the final delta and the close
        // time both reflect the end of the connection, not its last bytes.
        flow.last_seen = OffsetDateTime::now_utc();
        self.closed_owners[closed_owner_kind(&flow.app_path, &flow.app_name)]
            .fetch_add(1, Ordering::Relaxed);
        self.queue_log(key, &flow, true);
        // A named placeholder may yet get its path, and a connection whose
        // process had exited before it could be asked may yet get its process:
        // the lifecycle events for either can arrive after the close.
        if process_resolver::is_recoverable_placeholder(&flow.app_path)
            || (flow.pid != 0 && is_unknown_attribution(&flow))
        {
            self.closed_identities
                .lock()
                .remember(key, flow, Instant::now());
        }
    }

    /// Re-attempts PID resolution at flow close when open-time attribution failed.
    ///
    /// Unknown rows and the path placeholder both get this final
    /// chance. Placeholder upgrades keep the strict same-instance rule: an
    /// authoritative path plus matching process creation evidence, so a
    /// recycled PID observed only by the socket table cannot rename the flow.
    pub(super) fn maybe_reresolve_flow(
        &self,
        mut flow: ActiveFlow,
        key: &FlowKey,
        meta: &FlowMeta,
    ) -> ActiveFlow {
        flow.attribution_lookup = AttributionLookup::Idle;
        let placeholder = process_resolver::is_recoverable_placeholder(&flow.app_path);
        if !placeholder
            && !flow
                .app_name
                .eq_ignore_ascii_case(process_resolver::UNKNOWN_APP_NAME)
            && flow.app_id > 0
        {
            return flow;
        }

        if flow.pid != 0 && meta.pid != 0 && flow.pid != meta.pid {
            return flow;
        }
        if flow.pid != 0 && meta.pid == 0 {
            self.try_refresh_attribution(&mut flow, key, true);
            return flow;
        }
        let incoming_ts = attributable_process_start_ts(meta);
        if let (Some(known), Some(incoming)) = (flow.process_start_ts, incoming_ts) {
            if !process_resolver::start_ts_compatible(known, Some(incoming)) {
                return flow;
            }
        }
        if placeholder {
            if flow.process_start_ts.is_none() {
                return flow;
            }
            if incoming_ts.is_none() {
                // Untimestamped close metadata cannot prove ownership. Query
                // using the original instance's timestamp instead.
                self.try_refresh_attribution(&mut flow, key, true);
                return flow;
            }
        }

        let Some(processor) = &self.processor else {
            return flow;
        };

        let ResolvedApplication {
            app_id,
            app_path,
            app_name,
            start_ts,
        } = processor.resolve_flow_app(key, meta);
        if placeholder {
            if start_ts == 0
                || !process_resolver::start_ts_compatible(start_ts, flow.process_start_ts)
            {
                return flow;
            }
            // A verified System fold is the one placeholder upgrade that needs
            // no real path: the allowlist match is the proof of ownership.
            if !identity_upgrade_acceptable(true, &app_path, &app_name)
                && !system_services::is_system_identity(&app_path, &app_name)
            {
                return flow;
            }
        } else if app_path.is_empty()
            || app_name.eq_ignore_ascii_case(process_resolver::UNKNOWN_APP_NAME)
        {
            if flow.pid != 0 || meta.pid == 0 || !is_unknown_attribution(&flow) {
                return flow;
            }
            // The close is the first to say which process had the connection,
            // and that process cannot be named now. Who it was is kept all the
            // same: its lifecycle events can name it after the close, and the
            // row is found again by this PID.
            flow.pid = meta.pid;
            flow.process_start_ts = attributable_process_start_ts(meta);
            if app_id > 0 {
                // It had an owner, so the row says why that owner is unknown.
                flow.app_id = app_id;
                flow.app_path = app_path;
                flow.app_name = app_name;
            }
            return flow;
        }

        let pid = if flow.pid == 0 && meta.pid > 0 {
            meta.pid
        } else {
            flow.pid
        };
        let process_start_ts = flow
            .process_start_ts
            .or_else(|| attributable_process_start_ts(meta))
            .or_else(|| (pid > 0 && start_ts > 0).then_some(start_ts));
        ActiveFlow {
            app_id,
            app_path,
            app_name,
            pid,
            process_start_ts,
            ..flow
        }
    }
}

impl<S: FlowStore + 'static> FlowTracker<S> {
    /// Spawns [`Self::run`] under a supervisor that reports stalls and unexpected exits.
    ///
    /// The event loop ends normally only when the bridge closes its channel during
    /// shutdown, which cancelling `shutdown` announces. Anything else — a panic, an exit
    /// while the daemon is still running, or a long stretch without progress — leaves
    /// connection logging stopped or frozen, which the dashboard has to say.
    ///
    /// A panic is caught inside this task, so the join result is always `Ok(())` and
    /// the fault is reported through `collector_health` instead.
    #[must_use]
    pub fn spawn_supervised(
        self: Arc<Self>,
        rx: mpsc::Receiver<FlowEvent>,
        collector_health: Arc<CollectorHealth>,
        shutdown: CancellationToken,
    ) -> tokio::task::JoinHandle<()> {
        let progress = Arc::clone(&self);
        let timing = self.watchdog;
        tokio::spawn(async move {
            let run = AssertUnwindSafe(self.run(rx)).catch_unwind();
            tokio::pin!(run);
            let mut watchdog = tokio_time::interval(timing.interval);
            watchdog.set_missed_tick_behavior(tokio_time::MissedTickBehavior::Delay);
            // The first tick is immediate, and the tracker has not had a chance to make
            // progress yet, so it must not count toward a stall.
            watchdog.tick().await;
            let mut last_progress = progress.progress_count();
            let mut stalled_ticks = 0_u32;
            let mut stalled = false;

            loop {
                tokio::select! {
                    result = &mut run => {
                        let unexpected = match result {
                            Ok(Ok(())) => !shutdown.is_cancelled(),
                            Ok(Err(error)) => {
                                tracing::warn!(%error, "flow tracker stopped");
                                !shutdown.is_cancelled()
                            }
                            Err(_) => {
                                tracing::error!("flow tracker panicked");
                                true
                            }
                        };
                        if unexpected {
                            collector_health.mark_flow_tracker_stopped(
                                "Flow recording stopped unexpectedly. Connection history is no longer \
                                 being recorded; restart the daemon to resume it.",
                            );
                        }
                        return;
                    }
                    _ = watchdog.tick() => {
                        let current = progress.progress_count();
                        if current == last_progress {
                            stalled_ticks = stalled_ticks.saturating_add(1);
                            if !stalled && stalled_ticks >= timing.stall_ticks {
                                stalled = true;
                                tracing::error!(
                                    ticks = stalled_ticks,
                                    "flow tracker is not making progress"
                                );
                                collector_health.mark_flow_tracker_stalled(
                                    "Flow tracking is not making progress. Connection history will \
                                     stay incomplete until it recovers.",
                                );
                            }
                        } else {
                            last_progress = current;
                            stalled_ticks = 0;
                            if stalled {
                                stalled = false;
                                collector_health.clear_flow_tracker_stalled();
                                tracing::info!("flow tracker resumed");
                            }
                        }
                    }
                }
            }
        })
    }

    /// Runs one unit of blocking tracker work on the blocking pool.
    ///
    /// A flush writes `SQLite`, and the active-flow pass can walk the host's whole
    /// socket table; running either inline parks an async runtime worker for the
    /// duration. Serialization stays with the tracker's own locks, so dispatching to
    /// the blocking pool cannot interleave a flush with a close.
    ///
    /// A panic in the work is logged and yields `None`, so one bad event or
    /// flush costs that unit of work instead of stopping connection logging.
    async fn offload_blocking<T, F>(self: &Arc<Self>, work: F) -> Option<T>
    where
        F: FnOnce(&Self) -> T + Send + 'static,
        T: Send + 'static,
    {
        let tracker = Arc::clone(self);
        match tokio::task::spawn_blocking(move || work(&tracker)).await {
            Ok(value) => Some(value),
            Err(error) => {
                tracing::error!(%error, "flow tracker work panicked; continuing");
                None
            }
        }
    }

    /// Monotonic progress counter, sampled by the supervisor's stall watchdog.
    fn progress_count(&self) -> u64 {
        self.progress.load(Ordering::Relaxed)
    }
}
