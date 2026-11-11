//! Closed connections whose name may still change, and the row updates that
//! follow.
//!
//! No log is written for a connection after the one that closes it, so a name
//! judged afterwards reaches the row from here. Two things can change it.
//!
//! A hint recorded before the connection opened can arrive after it closed.
//! Until every such hint has had time to arrive the name is provisional, and
//! what a lookup then finds replaces it (see [`Naming`]).
//!
//! After that, a name that is not confirmed waits a while longer for a hint
//! that confirms it. ETW DNS events reach the processor in batches about a
//! second apart, so a short connection often closes first.

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

use antiwire_events::TrafficEvent;
use antiwire_store::{ConnectionDomainUpgrade, DomainEvidence, NewConnectionLog};
use netmetrics_core::canonicalize_ip;
use time::OffsetDateTime;
use tracing::warn;

use super::hint_scopes::Opening;
use super::{FlowProcessor, Naming, NewlyNamed};
use crate::domain_stats::executable_key;

/// How long a closed connection whose name is not final is held.
const LATE_NAME_WINDOW: Duration = Duration::from_secs(10);

/// Bound on the closed connections held, however many addresses they went to.
pub(super) const CLOSED_NAMES_CAP: usize = 4_096;

/// Flush ticks a name waits for its connection's row to be written.
const NAME_WRITE_ATTEMPTS: u8 = 30;

impl FlowProcessor {
    /// Holds a closed connection whose name could still change, so that what
    /// arrives for `remote` afterwards still reaches its row. `naming` is what
    /// the lookup made as it closed said of the name in `log`, or `None` when
    /// the name was final already. `app_name` is the connection's
    /// application, for the record republished when the name changes.
    pub(crate) fn await_final_name(
        &self,
        pid: u32,
        remote: IpAddr,
        app_name: &str,
        opening: Opening,
        naming: Option<Naming>,
        log: &NewConnectionLog,
    ) {
        let executable = executable_key(&log.app_path);
        self.domain_stats.record_closed_row(
            antiwire_store::domain_evidence(&log.dst_domain),
            pid,
            executable,
            remote,
            opening.at_ms,
        );
        let now_ms = netmetrics_core::unix_now_ms();
        let Some(naming) = naming.filter(|naming| naming.open_at(now_ms)) else {
            return;
        };
        // Without a process no hint is the connection's own, and without a
        // session id its row cannot be found again.
        if pid == 0 || log.conn_id == 0 {
            return;
        }
        let now = Instant::now();
        let mut closed = self.closed_names.lock();
        if !closed.has_room(now, now_ms) {
            drop(closed);
            self.domain_stats.record_closed_name_shed();
            return;
        }
        closed.hold(
            canonicalize_ip(remote),
            ClosedName {
                pid,
                executable,
                opening,
                conn_id: log.conn_id,
                conn_pid: log.conn_pid,
                conn_start: log.timestamp,
                written: log.dst_domain.clone(),
                naming,
                deadline: now + LATE_NAME_WINDOW,
                record: super::traffic_event_from_log(app_name, &log.app_path, log),
            },
        );
    }

    /// Judges again the closed connections to the addresses in `named`, and
    /// writes the names that changed. Called on the flush tick with the
    /// addresses evidence arrived for since the last one.
    ///
    /// Each row that takes a name is published again with it. Subscribers
    /// last saw the row as it closed, and on a quiet machine no other event
    /// would prompt them to read it again.
    pub(crate) fn settle_closed_names(&self, named: &NewlyNamed) {
        let now_ms = netmetrics_core::unix_now_ms();
        let due = {
            let mut closed = self.closed_names.lock();
            closed.expire(Instant::now(), now_ms);
            closed.take_named(named)
        };
        // The lookups read the hints and the store, so the held connections
        // are judged with nothing locked.
        let mut ready = Vec::new();
        for (remote, rows) in due {
            let still_open: Vec<ClosedName> = rows
                .into_iter()
                .filter_map(|row| self.judge_closed(remote, row, now_ms, &mut ready))
                .collect();
            self.closed_names.lock().put_back(remote, still_open);
        }
        if !ready.is_empty() {
            self.ready_domain_upgrades.lock().extend(ready);
        }
        self.write_name_upgrades();
    }

    /// Looks up the closed connection `row`, to `remote`, again at `now_ms`.
    /// A name that differs from the one written is queued in `ready`. Returns
    /// the row while its name could still change.
    fn judge_closed(
        &self,
        remote: IpAddr,
        mut row: ClosedName,
        now_ms: u64,
        ready: &mut Vec<ReadyUpgrade>,
    ) -> Option<ClosedName> {
        if !row.naming.open_at(now_ms) {
            return None;
        }
        let replaces = row.naming.provisional_at(now_ms);
        let judged = self.name_connection(row.pid, row.executable, &remote, row.opening);
        let confirmed =
            antiwire_store::domain_evidence(&judged.domain) == DomainEvidence::Confirmed;
        // Evidence from after a connection closed says little about it, so
        // once the name is complete only a confirmation changes it.
        if replaces || confirmed {
            let chosen = judged.over(&row.written, replaces);
            if chosen != row.written {
                let replace = chosen != antiwire_store::prefer_dst_domain(&row.written, &chosen);
                if replace {
                    self.domain_stats
                        .record_correction(true, antiwire_store::domain_evidence(&chosen));
                }
                ready.push(ReadyUpgrade {
                    upgrade: ConnectionDomainUpgrade {
                        conn_id: row.conn_id,
                        conn_pid: row.conn_pid,
                        conn_start: row.conn_start,
                        dst_domain: chosen.clone(),
                        replace,
                    },
                    attempts: NAME_WRITE_ATTEMPTS,
                    record: row.record.clone(),
                });
                row.written = chosen;
            }
        }
        row.naming = judged.naming;
        row.naming.open_at(now_ms).then_some(row)
    }

    /// Writes the names queued for closed connections. A name whose row is
    /// not written yet waits for a later tick.
    pub(crate) fn write_name_upgrades(&self) {
        let ready = std::mem::take(&mut *self.ready_domain_upgrades.lock());
        if ready.is_empty() {
            return;
        }
        let upgrades: Vec<ConnectionDomainUpgrade> =
            ready.iter().map(|ready| ready.upgrade.clone()).collect();
        let found = match self.store.upgrade_connection_domains(&upgrades) {
            Ok(found) => {
                if found.len() != upgrades.len() {
                    warn!(
                        upgrades = upgrades.len(),
                        answered = found.len(),
                        "late domain upgrade answered a different number of rows; retrying the rest"
                    );
                }
                found
            }
            Err(error) => {
                // A failed write says nothing about the rows, so every upgrade
                // spends one attempt and waits for the next tick.
                warn!(error = %error, upgrades = upgrades.len(), "late domain upgrade failed");
                Vec::new()
            }
        };
        let mut retry = Vec::new();
        for (index, mut ready) in ready.into_iter().enumerate() {
            if found.get(index).copied().unwrap_or(false) {
                self.domain_stats.record_late_upgrade();
                ready.record.dst_domain = ready.upgrade.dst_domain;
                self.traffic_hub.publish(ready.record);
            } else if ready.attempts > 1 {
                ready.attempts -= 1;
                retry.push(ready);
            }
        }
        if !retry.is_empty() {
            // Names queued since the take are newer, and are written after.
            let mut queued = self.ready_domain_upgrades.lock();
            retry.append(&mut queued);
            *queued = retry;
        }
    }
}

/// A closed connection whose name could still change.
#[derive(Debug)]
struct ClosedName {
    /// The connection's process.
    pid: u32,
    /// [`executable_key`] of the connection's application.
    executable: u64,
    /// When the connection opened, which is when its name is judged.
    opening: Opening,
    conn_id: i64,
    conn_pid: i32,
    conn_start: OffsetDateTime,
    /// The name its row was last given.
    written: String,
    /// What the last lookup said of that name.
    naming: Naming,
    deadline: Instant,
    /// The connection's record as published when it closed.
    record: TrafficEvent,
}

/// A name waiting to be written to its closed connection's row.
#[derive(Debug)]
pub(super) struct ReadyUpgrade {
    pub(super) upgrade: ConnectionDomainUpgrade,
    /// Flush ticks left to find the row.
    pub(super) attempts: u8,
    /// The connection's record, published again once the row has its name.
    pub(super) record: TrafficEvent,
}

/// Closed connections whose name could still change, by canonical remote
/// address.
///
/// The bound is on connections, not addresses: any number of connections can
/// close to one address, and each is held with a copy of its record.
#[derive(Debug, Default)]
pub(super) struct ClosedNames {
    by_address: HashMap<IpAddr, Vec<ClosedName>>,
    /// Connections held, across every address.
    rows: usize,
}

impl ClosedNames {
    /// Whether one more connection can be held, after dropping those whose
    /// wait is over if that is what it takes.
    fn has_room(&mut self, now: Instant, now_ms: u64) -> bool {
        if self.rows >= CLOSED_NAMES_CAP {
            self.expire(now, now_ms);
        }
        self.rows < CLOSED_NAMES_CAP
    }

    /// Holds `row`, a connection to `remote`. Ask [`Self::has_room`] first.
    fn hold(&mut self, remote: IpAddr, row: ClosedName) {
        self.by_address.entry(remote).or_default().push(row);
        self.rows += 1;
    }

    /// Takes the connections to every address in `named`, oldest first.
    fn take_named(&mut self, named: &NewlyNamed) -> Vec<(IpAddr, Vec<ClosedName>)> {
        if named.is_empty() || self.rows == 0 {
            return Vec::new();
        }
        let addresses: Vec<IpAddr> = self
            .by_address
            .keys()
            .copied()
            .filter(|address| named.names(*address))
            .collect();
        addresses
            .into_iter()
            .filter_map(|address| {
                let rows = self.by_address.remove(&address)?;
                self.rows -= rows.len();
                Some((address, rows))
            })
            .collect()
    }

    /// Returns connections [`Self::take_named`] gave out that are still held.
    fn put_back(&mut self, remote: IpAddr, rows: Vec<ClosedName>) {
        if rows.is_empty() {
            return;
        }
        self.rows += rows.len();
        let held = self.by_address.entry(remote).or_default();
        // Any held since the take are newer.
        let newer = std::mem::replace(held, rows);
        held.extend(newer);
    }

    /// Drops the connections whose wait is over: held for as long as any is,
    /// or with a name nothing arriving now could change.
    fn expire(&mut self, now: Instant, now_ms: u64) {
        let mut rows = 0;
        self.by_address.retain(|_, held| {
            held.retain(|row| row.deadline > now && row.naming.open_at(now_ms));
            rows += held.len();
            !held.is_empty()
        });
        self.rows = rows;
    }

    /// Connections held, across every address.
    #[cfg(test)]
    pub(super) fn len(&self) -> usize {
        self.rows
    }
}
