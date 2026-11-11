//! Connection log queries: per-connection upserts, attribution, filtering, paging.

use std::collections::HashMap;

use antiwire_tuning::{DEFAULT_LOG_PAGE_SIZE, LOG_RETENTION_PURGE_BATCH_SIZE, MAX_LOG_PAGE_SIZE};
use rusqlite::Row;
use time::OffsetDateTime;

use crate::domain_evidence::prefer_dst_domain;
use crate::error::Result;
use crate::models::{
    activity_bucket_start, format_timestamp, parse_timestamp, ApplicationLogSummary,
    ApplicationLogSummaryQuery, ConnectionDomainUpgrade, ConnectionLog, ConnectionLogAttribution,
    ConnectionLogPage, ConnectionLogQuery, NewConnectionLog,
};

use super::activity::{apply_activity_deltas, ActivityDelta};
use crate::store::Store;
use crate::store::{get_timestamp, row_id_to_i32};

impl Store {
    /// Inserts new connection logs or advances the rows of their connections.
    ///
    /// Identity is the connection triple (`conn_id`, `conn_pid`, connection
    /// start), not the flow tuple: repeats carrying the same triple accumulate
    /// byte deltas and refresh `last_seen` on that connection's row, while a
    /// new connection — recycled tuple, superseded socket, reopen after close,
    /// or a relaunched daemon reusing session ids — carries a different triple
    /// and starts its own row. A zero `conn_id` (legacy/unattributed) never
    /// matches and always inserts.
    ///
    /// A row with a close time is terminal: further flushes for its triple
    /// start a fresh row instead of accumulating onto it.
    pub fn insert_connection_logs(&self, logs: &[NewConnectionLog]) -> Result<()> {
        if logs.is_empty() {
            return Ok(());
        }

        // The lookup and every write share one transaction, and the connection lock
        // is held for its whole duration.
        //
        // This used to drive `BEGIN IMMEDIATE`/`COMMIT` through [`Db`]'s helpers,
        // each of which takes and releases the connection lock. That left the lock
        // free between statements while a transaction was open, so any other thread
        // writing in that window — the DNS cache writer, the DNS block recorder, a
        // settings update — had its statement silently enrolled into this
        // transaction and destroyed by its rollback, while any thread opening its
        // own transaction failed outright with "cannot start a transaction within a
        // transaction". The lookup also ran before `BEGIN`, so a concurrent insert
        // of the same connection could race the insert-vs-update decision into a
        // duplicate row.
        //
        // The in-memory liveness set (`active_conns`) is updated only after the
        // transaction commits: a rolled-back batch must not mark triples active.
        let pending_liveness = self.db.transaction_with(|tx| {
            // Rows already persisted, plus rows inserted earlier in this batch:
            // two flushes for one connection may arrive in a single call, and
            // the second must advance the first rather than fork a duplicate.
            let mut known = find_connection_logs_by_conn_triples(
                tx,
                logs.iter().filter(|log| log.conn_id != 0).map(|log| {
                    (
                        log.conn_id,
                        log.conn_pid,
                        format_timestamp(log.timestamp),
                    )
                }),
            )?;

            // Three statements prepared once for the batch: a periodic flush carries
            // one entry per active connection, which runs to thousands. Closes
            // are one row-lifetime event each, so the extra statement is noise.
            let mut update = tx.prepare(
                "UPDATE connection_logs SET
                    bytes_sent = bytes_sent + ?1,
                    bytes_received = bytes_received + ?2,
                    last_seen = ?3,
                    action_taken = ?4,
                    dst_domain = ?5,
                    country_code = CASE WHEN country_code = '' THEN ?6 ELSE country_code END,
                    isp = CASE WHEN isp = '' THEN ?7 ELSE isp END,
                    blocklist_names = CASE WHEN ?8 = '' THEN blocklist_names ELSE ?8 END
                 WHERE id = ?9",
            )?;
            let mut insert = tx.prepare(
                "INSERT INTO connection_logs (
                    timestamp, app_id, protocol, src_ip, src_port, dst_ip, dst_port, dst_domain,
                    bytes_sent, bytes_received, action_taken, last_seen, country_code, isp,
                    blocklist_names, conn_id, conn_pid, app_path
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18)",
            )?;
            let mut close = tx.prepare(
                "UPDATE connection_logs SET
                    closed_at = CASE WHEN closed_at = '' THEN ?1 ELSE closed_at END
                 WHERE id = ?2",
            )?;
            let mut activity = HashMap::<OffsetDateTime, ActivityDelta>::new();
            // Ordered liveness intents for `active_conns`, applied after commit
            // in log order so a `[open, close]` batch ends inactive and a
            // `[close, reopen]` batch ends active.
            let mut pending_liveness: Vec<((i64, i32, String), bool)> = Vec::new();

            for log in logs {
                let bucket = activity_bucket_start(log.last_seen);
                let delta = activity.entry(bucket).or_default();
                delta.event_count += 1;
                delta.bytes_sent += u64::try_from(log.bytes_sent).unwrap_or(0);
                delta.bytes_received += u64::try_from(log.bytes_received).unwrap_or(0);

                upsert_connection_log(
                    tx,
                    &mut update,
                    &mut insert,
                    &mut close,
                    &mut known,
                    delta,
                    log,
                )?;
                // Legacy rows (`conn_id == 0`) never match another row and are
                // never liveness evidence.
                if log.conn_id != 0 {
                    pending_liveness.push((
                        (
                            log.conn_id,
                            log.conn_pid,
                            format_timestamp(log.timestamp),
                        ),
                        log.is_close,
                    ));
                }
            }

            drop(update);
            drop(insert);
            drop(close);
            apply_activity_deltas(tx, &activity)?;
            Ok(pending_liveness)
        })?;

        if !pending_liveness.is_empty() {
            let mut active = self.active_conns.lock();
            for (triple, is_close) in pending_liveness {
                if is_close {
                    active.remove(&triple);
                } else {
                    active.insert(triple);
                }
            }
        }
        Ok(())
    }

    /// Moves a persisted connection from a provisional application to its resolved owner.
    ///
    /// A non-zero `conn_id` re-points exactly the row whose full identity
    /// triple matches. A zero id falls back to the flow-tuple match. Rows are
    /// never merged or deleted.
    ///
    /// # Errors
    ///
    /// Returns an error when the update fails.
    pub fn reattribute_connection_log(&self, attribution: &ConnectionLogAttribution) -> Result<()> {
        if attribution.from_app_id == attribution.to_app_id && attribution.conn_id == 0 {
            return Ok(());
        }

        if attribution.conn_id != 0 {
            self.db.execute(
                "UPDATE connection_logs
                  SET app_id = ?1,
                      app_path = COALESCE(
                          (SELECT app_path FROM applications WHERE id = ?1), app_path)
                  WHERE id = (SELECT id FROM connection_logs
                    WHERE conn_id = ?2 AND conn_pid = ?3 AND timestamp = ?4 AND app_id = ?5
                    ORDER BY (closed_at = '') DESC, id DESC LIMIT 1)",
                rusqlite::params![
                    attribution.to_app_id,
                    attribution.conn_id,
                    attribution.conn_pid,
                    format_timestamp(attribution.conn_start),
                    attribution.from_app_id,
                ],
            )?;
            return Ok(());
        }

        self.db.execute(
            "UPDATE connection_logs
              SET app_id = ?1,
                  app_path = COALESCE(
                      (SELECT app_path FROM applications WHERE id = ?1), app_path)
              WHERE app_id = ?2
                AND LOWER(protocol) = LOWER(?3)
                AND LOWER(src_ip) = LOWER(?4)
                AND LOWER(dst_ip) = LOWER(?5)
                AND dst_port = ?6",
            rusqlite::params![
                attribution.to_app_id,
                attribution.from_app_id,
                attribution.protocol,
                attribution.src_ip,
                attribution.dst_ip,
                attribution.dst_port,
            ],
        )?;
        Ok(())
    }

    /// Applies domains to closed connections' rows, which no later log for
    /// the connection updates.
    ///
    /// Each domain goes through [`prefer_dst_domain`], so a confirmed domain is
    /// never replaced, unless the upgrade says it replaces the row's own.
    ///
    /// Returns, per upgrade, whether its connection's row was there to take
    /// it. A row is not until the log that closes it is written. That log
    /// carries the name the connection closed with, and written after an
    /// upgrade that replaces the row's name it would put the old one back.
    /// The caller tries again later.
    ///
    /// # Errors
    ///
    /// Returns an error when the lookup or the update fails; nothing is applied.
    pub fn upgrade_connection_domains(
        &self,
        upgrades: &[ConnectionDomainUpgrade],
    ) -> Result<Vec<bool>> {
        if upgrades.is_empty() {
            return Ok(Vec::new());
        }
        self.db.transaction_with(|tx| {
            let mut find = tx.prepare_cached(
                "SELECT id, dst_domain FROM connection_logs
                  WHERE conn_id = ?1 AND conn_pid = ?2 AND timestamp = ?3
                    AND closed_at != ''
                  ORDER BY id DESC LIMIT 1",
            )?;
            let mut update =
                tx.prepare_cached("UPDATE connection_logs SET dst_domain = ?1 WHERE id = ?2")?;
            let mut found = Vec::with_capacity(upgrades.len());
            for upgrade in upgrades {
                let row = find
                    .query_row(
                        rusqlite::params![
                            upgrade.conn_id,
                            upgrade.conn_pid,
                            format_timestamp(upgrade.conn_start),
                        ],
                        |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?)),
                    )
                    .map(Some)
                    .or_else(|error| match error {
                        rusqlite::Error::QueryReturnedNoRows => Ok(None),
                        error => Err(error),
                    })?;
                let Some((id, existing)) = row else {
                    found.push(false);
                    continue;
                };
                let chosen = if upgrade.replace {
                    upgrade.dst_domain.clone()
                } else {
                    prefer_dst_domain(&existing, &upgrade.dst_domain)
                };
                if chosen != existing {
                    update.execute(rusqlite::params![chosen, id])?;
                }
                found.push(true);
            }
            Ok(found)
        })
    }

    /// Deletes one batch of old connection logs. A missing cutoff disables retention.
    pub fn purge_connection_logs_before(&self, cutoff: Option<OffsetDateTime>) -> Result<u64> {
        let Some(cutoff) = cutoff else {
            return Ok(0);
        };
        // Fixed-width UTC timestamps keep the indexed DELETE and the
        // in-memory liveness cutoff in the same chronological order.
        let cutoff_str = format_timestamp(cutoff);
        let deleted = self.db.execute(
            "DELETE FROM connection_logs WHERE id IN (
                SELECT id FROM connection_logs WHERE timestamp < ?1 ORDER BY timestamp LIMIT ?2
             )",
            rusqlite::params![cutoff_str, LOG_RETENTION_PURGE_BATCH_SIZE],
        )?;
        // Bound the liveness set: triples whose connection start was purged
        // can never be returned by a query again.
        if deleted < u64::from(LOG_RETENTION_PURGE_BATCH_SIZE) {
            let mut active = self.active_conns.lock();
            // A bounded pass may leave older rows for the next pass. Do not
            // drop their liveness until all old rows have been removed.
            active.retain(|(_, _, start)| *start >= cutoff_str);
        }
        Ok(deleted)
    }

    /// Returns a paginated slice of connection logs plus aggregate counts.
    pub fn query_connection_logs(&self, query: &ConnectionLogQuery) -> Result<ConnectionLogPage> {
        let limit = clamp_log_limit(query.limit);
        let offset = clamp_log_offset(query.offset);
        let where_clause = build_log_where_clause(query);
        let order_clause = build_log_order_clause(query);

        let stats_sql = format!(
            "SELECT COUNT(*),
                    COALESCE(SUM(CASE WHEN LOWER(action_taken) IN ('blocked', 'block') THEN 1 ELSE 0 END), 0),
                    COUNT(DISTINCT NULLIF(dst_domain, ''))
             FROM connection_logs WHERE {where_clause}"
        );

        let page_sql = format!(
            "WITH page AS MATERIALIZED (
                SELECT id FROM connection_logs WHERE {where_clause}
                ORDER BY {order_clause} LIMIT ?1 OFFSET ?2
             )
             SELECT id, timestamp, app_id, protocol, src_ip, src_port, dst_ip, dst_port,
                    dst_domain, bytes_sent, bytes_received, action_taken, last_seen, country_code, isp,
                    blocklist_names, conn_id, conn_pid, closed_at, app_path
             FROM connection_logs
             WHERE id IN (SELECT id FROM page)
             ORDER BY {order_clause}"
        );
        let ((total_count, blocked_count, unique_domain_count), mut logs) =
            self.db.read_snapshot(|tx| {
                let counts = tx.prepare_cached(&stats_sql)?.query_row([], |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, i64>(2)?,
                    ))
                })?;
                let mut statement = tx.prepare_cached(&page_sql)?;
                let logs = statement
                    .query_map(rusqlite::params![limit, offset], map_connection_log)?
                    .collect::<rusqlite::Result<Vec<_>>>()?;
                Ok((counts, logs))
            })?;

        // Overlay session liveness: a row is active only when it is unclosed,
        // carries a real triple, and that triple saw a non-close write in this
        // process lifetime. Closed rows are never active even while their
        // triple lingers for a reopened successor; legacy `conn_id == 0` rows
        // never match and stay inactive. Snapshot the set so per-row
        // formatting does not hold the lock across the page.
        if !logs.is_empty() {
            let active = self.active_conns.lock().clone();
            if !active.is_empty() {
                for log in &mut logs {
                    if log.closed_at.is_none() && log.conn_id != 0 {
                        let triple = (log.conn_id, log.conn_pid, format_timestamp(log.timestamp));
                        log.is_active = active.contains(&triple);
                    }
                }
            }
        }

        Ok(ConnectionLogPage {
            logs,
            total_count: u64::try_from(total_count).unwrap_or(u64::MAX),
            blocked_count: u64::try_from(blocked_count).unwrap_or(u64::MAX),
            unique_domain_count: u64::try_from(unique_domain_count).unwrap_or(u64::MAX),
        })
    }

    /// Counts blocked connection logs within a rolling time window.
    pub fn count_blocked_connections(&self, time_filter_seconds: u32) -> Result<u64> {
        let mut clauses = vec!["1 = 1".to_owned()];
        append_log_time_filters(&mut clauses, time_filter_seconds, None, None, "");
        clauses
            .push("(LOWER(action_taken) = 'blocked' OR LOWER(action_taken) = 'block')".to_owned());
        let where_clause = clauses.join(" AND ");
        let sql = format!("SELECT COUNT(*) FROM connection_logs WHERE {where_clause}");
        let count: i64 = self.db.query_row(&sql, [], |row| row.get(0))?;
        Ok(u64::try_from(count).unwrap_or(u64::MAX))
    }

    /// Returns per-application connection log aggregates for the UI.
    pub fn query_application_log_summaries(
        &self,
        query: &ApplicationLogSummaryQuery,
    ) -> Result<Vec<ApplicationLogSummary>> {
        let mut where_clauses = vec!["1 = 1".to_owned()];
        append_log_time_filters(
            &mut where_clauses,
            query.time_filter_seconds,
            query.time_window_start,
            query.time_window_end,
            "cl",
        );

        if let Some(action_filter) = query.action_filter.as_deref() {
            match action_filter.to_ascii_lowercase().as_str() {
                "allowed" => where_clauses.push(
                    "(LOWER(cl.action_taken) != 'blocked' AND LOWER(cl.action_taken) != 'block')"
                        .to_owned(),
                ),
                "blocked" => where_clauses.push(
                    "(LOWER(cl.action_taken) = 'blocked' OR LOWER(cl.action_taken) = 'block')"
                        .to_owned(),
                ),
                _ => {}
            }
        }

        let where_sql = where_clauses.join(" AND ");
        let sql = format!(
            "SELECT cl.app_id,
                    COALESCE(NULLIF(a.app_name, ''), 'unknown.exe') AS app_name,
                    COALESCE(a.app_path, '') AS app_path,
                    COUNT(*) AS connection_count,
                    SUM(CASE
                        WHEN LOWER(cl.action_taken) IN ('blocked', 'block') THEN 1
                        ELSE 0
                    END) AS blocked_count,
                    COALESCE(SUM(cl.bytes_sent), 0) AS bytes_sent,
                    COALESCE(SUM(cl.bytes_received), 0) AS bytes_received,
                    MAX(cl.last_seen) AS last_seen
             FROM connection_logs cl
             LEFT JOIN applications a ON a.id = cl.app_id
             WHERE {where_sql}
             GROUP BY cl.app_id
             ORDER BY (COALESCE(SUM(cl.bytes_sent), 0) + COALESCE(SUM(cl.bytes_received), 0)) DESC, app_name ASC"
        );

        self.db.query_map(&sql, [], map_application_log_summary)
    }
}

/// Advances one connection log: accumulates onto the row matching its identity
/// triple, or inserts a fresh row when nothing open matches.
///
/// A row that already carries a close time is terminal and never accumulates:
/// the flush starts a new row instead, so traffic that arrived after the close
/// cannot rewrite a finished connection. A flush marked as a close records its
/// time (first close wins) and releases the triple, so any later flush for it
/// also starts fresh.
fn upsert_connection_log(
    tx: &rusqlite::Transaction<'_>,
    update: &mut rusqlite::Statement<'_>,
    insert: &mut rusqlite::Statement<'_>,
    close: &mut rusqlite::Statement<'_>,
    known: &mut HashMap<ConnTriple, ExistingConnection>,
    delta: &mut ActivityDelta,
    log: &NewConnectionLog,
) -> Result<()> {
    if log.conn_id != 0 {
        let triple = (log.conn_id, log.conn_pid, format_timestamp(log.timestamp));
        match known.get(&triple).cloned() {
            Some(row) if !row.closed => {
                let dst_domain = if log.replace_domain {
                    log.dst_domain.clone()
                } else {
                    prefer_dst_domain(&row.dst_domain, &log.dst_domain)
                };
                update.execute(rusqlite::params![
                    log.bytes_sent,
                    log.bytes_received,
                    format_timestamp(log.last_seen),
                    log.action_taken,
                    dst_domain,
                    log.country_code,
                    log.isp,
                    log.blocklist_names,
                    row.id,
                ])?;
                if log.is_close {
                    close.execute(rusqlite::params![format_timestamp(log.last_seen), row.id])?;
                }
                if let Some(entry) = known.get_mut(&triple) {
                    entry.dst_domain = dst_domain;
                    entry.closed = log.is_close;
                }
                return Ok(());
            }
            Some(row) if log.is_close => {
                // Duplicate close for an already-closed row: idempotent. The
                // first-wins `CASE` keeps the original close time.
                close.execute(rusqlite::params![format_timestamp(log.last_seen), row.id])?;
                return Ok(());
            }
            // A live flush for a closed triple, or a wholly new triple, starts
            // a fresh row below: finished connections never absorb new traffic.
            _ => {}
        }
        if is_blocked_action(&log.action_taken) {
            delta.blocked_count += 1;
        }
        insert.execute(rusqlite::params![
            format_timestamp(log.timestamp),
            log.app_id,
            log.protocol,
            log.src_ip,
            log.src_port,
            log.dst_ip,
            log.dst_port,
            log.dst_domain,
            log.bytes_sent,
            log.bytes_received,
            log.action_taken,
            format_timestamp(log.last_seen),
            log.country_code,
            log.isp,
            log.blocklist_names,
            log.conn_id,
            log.conn_pid,
            log.app_path,
        ])?;
        let row_id = row_id_to_i32(tx.last_insert_rowid())?;
        if log.is_close {
            close.execute(rusqlite::params![format_timestamp(log.last_seen), row_id])?;
        }
        known.insert(
            triple,
            ExistingConnection {
                id: row_id,
                dst_domain: log.dst_domain.clone(),
                closed: log.is_close,
            },
        );
        return Ok(());
    }
    if is_blocked_action(&log.action_taken) {
        delta.blocked_count += 1;
    }
    insert.execute(rusqlite::params![
        format_timestamp(log.timestamp),
        log.app_id,
        log.protocol,
        log.src_ip,
        log.src_port,
        log.dst_ip,
        log.dst_port,
        log.dst_domain,
        log.bytes_sent,
        log.bytes_received,
        log.action_taken,
        format_timestamp(log.last_seen),
        log.country_code,
        log.isp,
        log.blocklist_names,
        log.conn_id,
        log.conn_pid,
        log.app_path,
    ])?;
    Ok(())
}

/// Persisted identity of one connection row, for the insert-vs-update decision.
#[derive(Clone)]
struct ExistingConnection {
    id: i32,
    dst_domain: String,
    closed: bool,
}

/// Connection identity triple: session id, open-time pid, connection start.
///
/// `timestamp` is the formatted connection start; tracker flow rows always
/// carry the same `opened_at` instant, so equal instants format equally.
type ConnTriple = (i64, i32, String);

/// Looks up the persisted row for each connection triple, chunked to stay
/// inside the `SQLite` bound-parameter limit.
///
/// Takes a connection rather than `&Store` so it can run inside the caller's open
/// transaction. Its result decides insert-versus-update, so running it outside would
/// let a concurrent writer insert the same connection in between and turn one
/// connection into two rows.
fn find_connection_logs_by_conn_triples<I>(
    conn: &rusqlite::Connection,
    triples: I,
) -> Result<HashMap<ConnTriple, ExistingConnection>>
where
    I: IntoIterator<Item = ConnTriple>,
{
    const CHUNK_SIZE: usize = 200;

    let triples: Vec<ConnTriple> = triples.into_iter().collect();
    if triples.is_empty() {
        return Ok(HashMap::new());
    }

    // Row-value `IN` keeps one statement shape for every chunk — short tail
    // chunks are padded with an unmatchable `conn_id = -1` triple — so
    // `prepare_cached` reuses a single plan instead of recompiling per chunk
    // length. Live session ids start at one, so the padding never matches.
    let placeholders = (0..CHUNK_SIZE)
        .map(|_| "(?, ?, ?)".to_owned())
        .collect::<Vec<_>>()
        .join(", ");
    let sql = format!(
        "SELECT id, dst_domain, conn_id, conn_pid, timestamp, closed_at
          FROM connection_logs
          WHERE (conn_id, conn_pid, timestamp) IN ({placeholders})
          ORDER BY (closed_at = '') ASC, id ASC"
    );

    let mut found = HashMap::new();
    for chunk in triples.chunks(CHUNK_SIZE) {
        use rusqlite::types::Value;
        let mut params: Vec<Value> = Vec::with_capacity(CHUNK_SIZE * 3);
        for triple in chunk {
            params.push(Value::Integer(triple.0));
            params.push(Value::Integer(i64::from(triple.1)));
            params.push(Value::Text(triple.2.clone()));
        }
        // Pad the tail with unmatchable triples.
        while params.len() < CHUNK_SIZE * 3 {
            params.push(Value::Integer(-1));
            params.push(Value::Integer(-1));
            params.push(Value::Text(String::new()));
        }
        let mut statement = conn.prepare_cached(&sql)?;
        let rows = statement
            .query_map(rusqlite::params_from_iter(params.iter()), |row| {
                Ok((
                    (
                        row.get::<_, i64>(2)?,
                        row.get::<_, i32>(3)?,
                        row.get::<_, String>(4)?,
                    ),
                    ExistingConnection {
                        id: row.get(0)?,
                        dst_domain: row.get(1)?,
                        closed: !row.get::<_, String>(5)?.is_empty(),
                    },
                ))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        drop(statement);
        // Closed rows are a fallback for idempotent close markers. Open rows
        // sort last, with the newest id winning within each identity.
        found.extend(rows);
    }

    Ok(found)
}

fn clamp_log_limit(limit: u32) -> i32 {
    if limit == 0 {
        return DEFAULT_LOG_PAGE_SIZE;
    }
    if limit > MAX_LOG_PAGE_SIZE as u32 {
        MAX_LOG_PAGE_SIZE
    } else {
        i32::try_from(limit).unwrap_or(MAX_LOG_PAGE_SIZE)
    }
}

fn clamp_log_offset(offset: u32) -> i32 {
    i32::try_from(offset).unwrap_or(i32::MAX)
}

fn sql_string_literal(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}

fn sql_like_pattern(value: &str) -> String {
    let escaped = value
        .replace('\\', "\\\\")
        .replace('%', "\\%")
        .replace('_', "\\_");
    sql_string_literal(&format!("%{escaped}%"))
}

/// ISO alpha-2 codes rolled into United States totals (matches client analytics).
const US_TERRITORY_COUNTRY_CODES: [&str; 8] = ["US", "USA", "PR", "VI", "GU", "AS", "MP", "UM"];

fn country_filter_sql_clauses(raw: &str) -> Vec<String> {
    let upper = raw.trim().to_ascii_uppercase();
    if upper.is_empty() {
        return vec![];
    }
    if upper.eq_ignore_ascii_case("unknown") {
        return vec!["(country_code = '' OR country_code IS NULL)".to_owned()];
    }

    let codes: Vec<&str> = if upper == "US" || upper == "USA" {
        US_TERRITORY_COUNTRY_CODES.to_vec()
    } else {
        vec![upper.as_str()]
    };

    let literals = codes
        .iter()
        .map(|code| sql_string_literal(code))
        .collect::<Vec<_>>()
        .join(", ");
    vec![format!("UPPER(country_code) IN ({literals})")]
}

fn build_log_where_clause(query: &ConnectionLogQuery) -> String {
    let mut clauses = vec!["1 = 1".to_owned()];
    append_log_time_filters(
        &mut clauses,
        query.time_filter_seconds,
        query.time_window_start,
        query.time_window_end,
        "",
    );

    if let Some(action_filter) = query.action_filter.as_deref() {
        match action_filter.to_ascii_lowercase().as_str() {
            "allowed" => clauses.push(
                "(LOWER(action_taken) != 'blocked' AND LOWER(action_taken) != 'block')".to_owned(),
            ),
            "blocked" => clauses.push(
                "(LOWER(action_taken) = 'blocked' OR LOWER(action_taken) = 'block')".to_owned(),
            ),
            _ => {}
        }
    }

    if let Some(app_name) = query.app_name.as_deref().filter(|name| !name.is_empty()) {
        clauses.push(format!(
            "app_id IN (SELECT id FROM applications WHERE LOWER(app_name) = LOWER({}))",
            sql_string_literal(app_name)
        ));
    }

    // An exact row id narrows the name match above: one install path out of
    // several sharing a name. Positive ids only; 0/negative means unset and
    // preserves the legacy name-only match for older clients.
    if let Some(app_id) = query.app_id.filter(|id| *id > 0) {
        clauses.push(format!("app_id = {app_id}"));
    }

    if let Some(search_query) = query
        .search_query
        .as_deref()
        .map(str::trim)
        .filter(|query| !query.is_empty())
    {
        let pattern = sql_like_pattern(search_query);
        clauses.push(format!(
            "(dst_domain LIKE {pattern} ESCAPE '\\'
              OR dst_ip LIKE {pattern} ESCAPE '\\'
              OR src_ip LIKE {pattern} ESCAPE '\\'
              OR protocol LIKE {pattern} ESCAPE '\\'
              OR CAST(dst_port AS TEXT) LIKE {pattern} ESCAPE '\\'
              OR app_path LIKE {pattern} ESCAPE '\\'
              OR app_id IN (
                SELECT id FROM applications
                WHERE app_name LIKE {pattern} ESCAPE '\\'
                   OR app_path LIKE {pattern} ESCAPE '\\'
              ))"
        ));
    }

    if let Some(protocol) = query
        .protocol_filter
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty() && !value.eq_ignore_ascii_case("all"))
    {
        clauses.push(format!(
            "UPPER(protocol) = {}",
            sql_string_literal(&protocol.to_ascii_uppercase())
        ));
    }

    if let Some(country) = query.country_code.as_deref() {
        clauses.extend(country_filter_sql_clauses(country));
    }

    if let Some(port) = query.port {
        clauses.push(format!("dst_port = {port}"));
    }

    if let Some(host) = query
        .host
        .as_deref()
        .map(str::trim)
        .filter(|host| !host.is_empty())
    {
        let literal = sql_string_literal(host);
        clauses.push(format!(
            "(LOWER(dst_domain) = LOWER({literal}) OR dst_ip = {literal})"
        ));
    }

    clauses.join(" AND ")
}

fn is_blocked_action(action: &str) -> bool {
    let action = action.to_ascii_lowercase();
    action == "blocked" || action == "block"
}

fn append_log_time_filters(
    clauses: &mut Vec<String>,
    time_filter_seconds: u32,
    time_window_start: Option<OffsetDateTime>,
    time_window_end: Option<OffsetDateTime>,
    table_prefix: &str,
) {
    let prefix = if table_prefix.is_empty() {
        String::new()
    } else {
        format!("{table_prefix}.")
    };
    let last_seen = format!("{prefix}last_seen");
    let timestamp = format!("{prefix}timestamp");

    // A partially specified window still applies: requiring both bounds here
    // would silently widen a start-only or end-only request to all time.
    if time_window_start.is_some() || time_window_end.is_some() {
        if let Some(start) = time_window_start {
            let start = format_timestamp(start);
            clauses.push(format!(
                "({last_seen} >= '{start}' OR {timestamp} >= '{start}')"
            ));
        }
        if let Some(end) = time_window_end {
            let end = format_timestamp(end);
            clauses.push(format!("({last_seen} < '{end}' OR {timestamp} < '{end}')"));
        }
        return;
    }

    if time_filter_seconds > 0 {
        let cutoff =
            OffsetDateTime::now_utc() - time::Duration::seconds(i64::from(time_filter_seconds));
        let cutoff = format_timestamp(cutoff);
        clauses.push(format!(
            "({last_seen} >= '{cutoff}' OR {timestamp} >= '{cutoff}')"
        ));
    }
}

fn build_log_order_clause(query: &ConnectionLogQuery) -> String {
    let descending = query.sort_descending || query.order_by.is_none();
    let direction = if descending { "DESC" } else { "ASC" };

    let order_expr = match query
        .order_by
        .as_deref()
        .unwrap_or("last_seen")
        .to_ascii_lowercase()
        .as_str()
    {
        "app" | "application" => "(SELECT COALESCE(NULLIF(a.app_name, ''), 'unknown.exe') FROM applications a WHERE a.id = connection_logs.app_id)".to_owned(),
        "domain" | "host" => "dst_domain".to_owned(),
        "port" => "dst_port".to_owned(),
        "protocol" | "proto" => "protocol".to_owned(),
        "dst" | "ip" => "dst_ip".to_owned(),
        "src" | "sip" => "src_ip".to_owned(),
        "bytes_sent" | "up" => "bytes_sent".to_owned(),
        "bytes_received" | "down" => "bytes_received".to_owned(),
        "timestamp" => "timestamp".to_owned(),
        "action" | "state" => "action_taken".to_owned(),
        "country" | "geo" | "country_code" => "country_code".to_owned(),
        _ => "last_seen".to_owned(),
    };

    format!("{order_expr} {direction}, id {direction}")
}

fn map_connection_log(row: &Row) -> std::result::Result<ConnectionLog, rusqlite::Error> {
    Ok(ConnectionLog {
        is_active: false,
        id: row.get(0)?,
        timestamp: get_timestamp(row, 1)?,
        app_id: row.get(2)?,
        protocol: row.get(3)?,
        src_ip: row.get(4)?,
        src_port: row.get(5)?,
        dst_ip: row.get(6)?,
        dst_port: row.get(7)?,
        dst_domain: row.get(8)?,
        bytes_sent: row.get(9)?,
        bytes_received: row.get(10)?,
        action_taken: row.get(11)?,
        last_seen: get_timestamp(row, 12)?,
        country_code: row.get(13)?,
        isp: row.get(14)?,
        blocklist_names: row.get(15)?,
        conn_id: row.get(16)?,
        conn_pid: row.get(17)?,
        closed_at: {
            let raw: String = row.get(18)?;
            if raw.is_empty() {
                None
            } else {
                Some(parse_timestamp(&raw).map_err(|_| rusqlite::Error::InvalidColumnIndex(18))?)
            }
        },
        app_path: row.get(19)?,
    })
}

fn map_application_log_summary(
    row: &Row,
) -> std::result::Result<ApplicationLogSummary, rusqlite::Error> {
    Ok(ApplicationLogSummary {
        app_id: row.get(0)?,
        app_name: row.get(1)?,
        app_path: row.get(2)?,
        connection_count: u64::try_from(row.get::<_, i64>(3)?).unwrap_or(u64::MAX),
        blocked_count: u64::try_from(row.get::<_, i64>(4)?).unwrap_or(u64::MAX),
        bytes_sent: u64::try_from(row.get::<_, i64>(5)?).unwrap_or(u64::MAX),
        bytes_received: u64::try_from(row.get::<_, i64>(6)?).unwrap_or(u64::MAX),
        last_seen: get_timestamp(row, 7)?,
    })
}
