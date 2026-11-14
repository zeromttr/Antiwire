//! Alert notification queries.

use rusqlite::Row;

use crate::error::Result;
use crate::models::{format_timestamp, Alert, NewAlert};

use crate::store::get_timestamp;

impl crate::store::Store {
    /// Stores one notification and returns its database id.
    pub fn insert_alert(&self, alert: &NewAlert) -> Result<i64> {
        self.db.execute_insert(
            "INSERT INTO alerts (alert_type, title, message, timestamp, severity)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            rusqlite::params![
                alert.alert_type,
                alert.title,
                alert.message,
                format_timestamp(alert.timestamp),
                alert.severity,
            ],
        )
    }

    /// Inserts `alerts` in one transaction and returns their ids, in order.
    pub fn insert_alerts(&self, alerts: &[NewAlert]) -> Result<Vec<i64>> {
        if alerts.is_empty() {
            return Ok(Vec::new());
        }
        self.db.transaction_with(|tx| {
            let mut insert = tx.prepare_cached(
                "INSERT INTO alerts (alert_type, title, message, timestamp, severity)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
            )?;
            alerts
                .iter()
                .map(|alert| {
                    insert.execute(rusqlite::params![
                        alert.alert_type,
                        alert.title,
                        alert.message,
                        format_timestamp(alert.timestamp),
                        alert.severity,
                    ])?;
                    Ok(tx.last_insert_rowid())
                })
                .collect()
        })
    }

    /// Returns at most 10000 saved alerts with the newest event first.
    pub fn list_alerts(&self) -> Result<Vec<Alert>> {
        self.list_recent_alerts(10_000)
    }

    /// Returns at most `limit` saved alerts with the newest event first.
    ///
    /// The dashboard only ever renders the latest rows, so callers should prefer
    /// this over [`Self::list_alerts`] on an alerts table that grows for the
    /// lifetime of the daemon.
    pub fn list_recent_alerts(&self, limit: usize) -> Result<Vec<Alert>> {
        let limit = i64::try_from(limit.min(10_000)).unwrap_or(10_000);
        self.db.query_map(
            "SELECT id, alert_type, title, message, timestamp, severity
             FROM alerts
             ORDER BY timestamp DESC, id DESC
             LIMIT ?1",
            rusqlite::params![limit],
            map_alert,
        )
    }

    /// Removes one alert, returning whether it existed. Deleting a missing
    /// alert is not an error, since another window may have dismissed it.
    pub fn delete_alert(&self, id: i64) -> Result<bool> {
        let deleted = self
            .db
            .execute("DELETE FROM alerts WHERE id = ?1", rusqlite::params![id])?;
        Ok(deleted > 0)
    }

    /// Removes every saved alert and returns the number of deleted rows.
    pub fn clear_alerts(&self) -> Result<u64> {
        self.db.execute("DELETE FROM alerts", [])
    }
}

fn map_alert(row: &Row<'_>) -> rusqlite::Result<Alert> {
    Ok(Alert {
        id: row.get(0)?,
        alert_type: row.get(1)?,
        title: row.get(2)?,
        message: row.get(3)?,
        timestamp: get_timestamp(row, 4)?,
        severity: row.get(5)?,
    })
}
