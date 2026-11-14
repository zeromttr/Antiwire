//! Firewall rule queries, including the CIDR payload table.

use std::collections::HashMap;

use rusqlite::Row;

use antiwire_policy::{RuleDirection, RuleTargetKind, Verdict};

use crate::error::{Result, StoreError};
use crate::models::{format_timestamp, FirewallRule};

use crate::store::{get_timestamp, row_id_to_i32};

impl crate::store::Store {
    /// Returns every readable firewall rule ordered by creation time.
    ///
    /// A row this build cannot read is logged and left out, so one damaged
    /// row cannot hide every other rule.
    pub fn list_rules(&self) -> Result<Vec<FirewallRule>> {
        self.db
            .query_map(
                "SELECT id, target_type, target_value, action, direction, created_at
                 FROM firewall_rules
                 ORDER BY created_at ASC, id ASC",
                [],
                read_firewall_rule,
            )
            .map(readable_rules)
    }

    /// Returns a single firewall rule by id.
    ///
    /// # Errors
    ///
    /// [`StoreError::RuleNotFound`] when no row has `id`, and
    /// [`StoreError::UnreadableRule`] when the row cannot be read.
    pub fn get_rule(&self, id: i32) -> Result<FirewallRule> {
        self.db
            .query_optional(
                "SELECT id, target_type, target_value, action, direction, created_at
                 FROM firewall_rules
                 WHERE id = ?1",
                rusqlite::params![id],
                read_firewall_rule,
            )?
            .ok_or(StoreError::RuleNotFound(id))?
    }

    /// Returns every APPLICATION rule ordered by creation time.
    ///
    /// Used to re-point rules after an application updates in place. The
    /// caller matches targets in memory because a rule can be left behind on
    /// any earlier version directory, not just the immediately previous one;
    /// filtering by one exact target would miss those.
    pub fn list_application_rules(&self) -> Result<Vec<FirewallRule>> {
        self.db
            .query_map(
                "SELECT id, target_type, target_value, action, direction, created_at
                 FROM firewall_rules
                 WHERE UPPER(target_type) IN ('APPLICATION', 'APP')
                 ORDER BY created_at ASC, id ASC",
                [],
                read_firewall_rule,
            )
            .map(readable_rules)
    }

    /// Inserts a new firewall rule and returns the assigned id.
    pub fn insert_rule(&self, rule: &FirewallRule) -> Result<i32> {
        let row_id = self.db.execute_insert(
            "INSERT INTO firewall_rules (target_type, target_value, action, direction, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            rusqlite::params![
                rule.target_type.as_str(),
                rule.target_value,
                rule.action.as_str(),
                rule.direction.as_str(),
                format_timestamp(rule.created_at),
            ],
        )?;
        row_id_to_i32(row_id)
    }

    /// Inserts a rule together with its CIDR payload and returns the new id.
    ///
    /// Both writes share one transaction, so a rule can never be persisted with
    /// a partial network list.
    pub fn insert_rule_with_cidrs(&self, rule: &FirewallRule, cidrs: &[String]) -> Result<i32> {
        self.db.transaction_with(|tx| {
            tx.execute(
                "INSERT INTO firewall_rules (target_type, target_value, action, direction, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                rusqlite::params![
                    rule.target_type.as_str(),
                    rule.target_value,
                    rule.action.as_str(),
                    rule.direction.as_str(),
                    format_timestamp(rule.created_at),
                ],
            )?;
            let rule_id = row_id_to_i32(tx.last_insert_rowid())?;

            // One prepared statement reused across every network: a large
            // country list is tens of thousands of rows.
            let mut statement = tx.prepare(
                "INSERT INTO firewall_rule_cidrs (rule_id, cidr, ordinal) VALUES (?1, ?2, ?3)",
            )?;
            for (ordinal, cidr) in cidrs.iter().enumerate() {
                let ordinal = i64::try_from(ordinal).unwrap_or(i64::MAX);
                statement.execute(rusqlite::params![rule_id, cidr, ordinal])?;
            }
            drop(statement);

            Ok(rule_id)
        })
    }

    /// Returns the CIDR payload for one rule in insertion order.
    #[cfg(any(test, feature = "test-support"))]
    pub fn list_rule_cidrs(&self, rule_id: i32) -> Result<Vec<String>> {
        self.db.query_map(
            "SELECT cidr FROM firewall_rule_cidrs WHERE rule_id = ?1 ORDER BY ordinal ASC, id ASC",
            rusqlite::params![rule_id],
            |row| row.get::<_, String>(0),
        )
    }

    /// Returns every CIDR payload grouped by rule id.
    ///
    /// One query for the whole table, so daemon startup does not issue a
    /// round trip per rule.
    pub fn list_all_rule_cidrs(&self) -> Result<HashMap<i32, Vec<String>>> {
        let rows = self.db.query_map(
            "SELECT rule_id, cidr FROM firewall_rule_cidrs ORDER BY rule_id ASC, ordinal ASC, id ASC",
            [],
            |row| Ok((row.get::<_, i32>(0)?, row.get::<_, String>(1)?)),
        )?;
        let mut grouped: HashMap<i32, Vec<String>> = HashMap::new();
        for (rule_id, cidr) in rows {
            grouped.entry(rule_id).or_default().push(cidr);
        }
        Ok(grouped)
    }

    /// Returns how many CIDRs each rule owns.
    ///
    /// Lets listing summarize a country block without loading its networks.
    pub fn count_rule_cidrs_by_rule(&self) -> Result<HashMap<i32, i64>> {
        let rows = self.db.query_map(
            "SELECT rule_id, COUNT(*) FROM firewall_rule_cidrs GROUP BY rule_id",
            [],
            |row| Ok((row.get::<_, i32>(0)?, row.get::<_, i64>(1)?)),
        )?;
        Ok(rows.into_iter().collect())
    }

    /// Updates an existing firewall rule.
    pub fn update_rule(&self, rule: &FirewallRule) -> Result<()> {
        let updated = self.db.execute(
            "UPDATE firewall_rules
             SET target_type = ?2, target_value = ?3, action = ?4, direction = ?5, created_at = ?6
             WHERE id = ?1",
            rusqlite::params![
                rule.id,
                rule.target_type.as_str(),
                rule.target_value,
                rule.action.as_str(),
                rule.direction.as_str(),
                format_timestamp(rule.created_at),
            ],
        )?;
        if updated == 0 {
            return Err(StoreError::RuleNotFound(rule.id));
        }
        Ok(())
    }

    /// Deletes a firewall rule by id.
    pub fn delete_rule(&self, id: i32) -> Result<()> {
        let deleted = self.db.execute(
            "DELETE FROM firewall_rules WHERE id = ?1",
            rusqlite::params![id],
        )?;
        if deleted == 0 {
            return Err(StoreError::RuleNotFound(id));
        }
        Ok(())
    }
}

/// Reads one rule row.
///
/// A target kind, action, or direction this build does not know is an error
/// rather than a guess: defaulting it would show and enforce a rule the user
/// never made.
fn read_firewall_rule(row: &Row<'_>) -> rusqlite::Result<Result<FirewallRule>> {
    let id: i32 = row.get(0)?;
    let target_type: String = row.get(1)?;
    let action: String = row.get(3)?;
    let direction: String = row.get(4)?;
    let unreadable = |field: &str, value: &str| StoreError::UnreadableRule {
        id,
        reason: format!("unknown {field} {value:?}"),
    };
    let Some(target_type) = RuleTargetKind::parse(&target_type) else {
        return Ok(Err(unreadable("target type", &target_type)));
    };
    let Some(action) = Verdict::parse(&action) else {
        return Ok(Err(unreadable("action", &action)));
    };
    let Some(direction) = RuleDirection::parse(&direction) else {
        return Ok(Err(unreadable("direction", &direction)));
    };
    Ok(Ok(FirewallRule {
        id,
        target_type,
        target_value: row.get(2)?,
        action,
        direction,
        created_at: get_timestamp(row, 5)?,
    }))
}

fn readable_rules(rows: Vec<Result<FirewallRule>>) -> Vec<FirewallRule> {
    rows.into_iter()
        .filter_map(|row| {
            row.map_err(|error| tracing::warn!(%error, "skipping an unreadable firewall rule"))
                .ok()
        })
        .collect()
}
