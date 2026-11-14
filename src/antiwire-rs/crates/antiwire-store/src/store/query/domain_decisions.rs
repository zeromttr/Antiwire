//! Persisted `TypeSafe` ratings and the applied decision, one row per domain.

use std::collections::HashMap;
use std::num::NonZeroUsize;
use std::time::{Duration, Instant};

use lru::LruCache;
use parking_lot::Mutex;
use rusqlite::{OptionalExtension, Row};
use time::OffsetDateTime;

use crate::error::{Result, StoreError};
use crate::models::{
    bool_to_i64, format_timestamp, i64_to_bool, normalize_scan_tier, parse_timestamp,
    DomainDecision, DomainDecisionPage, DomainDecisionQuery, DomainDecisionVerdictFilter,
    DomainLookup,
};

use crate::store::get_timestamp;

fn join_list(items: &[String]) -> String {
    items.join("\n")
}

fn split_list(value: &str) -> Vec<String> {
    if value.is_empty() {
        Vec::new()
    } else {
        value.split('\n').map(str::to_owned).collect()
    }
}

fn optional_time(value: Option<String>) -> rusqlite::Result<Option<OffsetDateTime>> {
    value
        .map(|text| {
            parse_timestamp(&text).map_err(|error| {
                rusqlite::Error::FromSqlConversionFailure(
                    0,
                    rusqlite::types::Type::Text,
                    Box::new(error),
                )
            })
        })
        .transpose()
}

fn map_domain_lookup(row: &Row<'_>) -> rusqlite::Result<DomainLookup> {
    Ok(DomainLookup {
        domain: row.get(0)?,
        source: row.get(1)?,
        registrar: row.get(2)?,
        registrar_id: row.get(3)?,
        statuses: split_list(&row.get::<_, String>(4)?),
        nameservers: split_list(&row.get::<_, String>(5)?),
        registered_at: optional_time(row.get(6)?)?,
        expires_at: optional_time(row.get(7)?)?,
        registry_updated_at: optional_time(row.get(8)?)?,
        registrant_name: row.get(9)?,
        registrant_organization: row.get(10)?,
        redacted: i64_to_bool(row.get(11)?),
        dnssec: row.get::<_, Option<i64>>(12)?.map(i64_to_bool),
        fetched_at: optional_time(Some(row.get(13)?))?.expect("fetched_at"),
    })
}

const DOMAIN_DECISION_COLUMNS: &str = "
    domain, model, rating_advertising, rating_tracking, rating_telemetry, rating_analytics,
    rating_malicious, rating_fraud, rating_cryptomining, rating_tunnel, verdict, top_category,
    top_score, scan_tier, first_seen, updated_at,
    rating_newly_registered, rating_registry_hold, rating_hidden_registrant,
    rating_abusive_registrar";

const SELECT_DOMAIN_DECISION: &str = "SELECT
    domain, model, rating_advertising, rating_tracking, rating_telemetry, rating_analytics,
    rating_malicious, rating_fraud, rating_cryptomining, rating_tunnel, verdict, top_category,
    top_score, scan_tier, first_seen, updated_at,
    rating_newly_registered, rating_registry_hold, rating_hidden_registrant,
    rating_abusive_registrar
  FROM domain_decisions WHERE domain = ?1";

const DEFAULT_DECISION_PAGE_SIZE: usize = 100;
const MAX_DECISION_PAGE_SIZE: usize = 500;
/// How long a delete suppresses an in-flight classification from saving that domain.
///
/// Background persist retries finish well inside this window. After it, a new
/// classification may save the domain again.
const DECISION_DELETE_GUARD: Duration = Duration::from_secs(180);

/// Bound as `?1`: NULL matches every domain.
const DECISION_SEARCH_CLAUSE: &str = "(?1 IS NULL OR domain LIKE ?1 ESCAPE '\\')";

/// When work on a domain began, taken before its network calls.
///
/// A save that carries a fence is dropped if the domain was deleted after the
/// fence was taken, so a classification or registry lookup that was already
/// running cannot bring back a row the user just deleted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct DeletionFence(Instant);

impl DeletionFence {
    /// A fence at this moment.
    #[must_use]
    pub fn now() -> Self {
        Self(Instant::now())
    }
}

impl DomainDecisionVerdictFilter {
    const fn sql_clause(self) -> &'static str {
        match self {
            Self::All => "1 = 1",
            Self::Block => "verdict = 'block'",
            Self::Record => "verdict = 'record'",
            Self::Clean => "verdict NOT IN ('block', 'record')",
        }
    }
}

struct CacheEntry {
    decision: DomainDecision,
    cached_at: Instant,
}

/// What memory alone knows about a domain's saved decision.
#[derive(Debug, Clone, PartialEq)]
#[expect(
    clippy::large_enum_variant,
    reason = "read once per DNS query; boxing the decision would add an allocation to each read"
)]
pub enum ResidentDecision {
    /// The saved decision.
    Saved(DomainDecision),
    /// SQLite was read within [`antiwire_tuning::DNS_AI_DECISION_CACHE_TTL`]
    /// and has no decision for the domain.
    NotSaved,
    /// Not in memory. Only [`crate::Store::get_domain_decision`] can tell.
    Unknown,
}

/// A [`ResidentDecision`], and whether it is about to leave memory.
#[derive(Debug, Clone, PartialEq)]
pub struct Resident {
    pub decision: ResidentDecision,
    /// The entry is within [`antiwire_tuning::DNS_AI_DECISION_REFRESH_LEAD`]
    /// of expiring. A caller that keeps deciding from memory should have
    /// [`crate::Store::reload_domain_decision`] run off its own path.
    pub refresh_due: bool,
}

impl Resident {
    const UNKNOWN: Self = Self {
        decision: ResidentDecision::Unknown,
        refresh_due: false,
    };

    /// `decision` as read at `read_at`, or [`Self::UNKNOWN`] once that is
    /// too long ago to rely on.
    fn aged(read_at: Instant, decision: impl FnOnce() -> ResidentDecision) -> Self {
        let ttl = antiwire_tuning::DNS_AI_DECISION_CACHE_TTL;
        let age = read_at.elapsed();
        if age >= ttl {
            return Self::UNKNOWN;
        }
        Self {
            decision: decision(),
            refresh_due: age >= ttl.saturating_sub(antiwire_tuning::DNS_AI_DECISION_REFRESH_LEAD),
        }
    }
}

/// Saved decisions, and the domains a read found none for. The write lock in
/// Store serializes fills with commits; the cache lock itself is never held
/// during SQLite I/O.
pub(crate) struct DecisionCache {
    entries: Mutex<Residents>,
    /// Domains deleted in this process, so an older in-flight save cannot recreate them.
    deleted_at: Mutex<HashMap<String, Instant>>,
}

/// Both halves under one lock, so a domain is never in both at once.
struct Residents {
    saved: LruCache<String, CacheEntry>,
    /// Domains SQLite had no decision for, by when it was read. Kept apart
    /// from `saved` so a run of never-classified names cannot evict the
    /// decisions that are enforced from memory.
    not_saved: LruCache<String, Instant>,
}

impl DecisionCache {
    pub(crate) fn new() -> Self {
        let capacity = NonZeroUsize::new(antiwire_tuning::DNS_AI_DECISION_CACHE_CAP)
            .expect("AI decision cache capacity must be nonzero");
        Self {
            entries: Mutex::new(Residents {
                saved: LruCache::new(capacity),
                not_saved: LruCache::new(capacity),
            }),
            deleted_at: Mutex::new(HashMap::new()),
        }
    }

    fn mark_deleted(&self, domain: &str) {
        let mut deleted = self.deleted_at.lock();
        let now = Instant::now();
        deleted.retain(|_, at| now.saturating_duration_since(*at) < DECISION_DELETE_GUARD);
        deleted.insert(domain.to_owned(), now);
    }

    fn deleted_after(&self, domain: &str, fence: DeletionFence) -> bool {
        let mut deleted = self.deleted_at.lock();
        let Some(at) = deleted.get(domain).copied() else {
            return false;
        };
        if at.elapsed() >= DECISION_DELETE_GUARD {
            deleted.remove(domain);
            return false;
        }
        at > fence.0
    }

    fn get(&self, domain: &str) -> Option<DomainDecision> {
        match self.resident(domain).decision {
            ResidentDecision::Saved(decision) => Some(decision),
            ResidentDecision::NotSaved | ResidentDecision::Unknown => None,
        }
    }

    fn resident(&self, domain: &str) -> Resident {
        let mut entries = self.entries.lock();
        let resident = if let Some(entry) = entries.saved.get(domain) {
            Resident::aged(entry.cached_at, || {
                ResidentDecision::Saved(entry.decision.clone())
            })
        } else if let Some(read_at) = entries.not_saved.get(domain) {
            Resident::aged(*read_at, || ResidentDecision::NotSaved)
        } else {
            return Resident::UNKNOWN;
        };
        if resident.decision == ResidentDecision::Unknown {
            entries.saved.pop(domain);
            entries.not_saved.pop(domain);
        }
        resident
    }

    fn insert(&self, decision: DomainDecision) {
        let mut entries = self.entries.lock();
        entries.not_saved.pop(&decision.domain);
        entries.saved.put(
            decision.domain.clone(),
            CacheEntry {
                decision,
                cached_at: Instant::now(),
            },
        );
    }

    /// Records that SQLite, read just now, has no decision for `domain`.
    fn insert_not_saved(&self, domain: &str) {
        let mut entries = self.entries.lock();
        entries.saved.pop(domain);
        entries.not_saved.put(domain.to_owned(), Instant::now());
    }

    /// Forgets everything about `domain`, so the next read asks SQLite.
    fn remove(&self, domain: &str) {
        let mut entries = self.entries.lock();
        entries.saved.pop(domain);
        entries.not_saved.pop(domain);
    }

    /// Updates the verdict fields of a resident entry. A miss leaves the cache
    /// empty so the next read fills it from the row just written.
    fn revise_outcome(&self, domain: &str, verdict: &str, top_category: &str, top_score: f64) {
        let mut entries = self.entries.lock();
        // The row exists: it was just updated.
        entries.not_saved.pop(domain);
        let Some(entry) = entries.saved.get_mut(domain) else {
            return;
        };
        verdict.clone_into(&mut entry.decision.verdict);
        top_category.clone_into(&mut entry.decision.top_category);
        entry.decision.top_score = top_score;
    }
}

impl crate::store::Store {
    /// Inserts or replaces the decision record for `decision.domain`.
    ///
    /// `first_seen` is preserved across updates; every other column, including
    /// `updated_at`, is replaced with the incoming values.
    pub fn upsert_domain_decision(&self, decision: &DomainDecision) -> Result<()> {
        self.upsert_domain_decision_unless_deleted(decision, None)
            .map(|_| ())
    }

    /// Inserts `decision` only when the row is absent and was not deleted after `fence`.
    ///
    /// An existing row is left unchanged, so a late classification cannot replace
    /// a newer save. Returns whether a row was inserted.
    pub fn insert_domain_decision_if_absent(
        &self,
        decision: &DomainDecision,
        fence: DeletionFence,
    ) -> Result<bool> {
        let domain = normalize_domain_key(&decision.domain)?;
        let _write = self.decision_write_lock.lock();
        if self.decision_cache.deleted_after(&domain, fence) {
            return Ok(false);
        }
        let inserted = self.write_domain_decision(
            "INSERT INTO domain_decisions (
                domain, model, rating_advertising, rating_tracking, rating_telemetry,
                rating_analytics, rating_malicious, rating_fraud, rating_cryptomining, rating_tunnel,
                verdict, top_category, top_score, scan_tier, first_seen, updated_at,
                rating_newly_registered, rating_registry_hold, rating_hidden_registrant,
                rating_abusive_registrar
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20)
             ON CONFLICT(domain) DO NOTHING",
            &domain,
            decision,
        )?;
        if inserted == 0 {
            return Ok(false);
        }
        self.remember_decision(&domain);
        Ok(true)
    }

    /// Replaces the saved decision unless `fence` is set and the domain was
    /// deleted after it. Returns whether the row was written.
    pub fn upsert_domain_decision_unless_deleted(
        &self,
        decision: &DomainDecision,
        fence: Option<DeletionFence>,
    ) -> Result<bool> {
        let domain = normalize_domain_key(&decision.domain)?;
        let _write = self.decision_write_lock.lock();
        if fence.is_some_and(|fence| self.decision_cache.deleted_after(&domain, fence)) {
            return Ok(false);
        }
        self.write_domain_decision(
            "INSERT INTO domain_decisions (
                domain, model, rating_advertising, rating_tracking, rating_telemetry,
                rating_analytics, rating_malicious, rating_fraud, rating_cryptomining, rating_tunnel,
                verdict, top_category, top_score, scan_tier, first_seen, updated_at,
                rating_newly_registered, rating_registry_hold, rating_hidden_registrant,
                rating_abusive_registrar
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20)
             ON CONFLICT(domain) DO UPDATE SET
                model = excluded.model,
                rating_advertising = excluded.rating_advertising,
                rating_tracking = excluded.rating_tracking,
                rating_telemetry = excluded.rating_telemetry,
                rating_analytics = excluded.rating_analytics,
                rating_malicious = excluded.rating_malicious,
                rating_fraud = excluded.rating_fraud,
                rating_cryptomining = excluded.rating_cryptomining,
                rating_tunnel = excluded.rating_tunnel,
                verdict = excluded.verdict,
                top_category = excluded.top_category,
                top_score = excluded.top_score,
                scan_tier = excluded.scan_tier,
                updated_at = excluded.updated_at,
                rating_newly_registered = excluded.rating_newly_registered,
                rating_registry_hold = excluded.rating_registry_hold,
                rating_hidden_registrant = excluded.rating_hidden_registrant,
                rating_abusive_registrar = excluded.rating_abusive_registrar",
            &domain,
            decision,
        )?;
        // Read back the committed row: ON CONFLICT preserves first_seen and
        // normalizes scan_tier, so the caller's value is not always identical.
        self.remember_decision(&domain);
        Ok(true)
    }

    /// Writes the advanced decision and, when `lookup` is set, its registration
    /// row in one transaction. A lookup failure rolls the decision back, so the
    /// caller does not keep a new verdict after reporting failure.
    ///
    /// Returns false, saving nothing, when the decision's domain was deleted
    /// after `fence`. The registration row may belong to a parent domain
    /// (`example.com` for `sub.example.com`). If only that domain was deleted,
    /// the decision is still saved and just the stale registration row is
    /// dropped.
    pub fn save_advanced_check(
        &self,
        decision: &DomainDecision,
        fence: DeletionFence,
        lookup: Option<&DomainLookup>,
    ) -> Result<bool> {
        let domain = normalize_domain_key(&decision.domain)?;
        let lookup_domain = lookup
            .map(|lookup| normalize_domain_key(&lookup.domain))
            .transpose()?;
        let _write = self.decision_write_lock.lock();
        if self.decision_cache.deleted_after(&domain, fence) {
            return Ok(false);
        }
        let lookup_domain = lookup_domain
            .filter(|lookup_domain| !self.decision_cache.deleted_after(lookup_domain, fence));
        self.db.transaction_with(|tx| {
            Self::write_domain_decision_tx(tx, &domain, decision)?;
            if let Some((lookup, lookup_domain)) = lookup.zip(lookup_domain.as_ref()) {
                Self::write_domain_lookup_tx(tx, lookup_domain, lookup)?;
            }
            Ok(())
        })?;
        self.remember_decision(&domain);
        Ok(true)
    }

    /// Returns a resident saved decision without touching SQLite. A missing
    /// entry means only that the caller must use `get_domain_decision`.
    pub fn cached_domain_decision(&self, domain: &str) -> Option<DomainDecision> {
        let domain = normalize_domain_key(domain).ok()?;
        self.decision_cache.get(&domain)
    }

    /// What memory alone knows about `domain`'s saved decision, without
    /// touching SQLite: the decision, that a recent read found none, or
    /// nothing. Every write in this process replaces what is remembered, so
    /// only another process's write can be missed, and for no longer than
    /// [`antiwire_tuning::DNS_AI_DECISION_CACHE_TTL`].
    #[must_use]
    pub fn resident_domain_decision(&self, domain: &str) -> Resident {
        normalize_domain_key(domain).map_or(Resident::UNKNOWN, |domain| {
            self.decision_cache.resident(&domain)
        })
    }

    /// Reads `domain`'s decision from SQLite again, whatever memory holds,
    /// and remembers what it finds for a new residency period.
    pub fn reload_domain_decision(&self, domain: &str) -> Result<Option<DomainDecision>> {
        let domain = normalize_domain_key(domain)?;
        let _write = self.decision_write_lock.lock();
        self.read_through(&domain)
    }

    /// Makes what memory holds for `domain` look `age` old.
    #[cfg(any(test, feature = "test-support"))]
    pub fn age_resident_decision(&self, domain: &str, age: std::time::Duration) {
        let Some(read_at) = Instant::now().checked_sub(age) else {
            return;
        };
        let mut entries = self.decision_cache.entries.lock();
        if let Some(entry) = entries.saved.get_mut(domain) {
            entry.cached_at = read_at;
        }
        if let Some(entry) = entries.not_saved.get_mut(domain) {
            *entry = read_at;
        }
    }

    /// Returns the decision record for `domain`, if it has been classified.
    pub fn get_domain_decision(&self, domain: &str) -> Result<Option<DomainDecision>> {
        let domain = normalize_domain_key(domain)?;
        if let Some(cached) = self.decision_cache.get(&domain) {
            return Ok(Some(cached));
        }
        let _write = self.decision_write_lock.lock();
        if let Some(cached) = self.decision_cache.get(&domain) {
            return Ok(Some(cached));
        }
        self.read_through(&domain)
    }

    /// Reads the row for the normalized `domain` and remembers what it finds.
    /// The caller holds the write lock, so no save in this process falls
    /// between the read and the note of it.
    fn read_through(&self, domain: &str) -> Result<Option<DomainDecision>> {
        let stored = self.db.query_optional(
            SELECT_DOMAIN_DECISION,
            rusqlite::params![domain],
            map_domain_decision,
        )?;
        match &stored {
            Some(decision) => self.decision_cache.insert(decision.clone()),
            None => self.decision_cache.insert_not_saved(domain),
        }
        Ok(stored)
    }

    /// Decisions with a domain key strictly after `after_domain`, in key order.
    ///
    /// Pass `""` to start at the first row. Used to recompute verdicts without
    /// loading the whole table at once.
    pub fn list_domain_decisions_after(
        &self,
        after_domain: &str,
        limit: usize,
    ) -> Result<Vec<DomainDecision>> {
        let limit = i64::try_from(limit.clamp(1, MAX_DECISION_PAGE_SIZE)).unwrap_or(i64::MAX);
        self.db.query_map(
            &format!(
                "SELECT {DOMAIN_DECISION_COLUMNS}
                 FROM domain_decisions WHERE domain > ?1 ORDER BY domain LIMIT ?2"
            ),
            rusqlite::params![after_domain, limit],
            map_domain_decision,
        )
    }

    /// Replaces the applied verdict for one domain, leaving scores and timestamps.
    ///
    /// Returns whether a row changed. The in-memory copy is updated too, so a
    /// later cache hit does not keep the verdict from before this write.
    pub fn revise_domain_decision_outcome(
        &self,
        domain: &str,
        verdict: &str,
        top_category: &str,
        top_score: f64,
    ) -> Result<bool> {
        let domain = normalize_domain_key(domain)?;
        let _write = self.decision_write_lock.lock();
        let Some(current) = self.db.query_optional(
            SELECT_DOMAIN_DECISION,
            rusqlite::params![domain],
            map_domain_decision,
        )?
        else {
            self.decision_cache.remove(&domain);
            return Ok(false);
        };
        if current.verdict == verdict
            && current.top_category == top_category
            && (current.top_score - top_score).abs() <= f64::EPSILON
        {
            return Ok(false);
        }
        self.db.execute(
            "UPDATE domain_decisions
             SET verdict = ?2, top_category = ?3, top_score = ?4
             WHERE domain = ?1",
            rusqlite::params![domain, verdict, top_category, top_score],
        )?;
        self.decision_cache
            .revise_outcome(&domain, verdict, top_category, top_score);
        Ok(true)
    }

    /// Deletes the saved decision for `domain` from SQLite and the cache.
    ///
    /// Returns the row that was removed, read in the same statement, so the
    /// caller learns the verdict that stopped applying. A missing row still
    /// drops a stale cache entry so a later lookup cannot reuse a decision
    /// that no longer exists. Equivalent names (`Example.COM.`) share one key.
    pub fn delete_domain_decision(&self, domain: &str) -> Result<Option<DomainDecision>> {
        let domain = normalize_domain_key(domain)?;
        let _write = self.decision_write_lock.lock();
        let deleted = self.db.transaction_with(|tx| {
            let deleted = tx
                .query_row(
                    &format!(
                        "DELETE FROM domain_decisions WHERE domain = ?1
                         RETURNING {DOMAIN_DECISION_COLUMNS}"
                    ),
                    rusqlite::params![domain],
                    map_domain_decision,
                )
                .optional()?;
            tx.execute(
                "DELETE FROM domain_lookups WHERE domain = ?1",
                rusqlite::params![domain],
            )?;
            Ok(deleted)
        })?;
        self.decision_cache.remove(&domain);
        // A first lookup or classification may still be running even when
        // there was no decision row to delete.
        self.decision_cache.mark_deleted(&domain);
        Ok(deleted)
    }

    /// Replaces a registration record unless the domain was deleted after
    /// `fence`, which is taken before the network lookup begins. Returns
    /// whether the record was saved.
    pub fn upsert_domain_lookup(
        &self,
        lookup: &DomainLookup,
        fence: DeletionFence,
    ) -> Result<bool> {
        let domain = normalize_domain_key(&lookup.domain)?;
        let _write = self.decision_write_lock.lock();
        if self.decision_cache.deleted_after(&domain, fence) {
            return Ok(false);
        }
        self.db.transaction_with(|tx| {
            Self::write_domain_lookup_tx(tx, &domain, lookup)?;
            Ok(())
        })?;
        Ok(true)
    }

    /// The saved registration record, if one was stored.
    pub fn get_domain_lookup(&self, domain: &str) -> Result<Option<DomainLookup>> {
        let domain = normalize_domain_key(domain)?;
        self.db.query_optional(
            "SELECT domain, source, registrar, registrar_id, statuses, nameservers,
                    registered_at, expires_at, registry_updated_at, registrant_name,
                    registrant_organization, redacted, dnssec, fetched_at
             FROM domain_lookups WHERE domain = ?1",
            rusqlite::params![domain],
            map_domain_lookup,
        )
    }

    fn write_domain_decision(
        &self,
        sql: &str,
        domain: &str,
        decision: &DomainDecision,
    ) -> Result<u64> {
        let scan_tier = normalize_scan_tier(&decision.scan_tier);
        let first_seen = format_timestamp(decision.first_seen);
        let updated_at = format_timestamp(decision.updated_at);
        self.db.execute(
            sql,
            rusqlite::params![
                domain,
                decision.model,
                decision.rating_advertising,
                decision.rating_tracking,
                decision.rating_telemetry,
                decision.rating_analytics,
                decision.rating_malicious,
                decision.rating_fraud,
                decision.rating_cryptomining,
                decision.rating_tunnel,
                decision.verdict,
                decision.top_category,
                decision.top_score,
                scan_tier,
                first_seen,
                updated_at,
                decision.rating_newly_registered,
                decision.rating_registry_hold,
                decision.rating_hidden_registrant,
                decision.rating_abusive_registrar,
            ],
        )
    }

    fn write_domain_decision_tx(
        tx: &rusqlite::Transaction<'_>,
        domain: &str,
        decision: &DomainDecision,
    ) -> Result<usize> {
        let scan_tier = normalize_scan_tier(&decision.scan_tier);
        tx.execute(
            "INSERT INTO domain_decisions (
                domain, model, rating_advertising, rating_tracking, rating_telemetry,
                rating_analytics, rating_malicious, rating_fraud, rating_cryptomining, rating_tunnel,
                verdict, top_category, top_score, scan_tier, first_seen, updated_at,
                rating_newly_registered, rating_registry_hold, rating_hidden_registrant,
                rating_abusive_registrar
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20)
             ON CONFLICT(domain) DO UPDATE SET
                model = excluded.model,
                rating_advertising = excluded.rating_advertising,
                rating_tracking = excluded.rating_tracking,
                rating_telemetry = excluded.rating_telemetry,
                rating_analytics = excluded.rating_analytics,
                rating_malicious = excluded.rating_malicious,
                rating_fraud = excluded.rating_fraud,
                rating_cryptomining = excluded.rating_cryptomining,
                rating_tunnel = excluded.rating_tunnel,
                verdict = excluded.verdict,
                top_category = excluded.top_category,
                top_score = excluded.top_score,
                scan_tier = excluded.scan_tier,
                updated_at = excluded.updated_at,
                rating_newly_registered = excluded.rating_newly_registered,
                rating_registry_hold = excluded.rating_registry_hold,
                rating_hidden_registrant = excluded.rating_hidden_registrant,
                rating_abusive_registrar = excluded.rating_abusive_registrar",
            rusqlite::params![
                domain,
                decision.model,
                decision.rating_advertising,
                decision.rating_tracking,
                decision.rating_telemetry,
                decision.rating_analytics,
                decision.rating_malicious,
                decision.rating_fraud,
                decision.rating_cryptomining,
                decision.rating_tunnel,
                decision.verdict,
                decision.top_category,
                decision.top_score,
                scan_tier,
                format_timestamp(decision.first_seen),
                format_timestamp(decision.updated_at),
                decision.rating_newly_registered,
                decision.rating_registry_hold,
                decision.rating_hidden_registrant,
                decision.rating_abusive_registrar,
            ],
        )
        .map_err(Into::into)
    }

    fn write_domain_lookup_tx(
        tx: &rusqlite::Transaction<'_>,
        domain: &str,
        lookup: &DomainLookup,
    ) -> Result<usize> {
        tx.execute(
            "INSERT INTO domain_lookups (
                domain, source, registrar, registrar_id, statuses, nameservers,
                registered_at, expires_at, registry_updated_at, registrant_name,
                registrant_organization, redacted, dnssec, fetched_at
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)
             ON CONFLICT(domain) DO UPDATE SET
                source = excluded.source,
                registrar = excluded.registrar,
                registrar_id = excluded.registrar_id,
                statuses = excluded.statuses,
                nameservers = excluded.nameservers,
                registered_at = excluded.registered_at,
                expires_at = excluded.expires_at,
                registry_updated_at = excluded.registry_updated_at,
                registrant_name = excluded.registrant_name,
                registrant_organization = excluded.registrant_organization,
                redacted = excluded.redacted,
                dnssec = excluded.dnssec,
                fetched_at = excluded.fetched_at",
            rusqlite::params![
                domain,
                lookup.source,
                lookup.registrar,
                lookup.registrar_id,
                join_list(&lookup.statuses),
                join_list(&lookup.nameservers),
                lookup.registered_at.map(format_timestamp),
                lookup.expires_at.map(format_timestamp),
                lookup.registry_updated_at.map(format_timestamp),
                lookup.registrant_name,
                lookup.registrant_organization,
                bool_to_i64(lookup.redacted),
                lookup.dnssec.map(bool_to_i64),
                format_timestamp(lookup.fetched_at),
            ],
        )
        .map_err(Into::into)
    }

    fn remember_decision(&self, domain: &str) {
        match self.db.query_optional(
            SELECT_DOMAIN_DECISION,
            rusqlite::params![domain],
            map_domain_decision,
        ) {
            Ok(Some(stored)) => self.decision_cache.insert(stored),
            _ => self.decision_cache.remove(domain),
        }
    }

    /// Returns one page of saved decisions, most recently updated first.
    ///
    /// A `limit` of 0 selects the default page size; larger requests are capped.
    pub fn query_domain_decisions(
        &self,
        query: &DomainDecisionQuery,
    ) -> Result<DomainDecisionPage> {
        let limit = match query.limit {
            0 => DEFAULT_DECISION_PAGE_SIZE,
            limit => limit.min(MAX_DECISION_PAGE_SIZE),
        };
        let limit = i64::try_from(limit).unwrap_or(i64::MAX);
        let offset = i64::try_from(query.offset).unwrap_or(i64::MAX);
        let pattern = query
            .search_query
            .as_deref()
            .map(str::trim)
            .filter(|search| !search.is_empty())
            .map(like_contains_pattern);

        let (block_count, record_count, clean_count) = self.db.query_row(
            &format!(
                "SELECT
                    COALESCE(SUM(verdict = 'block'), 0),
                    COALESCE(SUM(verdict = 'record'), 0),
                    COALESCE(SUM(verdict NOT IN ('block', 'record')), 0)
                 FROM domain_decisions WHERE {DECISION_SEARCH_CLAUSE}"
            ),
            rusqlite::params![pattern],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                ))
            },
        )?;
        let [block_count, record_count, clean_count] =
            [block_count, record_count, clean_count].map(|count| u64::try_from(count).unwrap_or(0));
        let total_count = match query.verdict {
            DomainDecisionVerdictFilter::All => block_count + record_count + clean_count,
            DomainDecisionVerdictFilter::Block => block_count,
            DomainDecisionVerdictFilter::Record => record_count,
            DomainDecisionVerdictFilter::Clean => clean_count,
        };

        let decisions = self.db.query_map(
            &format!(
                "SELECT {DOMAIN_DECISION_COLUMNS}
                 FROM domain_decisions
                 WHERE {DECISION_SEARCH_CLAUSE} AND {}
                 ORDER BY updated_at DESC, domain ASC
                 LIMIT ?2 OFFSET ?3",
                query.verdict.sql_clause()
            ),
            rusqlite::params![pattern, limit, offset],
            map_domain_decision,
        )?;

        Ok(DomainDecisionPage {
            decisions,
            total_count,
            block_count,
            record_count,
            clean_count,
        })
    }
}

/// `%value%` with LIKE metacharacters escaped for `ESCAPE '\'`.
fn like_contains_pattern(value: &str) -> String {
    let escaped = value
        .replace('\\', "\\\\")
        .replace('%', "\\%")
        .replace('_', "\\_");
    format!("%{escaped}%")
}

/// Canonical decision key: lowercase ASCII without a trailing dot.
///
/// Matches DNS (`DomainKey`) and AI (`normalize_domain`) normalization so
/// lookup, classification, persistence, and concurrent-request coordination
/// share one key. Equivalent names (`Example.COM.`, `example.com`) map to the
/// same row, and saved negative classifications suppress new AI calls.
pub fn normalize_domain_key(domain: &str) -> Result<String> {
    let domain = domain.trim().trim_end_matches('.').to_ascii_lowercase();
    if domain.is_empty() {
        return Err(StoreError::InvalidInput("domain is empty".to_owned()));
    }
    Ok(domain)
}

/// The decisions page knows this category as `fraud`. Rows written before that
/// rename still say `security_fraud`; both names are the same score.
fn canonical_top_category(category: String) -> String {
    if category == "security_fraud" {
        "fraud".to_owned()
    } else {
        category
    }
}

fn map_domain_decision(row: &Row) -> std::result::Result<DomainDecision, rusqlite::Error> {
    Ok(DomainDecision {
        domain: row.get(0)?,
        model: row.get(1)?,
        rating_advertising: row.get(2)?,
        rating_tracking: row.get(3)?,
        rating_telemetry: row.get(4)?,
        rating_analytics: row.get(5)?,
        rating_malicious: row.get(6)?,
        rating_fraud: row.get(7)?,
        rating_cryptomining: row.get(8)?,
        rating_tunnel: row.get(9)?,
        verdict: row.get(10)?,
        top_category: canonical_top_category(row.get(11)?),
        top_score: row.get(12)?,
        scan_tier: normalize_scan_tier(&row.get::<_, String>(13)?),
        first_seen: get_timestamp(row, 14)?,
        updated_at: get_timestamp(row, 15)?,
        rating_newly_registered: row.get(16)?,
        rating_registry_hold: row.get(17)?,
        rating_hidden_registrant: row.get(18)?,
        rating_abusive_registrar: row.get(19)?,
    })
}

#[cfg(test)]
mod cache_tests {
    use super::*;
    use crate::Store;
    use std::time::{Duration, Instant};
    use time::OffsetDateTime;

    fn decision(domain: &str, score: f64) -> DomainDecision {
        let now = OffsetDateTime::now_utc();
        DomainDecision {
            domain: domain.to_owned(),
            model: "test".to_owned(),
            rating_advertising: 0.0,
            rating_tracking: 0.0,
            rating_telemetry: 0.0,
            rating_analytics: 0.0,
            rating_malicious: score,
            rating_fraud: 0.0,
            rating_cryptomining: 0.0,
            rating_tunnel: 0.0,
            verdict: "block".to_owned(),
            top_category: "malicious".to_owned(),
            top_score: score,
            rating_newly_registered: 0.0,
            rating_registry_hold: 0.0,
            rating_hidden_registrant: 0.0,
            rating_abusive_registrar: 0.0,
            scan_tier: "basic".to_owned(),
            first_seen: now,
            updated_at: now,
        }
    }

    fn lookup(domain: &str) -> DomainLookup {
        DomainLookup {
            domain: domain.to_owned(),
            source: "rdap".to_owned(),
            registrar: None,
            registrar_id: None,
            statuses: Vec::new(),
            nameservers: Vec::new(),
            registered_at: None,
            expires_at: None,
            registry_updated_at: None,
            registrant_name: None,
            registrant_organization: None,
            redacted: false,
            dnssec: None,
            fetched_at: OffsetDateTime::now_utc(),
        }
    }

    #[test]
    fn a_late_lookup_cannot_restore_a_deleted_domain_but_a_new_lookup_can() {
        let store = Store::open(":memory:").unwrap();
        for has_decision in [false, true] {
            let row = lookup("Example.COM.");
            if has_decision {
                store
                    .upsert_domain_decision(&decision("example.com", 0.9))
                    .unwrap();
            }
            let started =
                DeletionFence(Instant::now().checked_sub(Duration::from_secs(1)).unwrap());
            assert!(store
                .upsert_domain_lookup(&row, DeletionFence::now())
                .unwrap());
            assert_eq!(
                store
                    .delete_domain_decision("EXAMPLE.COM.")
                    .unwrap()
                    .is_some(),
                has_decision
            );
            assert!(!store.upsert_domain_lookup(&row, started).unwrap());
            assert!(store.get_domain_lookup("example.com").unwrap().is_none());
            assert!(store
                .upsert_domain_lookup(&row, DeletionFence::now())
                .unwrap());
            assert!(store.get_domain_lookup("example.com").unwrap().is_some());
        }
    }

    #[test]
    fn advanced_save_drops_only_a_registration_row_deleted_during_the_check() {
        let store = Store::open(":memory:").unwrap();
        let started = DeletionFence(Instant::now().checked_sub(Duration::from_secs(1)).unwrap());
        store.delete_domain_decision("example.com").unwrap();
        assert!(store
            .save_advanced_check(
                &decision("sub.example.com", 0.9),
                started,
                Some(&lookup("Example.COM."))
            )
            .unwrap());
        assert!(store
            .get_domain_decision("sub.example.com")
            .unwrap()
            .is_some());
        assert!(store.get_domain_lookup("example.com").unwrap().is_none());

        // A check that starts after the deletion saves the registration row.
        assert!(store
            .save_advanced_check(
                &decision("sub.example.com", 0.9),
                DeletionFence::now(),
                Some(&lookup("example.com"))
            )
            .unwrap());
        assert!(store.get_domain_lookup("example.com").unwrap().is_some());
    }

    #[test]
    fn advanced_save_is_rejected_when_its_own_domain_was_deleted() {
        let store = Store::open(":memory:").unwrap();
        let started = DeletionFence(Instant::now().checked_sub(Duration::from_secs(1)).unwrap());
        store.delete_domain_decision("sub.example.com").unwrap();
        assert!(!store
            .save_advanced_check(
                &decision("sub.example.com", 0.9),
                started,
                Some(&lookup("example.com"))
            )
            .unwrap());
        assert!(store
            .get_domain_decision("sub.example.com")
            .unwrap()
            .is_none());
        assert!(store.get_domain_lookup("example.com").unwrap().is_none());
    }

    #[test]
    fn failed_lookup_deletion_preserves_the_decision_and_cache() {
        let store = Store::open(":memory:").unwrap();
        store
            .upsert_domain_decision(&decision("example.com", 0.9))
            .unwrap();
        store.db.execute_batch("CREATE TRIGGER reject_lookup_delete BEFORE DELETE ON domain_lookups BEGIN SELECT RAISE(ABORT, 'test failure'); END;").unwrap();
        store
            .upsert_domain_lookup(&lookup("example.com"), DeletionFence::now())
            .unwrap();
        assert!(store.delete_domain_decision("example.com").is_err());
        assert!(store.cached_domain_decision("example.com").is_some());
        assert!(store.get_domain_decision("example.com").unwrap().is_some());
        assert!(store.get_domain_lookup("example.com").unwrap().is_some());
    }

    #[test]
    fn an_older_classification_does_not_restore_a_deleted_decision() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path().join("decisions.db")).unwrap();
        let started = DeletionFence(Instant::now().checked_sub(Duration::from_secs(1)).unwrap());
        store
            .upsert_domain_decision(&decision("ads.example", 0.9))
            .unwrap();
        assert!(store
            .delete_domain_decision("ads.example")
            .unwrap()
            .is_some());

        let stale = decision("ads.example", 0.9);
        assert!(!store
            .insert_domain_decision_if_absent(&stale, started)
            .unwrap());
        assert!(!store
            .upsert_domain_decision_unless_deleted(&stale, Some(started))
            .unwrap());
        assert!(store.get_domain_decision("ads.example").unwrap().is_none());

        let later = DeletionFence::now();
        assert!(store
            .insert_domain_decision_if_absent(&stale, later)
            .unwrap());
        assert!(store.get_domain_decision("ads.example").unwrap().is_some());
    }

    #[test]
    fn an_older_classification_does_not_replace_a_saved_row() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path().join("decisions.db")).unwrap();
        let started = DeletionFence::now();
        store
            .upsert_domain_decision(&decision("ads.example", 0.2))
            .unwrap();
        let mut newer_score = decision("ads.example", 0.9);
        newer_score.verdict = "block".to_owned();
        assert!(!store
            .insert_domain_decision_if_absent(&newer_score, started)
            .unwrap());
        let kept = store
            .get_domain_decision("ads.example")
            .unwrap()
            .expect("row");
        assert!((kept.rating_malicious - 0.2).abs() < f64::EPSILON);
    }

    #[test]
    fn a_failed_lookup_rolls_back_the_advanced_decision() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path().join("decisions.db")).unwrap();
        store
            .upsert_domain_decision(&decision("ads.example", 0.2))
            .unwrap();
        store
            .db
            .execute("DROP TABLE domain_lookups", rusqlite::params![])
            .unwrap();
        let mut advanced = decision("ads.example", 0.9);
        advanced.scan_tier = "advanced".to_owned();
        advanced.verdict = "block".to_owned();
        let now = OffsetDateTime::now_utc();
        let lookup = DomainLookup {
            domain: "ads.example".to_owned(),
            source: "rdap".to_owned(),
            registrar: None,
            registrar_id: None,
            statuses: Vec::new(),
            nameservers: Vec::new(),
            registered_at: None,
            expires_at: None,
            registry_updated_at: None,
            registrant_name: None,
            registrant_organization: None,
            redacted: false,
            dnssec: None,
            fetched_at: now,
        };
        assert!(store
            .save_advanced_check(&advanced, DeletionFence::now(), Some(&lookup))
            .is_err());
        let tier: String = store
            .db
            .query_row(
                "SELECT scan_tier FROM domain_decisions WHERE domain = ?1",
                rusqlite::params!["ads.example"],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(tier, "basic");
        let cached = store.cached_domain_decision("ads.example").unwrap();
        assert_eq!(cached.scan_tier, "basic");
        assert!((cached.rating_malicious - 0.2).abs() < f64::EPSILON);
    }

    #[test]
    fn an_advanced_check_writes_a_lookup_row_only_when_given_one() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path().join("decisions.db")).unwrap();
        let mut advanced = decision("example.com", 0.0);
        advanced.scan_tier = "advanced".to_owned();
        let lookup = DomainLookup {
            domain: "example.com".to_owned(),
            source: "rdap".to_owned(),
            registrar: Some("Reserved".to_owned()),
            registrar_id: Some("376".to_owned()),
            statuses: Vec::new(),
            nameservers: Vec::new(),
            registered_at: None,
            expires_at: None,
            registry_updated_at: None,
            registrant_name: None,
            registrant_organization: None,
            redacted: false,
            dnssec: Some(true),
            fetched_at: OffsetDateTime::now_utc(),
        };

        assert!(store
            .save_advanced_check(&advanced, DeletionFence::now(), None)
            .unwrap());
        assert!(store.get_domain_lookup("example.com").unwrap().is_none());

        assert!(store
            .save_advanced_check(&advanced, DeletionFence::now(), Some(&lookup))
            .unwrap());
        assert_eq!(
            store
                .get_domain_lookup("example.com")
                .unwrap()
                .unwrap()
                .registrar_id
                .as_deref(),
            Some("376")
        );
    }

    #[test]
    fn saved_decision_is_resident_and_write_through() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path().join("decisions.db")).unwrap();
        assert!(store.cached_domain_decision("Example.COM.").is_none());
        store
            .upsert_domain_decision(&decision("Example.COM.", 0.8))
            .unwrap();
        let first = store.cached_domain_decision("example.com").unwrap();
        assert!((first.rating_malicious - 0.8).abs() < f64::EPSILON);
        store
            .upsert_domain_decision(&decision("example.com", 0.2))
            .unwrap();
        let updated = store.cached_domain_decision("EXAMPLE.com.").unwrap();
        assert!((updated.rating_malicious - 0.2).abs() < f64::EPSILON);
        assert_eq!(updated.first_seen, first.first_seen);
    }

    #[test]
    fn a_read_that_finds_no_decision_is_remembered_until_one_is_saved() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path().join("decisions.db")).unwrap();
        assert_eq!(
            store.resident_domain_decision("New.Example.").decision,
            ResidentDecision::Unknown,
            "nothing is known before SQLite is read"
        );
        assert!(store.get_domain_decision("new.example").unwrap().is_none());
        assert_eq!(
            store.resident_domain_decision("New.Example.").decision,
            ResidentDecision::NotSaved
        );
        assert!(store.cached_domain_decision("new.example").is_none());

        store
            .upsert_domain_decision(&decision("new.example", 0.4))
            .unwrap();
        assert!(store.cached_domain_decision("new.example").is_some());
        assert!(matches!(
            store.resident_domain_decision("new.example").decision,
            ResidentDecision::Saved(_)
        ));
    }

    #[test]
    fn every_way_of_saving_replaces_a_remembered_absence() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path().join("decisions.db")).unwrap();
        let absent = |domain: &str| {
            assert!(store.get_domain_decision(domain).unwrap().is_none());
            assert_eq!(
                store.resident_domain_decision(domain).decision,
                ResidentDecision::NotSaved
            );
        };
        let saved = |domain: &str| {
            assert!(
                matches!(
                    store.resident_domain_decision(domain).decision,
                    ResidentDecision::Saved(_)
                ),
                "{domain}"
            );
        };

        absent("upsert.example");
        store
            .upsert_domain_decision(&decision("upsert.example", 0.4))
            .unwrap();
        saved("upsert.example");

        absent("insert.example");
        assert!(store
            .insert_domain_decision_if_absent(
                &decision("insert.example", 0.4),
                DeletionFence::now()
            )
            .unwrap());
        saved("insert.example");

        absent("advanced.example");
        assert!(store
            .save_advanced_check(
                &decision("advanced.example", 0.4),
                DeletionFence::now(),
                None
            )
            .unwrap());
        saved("advanced.example");
    }

    #[test]
    fn a_deleted_decision_is_not_remembered_either_way() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path().join("decisions.db")).unwrap();
        store
            .upsert_domain_decision(&decision("gone.example", 0.4))
            .unwrap();
        store.delete_domain_decision("gone.example").unwrap();
        assert_eq!(
            store.resident_domain_decision("gone.example").decision,
            ResidentDecision::Unknown
        );

        assert!(store
            .get_domain_decision("never.example")
            .unwrap()
            .is_none());
        store.delete_domain_decision("never.example").unwrap();
        assert_eq!(
            store.resident_domain_decision("never.example").decision,
            ResidentDecision::Unknown
        );
    }

    #[test]
    fn a_remembered_absence_expires_and_sees_another_handles_write() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("decisions.db");
        let first = Store::open(&path).unwrap();
        assert!(first.get_domain_decision("late.example").unwrap().is_none());
        Store::open(&path)
            .unwrap()
            .upsert_domain_decision(&decision("late.example", 0.8))
            .unwrap();
        assert_eq!(
            first.resident_domain_decision("late.example").decision,
            ResidentDecision::NotSaved,
            "another process's write is not seen before the entry expires"
        );

        first.age_resident_decision("late.example", antiwire_tuning::DNS_AI_DECISION_CACHE_TTL);
        assert_eq!(
            first.resident_domain_decision("late.example").decision,
            ResidentDecision::Unknown
        );
        assert!(first.get_domain_decision("late.example").unwrap().is_some());
        assert!(matches!(
            first.resident_domain_decision("late.example").decision,
            ResidentDecision::Saved(_)
        ));
    }

    #[test]
    fn an_entry_near_the_end_of_its_residency_is_due_a_refresh() {
        let ttl = antiwire_tuning::DNS_AI_DECISION_CACHE_TTL;
        let lead = antiwire_tuning::DNS_AI_DECISION_REFRESH_LEAD;
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path().join("decisions.db")).unwrap();
        store
            .upsert_domain_decision(&decision("saved.example", 0.4))
            .unwrap();
        assert!(store
            .get_domain_decision("absent.example")
            .unwrap()
            .is_none());

        for domain in ["saved.example", "absent.example"] {
            assert!(
                !store.resident_domain_decision(domain).refresh_due,
                "{domain} was just read"
            );
            let lead_starts = ttl.saturating_sub(lead);
            store.age_resident_decision(domain, lead_starts.saturating_sub(Duration::from_secs(1)));
            assert!(!store.resident_domain_decision(domain).refresh_due);
            store.age_resident_decision(domain, lead_starts + Duration::from_secs(1));
            let aging = store.resident_domain_decision(domain);
            assert!(aging.refresh_due, "{domain} is inside the lead");
            assert_ne!(
                aging.decision,
                ResidentDecision::Unknown,
                "{domain} is still decided from memory"
            );
        }
    }

    #[test]
    fn a_reload_reads_sqlite_again_and_restarts_the_residency() {
        let ttl = antiwire_tuning::DNS_AI_DECISION_CACHE_TTL;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("decisions.db");
        let first = Store::open(&path).unwrap();
        first
            .upsert_domain_decision(&decision("changed.example", 0.8))
            .unwrap();
        assert!(first.get_domain_decision("new.example").unwrap().is_none());
        // Another process changes one decision and saves the other.
        let second = Store::open(&path).unwrap();
        second
            .upsert_domain_decision(&decision("changed.example", 0.2))
            .unwrap();
        second
            .upsert_domain_decision(&decision("new.example", 0.6))
            .unwrap();
        for domain in ["changed.example", "new.example"] {
            first.age_resident_decision(domain, ttl.saturating_sub(Duration::from_secs(1)));
        }

        let reloaded = first.reload_domain_decision("Changed.Example.").unwrap();
        assert!((reloaded.unwrap().rating_malicious - 0.2).abs() < f64::EPSILON);
        assert!(first
            .reload_domain_decision("new.example")
            .unwrap()
            .is_some());
        for domain in ["changed.example", "new.example"] {
            let resident = first.resident_domain_decision(domain);
            assert!(matches!(resident.decision, ResidentDecision::Saved(_)));
            assert!(!resident.refresh_due, "{domain} starts a new residency");
        }

        assert!(first
            .reload_domain_decision("none.example")
            .unwrap()
            .is_none());
        assert_eq!(
            first.resident_domain_decision("none.example").decision,
            ResidentDecision::NotSaved
        );
    }

    #[test]
    fn never_classified_names_do_not_evict_saved_decisions() {
        let cache = DecisionCache::new();
        cache.insert(decision("kept.example", 0.5));
        for index in 0..=antiwire_tuning::DNS_AI_DECISION_CACHE_CAP {
            cache.insert_not_saved(&format!("absent-{index}.example"));
        }
        assert!(cache.get("kept.example").is_some());
        assert_eq!(
            cache.resident("absent-0.example").decision,
            ResidentDecision::Unknown,
            "the oldest absence was evicted"
        );
        assert_eq!(
            cache.resident("absent-1.example").decision,
            ResidentDecision::NotSaved
        );
    }

    #[test]
    fn expired_entry_reload_sees_another_handle_write() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("decisions.db");
        let first = Store::open(&path).unwrap();
        first
            .upsert_domain_decision(&decision("shared.example", 0.8))
            .unwrap();
        let second = Store::open(&path).unwrap();
        second
            .upsert_domain_decision(&decision("shared.example", 0.2))
            .unwrap();
        assert!(
            (first
                .cached_domain_decision("shared.example")
                .unwrap()
                .rating_malicious
                - 0.8)
                .abs()
                < f64::EPSILON
        );
        first
            .decision_cache
            .entries
            .lock()
            .saved
            .get_mut("shared.example")
            .unwrap()
            .cached_at = Instant::now()
            .checked_sub(antiwire_tuning::DNS_AI_DECISION_CACHE_TTL)
            .unwrap();
        assert!(first.cached_domain_decision("shared.example").is_none());
        assert!(
            (first
                .get_domain_decision("shared.example")
                .unwrap()
                .unwrap()
                .rating_malicious
                - 0.2)
                .abs()
                < f64::EPSILON
        );
    }

    #[test]
    fn cache_evicts_least_recently_used_decision() {
        let cache = DecisionCache::new();
        for index in 0..antiwire_tuning::DNS_AI_DECISION_CACHE_CAP {
            cache.insert(decision(&format!("domain-{index}.example"), 0.5));
        }
        assert!(cache.get("domain-0.example").is_some());
        cache.insert(decision("extra.example", 0.5));
        assert!(cache.get("domain-1.example").is_none());
        assert!(cache.get("domain-0.example").is_some());
    }
}

#[cfg(test)]
mod page_tests {
    use super::*;
    use crate::Store;
    use time::OffsetDateTime;

    fn saved(store: &Store, domain: &str, verdict: &str, updated_unix: i64) {
        let updated_at = OffsetDateTime::from_unix_timestamp(updated_unix).unwrap();
        store
            .upsert_domain_decision(&DomainDecision {
                domain: domain.to_owned(),
                model: "test".to_owned(),
                rating_advertising: 0.0,
                rating_tracking: 0.0,
                rating_telemetry: 0.0,
                rating_analytics: 0.0,
                rating_malicious: 0.9,
                rating_fraud: 0.0,
                rating_cryptomining: 0.0,
                rating_tunnel: 0.0,
                verdict: verdict.to_owned(),
                top_category: if verdict.is_empty() { "" } else { "malicious" }.to_owned(),
                top_score: 0.9,
                rating_newly_registered: 0.0,
                rating_registry_hold: 0.0,
                rating_hidden_registrant: 0.0,
                rating_abusive_registrar: 0.0,
                scan_tier: "basic".to_owned(),
                first_seen: updated_at,
                updated_at,
            })
            .unwrap();
    }

    fn seeded() -> (tempfile::TempDir, Store) {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path().join("decisions.db")).unwrap();
        saved(&store, "ads.example", "block", 1_700_000_300);
        saved(&store, "metrics.example", "record", 1_700_000_200);
        saved(&store, "clean.example", "", 1_700_000_100);
        saved(&store, "under_score.test", "record", 1_700_000_000);
        (dir, store)
    }

    fn domains(page: &DomainDecisionPage) -> Vec<&str> {
        page.decisions
            .iter()
            .map(|row| row.domain.as_str())
            .collect()
    }

    #[test]
    fn lists_newest_first_with_verdict_counts() {
        let (_dir, store) = seeded();
        let page = store
            .query_domain_decisions(&DomainDecisionQuery::default())
            .unwrap();
        assert_eq!(
            domains(&page),
            [
                "ads.example",
                "metrics.example",
                "clean.example",
                "under_score.test"
            ]
        );
        assert_eq!(page.total_count, 4);
        assert_eq!(
            (page.block_count, page.record_count, page.clean_count),
            (1, 2, 1)
        );
    }

    #[test]
    fn verdict_filter_narrows_rows_but_not_verdict_counts() {
        let (_dir, store) = seeded();
        for (verdict, expected) in [
            (DomainDecisionVerdictFilter::Block, vec!["ads.example"]),
            (
                DomainDecisionVerdictFilter::Record,
                vec!["metrics.example", "under_score.test"],
            ),
            (DomainDecisionVerdictFilter::Clean, vec!["clean.example"]),
        ] {
            let page = store
                .query_domain_decisions(&DomainDecisionQuery {
                    verdict,
                    ..Default::default()
                })
                .unwrap();
            assert_eq!(domains(&page), expected, "{verdict:?}");
            assert_eq!(page.total_count, expected.len() as u64);
            assert_eq!(page.block_count + page.record_count + page.clean_count, 4);
        }
    }

    #[test]
    fn search_matches_substrings_and_treats_like_wildcards_literally() {
        let (_dir, store) = seeded();
        let search = |text: &str| {
            store
                .query_domain_decisions(&DomainDecisionQuery {
                    search_query: Some(text.to_owned()),
                    ..Default::default()
                })
                .unwrap()
        };
        let page = search("  METRICS ");
        assert_eq!(domains(&page), ["metrics.example"]);
        assert_eq!(
            (page.block_count, page.record_count, page.clean_count),
            (0, 1, 0)
        );
        assert_eq!(domains(&search("_")), ["under_score.test"]);
        assert_eq!(search("%").decisions, []);
        assert_eq!(search("").total_count, 4);
    }

    #[test]
    fn pages_with_limit_and_offset() {
        let (_dir, store) = seeded();
        let page = store
            .query_domain_decisions(&DomainDecisionQuery {
                limit: 2,
                offset: 1,
                ..Default::default()
            })
            .unwrap();
        assert_eq!(domains(&page), ["metrics.example", "clean.example"]);
        assert_eq!(page.total_count, 4);
    }

    #[test]
    fn revising_a_verdict_keeps_scores_timestamps_and_the_cache() {
        let (_dir, store) = seeded();
        let before = store
            .get_domain_decision("ads.example")
            .unwrap()
            .expect("seeded row");
        assert!(store.cached_domain_decision("ads.example").is_some());

        assert!(store
            .revise_domain_decision_outcome("ads.example", "", "", before.top_score)
            .unwrap());
        let after = store
            .cached_domain_decision("ads.example")
            .expect("cache keeps the revised row");
        assert_eq!(after.verdict, "");
        assert_eq!(after.top_category, "");
        assert_eq!(
            after.rating_malicious.to_bits(),
            before.rating_malicious.to_bits()
        );
        assert_eq!(after.first_seen, before.first_seen);
        assert_eq!(after.updated_at, before.updated_at);

        let stored = store
            .get_domain_decision("ads.example")
            .unwrap()
            .expect("row");
        assert_eq!(stored.verdict, "");
        assert_eq!(stored.updated_at, before.updated_at);

        assert!(!store
            .revise_domain_decision_outcome("ads.example", "", "", before.top_score)
            .unwrap());
        assert!(!store
            .revise_domain_decision_outcome("missing.example", "", "", 0.0)
            .unwrap());
    }

    #[test]
    fn legacy_security_fraud_category_reads_as_fraud() {
        let (_dir, store) = seeded();
        let updated_at = OffsetDateTime::from_unix_timestamp(1_700_000_400).unwrap();
        store
            .upsert_domain_decision(&DomainDecision {
                domain: "lookalike.example".to_owned(),
                model: "test".to_owned(),
                rating_advertising: 0.0,
                rating_tracking: 0.0,
                rating_telemetry: 0.0,
                rating_analytics: 0.0,
                rating_malicious: 0.0,
                rating_fraud: 0.91,
                rating_cryptomining: 0.0,
                rating_tunnel: 0.0,
                verdict: "record".to_owned(),
                top_category: "security_fraud".to_owned(),
                top_score: 0.91,
                rating_newly_registered: 0.0,
                rating_registry_hold: 0.0,
                rating_hidden_registrant: 0.0,
                rating_abusive_registrar: 0.0,
                scan_tier: "basic".to_owned(),
                first_seen: updated_at,
                updated_at,
            })
            .unwrap();

        let loaded = store
            .get_domain_decision("lookalike.example")
            .unwrap()
            .expect("row");
        assert_eq!(loaded.top_category, "fraud");
    }

    #[test]
    fn deleting_a_decision_removes_the_row_and_the_cache() {
        let (_dir, store) = seeded();
        assert!(store.get_domain_decision("ads.example").unwrap().is_some());
        assert!(store.cached_domain_decision("ads.example").is_some());

        assert!(store
            .delete_domain_decision("ADS.EXAMPLE.")
            .unwrap()
            .is_some());

        assert!(store.cached_domain_decision("ads.example").is_none());
        assert!(store.get_domain_decision("ads.example").unwrap().is_none());
        let page = store
            .query_domain_decisions(&DomainDecisionQuery::default())
            .unwrap();
        assert!(!domains(&page).contains(&"ads.example"));
        assert_eq!(page.total_count, 3);
        assert_eq!(page.block_count, 0);

        assert!(store
            .delete_domain_decision("ads.example")
            .unwrap()
            .is_none());
        assert!(store
            .delete_domain_decision("missing.example")
            .unwrap()
            .is_none());
    }

    #[test]
    fn a_lookup_is_replaced_and_removed_with_the_decision() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path().join("lookups.db")).unwrap();
        assert!(!store.get_settings().unwrap().save_domain_lookups);
        let fetched = OffsetDateTime::UNIX_EPOCH;
        store
            .upsert_domain_lookup(
                &crate::DomainLookup {
                    domain: "Example.COM.".to_owned(),
                    source: "rdap".to_owned(),
                    registrar: Some("Reserved".to_owned()),
                    registrar_id: Some("376".to_owned()),
                    statuses: vec!["ok".to_owned()],
                    nameservers: vec!["ns.example".to_owned()],
                    registered_at: Some(fetched),
                    expires_at: None,
                    registry_updated_at: None,
                    registrant_name: None,
                    registrant_organization: Some("IANA".to_owned()),
                    redacted: false,
                    dnssec: Some(true),
                    fetched_at: fetched,
                },
                DeletionFence::now(),
            )
            .unwrap();
        store
            .upsert_domain_lookup(
                &crate::DomainLookup {
                    domain: "example.com".to_owned(),
                    source: "whois".to_owned(),
                    registrar: None,
                    registrar_id: None,
                    statuses: Vec::new(),
                    nameservers: Vec::new(),
                    registered_at: None,
                    expires_at: None,
                    registry_updated_at: None,
                    registrant_name: None,
                    registrant_organization: None,
                    redacted: true,
                    dnssec: None,
                    fetched_at: fetched,
                },
                DeletionFence::now(),
            )
            .unwrap();
        let saved = store.get_domain_lookup("example.com").unwrap().unwrap();
        assert_eq!(saved.source, "whois");
        assert!(saved.redacted);
        assert!(store.delete_domain_decision("missing.example").is_ok());
        store
            .upsert_domain_lookup(
                &crate::DomainLookup {
                    domain: "missing.example".to_owned(),
                    source: "rdap".to_owned(),
                    registrar: None,
                    registrar_id: None,
                    statuses: Vec::new(),
                    nameservers: Vec::new(),
                    registered_at: None,
                    expires_at: None,
                    registry_updated_at: None,
                    registrant_name: None,
                    registrant_organization: None,
                    redacted: false,
                    dnssec: None,
                    fetched_at: fetched,
                },
                DeletionFence::now(),
            )
            .unwrap();
        assert!(store
            .delete_domain_decision("missing.example")
            .unwrap()
            .is_none());
        assert!(store
            .get_domain_lookup("missing.example")
            .unwrap()
            .is_none());
        assert!(store.get_domain_lookup("example.com").unwrap().is_some());
    }
}
