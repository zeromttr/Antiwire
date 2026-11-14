//! Application identity queries: version-family-keyed rows plus per-path history.

use antiwire_policy::stable_identity;
use rusqlite::OptionalExtension;
use rusqlite::Row;
use time::OffsetDateTime;

use crate::error::{Result, StoreError};
use crate::models::{format_timestamp, Application, ApplicationSighting};

#[cfg(test)]
use crate::models::ApplicationPathHistoryEntry;

use crate::store::{get_timestamp, row_id_to_i32, APPLICATION_PATH_HISTORY_LIMIT};

impl crate::store::Store {
    /// Records that an executable at `app_path` with display name `app_name` ran.
    ///
    /// Identity is the version family of the path. An exact-path sighting
    /// refreshes its row; a path that is new but belongs to a known family (a
    /// version bump inside the same install root) joins that row and records
    /// the move. A path that shares nothing but the name stays its own row, so
    /// a binary that adopted another application's file name can neither share
    /// its row nor repoint its stored location.
    ///
    /// When a new row's name is already known from a different location, the
    /// returned [`ApplicationSighting`] carries that location in
    /// `previous_path` so the caller can raise the move (or the impersonation).
    /// An existing identity whose path moved reports the same way with
    /// `is_new_application` false and `path_changed` true.
    ///
    /// Set `authoritative_path` to false when `app_path` is a placeholder the
    /// resolver fell back to rather than a real filesystem location. Such a
    /// sighting carries no location and can only join an existing identity by
    /// name; it never creates a second row for a known name.
    // One linear transaction: splitting the branch arms into helpers would
    // thread six parameters through each and hide the lookup order that is the
    // point of two-tier identity.
    #[allow(clippy::too_many_lines)]
    pub fn record_application_sighting(
        &self,
        app_name: &str,
        app_path: &str,
        authoritative_path: bool,
        seen_at: OffsetDateTime,
    ) -> Result<ApplicationSighting> {
        let app_name = fallback_app_name(app_name, app_path);
        if app_name.is_empty() {
            return Err(StoreError::Database(
                "cannot record an application with no name".to_owned(),
            ));
        }

        self.db.transaction_with(|tx| {
            if !authoritative_path {
                // A synthetic path identifies nothing; fall back to the name so
                // failed lookups reuse the application's real row instead of
                // forking a nameless placeholder per failure.
                let existing = tx
                    .query_row(
                        "SELECT id FROM applications
                         WHERE LOWER(app_name) = LOWER(?1)
                         ORDER BY id ASC LIMIT 1",
                        rusqlite::params![app_name],
                        |row| row.get::<_, i32>(0),
                    )
                    .optional()?;
                let Some(app_id) = existing else {
                    let identity_key = stable_identity(&app_name, app_path, false);
                    tx.execute(
                        "INSERT INTO applications
                             (app_path, app_name, signature_fingerprint, identity_key, first_seen)
                         VALUES (?1, ?2, '', ?3, ?4)",
                        rusqlite::params![
                            app_path,
                            app_name,
                            identity_key,
                            format_timestamp(seen_at)
                        ],
                    )?;
                    let app_id = row_id_to_i32(tx.last_insert_rowid())?;
                    record_path_history(tx, app_id, app_path, seen_at)?;
                    return Ok(ApplicationSighting {
                        app_id,
                        is_new_application: true,
                        path_changed: false,
                        previous_path: None,
                    });
                };
                return Ok(ApplicationSighting {
                    app_id,
                    is_new_application: false,
                    path_changed: false,
                    previous_path: None,
                });
            }

            let identity_key = stable_identity(&app_name, app_path, true);

            let existing = tx
                .query_row(
                    "SELECT id, app_path, app_name, identity_key FROM applications
                     WHERE LOWER(app_path) = LOWER(?1)
                     ORDER BY id ASC LIMIT 1",
                    rusqlite::params![app_path],
                    |row| {
                        Ok((
                            row.get::<_, i32>(0)?,
                            row.get::<_, String>(1)?,
                            row.get::<_, String>(2)?,
                            row.get::<_, String>(3)?,
                        ))
                    },
                )
                .optional()?;

            if let Some((app_id, current_path, current_name, current_key)) = existing {
                // Case-insensitive path lookup means a recased spelling is the
                // same file; refresh what the row reports without forking. The
                // key is refreshed too so it tracks the spelling on record.
                if current_name != app_name {
                    tx.execute(
                        "UPDATE applications SET app_name = ?2 WHERE id = ?1",
                        rusqlite::params![app_id, app_name],
                    )?;
                }
                if current_path != app_path || current_key != identity_key {
                    tx.execute(
                        "UPDATE applications SET app_path = ?2, identity_key = ?3 WHERE id = ?1",
                        rusqlite::params![app_id, app_path, identity_key],
                    )?;
                }
                record_path_history(tx, app_id, app_path, seen_at)?;
                return Ok(ApplicationSighting {
                    app_id,
                    is_new_application: false,
                    path_changed: false,
                    previous_path: None,
                });
            }

            // Version-family fallback: a new path under the same install root
            // is a move inside one identity, not a new application.
            let family = tx
                .query_row(
                    "SELECT id, app_path, app_name FROM applications
                     WHERE identity_key = ?1
                     ORDER BY id ASC LIMIT 1",
                    rusqlite::params![identity_key],
                    |row| {
                        Ok((
                            row.get::<_, i32>(0)?,
                            row.get::<_, String>(1)?,
                            row.get::<_, String>(2)?,
                        ))
                    },
                )
                .optional()?;

            if let Some((app_id, current_path, current_name)) = family {
                if current_name != app_name {
                    tx.execute(
                        "UPDATE applications SET app_name = ?2 WHERE id = ?1",
                        rusqlite::params![app_id, app_name],
                    )?;
                }
                let path_changed = !current_path.eq_ignore_ascii_case(app_path);
                if path_changed {
                    tx.execute(
                        "UPDATE applications SET app_path = ?2 WHERE id = ?1",
                        rusqlite::params![app_id, app_path],
                    )?;
                }
                record_path_history(tx, app_id, app_path, seen_at)?;
                return Ok(ApplicationSighting {
                    app_id,
                    is_new_application: false,
                    path_changed,
                    previous_path: path_changed.then_some(current_path),
                });
            }

            tx.execute(
                "INSERT INTO applications
                     (app_path, app_name, signature_fingerprint, identity_key, first_seen)
                 VALUES (?1, ?2, '', ?3, ?4)",
                rusqlite::params![app_path, app_name, identity_key, format_timestamp(seen_at)],
            )?;
            let app_id = row_id_to_i32(tx.last_insert_rowid())?;
            record_path_history(tx, app_id, app_path, seen_at)?;

            // The name running from somewhere else is what makes this new row a
            // move worth raising rather than an ordinary first sighting.
            let previous_path = tx
                .query_row(
                    "SELECT app_path FROM applications
                     WHERE LOWER(app_name) = LOWER(?1) AND id != ?2
                     ORDER BY id ASC LIMIT 1",
                    rusqlite::params![app_name, app_id],
                    |row| row.get::<_, String>(0),
                )
                .optional()?;

            Ok(ApplicationSighting {
                app_id,
                is_new_application: true,
                path_changed: false,
                previous_path,
            })
        })
    }

    /// Startup-only cleanup, before application caches and active flows exist.
    /// During collection even an unreferenced row can have in-memory owners.
    /// Keep the reference check and deletion in a single atomic statement.
    pub(in crate::store) fn prune_startup_placeholders(&mut self) -> Result<()> {
        self.db.execute(
            "DELETE FROM applications
             WHERE app_path COLLATE NOCASE IN (
                 'Path unavailable', 'System / Elevated Process', 'Unknown (No Owner)',
                 'Unknown (Exited)', 'Unknown (Access Denied)'
             )
             AND NOT EXISTS (
                 SELECT 1 FROM connection_logs WHERE app_id = applications.id
             )",
            [],
        )?;
        Ok(())
    }

    /// Returns the recent distinct locations `app_id` has run from, newest first.
    #[cfg(test)]
    pub(crate) fn list_application_path_history(
        &self,
        app_id: i32,
    ) -> Result<Vec<ApplicationPathHistoryEntry>> {
        self.db.query_map(
            "SELECT app_path, first_seen, last_seen
             FROM application_path_history
             WHERE app_id = ?1
             ORDER BY last_seen DESC, id DESC",
            rusqlite::params![app_id],
            map_application_path_history,
        )
    }

    /// Test-only seam for exercising the path-history bound directly.
    ///
    /// Path-keyed identity means the live path only ever appends one location
    /// per application, so the cap can only be reached by the retention test.
    #[cfg(test)]
    pub(crate) fn record_path_history_for_test(
        &self,
        app_id: i32,
        app_path: &str,
        seen_at: OffsetDateTime,
    ) -> Result<()> {
        self.db
            .transaction_with(|tx| record_path_history(tx, app_id, app_path, seen_at))
    }

    /// Gives application `app_id` the name `app_name`, and nothing else: its path, identity
    /// and history stay as they are.
    ///
    /// # Errors
    ///
    /// [`StoreError::ApplicationNotFound`] when no application has that id.
    pub fn rename_application(&self, app_id: i32, app_name: &str) -> Result<()> {
        let updated = self.db.execute(
            "UPDATE applications SET app_name = ?2 WHERE id = ?1",
            rusqlite::params![app_id, app_name],
        )?;
        if updated == 0 {
            return Err(StoreError::ApplicationNotFound(app_id));
        }
        Ok(())
    }

    /// Inserts or updates an application and returns its id.
    ///
    /// Prefer [`Self::record_application_sighting`] on the live resolution path:
    /// it reports moves and maintains the path history.
    #[cfg(test)]
    pub(crate) fn upsert_application(&self, app: &Application) -> Result<i32> {
        if app.id > 0 {
            let updated = self.db.execute(
                "UPDATE applications
                 SET app_path = ?2, app_name = ?3, signature_fingerprint = ?4, first_seen = ?5
                 WHERE id = ?1",
                rusqlite::params![
                    app.id,
                    app.app_path,
                    app.app_name,
                    app.signature_fingerprint,
                    format_timestamp(app.first_seen),
                ],
            )?;
            if updated == 0 {
                return Err(StoreError::ApplicationNotFound(app.id));
            }
            return Ok(app.id);
        }

        let app_name = fallback_app_name(&app.app_name, &app.app_path);
        let sighting =
            self.record_application_sighting(&app_name, &app.app_path, true, app.first_seen)?;
        if !app.signature_fingerprint.is_empty() {
            self.db.execute(
                "UPDATE applications SET signature_fingerprint = ?2 WHERE id = ?1",
                rusqlite::params![sighting.app_id, app.signature_fingerprint],
            )?;
        }
        Ok(sighting.app_id)
    }

    /// Returns a single application by id.
    #[cfg(test)]
    pub(crate) fn get_application(&self, id: i32) -> Result<Application> {
        self.db
            .query_optional(
                "SELECT id, app_path, app_name, signature_fingerprint, first_seen
                 FROM applications
                 WHERE id = ?1",
                rusqlite::params![id],
                map_application,
            )?
            .ok_or(StoreError::ApplicationNotFound(id))
    }

    /// Returns an application by executable name, if present.
    ///
    /// A name may now match more than one row (the same binary name at several
    /// locations), so this returns the oldest. Use the application id, not the
    /// name, when a specific row is meant.
    pub fn find_application_by_name(&self, app_name: &str) -> Result<Option<Application>> {
        self.db.query_optional(
            "SELECT id, app_path, app_name, signature_fingerprint, first_seen
             FROM applications
             WHERE LOWER(app_name) = LOWER(?1)
             ORDER BY id ASC LIMIT 1",
            rusqlite::params![app_name],
            map_application,
        )
    }

    /// Returns every known application ordered by path.
    pub fn list_applications(&self) -> Result<Vec<Application>> {
        self.db.query_map(
            "SELECT id, app_path, app_name, signature_fingerprint, first_seen
             FROM applications
             ORDER BY app_path ASC, id ASC",
            [],
            map_application,
        )
    }

    /// Returns the applications matching `ids`, skipping unknown ones.
    ///
    /// Resolves just the rows a result page references instead of loading the
    /// whole applications table for every log query. Duplicate and out-of-range
    /// ids are harmless; the result is keyed by id at the call site.
    pub fn find_applications_by_ids(&self, ids: &[i32]) -> Result<Vec<Application>> {
        const CHUNK_SIZE: usize = 500;

        let unique: Vec<i32> = {
            let mut seen = std::collections::BTreeSet::from_iter(ids.iter().copied());
            seen.retain(|id| *id > 0);
            seen.into_iter().collect()
        };
        if unique.is_empty() {
            return Ok(Vec::new());
        }

        // `SQLite` caps bound parameters (32,766 by default) and a
        // 50,000-row page can reference more distinct applications than that,
        // so the lookup is chunked instead of expanding one `IN` list to the
        // page size. One statement shape shared by every chunk — short
        // tail chunks are padded with an unmatchable `id = -1` — keeps a
        // single cached plan.
        let placeholders = (1..=CHUNK_SIZE)
            .map(|index| format!("?{index}"))
            .collect::<Vec<_>>()
            .join(", ");
        let sql = format!(
            "SELECT id, app_path, app_name, signature_fingerprint, first_seen
             FROM applications
             WHERE id IN ({placeholders})"
        );

        let mut found = Vec::new();
        for chunk in unique.chunks(CHUNK_SIZE) {
            let mut params = chunk.to_vec();
            // Autoincrement ids are never negative, so padding never matches.
            params.resize(CHUNK_SIZE, -1);
            found.extend(self.db.query_map(
                &sql,
                rusqlite::params_from_iter(params.iter()),
                map_application,
            )?);
        }
        Ok(found)
    }
}

/// Records `app_path` against `app_id`, refreshing it if already known, then
/// evicts everything past [`APPLICATION_PATH_HISTORY_LIMIT`].
fn record_path_history(
    tx: &rusqlite::Transaction<'_>,
    app_id: i32,
    app_path: &str,
    seen_at: OffsetDateTime,
) -> Result<()> {
    let seen_at = format_timestamp(seen_at);
    tx.execute(
        "INSERT INTO application_path_history (app_id, app_path, first_seen, last_seen)
         VALUES (?1, ?2, ?3, ?3)
         ON CONFLICT(app_id, app_path) DO UPDATE SET last_seen = excluded.last_seen",
        rusqlite::params![app_id, app_path, seen_at],
    )?;
    tx.execute(
        "DELETE FROM application_path_history
         WHERE app_id = ?1
           AND id NOT IN (
               SELECT id FROM application_path_history
               WHERE app_id = ?1
               ORDER BY last_seen DESC, id DESC
               LIMIT ?2
           )",
        rusqlite::params![app_id, APPLICATION_PATH_HISTORY_LIMIT],
    )?;
    Ok(())
}

/// Derives a usable identity when the resolver produced no process name.
///
/// Falls back to the executable's file name, then to the path itself, so a
/// nameless row can never collide with every other nameless row on `''`.
fn fallback_app_name(app_name: &str, app_path: &str) -> String {
    let name = app_name.trim();
    if !name.is_empty() {
        return name.to_owned();
    }
    let path = app_path.trim();
    let basename = path.rsplit(['\\', '/']).next().unwrap_or(path).trim();
    if basename.is_empty() {
        path.to_owned()
    } else {
        basename.to_owned()
    }
}

fn map_application(row: &Row) -> std::result::Result<Application, rusqlite::Error> {
    Ok(Application {
        id: row.get(0)?,
        app_path: row.get(1)?,
        app_name: row.get(2)?,
        signature_fingerprint: row.get(3)?,
        first_seen: get_timestamp(row, 4)?,
    })
}

#[cfg(test)]
fn map_application_path_history(
    row: &Row,
) -> std::result::Result<ApplicationPathHistoryEntry, rusqlite::Error> {
    Ok(ApplicationPathHistoryEntry {
        app_path: row.get(0)?,
        first_seen: get_timestamp(row, 1)?,
        last_seen: get_timestamp(row, 2)?,
    })
}

#[cfg(test)]
mod id_lookup_tests {
    use super::*;
    use crate::models::Application;

    fn store() -> (tempfile::NamedTempFile, crate::store::Store) {
        let file = tempfile::NamedTempFile::new().expect("temp store file");
        let store = crate::store::Store::open(file.path()).expect("open store");
        (file, store)
    }

    fn app(name: &str) -> Application {
        Application {
            id: 0,
            app_path: format!(r"C:\apps\{name}"),
            app_name: name.to_owned(),
            signature_fingerprint: String::new(),
            first_seen: OffsetDateTime::UNIX_EPOCH,
        }
    }

    #[test]
    fn resolves_only_the_requested_ids_and_skips_unknown_or_invalid_ones() {
        let (_dir, store) = store();
        let first = store.upsert_application(&app("a.exe")).expect("a");
        let second = store.upsert_application(&app("b.exe")).expect("b");

        let found = store
            .find_applications_by_ids(&[first, second, 9999, 0, -1, first])
            .expect("lookup");
        let mut ids: Vec<i32> = found.iter().map(|application| application.id).collect();
        ids.sort_unstable();
        assert_eq!(ids, vec![first, second]);

        assert_eq!(
            store.find_applications_by_ids(&[]).expect("empty lookup"),
            []
        );
    }

    #[test]
    fn oversized_id_pages_chunk_without_hitting_the_parameter_limit() {
        let (_dir, store) = store();
        let first = store.upsert_application(&app("a.exe")).expect("a");
        let second = store.upsert_application(&app("b.exe")).expect("b");
        let third = store.upsert_application(&app("c.exe")).expect("c");

        // A 50,000-row page can reference this many distinct ids, more than
        // `SQLite`'s default 32,766 bound-parameter cap.
        let mut ids: Vec<i32> = (1..=50_000).collect();
        ids.extend([first, second, third]);

        let found = store
            .find_applications_by_ids(&ids)
            .expect("chunked lookup");
        let mut found_ids: Vec<i32> = found.iter().map(|application| application.id).collect();
        found_ids.sort_unstable();
        assert_eq!(found_ids, vec![first, second, third]);
    }
}
