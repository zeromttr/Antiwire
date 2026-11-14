use super::*;
use crate::models::{
    activity_bucket_start, format_timestamp, Application, ConnectionDomainUpgrade,
    ConnectionLogAttribution, ConnectionLogQuery, DnsCacheEntry, DomainDecision, FirewallRule,
    NetworkDevice, NetworkDeviceWatch, NewAlert, NewConnectionLog,
};
use antiwire_policy::RuleTargetKind;
use antiwire_secrets::SecretBytes;
use std::sync::{Arc, Barrier};
use tempfile::NamedTempFile;
use time::macros::datetime;

struct MemoryKeyStore;

impl KeyStore for MemoryKeyStore {
    fn load_key(
        &self,
    ) -> std::result::Result<Option<SecretBytes>, antiwire_secrets::KeyStoreError> {
        Ok(None)
    }

    fn save_key(&self, key: &[u8]) -> std::result::Result<(), antiwire_secrets::KeyStoreError> {
        assert_eq!(key.len(), DB_KEY_LEN);
        Ok(())
    }
}

struct FixedKeyStore;

impl KeyStore for FixedKeyStore {
    fn load_key(
        &self,
    ) -> std::result::Result<Option<SecretBytes>, antiwire_secrets::KeyStoreError> {
        Ok(Some(SecretBytes::new(vec![7; DB_KEY_LEN])))
    }

    fn save_key(&self, _key: &[u8]) -> std::result::Result<(), antiwire_secrets::KeyStoreError> {
        unreachable!("fixed key is always available")
    }
}

fn temp_store() -> (NamedTempFile, Store) {
    let file = NamedTempFile::with_suffix(".libsql").expect("temp file");
    let store = Store::open(file.path()).expect("open store");
    (file, store)
}

#[test]
fn migrate_is_idempotent() {
    let (_file, store) = temp_store();
    store.migrate().expect("second migrate");
    store.migrate().expect("third migrate");
}

#[test]
fn a_database_stamped_below_the_baseline_is_refused() {
    let (file, store) = temp_store();
    // The ledger should never hold a non-positive version; planting one
    // simulates a file written by something other than this runner.
    store
        .db
        .execute("DELETE FROM schema_migrations", [])
        .expect("clear version ledger");
    store
        .db
        .execute("INSERT INTO schema_migrations (version) VALUES (-1)", [])
        .expect("tamper with version");
    drop(store);

    // No upgrade path exists from before the consolidated baseline:
    // the mismatch is refused with an actionable message instead of
    // silently running against unknown tables.
    let error = Store::open(file.path())
        .err()
        .expect("pre-baseline schema must be refused");
    assert!(
        error.to_string().contains("schema version"),
        "unexpected error: {error}"
    );
}

#[test]
fn a_newer_database_is_refused_until_the_daemon_is_upgraded() {
    let (file, store) = temp_store();
    store
        .db
        .execute("DELETE FROM schema_migrations", [])
        .expect("clear version ledger");
    store
        .db
        .execute(
            "INSERT INTO schema_migrations (version) VALUES (?1)",
            [latest_migration_version() + 1],
        )
        .expect("fast-forward version");
    drop(store);

    let error = Store::open(file.path())
        .err()
        .expect("a newer database must be refused");
    assert!(
        error.to_string().contains("only knows up to"),
        "unexpected error: {error}"
    );
}

#[test]
fn incremental_migrations_apply_once_and_stamp_versions() {
    let file = NamedTempFile::with_suffix(".libsql").expect("temp file");
    let db = crate::db::Db::open_local(file.path()).expect("open db");
    let store = Store {
        path: file.path().to_path_buf(),
        db,
        db_key: None,
        dns_front: crate::dns_front::DnsFrontCache::new(),
        decision_cache: crate::store::query::domain_decisions::DecisionCache::new(),
        decision_write_lock: Mutex::new(()),
        dns_write_lock: Mutex::new(()),
        settings_write_lock: Mutex::new(()),
        active_conns: Mutex::new(HashSet::new()),
        #[cfg(test)]
        dns_after_commit: Mutex::new(None),
        dns_purge_at: Mutex::new(None),
    };
    store
        .db
        .execute_batch(
            "CREATE TABLE IF NOT EXISTS schema_migrations (
                version INTEGER PRIMARY KEY NOT NULL,
                applied_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
            );",
        )
        .expect("migration ledger");

    let steps: &[(i64, &str)] = &[
        (1, "CREATE TABLE incremental_test (value TEXT NOT NULL);"),
        (
            2,
            "ALTER TABLE incremental_test ADD COLUMN extra TEXT NOT NULL DEFAULT '';",
        ),
    ];
    store.apply_new_migrations(steps).expect("first pass");
    store
        .apply_new_migrations(steps)
        .expect("re-open applies nothing");

    let versions: Vec<i64> = store
        .db
        .query_map(
            "SELECT version FROM schema_migrations WHERE version <= 2 ORDER BY version ASC",
            [],
            |row| row.get(0),
        )
        .expect("versions");
    assert_eq!(
        versions,
        vec![1, 2],
        "each step stamps exactly its own version"
    );

    let columns: Vec<String> = store
        .db
        .query_map("PRAGMA table_info(incremental_test)", [], |row| {
            row.get::<_, String>(1)
        })
        .expect("columns");
    assert_eq!(
        columns,
        vec!["value", "extra"],
        "both steps must have applied"
    );
}

#[test]
fn an_unreadable_rule_is_reported_instead_of_guessed() {
    // A damaged action used to read back as a block, which showed and
    // enforced a rule the user never made.
    let (_file, store) = temp_store();
    for (target_type, action) in [("DNS", "BLOCK"), ("DNS", "DENY"), ("PORT", "ALLOW")] {
        store
            .db
            .execute(
                "INSERT INTO firewall_rules (target_type, target_value, action, direction, created_at)
                 VALUES (?1, 'example.com', ?2, 'OUTBOUND', ?3)",
                rusqlite::params![
                    target_type,
                    action,
                    format_timestamp(datetime!(2026-02-01 10:00:00 UTC))
                ],
            )
            .expect("rule row");
    }

    let rules = store.list_rules().expect("rules");
    assert_eq!(rules.len(), 1, "only the readable row is listed");
    assert_eq!(rules[0].target_type, RuleTargetKind::Dns);
    assert!(matches!(
        store.get_rule(rules[0].id + 1),
        Err(StoreError::UnreadableRule { .. })
    ));
}

#[test]
fn alerts_round_trip_and_can_be_dismissed_or_cleared() {
    let (_file, store) = temp_store();
    let first = NewAlert {
        alert_type: "MALICIOUS_FLOW".to_owned(),
        title: "Blocked connection".to_owned(),
        message: "example.com was blocked".to_owned(),
        timestamp: datetime!(2026-08-03 10:00:00 UTC),
        severity: "WARNING".to_owned(),
    };
    let second = NewAlert {
        timestamp: datetime!(2026-08-03 10:01:00 UTC),
        title: "New application".to_owned(),
        alert_type: "NEW_APP".to_owned(),
        message: "example.exe was seen".to_owned(),
        severity: "INFO".to_owned(),
    };

    let first_id = store.insert_alert(&first).expect("insert first alert");
    let second_id = store.insert_alert(&second).expect("insert second alert");
    let alerts = store.list_alerts().expect("list alerts");
    assert_eq!(alerts.len(), 2);
    assert_eq!(alerts[0].id, second_id);
    assert_eq!(alerts[0].title, "New application");
    assert_eq!(alerts[1].id, first_id);

    assert!(store.delete_alert(first_id).expect("dismiss alert"));
    assert!(!store.delete_alert(first_id).expect("dismiss again"));
    assert_eq!(store.list_alerts().expect("list after dismiss").len(), 1);

    assert_eq!(store.clear_alerts().expect("clear alerts"), 1);
    assert_eq!(store.list_alerts().expect("list after clear"), []);
}

#[test]
fn a_batch_of_alerts_is_saved_in_order_with_its_ids() {
    let (_file, store) = temp_store();
    let alert = |minute: u8| NewAlert {
        alert_type: "NEW_APP".to_owned(),
        title: format!("alert {minute}"),
        message: String::new(),
        timestamp: datetime!(2026-08-03 10:00:00 UTC) + time::Duration::minutes(minute.into()),
        severity: "INFO".to_owned(),
    };

    let ids = store
        .insert_alerts(&[alert(0), alert(1), alert(2)])
        .expect("insert batch");

    assert_eq!(ids.len(), 3);
    assert!(ids.windows(2).all(|pair| pair[0] < pair[1]));
    let saved = store.list_alerts().expect("list alerts");
    assert_eq!(saved[0].id, ids[2]);
    assert_eq!(saved[0].title, "alert 2");
    assert_eq!(store.insert_alerts(&[]).expect("empty batch"), []);
}

#[test]
fn recent_alerts_returns_only_the_newest_rows() {
    let (_file, store) = temp_store();
    for minute in 0..5u8 {
        store
            .insert_alert(&NewAlert {
                alert_type: "MALICIOUS_FLOW".to_owned(),
                title: format!("alert {minute}"),
                message: "example.com was blocked".to_owned(),
                timestamp: datetime!(2026-08-03 10:00 UTC)
                    + time::Duration::minutes(i64::from(minute)),
                severity: "WARNING".to_owned(),
            })
            .expect("insert alert");
    }

    let recent = store.list_recent_alerts(2).expect("recent alerts");
    assert_eq!(recent.len(), 2);
    assert_eq!(recent[0].title, "alert 4");
    assert_eq!(recent[1].title, "alert 3");
}

fn country_rule() -> FirewallRule {
    FirewallRule {
        id: 0,
        target_type: RuleTargetKind::Country,
        target_value: "KP".to_owned(),
        action: antiwire_policy::Verdict::Block,
        direction: antiwire_policy::RuleDirection::Both,
        created_at: datetime!(2026-01-15 12:00:00 UTC),
    }
}

#[test]
fn rule_cidrs_round_trip_in_insertion_order() {
    let (_file, store) = temp_store();
    let cidrs = vec![
        "175.45.176.0/22".to_owned(),
        "210.52.109.0/24".to_owned(),
        "77.94.35.0/24".to_owned(),
    ];
    let id = store
        .insert_rule_with_cidrs(&country_rule(), &cidrs)
        .expect("insert");

    assert_eq!(store.list_rule_cidrs(id).expect("list"), cidrs);
    assert_eq!(
        store.list_all_rule_cidrs().expect("all").get(&id),
        Some(&cidrs)
    );
    assert_eq!(
        store.count_rule_cidrs_by_rule().expect("counts").get(&id),
        Some(&3)
    );
    assert_eq!(store.get_rule(id).expect("rule").target_value, "KP");
}

#[test]
fn deleting_a_rule_cascades_to_its_cidrs() {
    // The cascade depends on `PRAGMA foreign_keys = ON` being set at open,
    // which is easy to lose silently — so assert it rather than assume it.
    let (_file, store) = temp_store();
    let id = store
        .insert_rule_with_cidrs(&country_rule(), &["203.0.113.0/24".to_owned()])
        .expect("insert");
    assert_eq!(store.list_rule_cidrs(id).expect("before").len(), 1);

    store.delete_rule(id).expect("delete");
    assert_eq!(store.list_rule_cidrs(id).expect("after"), [] as [String; 0]);
    assert!(store.list_all_rule_cidrs().expect("all").is_empty());
}

#[test]
fn a_failed_transaction_leaves_no_rule_behind() {
    // `insert_rule_with_cidrs` writes the rule and its networks in one
    // transaction so a failure part-way through cannot persist a rule with
    // a truncated network list. Exercise that rollback directly: forcing a
    // mid-statement SQLite failure is contrived, but the guarantee the
    // caller depends on is that an error anywhere discards the whole write.
    let (_file, store) = temp_store();
    let rule = country_rule();

    let outcome: Result<i32> = store.db.transaction_with(|tx| {
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
        tx.execute(
            "INSERT INTO firewall_rule_cidrs (rule_id, cidr, ordinal) VALUES (?1, ?2, 0)",
            rusqlite::params![rule_id, "203.0.113.0/24"],
        )?;
        Err(StoreError::RuleNotFound(rule_id))
    });

    assert!(outcome.is_err());
    assert_eq!(store.list_rules().expect("rules"), []);
    assert!(store.list_all_rule_cidrs().expect("cidrs").is_empty());
}

#[test]
fn orphaned_cidr_rows_are_refused() {
    // The child table's foreign key is what makes the cascade meaningful;
    // without enforcement, deleting a rule would silently leak its networks.
    let (_file, store) = temp_store();
    assert!(store
        .db
        .execute(
            "INSERT INTO firewall_rule_cidrs (rule_id, cidr, ordinal) VALUES (424242, '10.0.0.0/8', 0)",
            [],
        )
        .is_err());
}

#[test]
fn relocating_an_application_forks_a_new_row_and_reports_the_move() {
    let (_file, store) = temp_store();
    let first = store
        .record_application_sighting(
            "updater.exe",
            r"C:\Program Files\Vendor\v1\updater.exe",
            true,
            datetime!(2026-01-01 00:00:00 UTC),
        )
        .expect("first sighting");
    assert!(first.is_new_application);
    assert_eq!(first.previous_path, None);

    let moved = store
        .record_application_sighting(
            "updater.exe",
            r"C:\Users\me\AppData\Local\Temp\updater.exe",
            true,
            datetime!(2026-01-02 00:00:00 UTC),
        )
        .expect("relocated sighting");
    assert_ne!(moved.app_id, first.app_id);
    assert!(moved.is_new_application);
    assert_eq!(
        moved.previous_path.as_deref(),
        Some(r"C:\Program Files\Vendor\v1\updater.exe")
    );

    // The first location keeps its own row and path, so its historical logs
    // are not rewritten by the move.
    let app = store.get_application(first.app_id).expect("application");
    assert_eq!(app.app_path, r"C:\Program Files\Vendor\v1\updater.exe");
    assert_eq!(store.list_applications().expect("apps").len(), 2);
}

#[test]
fn a_same_named_binary_cannot_repoint_an_existing_application() {
    let (_file, store) = temp_store();
    let base = datetime!(2026-01-01 00:00:00 UTC);
    let chrome = store
        .record_application_sighting(
            "chrome.exe",
            r"C:\Program Files\Google\Chrome\Application\chrome.exe",
            true,
            base,
        )
        .expect("chrome");
    let impostor = store
        .record_application_sighting(
            "chrome.exe",
            r"C:\Users\me\AppData\Local\Temp\chrome.exe",
            true,
            base,
        )
        .expect("impostor");

    assert_ne!(chrome.app_id, impostor.app_id);
    assert_eq!(
        store
            .get_application(chrome.app_id)
            .expect("chrome")
            .app_path,
        r"C:\Program Files\Google\Chrome\Application\chrome.exe"
    );
    assert_eq!(store.list_applications().expect("apps").len(), 2);
}

#[test]
fn a_version_bump_joins_the_existing_application_and_reports_the_move() {
    let (_file, store) = temp_store();
    let first = store
        .record_application_sighting(
            "GitHubDesktop.exe",
            r"C:\Users\me\AppData\Local\GitHubDesktop\app-3.6.5\GitHubDesktop.exe",
            true,
            datetime!(2026-01-01 00:00:00 UTC),
        )
        .expect("first version");
    assert!(first.is_new_application);
    assert!(!first.path_changed);

    let updated = store
        .record_application_sighting(
            "GitHubDesktop.exe",
            r"C:\Users\me\AppData\Local\GitHubDesktop\app-3.6.6\GitHubDesktop.exe",
            true,
            datetime!(2026-01-02 00:00:00 UTC),
        )
        .expect("updated version");

    assert_eq!(updated.app_id, first.app_id);
    assert!(!updated.is_new_application);
    assert!(updated.path_changed);
    assert_eq!(
        updated.previous_path.as_deref(),
        Some(r"C:\Users\me\AppData\Local\GitHubDesktop\app-3.6.5\GitHubDesktop.exe")
    );

    // One row now reports the current install and keeps both locations.
    assert_eq!(store.list_applications().expect("apps").len(), 1);
    let app = store.get_application(first.app_id).expect("application");
    assert_eq!(
        app.app_path,
        r"C:\Users\me\AppData\Local\GitHubDesktop\app-3.6.6\GitHubDesktop.exe"
    );
    let history = store
        .list_application_path_history(first.app_id)
        .expect("history");
    assert_eq!(history.len(), 2);

    // Re-running the new version is no longer a move.
    let again = store
        .record_application_sighting(
            "GitHubDesktop.exe",
            r"C:\Users\me\AppData\Local\GitHubDesktop\app-3.6.6\GitHubDesktop.exe",
            true,
            datetime!(2026-01-03 00:00:00 UTC),
        )
        .expect("same version");
    assert_eq!(again.app_id, first.app_id);
    assert!(!again.path_changed);
    assert_eq!(again.previous_path, None);
}

#[test]
fn the_same_name_outside_the_install_root_stays_its_own_row() {
    let (_file, store) = temp_store();
    let base = datetime!(2026-01-01 00:00:00 UTC);
    let installed = store
        .record_application_sighting(
            "GitHubDesktop.exe",
            r"C:\Users\me\AppData\Local\GitHubDesktop\app-3.6.6\GitHubDesktop.exe",
            true,
            base,
        )
        .expect("installed");
    let portable = store
        .record_application_sighting(
            "GitHubDesktop.exe",
            r"C:\Users\me\Desktop\GitHubDesktop.exe",
            true,
            base,
        )
        .expect("portable");

    assert_ne!(installed.app_id, portable.app_id);
    assert!(portable.is_new_application);
    assert_eq!(
        portable.previous_path.as_deref(),
        Some(r"C:\Users\me\AppData\Local\GitHubDesktop\app-3.6.6\GitHubDesktop.exe")
    );
    assert_eq!(store.list_applications().expect("apps").len(), 2);
}

#[test]
fn non_version_numeric_directories_do_not_merge() {
    let (_file, store) = temp_store();
    let base = datetime!(2026-01-01 00:00:00 UTC);
    let first = store
        .record_application_sighting("report.exe", r"C:\data\2024\report.exe", true, base)
        .expect("first year");
    let second = store
        .record_application_sighting("report.exe", r"C:\data\2025\report.exe", true, base)
        .expect("second year");
    assert_ne!(first.app_id, second.app_id);
    assert_eq!(store.list_applications().expect("apps").len(), 2);
}

#[test]
fn re_running_from_a_known_path_is_not_reported_as_a_move() {
    let (_file, store) = temp_store();
    let base = datetime!(2026-01-01 00:00:00 UTC);
    let first = store
        .record_application_sighting("app.exe", r"C:\apps\app.exe", true, base)
        .expect("first");
    let again = store
        .record_application_sighting("app.exe", r"C:\apps\app.exe", true, base)
        .expect("same path");
    assert_eq!(again.app_id, first.app_id);
    assert!(!again.is_new_application);
    assert_eq!(again.previous_path, None);

    // Windows filenames are case-insensitive: a differently-cased spelling
    // is the same file, and must not read as a relocation.
    let recased = store
        .record_application_sighting("APP.EXE", r"C:\Apps\App.exe", true, base)
        .expect("recased path");
    assert_eq!(recased.app_id, first.app_id);
    assert!(!recased.is_new_application);
    assert_eq!(recased.previous_path, None);
}

#[test]
fn path_history_keeps_the_ten_most_recent_distinct_paths() {
    let (_file, store) = temp_store();
    let base = datetime!(2026-01-01 00:00:00 UTC);
    let app_id = store
        .record_application_sighting("rover.exe", r"C:\dir0\rover.exe", true, base)
        .expect("sighting")
        .app_id;
    for index in 1..15 {
        store
            .record_path_history_for_test(
                app_id,
                &format!(r"C:\dir{index}\rover.exe"),
                base + time::Duration::hours(index),
            )
            .expect("history append");
    }

    let history = store
        .list_application_path_history(app_id)
        .expect("history");
    assert_eq!(
        history.len(),
        usize::try_from(APPLICATION_PATH_HISTORY_LIMIT).expect("limit fits")
    );
    assert_eq!(history[0].app_path, r"C:\dir14\rover.exe");
    assert_eq!(history[9].app_path, r"C:\dir5\rover.exe");
}

#[test]
fn revisiting_a_path_refreshes_it_instead_of_consuming_a_second_slot() {
    let (_file, store) = temp_store();
    let base = datetime!(2026-01-01 00:00:00 UTC);
    let stable = r"C:\apps\flip.exe";
    let other = r"C:\temp\flip.exe";
    let app_id = store
        .record_application_sighting("flip.exe", stable, true, base)
        .expect("sighting")
        .app_id;
    for index in 1..=7 {
        let path = if index % 2 == 0 { other } else { stable };
        store
            .record_path_history_for_test(app_id, path, base + time::Duration::hours(index))
            .expect("history append");
    }

    let history = store
        .list_application_path_history(app_id)
        .expect("history");
    assert_eq!(history.len(), 2);
    assert_eq!(history[0].app_path, stable);
    assert_eq!(history[0].first_seen, base);
    assert_eq!(history[0].last_seen, base + time::Duration::hours(7));
}

#[test]
fn a_placeholder_path_never_displaces_a_real_one() {
    let (_file, store) = temp_store();
    let base = datetime!(2026-01-01 00:00:00 UTC);
    let real = store
        .record_application_sighting("guarded.exe", r"C:\apps\guarded.exe", true, base)
        .expect("real path");

    let fallback = store
        .record_application_sighting(
            "guarded.exe",
            "System / Elevated Process",
            false,
            base + time::Duration::hours(1),
        )
        .expect("failed resolution");

    assert_eq!(fallback.app_id, real.app_id);
    assert_eq!(fallback.previous_path, None);
    assert_eq!(
        store
            .get_application(real.app_id)
            .expect("application")
            .app_path,
        r"C:\apps\guarded.exe"
    );
    assert_eq!(
        store
            .list_application_path_history(real.app_id)
            .expect("history")
            .len(),
        1
    );
}

#[test]
fn placeholder_first_sighting_is_not_auto_merged_by_a_later_real_path() {
    // Order dependence, documented: a fallback sighting that arrives
    // before any real path owns the name's first row, and the later real
    // path forks rather than healing. Same-instance evidence lives in the
    // flow layer (PID plus creation time); the store cannot tell a
    // recovery from a relocation, so it must not guess.
    let (_file, store) = temp_store();
    let base = datetime!(2026-01-01 00:00:00 UTC);
    let fallback = store
        .record_application_sighting("guarded.exe", "System / Elevated Process", false, base)
        .expect("failed resolution");
    assert!(fallback.is_new_application);

    let real = store
        .record_application_sighting(
            "guarded.exe",
            r"C:\apps\guarded.exe",
            true,
            base + time::Duration::hours(1),
        )
        .expect("real path");

    assert_ne!(real.app_id, fallback.app_id);
    assert_eq!(store.list_applications().expect("apps").len(), 2);
}

#[test]
fn unreferenced_placeholders_are_pruned_but_nothing_else_is() {
    let (file, store) = temp_store();
    let base = datetime!(2026-01-01 00:00:00 UTC);
    let orphan = store
        .record_application_sighting("ghost.exe", "System / Elevated Process", false, base)
        .expect("placeholder")
        .app_id;
    let real = store
        .record_application_sighting("real.exe", r"C:\apps\real.exe", true, base)
        .expect("real")
        .app_id;

    let system = store
        .record_application_sighting("system", "System", true, base)
        .expect("system")
        .app_id;
    let unknown = store
        .record_application_sighting("unknown.exe", "Unknown (Exited)", false, base)
        .expect("unknown")
        .app_id;
    // Cleanup only happens after the previous lifetime's owners are gone.
    drop(store);
    let store = Store::open(file.path()).expect("reopen");
    assert!(store.get_application(orphan).is_err());
    assert!(store.get_application(unknown).is_err());
    // Real rows are identities, never residue — even with no logs yet.
    assert!(store.get_application(real).is_ok());
    assert!(store.get_application(system).is_ok());
}

#[test]
fn referenced_placeholders_survive_pruning() {
    let (file, store) = temp_store();
    let base = datetime!(2026-01-01 00:00:00 UTC);
    let placeholder = store
        .record_application_sighting("busy.exe", "System / Elevated Process", false, base)
        .expect("placeholder")
        .app_id;
    store
        .db
        .execute(
            "INSERT INTO connection_logs (timestamp, app_id, last_seen) VALUES (?1, ?2, ?1)",
            rusqlite::params!["2026-01-01T00:00:00Z", placeholder,],
        )
        .expect("log referencing the placeholder");

    drop(store);
    let store = Store::open(file.path()).expect("reopen");
    assert!(store.get_application(placeholder).is_ok());
}

#[test]
fn nameless_applications_do_not_collapse_onto_each_other() {
    let (_file, store) = temp_store();
    let base = datetime!(2026-01-01 00:00:00 UTC);
    let first = store
        .record_application_sighting("", r"C:\one\alpha.exe", true, base)
        .expect("first nameless");
    let second = store
        .record_application_sighting("", r"C:\two\beta.exe", true, base)
        .expect("second nameless");

    assert_ne!(first.app_id, second.app_id);
    assert_eq!(
        store.get_application(first.app_id).expect("first").app_name,
        "alpha.exe"
    );
}

#[test]
fn firewall_rule_crud_round_trip() {
    let (_file, store) = temp_store();
    let created_at = datetime!(2026-01-15 12:00:00 UTC);
    let mut rule = FirewallRule {
        id: 0,
        target_type: RuleTargetKind::Dns,
        target_value: "evil.test".to_owned(),
        action: antiwire_policy::Verdict::Block,
        direction: antiwire_policy::RuleDirection::Both,
        created_at,
    };

    let id = store.insert_rule(&rule).expect("insert rule");
    rule.id = id;

    let loaded = store.get_rule(id).expect("get rule");
    assert_eq!(loaded, rule);

    rule.action = antiwire_policy::Verdict::Allow;
    rule.direction = antiwire_policy::RuleDirection::Inbound;
    store.update_rule(&rule).expect("update rule");
    let reloaded = store.get_rule(id).expect("reload");
    assert_eq!(reloaded.action, antiwire_policy::Verdict::Allow);
    assert_eq!(reloaded.direction, antiwire_policy::RuleDirection::Inbound);

    let all = store.list_rules().expect("list rules");
    assert_eq!(all.len(), 1);

    store.delete_rule(id).expect("delete rule");
    assert!(matches!(
        store.get_rule(id),
        Err(StoreError::RuleNotFound(found)) if found == id
    ));
}

#[test]
fn application_rules_are_listed_in_creation_order_and_exclude_other_types() {
    let (_file, store) = temp_store();
    let first_id = store
        .insert_rule(&FirewallRule {
            id: 0,
            target_type: RuleTargetKind::Application,
            target_value: r"C:\Apps\App-1.0\app.exe".to_owned(),
            action: antiwire_policy::Verdict::Block,
            direction: antiwire_policy::RuleDirection::Both,
            created_at: datetime!(2026-01-15 12:00:00 UTC),
        })
        .expect("first application rule");
    store
        .insert_rule(&FirewallRule {
            id: 0,
            target_type: RuleTargetKind::Application,
            target_value: r"C:\Other\app.exe".to_owned(),
            action: antiwire_policy::Verdict::Allow,
            direction: antiwire_policy::RuleDirection::Both,
            created_at: datetime!(2026-01-16 12:00:00 UTC),
        })
        .expect("second application rule");
    store
        .insert_rule(&country_rule())
        .expect("country rule is not an application");

    let listed = store.list_application_rules().expect("list");
    assert_eq!(listed.len(), 2);
    assert_eq!(listed[0].id, first_id);
    assert_eq!(listed[0].target_value, r"C:\Apps\App-1.0\app.exe");
    assert_eq!(listed[1].target_value, r"C:\Other\app.exe");
}

#[test]
fn concurrent_rule_inserts_return_their_own_row_ids() {
    const INSERT_COUNT: usize = 16;

    let (_file, store) = temp_store();
    let store = Arc::new(store);
    let barrier = Arc::new(Barrier::new(INSERT_COUNT));
    let mut workers = Vec::with_capacity(INSERT_COUNT);

    for index in 0..INSERT_COUNT {
        let store = Arc::clone(&store);
        let barrier = Arc::clone(&barrier);
        workers.push(std::thread::spawn(move || {
            let target_value = format!("concurrent-{index}.test");
            let rule = FirewallRule {
                id: 0,
                target_type: RuleTargetKind::Dns,
                target_value: target_value.clone(),
                action: antiwire_policy::Verdict::Block,
                direction: antiwire_policy::RuleDirection::Outbound,
                created_at: datetime!(2026-01-15 12:00:00 UTC),
            };
            barrier.wait();
            let id = store.insert_rule(&rule).expect("insert concurrent rule");
            let stored = store.get_rule(id).expect("load inserted rule");
            assert_eq!(stored.target_value, target_value);
            id
        }));
    }

    let mut ids = workers
        .into_iter()
        .map(|worker| worker.join().expect("join insert worker"))
        .collect::<Vec<_>>();
    ids.sort_unstable();
    ids.dedup();
    assert_eq!(ids.len(), INSERT_COUNT);
}

#[test]
fn ai_endpoint_is_not_persisted() {
    let (_file, store) = temp_store();
    let has_ai_url: i64 = store
        .db
        .query_row(
            "SELECT COUNT(*) FROM pragma_table_info('daemon_settings') WHERE name = 'ai_url'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(has_ai_url, 0);
    let settings = store.get_settings().expect("settings still load");
    store
        .update_settings(&settings)
        .expect("settings still save");
}

#[test]
fn private_relay_compatibility_starts_off_and_saves() {
    let (_file, store) = temp_store();
    let mut settings = store.get_settings().expect("settings");
    assert!(!settings.private_relay_compatibility);
    assert!(settings.uses_packet_rules());

    settings.private_relay_compatibility = true;
    store.update_settings(&settings).expect("save");

    let saved = store.get_settings().expect("reload");
    assert!(saved.private_relay_compatibility);
    assert!(!saved.uses_packet_rules());
}

#[test]
fn single_column_setters_leave_the_rest_of_the_row_alone() {
    let (_file, store) = temp_store();
    let mut settings = store.get_settings().expect("get settings");
    settings.siem_url = "https://siem.example".to_owned();
    settings.hosts_blocklist_enabled = true;
    store.update_settings(&settings).expect("update settings");

    let at = datetime!(2026-01-02 03:04:05 UTC);
    store.set_hosts_blocklist_last_updated(at).expect("hosts");
    store.set_geoip_database_last_updated(at).expect("geoip");

    let reloaded = store.get_settings().expect("reload");
    assert_eq!(reloaded.hosts_blocklist_last_updated, at);
    assert_eq!(reloaded.geoip_database_last_updated, at);
    assert_eq!(reloaded.siem_url, "https://siem.example");
    assert!(reloaded.hosts_blocklist_enabled);
}

/// The regression the record's own table guards: a whole-row settings save
/// wrote back the redirect record it had read, so a save that raced a
/// redirect lost the adapters' real DNS servers. Settings saves no longer
/// reach the record at all.
#[test]
fn settings_saves_never_touch_the_dns_redirect_record() {
    let (_file, store) = temp_store();
    let stale = store.get_settings().expect("settings");
    store.set_dns_redirect("saved adapters").expect("record");

    store
        .update_settings(&stale)
        .expect("a whole-row save of an older copy");
    store
        .modify_settings(|previous| Ok(previous.clone()))
        .expect("a merge");

    assert_eq!(
        store.get_dns_redirect().expect("record").as_deref(),
        Some("saved adapters")
    );
}

#[test]
fn the_dns_redirect_record_is_replaced_and_cleared() {
    let (_file, store) = temp_store();
    assert_eq!(store.get_dns_redirect().expect("nothing recorded"), None);

    store.set_dns_redirect("wifi").expect("record");
    store.set_dns_redirect("wifi+vpn").expect("replace");
    assert_eq!(
        store.get_dns_redirect().expect("record").as_deref(),
        Some("wifi+vpn")
    );

    store.clear_dns_redirect().expect("clear");
    assert_eq!(store.get_dns_redirect().expect("cleared"), None);
    store
        .clear_dns_redirect()
        .expect("clearing again is harmless");
}

#[test]
fn settings_get_and_update() {
    let (_file, store) = temp_store();
    let mut settings = store.get_settings().expect("get settings");
    assert_eq!(settings.id, 1);
    assert!(settings.dns_resolver_enabled);

    settings.ai_api_key = antiwire_secrets::SecretBytes::from_string("secret-token".to_owned());
    settings.ai_enabled = true;
    settings.ai_decision_mode = "proactive".to_owned();
    settings.ai_confidence_fraud = 140;
    settings.ai_confidence_tunnel = 65;
    settings.ai_confidence_advertising = 40;
    settings.ai_confidence_tracking = 0;
    settings.ai_advertising_enabled = false;
    settings.ai_malicious_action = "block".to_owned();
    settings.ai_tunnel_action = "nonsense".to_owned();
    store.update_settings(&settings).expect("update settings");

    let reloaded = store.get_settings().expect("reload settings");
    assert!(reloaded.ai_enabled);
    assert_eq!(
        reloaded.ai_api_key.expose_secret(),
        b"secret-token".as_slice()
    );
    assert!(!format!("{reloaded:?}").contains("secret-token"));
    assert_eq!(reloaded.ai_decision_mode, "proactive");
    assert_eq!(reloaded.ai_confidence_fraud, 100);
    assert_eq!(reloaded.ai_confidence_tunnel, 65);
    assert_eq!(reloaded.ai_confidence_advertising, 60);
    assert_eq!(reloaded.ai_confidence_tracking, 60);
    assert!(!reloaded.ai_advertising_enabled);
    assert_eq!(reloaded.ai_malicious_action, "block");
    assert_eq!(
        reloaded.ai_tunnel_action, "record",
        "an unrecognized action must normalize to record"
    );
    assert_eq!(reloaded.ai_advertising_action, "record");
    assert!(reloaded.ai_tracking_enabled);
}

#[test]
fn domain_decision_upsert_preserves_first_seen() {
    let (_file, store) = temp_store();
    let first = datetime!(2026-04-01 09:00:00 UTC);
    let later = datetime!(2026-04-02 10:00:00 UTC);

    assert!(store
        .get_domain_decision("ads.example.com")
        .expect("get missing")
        .is_none());

    let decision = DomainDecision {
        domain: "ADS.Example.com".to_owned(),
        model: "jev-1.13.0".to_owned(),
        rating_advertising: 0.92,
        rating_tracking: 0.41,
        rating_telemetry: 0.1,
        rating_analytics: 0.2,
        rating_malicious: 0.01,
        rating_fraud: 0.0,
        rating_cryptomining: 0.0,
        rating_tunnel: 0.05,
        verdict: "block".to_owned(),
        top_category: "advertising".to_owned(),
        top_score: 0.92,
        rating_newly_registered: 0.0,
        rating_registry_hold: 0.0,
        rating_hidden_registrant: 0.0,
        rating_abusive_registrar: 0.0,
        scan_tier: "advanced".to_owned(),
        first_seen: first,
        updated_at: first,
    };
    store
        .upsert_domain_decision(&decision)
        .expect("insert decision");

    let stored = store
        .get_domain_decision("ads.example.com")
        .expect("get decision")
        .expect("decision present");
    assert_eq!(stored.domain, "ads.example.com", "domain key is normalized");
    assert_eq!(stored.model, "jev-1.13.0");
    assert!((stored.rating_advertising - 0.92).abs() < 1e-9);
    assert_eq!(stored.verdict, "block");
    assert_eq!(stored.top_category, "advertising");
    assert_eq!(stored.scan_tier, "advanced");
    assert_eq!(stored.first_seen, first);

    let updated = DomainDecision {
        rating_advertising: 0.3,
        verdict: "record".to_owned(),
        top_category: "tracking".to_owned(),
        top_score: 0.61,
        rating_newly_registered: 0.0,
        rating_registry_hold: 0.0,
        rating_hidden_registrant: 0.0,
        rating_abusive_registrar: 0.0,
        scan_tier: "nonsense".to_owned(),
        updated_at: later,
        ..decision
    };
    store
        .upsert_domain_decision(&updated)
        .expect("update decision");

    let stored = store
        .get_domain_decision("ads.example.com")
        .expect("get updated")
        .expect("decision present");
    assert_eq!(
        stored.first_seen, first,
        "first_seen must survive an update"
    );
    assert_eq!(stored.updated_at, later);
    assert!((stored.rating_advertising - 0.3).abs() < 1e-9);
    assert_eq!(stored.verdict, "record");
    assert_eq!(stored.top_category, "tracking");
    assert_eq!(
        stored.scan_tier, "basic",
        "unknown tier normalizes to basic"
    );

    assert!(
        store.get_domain_decision("   ").is_err(),
        "an empty domain is rejected"
    );
}

#[test]
fn settings_encrypt_api_key_with_keystore() {
    let file = NamedTempFile::with_suffix(".libsql").expect("temp file");
    let keystore = MemoryKeyStore;
    let store = Store::open_with_keystore(file.path(), &keystore).expect("open with keystore");

    let mut settings = store.get_settings().expect("get settings");
    settings.ai_api_key = antiwire_secrets::SecretBytes::from_string("secret-token".to_owned());
    store.update_settings(&settings).expect("update settings");

    let reloaded = store.get_settings().expect("reload settings");
    assert_eq!(
        reloaded.ai_api_key.expose_secret(),
        b"secret-token".as_slice()
    );
    let stored: String = store
        .db
        .query_row(
            "SELECT ai_api_key FROM daemon_settings WHERE id = 1",
            [],
            |row| row.get(0),
        )
        .expect("raw encrypted setting");
    assert!(stored.starts_with("enc:v2:"));
}

/// The regression this guards: the SIEM auth token sat in the database as
/// plaintext beside the encrypted AI key.
#[test]
fn settings_encrypt_siem_token_and_read_a_legacy_plaintext_one() {
    let file = NamedTempFile::with_suffix(".libsql").expect("temp file");
    let store =
        Store::open_with_keystore(file.path(), &MemoryKeyStore).expect("open with keystore");
    let raw = |store: &Store| -> String {
        store
            .db
            .query_row(
                "SELECT siem_auth_token FROM daemon_settings WHERE id = 1",
                [],
                |row| row.get(0),
            )
            .expect("raw setting")
    };

    // A token written before encryption still reads back.
    store
        .db
        .execute(
            "UPDATE daemon_settings SET siem_auth_token = 'legacy-token' WHERE id = 1",
            [],
        )
        .expect("legacy token");
    let mut settings = store.get_settings().expect("get settings");
    assert_eq!(settings.siem_auth_token, "legacy-token");

    // The next save encrypts it.
    settings.siem_auth_token = "Bearer hunter2".to_owned();
    store.update_settings(&settings).expect("update settings");
    assert!(raw(&store).starts_with("enc:v2:"));
    assert_eq!(
        store.get_settings().expect("reload").siem_auth_token,
        "Bearer hunter2"
    );
}

#[test]
fn legacy_v1_setting_is_rewritten_on_update() {
    let file = NamedTempFile::with_suffix(".libsql").expect("temp file");
    let store =
        Store::open_with_keystore(file.path(), &FixedKeyStore).expect("open with fixed key");
    let key = SecretBytes::new(vec![7; DB_KEY_LEN]);
    let legacy = crate::crypto::encrypt_v1_for_test("legacy-token", &key);
    store
        .db
        .execute(
            "UPDATE daemon_settings SET ai_api_key = ?1 WHERE id = 1",
            [&legacy],
        )
        .expect("insert legacy setting");

    let settings = store.get_settings().expect("read legacy setting");
    assert_eq!(
        settings.ai_api_key.expose_secret(),
        b"legacy-token".as_slice()
    );
    store
        .update_settings(&settings)
        .expect("rewrite legacy setting");

    let stored: String = store
        .db
        .query_row(
            "SELECT ai_api_key FROM daemon_settings WHERE id = 1",
            [],
            |row| row.get(0),
        )
        .expect("raw encrypted setting");
    assert!(stored.starts_with("enc:v2:"));
}

#[test]
fn connection_log_batch_insert_and_paginated_query() {
    let (_file, store) = temp_store();
    let base = datetime!(2026-02-01 10:00:00 UTC);

    let logs = vec![
        NewConnectionLog {
            replace_domain: false,
            is_close: false,
            conn_pid: 0,
            conn_id: 0,
            timestamp: base,
            app_id: 1,
            app_path: String::new(),
            protocol: "TCP".to_owned(),
            src_ip: "10.0.0.1".to_owned(),
            src_port: 12345,
            dst_ip: "93.184.216.34".to_owned(),
            dst_port: 443,
            dst_domain: "example.com".to_owned(),
            bytes_sent: 1024,
            bytes_received: 4096,
            action_taken: "ALLOWED".to_owned(),
            last_seen: base,
            country_code: "US".to_owned(),
            isp: "Example ISP".to_owned(),
            blocklist_names: String::new(),
        },
        NewConnectionLog {
            replace_domain: false,
            is_close: false,
            conn_pid: 0,
            conn_id: 0,
            timestamp: base,
            app_id: 2,
            app_path: String::new(),
            protocol: "UDP".to_owned(),
            src_ip: "10.0.0.2".to_owned(),
            src_port: 53,
            dst_ip: "1.1.1.1".to_owned(),
            dst_port: 53,
            dst_domain: String::new(),
            bytes_sent: 128,
            bytes_received: 64,
            action_taken: "BLOCKED".to_owned(),
            last_seen: base + time::Duration::seconds(5),
            country_code: String::new(),
            isp: String::new(),
            blocklist_names: String::new(),
        },
    ];

    store
        .insert_connection_logs(&logs)
        .expect("batch insert logs");

    let page = store
        .query_connection_logs(&ConnectionLogQuery {
            limit: 1,
            sort_descending: true,
            ..ConnectionLogQuery::default()
        })
        .expect("query logs");

    assert_eq!(page.total_count, 2);
    assert_eq!(page.blocked_count, 1);
    assert_eq!(page.unique_domain_count, 1);
    assert_eq!(page.logs.len(), 1);
    assert_eq!(page.logs[0].action_taken, "BLOCKED");

    let allowed = store
        .query_connection_logs(&ConnectionLogQuery {
            action_filter: Some("Allowed".to_owned()),
            ..ConnectionLogQuery::default()
        })
        .expect("allowed filter");
    assert_eq!(allowed.total_count, 1);
    assert_eq!(allowed.logs[0].action_taken, "ALLOWED");
}

#[test]
fn connection_log_query_filters_by_application_name() {
    let (_file, store) = temp_store();
    let base = datetime!(2026-02-01 10:00:00 UTC);
    let chrome_id = store
        .upsert_application(&Application {
            id: 0,
            app_path: "C:\\Chrome\\chrome.exe".to_owned(),
            app_name: "chrome.exe".to_owned(),
            signature_fingerprint: String::new(),
            first_seen: base,
        })
        .expect("chrome app");
    let firefox_id = store
        .upsert_application(&Application {
            id: 0,
            app_path: "C:\\Firefox\\firefox.exe".to_owned(),
            app_name: "firefox.exe".to_owned(),
            signature_fingerprint: String::new(),
            first_seen: base,
        })
        .expect("firefox app");

    store
        .insert_connection_logs(&[
            NewConnectionLog {
                replace_domain: false,
                is_close: false,
                conn_pid: 0,
                conn_id: 0,
                timestamp: base,
                app_id: chrome_id,
                app_path: String::new(),
                protocol: "TCP".to_owned(),
                src_ip: "10.0.0.1".to_owned(),
                src_port: 12345,
                dst_ip: "93.184.216.34".to_owned(),
                dst_port: 443,
                dst_domain: "example.com".to_owned(),
                bytes_sent: 1024,
                bytes_received: 4096,
                action_taken: "ALLOWED".to_owned(),
                last_seen: base,
                country_code: "US".to_owned(),
                isp: String::new(),
                blocklist_names: String::new(),
            },
            NewConnectionLog {
                replace_domain: false,
                is_close: false,
                conn_pid: 0,
                conn_id: 0,
                timestamp: base,
                app_id: firefox_id,
                app_path: String::new(),
                protocol: "TCP".to_owned(),
                src_ip: "10.0.0.2".to_owned(),
                src_port: 54321,
                dst_ip: "93.184.216.35".to_owned(),
                dst_port: 443,
                dst_domain: "mozilla.org".to_owned(),
                bytes_sent: 512,
                bytes_received: 256,
                action_taken: "ALLOWED".to_owned(),
                last_seen: base,
                country_code: String::new(),
                isp: String::new(),
                blocklist_names: String::new(),
            },
        ])
        .expect("insert logs");

    let chrome_only = store
        .query_connection_logs(&ConnectionLogQuery {
            app_name: Some("chrome.exe".to_owned()),
            ..ConnectionLogQuery::default()
        })
        .expect("chrome filter");

    assert_eq!(chrome_only.total_count, 1);
    assert_eq!(chrome_only.logs.len(), 1);
    assert_eq!(chrome_only.logs[0].app_id, chrome_id);
    assert_eq!(chrome_only.logs[0].dst_domain, "example.com");
}

#[test]
fn connection_log_query_filters_by_application_id_within_shared_name() {
    let (_file, store) = temp_store();
    let base = datetime!(2026-02-01 10:00:00 UTC);
    let log_for = |app_id: i32, dst_ip: &str| NewConnectionLog {
        replace_domain: false,
        is_close: false,
        conn_pid: 0,
        conn_id: 0,
        timestamp: base,
        app_id,
        app_path: String::new(),
        protocol: "TCP".to_owned(),
        src_ip: "10.0.0.1".to_owned(),
        src_port: 12345,
        dst_ip: dst_ip.to_owned(),
        dst_port: 443,
        dst_domain: String::new(),
        bytes_sent: 10,
        bytes_received: 10,
        action_taken: "ALLOWED".to_owned(),
        last_seen: base,
        country_code: String::new(),
        isp: String::new(),
        blocklist_names: String::new(),
    };

    // One name at two install paths forks two application rows by design.
    let first_id = store
        .upsert_application(&Application {
            id: 0,
            app_path: "C:\\Apps\\v1\\tool.exe".to_owned(),
            app_name: "tool.exe".to_owned(),
            signature_fingerprint: String::new(),
            first_seen: base,
        })
        .expect("first path");
    let second_id = store
        .upsert_application(&Application {
            id: 0,
            app_path: "C:\\Apps\\v2\\tool.exe".to_owned(),
            app_name: "tool.exe".to_owned(),
            signature_fingerprint: String::new(),
            first_seen: base,
        })
        .expect("second path");
    assert_ne!(first_id, second_id, "each path keeps its own row");

    store
        .insert_connection_logs(&[
            log_for(first_id, "93.184.216.34"),
            log_for(second_id, "93.184.216.35"),
        ])
        .expect("insert logs");

    // Name-only (legacy) matches both install paths.
    let both = store
        .query_connection_logs(&ConnectionLogQuery {
            app_name: Some("tool.exe".to_owned()),
            ..ConnectionLogQuery::default()
        })
        .expect("name filter");
    assert_eq!(both.total_count, 2);

    // An exact id narrows the name match to one install path.
    let exact = store
        .query_connection_logs(&ConnectionLogQuery {
            app_name: Some("tool.exe".to_owned()),
            app_id: Some(second_id),
            ..ConnectionLogQuery::default()
        })
        .expect("id filter");
    assert_eq!(exact.total_count, 1);
    assert_eq!(exact.logs[0].app_id, second_id);

    // A non-positive id preserves the legacy name-only match for older clients.
    let legacy = store
        .query_connection_logs(&ConnectionLogQuery {
            app_name: Some("tool.exe".to_owned()),
            app_id: Some(0),
            ..ConnectionLogQuery::default()
        })
        .expect("zero id filter");
    assert_eq!(legacy.total_count, 2);

    // Summaries still report one row per install path, each carrying its id
    // so the UI can select exactly the row whose count it shows.
    let summaries = store
        .query_application_log_summaries(&crate::models::ApplicationLogSummaryQuery::default())
        .expect("summaries");
    assert_eq!(summaries.len(), 2);
    for summary in &summaries {
        assert_eq!(summary.connection_count, 1);
        assert!(summary.app_id == first_id || summary.app_id == second_id);
    }
}

#[test]
fn connection_log_query_orders_globally_by_bytes_received() {
    let (_file, store) = temp_store();
    let base = datetime!(2026-02-01 10:00:00 UTC);

    for (index, bytes_received) in [(1_i32, 100_i64), (2, 900), (3, 500)] {
        store
            .insert_connection_logs(&[NewConnectionLog {
                replace_domain: false,
                is_close: false,
                conn_pid: 0,
                conn_id: 0,
                timestamp: base + time::Duration::seconds(i64::from(index)),
                app_id: index,
                app_path: String::new(),
                protocol: "TCP".to_owned(),
                src_ip: format!("10.0.0.{index}"),
                src_port: 40_000 + index,
                dst_ip: format!("93.184.216.{index}"),
                dst_port: 443,
                dst_domain: format!("host{index}.example"),
                bytes_sent: 10,
                bytes_received,
                action_taken: "ALLOWED".to_owned(),
                last_seen: base + time::Duration::seconds(i64::from(index)),
                country_code: String::new(),
                isp: String::new(),
                blocklist_names: String::new(),
            }])
            .expect("insert log");
    }

    let page_one = store
        .query_connection_logs(&ConnectionLogQuery {
            limit: 2,
            order_by: Some("bytes_received".to_owned()),
            sort_descending: true,
            ..ConnectionLogQuery::default()
        })
        .expect("page one");
    assert_eq!(page_one.total_count, 3);
    assert_eq!(page_one.logs.len(), 2);
    assert_eq!(page_one.logs[0].bytes_received, 900);
    assert_eq!(page_one.logs[1].bytes_received, 500);

    let page_two = store
        .query_connection_logs(&ConnectionLogQuery {
            limit: 2,
            offset: 2,
            order_by: Some("bytes_received".to_owned()),
            sort_descending: true,
            ..ConnectionLogQuery::default()
        })
        .expect("page two");
    assert_eq!(page_two.logs.len(), 1);
    assert_eq!(page_two.logs[0].bytes_received, 100);
}

#[test]
fn connection_log_query_filters_by_protocol() {
    let (_file, store) = temp_store();
    let base = datetime!(2026-02-01 10:00:00 UTC);

    store
        .insert_connection_logs(&[
            NewConnectionLog {
                replace_domain: false,
                is_close: false,
                conn_pid: 0,
                conn_id: 0,
                timestamp: base,
                app_id: 1,
                app_path: String::new(),
                protocol: "TCP".to_owned(),
                src_ip: "10.0.0.1".to_owned(),
                src_port: 12345,
                dst_ip: "93.184.216.34".to_owned(),
                dst_port: 443,
                dst_domain: "example.com".to_owned(),
                bytes_sent: 1024,
                bytes_received: 4096,
                action_taken: "ALLOWED".to_owned(),
                last_seen: base,
                country_code: String::new(),
                isp: String::new(),
                blocklist_names: String::new(),
            },
            NewConnectionLog {
                replace_domain: false,
                is_close: false,
                conn_pid: 0,
                conn_id: 0,
                timestamp: base,
                app_id: 2,
                app_path: String::new(),
                protocol: "UDP".to_owned(),
                src_ip: "10.0.0.2".to_owned(),
                src_port: 53,
                dst_ip: "1.1.1.1".to_owned(),
                dst_port: 53,
                dst_domain: String::new(),
                bytes_sent: 128,
                bytes_received: 64,
                action_taken: "ALLOWED".to_owned(),
                last_seen: base,
                country_code: String::new(),
                isp: String::new(),
                blocklist_names: String::new(),
            },
        ])
        .expect("insert logs");

    let udp_only = store
        .query_connection_logs(&ConnectionLogQuery {
            protocol_filter: Some("UDP".to_owned()),
            ..ConnectionLogQuery::default()
        })
        .expect("udp filter");

    assert_eq!(udp_only.total_count, 1);
    assert_eq!(udp_only.logs[0].protocol, "UDP");
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "country filter regression cases share one fixture"
)]
fn connection_log_query_filters_by_country_code() {
    let (_file, store) = temp_store();
    let base = datetime!(2026-02-01 10:00:00 UTC);

    store
        .insert_connection_logs(&[
            NewConnectionLog {
                replace_domain: false,
                is_close: false,
                conn_pid: 0,
                conn_id: 0,
                timestamp: base,
                app_id: 1,
                app_path: String::new(),
                protocol: "TCP".to_owned(),
                src_ip: "10.0.0.1".to_owned(),
                src_port: 12_345,
                dst_ip: "93.184.216.34".to_owned(),
                dst_port: 443,
                dst_domain: "example.com".to_owned(),
                bytes_sent: 1024,
                bytes_received: 4096,
                action_taken: "ALLOWED".to_owned(),
                last_seen: base,
                country_code: "US".to_owned(),
                isp: String::new(),
                blocklist_names: String::new(),
            },
            NewConnectionLog {
                replace_domain: false,
                is_close: false,
                conn_pid: 0,
                conn_id: 0,
                timestamp: base,
                app_id: 1,
                app_path: String::new(),
                protocol: "TCP".to_owned(),
                src_ip: "10.0.0.1".to_owned(),
                src_port: 12_346,
                dst_ip: "198.51.100.1".to_owned(),
                dst_port: 443,
                dst_domain: "other.example".to_owned(),
                bytes_sent: 512,
                bytes_received: 256,
                action_taken: "ALLOWED".to_owned(),
                last_seen: base,
                country_code: "PR".to_owned(),
                isp: String::new(),
                blocklist_names: String::new(),
            },
            NewConnectionLog {
                replace_domain: false,
                is_close: false,
                conn_pid: 0,
                conn_id: 0,
                timestamp: base,
                app_id: 1,
                app_path: String::new(),
                protocol: "TCP".to_owned(),
                src_ip: "10.0.0.1".to_owned(),
                src_port: 12_347,
                dst_ip: "203.0.113.1".to_owned(),
                dst_port: 443,
                dst_domain: "nl.example".to_owned(),
                bytes_sent: 256,
                bytes_received: 128,
                action_taken: "ALLOWED".to_owned(),
                last_seen: base,
                country_code: "NL".to_owned(),
                isp: String::new(),
                blocklist_names: String::new(),
            },
        ])
        .expect("insert logs");

    let us_only = store
        .query_connection_logs(&ConnectionLogQuery {
            country_code: Some("US".to_owned()),
            ..ConnectionLogQuery::default()
        })
        .expect("us filter");

    assert_eq!(us_only.total_count, 2);
    assert!(us_only
        .logs
        .iter()
        .all(|log| log.country_code == "US" || log.country_code == "PR"));

    let nl_only = store
        .query_connection_logs(&ConnectionLogQuery {
            country_code: Some("NL".to_owned()),
            ..ConnectionLogQuery::default()
        })
        .expect("nl filter");

    assert_eq!(nl_only.total_count, 1);
    assert_eq!(nl_only.logs[0].country_code, "NL");

    // Host matches the domain case-insensitively, or the exact IP.
    let by_domain = store
        .query_connection_logs(&ConnectionLogQuery {
            host: Some("Other.Example".to_owned()),
            ..ConnectionLogQuery::default()
        })
        .expect("host filter");
    assert_eq!(by_domain.total_count, 1);
    assert_eq!(by_domain.logs[0].country_code, "PR");

    let by_ip = store
        .query_connection_logs(&ConnectionLogQuery {
            host: Some("203.0.113.1".to_owned()),
            ..ConnectionLogQuery::default()
        })
        .expect("ip filter");
    assert_eq!(by_ip.total_count, 1);

    // Filters stack: port 443 and the US group together.
    let stacked = store
        .query_connection_logs(&ConnectionLogQuery {
            port: Some(443),
            country_code: Some("US".to_owned()),
            ..ConnectionLogQuery::default()
        })
        .expect("stacked filters");
    assert_eq!(stacked.total_count, 2);

    let wrong_port = store
        .query_connection_logs(&ConnectionLogQuery {
            port: Some(80),
            ..ConnectionLogQuery::default()
        })
        .expect("port filter");
    assert_eq!(wrong_port.total_count, 0);
}

#[test]
fn country_statistics_include_entire_history_and_normalize_codes() {
    let (_file, store) = temp_store();
    let base = datetime!(2026-02-01 10:00:00 UTC);
    let make_log = |country: &str, last_seen| NewConnectionLog {
        replace_domain: false,
        is_close: false,
        conn_pid: 0,
        conn_id: 0,
        timestamp: base,
        app_id: 1,
        app_path: String::new(),
        protocol: "TCP".to_owned(),
        src_ip: "10.0.0.1".to_owned(),
        src_port: 12_345,
        dst_ip: "93.184.216.34".to_owned(),
        dst_port: 443,
        dst_domain: "example.com".to_owned(),
        bytes_sent: 0,
        bytes_received: 0,
        action_taken: "ALLOWED".to_owned(),
        last_seen,
        country_code: country.to_owned(),
        isp: String::new(),
        blocklist_names: String::new(),
    };
    let mut logs: Vec<_> = [
        "IN", " us ", "DE", "GB", "FR", "CA", "AU", "JP", "", "  ", "OTHER", "-", "—",
    ]
    .iter()
    .map(|country| make_log(country, base))
    .collect();
    logs.extend((0..301).map(|_| make_log("US", base + time::Duration::days(1))));
    store.insert_connection_logs(&logs).expect("insert history");

    let sample = store
        .query_connection_logs(&ConnectionLogQuery {
            limit: 300,
            ..ConnectionLogQuery::default()
        })
        .expect("recent sample");
    assert!(sample.logs.iter().all(|log| log.country_code == "US"));

    let statistics = store
        .query_country_statistics()
        .expect("country statistics");
    assert_eq!(statistics.total_count, 314);
    assert_eq!(statistics.unknown_count, 5);
    assert_eq!(statistics.country_counts.len(), 8);
    assert_eq!(statistics.country_counts["US"], 302);
    assert_eq!(statistics.country_counts["IN"], 1);
    assert_eq!(statistics.country_counts.values().sum::<u64>(), 309);
}

#[test]
fn country_statistics_are_empty_for_an_empty_database() {
    let (_file, store) = temp_store();
    let statistics = store
        .query_country_statistics()
        .expect("country statistics");
    assert_eq!(statistics.total_count, 0);
    assert_eq!(statistics.unknown_count, 0);
    assert!(statistics.country_counts.is_empty());
}

#[test]
fn partially_specified_time_windows_filter_returned_rows() {
    let (_file, store) = temp_store();
    let base = datetime!(2026-02-01 10:00:00 UTC);

    let log = |dst_port: i32, timestamp, last_seen| NewConnectionLog {
        replace_domain: false,
        is_close: false,
        conn_pid: 0,
        conn_id: 0,
        timestamp,
        app_id: 1,
        app_path: String::new(),
        protocol: "TCP".to_owned(),
        src_ip: "10.0.0.1".to_owned(),
        src_port: 12345,
        dst_ip: "93.184.216.34".to_owned(),
        dst_port,
        dst_domain: format!("host-{dst_port}"),
        bytes_sent: 10,
        bytes_received: 10,
        action_taken: "ALLOWED".to_owned(),
        last_seen,
        country_code: String::new(),
        isp: String::new(),
        blocklist_names: String::new(),
    };
    // "flow-started-early" began before any window but was last seen
    // during the late one, so a start-only window must still match it
    // through `last_seen`.
    store
        .insert_connection_logs(&[
            log(1, base, base),
            log(
                2,
                base + time::Duration::minutes(10),
                base + time::Duration::minutes(10),
            ),
            log(
                3,
                base + time::Duration::minutes(20),
                base + time::Duration::minutes(20),
            ),
            log(4, base, base + time::Duration::minutes(20)),
        ])
        .expect("insert logs");

    let domains = |page: crate::models::ConnectionLogPage| {
        let mut domains: Vec<String> = page
            .logs
            .iter()
            .map(|entry| entry.dst_domain.clone())
            .collect();
        domains.sort();
        domains
    };

    // Start-only: rows at or after the window start, on either column.
    let start_only = store
        .query_connection_logs(&ConnectionLogQuery {
            time_window_start: Some(base + time::Duration::minutes(5)),
            ..ConnectionLogQuery::default()
        })
        .expect("start-only window");
    assert_eq!(
        domains(start_only),
        vec!["host-2", "host-3", "host-4"],
        "start-only must exclude rows entirely before the window"
    );

    // End-only: rows before the window end, on either column.
    let end_only = store
        .query_connection_logs(&ConnectionLogQuery {
            time_window_end: Some(base + time::Duration::minutes(15)),
            ..ConnectionLogQuery::default()
        })
        .expect("end-only window");
    assert_eq!(
        domains(end_only),
        vec!["host-1", "host-2", "host-4"],
        "end-only must exclude rows entirely at or after the window"
    );

    // A set bound overrides `time_filter_seconds` even when partially
    // specified; otherwise the rolling filter would silently narrow the
    // request to the last hour and return nothing.
    let start_only_with_rolling_filter = store
        .query_connection_logs(&ConnectionLogQuery {
            time_filter_seconds: 3_600,
            time_window_start: Some(base + time::Duration::minutes(5)),
            ..ConnectionLogQuery::default()
        })
        .expect("start-only window with rolling filter");
    assert_eq!(start_only_with_rolling_filter.total_count, 3);

    // The prefixed summary queries share the window helper; verify the
    // same partial window reaches them.
    let summaries = store
        .query_application_log_summaries(&crate::models::ApplicationLogSummaryQuery {
            time_window_start: Some(base + time::Duration::minutes(5)),
            ..crate::models::ApplicationLogSummaryQuery::default()
        })
        .expect("start-only summary window");
    let total: u64 = summaries
        .iter()
        .map(|summary| summary.connection_count)
        .sum();
    assert_eq!(total, 3);
}

#[test]
fn connection_log_upsert_accumulates_one_connection_and_splits_another() {
    let (_file, store) = temp_store();
    let base = datetime!(2026-02-01 10:00:00 UTC);

    let first = NewConnectionLog {
        replace_domain: false,
        is_close: false,
        timestamp: base,
        app_id: 1,
        app_path: String::new(),
        protocol: "TCP".to_owned(),
        src_ip: "10.0.0.1".to_owned(),
        src_port: 12345,
        dst_ip: "93.184.216.34".to_owned(),
        dst_port: 443,
        dst_domain: "example.com".to_owned(),
        bytes_sent: 1024,
        bytes_received: 4096,
        action_taken: "ALLOWED".to_owned(),
        last_seen: base,
        country_code: "US".to_owned(),
        isp: "Example ISP".to_owned(),
        blocklist_names: String::new(),
        conn_id: 11,
        conn_pid: 7100,
    };
    let second = NewConnectionLog {
        is_close: false,
        bytes_sent: 512,
        bytes_received: 256,
        action_taken: "BLOCKED".to_owned(),
        last_seen: base + time::Duration::seconds(30),
        blocklist_names: "hagezi_light".to_owned(),
        ..first.clone()
    };

    store
        .insert_connection_logs(&[first.clone(), second])
        .expect("insert logs");

    // Same connection, two flushes: traffic accumulates onto its row.
    let page = store
        .query_connection_logs(&ConnectionLogQuery::default())
        .expect("query logs");
    assert_eq!(page.total_count, 1);
    assert_eq!(page.logs[0].conn_id, 11);
    assert_eq!(page.logs[0].bytes_sent, 1536);
    assert_eq!(page.logs[0].bytes_received, 4352);
    assert_eq!(page.logs[0].last_seen, base + time::Duration::seconds(30));
    assert_eq!(page.logs[0].action_taken, "BLOCKED");
    assert_eq!(page.logs[0].blocklist_names, "hagezi_light");

    // A later flush for the same connection keeps accumulating.
    let later = NewConnectionLog {
        is_close: false,
        bytes_sent: 1,
        bytes_received: 2,
        action_taken: "BLOCKED".to_owned(),
        last_seen: base + time::Duration::seconds(60),
        blocklist_names: "hagezi_tif".to_owned(),
        ..first.clone()
    };
    store
        .insert_connection_logs(&[later])
        .expect("insert later flush");

    let page = store
        .query_connection_logs(&ConnectionLogQuery::default())
        .expect("query accumulated log");
    assert_eq!(page.total_count, 1);
    assert_eq!(page.logs[0].bytes_sent, 1537);
    assert_eq!(page.logs[0].bytes_received, 4354);
    assert_eq!(page.logs[0].blocklist_names, "hagezi_tif");

    // The same tuple from a *different* connection starts its own row,
    // so rewind can tell the two apart.
    let other_connection = NewConnectionLog {
        is_close: false,
        timestamp: base + time::Duration::hours(1),
        last_seen: base + time::Duration::hours(1),
        bytes_sent: 7,
        bytes_received: 9,
        action_taken: "ALLOWED".to_owned(),
        blocklist_names: String::new(),
        conn_id: 12,
        ..first.clone()
    };
    store
        .insert_connection_logs(&[other_connection])
        .expect("insert other connection");

    let page = store
        .query_connection_logs(&ConnectionLogQuery::default())
        .expect("query both connections");
    assert_eq!(page.total_count, 2);
    let mut by_conn: Vec<(i64, i64, i64)> = page
        .logs
        .iter()
        .map(|log| (log.conn_id, log.bytes_sent, log.bytes_received))
        .collect();
    by_conn.sort_unstable();
    assert_eq!(by_conn, vec![(11, 1537, 4354), (12, 7, 9)]);
}

fn close_test_log(base: OffsetDateTime) -> NewConnectionLog {
    NewConnectionLog {
        replace_domain: false,
        timestamp: base,
        app_id: 1,
        app_path: String::new(),
        protocol: "TCP".to_owned(),
        src_ip: "10.0.0.1".to_owned(),
        src_port: 12345,
        dst_ip: "93.184.216.34".to_owned(),
        dst_port: 443,
        dst_domain: "example.com".to_owned(),
        bytes_sent: 1024,
        bytes_received: 4096,
        action_taken: "ALLOWED".to_owned(),
        last_seen: base,
        country_code: String::new(),
        isp: String::new(),
        blocklist_names: String::new(),
        conn_id: 11,
        conn_pid: 7100,
        is_close: false,
    }
}

#[test]
fn close_marker_records_close_time_and_freezes_the_row() {
    let (_file, store) = temp_store();
    let base = datetime!(2026-02-01 10:00:00 UTC);
    store
        .insert_connection_logs(std::slice::from_ref(&close_test_log(base)))
        .expect("insert connection");

    let closed_at = base + time::Duration::seconds(30);
    let close = NewConnectionLog {
        bytes_sent: 0,
        bytes_received: 0,
        last_seen: closed_at,
        is_close: true,
        ..close_test_log(base)
    };
    store
        .insert_connection_logs(std::slice::from_ref(&close))
        .expect("record close");

    let page = store
        .query_connection_logs(&ConnectionLogQuery::default())
        .expect("query closed row");
    assert_eq!(page.total_count, 1);
    assert_eq!(page.logs[0].bytes_sent, 1024);
    assert_eq!(page.logs[0].bytes_received, 4096);
    assert_eq!(page.logs[0].closed_at, Some(closed_at));

    // A repeated close never moves the recorded end time.
    let again = NewConnectionLog {
        last_seen: closed_at + time::Duration::seconds(30),
        ..close
    };
    store
        .insert_connection_logs(std::slice::from_ref(&again))
        .expect("repeat close");

    let page = store
        .query_connection_logs(&ConnectionLogQuery::default())
        .expect("query after repeat close");
    assert_eq!(page.total_count, 1);
    assert_eq!(page.logs[0].closed_at, Some(closed_at));
}

#[test]
fn active_connection_status_requires_current_session_evidence() {
    let (file, store) = temp_store();
    let base = datetime!(2026-02-01 10:00:00 UTC);
    let live = close_test_log(base);
    store
        .insert_connection_logs(std::slice::from_ref(&live))
        .expect("open");
    let rows = store
        .query_connection_logs(&ConnectionLogQuery::default())
        .expect("query");
    assert!(rows.logs[0].is_active);
    assert!(rows.logs[0].closed_at.is_none());
    drop(store);
    let store = Store::open(file.path()).expect("restart");
    let rows = store
        .query_connection_logs(&ConnectionLogQuery::default())
        .expect("query history");
    assert!(
        !rows.logs[0].is_active,
        "an unclosed historical row is not proof of liveness"
    );
    let close = NewConnectionLog {
        is_close: true,
        ..live
    };
    store.insert_connection_logs(&[close]).expect("close");
    let rows = store
        .query_connection_logs(&ConnectionLogQuery::default())
        .expect("query closed");
    assert!(!rows.logs[0].is_active);
    assert!(rows.logs[0].closed_at.is_some());
}

#[test]
fn flush_after_close_starts_a_new_row() {
    let (_file, store) = temp_store();
    let base = datetime!(2026-02-01 10:00:00 UTC);
    let first = close_test_log(base);
    store
        .insert_connection_logs(std::slice::from_ref(&first))
        .expect("insert connection");

    let closed_at = base + time::Duration::seconds(30);
    store
        .insert_connection_logs(&[NewConnectionLog {
            bytes_sent: 0,
            bytes_received: 0,
            last_seen: closed_at,
            is_close: true,
            ..first.clone()
        }])
        .expect("record close");

    // Traffic arriving after the close (reordered events, a late flush)
    // must not rewrite the finished connection.
    let late = NewConnectionLog {
        bytes_sent: 100,
        bytes_received: 200,
        last_seen: base + time::Duration::seconds(90),
        ..first
    };
    store
        .insert_connection_logs(std::slice::from_ref(&late))
        .expect("late flush");
    store
        .db
        .execute("PRAGMA reverse_unordered_selects = ON", [])
        .unwrap();
    for _ in 0..3 {
        store
            .insert_connection_logs(std::slice::from_ref(&late))
            .expect("subsequent late flush");
    }

    let page = store
        .query_connection_logs(&ConnectionLogQuery::default())
        .expect("query both rows");
    assert_eq!(page.total_count, 2);
    let mut rows: Vec<(i64, i64, Option<OffsetDateTime>)> = page
        .logs
        .iter()
        .map(|log| (log.bytes_sent, log.bytes_received, log.closed_at))
        .collect();
    rows.sort_unstable();
    assert_eq!(rows, vec![(400, 800, None), (1024, 4096, Some(closed_at))]);
}

#[test]
fn close_of_unknown_connection_inserts_born_closed_row() {
    let (_file, store) = temp_store();
    let base = datetime!(2026-02-01 10:00:00 UTC);
    let close = NewConnectionLog {
        last_seen: base + time::Duration::seconds(5),
        is_close: true,
        ..close_test_log(base)
    };
    store
        .insert_connection_logs(std::slice::from_ref(&close))
        .expect("insert born-closed row");

    let page = store
        .query_connection_logs(&ConnectionLogQuery::default())
        .expect("query");
    assert_eq!(page.total_count, 1);
    assert_eq!(page.logs[0].bytes_sent, 1024);
    assert_eq!(
        page.logs[0].closed_at,
        Some(base + time::Duration::seconds(5))
    );
}

#[test]
fn relaunched_session_id_does_not_adopt_the_old_row() {
    let (_file, store) = temp_store();
    let base = datetime!(2026-02-01 10:00:00 UTC);
    let first = NewConnectionLog {
        replace_domain: false,
        is_close: false,
        timestamp: base,
        app_id: 1,
        app_path: String::new(),
        protocol: "TCP".to_owned(),
        src_ip: "10.0.0.1".to_owned(),
        src_port: 12345,
        dst_ip: "93.184.216.34".to_owned(),
        dst_port: 443,
        dst_domain: "example.com".to_owned(),
        bytes_sent: 1024,
        bytes_received: 4096,
        action_taken: "ALLOWED".to_owned(),
        last_seen: base,
        country_code: String::new(),
        isp: String::new(),
        blocklist_names: String::new(),
        conn_id: 11,
        conn_pid: 7100,
    };
    store
        .insert_connection_logs(std::slice::from_ref(&first))
        .expect("insert original connection");

    // A relaunched daemon reusing the session id must not adopt the old
    // row: same conn_id but a different pid and start inserts fresh.
    let restarted = NewConnectionLog {
        is_close: false,
        timestamp: base + time::Duration::days(1),
        last_seen: base + time::Duration::days(1),
        bytes_sent: 3,
        bytes_received: 4,
        conn_pid: 7200,
        ..first.clone()
    };
    store
        .insert_connection_logs(&[restarted])
        .expect("insert restarted connection");

    let page = store
        .query_connection_logs(&ConnectionLogQuery::default())
        .expect("query after restart");
    assert_eq!(page.total_count, 2);
    let mut by_conn: Vec<(i64, i32, i64, i64)> = page
        .logs
        .iter()
        .map(|log| {
            (
                log.conn_id,
                log.conn_pid,
                log.bytes_sent,
                log.bytes_received,
            )
        })
        .collect();
    by_conn.sort_unstable();
    assert_eq!(by_conn, vec![(11, 7100, 1024, 4096), (11, 7200, 3, 4)]);
}

#[test]
fn dns_batch_rolls_back_history_and_activity_together() {
    let (_file, store) = temp_store();
    let now = datetime!(2026-03-01 12:00:00 UTC);
    store.db.execute("CREATE TRIGGER reject_activity BEFORE INSERT ON activity_buckets BEGIN SELECT RAISE(ABORT, 'test failure'); END", []).unwrap();
    let rows = vec![
        (
            1,
            "ads.example".to_owned(),
            now,
            String::new(),
            String::new()
        );
        256
    ];
    assert!(store.insert_dns_block_logs(&rows).is_err());
    assert_eq!(
        store
            .query_connection_logs(&ConnectionLogQuery::default())
            .unwrap()
            .total_count,
        0
    );
    let sightings: i64 = store
        .db
        .query_row("SELECT COUNT(*) FROM seen_domains", [], |row| row.get(0))
        .unwrap();
    assert_eq!(sightings, 0);
    store
        .db
        .execute("DROP TRIGGER reject_activity", [])
        .unwrap();
    let first_sightings = store.insert_dns_block_logs(&rows).unwrap();
    assert_eq!(first_sightings.iter().filter(|&&first| first).count(), 1);
    assert_eq!(
        store
            .query_connection_logs(&ConnectionLogQuery::default())
            .unwrap()
            .total_count,
        256
    );
}

#[test]
fn history_uses_exact_subsecond_filter_and_retention_boundaries() {
    let (_file, store) = temp_store();
    let raw = [
        "2026-10-16T00:00:05Z",
        "2026-10-16T00:00:05.000000001Z",
        "2026-10-16T00:00:05.5Z",
    ];
    for text in raw {
        store
            .db
            .execute(
                "INSERT INTO connection_logs(timestamp,last_seen) VALUES (?1,?1)",
                [format_timestamp(parse_timestamp(text).unwrap())],
            )
            .unwrap();
    }
    let start = parse_timestamp(raw[0]).unwrap();
    let end = parse_timestamp(raw[2]).unwrap();

    let page = store
        .query_connection_logs(&ConnectionLogQuery {
            time_window_start: Some(start),
            time_window_end: Some(end),
            order_by: Some("timestamp".to_owned()),
            sort_descending: false,
            ..ConnectionLogQuery::default()
        })
        .unwrap();
    assert_eq!(page.total_count, 2);
    assert_eq!(
        page.logs
            .iter()
            .map(|row| row.timestamp)
            .collect::<Vec<OffsetDateTime>>(),
        [start, start + time::Duration::nanoseconds(1)]
    );

    assert_eq!(store.purge_connection_logs_before(Some(end)).unwrap(), 2);
    assert_eq!(
        store
            .query_connection_logs(&ConnectionLogQuery::default())
            .unwrap()
            .logs[0]
            .timestamp,
        end
    );
}

#[test]
fn reattribution_selects_only_newest_open_duplicate() {
    let (_file, store) = temp_store();
    let now = datetime!(2026-03-01 12:00:00 UTC);
    let log = close_test_log(now);
    store
        .insert_connection_logs(&[NewConnectionLog {
            is_close: true,
            ..log.clone()
        }])
        .unwrap();
    store
        .insert_connection_logs(std::slice::from_ref(&log))
        .unwrap();
    // Also simulate duplicate open rows from an older writer.
    store.db.execute("INSERT INTO connection_logs SELECT NULL, timestamp, app_id, protocol, src_ip, src_port, dst_ip, dst_port, dst_domain, bytes_sent, bytes_received, action_taken, last_seen, country_code, isp, blocklist_names, conn_id, conn_pid, closed_at, app_path FROM connection_logs WHERE closed_at = ''", []).unwrap();
    store
        .reattribute_connection_log(&ConnectionLogAttribution {
            from_app_id: 1,
            to_app_id: 2,
            protocol: log.protocol,
            src_ip: log.src_ip,
            dst_ip: log.dst_ip,
            dst_port: log.dst_port,
            conn_id: log.conn_id,
            conn_pid: log.conn_pid,
            conn_start: now,
        })
        .unwrap();
    let page = store
        .query_connection_logs(&ConnectionLogQuery::default())
        .unwrap();
    let newest = page.logs.iter().max_by_key(|row| row.id).unwrap();
    assert_eq!(newest.app_id, 2);
    assert_eq!(page.logs.iter().filter(|row| row.app_id == 2).count(), 1);
}

#[test]
fn reattribution_falls_back_to_the_newest_closed_row() {
    let (_file, store) = temp_store();
    let now = datetime!(2026-03-01 12:00:00 UTC);
    let log = close_test_log(now);
    store
        .insert_connection_logs(&[NewConnectionLog {
            is_close: true,
            ..log.clone()
        }])
        .unwrap();

    store
        .reattribute_connection_log(&ConnectionLogAttribution {
            from_app_id: 1,
            to_app_id: 2,
            protocol: log.protocol,
            src_ip: log.src_ip,
            dst_ip: log.dst_ip,
            dst_port: log.dst_port,
            conn_id: log.conn_id,
            conn_pid: log.conn_pid,
            conn_start: now,
        })
        .unwrap();

    let page = store
        .query_connection_logs(&ConnectionLogQuery::default())
        .unwrap();
    assert_eq!(page.logs[0].app_id, 2);
    assert_eq!(page.logs[0].closed_at, Some(now));
}

#[test]
fn a_closed_row_takes_a_confirmed_domain_but_keeps_one_it_has() {
    let (_file, store) = temp_store();
    let now = datetime!(2026-03-01 12:00:00 UTC);
    let inferred = NewConnectionLog {
        dst_domain: "example.com (inferred)".to_owned(),
        is_close: true,
        ..close_test_log(now)
    };
    let confirmed = NewConnectionLog {
        conn_id: 12,
        dst_domain: "kept.example".to_owned(),
        is_close: true,
        ..close_test_log(now)
    };
    store
        .insert_connection_logs(&[inferred.clone(), confirmed.clone()])
        .unwrap();

    let upgrade = |log: &NewConnectionLog, domain: &str| ConnectionDomainUpgrade {
        replace: false,
        conn_id: log.conn_id,
        conn_pid: log.conn_pid,
        conn_start: log.timestamp,
        dst_domain: domain.to_owned(),
    };
    let found = store
        .upgrade_connection_domains(&[
            upgrade(&inferred, "example.com"),
            upgrade(&confirmed, "other.example"),
            ConnectionDomainUpgrade {
                conn_id: 99,
                ..upgrade(&inferred, "unwritten.example")
            },
        ])
        .unwrap();
    assert_eq!(found, [true, true, false]);

    let page = store
        .query_connection_logs(&ConnectionLogQuery::default())
        .unwrap();
    let domain_of = |conn_id: i64| {
        page.logs
            .iter()
            .find(|log| log.conn_id == conn_id)
            .map(|log| log.dst_domain.clone())
    };
    assert_eq!(domain_of(11).as_deref(), Some("example.com"));
    assert_eq!(domain_of(12).as_deref(), Some("kept.example"));
}

/// A name judged again from better evidence replaces the row's own, whichever
/// is the stronger: a confirmed name gives way, to a weaker one or to none.
#[test]
fn a_domain_that_replaces_is_stored_over_a_confirmed_one() {
    let (_file, store) = temp_store();
    let now = datetime!(2026-03-01 12:00:00 UTC);
    let row = |conn_id: i64, closed: bool| NewConnectionLog {
        conn_id,
        dst_domain: "first.example".to_owned(),
        is_close: closed,
        ..close_test_log(now)
    };
    let (open, closed, withdrawn) = (row(21, false), row(22, true), row(23, true));
    store
        .insert_connection_logs(&[open.clone(), closed.clone(), withdrawn.clone()])
        .unwrap();
    let domain_of = |conn_id: i64| {
        store
            .query_connection_logs(&ConnectionLogQuery::default())
            .unwrap()
            .logs
            .into_iter()
            .find(|log| log.conn_id == conn_id)
            .map(|log| log.dst_domain)
    };

    // A later log for an open connection.
    let later = |domain: &str, replace_domain: bool| NewConnectionLog {
        dst_domain: domain.to_owned(),
        replace_domain,
        bytes_sent: 0,
        bytes_received: 0,
        ..open.clone()
    };
    store
        .insert_connection_logs(&[later("second.example", false)])
        .unwrap();
    assert_eq!(
        domain_of(21).as_deref(),
        Some("first.example"),
        "a confirmed domain is kept unless the log says it replaces"
    );
    store
        .insert_connection_logs(&[later("second.example (inferred)", true)])
        .unwrap();
    assert_eq!(domain_of(21).as_deref(), Some("second.example (inferred)"));

    // The same for rows that are closed, which only an upgrade reaches.
    let upgrade = |log: &NewConnectionLog, domain: &str| ConnectionDomainUpgrade {
        conn_id: log.conn_id,
        conn_pid: log.conn_pid,
        conn_start: log.timestamp,
        dst_domain: domain.to_owned(),
        replace: true,
    };
    let found = store
        .upgrade_connection_domains(&[
            upgrade(&closed, "second.example"),
            upgrade(&withdrawn, ""),
            upgrade(&open, "third.example"),
        ])
        .unwrap();
    assert_eq!(
        found,
        [true, true, false],
        "a row waits for the log that closes it, which would undo the upgrade"
    );
    assert_eq!(domain_of(22).as_deref(), Some("second.example"));
    assert_eq!(domain_of(23).as_deref(), Some(""));
    assert_eq!(domain_of(21).as_deref(), Some("second.example (inferred)"));

    // The closing log arrives with the name the connection closed with, and
    // then the upgrade is taken.
    store
        .insert_connection_logs(&[NewConnectionLog {
            is_close: true,
            ..later("second.example (inferred)", false)
        }])
        .unwrap();
    let found = store
        .upgrade_connection_domains(&[upgrade(&open, "third.example")])
        .unwrap();
    assert_eq!(found, [true]);
    assert_eq!(domain_of(21).as_deref(), Some("third.example"));
}

#[test]
fn dns_block_log_appends_each_block_as_its_own_row() {
    let (_file, store) = temp_store();
    let now = datetime!(2026-03-01 12:00:00 UTC);
    store
        .insert_dns_block_log(
            1,
            r"C:\Apps\browser.exe",
            "ads.example",
            now,
            "hagezi_light",
        )
        .expect("insert dns block");

    let page = store
        .query_connection_logs(&ConnectionLogQuery::default())
        .expect("query");
    assert_eq!(page.total_count, 1);
    assert_eq!(page.logs[0].closed_at, Some(now));
    assert_eq!(page.logs[0].protocol, "DNS");
    assert_eq!(page.logs[0].dst_domain, "ads.example");
    assert_eq!(page.logs[0].app_path, r"C:\Apps\browser.exe");
    assert_eq!(page.logs[0].blocklist_names, "hagezi_light");

    let later = now + time::Duration::seconds(30);
    store
        .insert_dns_block_log(
            1,
            r"C:\Apps\browser.exe",
            "ads.example",
            later,
            "hagezi_light\nhagezi_tif",
        )
        .expect("second block is a new row");
    let page = store
        .query_connection_logs(&ConnectionLogQuery::default())
        .expect("query after second block");
    assert_eq!(page.total_count, 2);

    store
        .insert_dns_block_log(
            1,
            r"C:\Apps\browser.exe",
            "ads.example",
            later + time::Duration::seconds(30),
            "",
        )
        .expect("third block is a new row");
    let page = store
        .query_connection_logs(&ConnectionLogQuery::default())
        .expect("query after third block");
    assert_eq!(page.total_count, 3);
    // Each block keeps the attribution it was recorded with.
    let mut names: Vec<&str> = page
        .logs
        .iter()
        .map(|log| log.blocklist_names.as_str())
        .collect();
    names.sort_unstable();
    assert_eq!(names, vec!["", "hagezi_light", "hagezi_light\nhagezi_tif"]);
}

#[test]
fn late_attribution_moves_unknown_connection_row() {
    let (_file, store) = temp_store();
    let base = datetime!(2026-02-01 10:00:00 UTC);
    let unknown = NewConnectionLog {
        replace_domain: false,
        is_close: false,
        timestamp: base,
        app_id: 1,
        app_path: String::new(),
        protocol: "TCP".to_owned(),
        src_ip: "10.0.0.1".to_owned(),
        src_port: 12_345,
        dst_ip: "93.184.216.34".to_owned(),
        dst_port: 443,
        dst_domain: "example.com".to_owned(),
        bytes_sent: 1024,
        bytes_received: 4096,
        action_taken: "ALLOWED".to_owned(),
        last_seen: base,
        country_code: "US".to_owned(),
        isp: "Example ISP".to_owned(),
        blocklist_names: "hagezi_light".to_owned(),
        conn_id: 5,
        conn_pid: 7100,
    };
    store
        .insert_connection_logs(std::slice::from_ref(&unknown))
        .expect("insert unknown flow");

    store
        .reattribute_connection_log(&ConnectionLogAttribution {
            from_app_id: 1,
            to_app_id: 2,
            protocol: unknown.protocol.clone(),
            src_ip: unknown.src_ip.clone(),
            dst_ip: unknown.dst_ip.clone(),
            dst_port: unknown.dst_port,
            conn_id: 5,
            conn_pid: 7100,
            conn_start: base,
        })
        .expect("reattribute");

    let page = store
        .query_connection_logs(&ConnectionLogQuery::default())
        .expect("query logs");
    assert_eq!(page.total_count, 1);
    assert_eq!(page.logs[0].app_id, 2);
    assert_eq!(page.logs[0].bytes_sent, 1024);
    assert_eq!(page.logs[0].bytes_received, 4096);
    assert_eq!(page.logs[0].blocklist_names, "hagezi_light");
}

#[test]
fn a_version_update_keeps_each_records_own_path() {
    let (_file, store) = temp_store();
    let first_seen = datetime!(2026-03-01 00:00:00 UTC);
    let moved_at = datetime!(2026-03-02 00:00:00 UTC);
    let first_path = r"C:\Apps\App-1.0\App.exe";
    let second_path = r"C:\Apps\App-2.0\App.exe";

    let app_id = store
        .record_application_sighting("App.exe", first_path, true, first_seen)
        .expect("first version")
        .app_id;
    store
        .insert_connection_logs(&[NewConnectionLog {
            app_id,
            app_path: first_path.to_owned(),
            conn_id: 1,
            ..close_test_log(first_seen)
        }])
        .expect("first record");

    let updated = store
        .record_application_sighting("App.exe", second_path, true, moved_at)
        .expect("second version");
    assert_eq!(updated.app_id, app_id);
    store
        .insert_connection_logs(&[NewConnectionLog {
            app_id,
            app_path: second_path.to_owned(),
            conn_id: 2,
            ..close_test_log(moved_at)
        }])
        .expect("second record");

    // Each record keeps the version it ran from, under the one application.
    let page = store
        .query_connection_logs(&ConnectionLogQuery::default())
        .expect("logs");
    let mut paths: Vec<&str> = page.logs.iter().map(|log| log.app_path.as_str()).collect();
    paths.sort_unstable();
    assert_eq!(paths, vec![first_path, second_path]);

    // The application row and its summary still report the current install.
    assert_eq!(
        store.get_application(app_id).expect("application").app_path,
        second_path
    );
    let summaries = store
        .query_application_log_summaries(&crate::models::ApplicationLogSummaryQuery::default())
        .expect("summaries");
    assert_eq!(summaries.len(), 1);
    assert_eq!(summaries[0].app_path, second_path);
}

#[test]
fn late_attribution_adopts_the_resolved_applications_path() {
    let (_file, store) = temp_store();
    let base = datetime!(2026-02-01 10:00:00 UTC);
    let placeholder = store
        .record_application_sighting("unknown.exe", "Unknown (No Owner)", true, base)
        .expect("placeholder row")
        .app_id;
    let real = store
        .record_application_sighting("Real.exe", r"C:\Apps\Real.exe", true, base)
        .expect("real row")
        .app_id;
    assert_ne!(placeholder, real);

    store
        .insert_connection_logs(&[NewConnectionLog {
            app_id: placeholder,
            app_path: "Unknown (No Owner)".to_owned(),
            conn_id: 7,
            conn_pid: 7200,
            ..close_test_log(base)
        }])
        .expect("insert placeholder flow");

    store
        .reattribute_connection_log(&ConnectionLogAttribution {
            from_app_id: placeholder,
            to_app_id: real,
            protocol: "TCP".to_owned(),
            src_ip: "10.0.0.1".to_owned(),
            dst_ip: "93.184.216.34".to_owned(),
            dst_port: 443,
            conn_id: 7,
            conn_pid: 7200,
            conn_start: base,
        })
        .expect("reattribute");

    let page = store
        .query_connection_logs(&ConnectionLogQuery::default())
        .expect("logs");
    assert_eq!(page.logs.len(), 1);
    assert_eq!(page.logs[0].app_id, real);
    assert_eq!(page.logs[0].app_path, r"C:\Apps\Real.exe");
}

#[test]
fn late_attribution_repoints_only_the_matching_connection() {
    let (_file, store) = temp_store();
    let base = datetime!(2026-02-01 10:00:00 UTC);
    let unknown = NewConnectionLog {
        replace_domain: false,
        is_close: false,
        timestamp: base,
        app_id: 1,
        app_path: String::new(),
        protocol: "TCP".to_owned(),
        src_ip: "10.0.0.1".to_owned(),
        src_port: 12_345,
        dst_ip: "93.184.216.34".to_owned(),
        dst_port: 443,
        dst_domain: String::new(),
        bytes_sent: 1024,
        bytes_received: 4096,
        action_taken: "ALLOWED".to_owned(),
        last_seen: base,
        country_code: String::new(),
        isp: String::new(),
        blocklist_names: "hagezi_light".to_owned(),
        conn_id: 5,
        conn_pid: 7100,
    };
    let resolved = NewConnectionLog {
        is_close: false,
        app_id: 2,
        dst_domain: "example.com".to_owned(),
        bytes_sent: 512,
        bytes_received: 256,
        last_seen: base + time::Duration::seconds(30),
        country_code: "US".to_owned(),
        isp: "Example ISP".to_owned(),
        blocklist_names: String::new(),
        conn_id: 6,
        ..unknown.clone()
    };
    store
        .insert_connection_logs(&[unknown.clone(), resolved])
        .expect("insert both rows");

    store
        .reattribute_connection_log(&ConnectionLogAttribution {
            from_app_id: 1,
            to_app_id: 2,
            protocol: unknown.protocol,
            src_ip: unknown.src_ip,
            dst_ip: unknown.dst_ip,
            dst_port: unknown.dst_port,
            conn_id: 5,
            conn_pid: 7100,
            conn_start: base,
        })
        .expect("reattribute one connection");

    let page = store
        .query_connection_logs(&ConnectionLogQuery::default())
        .expect("query logs");
    // Each connection keeps its own row and byte totals; only the
    // re-attributed connection changes owner.
    assert_eq!(page.total_count, 2);
    let mut by_conn: Vec<(i64, i32, i64, i64)> = page
        .logs
        .iter()
        .map(|log| (log.conn_id, log.app_id, log.bytes_sent, log.bytes_received))
        .collect();
    by_conn.sort_unstable();
    assert_eq!(by_conn, vec![(5, 2, 1024, 4096), (6, 2, 512, 256)]);
    assert!(page.logs.iter().any(|log| log.dst_domain == "example.com"));
    assert!(page
        .logs
        .iter()
        .any(|log| log.blocklist_names == "hagezi_light"));
}

#[test]
fn dns_cache_skips_write_when_unchanged_and_recent() {
    let (_file, store) = temp_store();
    let base = OffsetDateTime::now_utc() - time::Duration::minutes(10);
    let entry = DnsCacheEntry {
        id: "93.184.216.34".to_owned(),
        domain: "example.com".to_owned(),
        last_seen: base,
    };
    store.upsert_dns_cache(&entry).expect("initial upsert");

    let refresh = DnsCacheEntry {
        id: entry.id.clone(),
        domain: entry.domain.clone(),
        last_seen: base + time::Duration::seconds(30),
    };
    store.upsert_dns_cache(&refresh).expect("throttled upsert");

    // The stored row keeps its throttled timestamp...
    let row = store
        .get_dns_cache_row("93.184.216.34")
        .expect("row")
        .expect("entry");
    assert_eq!(row.last_seen, base);
    // ...while reads serve the latest observation from the front cache.
    let loaded = store
        .get_dns_cache("93.184.216.34")
        .expect("lookup")
        .expect("entry");
    assert_eq!(loaded.last_seen, base + time::Duration::seconds(30));

    let later = DnsCacheEntry {
        id: entry.id,
        domain: entry.domain,
        last_seen: base + time::Duration::minutes(6),
    };
    store.upsert_dns_cache(&later).expect("interval upsert");
    let loaded = store
        .get_dns_cache("93.184.216.34")
        .expect("lookup")
        .expect("entry");
    assert_eq!(loaded.last_seen, later.last_seen);
}

#[test]
fn dns_front_cache_serves_repeated_positive_lookups_without_sqlite() {
    let (_file, store) = temp_store();
    store
        .upsert_dns_cache(&DnsCacheEntry {
            id: "93.184.216.34".to_owned(),
            domain: "example.test".to_owned(),
            last_seen: OffsetDateTime::now_utc() - time::Duration::minutes(1),
        })
        .expect("upsert");

    // The upsert already populated the front cache, so even the first
    // lookup is a hit: none of these may touch SQLite.
    assert_eq!(store.dns_front.sqlite_reads(), 0);
    for _ in 0..5 {
        let loaded = store
            .get_dns_cache("93.184.216.34")
            .expect("lookup")
            .expect("entry");
        assert_eq!(loaded.domain, "example.test");
    }
    assert_eq!(
        store.dns_front.sqlite_reads(),
        0,
        "front hits must not touch SQLite"
    );
    assert!(
        store.dns_front.hits() >= 4,
        "repeat lookups must be front hits"
    );
}

#[test]
fn dns_front_cache_populates_from_sqlite_on_first_miss() {
    let (file, store) = temp_store();
    store
        .upsert_dns_cache(&DnsCacheEntry {
            id: "93.184.216.34".to_owned(),
            domain: "example.test".to_owned(),
            last_seen: OffsetDateTime::now_utc() - time::Duration::minutes(1),
        })
        .expect("upsert");
    drop(store);

    // A fresh handle starts with an empty front cache: the first lookup
    // reads SQLite once and populates it, the rest are hits.
    let reopened = Store::open(file.path()).expect("reopen");
    let loaded = reopened
        .get_dns_cache("93.184.216.34")
        .expect("lookup")
        .expect("entry");
    assert_eq!(loaded.domain, "example.test");
    assert_eq!(reopened.dns_front.sqlite_reads(), 1);
    for _ in 0..4 {
        reopened
            .get_dns_cache("93.184.216.34")
            .expect("lookup")
            .expect("entry");
    }
    assert_eq!(
        reopened.dns_front.sqlite_reads(),
        1,
        "only the populating lookup may touch SQLite"
    );
}

#[test]
fn dns_front_cache_serves_repeated_misses_without_sqlite() {
    let (_file, store) = temp_store();
    assert!(store.get_dns_cache("192.0.2.9").expect("lookup").is_none());
    assert_eq!(store.dns_front.sqlite_reads(), 1);
    for _ in 0..5 {
        assert!(store.get_dns_cache("192.0.2.9").expect("lookup").is_none());
    }
    assert_eq!(
        store.dns_front.sqlite_reads(),
        1,
        "repeat misses must be served from the front cache"
    );
}

#[test]
fn newly_recorded_answer_replaces_a_cached_miss_immediately() {
    let (_file, store) = temp_store();
    let observed = OffsetDateTime::now_utc();
    assert!(store
        .get_dns_cache("198.51.100.7")
        .expect("lookup")
        .is_none());
    store
        .upsert_dns_cache(&DnsCacheEntry {
            id: "198.51.100.7".to_owned(),
            domain: "fresh.test".to_owned(),
            last_seen: observed,
        })
        .expect("upsert");
    let loaded = store
        .get_dns_cache("198.51.100.7")
        .expect("lookup")
        .expect("entry");
    assert_eq!(loaded.domain, "fresh.test");
    assert_eq!(loaded.last_seen, observed);
}

#[test]
fn dns_cache_keys_are_canonicalized_across_spellings() {
    let (_file, store) = temp_store();
    let observed = OffsetDateTime::now_utc();
    // Uppercase spelling on write...
    store
        .upsert_dns_cache(&DnsCacheEntry {
            id: "2001:DB8::1".to_owned(),
            domain: "v6.test".to_owned(),
            last_seen: observed,
        })
        .expect("upsert");
    // ...is found through the canonical spelling as a single row.
    let loaded = store
        .get_dns_cache("2001:db8::1")
        .expect("lookup")
        .expect("entry");
    assert_eq!(loaded.domain, "v6.test");
    assert_eq!(loaded.id, "2001:db8::1");
    let row_count: i64 = store
        .db
        .query_row("SELECT COUNT(*) FROM dns_cache_entries", [], |row| {
            row.get(0)
        })
        .expect("count");
    assert_eq!(row_count, 1);
}

#[test]
fn dns_cache_changed_domain_with_older_observation_is_rejected() {
    let (_file, store) = temp_store();
    let newer = OffsetDateTime::now_utc() - time::Duration::minutes(1);
    let older = newer - time::Duration::minutes(10);
    store
        .upsert_dns_cache(&DnsCacheEntry {
            id: "93.184.216.34".to_owned(),
            domain: "new.test".to_owned(),
            last_seen: newer,
        })
        .expect("initial upsert");
    // A delayed observation for a different domain must not regress the row.
    store
        .upsert_dns_cache(&DnsCacheEntry {
            id: "93.184.216.34".to_owned(),
            domain: "old.test".to_owned(),
            last_seen: older,
        })
        .expect("stale upsert");

    let row = store
        .get_dns_cache_row("93.184.216.34")
        .expect("row")
        .expect("entry");
    assert_eq!(row.domain, "new.test");
    assert_eq!(row.last_seen, newer);
    let loaded = store
        .get_dns_cache("93.184.216.34")
        .expect("lookup")
        .expect("entry");
    assert_eq!(loaded.domain, "new.test");
}

#[test]
fn dns_cache_equal_timestamps_go_to_the_later_writer_for_changed_domains() {
    let (_file, store) = temp_store();
    let at = OffsetDateTime::now_utc() - time::Duration::minutes(1);
    for domain in ["first.test", "second.test"] {
        store
            .upsert_dns_cache(&DnsCacheEntry {
                id: "93.184.216.34".to_owned(),
                domain: domain.to_owned(),
                last_seen: at,
            })
            .expect("upsert");
    }
    let row = store
        .get_dns_cache_row("93.184.216.34")
        .expect("row")
        .expect("entry");
    assert_eq!(row.domain, "second.test");
}

#[test]
fn dns_cache_unchanged_equal_timestamp_stays_throttled() {
    let (_file, store) = temp_store();
    let at = OffsetDateTime::now_utc() - time::Duration::minutes(1);
    let entry = DnsCacheEntry {
        id: "93.184.216.34".to_owned(),
        domain: "same.test".to_owned(),
        last_seen: at,
    };
    store.upsert_dns_cache(&entry).expect("initial upsert");
    store.upsert_dns_cache(&entry).expect("repeat upsert");
    let row = store
        .get_dns_cache_row("93.184.216.34")
        .expect("row")
        .expect("entry");
    assert_eq!(row.last_seen, at);
}

#[test]
fn dns_cache_throttle_boundary_refreshes_only_past_the_interval() {
    use antiwire_tuning::DNS_PERSISTENT_LAST_SEEN_INTERVAL;

    let (_file, store) = temp_store();
    let base = OffsetDateTime::now_utc() - time::Duration::minutes(10);
    let entry = |last_seen| DnsCacheEntry {
        id: "93.184.216.34".to_owned(),
        domain: "steady.test".to_owned(),
        last_seen,
    };
    store.upsert_dns_cache(&entry(base)).expect("initial");

    let throttle_secs =
        i64::try_from(DNS_PERSISTENT_LAST_SEEN_INTERVAL.as_secs()).unwrap_or(i64::MAX);
    let within = base + time::Duration::new(throttle_secs - 1, 0);
    store.upsert_dns_cache(&entry(within)).expect("within");
    let row = store
        .get_dns_cache_row("93.184.216.34")
        .expect("row")
        .expect("entry");
    assert_eq!(
        row.last_seen, base,
        "just inside the window stays throttled"
    );

    let past = base + time::Duration::new(throttle_secs + 60, 0);
    store.upsert_dns_cache(&entry(past)).expect("past");
    let row = store
        .get_dns_cache_row("93.184.216.34")
        .expect("row")
        .expect("entry");
    assert_eq!(row.last_seen, past, "past the window refreshes");
}

#[test]
fn delayed_changed_observation_is_ordered_after_throttled_refresh() {
    let (_file, store) = temp_store();
    let base = OffsetDateTime::now_utc() - time::Duration::minutes(10);
    let refreshed = base + time::Duration::minutes(4);
    let delayed = base + time::Duration::minutes(2);
    let write = |domain: &str, last_seen: OffsetDateTime| DnsCacheEntry {
        id: "192.0.2.77".to_owned(),
        domain: domain.to_owned(),
        last_seen,
    };
    store
        .upsert_dns_cache(&write("a.test", base))
        .expect("initial");
    store
        .upsert_dns_cache(&write("a.test", refreshed))
        .expect("refresh");
    store
        .upsert_dns_cache(&write("b.test", delayed))
        .expect("delayed");

    let row = store
        .get_dns_cache_row("192.0.2.77")
        .expect("row")
        .expect("entry");
    assert_eq!(row.domain, "a.test");
    assert_eq!(row.last_seen, base);
    assert_eq!(
        row.latest_seen, refreshed,
        "latest observation remains separate from throttled persistence"
    );
}

#[test]
fn submicrosecond_order_survives_reopen() {
    let (file, store) = temp_store();
    let base = OffsetDateTime::now_utc() - time::Duration::minutes(10);
    let older = base + time::Duration::microseconds(100);
    let newer = base + time::Duration::microseconds(400);
    store
        .upsert_dns_cache(&DnsCacheEntry {
            id: "192.0.2.78".to_owned(),
            domain: "new.test".to_owned(),
            last_seen: newer,
        })
        .expect("newer");
    store
        .upsert_dns_cache(&DnsCacheEntry {
            id: "192.0.2.78".to_owned(),
            domain: "old.test".to_owned(),
            last_seen: older,
        })
        .expect("older");
    drop(store);
    let reopened = Store::open(file.path()).expect("reopen");
    let row = reopened
        .get_dns_cache_row("192.0.2.78")
        .expect("row")
        .expect("entry");
    assert_eq!(row.domain, "new.test");
    assert_eq!(row.last_seen, newer);
}

#[test]
fn dns_cache_out_of_order_batches_converge_on_the_newest_observation() {
    let (_file, store) = temp_store();
    let base = OffsetDateTime::now_utc() - time::Duration::minutes(30);
    let older = DnsCacheEntry {
        id: String::new(),
        domain: "old.test".to_owned(),
        last_seen: base,
    };
    let newer = DnsCacheEntry {
        id: String::new(),
        domain: "new.test".to_owned(),
        last_seen: base + time::Duration::minutes(1),
    };

    // Old-before-new in one batch...
    let mut first = older.clone();
    first.id = "192.0.2.21".to_owned();
    let mut second = newer.clone();
    second.id = "192.0.2.21".to_owned();
    store
        .upsert_dns_cache_batch(&[first, second])
        .expect("old-then-new batch");
    // ...and new-before-old in another: both must converge on newest.
    let mut third = newer.clone();
    third.id = "192.0.2.22".to_owned();
    let mut fourth = older.clone();
    fourth.id = "192.0.2.22".to_owned();
    store
        .upsert_dns_cache_batch(&[third, fourth])
        .expect("new-then-old batch");

    for ip in ["192.0.2.21", "192.0.2.22"] {
        let row = store.get_dns_cache_row(ip).expect("row").expect("entry");
        assert_eq!(
            row.domain, "new.test",
            "batch order must not matter for {ip}"
        );
        let loaded = store.get_dns_cache(ip).expect("lookup").expect("entry");
        assert_eq!(
            loaded.domain, "new.test",
            "the front cache must agree with the row for {ip}"
        );
    }
}

#[test]
fn purge_expired_dns_cache_removes_only_eligible_rows_in_batches() {
    let (_file, store) = temp_store();
    // Prime the purge gate with a throwaway write so the old rows below
    // persist until the explicit purge calls.
    store
        .upsert_dns_cache(&DnsCacheEntry {
            id: "192.0.2.200".to_owned(),
            domain: "prime.test".to_owned(),
            last_seen: OffsetDateTime::now_utc(),
        })
        .expect("prime");

    let old = OffsetDateTime::now_utc() - time::Duration::hours(25);
    for (index, ip) in ["192.0.2.201", "192.0.2.202", "192.0.2.203"]
        .iter()
        .enumerate()
    {
        store
            .upsert_dns_cache(&DnsCacheEntry {
                id: (*ip).to_owned(),
                domain: format!("old{index}.test"),
                last_seen: old,
            })
            .expect("upsert old");
    }
    store
        .upsert_dns_cache(&DnsCacheEntry {
            id: "192.0.2.204".to_owned(),
            domain: "fresh.test".to_owned(),
            last_seen: OffsetDateTime::now_utc(),
        })
        .expect("upsert fresh");

    let cutoff = OffsetDateTime::now_utc() - time::Duration::hours(24);
    assert_eq!(store.purge_expired_dns_cache(cutoff, 2).expect("purge"), 2);
    assert_eq!(store.purge_expired_dns_cache(cutoff, 2).expect("purge"), 1);
    assert_eq!(store.purge_expired_dns_cache(cutoff, 2).expect("purge"), 0);

    for ip in ["192.0.2.201", "192.0.2.202", "192.0.2.203"] {
        assert!(
            store.get_dns_cache_row(ip).expect("row").is_none(),
            "{ip} must be purged"
        );
    }
    assert_eq!(
        store
            .get_dns_cache_row("192.0.2.204")
            .expect("row")
            .expect("fresh entry")
            .domain,
        "fresh.test"
    );
    assert_eq!(
        store.dns_front.len(),
        2,
        "only the prime and fresh positives may remain resident"
    );
}

#[test]
fn dns_writes_drive_one_retention_purge_then_gate_on_interval() {
    let (_file, store) = temp_store();
    let old = OffsetDateTime::now_utc() - time::Duration::hours(25);
    let entry = DnsCacheEntry {
        id: "192.0.2.210".to_owned(),
        domain: "old.test".to_owned(),
        last_seen: old,
    };
    // A fresh store purges on its first write pass: the already-expired
    // row never survives the call that wrote it.
    store
        .upsert_dns_cache_batch(std::slice::from_ref(&entry))
        .expect("batch");
    assert!(store
        .get_dns_cache_row("192.0.2.210")
        .expect("row")
        .is_none());
    // The next write finds the interval gate closed, so its expired row
    // persists until a later pass.
    store
        .upsert_dns_cache_batch(std::slice::from_ref(&entry))
        .expect("batch");
    assert!(store
        .get_dns_cache_row("192.0.2.210")
        .expect("row")
        .is_some());
}

#[test]
fn dns_retention_range_scan_is_indexed_for_expired_and_empty_passes() {
    use crate::models::format_dns_timestamp;

    let (_file, store) = temp_store();
    let old = OffsetDateTime::now_utc() - time::Duration::days(2);
    let cutoff = OffsetDateTime::now_utc() - time::Duration::hours(24);
    store
        .db
        .execute(
            "INSERT INTO dns_cache_entries (id, domain, last_seen, latest_seen)
             VALUES (?1, 'expired.test', ?2, ?2)",
            rusqlite::params!["seed", format_dns_timestamp(old)],
        )
        .expect("seed row");
    store
        .db
        .execute_batch(
            "WITH RECURSIVE ids(n) AS (
                SELECT 1 UNION ALL SELECT n + 1 FROM ids WHERE n < 100000
             )
             INSERT INTO dns_cache_entries (id, domain, last_seen, latest_seen)
             SELECT printf('bulk-%d', n), 'expired.test',
                    '2020-01-01T00:00:00.000000000Z',
                    '2020-01-01T00:00:00.000000000Z'
             FROM ids;",
        )
        .expect("seed large expired table");

    let sql = Store::DNS_RETENTION_SQL;
    let (removed, vm_steps, fullscan_steps, elapsed) = store
        .db
        .execute_profiled(sql, rusqlite::params![format_dns_timestamp(cutoff), 1000])
        .expect("profile expired pass");
    assert_eq!(removed, 1000);
    assert!(
        fullscan_steps < 10_000,
        "unexpected full scan work: {fullscan_steps}"
    );
    assert!(vm_steps < 100_000, "unexpected VM work: {vm_steps}");

    // Keep the large table populated: this cutoff has no qualifying rows.
    let (removed, empty_vm_steps, empty_fullscan_steps, empty_elapsed) = store
        .db
        .execute_profiled(
            sql,
            rusqlite::params![format_dns_timestamp(OffsetDateTime::UNIX_EPOCH), 1000],
        )
        .expect("profile empty pass");
    assert_eq!(removed, 0);
    assert_eq!(empty_fullscan_steps, 0);
    assert!(empty_vm_steps < 100);
    eprintln!(
        "dns retention profile: expired={elapsed:?} ({vm_steps} vm, {fullscan_steps} fullscan), empty={empty_elapsed:?} ({empty_vm_steps} vm, {empty_fullscan_steps} fullscan)"
    );
}

#[test]
fn connection_log_conn_lookup_uses_the_identity_index() {
    let (_file, store) = temp_store();
    // Mirrors the lookup in `insert_connection_logs`: the identity triple
    // must resolve through the composite identity index rather than scanning
    // the table.
    let plan: Vec<String> = store
        .db
        .query_map(
            "EXPLAIN QUERY PLAN
             SELECT id, dst_domain, conn_id, conn_pid, timestamp FROM connection_logs
              WHERE (conn_id, conn_pid, timestamp) IN ((1, 2, '2026-01-01T00:00:00Z'))",
            [],
            |row| row.get::<_, String>(3),
        )
        .expect("query plan");
    assert!(
        plan.iter()
            .any(|detail| detail.contains("idx_connection_logs_conn_identity")),
        "conn lookup must use the identity index: {plan:?}"
    );
}

#[test]
fn concurrent_dns_reads_and_writes_stay_coherent() {
    use std::sync::{Arc, Barrier};

    let (_file, store) = temp_store();
    let store = Arc::new(store);
    let ip = "203.0.113.44";
    let start = OffsetDateTime::now_utc();
    let barrier = Arc::new(Barrier::new(5));

    let writer_store = Arc::clone(&store);
    let writer_barrier = Arc::clone(&barrier);
    let writer = std::thread::spawn(move || {
        writer_barrier.wait();
        for seq in 0..100 {
            writer_store
                .upsert_dns_cache(&DnsCacheEntry {
                    id: ip.to_owned(),
                    domain: format!("w{seq}.test"),
                    last_seen: start + time::Duration::seconds(seq),
                })
                .expect("upsert");
        }
    });

    let mut readers = Vec::new();
    for _ in 0..4 {
        let reader_store = Arc::clone(&store);
        let reader_barrier = Arc::clone(&barrier);
        readers.push(std::thread::spawn(move || {
            reader_barrier.wait();
            let mut seen: Vec<OffsetDateTime> = Vec::new();
            for _ in 0..500 {
                if let Some(entry) = reader_store.get_dns_cache(ip).expect("lookup") {
                    seen.push(entry.last_seen);
                }
            }
            seen
        }));
    }

    writer.join().expect("writer");
    for reader in readers {
        let seen = reader.join().expect("reader");
        let mut previous: Option<OffsetDateTime> = None;
        for observed in &seen {
            if let Some(previous) = previous {
                assert!(
                    *observed >= previous,
                    "a reader must never see an older mapping after a newer one ({previous} then {observed})"
                );
            }
            previous = Some(*observed);
        }
    }

    let loaded = store.get_dns_cache(ip).expect("lookup").expect("entry");
    assert_eq!(loaded.domain, "w99.test");
    assert_eq!(loaded.last_seen, start + time::Duration::seconds(99));
}

#[test]
fn domain_sighting_is_reported_only_once() {
    let (_file, store) = temp_store();
    let now = datetime!(2026-08-10 12:00:00 UTC);
    assert!(store
        .record_domain_sighting("Example.COM", now)
        .expect("first"));
    assert!(!store
        .record_domain_sighting("example.com", now)
        .expect("second"));
    assert!(!store.record_domain_sighting("  ", now).expect("blank"));
}

#[test]
fn update_channel_defaults_to_stable_and_round_trips() {
    let (_file, store) = temp_store();
    let mut settings = store.get_settings().expect("defaults");
    assert_eq!(settings.update_channel, "stable");

    settings.update_channel = "nightly".to_owned();
    store.update_settings(&settings).expect("update");
    assert_eq!(
        store.get_settings().expect("reload").update_channel,
        "nightly"
    );

    // A channel this daemon does not know is stored as stable.
    settings.update_channel = "canary".to_owned();
    store.update_settings(&settings).expect("update");
    assert_eq!(
        store.get_settings().expect("reload").update_channel,
        "stable"
    );
}

#[test]
fn siem_sink_flags_survive_settings_round_trip() {
    let (_file, store) = temp_store();
    let mut settings = store.get_settings().expect("defaults");
    assert!(settings.siem_file_enabled);
    assert!(!settings.siem_syslog_enabled);

    settings.siem_enabled = true;
    settings.siem_file_enabled = false;
    settings.siem_syslog_enabled = true;
    settings.siem_webhook_enabled = true;
    settings.siem_url = "https://hooks.example/siem".to_owned();
    settings.siem_auth_header = "X-Token".to_owned();
    settings.siem_auth_token = "abc".to_owned();
    store.update_settings(&settings).expect("update");

    let loaded = store.get_settings().expect("reload");
    assert!(!loaded.siem_file_enabled);
    assert!(loaded.siem_syslog_enabled);
    assert!(loaded.siem_webhook_enabled);
    assert_eq!(loaded.siem_url, "https://hooks.example/siem");
    assert_eq!(loaded.siem_auth_header, "X-Token");
    assert_eq!(loaded.siem_auth_token, "abc");
}

#[test]
fn local_name_answering_defaults_on_and_round_trips_off() {
    let (_file, store) = temp_store();
    let mut settings = store.get_settings().expect("defaults");
    assert!(settings.dns_answer_local_names_enabled);

    settings.dns_answer_local_names_enabled = false;
    store.update_settings(&settings).expect("update");
    assert!(
        !store
            .get_settings()
            .expect("reload")
            .dns_answer_local_names_enabled
    );

    settings.dns_answer_local_names_enabled = true;
    store.update_settings(&settings).expect("update");
    assert!(
        store
            .get_settings()
            .expect("reload")
            .dns_answer_local_names_enabled
    );
}

#[test]
fn new_domain_blocking_defaults_off_for_a_month_and_round_trips() {
    let (_file, store) = temp_store();
    let mut settings = store.get_settings().expect("defaults");
    assert!(!settings.dns_new_domain_blocking_enabled);
    assert_eq!(settings.dns_new_domain_max_age_days, 30);

    settings.dns_new_domain_blocking_enabled = true;
    settings.dns_new_domain_max_age_days = 7;
    store.update_settings(&settings).expect("update");
    let loaded = store.get_settings().expect("reload");
    assert!(loaded.dns_new_domain_blocking_enabled);
    assert_eq!(loaded.dns_new_domain_max_age_days, 7);
}

#[test]
fn open_with_keystore_resolves_key() {
    let file = NamedTempFile::with_suffix(".libsql").expect("temp file");
    let keystore = MemoryKeyStore;
    let store = Store::open_with_keystore(file.path(), &keystore).expect("open with keystore");
    assert!(store.get_settings().is_ok());
}

fn sample_log(index: usize) -> NewConnectionLog {
    NewConnectionLog {
        replace_domain: false,
        is_close: false,
        conn_pid: 0,
        // Stable identity triples across batches: re-running the same
        // batch must accumulate onto the same rows.
        conn_id: i64::try_from(index % 250).unwrap_or(0) + 1,
        timestamp: datetime!(2026-01-01 00:00:00 UTC),
        app_id: 1,
        app_path: String::new(),
        protocol: "TCP".to_owned(),
        src_ip: "10.0.0.2".to_owned(),
        src_port: 40_000,
        dst_ip: format!("203.0.113.{}", index % 250),
        dst_port: 443,
        dst_domain: String::new(),
        bytes_sent: 10,
        bytes_received: 20,
        action_taken: "ALLOWED".to_owned(),
        last_seen: datetime!(2026-01-01 00:00:01 UTC),
        country_code: String::new(),
        isp: String::new(),
        blocklist_names: String::new(),
    }
}

/// `insert_connection_logs` must hold the connection lock for its whole
/// transaction.
///
/// It used to drive `BEGIN IMMEDIATE`/`COMMIT` through helpers that take the
/// lock per statement, so another thread writing in between either had its write
/// swallowed into this transaction or — if it opened its own — failed with
/// "cannot start a transaction within a transaction". Both threads here hammer
/// the store concurrently; a single error from either side is the regression.
#[test]
fn concurrent_writes_are_not_swallowed_by_a_batch_insert() {
    const ROUNDS: usize = 60;
    const BATCH: usize = 200;

    let file = NamedTempFile::with_suffix(".libsql").expect("temp file");
    let store = Arc::new(Store::open(file.path()).expect("open"));

    let barrier = Arc::new(Barrier::new(2));
    let sighting_store = Arc::clone(&store);
    let sighting_barrier = Arc::clone(&barrier);

    // A `transaction_with` caller, standing in for the DNS block recorder
    // resolving an application while a flow flush is in progress.
    let sightings = std::thread::spawn(move || {
        sighting_barrier.wait();
        let mut failures = Vec::new();
        for round in 0..ROUNDS {
            if let Err(error) = sighting_store.record_application_sighting(
                &format!("app{round}.exe"),
                &format!(r"C:\apps\app{round}.exe"),
                true,
                datetime!(2026-01-01 00:00:00 UTC),
            ) {
                failures.push(error.to_string());
            }
        }
        failures
    });

    barrier.wait();
    let mut insert_failures = Vec::new();
    for round in 0..ROUNDS {
        let logs: Vec<NewConnectionLog> = (0..BATCH)
            .map(|index| sample_log(round * BATCH + index))
            .collect();
        if let Err(error) = store.insert_connection_logs(&logs) {
            insert_failures.push(error.to_string());
        }
    }

    let sighting_failures = sightings.join().expect("sighting thread");
    assert!(
        sighting_failures.is_empty(),
        "concurrent transactional writes must not fail: {sighting_failures:?}"
    );
    assert!(
        insert_failures.is_empty(),
        "batch inserts must not fail: {insert_failures:?}"
    );

    // Every sighting is durable, not rolled back with someone else's batch.
    assert_eq!(
        store.list_applications().expect("applications").len(),
        ROUNDS
    );
}

/// Behaviour guard for the per-connection upsert: re-running the same
/// connections must accumulate onto their rows, never fork duplicates.
#[test]
fn repeated_batches_accumulate_onto_the_same_connection_rows() {
    let file = NamedTempFile::with_suffix(".libsql").expect("temp file");
    let store = Store::open(file.path()).expect("open");

    let logs: Vec<NewConnectionLog> = (0..10).map(sample_log).collect();
    store.insert_connection_logs(&logs).expect("first batch");
    store.insert_connection_logs(&logs).expect("second batch");

    let page = store
        .query_connection_logs(&ConnectionLogQuery::default())
        .expect("logs");
    assert_eq!(page.total_count, 10, "one row per connection");
    for log in &page.logs {
        assert_eq!(log.bytes_sent, 20, "both batches accumulated");
        assert_eq!(log.bytes_received, 40);
    }
}

#[test]
fn activity_buckets_accumulate_and_purge_with_retention() {
    let (_file, store) = temp_store();
    let bucket_time = datetime!(2026-02-01 10:15:00 UTC);
    let bucket_start = activity_bucket_start(bucket_time);
    store
        .insert_connection_logs(&[NewConnectionLog {
            replace_domain: false,
            is_close: false,
            conn_pid: 0,
            conn_id: 0,
            timestamp: bucket_time,
            app_id: 1,
            app_path: String::new(),
            protocol: "TCP".to_owned(),
            src_ip: "10.0.0.2".to_owned(),
            src_port: 4444,
            dst_ip: "93.184.216.34".to_owned(),
            dst_port: 443,
            dst_domain: "example.com".to_owned(),
            bytes_sent: 5,
            bytes_received: 7,
            action_taken: "ALLOWED".to_owned(),
            last_seen: bucket_time,
            country_code: String::new(),
            isp: String::new(),
            blocklist_names: String::new(),
        }])
        .expect("insert log");

    let buckets = store
        .query_activity_buckets(bucket_start, bucket_start + time::Duration::minutes(30))
        .expect("query buckets");
    assert_eq!(buckets.len(), 1);
    assert_eq!(buckets[0].bucket_start, bucket_start);
    assert_eq!(buckets[0].event_count, 1);
    assert_eq!(buckets[0].bytes_sent, 5);
    assert_eq!(buckets[0].bytes_received, 7);

    store
        .purge_activity_buckets_before(Some(bucket_start + time::Duration::minutes(30)))
        .expect("purge buckets");
    let remaining = store
        .query_activity_buckets(
            bucket_start - time::Duration::days(1),
            bucket_start + time::Duration::days(1),
        )
        .expect("query after purge");
    assert_eq!(remaining, []);
}

#[test]
fn network_scan_atomically_marks_missing_devices_offline() {
    let (_file, store) = temp_store();
    let first_seen = datetime!(2026-08-03 10:00:00 UTC);
    let first = NetworkDevice {
        mac_address: "00:1B:63:00:00:01".to_owned(),
        ip_address: "192.168.1.2".to_owned(),
        manufacturer: "Apple, Inc.".to_owned(),
        mdns_name: "living-room-tv.local".to_owned(),
        adapter_id: String::new(),
        first_seen,
        last_seen: first_seen,
        present: true,
    };
    let second = NetworkDevice {
        mac_address: "00:1B:63:00:00:02".to_owned(),
        ip_address: "192.168.1.3".to_owned(),
        ..first.clone()
    };
    store
        .apply_network_scan(&[first.clone(), second])
        .expect("initial scan");

    let seen_again = NetworkDevice {
        mdns_name: String::new(),
        last_seen: datetime!(2026-08-03 11:00:00 UTC),
        ..first
    };
    store
        .apply_network_scan(&[seen_again])
        .expect("second scan");

    let devices = store.list_network_devices().expect("devices");
    assert_eq!(devices.len(), 2);
    assert!(devices[0].present);
    assert_eq!(devices[0].first_seen, first_seen);
    assert_eq!(devices[0].mdns_name, "living-room-tv.local");
    assert!(!devices[1].present);
}

#[test]
fn device_watch_round_trip_keeps_ip_and_transition_state() {
    let (_file, store) = temp_store();
    let watch = NetworkDeviceWatch {
        id: 0,
        ip_address: "192.168.1.7".to_owned(),
        mac_address: "00:1B:63:00:00:07".to_owned(),
        adapter_id: String::new(),
        cidr: "192.168.1.0/24".to_owned(),
        interval_minutes: 5,
        enabled: true,
        present: false,
        baseline_established: false,
        last_checked: datetime!(1970-01-01 00:00:00 UTC),
    };
    let id = store.insert_device_watch(&watch).expect("insert watch");
    let checked_at = datetime!(2026-08-03 12:00:00 UTC);
    store
        .update_device_watch_state(id, true, true, checked_at)
        .expect("update state");

    let saved = store.list_device_watches().expect("list watches");
    assert_eq!(saved[0].ip_address, "192.168.1.7");
    assert!(saved[0].present);
    assert!(saved[0].baseline_established);
    assert_eq!(saved[0].last_checked, checked_at);
}
