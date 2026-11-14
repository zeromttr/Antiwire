use std::sync::Arc;

use antiwire_events::{Alert, AlertKind, AlertPublisher, Severity};
use antiwire_platform::SiemExporter;
use antiwire_store::Store;
use antiwire_tuning::KNOWN_APP_IDS_CACHE_CAP;
use moka::sync::Cache;
use time::OffsetDateTime;
use tracing::warn;

use crate::process_resolver::{self, ProcessIdentities, ResolvedIdentity};
use crate::sanitize;

/// Re-points persisted firewall rules when an application's executable moves.
///
/// The flow layer observes the move; rule persistence and native enforcement
/// live above it, so the wiring is injected as a callback. Implementations
/// must be best-effort: the resolver cannot recover from a failed retarget.
pub trait AppRuleRetargeter: Send + Sync {
    /// Points rules targeting `previous_path` at `new_path`.
    fn retarget_app_rules(&self, previous_path: &str, new_path: &str);
}

/// Resolves executable paths to persisted application ids, creating rows on first sight.
///
/// Applications are identified by executable path. A binary that adopts another
/// application's file name is a different application and can neither share its
/// row nor repoint its stored path, so historical connection logs (which keep
/// only `app_id`) can no longer be rewritten by a name collision. A known name
/// appearing at a new path raises a path-change alert.
pub struct AppIdResolver {
    store: Arc<Store>,
    alerts: AlertPublisher,
    siem: SiemExporter,
    known: Cache<(String, String), i32>,
    rule_retargeter: Option<Arc<dyn AppRuleRetargeter>>,
    /// The process evidence every resolution through this resolver draws on.
    processes: ProcessIdentities,
}

/// Application attribution and the process-instance evidence that selected it.
pub(crate) struct ResolvedApplication {
    pub app_id: i32,
    pub app_path: String,
    pub app_name: String,
    pub start_ts: u64,
}

impl ResolvedApplication {
    pub fn into_parts(self) -> (i32, String, String) {
        (self.app_id, self.app_path, self.app_name)
    }
}

fn build_known_app_cache(max_capacity: u64) -> Cache<(String, String), i32> {
    Cache::builder().max_capacity(max_capacity).build()
}

impl AppIdResolver {
    pub fn new(store: Arc<Store>, alerts: AlertPublisher, siem: SiemExporter) -> Self {
        let resolver = Self {
            store,
            alerts,
            siem,
            known: build_known_app_cache(KNOWN_APP_IDS_CACHE_CAP),
            rule_retargeter: None,
            processes: ProcessIdentities::new(),
        };
        resolver.warm_cache();
        resolver
    }

    /// Injects the callback that re-points firewall rules after a version move.
    ///
    /// Optional so a resolver without rule wiring (tests, collectors) keeps
    /// working; production always installs it.
    #[must_use]
    pub fn with_rule_retargeter(mut self, retargeter: Arc<dyn AppRuleRetargeter>) -> Self {
        self.rule_retargeter = Some(retargeter);
        self
    }

    /// The process evidence this resolver draws on, which lifecycle events feed.
    pub(crate) fn processes(&self) -> &ProcessIdentities {
        &self.processes
    }

    /// Returns `(app_id, app_path, app_name)`. `app_id` is zero when resolution fails.
    pub(crate) fn resolve_pid(
        &self,
        pid: u32,
        meta_path: Option<&str>,
        meta_name: Option<&str>,
        meta_start_ts: Option<u64>,
    ) -> (i32, String, String) {
        self.resolve_pid_identity(pid, meta_path, meta_name, meta_start_ts)
            .into_parts()
    }

    pub(crate) fn resolve_pid_identity(
        &self,
        pid: u32,
        meta_path: Option<&str>,
        meta_name: Option<&str>,
        meta_start_ts: Option<u64>,
    ) -> ResolvedApplication {
        let identity = self
            .processes
            .resolve(pid, meta_path, meta_name, meta_start_ts);
        self.application_for(identity)
    }

    /// The application row for an already resolved identity, created on first
    /// sight. An empty path is a failed resolution and gets no row.
    pub(crate) fn application_for(&self, identity: ResolvedIdentity) -> ResolvedApplication {
        ResolvedApplication {
            app_id: if identity.path.is_empty() {
                0
            } else {
                self.get_or_create_app_id(&identity.path, &identity.name)
            },
            app_path: identity.path,
            app_name: identity.name,
            start_ts: identity.start_ts,
        }
    }

    /// Resolves the executable identity without touching the applications table.
    ///
    /// Used to test allowlist membership before deciding whether a flow folds
    /// into `System`: a verified fold must not mint the service's application
    /// row (or its new-application alert) on the way there.
    pub(crate) fn peek_identity(
        &self,
        pid: u32,
        meta_path: Option<&str>,
        meta_name: Option<&str>,
        meta_start_ts: Option<u64>,
    ) -> ResolvedIdentity {
        self.processes
            .resolve(pid, meta_path, meta_name, meta_start_ts)
    }

    /// Returns `(app_id, app_path, app_name)` for a flow with no observed owner.
    ///
    /// This is distinct from [`Self::unknown_exited`]: no PID was ever known, so
    /// there is no resolution that could have failed. Keeping the two apart
    /// makes the residual unknowns diagnosable.
    pub(crate) fn unknown_no_owner(&self) -> (i32, String, String) {
        self.unknown_placeholder("Unknown (No Owner)")
    }

    /// Returns `(app_id, app_path, app_name)` for a PID that exited before resolution.
    pub(crate) fn unknown_exited(&self) -> (i32, String, String) {
        self.unknown_placeholder("Unknown (Exited)")
    }

    /// Returns `(app_id, app_path, app_name)` for the canonical `System` identity.
    ///
    /// Used for OS-originated traffic the classifier folded. The path is synthetic,
    /// so this never raises new-application or relocation alerts and always joins
    /// the single `System` row.
    pub(crate) fn system_identity(&self) -> (i32, String, String) {
        let app_path = crate::system_services::SYSTEM_APP_PATH.to_owned();
        let app_name = crate::system_services::SYSTEM_APP_NAME.to_owned();
        (
            self.get_or_create_app_id(&app_path, &app_name),
            app_path,
            app_name,
        )
    }

    pub(crate) fn resolved_system_identity(&self, start_ts: u64) -> ResolvedApplication {
        let (app_id, app_path, app_name) = self.system_identity();
        ResolvedApplication {
            app_id,
            app_path,
            app_name,
            start_ts,
        }
    }

    fn unknown_placeholder(&self, app_path: &str) -> (i32, String, String) {
        let app_name = process_resolver::UNKNOWN_APP_NAME.to_owned();
        (
            self.get_or_create_app_id(app_path, &app_name),
            app_path.to_owned(),
            app_name,
        )
    }

    /// Returns the database id for `app_path`, creating the application row when needed.
    ///
    /// The identity is the path, so a first sighting of a path always reaches
    /// the store and a later name collision cannot repoint an existing row.
    /// Both inputs are sanitized here, the single boundary through which
    /// process-chosen strings enter the applications table and its alerts.
    pub(crate) fn get_or_create_app_id(&self, app_path: &str, app_name: &str) -> i32 {
        let app_path = sanitize::trimmed(app_path, sanitize::MAX_PATH_CHARS);
        let app_name = sanitize::trimmed(app_name, sanitize::MAX_NAME_CHARS);
        if app_path.is_empty() {
            return 0;
        }

        let authoritative_path = path_is_authoritative(&app_path);
        let cache_key = cache_key_for(&app_path, &app_name, authoritative_path);
        if let Some(app_id) = self.known.get(&cache_key) {
            return app_id;
        }

        let app_id = match self.store.record_application_sighting(
            &app_name,
            &app_path,
            authoritative_path,
            OffsetDateTime::now_utc(),
        ) {
            Ok(sighting) => {
                // Placeholder paths describe a failed resolution, not a new
                // program, so they must not raise new-application or relocation
                // alerts. Real paths still do.
                if !process_resolver::is_synthetic_path(&app_path) {
                    let previous_path = sighting
                        .previous_path
                        .as_deref()
                        .filter(|path| !process_resolver::is_synthetic_path(path));
                    if sighting.is_new_application {
                        match previous_path {
                            // The same name is already known from a real
                            // location: this is a move (or an impersonation),
                            // not a first sighting.
                            Some(previous_path) => {
                                self.notify_path_change(
                                    &app_name,
                                    previous_path,
                                    &app_path,
                                    Severity::Warning,
                                );
                            }
                            None => self.notify_new_application(&app_name, &app_path),
                        }
                    } else if sighting.path_changed {
                        // A version bump inside the same install family keeps
                        // one identity; the move is informational, not a new
                        // application or a relocation.
                        if let Some(previous_path) = previous_path {
                            self.notify_path_change(
                                &app_name,
                                previous_path,
                                &app_path,
                                Severity::Info,
                            );
                            if let Some(retargeter) = &self.rule_retargeter {
                                retargeter.retarget_app_rules(previous_path, &app_path);
                            }
                        }
                    }
                }
                sighting.app_id
            }
            Err(error) => {
                warn!(error = %error, app_path, app_name, "failed to record application sighting");
                // A real executable path is the identity. A failed write must
                // not fall back to an older same-name row: caching that id
                // would make the resolver stop retrying after the database
                // recovers and could suppress a version-move retarget.
                0
            }
        };

        if app_id > 0 {
            self.remember_app_id(&cache_key, app_id);
        }
        app_id
    }

    fn notify_new_application(&self, app_name: &str, app_path: &str) {
        self.siem.queue_new_app_event(app_name, app_path);
        self.alerts.publish(Alert::new(
            AlertKind::NewApplication,
            Severity::Warning,
            "New Application Detected",
            format!("Program '{app_name}' at '{app_path}' is attempting to establish connections."),
        ));
    }

    /// Raises an executable that has started running from somewhere new.
    ///
    /// Routine for self-updating apps, but it is also what a name being run out
    /// of a temp or profile directory looks like, so a relocation is a warning.
    /// A version-only move inside an existing identity is informational.
    fn notify_path_change(
        &self,
        app_name: &str,
        previous_path: &str,
        app_path: &str,
        severity: Severity,
    ) {
        let previous_path = sanitize::trimmed(previous_path, sanitize::MAX_PATH_CHARS);
        self.alerts.publish(Alert::new(
            AlertKind::ApplicationPathChanged,
            severity,
            "Application Running From a New Location",
            format!(
                "Program '{app_name}' is now running from '{app_path}', previously '{previous_path}'."
            ),
        ));
    }

    fn remember_app_id(&self, cache_key: &(String, String), app_id: i32) {
        self.known.insert(cache_key.clone(), app_id);
    }

    fn warm_cache(&self) {
        match self.store.list_applications() {
            Ok(apps) => {
                for app in apps {
                    if !app.app_path.is_empty() {
                        let authoritative = path_is_authoritative(&app.app_path);
                        self.known.insert(
                            cache_key_for(&app.app_path, &app.app_name, authoritative),
                            app.id,
                        );
                    }
                }
                self.known.run_pending_tasks();
            }
            Err(error) => warn!(error = %error, "failed to warm application cache"),
        }
    }
}

/// Whether an application path is a real identity rather than a failed resolution.
///
/// Unknown placeholders are path-keyed so each failure reason (`No Owner`,
/// `Exited`, `Access Denied`) keeps its own application row. The basename
/// fallback (`Path unavailable`) stays name-keyed so it keeps joining
/// the real application's row instead of forking one per failure.
fn path_is_authoritative(app_path: &str) -> bool {
    !process_resolver::is_synthetic_path(app_path)
        || process_resolver::is_unknown_placeholder(app_path)
}

/// Builds the `known` cache key for one application identity.
///
/// A real path and an unknown placeholder (`Unknown (Exited)`) are the whole
/// identity, so the display name is not part of the key. Remaining synthetics
/// (`Path unavailable`) stay name-keyed so they keep joining the real
/// application's row.
fn cache_key_for(app_path: &str, app_name: &str, authoritative_path: bool) -> (String, String) {
    if authoritative_path {
        (app_path.to_owned(), String::new())
    } else {
        (app_path.to_owned(), app_name.to_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use antiwire_events::NotificationHub;
    use antiwire_policy::BASENAME_FALLBACK_PATH;
    use antiwire_secrets::UnixSecureFileKeyProvider;
    use tempfile::tempdir;

    fn fixture(dir: &std::path::Path) -> (Arc<Store>, AlertPublisher, AppIdResolver) {
        let keystore = UnixSecureFileKeyProvider::new(dir.join("key"));
        let store =
            Arc::new(Store::open_with_keystore(dir.join("db.sqlite"), &keystore).expect("open"));
        let publisher = AlertPublisher::unsaved(NotificationHub::with_capacity(8), None);
        let resolver = AppIdResolver::new(
            Arc::clone(&store),
            publisher.clone(),
            antiwire_platform::SiemExporter::new(antiwire_platform::SiemConfig::default()),
        );
        (store, publisher, resolver)
    }

    #[derive(Default)]
    struct RecordingRetargeter {
        calls: std::sync::Mutex<Vec<(String, String)>>,
    }

    impl AppRuleRetargeter for RecordingRetargeter {
        fn retarget_app_rules(&self, previous_path: &str, new_path: &str) {
            self.calls
                .lock()
                .expect("calls")
                .push((previous_path.to_owned(), new_path.to_owned()));
        }
    }

    #[test]
    fn unknown_exited_returns_stable_application_id() {
        let dir = tempdir().expect("tempdir");
        let (_, _, resolver) = fixture(dir.path());

        let first = resolver.unknown_exited();
        let second = resolver.unknown_exited();
        assert!(first.0 > 0);
        assert_eq!(first.0, second.0);
        assert_eq!(first.1, "Unknown (Exited)");
        assert_eq!(first.2, "unknown.exe");
    }

    #[test]
    fn unknown_no_owner_is_stable_and_distinct_from_exited() {
        let dir = tempdir().expect("tempdir");
        let (store, _, resolver) = fixture(dir.path());

        let no_owner = resolver.unknown_no_owner();
        let again = resolver.unknown_no_owner();
        let exited = resolver.unknown_exited();
        assert!(no_owner.0 > 0);
        assert_eq!(no_owner.0, again.0);
        assert_eq!(no_owner.1, "Unknown (No Owner)");
        assert_eq!(no_owner.2, "unknown.exe");
        assert_ne!(
            no_owner.0, exited.0,
            "the two placeholder reasons must not share a row"
        );
        assert_eq!(store.list_applications().expect("apps").len(), 2);
    }

    #[tokio::test]
    async fn placeholder_identities_do_not_raise_new_application_alerts() {
        let dir = tempdir().expect("tempdir");
        let (_, publisher, resolver) = fixture(dir.path());
        let mut events = publisher.subscribe();

        assert!(resolver.unknown_no_owner().0 > 0);
        assert!(resolver.unknown_exited().0 > 0);
        assert!(resolver.unknown_no_owner().0 > 0);

        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(50), events.recv())
                .await
                .is_err(),
            "placeholders describe a failed resolution, not a new application"
        );
    }

    #[test]
    fn maps_executable_path_to_application_id() {
        let dir = tempdir().expect("tempdir");
        let (_, _, resolver) = fixture(dir.path());

        let first = resolver.get_or_create_app_id(r"C:\Program Files\Example\app.exe", "app.exe");
        assert!(first > 0);

        let second = resolver.get_or_create_app_id(r"C:\Program Files\Example\app.exe", "app.exe");
        assert_eq!(first, second);
    }

    #[test]
    fn known_application_cache_is_bounded() {
        let cache = build_known_app_cache(2);
        cache.insert(("one.exe".to_owned(), "one.exe".to_owned()), 1);
        assert_eq!(
            cache.get(&("one.exe".to_owned(), "one.exe".to_owned())),
            Some(1)
        );

        cache.insert(("two.exe".to_owned(), "two.exe".to_owned()), 2);
        cache.insert(("three.exe".to_owned(), "three.exe".to_owned()), 3);
        cache.run_pending_tasks();

        assert!(cache.entry_count() <= 2);
    }

    #[test]
    fn cache_keys_follow_path_authority() {
        assert_eq!(
            cache_key_for(
                r"C:\apps\app.exe",
                "app.exe",
                path_is_authoritative(r"C:\apps\app.exe")
            ),
            (r"C:\apps\app.exe".to_owned(), String::new())
        );
        assert_eq!(
            cache_key_for(
                "Unknown (Exited)",
                "unknown.exe",
                path_is_authoritative("Unknown (Exited)")
            ),
            ("Unknown (Exited)".to_owned(), String::new())
        );
        assert_eq!(
            cache_key_for(
                BASENAME_FALLBACK_PATH,
                "svchost.exe",
                path_is_authoritative(BASENAME_FALLBACK_PATH)
            ),
            (BASENAME_FALLBACK_PATH.to_owned(), "svchost.exe".to_owned())
        );
    }

    #[tokio::test]
    async fn relocating_an_application_forks_identity_and_raises_the_move() {
        let dir = tempdir().expect("tempdir");
        let (store, publisher, resolver) = fixture(dir.path());
        let mut events = publisher.subscribe();

        let installed =
            resolver.get_or_create_app_id(r"C:\Program Files\Vendor\v1\updater.exe", "updater.exe");
        assert_eq!(
            events.recv().await.expect("new app").kind,
            AlertKind::NewApplication
        );

        let relocated = resolver
            .get_or_create_app_id(r"C:\Users\me\AppData\Local\Temp\updater.exe", "updater.exe");
        assert_ne!(
            relocated, installed,
            "a different path is a different application identity"
        );

        let event = events.recv().await.expect("path change");
        assert_eq!(event.kind, AlertKind::ApplicationPathChanged);
        assert!(event
            .message
            .contains(r"C:\Users\me\AppData\Local\Temp\updater.exe"));
        assert!(event
            .message
            .contains(r"C:\Program Files\Vendor\v1\updater.exe"));

        // Both locations remain independently attributable.
        assert_eq!(store.list_applications().expect("apps").len(), 2);
        assert_eq!(
            store
                .find_application_by_name("updater.exe")
                .expect("application")
                .expect("exists")
                .app_path,
            r"C:\Program Files\Vendor\v1\updater.exe"
        );
    }

    #[tokio::test]
    async fn version_bump_keeps_identity_and_raises_an_informational_move() {
        let dir = tempdir().expect("tempdir");
        let (store, publisher, resolver) = fixture(dir.path());
        let mut events = publisher.subscribe();

        let first = resolver.get_or_create_app_id(
            r"C:\Users\me\AppData\Local\GitHubDesktop\app-3.6.5\GitHubDesktop.exe",
            "GitHubDesktop.exe",
        );
        assert_eq!(
            events.recv().await.expect("new app").kind,
            AlertKind::NewApplication
        );

        let updated = resolver.get_or_create_app_id(
            r"C:\Users\me\AppData\Local\GitHubDesktop\app-3.6.6\GitHubDesktop.exe",
            "GitHubDesktop.exe",
        );
        assert_eq!(updated, first, "a version bump is the same application");
        assert_eq!(store.list_applications().expect("apps").len(), 1);

        let event = events.recv().await.expect("path change");
        assert_eq!(event.kind, AlertKind::ApplicationPathChanged);
        assert_eq!(
            event.severity,
            Severity::Info,
            "a version move is informational"
        );
        assert!(event.message.contains("app-3.6.6"));
        assert!(event.message.contains("app-3.6.5"));

        // Re-running the current version raises nothing further.
        assert_eq!(
            resolver.get_or_create_app_id(
                r"C:\Users\me\AppData\Local\GitHubDesktop\app-3.6.6\GitHubDesktop.exe",
                "GitHubDesktop.exe",
            ),
            first
        );
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(50), events.recv())
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn a_same_named_copy_outside_the_install_root_is_a_new_application() {
        let dir = tempdir().expect("tempdir");
        let (store, publisher, resolver) = fixture(dir.path());
        let mut events = publisher.subscribe();

        let installed = resolver.get_or_create_app_id(
            r"C:\Users\me\AppData\Local\GitHubDesktop\app-3.6.6\GitHubDesktop.exe",
            "GitHubDesktop.exe",
        );
        assert_eq!(
            events.recv().await.expect("new app").kind,
            AlertKind::NewApplication
        );

        let desktop = resolver.get_or_create_app_id(
            r"C:\Users\me\Desktop\GitHubDesktop.exe",
            "GitHubDesktop.exe",
        );
        assert_ne!(desktop, installed);
        assert_eq!(store.list_applications().expect("apps").len(), 2);
        assert_eq!(
            events.recv().await.expect("path change").kind.as_str(),
            "APP_PATH_CHANGED"
        );
    }

    #[tokio::test]
    async fn a_version_move_retargets_firewall_rules_but_a_relocation_does_not() {
        let dir = tempdir().expect("tempdir");
        let (_, publisher, resolver) = fixture(dir.path());
        let retargeter = Arc::new(RecordingRetargeter::default());
        let resolver = resolver.with_rule_retargeter(retargeter.clone());
        let mut events = publisher.subscribe();

        resolver.get_or_create_app_id(r"C:\Users\me\app-1.0\app.exe", "app.exe");
        assert_eq!(
            events.recv().await.expect("new app").kind,
            AlertKind::NewApplication
        );

        resolver.get_or_create_app_id(r"C:\Users\me\app-2.0\app.exe", "app.exe");
        assert_eq!(
            events.recv().await.expect("path change").kind.as_str(),
            "APP_PATH_CHANGED"
        );

        // A copy outside the install root is a new application, so its rules
        // must not be re-pointed at the installed binary's path.
        resolver.get_or_create_app_id(r"C:\Users\me\Desktop\app.exe", "app.exe");
        assert_eq!(
            events.recv().await.expect("path change").kind.as_str(),
            "APP_PATH_CHANGED"
        );

        let calls = retargeter.calls.lock().expect("calls");
        assert_eq!(calls.len(), 1, "only the version move retargets");
        assert_eq!(calls[0].0, r"C:\Users\me\app-1.0\app.exe");
        assert_eq!(calls[0].1, r"C:\Users\me\app-2.0\app.exe");
    }

    #[tokio::test]
    async fn same_named_binary_cannot_repoint_another_application() {
        let dir = tempdir().expect("tempdir");
        let (store, publisher, resolver) = fixture(dir.path());
        let mut events = publisher.subscribe();

        let chrome = resolver.get_or_create_app_id(
            r"C:\Program Files\Google\Chrome\Application\chrome.exe",
            "chrome.exe",
        );
        assert_eq!(
            events.recv().await.expect("new app").kind,
            AlertKind::NewApplication
        );

        let impostor = resolver
            .get_or_create_app_id(r"C:\Users\me\AppData\Local\Temp\chrome.exe", "chrome.exe");
        assert_ne!(impostor, chrome);

        // The impostor raises an alert and gets its own row; Chrome's stored
        // path is untouched, so historical logs keep their original attribution.
        assert_eq!(
            events.recv().await.expect("path change").kind.as_str(),
            "APP_PATH_CHANGED"
        );
        let chrome_app = store
            .find_application_by_name("chrome.exe")
            .expect("application")
            .expect("exists");
        assert_eq!(
            chrome_app.app_path,
            r"C:\Program Files\Google\Chrome\Application\chrome.exe"
        );
        assert_eq!(store.list_applications().expect("apps").len(), 2);
    }

    #[test]
    fn case_only_path_change_keeps_one_identity() {
        let dir = tempdir().expect("tempdir");
        let (store, _, resolver) = fixture(dir.path());

        let first = resolver.get_or_create_app_id(r"C:\apps\Tool.exe", "Tool.exe");
        let recased = resolver.get_or_create_app_id(r"C:\Apps\tool.exe", "Tool.exe");

        assert_eq!(first, recased);
        assert_eq!(store.list_applications().expect("apps").len(), 1);
    }

    #[test]
    fn failed_path_resolution_does_not_look_like_a_relocation() {
        let dir = tempdir().expect("tempdir");
        let (store, _, resolver) = fixture(dir.path());

        let real = resolver.get_or_create_app_id(r"C:\apps\guarded.exe", "guarded.exe");
        let fallback = resolver.get_or_create_app_id(BASENAME_FALLBACK_PATH, "guarded.exe");

        assert_eq!(fallback, real);
        assert_eq!(
            store
                .find_application_by_name("guarded.exe")
                .expect("application")
                .expect("application exists")
                .app_path,
            r"C:\apps\guarded.exe"
        );
    }

    #[test]
    fn failed_authoritative_write_returns_zero_and_retries_after_recovery() {
        let dir = tempdir().expect("tempdir");
        let keystore = UnixSecureFileKeyProvider::new(dir.path().join("key"));
        let store = Arc::new(
            Store::open_with_keystore(dir.path().join("db.sqlite"), &keystore).expect("open"),
        );
        let publisher = AlertPublisher::unsaved(NotificationHub::with_capacity(8), None);
        let seen = OffsetDateTime::now_utc();
        let first = store
            .record_application_sighting("same.exe", r"C:\one\same.exe", true, seen)
            .expect("first application")
            .app_id;
        let second = store
            .record_application_sighting("same.exe", r"C:\two\same.exe", true, seen)
            .expect("second application")
            .app_id;
        assert!(
            first < second,
            "fixture rows must have stable oldest-first order"
        );

        let resolver = AppIdResolver::new(
            Arc::clone(&store),
            publisher,
            antiwire_platform::SiemExporter::new(antiwire_platform::SiemConfig::default()),
        );
        let db = rusqlite::Connection::open(store.path()).expect("fault-injection connection");
        db.execute_batch(
            "CREATE TRIGGER fail_authoritative_application_insert
             BEFORE INSERT ON applications
             BEGIN SELECT RAISE(ABORT, 'injected application insert failure'); END;",
        )
        .expect("install insert fault");

        let candidate = r"C:\three\same.exe";
        assert_eq!(
            resolver.get_or_create_app_id(candidate, "same.exe"),
            0,
            "a real-path write failure must not use an older same-name row"
        );
        assert_eq!(
            store.list_applications().expect("applications").len(),
            2,
            "the failed insert must not create a row"
        );

        db.execute_batch("DROP TRIGGER fail_authoritative_application_insert")
            .expect("remove insert fault");
        let recovered = resolver.get_or_create_app_id(candidate, "same.exe");
        assert!(recovered > 0);
        assert_ne!(recovered, first);
        assert_ne!(recovered, second);
        assert_eq!(
            store
                .find_application_by_name("same.exe")
                .expect("application lookup")
                .expect("candidate application")
                .app_path,
            r"C:\one\same.exe",
            "oldest-name lookup remains the old row while the real path gets its own row"
        );
        assert!(store
            .list_applications()
            .expect("applications")
            .iter()
            .any(|app| app.id == recovered && app.app_path == candidate));
    }

    #[test]
    fn failed_version_move_retries_retarget_after_database_recovery() {
        let dir = tempdir().expect("tempdir");
        let (store, _hub, resolver) = fixture(dir.path());
        let retargeter = Arc::new(RecordingRetargeter::default());
        let retargeter_for_resolver: Arc<dyn AppRuleRetargeter> = retargeter.clone();
        let resolver = resolver.with_rule_retargeter(retargeter_for_resolver);
        let previous = r"C:\Users\me\app-1.0\app.exe";
        let updated = r"C:\Users\me\app-2.0\app.exe";
        let app_id = resolver.get_or_create_app_id(previous, "app.exe");
        assert!(app_id > 0);

        let db = rusqlite::Connection::open(store.path()).expect("fault-injection connection");
        db.execute_batch(
            "CREATE TRIGGER fail_application_move
             BEFORE UPDATE ON applications
             BEGIN SELECT RAISE(ABORT, 'injected application move failure'); END;",
        )
        .expect("install update fault");

        assert_eq!(resolver.get_or_create_app_id(updated, "app.exe"), 0);
        assert!(retargeter.calls.lock().expect("calls").is_empty());

        db.execute_batch("DROP TRIGGER fail_application_move")
            .expect("remove update fault");
        assert_eq!(resolver.get_or_create_app_id(updated, "app.exe"), app_id);
        assert_eq!(
            retargeter.calls.lock().expect("calls").as_slice(),
            &[(previous.to_owned(), updated.to_owned())]
        );
    }

    #[tokio::test]
    async fn notification_text_strips_control_characters() {
        let dir = tempdir().expect("tempdir");
        let (_, publisher, resolver) = fixture(dir.path());
        let mut events = publisher.subscribe();

        let app_path = "C:\\apps\\evil\nINFO forged.exe";
        let app_name = "evil\nINFO forged.exe";
        assert!(resolver.get_or_create_app_id(app_path, app_name) > 0);

        let event = events.recv().await.expect("new app event");
        assert!(!event.message.contains('\n'));
        assert!(!event.message.contains('\u{0}'));
    }

    #[test]
    fn prefers_flow_meta_process_path() {
        let expected_path = if cfg!(windows) {
            r"C:\Windows\System32\curl.exe"
        } else {
            "/usr/bin/curl"
        };
        let identity =
            ProcessIdentities::new().resolve(0, Some(expected_path), Some("curl.exe"), None);
        assert_eq!(identity.path, expected_path);
        assert_eq!(identity.name, "curl.exe");
    }
}
