//! The system DNS redirect from start to finish on this host's real network
//! settings, through the same API the daemon uses: redirect, extend, restore.
//!
//! Run it from an elevated shell on Windows, or as root on Linux and macOS.
//! It points the host's DNS at 127.0.0.1 for a few seconds, IPv4 only, and
//! puts back the settings it found, whatever happens.

use std::path::Path;
use std::sync::Arc;

use antiwire_dns_os::backend::{capture_state, is_elevated, restore};
use antiwire_dns_redirect::{DnsRedirect, RedirectOutcome};
use antiwire_secrets::UnixSecureFileKeyProvider;
use antiwire_store::Store;

/// Puts back the DNS settings the test found, unless it already did.
struct RestoreOnDrop(Option<String>);

impl Drop for RestoreOnDrop {
    fn drop(&mut self) {
        if let Some(saved) = self.0.take() {
            if !restore(&saved) {
                eprintln!("DNS test cleanup failed; the settings it found: {saved}");
            }
        }
    }
}

fn journal_in(data_dir: &Path) -> bool {
    data_dir.join("dns-redirect-state.json").exists()
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires an elevated shell or root, and changes the host's DNS settings"]
async fn elevated_redirect_extend_and_restore() {
    assert!(is_elevated(), "run this ignored test elevated");
    let saved = capture_state().expect("DNS settings captured");
    let mut cleanup = RestoreOnDrop(Some(saved.clone()));

    let data_dir = tempfile::tempdir().expect("data dir");
    let keystore = UnixSecureFileKeyProvider::new(data_dir.path().join("key"));
    let store = Arc::new(
        Store::open_with_keystore(data_dir.path().join("antiwire.libsql"), &keystore)
            .expect("store"),
    );
    let mut redirect = DnsRedirect::new(Arc::clone(&store), data_dir.path(), false);

    let outcome = redirect
        .redirect(false)
        .await
        .expect("a fresh store has a record to read");
    assert!(
        matches!(
            outcome,
            RedirectOutcome::Complete | RedirectOutcome::Partial
        ),
        "{outcome:?}"
    );
    let recorded = store
        .get_dns_redirect()
        .expect("record")
        .expect("the redirect is recorded before anything changes");
    assert!(journal_in(data_dir.path()), "the journal is written");
    let during = capture_state().expect("DNS settings captured while redirected");
    assert!(
        during.contains("127.0.0.1"),
        "DNS points at the resolver: {during}"
    );

    // What a network transition with nothing new does: the redirect is
    // applied again, and its record stays as it was.
    redirect
        .extender(false)
        .expect("an elevated process may redirect")
        .extend()
        .await;
    assert_eq!(
        store.get_dns_redirect().expect("record").as_deref(),
        Some(recorded.as_str())
    );

    redirect.restore().await.expect("the restore is confirmed");
    cleanup.0 = None;
    assert_eq!(store.get_dns_redirect().expect("record"), None);
    assert!(!journal_in(data_dir.path()), "the journal is cleared");
    assert_eq!(
        capture_state().expect("DNS settings captured after the restore"),
        saved,
        "the DNS settings are back as they were"
    );
}
