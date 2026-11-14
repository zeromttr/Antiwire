//! The firewall block on public DNS-over-HTTPS resolvers.

use std::sync::Arc;

use antiwire_enforce::{EnforceError, EnforcementClient};
use antiwire_policy::EnforcementOp;
use antiwire_store::{DaemonSetting, Store, StoreError};
use parking_lot::Mutex;

/// Why the `DoH` block could not be brought in line with the settings.
#[derive(Debug, thiserror::Error)]
pub enum DohBlockError {
    #[error("could not read the settings: {0}")]
    Settings(#[from] StoreError),
    #[error(transparent)]
    Enforce(#[from] EnforceError),
}

/// Keeps the native `DoH` block matching the saved settings.
///
/// The block is a setting, not a user rule, so it has its own owner. It reads
/// the settings itself, under its own lock, so two reconciles can never
/// install blocks for different settings out of order.
pub struct DohBlocker {
    store: Arc<Store>,
    enforce: EnforcementClient,
    gate: Mutex<()>,
}

impl DohBlocker {
    #[must_use]
    pub fn new(store: Arc<Store>, enforce: EnforcementClient) -> Self {
        Self {
            store,
            enforce,
            gate: Mutex::new(()),
        }
    }

    /// Installs or removes the block to match the saved settings.
    ///
    /// The resolver the saved settings use always stays reachable, and so does
    /// each one in `also_spare`: during a resolver change, the one still in use
    /// until the switch completes. Blocking.
    ///
    /// Run after [`RuleService::install_saved_rules`](crate::RuleService::install_saved_rules)
    /// at startup, which clears every managed rule, this block included.
    ///
    /// # Errors
    ///
    /// [`DohBlockError::Settings`] when the settings cannot be read, and
    /// [`DohBlockError::Enforce`] when the firewall rejects the change.
    pub fn reconcile(&self, also_spare: &[&DaemonSetting]) -> Result<(), DohBlockError> {
        let _gate = self.gate.lock();
        let settings = self.store.get_settings()?;
        let op = if settings.doh_blocking_enabled {
            let mut in_use = vec![&settings];
            in_use.extend_from_slice(also_spare);
            EnforcementOp::AddDohBlock {
                doh_ips: antiwire_dns::doh_block_targets(&in_use),
                port: antiwire_dns::DOH_PORT,
            }
        } else {
            EnforcementOp::RemoveDohBlocks
        };
        self.enforce.apply(op)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use antiwire_enforce::FirewallFilter;

    struct Recording {
        started: bool,
        applied: Arc<Mutex<Vec<EnforcementOp>>>,
    }

    impl FirewallFilter for Recording {
        fn start(&mut self) -> antiwire_enforce::Result<()> {
            self.started = true;
            Ok(())
        }

        fn stop(&mut self) -> antiwire_enforce::Result<()> {
            self.started = false;
            Ok(())
        }

        fn is_enforcing(&self) -> bool {
            self.started
        }

        fn apply(&mut self, op: EnforcementOp) -> antiwire_enforce::Result<()> {
            self.applied.lock().push(op);
            Ok(())
        }
    }

    fn blocker() -> (
        tempfile::NamedTempFile,
        Arc<Store>,
        Arc<Mutex<Vec<EnforcementOp>>>,
        DohBlocker,
    ) {
        let file = tempfile::NamedTempFile::new().expect("temp");
        let store = Arc::new(Store::open(file.path()).expect("open"));
        let applied = Arc::new(Mutex::new(Vec::new()));
        let enforce = EnforcementClient::with_filter(Recording {
            started: false,
            applied: Arc::clone(&applied),
        })
        .expect("enforcement worker");
        enforce.start().expect("start");
        let doh = DohBlocker::new(Arc::clone(&store), enforce);
        (file, store, applied, doh)
    }

    fn doh_ips(applied: &Mutex<Vec<EnforcementOp>>) -> Vec<String> {
        match applied.lock().last() {
            Some(EnforcementOp::AddDohBlock { doh_ips, port }) => {
                assert_eq!(*port, 443);
                doh_ips.clone()
            }
            other => panic!("expected a DoH block, got {other:?}"),
        }
    }

    #[test]
    fn the_block_spares_the_saved_resolver_and_each_one_still_in_use() {
        let (_file, store, recorded, doh) = blocker();
        let mut settings = store.get_settings().expect("settings");
        settings.doh_blocking_enabled = true;
        settings.dns_protocol = "doh".to_owned();
        settings.doh_provider = "cloudflare".to_owned();
        store.update_settings(&settings).expect("save");

        doh.reconcile(&[]).expect("reconcile");
        let blocked = doh_ips(&recorded);
        assert!(blocked.iter().any(|ip| ip == "8.8.8.8"));
        assert!(
            !blocked.iter().any(|ip| ip == "1.1.1.1"),
            "the daemon's own upstream must stay reachable"
        );

        let mut previous = settings.clone();
        previous.doh_provider = "google".to_owned();
        doh.reconcile(&[&previous]).expect("reconcile");
        let blocked = doh_ips(&recorded);
        assert!(!blocked.iter().any(|ip| ip == "8.8.8.8" || ip == "1.1.1.1"));
    }

    #[test]
    fn a_disabled_block_is_removed() {
        let (_file, store, applied, doh) = blocker();
        let mut settings = store.get_settings().expect("settings");
        settings.doh_blocking_enabled = false;
        store.update_settings(&settings).expect("save");

        doh.reconcile(&[]).expect("reconcile");

        assert!(matches!(
            applied.lock().as_slice(),
            [EnforcementOp::RemoveDohBlocks]
        ));
    }
}
