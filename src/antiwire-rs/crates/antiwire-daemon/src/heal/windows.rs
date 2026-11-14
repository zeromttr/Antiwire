//! Boot-time host-state heal when interactive shutdown was hard-killed.
//!
//! Boot recovery is armed by `antiwire_dns_redirect::DnsRedirect` once it
//! redirects. This module is the Windows attempt behind `--heal-host-state`,
//! which the parent module retries: open the durable store and restore what
//! it records, through `antiwire_dns_redirect::restore_orphaned`, which also
//! clears the record and disarms the ONSTART task.
//!
//! It restores DNS only. The reaper's `revert_orphaned_host_state` also
//! purges firewall rules, which this task must not touch.

use std::path::PathBuf;

use antiwire_dns_redirect::{restore_orphaned, OrphanedRedirect, RedirectError};
use antiwire_platform::DataPaths;
use anyhow::Context;
use tracing::info;

use super::{retry, Healed, RETRY_DELAYS};

/// Restore dirty DNS from the durable store and clear the dirty flag.
///
/// Each attempt runs while no daemon holds the instance lock, and releases
/// it before the pause that follows, so a daemon starting meanwhile waits
/// for one attempt at most and then takes the recovery over.
///
/// # Errors
///
/// When the store cannot be opened and there is no journal, when the dirty
/// flag cannot be cleared, or when the restore is still not confirmed after
/// the retries. The dirty flag, the journal and the boot task are then kept.
pub(crate) fn heal_host_state(data_dir: PathBuf) -> anyhow::Result<Healed> {
    let paths = DataPaths::new(data_dir);
    paths.ensure_root().context("data dir")?;
    retry(
        || match crate::process_lock::while_no_daemon(|| heal_once(&paths))? {
            Some(attempt) => attempt,
            None => Ok(Some(Healed::HandedOver)),
        },
        std::thread::sleep,
    )?
    .ok_or_else(|| {
        anyhow::anyhow!(
            "heal-host-state: DNS restore was not confirmed after {} attempts; \
             the dirty record and the boot task are kept for the next boot",
            RETRY_DELAYS.len() + 1
        )
    })
}

/// One attempt, under the instance lock. `None` when the restore was not
/// confirmed and is worth trying again.
///
/// The store is read on every attempt rather than once: a daemon that ran
/// between two attempts may have settled or changed the record.
fn heal_once(paths: &DataPaths) -> anyhow::Result<Option<Healed>> {
    use antiwire_secrets::WindowsDpapiKeyProvider;
    use antiwire_store::Store;

    let keystore = WindowsDpapiKeyProvider::new(paths.db_key());
    let store = Store::open_with_keystore(paths.database(), &keystore).context("open store");
    match restore_orphaned(store.as_ref().ok(), &paths.root) {
        Ok(OrphanedRedirect::Clean) => {
            info!("heal-host-state: no dirty DNS redirect");
            Ok(Some(Healed::Nothing))
        }
        Ok(OrphanedRedirect::Restored | OrphanedRedirect::RestoredFromJournal) => {
            info!("heal-host-state: DNS restore succeeded");
            Ok(Some(Healed::Restored))
        }
        Err(error) if error.is_retryable() => Ok(None),
        Err(RedirectError::NoRecord) => Err(match store {
            // Why the store could not be read says more than that.
            Err(error) => error,
            Ok(_) => RedirectError::NoRecord.into(),
        }),
        Err(error) => Err(anyhow::Error::new(error).context(
            "heal-host-state: DNS redirect recovery did not finish; the record and the boot task are kept",
        )),
    }
}
