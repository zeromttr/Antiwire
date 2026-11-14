//! Puts adapter DNS back from the recorded snapshot.

use tracing::warn;

use crate::host::Host;
use crate::state::SharedRedirect;
use crate::RedirectError;

/// Restores adapter DNS from the snapshot and settles the redirect, under the
/// OS gate. Succeeds at once when no redirect is in place.
///
/// Blocking: run it off the runtime. An extension still in its OS call
/// finishes first and its adapters are restored too; one that starts after
/// finds the redirect released.
///
/// # Errors
///
/// [`RedirectError::RestoreNotConfirmed`] when the restore was not confirmed,
/// and the redirect and its record are kept for a retry, and
/// [`RedirectError::RecordNotCleared`] when DNS was restored but its record
/// could not be cleared.
pub(crate) fn restore_redirect(
    redirect: &SharedRedirect,
    host: &Host,
) -> Result<(), RedirectError> {
    let _os = redirect.lock_os();
    restore_locked(redirect, host)
}

/// [`restore_redirect`] for a caller already holding the OS gate.
pub(crate) fn restore_locked(redirect: &SharedRedirect, host: &Host) -> Result<(), RedirectError> {
    let Some(snapshot) = redirect.snapshot() else {
        return Ok(());
    };
    if !(host.backend.restore)(&snapshot) {
        warn!("OS DNS restore was not confirmed; redirect state kept for the next attempt");
        return Err(RedirectError::RestoreNotConfirmed);
    }
    settle_restore(redirect, host)
}

/// Settles a confirmed restore: releases `redirect`, then clears its record,
/// and only then disarms boot recovery. A record that cannot be cleared keeps
/// the journal and boot recovery with it, so the next start or boot restores
/// again, which writes back the same servers.
fn settle_restore(redirect: &SharedRedirect, host: &Host) -> Result<(), RedirectError> {
    redirect.release();
    if let Err(error) = host.clear_record() {
        warn!(%error, "DNS was restored, but its redirect record could not be cleared");
        return Err(RedirectError::RecordNotCleared(error));
    }
    host.disarm_boot_recovery();
    Ok(())
}
