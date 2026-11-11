//! `--heal-host-state`: reverts host state a stopped daemon left behind, then
//! exits.
//!
//! Run by the Windows boot task and the Linux unit's `ExecStopPost`, both of
//! which can run beside a live daemon. A live daemon's redirect is not
//! orphaned, so each attempt runs only while no daemon holds the instance
//! lock, and the lock is released between attempts.
//!
//! What an attempt does depends on the platform. Windows restores DNS only
//! (see `windows`); elsewhere the heal makes the reaper's full
//! revert. The retries are shared.

use std::path::Path;
use std::time::Duration;

use anyhow::Result;
use tracing::{info, warn};

#[cfg(windows)]
mod windows;

/// Pauses before each retry of an attempt that did not finish. At boot an
/// adapter is often not enumerable yet, and nothing restarts a failed heal,
/// so without them the next attempt is the next boot or stop.
pub(crate) const RETRY_DELAYS: [Duration; 3] = [
    Duration::from_secs(2),
    Duration::from_secs(4),
    Duration::from_secs(8),
];

/// How a heal ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Healed {
    /// Nothing was left to restore. Only the Windows heal tells this apart
    /// from [`Self::Restored`].
    #[cfg_attr(not(windows), allow(dead_code))]
    Nothing,
    /// The host state was restored and its recovery record cleared.
    Restored,
    /// A daemon took the instance lock; it recovers the host from here.
    HandedOver,
}

/// Reverts what a stopped daemon left behind. See the module documentation.
///
/// # Errors
///
/// When the heal could not finish: see each platform's heal.
#[cfg(windows)]
pub(crate) fn heal_host_state(data_dir: &Path) -> Result<()> {
    let healed = windows::heal_host_state(data_dir.to_path_buf())?;
    info!(?healed, "heal-host-state finished");
    Ok(())
}

/// Reverts what a stopped daemon left behind: the reaper's revert, with a
/// few quick retries of an unconfirmed DNS restore or a failed firewall
/// cleanup. It must finish within the unit's stop timeout.
///
/// # Errors
///
/// When the store could not be read, or either revert is still undone after
/// the retries.
#[cfg(not(windows))]
pub(crate) fn heal_host_state(data_dir: &Path) -> Result<()> {
    use crate::process_lock::while_no_daemon;

    let healed = heal_orphaned(
        || while_no_daemon(|| antiwire_runtime::revert_orphaned_host_state(data_dir)),
        |pending| {
            while_no_daemon(|| antiwire_runtime::retry_orphaned_host_state(data_dir, pending))
        },
        std::thread::sleep,
    )?;
    info!(?healed, "heal-host-state finished");
    Ok(())
}

/// Runs `revert`, then `retry_pending` on what it left, after each of
/// [`RETRY_DELAYS`], until nothing is left. Each returns `None` while a
/// daemon holds the instance lock, which hands the recovery to it.
///
/// # Errors
///
/// When the store could not be read, which the revert reports even when it
/// restored everything from the journal, or something is still pending
/// after the last retry.
#[cfg(any(not(windows), test))]
fn heal_orphaned(
    revert: impl FnOnce() -> Result<Option<antiwire_runtime::OrphanedRevert>>,
    mut retry_pending: impl FnMut(
        antiwire_runtime::OrphanedPending,
    ) -> Result<Option<antiwire_runtime::OrphanedPending>>,
    sleep: impl FnMut(Duration),
) -> Result<Healed> {
    let mut revert = Some(revert);
    let mut pending = antiwire_runtime::OrphanedPending::default();
    let mut store = Ok(());
    let healed = retry(
        || {
            let now = match revert.take() {
                Some(revert) => revert()?.map(|reverted| {
                    store = reverted.result;
                    reverted.pending
                }),
                None => {
                    info!(
                        dns = pending.dns,
                        firewall = pending.firewall,
                        "heal-host-state: retrying the revert"
                    );
                    retry_pending(pending)?
                }
            };
            Ok(match now {
                None => Some(Healed::HandedOver),
                Some(now) if !now.any() => Some(Healed::Restored),
                Some(now) => {
                    pending = now;
                    None
                }
            })
        },
        sleep,
    )?;
    store?;
    if let Some(healed) = healed {
        return Ok(healed);
    }
    if pending.dns {
        anyhow::bail!("adapter DNS could not be restored; the next daemon start retries");
    }
    anyhow::bail!("firewall rules could not be removed; the next daemon start clears them")
}

/// Runs `attempt`, and again after each of [`RETRY_DELAYS`] while it returns
/// `None`, an attempt that did not finish. An error ends the heal at once.
///
/// # Errors
///
/// The first error an attempt returns.
pub(crate) fn retry(
    mut attempt: impl FnMut() -> Result<Option<Healed>>,
    mut sleep: impl FnMut(Duration),
) -> Result<Option<Healed>> {
    if let Some(healed) = attempt()? {
        return Ok(Some(report(healed)));
    }
    for delay in RETRY_DELAYS {
        warn!(
            retry_in = ?delay,
            "heal-host-state: host state is not fully restored yet; retrying"
        );
        sleep(delay);
        if let Some(healed) = attempt()? {
            return Ok(Some(report(healed)));
        }
    }
    Ok(None)
}

fn report(healed: Healed) -> Healed {
    if healed == Healed::HandedOver {
        info!(
            "heal-host-state: a daemon is running and owns its host state; leaving it the recovery"
        );
    }
    healed
}

#[cfg(test)]
mod tests {
    use super::*;
    use antiwire_runtime::{OrphanedPending, OrphanedRevert};

    const DNS: OrphanedPending = OrphanedPending {
        dns: true,
        firewall: false,
    };
    const NOTHING: OrphanedPending = OrphanedPending {
        dns: false,
        firewall: false,
    };

    fn reverted(pending: OrphanedPending) -> Result<Option<OrphanedRevert>> {
        Ok(Some(OrphanedRevert {
            pending,
            result: Ok(()),
        }))
    }

    #[test]
    fn an_attempt_that_finishes_late_is_retried_until_it_does() {
        let mut attempts = 0;
        let mut slept = Vec::new();
        let healed = retry(
            || {
                attempts += 1;
                Ok((attempts == 3).then_some(Healed::Restored))
            },
            |delay| slept.push(delay),
        );
        assert_eq!(healed.ok(), Some(Some(Healed::Restored)));
        assert_eq!(attempts, 3);
        assert_eq!(slept, RETRY_DELAYS[..2]);
    }

    #[test]
    fn retries_are_bounded() {
        let mut attempts = 0;
        let mut slept = Vec::new();
        let healed = retry(
            || {
                attempts += 1;
                Ok(None)
            },
            |delay| slept.push(delay),
        );
        assert_eq!(healed.ok(), Some(None));
        assert_eq!(attempts, RETRY_DELAYS.len() + 1);
        assert_eq!(slept, RETRY_DELAYS);
    }

    #[test]
    fn a_finished_first_attempt_does_not_wait() {
        let healed = retry(|| Ok(Some(Healed::Restored)), |_| panic!("no retry needed"));
        assert_eq!(healed.ok(), Some(Some(Healed::Restored)));
    }

    /// The regression this guards: the heal held the instance lock through
    /// every attempt and pause, longer than a starting daemon waits for it.
    /// A daemon that takes the lock between attempts ends the heal instead.
    #[test]
    fn a_daemon_that_starts_between_attempts_takes_the_recovery_over() {
        let mut attempts = 0;
        let healed = retry(
            || {
                attempts += 1;
                Ok((attempts == 2).then_some(Healed::HandedOver))
            },
            |_| {},
        );
        assert_eq!(healed.ok(), Some(Some(Healed::HandedOver)));
        assert_eq!(attempts, 2);
    }

    #[test]
    fn an_error_ends_the_heal_without_retrying() {
        let mut attempts = 0;
        let healed = retry(
            || {
                attempts += 1;
                Err(anyhow::anyhow!("store unavailable and no journal"))
            },
            |_| panic!("an error is not retried"),
        );
        assert!(healed.is_err());
        assert_eq!(attempts, 1);
    }

    #[test]
    fn a_running_daemon_is_left_its_host_state() {
        let healed = heal_orphaned(
            || Ok(None),
            |_| panic!("nothing to retry"),
            |_| panic!("no wait"),
        );
        assert_eq!(healed.ok(), Some(Healed::HandedOver));
    }

    #[test]
    fn only_what_the_revert_left_is_retried() {
        let mut retried = Vec::new();
        let healed = heal_orphaned(
            || reverted(DNS),
            |pending| {
                retried.push(pending);
                Ok(Some(NOTHING))
            },
            |_| {},
        );
        assert_eq!(healed.ok(), Some(Healed::Restored));
        assert_eq!(retried, [DNS]);
    }

    #[test]
    fn what_is_still_pending_after_the_retries_fails_the_heal() {
        let mut retries = 0;
        let healed = heal_orphaned(
            || reverted(DNS),
            |pending| {
                retries += 1;
                Ok(Some(pending))
            },
            |_| {},
        );
        let error = healed.expect_err("DNS is still redirected");
        assert!(error.to_string().contains("DNS"), "{error}");
        assert_eq!(retries, RETRY_DELAYS.len());
    }

    /// A store that could not be read is reported even when the journal
    /// restored everything, as is a handover after such a revert.
    #[test]
    fn a_store_failure_is_reported_however_the_heal_ends() {
        let unreadable = |pending| {
            Ok(Some(OrphanedRevert {
                pending,
                result: Err(anyhow::anyhow!("open store")),
            }))
        };
        assert!(heal_orphaned(|| unreadable(NOTHING), |_| panic!(), |_| {}).is_err());
        assert!(heal_orphaned(|| unreadable(DNS), |_| Ok(None), |_| {}).is_err());
    }
}
