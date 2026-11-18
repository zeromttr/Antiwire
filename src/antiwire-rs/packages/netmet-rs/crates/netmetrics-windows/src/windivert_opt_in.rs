//! Whether this process may use `WinDivert`. It may not until the application says so.
//!
//! `WinDivert` is a third-party kernel driver that captures packets. Anti-cheat software
//! can treat a loaded packet-capture driver as an integrity violation and refuse to start
//! a game, or ban the account. So the switch starts off, and while it is off nothing asks
//! the package's site for the archive, nothing loads the DLL, and nothing opens the
//! driver: [`refuse_unless_enabled`] stands in front of all three.
//!
//! The switch is one per process because the driver is one per machine: the FLOW listener
//! and the port-53 divert both open it.

use std::sync::atomic::{AtomicBool, Ordering};

#[cfg(target_arch = "x86_64")]
use crate::divert_error::DivertError;

static ENABLED: AtomicBool = AtomicBool::new(false);

/// Allows or forbids `WinDivert` for this process. It is forbidden until this is called
/// with `true`.
///
/// Allowing it lets a running collector start its FLOW listener, which downloads the
/// official package on first use, and lets the port-53 divert be installed. Forbidding it
/// stops that listener within one poll of the collector and refuses every later open. A
/// port-53 divert that is already installed keeps its handle until it is dropped.
///
/// Closing the last handle does not unload the driver. The `WinDivert` manual
/// (<https://reqrypt.org/windivert-doc.html>, "Driver Installation") says a running
/// driver is uninstalled at the next reboot, or by hand with `sc stop WinDivert`.
pub fn set_windivert_enabled(enabled: bool) {
    ENABLED.store(enabled, Ordering::Release);
}

/// Whether this build can use `WinDivert` at all. The official 2.2.2 package has x86 and
/// x64 drivers only, so every other architecture is built without it, and allowing it
/// there changes nothing.
#[must_use]
pub const fn windivert_supported() -> bool {
    cfg!(target_arch = "x86_64")
}

/// Whether `WinDivert` is allowed for this process. See [`set_windivert_enabled`].
#[must_use]
pub fn windivert_enabled() -> bool {
    ENABLED.load(Ordering::Acquire)
}

/// Refuses while `WinDivert` is forbidden.
///
/// # Errors
///
/// [`DivertError::turned_off`], which lasts: nothing on this side changes it, only
/// [`set_windivert_enabled`].
#[cfg(target_arch = "x86_64")]
pub(crate) fn refuse_unless_enabled() -> Result<(), DivertError> {
    if windivert_enabled() {
        Ok(())
    } else {
        Err(DivertError::turned_off())
    }
}

/// The switch is one per process, and tests run side by side in one. Tests that need
/// `WinDivert` allowed share it; a test that changes it has it alone.
#[cfg(test)]
pub(crate) mod testing {
    use super::set_windivert_enabled;
    #[cfg(target_arch = "x86_64")]
    use std::sync::RwLockReadGuard;
    use std::sync::{PoisonError, RwLock, RwLockWriteGuard};

    static SWITCH: RwLock<()> = RwLock::new(());

    /// Allows `WinDivert` for as long as the guard is held.
    #[cfg(target_arch = "x86_64")]
    pub(crate) fn allowed() -> RwLockReadGuard<'static, ()> {
        let guard = SWITCH.read().unwrap_or_else(PoisonError::into_inner);
        set_windivert_enabled(true);
        guard
    }

    /// The switch, held alone: its holder may change it with [`set_windivert_enabled`].
    /// It starts forbidden and is left forbidden.
    pub(crate) struct Alone {
        _guard: RwLockWriteGuard<'static, ()>,
    }

    /// Takes the switch alone, forbidden.
    pub(crate) fn alone() -> Alone {
        let guard = SWITCH.write().unwrap_or_else(PoisonError::into_inner);
        set_windivert_enabled(false);
        Alone { _guard: guard }
    }

    impl Drop for Alone {
        fn drop(&mut self) {
            set_windivert_enabled(false);
        }
    }
}

#[cfg(all(test, target_arch = "x86_64"))]
mod tests {
    use super::*;

    #[test]
    fn windivert_is_refused_until_it_is_allowed() {
        let _switch = testing::alone();
        assert!(!windivert_enabled());
        let refused = refuse_unless_enabled().expect_err("forbidden");
        assert!(refused.is_turned_off());
        assert!(!refused.passes(), "nothing on this side changes it");

        set_windivert_enabled(true);
        assert!(windivert_enabled());
        refuse_unless_enabled().expect("allowed");

        set_windivert_enabled(false);
        assert!(refuse_unless_enabled().is_err());
    }

    /// Opening the driver is refused before anything is fetched or loaded: the refusal
    /// is the switch's own, not a failed download.
    #[test]
    fn opening_the_driver_is_refused_while_windivert_is_off() {
        let _switch = testing::alone();
        let Err(refused) = crate::windivert_handle::Divert::open("true", 2, 0x0005) else {
            panic!("WinDivert opened while it was turned off");
        };
        assert!(refused.is_turned_off(), "{refused}");
    }
}
