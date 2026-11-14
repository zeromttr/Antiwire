//! Keeps a divert made of kernel rules in effect for as long as its owner holds it.
//!
//! An nftables table or a pf anchor belongs to the host, and any root process can remove or
//! empty it, or switch pf off, without telling the divert. So a [`DivertWatch`] checks the
//! rules every [`DIVERT_CHECK_INTERVAL`], puts them back when they are not in effect, and
//! reports each change to the divert's owner.

use crate::StopFlag;
use netmetrics_core::{DivertEvent, DivertReport};
use std::thread::{self, JoinHandle};
use std::time::Duration;

/// How often a [`DivertWatch`] checks its divert.
///
/// A loss is noticed within this interval plus the time one check takes, and repaired at once,
/// so this bounds how long DNS can bypass the stub after another tool removes the rules. A check
/// runs `nft` once on Linux and `pfctl` six times on macOS. Each is a short-lived process that
/// lists a few rules, so a check costs milliseconds of CPU time every five seconds.
pub const DIVERT_CHECK_INTERVAL: Duration = Duration::from_secs(5);

/// The rules of one installed divert, as its platform checks and installs them.
///
/// The type removes its rules when it drops. [`DivertWatch`] drops it only after the watch
/// thread has ended, so nothing can put the rules back once they are removed.
pub trait DivertRules: Send + 'static {
    /// Returns `Ok` when the rules this divert installed are in place and working.
    ///
    /// # Errors
    ///
    /// Says why they are not in effect, or why that could not be found out.
    fn check(&mut self) -> Result<(), String>;

    /// Installs the rules again, replacing whatever is left of them. `Ok` means the divert is
    /// in effect.
    ///
    /// # Errors
    ///
    /// Says why the rules could not be installed.
    fn install(&mut self) -> Result<(), String>;
}

/// Watches a divert's installed rules on a thread of its own: it checks them every
/// [`DIVERT_CHECK_INTERVAL`], installs them again when they are not in effect, and reports
/// each change as a [`DivertEvent`].
///
/// Dropping it, like [`DivertWatch::stop`], ends the thread and then drops the rules, which
/// removes them.
pub struct DivertWatch<R: DivertRules> {
    stop: StopFlag,
    thread: Option<JoinHandle<R>>,
}

impl<R: DivertRules> DivertWatch<R> {
    /// Watches `rules`, which are installed and in effect, and tells `report` what changes.
    ///
    /// # Errors
    ///
    /// Returns an error when the thread cannot start. The rules are removed then.
    pub fn start(rules: R, report: DivertReport) -> Result<Self, String> {
        Self::start_every(rules, report, DIVERT_CHECK_INTERVAL)
    }

    fn start_every(rules: R, report: DivertReport, interval: Duration) -> Result<Self, String> {
        let stop = StopFlag::new();
        let thread = {
            let stop = stop.clone();
            thread::Builder::new()
                .name("divert-watch".to_owned())
                .spawn(move || watch(rules, &*report, &stop, interval))
                .map_err(|error| format!("the divert watch could not start: {error}"))?
        };
        Ok(Self {
            stop,
            thread: Some(thread),
        })
    }

    /// Stops watching and removes the rules. Later calls do nothing.
    ///
    /// It waits for a check or repair in progress, whose commands are bounded, to finish.
    pub fn stop(&mut self) {
        let Some(thread) = self.thread.take() else {
            return;
        };
        self.stop.stop();
        // The rules come back only from a thread that has ended, so the removal that dropping
        // them runs comes after the last check or repair. A thread that panicked dropped them
        // as it unwound, also after its last one.
        if let Ok(rules) = thread.join() {
            drop(rules);
        }
    }
}

impl<R: DivertRules> Drop for DivertWatch<R> {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Checks `rules` until `stop`, then hands them back.
fn watch<R: DivertRules>(
    mut rules: R,
    report: &dyn Fn(DivertEvent),
    stop: &StopFlag,
    interval: Duration,
) -> R {
    let mut health = Health::InEffect;
    loop {
        stop.wait_timeout(interval);
        if stop.is_stop_requested() {
            return rules;
        }
        health = health.after_check(&mut rules, report, stop);
    }
}

/// What the watch has told the divert's owner so far.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Health {
    /// The divert is in effect; no loss is reported and unrestored.
    InEffect,
    /// A loss is reported, and no failure to restore it.
    Lost,
    /// A loss and a failure to restore it are reported. Later failures are not.
    RestoreFailing,
}

impl Health {
    /// Checks `rules`, installs them again when they are not in effect, and reports what
    /// changed since `self`.
    fn after_check(
        self,
        rules: &mut impl DivertRules,
        report: &dyn Fn(DivertEvent),
        stop: &StopFlag,
    ) -> Self {
        let lost = match rules.check() {
            Ok(()) => {
                // Something else may have put the rules back after a repair failed.
                if self != Self::InEffect {
                    report(DivertEvent::Restored);
                }
                return Self::InEffect;
            }
            Err(lost) => lost,
        };
        let health = if self == Self::InEffect {
            report(DivertEvent::Lost(lost));
            Self::Lost
        } else {
            self
        };
        // Nothing is put back after removal either way, since the rules are removed only after
        // this thread ends. But a repair its owner no longer wants would hold up the stop.
        if stop.is_stop_requested() {
            return health;
        }
        match rules.install() {
            Ok(()) => {
                report(DivertEvent::Restored);
                Self::InEffect
            }
            Err(error) => {
                if health != Self::RestoreFailing {
                    report(DivertEvent::RestoreFailed(error));
                }
                Self::RestoreFailing
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::sync::mpsc;
    use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
    use std::time::Instant;

    /// What happened to the fake host's divert rules.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Step {
        Check,
        Install,
        Remove,
    }

    #[derive(Default)]
    struct HostState {
        in_effect: bool,
        refuses_installs: bool,
        /// While set, an install that has started waits before it finishes.
        holds_installs: bool,
        steps: Vec<Step>,
    }

    /// A host whose divert rules a test can remove, refuse to install, or hold mid-install,
    /// and which records every step taken on them.
    #[derive(Clone, Default)]
    struct Host(Arc<(Mutex<HostState>, Condvar)>);

    impl Host {
        fn lock(&self) -> MutexGuard<'_, HostState> {
            self.0.0.lock().unwrap_or_else(PoisonError::into_inner)
        }

        /// Rules installed and in effect on this host.
        fn installed_rules(&self) -> FakeRules {
            self.lock().in_effect = true;
            FakeRules(self.clone())
        }

        fn set(&self, change: impl FnOnce(&mut HostState)) {
            change(&mut self.lock());
            self.0.1.notify_all();
        }

        fn steps(&self) -> Vec<Step> {
            self.lock().steps.clone()
        }

        fn count(&self, step: Step) -> usize {
            self.lock()
                .steps
                .iter()
                .filter(|taken| **taken == step)
                .count()
        }

        /// Waits until `step` has been taken `times` times; false on a timeout.
        fn wait_for(&self, step: Step, times: usize) -> bool {
            let deadline = Instant::now() + Duration::from_secs(10);
            while self.count(step) < times {
                if Instant::now() >= deadline {
                    return false;
                }
                thread::sleep(Duration::from_millis(1));
            }
            true
        }
    }

    struct FakeRules(Host);

    impl FakeRules {
        fn take(&self, step: Step) -> MutexGuard<'_, HostState> {
            let mut state = self.0.lock();
            state.steps.push(step);
            state
        }
    }

    impl DivertRules for FakeRules {
        fn check(&mut self) -> Result<(), String> {
            if self.take(Step::Check).in_effect {
                Ok(())
            } else {
                Err("the rules are gone".to_owned())
            }
        }

        fn install(&mut self) -> Result<(), String> {
            let mut state = self.take(Step::Install);
            while state.holds_installs {
                state = self
                    .0
                    .0
                    .1
                    .wait(state)
                    .unwrap_or_else(PoisonError::into_inner);
            }
            if state.refuses_installs {
                return Err("the install was refused".to_owned());
            }
            state.in_effect = true;
            Ok(())
        }
    }

    impl Drop for FakeRules {
        fn drop(&mut self) {
            self.take(Step::Remove).in_effect = false;
        }
    }

    /// Runs `checks` checks from `health` with a stop that is never requested, and returns
    /// the health they end in and what they reported.
    fn run_checks(
        rules: &mut FakeRules,
        mut health: Health,
        checks: usize,
    ) -> (Health, Vec<DivertEvent>) {
        let events = RefCell::new(Vec::new());
        let report = |event| events.borrow_mut().push(event);
        let stop = StopFlag::new();
        for _ in 0..checks {
            health = health.after_check(rules, &report, &stop);
        }
        (health, events.into_inner())
    }

    fn lost() -> DivertEvent {
        DivertEvent::Lost("the rules are gone".to_owned())
    }

    fn refused() -> DivertEvent {
        DivertEvent::RestoreFailed("the install was refused".to_owned())
    }

    #[test]
    fn a_divert_in_effect_is_left_alone_and_nothing_is_reported() {
        let host = Host::default();
        let mut rules = host.installed_rules();

        let (health, events) = run_checks(&mut rules, Health::InEffect, 3);

        assert_eq!(health, Health::InEffect);
        assert_eq!(events, []);
        assert_eq!(host.steps(), [Step::Check; 3]);
    }

    #[test]
    fn a_lost_divert_is_put_back_and_the_loss_and_the_restoration_are_each_reported_once() {
        let host = Host::default();
        let mut rules = host.installed_rules();
        host.set(|state| state.in_effect = false);

        let (health, events) = run_checks(&mut rules, Health::InEffect, 3);

        assert_eq!(health, Health::InEffect);
        assert_eq!(events, [lost(), DivertEvent::Restored]);
        assert_eq!(
            host.steps(),
            [Step::Check, Step::Install, Step::Check, Step::Check]
        );
    }

    #[test]
    fn a_divert_that_cannot_be_put_back_reports_the_failure_once_and_keeps_trying() {
        let host = Host::default();
        let mut rules = host.installed_rules();
        host.set(|state| {
            state.in_effect = false;
            state.refuses_installs = true;
        });

        let (health, events) = run_checks(&mut rules, Health::InEffect, 4);

        assert_eq!(health, Health::RestoreFailing);
        assert_eq!(events, [lost(), refused()]);
        assert_eq!(host.count(Step::Install), 4, "every check tries again");
    }

    #[test]
    fn a_restoration_after_failures_is_reported() {
        let host = Host::default();
        let mut rules = host.installed_rules();
        host.set(|state| {
            state.in_effect = false;
            state.refuses_installs = true;
        });
        let (health, _) = run_checks(&mut rules, Health::InEffect, 2);
        host.set(|state| state.refuses_installs = false);

        let (health, events) = run_checks(&mut rules, health, 2);

        assert_eq!(health, Health::InEffect);
        assert_eq!(events, [DivertEvent::Restored]);
    }

    #[test]
    fn rules_another_tool_puts_back_end_the_loss() {
        let host = Host::default();
        let mut rules = host.installed_rules();
        host.set(|state| {
            state.in_effect = false;
            state.refuses_installs = true;
        });
        let (health, _) = run_checks(&mut rules, Health::InEffect, 1);
        host.set(|state| state.in_effect = true);
        let installs = host.count(Step::Install);

        let (health, events) = run_checks(&mut rules, health, 1);

        assert_eq!(health, Health::InEffect);
        assert_eq!(events, [DivertEvent::Restored]);
        assert_eq!(host.count(Step::Install), installs);
    }

    /// A report that hands every event to the test.
    fn reporter() -> (mpsc::Receiver<DivertEvent>, DivertReport) {
        let (sender, events) = mpsc::channel();
        (
            events,
            Box::new(move |event| {
                let _ = sender.send(event);
            }),
        )
    }

    /// Long enough for many checks at the interval these tests use.
    const SEVERAL_INTERVALS: Duration = Duration::from_millis(100);
    const INTERVAL: Duration = Duration::from_millis(5);

    #[test]
    fn the_watch_repairs_a_loss_on_its_own_thread() {
        let host = Host::default();
        let (events, report) = reporter();
        let watch = DivertWatch::start_every(host.installed_rules(), report, INTERVAL)
            .expect("start the watch");

        host.set(|state| state.in_effect = false);

        let timeout = Duration::from_secs(10);
        assert_eq!(events.recv_timeout(timeout), Ok(lost()));
        assert_eq!(events.recv_timeout(timeout), Ok(DivertEvent::Restored));
        drop(watch);
    }

    #[test]
    fn dropping_the_watch_removes_the_rules_once_and_nothing_puts_them_back() {
        let host = Host::default();
        let (_events, report) = reporter();
        let watch = DivertWatch::start_every(host.installed_rules(), report, INTERVAL)
            .expect("start the watch");
        host.set(|state| state.in_effect = false);
        assert!(host.wait_for(Step::Install, 1), "the watch never repaired");

        drop(watch);

        let steps = host.steps();
        assert_eq!(steps.last(), Some(&Step::Remove), "{steps:?}");
        assert_eq!(host.count(Step::Remove), 1);
        thread::sleep(SEVERAL_INTERVALS);
        assert_eq!(
            host.steps(),
            steps,
            "something ran after the rules were removed"
        );
        assert!(!host.lock().in_effect);
    }

    #[test]
    fn a_drop_during_a_repair_waits_for_it_and_then_removes_the_rules() {
        let host = Host::default();
        let (_events, report) = reporter();
        let watch = DivertWatch::start_every(host.installed_rules(), report, INTERVAL)
            .expect("start the watch");
        host.set(|state| {
            state.holds_installs = true;
            state.in_effect = false;
        });
        assert!(host.wait_for(Step::Install, 1), "the watch never repaired");

        let (finished, finishing) = mpsc::channel();
        let owner = thread::spawn(move || {
            drop(watch);
            let _ = finished.send(());
        });
        assert!(
            finishing.recv_timeout(SEVERAL_INTERVALS).is_err(),
            "the drop did not wait for the repair in progress"
        );
        assert_eq!(
            host.count(Step::Remove),
            0,
            "removed while a repair was running"
        );
        host.set(|state| state.holds_installs = false);
        finishing
            .recv_timeout(Duration::from_secs(10))
            .expect("the drop finished once the repair did");
        owner.join().expect("the owner's thread");

        let steps = host.steps();
        assert_eq!(
            steps[steps.len() - 2..],
            [Step::Install, Step::Remove],
            "{steps:?}"
        );
        assert_eq!(host.count(Step::Remove), 1);
        thread::sleep(SEVERAL_INTERVALS);
        assert_eq!(
            host.steps(),
            steps,
            "something ran after the rules were removed"
        );
        assert!(
            !host.lock().in_effect,
            "the repair's rules outlived the drop"
        );
    }
}
