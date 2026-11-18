//! The port 53 divert a running resolver holds, installed off the resolver's own start.
//!
//! Installing it can take long: on Windows the first install downloads the `WinDivert`
//! package, which waits on the network. So the install runs on a blocking thread, and the
//! resolver's start waits for it only briefly. An install that outlasts the wait carries
//! on, and says how it ended itself.
//!
//! The divert is one per host: a table, an anchor or a driver filter that every install
//! names alike. So installs run one after another, and one that ends after the divert
//! was removed takes out what it installed.

use std::sync::Arc;
use std::time::Duration;

use netmetrics::dns_divert::DivertEvent;
use parking_lot::Mutex;
use tokio::sync::oneshot;
use tokio::task::JoinHandle;
use tracing::info;

/// Hears what becomes of the divert once it is installed.
pub(crate) type DivertReport = Box<dyn Fn(DivertEvent) + Send>;

/// An installed divert. It is kept only for its `Drop`, which removes it from the host.
pub(crate) type InstalledDivert = Box<dyn Send>;

/// Installs the divert on the host. May block for as long as a download takes.
pub(crate) type InstallDivert =
    Arc<dyn Fn(DivertReport) -> Result<InstalledDivert, String> + Send + Sync>;

/// How an install had ended when the wait for it was over.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum DivertInstall {
    Installed,
    /// Not installed, and why.
    Failed(String),
    /// Still under way. A failure is told to whoever asked for the install, later.
    Pending,
}

impl From<Result<(), String>> for DivertInstall {
    fn from(result: Result<(), String>) -> Self {
        match result {
            Ok(()) => Self::Installed,
            Err(detail) => Self::Failed(detail),
        }
    }
}

#[derive(Default)]
struct Slot {
    /// Counts removals. An install that ends after one is no longer wanted.
    removals: u64,
    installed: Option<InstalledDivert>,
}

/// The port 53 divert, installed or not, and the installs that bring it up.
pub(crate) struct Port53Divert {
    install: InstallDivert,
    slot: Arc<Mutex<Slot>>,
    /// The install asked for last. The next one waits for it to end.
    installing: Option<JoinHandle<()>>,
}

impl Port53Divert {
    /// The divert of this host, through `netmetrics`.
    pub(crate) fn on_host() -> Self {
        Self::installing_with(Arc::new(|report| {
            let divert = netmetrics::dns_divert::start(report)?;
            Ok(Box::new(divert) as InstalledDivert)
        }))
    }

    /// A divert that `install` installs.
    pub(crate) fn installing_with(install: InstallDivert) -> Self {
        Self {
            install,
            slot: Arc::new(Mutex::new(Slot::default())),
            installing: None,
        }
    }

    /// Installs the divert off this task, and waits up to `wait` for it.
    ///
    /// An install that takes longer carries on and is kept once it succeeds. If it
    /// fails, `late_failure` hears why; it hears nothing of an install the wait saw the
    /// end of, nor of one that [`remove`](Self::remove) overtook.
    pub(crate) async fn install(
        &mut self,
        report: DivertReport,
        wait: Duration,
        late_failure: impl FnOnce(String) + Send + 'static,
    ) -> DivertInstall {
        let wanted = self.slot.lock().removals;
        let (install, slot) = (Arc::clone(&self.install), Arc::clone(&self.slot));
        let previous = self.installing.take();
        let (ended, mut outcome) = oneshot::channel();
        self.installing = Some(tokio::spawn(async move {
            if let Some(previous) = previous {
                // However it ended, it is over, which is all the next install needs.
                let _ = previous.await;
            }
            let installing = tokio::task::spawn_blocking(move || {
                install_if_wanted(&install, &slot, wanted, report)
            });
            let result = match installing.await {
                Ok(Some(result)) => result,
                Ok(None) => return,
                Err(error) => Err(format!("the install did not finish: {error}")),
            };
            if let Err(unheard) = ended.send(result) {
                match unheard {
                    Ok(()) => info!(
                        "outbound port 53 that bypasses the stub is diverted to it, after a slow install"
                    ),
                    Err(detail) => late_failure(detail),
                }
            }
        }));
        match tokio::time::timeout(wait, &mut outcome).await {
            Ok(Ok(result)) => result.into(),
            Ok(Err(_)) => DivertInstall::Failed("the install was abandoned".to_owned()),
            Err(_) => {
                // Closed first, so that a result which arrives from now on goes to
                // `late_failure`, and one that arrived just before is read here.
                outcome.close();
                outcome
                    .try_recv()
                    .map_or(DivertInstall::Pending, DivertInstall::from)
            }
        }
    }

    /// Removes the divert. An install still under way removes its own when it ends.
    pub(crate) fn remove(&mut self) {
        let installed = {
            let mut slot = self.slot.lock();
            slot.removals += 1;
            slot.installed.take()
        };
        // Outside the lock: removing it from the host can take a while.
        drop(installed);
    }

    #[cfg(test)]
    pub(crate) fn is_installed(&self) -> bool {
        self.slot.lock().installed.is_some()
    }
}

/// Runs `install` and keeps its divert in `slot`, unless the divert has been removed since
/// `wanted` was read. Returns `None` then, with nothing left installed.
fn install_if_wanted(
    install: &InstallDivert,
    slot: &Mutex<Slot>,
    wanted: u64,
    report: DivertReport,
) -> Option<Result<(), String>> {
    if slot.lock().removals != wanted {
        return None;
    }
    let installed = install(report);
    let mut held = slot.lock();
    if held.removals != wanted {
        drop(held);
        // Removed while it was being installed: dropping it takes it out again.
        drop(installed);
        return None;
    }
    Some(installed.map(|divert| held.installed = Some(divert)))
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::mpsc::{self, Receiver, Sender};
    use std::time::Instant;

    use super::*;

    /// Long enough for an install that does not wait on anything.
    const PLENTY: Duration = Duration::from_secs(10);
    /// Short enough to give up on an install that is held back.
    const BRIEF: Duration = Duration::from_millis(20);

    /// Stands in for an installed divert, and records that it was removed.
    struct Fake(Arc<AtomicBool>);

    impl Drop for Fake {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }

    fn report() -> DivertReport {
        Box::new(|_| ())
    }

    /// An install that succeeds once `gate` lets it through, counting its calls.
    fn held_back(
        gate: Receiver<()>,
        calls: &Arc<AtomicUsize>,
        removed: &Arc<AtomicBool>,
    ) -> InstallDivert {
        let (gate, calls, removed) = (Mutex::new(gate), Arc::clone(calls), Arc::clone(removed));
        Arc::new(move |_| {
            calls.fetch_add(1, Ordering::SeqCst);
            gate.lock().recv().expect("gate");
            Ok(Box::new(Fake(Arc::clone(&removed))) as InstalledDivert)
        })
    }

    async fn wait_until(what: &str, mut holds: impl FnMut() -> bool) {
        let deadline = Instant::now() + PLENTY;
        while !holds() {
            assert!(Instant::now() < deadline, "{what}");
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }

    fn never(_: String) {
        panic!("the wait saw this install end");
    }

    #[tokio::test]
    async fn an_install_that_ends_in_time_is_held_until_it_is_removed() {
        let removed = Arc::new(AtomicBool::new(false));
        let fake = Arc::clone(&removed);
        let mut divert = Port53Divert::installing_with(Arc::new(move |_| {
            Ok(Box::new(Fake(Arc::clone(&fake))) as InstalledDivert)
        }));

        let outcome = divert.install(report(), PLENTY, never).await;

        assert_eq!(outcome, DivertInstall::Installed);
        assert!(divert.is_installed());
        assert!(!removed.load(Ordering::SeqCst));

        divert.remove();
        assert!(removed.load(Ordering::SeqCst));
        assert!(!divert.is_installed());
    }

    #[tokio::test]
    async fn an_install_that_fails_in_time_tells_only_the_one_waiting() {
        let mut divert =
            Port53Divert::installing_with(Arc::new(|_| Err("no permission".to_owned())));

        let outcome = divert.install(report(), PLENTY, never).await;

        assert_eq!(outcome, DivertInstall::Failed("no permission".to_owned()));
        assert!(!divert.is_installed());
    }

    #[tokio::test]
    async fn a_slow_install_is_not_waited_for_and_is_kept_once_it_succeeds() {
        let (open, gate) = mpsc::channel();
        let calls = Arc::new(AtomicUsize::new(0));
        let removed = Arc::new(AtomicBool::new(false));
        let mut divert = Port53Divert::installing_with(held_back(gate, &calls, &removed));

        let outcome = divert.install(report(), BRIEF, never).await;
        assert_eq!(outcome, DivertInstall::Pending);
        assert!(!divert.is_installed());

        open.send(()).expect("open the gate");
        wait_until("the slow install was not kept", || divert.is_installed()).await;
        assert!(!removed.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn a_slow_install_that_fails_says_so_itself() {
        let (open, gate): (Sender<()>, Receiver<()>) = mpsc::channel();
        let gate = Mutex::new(gate);
        let mut divert = Port53Divert::installing_with(Arc::new(move |_| {
            gate.lock().recv().expect("gate");
            Err("the download failed".to_owned())
        }));
        let (told, failures) = mpsc::channel();

        let outcome = divert
            .install(report(), BRIEF, move |detail| {
                told.send(detail).expect("tell");
            })
            .await;
        assert_eq!(outcome, DivertInstall::Pending);

        open.send(()).expect("open the gate");
        let failure = tokio::task::spawn_blocking(move || failures.recv_timeout(PLENTY))
            .await
            .expect("join");
        assert_eq!(failure.as_deref(), Ok("the download failed"));
        assert!(!divert.is_installed());
    }

    #[tokio::test]
    async fn a_slow_install_overtaken_by_a_removal_takes_out_what_it_installed() {
        let (open, gate) = mpsc::channel();
        let calls = Arc::new(AtomicUsize::new(0));
        let removed = Arc::new(AtomicBool::new(false));
        let mut divert = Port53Divert::installing_with(held_back(gate, &calls, &removed));

        assert_eq!(
            divert.install(report(), BRIEF, never).await,
            DivertInstall::Pending
        );
        divert.remove();
        open.send(()).expect("open the gate");

        wait_until("the overtaken install left its divert in place", || {
            removed.load(Ordering::SeqCst)
        })
        .await;
        assert!(!divert.is_installed());
    }

    /// Two installs at once would each replace the other's divert, and the one no longer
    /// wanted would then take the wanted one out.
    #[tokio::test]
    async fn the_next_install_waits_for_the_one_under_way() {
        let (open, gate) = mpsc::channel();
        let calls = Arc::new(AtomicUsize::new(0));
        let removed = Arc::new(AtomicBool::new(false));
        let mut divert = Port53Divert::installing_with(held_back(gate, &calls, &removed));

        assert_eq!(
            divert.install(report(), BRIEF, never).await,
            DivertInstall::Pending
        );
        divert.remove();
        assert_eq!(
            divert.install(report(), BRIEF, never).await,
            DivertInstall::Pending
        );
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "the second install started while the first was under way"
        );

        open.send(()).expect("let the first through");
        wait_until("the second install never started", || {
            calls.load(Ordering::SeqCst) == 2
        })
        .await;
        assert!(removed.load(Ordering::SeqCst), "the first was overtaken");
        removed.store(false, Ordering::SeqCst);

        open.send(()).expect("let the second through");
        wait_until("the second install was not kept", || divert.is_installed()).await;
        assert!(!removed.load(Ordering::SeqCst));
    }
}
