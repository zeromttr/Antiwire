//! Sends outbound DNS that bypasses the adapter stub to `127.0.0.1:53` / `[::1]:53`.
//!
//! The official `WinDivert` package is loaded the same way as the flow-owner listener:
//! downloaded from <https://reqrypt.org/download/WinDivert-2.2.2-A.zip> and checked
//! against that archive's SHA-256. Packets already aimed at the stub, and queries
//! this process sends upstream, are reinjected unchanged.
//!
//! A captured packet waits in the driver until it is reinjected, so a reader
//! that has stopped would hold every bypassing query and every reply the stub
//! sends. A supervisor thread closes the handle as soon as the reader stops,
//! then reopens it with backoff.

use crate::windivert_handle::{Divert, DivertAddress};
use nat::NatTable;
use netmetrics_core::{DivertEvent, DivertReport, LocalEndpoint, Protocol};
use packet::{PacketView, Redirect, owned_by_us, redirect_packet};
use std::io;
use std::panic::{self, AssertUnwindSafe};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, OnceLock, PoisonError};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

mod nat;
mod packet;
#[cfg(test)]
mod tests;

const LAYER_NETWORK: u32 = 0;
pub(super) const OUTBOUND_BIT: u32 = 1 << 17;
pub(super) const LOOPBACK_BIT: u32 = 1 << 18;
pub(super) const DNS_PORT: u16 = 53;
const ENCRYPTED_DNS_PORT: u16 = 853;
/// How long a packet waits for the FLOW listener to name its socket's owner
/// before the socket table is read instead.
pub(super) const FLOW_OWNER_WAIT: Duration = Duration::from_millis(10);
/// Wait before the first attempt to reopen a stopped divert.
const FIRST_RESTART_DELAY: Duration = Duration::from_secs(1);
/// Wait between later attempts.
const RESTART_DELAY: Duration = Duration::from_secs(5);
/// A reader that ran this long before stopping restarts with the first delay.
const STABLE_RUN: Duration = Duration::from_secs(60);

// Queries already on loopback are left alone by `redirect_packet`, so they
// are not captured: re-sending one makes the FLOW listener record `System` as
// the client endpoint's owner, which costs DNS attribution its event-recorded
// owner and forces a socket-table scan per query. Loopback replies from the
// stub are still captured, to undo the NAT for redirected queries.
const FILTER: &str = "(outbound and !loopback and (udp.DstPort == 53 or tcp.DstPort == 53 or udp.DstPort == 853 or tcp.DstPort == 853)) or (outbound and loopback and (udp.SrcPort == 53 or tcp.SrcPort == 53))";

/// Stops capturing port 53 when disabled or dropped.
pub struct ActiveDivert {
    supervisor: Arc<Supervisor>,
    thread: Option<JoinHandle<()>>,
}

impl ActiveDivert {
    /// Closes the `WinDivert` handle and stops redirecting port 53.
    pub fn disable(&mut self) {
        let Some(thread) = self.thread.take() else {
            return;
        };
        {
            let mut state = self.supervisor.lock();
            state.stopping = true;
            if let Some(divert) = &state.current {
                divert.shutdown_recv();
            }
        }
        self.supervisor.changed.notify_all();
        let _ = thread.join();
        // Release reservations even if the disabled handle is retained.
        *active_nat().lock().unwrap_or_else(PoisonError::into_inner) = None;
    }
}

impl Drop for ActiveDivert {
    fn drop(&mut self) {
        self.disable();
    }
}

/// The open handle, shared with [`ActiveDivert::disable`] so it can wake the reader.
#[derive(Default)]
struct Supervisor {
    state: Mutex<SupervisorState>,
    changed: Condvar,
}

#[derive(Default)]
struct SupervisorState {
    stopping: bool,
    current: Option<Arc<Divert>>,
}

impl Supervisor {
    fn lock(&self) -> MutexGuard<'_, SupervisorState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Waits `delay` unless disabled first; returns whether to keep going.
    fn sleep(&self, delay: Duration) -> bool {
        let deadline = Instant::now() + delay;
        let mut state = self.lock();
        while !state.stopping {
            let now = Instant::now();
            if now >= deadline {
                return true;
            }
            state = self
                .changed
                .wait_timeout(state, deadline - now)
                .unwrap_or_else(PoisonError::into_inner)
                .0;
        }
        false
    }

    /// Publishes a reopened handle, or returns `None` once disabled.
    fn publish(&self, divert: Divert) -> Option<Arc<Divert>> {
        let mut state = self.lock();
        if state.stopping {
            return None;
        }
        let divert = Arc::new(divert);
        state.current = Some(Arc::clone(&divert));
        Some(divert)
    }
}

/// Opens the official driver and redirects bypassed DNS at the stub.
///
/// `report` hears when the reader stops, each time it could not reopen, and
/// when it reopens; between a stop and a reopen, bypassing queries reach their
/// resolvers unredirected.
///
/// # Errors
///
/// Returns an error when the official package cannot be loaded or `WinDivertOpen` fails.
pub fn install(report: DivertReport) -> Result<ActiveDivert, String> {
    let mut active = active_nat().lock().unwrap_or_else(PoisonError::into_inner);
    if active.is_some() {
        return Err("DNS divert is already installed".to_owned());
    }
    let supervisor = Arc::new(Supervisor::default());
    let divert = Divert::open(FILTER, LAYER_NETWORK, 0)?;
    let divert = supervisor
        .publish(divert)
        .ok_or_else(|| "DNS divert was disabled while starting".to_owned())?;
    let thread = {
        let supervisor = Arc::clone(&supervisor);
        std::thread::Builder::new()
            .name("windivert-dns".to_owned())
            .spawn(move || supervise(&supervisor, divert, &*report))
            .map_err(|error| error.to_string())?
    };
    // Publish only after startup succeeds; retain the lock across startup so a
    // competing install cannot replace the table used by the running redirect.
    *active = Some(NatTable::default());
    Ok(ActiveDivert {
        supervisor,
        thread: Some(thread),
    })
}

fn active_nat() -> &'static Mutex<Option<NatTable>> {
    static ACTIVE: OnceLock<Mutex<Option<NatTable>>> = OnceLock::new();
    ACTIVE.get_or_init(|| Mutex::new(None))
}

/// Original local endpoint of a query redirected to the DNS stub.
///
/// Returns `None` for ordinary stub clients, expired mappings, or a stopped
/// divert. Synthetic endpoints are reserved while mapped, so a real client
/// cannot accidentally inherit another socket's origin. Look up ownership of
/// the returned endpoint while the client is still waiting for its response.
#[must_use]
pub fn original_endpoint(protocol: Protocol, endpoint: LocalEndpoint) -> Option<LocalEndpoint> {
    if !endpoint.address.is_loopback() {
        return None;
    }
    active_nat()
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .as_mut()?
        .original_endpoint(protocol, endpoint, Instant::now())
}

/// Runs the reader, closing its handle whenever it stops and reopening it
/// until disabled.
fn supervise(supervisor: &Supervisor, mut divert: Arc<Divert>, report: &dyn Fn(DivertEvent)) {
    let mut failures = 0_u32;
    loop {
        let started = Instant::now();
        let ended =
            panic::catch_unwind(AssertUnwindSafe(|| divert_loop(&divert))).unwrap_or_else(|_| {
                // A panic can stop mid-update, so the mappings start afresh.
                if let Some(nat) = active_nat()
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .as_mut()
                {
                    *nat = NatTable::default();
                }
                "the receive loop panicked".to_owned()
            });
        let stopping = {
            let mut state = supervisor.lock();
            state.current = None;
            state.stopping
        };
        // Closing the handle releases what the driver holds for this reader.
        drop(divert);
        if stopping {
            return;
        }
        if started.elapsed() >= STABLE_RUN {
            failures = 0;
        }
        report(DivertEvent::Lost(format!(
            "the packet reader stopped: {ended}"
        )));
        divert = loop {
            let delay = if failures == 0 {
                FIRST_RESTART_DELAY
            } else {
                RESTART_DELAY
            };
            failures = failures.saturating_add(1);
            if !supervisor.sleep(delay) {
                return;
            }
            match Divert::open(FILTER, LAYER_NETWORK, 0) {
                Ok(reopened) => match supervisor.publish(reopened) {
                    Some(reopened) => break reopened,
                    None => return,
                },
                Err(error) => report(DivertEvent::RestoreFailed(format!(
                    "WinDivert could not reopen: {error}"
                ))),
            }
        };
        report(DivertEvent::Restored);
    }
}

/// Returns why the reader stopped.
fn divert_loop(divert: &Divert) -> String {
    let mut buffer = vec![0u8; 64 * 1024];
    let our_pid = std::process::id();
    loop {
        let mut address = DivertAddress::zeroed();
        let Some(received) = divert.recv(&mut buffer, &mut address) else {
            return format!("receive failed: {}", io::Error::last_os_error());
        };
        let received_at = Instant::now();
        let Some(packet) = buffer.get_mut(..received) else {
            continue;
        };
        match handle_packet(packet, &mut address, our_pid, received_at) {
            Verdict::Reinject => {
                let _ = divert.send(packet, &address);
            }
            // The rewrite leaves every checksum stale. If WinDivert cannot
            // recompute them, the packet is dropped rather than sent broken.
            Verdict::Rewritten => {
                if divert.calc_checksums(packet, &mut address) {
                    let _ = divert.send(packet, &address);
                }
            }
            // Not reinjected: WinDivert drops the packet.
            Verdict::Drop => {}
            Verdict::Disabled => return "disabled".to_owned(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Verdict {
    /// Send on as received.
    Reinject,
    /// Send on with its addresses or ports rewritten.
    Rewritten,
    Drop,
    Disabled,
}

/// Decides one captured packet, rewriting it when it is redirected.
///
/// Ownership is settled before the NAT lock is taken: it can wait on the FLOW
/// listener or read the socket table, and DNS attribution takes the same lock.
fn handle_packet(
    packet: &mut [u8],
    address: &mut DivertAddress,
    our_pid: u32,
    received_at: Instant,
) -> Verdict {
    let outbound = address.layer_event & OUTBOUND_BIT != 0;
    let loopback = address.layer_event & LOOPBACK_BIT != 0;
    let view = PacketView::parse(packet);
    if outbound && !loopback {
        // The filter only captures outbound DNS here, so a packet that cannot
        // be read is DNS that cannot be redirected. Sending it on unchanged
        // would let a malformed or fragmented query skip filtering.
        let Some(view) = view else {
            return Verdict::Drop;
        };
        let owner = owned_by_us(&view, our_pid, received_at);
        if view.dst_port == ENCRYPTED_DNS_PORT {
            // Foreign DoT/DoQ cannot be redirected to the stub, so it is
            // dropped. A failed owner lookup keeps the daemon's own upstream.
            return if owner == Some(false) {
                Verdict::Drop
            } else {
                Verdict::Reinject
            };
        }
        return with_nat(|nat| {
            redirect_packet(
                packet,
                &view,
                address,
                nat,
                owner == Some(true),
                received_at,
            )
        });
    }
    // A reply from the stub, which needs the NAT of a redirected query undone.
    let Some(view) = view else {
        return Verdict::Reinject;
    };
    with_nat(|nat| redirect_packet(packet, &view, address, nat, false, received_at))
}

fn with_nat(redirect: impl FnOnce(&mut NatTable) -> Redirect) -> Verdict {
    let mut active = active_nat().lock().unwrap_or_else(PoisonError::into_inner);
    let Some(nat) = active.as_mut() else {
        return Verdict::Disabled;
    };
    match redirect(nat) {
        Redirect::Unchanged => Verdict::Reinject,
        Redirect::Rewritten => Verdict::Rewritten,
        Redirect::Unredirectable => Verdict::Drop,
    }
}
