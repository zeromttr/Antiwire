//! Connect-time flow owners from the official `WinDivert` 2.2.2 package.
//!
//! The DLL and driver are downloaded from <https://reqrypt.org/download/WinDivert-2.2.2-A.zip>
//! and checked against the hashes of that official archive. No third-party Rust binding is used.
//! The listener opens `WINDIVERT_LAYER_FLOW` in sniff and receive-only mode, so it records the
//! process that established a TCP or UDP flow without diverting packets. Each owner goes into the
//! collector's 5-tuple cache and, with the kernel's event time, into the endpoint owner feed that
//! DNS attribution reads (see [`crate::endpoint_owner`]).

use netmetrics_core::unix_now_ms;
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use netmetrics_core::{FlowKey, LocalEndpoint, Protocol};
use netmetrics_sys::{BackendEvent, EventSink};
use windows::Win32::System::Performance::{QueryPerformanceCounter, QueryPerformanceFrequency};

use crate::divert_error::DivertError;
use crate::endpoint_owner::{self, EndpointOwnerFeed};
use crate::flow_owner::{FlowOwner, FlowOwnerCache};
use crate::process_image::resolve_live_process_image;
use crate::windivert_handle::{Divert, DivertAddress};
use netmetrics_core::canonicalize_ip;

#[cfg(test)]
mod tests;

const LAYER_FLOW: u32 = 2;
const EVENT_FLOW_ESTABLISHED: u32 = 1;
const EVENT_FLOW_DELETED: u32 = 2;
const FLAG_SNIFF: u64 = 0x0001;
const FLAG_RECV_ONLY: u64 = 0x0004;
const PROTOCOL_TCP: u8 = 6;
const PROTOCOL_UDP: u8 = 17;

/// FLOW-layer listener. Dropping it unblocks the receive thread and closes the handle.
pub(crate) struct FlowListener {
    divert: Arc<Divert>,
    feed: Arc<EndpointOwnerFeed>,
    thread: Option<JoinHandle<()>>,
}

impl FlowListener {
    /// Whether the receive thread has exited, after which no flow is recorded.
    pub(crate) fn is_finished(&self) -> bool {
        self.thread.as_ref().is_none_or(JoinHandle::is_finished)
    }
}

impl Drop for FlowListener {
    fn drop(&mut self) {
        self.divert.shutdown_recv();
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
        endpoint_owner::withdraw(&self.feed);
    }
}

/// Downloads the official package when needed, then records flow owners into `cache`.
///
/// # Errors
///
/// Says why the listener could not start, and whether a later start could. While
/// `WinDivert` is turned off it refuses before anything is downloaded.
pub(crate) fn start(
    cache: Arc<Mutex<FlowOwnerCache>>,
    sink: EventSink,
) -> Result<FlowListener, DivertError> {
    // Sniff plus receive-only is the FLOW-layer pair from the WinDivert 2.2 manual; it
    // does not drop or inject packets.
    let divert = Arc::new(Divert::open(
        "true",
        LAYER_FLOW,
        FLAG_SNIFF | FLAG_RECV_ONLY,
    )?);
    let receiver = Arc::clone(&divert);
    let feed = Arc::new(EndpointOwnerFeed::new(crate::endpoint_owner::trusted_owner));
    let listener_feed = Arc::clone(&feed);
    let thread = std::thread::Builder::new()
        .name("windivert-flow".to_owned())
        .spawn(move || recv_loop(&receiver, &cache, &listener_feed, &sink))
        .map_err(|error| DivertError::passing(error.to_string()))?;
    endpoint_owner::publish(&feed);
    Ok(FlowListener {
        divert,
        feed,
        thread: Some(thread),
    })
}

fn recv_loop(
    divert: &Divert,
    cache: &Mutex<FlowOwnerCache>,
    feed: &EndpointOwnerFeed,
    sink: &EventSink,
) {
    let clock = KernelClock::new();
    loop {
        let mut address = DivertAddress::zeroed();
        feed.receiving(Instant::now());
        // The FLOW layer carries no packet, only the address.
        if divert.recv(&mut [], &mut address).is_none() {
            break;
        }
        feed.processing();
        let now = Instant::now();
        record_event(
            cache,
            feed,
            sink,
            &address,
            clock.instant_of(address.timestamp, now),
            now,
        );
    }
    // A reader that stopped records nothing more, so its answers are no longer current.
    feed.close();
}

/// Records one FLOW event into `cache` and `feed`.
fn record_event(
    cache: &Mutex<FlowOwnerCache>,
    feed: &EndpointOwnerFeed,
    sink: &EventSink,
    address: &DivertAddress,
    event_at: Instant,
    now: Instant,
) {
    let established = established_owner(address)
        .filter(|&(key, pid)| !is_reinjection_echo(&mut lock_cache(cache), &key, pid, now));
    // Opening the process is slow; do it before taking the lock that ETW
    // decoding shares.
    let owner = established.map(|(_, pid)| flow_owner(pid));
    apply_event(&mut lock_cache(cache), sink, address, now, owner);
    feed.received(
        event_at,
        established.map(|(key, pid)| {
            let local = LocalEndpoint {
                address: key.local_addr,
                port: key.local_port,
            };
            (key.protocol, local, pid)
        }),
        now,
    );
}

/// Whether a flow `pid` established on `key` is the echo of a packet the DNS
/// divert reinjected.
///
/// Reinjecting a packet makes the kernel report a second flow on the same
/// 5-tuple, owned by `System`. Recorded, it would replace the real owner: the
/// divert would then take the daemon's own `DoT`/`DoQ` socket for a foreign one
/// and drop its packets, and the flow's bytes would be counted for `System`.
/// Two processes cannot hold one 5-tuple at once, so a `System` flow on a
/// tuple another process already owns can only be that echo.
fn is_reinjection_echo(cache: &mut FlowOwnerCache, key: &FlowKey, pid: u32, now: Instant) -> bool {
    pid == endpoint_owner::SYSTEM_PID
        && cache
            .lookup(key, now)
            .is_some_and(|owner| owner.pid != endpoint_owner::SYSTEM_PID)
}

/// Key and owner of a FLOW event that established a flow.
fn established_owner(address: &DivertAddress) -> Option<(FlowKey, u32)> {
    let event = (address.layer_event >> 8) & 0xff;
    let pid = process_id(address);
    if event != EVENT_FLOW_ESTABLISHED || pid == 0 {
        return None;
    }
    Some((flow_key_from_address(address)?, pid))
}

/// Owner of a flow `pid` just established, with its image while it is alive.
fn flow_owner(pid: u32) -> FlowOwner {
    let image = resolve_live_process_image(pid);
    let (executable, name, start_ts) = image.map_or_else(
        || (String::new(), String::new(), 0),
        |image| {
            let name = image
                .path
                .rsplit(['\\', '/'])
                .next()
                .unwrap_or_default()
                .to_owned();
            (image.path, name, image.start_unix_ms)
        },
    );
    FlowOwner {
        pid,
        executable,
        name,
        start_ts,
    }
}

/// `owner` is the established flow's owner, resolved by [`flow_owner`].
fn apply_event(
    cache: &mut FlowOwnerCache,
    sink: &EventSink,
    address: &DivertAddress,
    now: Instant,
    owner: Option<FlowOwner>,
) {
    let event = (address.layer_event >> 8) & 0xff;
    let Some(key) = flow_key_from_address(address) else {
        return;
    };
    match event {
        EVENT_FLOW_ESTABLISHED => {
            // An owner the endpoint feed would not trust is not kept as a
            // flow's owner either. A `System` flow on loopback is the echo of
            // a packet the DNS divert reinjected, and [`is_reinjection_echo`]
            // catches it only when the real owner was recorded first.
            let local = LocalEndpoint {
                address: key.local_addr,
                port: key.local_port,
            };
            if let Some(owner) =
                owner.filter(|owner| endpoint_owner::trusted_owner(local, owner.pid) != 0)
            {
                cache.insert(key, owner, now);
            }
        }
        EVENT_FLOW_DELETED => {
            cache.retain_after_delete(&key, now);
            // UDP flow deletion is the WFP idle timeout, not the socket closing.
            if key.protocol == Protocol::Tcp {
                sink.emit(BackendEvent::Closed {
                    key,
                    pid: process_id(address),
                    timestamp: unix_now_ms(),
                });
            }
        }
        _ => {}
    }
}

/// Converts `WinDivert` timestamps, which are `QueryPerformanceCounter` ticks,
/// to `Instant`s by their distance from the present.
struct KernelClock {
    ticks_per_second: i64,
}

impl KernelClock {
    fn new() -> Self {
        let mut frequency = 0;
        // SAFETY: the out-pointer is a live local. The call cannot fail on
        // supported Windows; a zero frequency is handled by `instant_of_ticks`.
        let _ = unsafe { QueryPerformanceFrequency(&raw mut frequency) };
        Self {
            ticks_per_second: frequency,
        }
    }

    fn instant_of(&self, timestamp: i64, now: Instant) -> Instant {
        let mut counter = 0;
        // SAFETY: as above.
        let _ = unsafe { QueryPerformanceCounter(&raw mut counter) };
        instant_of_ticks(timestamp, counter, self.ticks_per_second, now)
    }
}

/// The `Instant` that `timestamp` ticks names, given that `counter` ticks is
/// `now`. A timestamp from the future, or an unknown frequency, is `now`.
fn instant_of_ticks(timestamp: i64, counter: i64, ticks_per_second: i64, now: Instant) -> Instant {
    if ticks_per_second <= 0 {
        return now;
    }
    let ticks = i128::from(counter.saturating_sub(timestamp).max(0));
    let nanos = ticks * 1_000_000_000 / i128::from(ticks_per_second);
    let age = Duration::from_nanos(u64::try_from(nanos).unwrap_or(u64::MAX));
    now.checked_sub(age).unwrap_or(now)
}

fn process_id(address: &DivertAddress) -> u32 {
    u32::from_ne_bytes(copy_array(&address.data[16..20]))
}

/// Builds a flow key from a FLOW-layer address. IPv4 values arrive as mapped IPv6.
fn flow_key_from_address(address: &DivertAddress) -> Option<FlowKey> {
    let protocol = match address.data[56] {
        PROTOCOL_TCP => Protocol::Tcp,
        PROTOCOL_UDP => Protocol::Udp,
        _ => return None,
    };
    let local_addr = address_from_words(&read_words(&address.data[20..36]))?;
    let remote_addr = address_from_words(&read_words(&address.data[36..52]))?;
    let local_port = u16::from_ne_bytes(copy_array(&address.data[52..54]));
    let remote_port = u16::from_ne_bytes(copy_array(&address.data[54..56]));
    if local_port == 0 || remote_port == 0 {
        return None;
    }
    Some(FlowKey {
        protocol,
        local_addr: canonicalize_ip(local_addr),
        local_port,
        remote_addr: canonicalize_ip(remote_addr),
        remote_port,
    })
}

fn read_words(bytes: &[u8]) -> [u32; 4] {
    let mut words = [0u32; 4];
    for (index, word) in words.iter_mut().enumerate() {
        let start = index * 4;
        *word = u32::from_ne_bytes(copy_array(&bytes[start..start + 4]));
    }
    words
}

fn copy_array<const N: usize>(bytes: &[u8]) -> [u8; N] {
    let mut array = [0u8; N];
    array.copy_from_slice(bytes);
    array
}

/// `WinDivert` stores a FLOW address as one host-order 128-bit value split
/// into native `UINT32` words, least significant first, so `127.0.0.1` is
/// `[0x7f00_0001, 0x0000_ffff, 0, 0]`.
fn address_from_words(words: &[u32; 4]) -> Option<std::net::IpAddr> {
    let value = words
        .iter()
        .rev()
        .fold(0u128, |value, word| (value << 32) | u128::from(*word));
    if value == 0 {
        return None;
    }
    let address = std::net::Ipv6Addr::from(value);
    Some(
        address
            .to_ipv4_mapped()
            .map_or(std::net::IpAddr::V6(address), std::net::IpAddr::V4),
    )
}

fn lock_cache(cache: &Mutex<FlowOwnerCache>) -> std::sync::MutexGuard<'_, FlowOwnerCache> {
    cache
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}
