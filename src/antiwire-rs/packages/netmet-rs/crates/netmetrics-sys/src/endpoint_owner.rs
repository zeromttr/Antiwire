//! Lifetime and timestamp conversion for native endpoint ownership sources.

use netmetrics_core::endpoint_owner::{EndpointOwnerFeed, publish, withdraw};
use netmetrics_core::{FlowKey, LocalEndpoint};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Publishes one native reader and removes it on every exit path.
#[derive(Debug)]
pub struct EndpointOwnerSource {
    feed: Arc<EndpointOwnerFeed>,
}

impl Default for EndpointOwnerSource {
    fn default() -> Self {
        let feed = Arc::new(EndpointOwnerFeed::default());
        publish(&feed);
        Self { feed }
    }
}

impl EndpointOwnerSource {
    /// Call before reading or processing a batch of native events.
    pub fn processing(&self) {
        self.feed.processing();
    }

    /// Call only after draining the native buffer, before waiting for more data.
    pub fn drained(&self) {
        self.feed.receiving(Instant::now());
    }

    /// Records an owner at the native event time, before any slow enrichment.
    ///
    /// Events must arrive in time order, since each one is also proof of
    /// progress; use [`Self::observe`] for any that may not. PID 0 names no
    /// process, so it advances progress without replacing a known owner.
    pub fn record(&self, key: FlowKey, pid: u32, event_at: Instant) {
        let established = (pid != 0).then(|| (key.protocol, local_endpoint(key), pid));
        self.feed.received(event_at, established, Instant::now());
    }

    /// Adds an owner to history from an event that may arrive out of time
    /// order. It never lets a lookup stop waiting. PID 0 is ignored.
    pub fn observe(&self, key: FlowKey, pid: u32, event_at: Instant) {
        if pid != 0 {
            self.feed.observed(
                event_at,
                key.protocol,
                local_endpoint(key),
                pid,
                Instant::now(),
            );
        }
    }
}

impl Drop for EndpointOwnerSource {
    fn drop(&mut self) {
        withdraw(&self.feed);
    }
}

fn local_endpoint(key: FlowKey) -> LocalEndpoint {
    LocalEndpoint {
        address: key.local_addr,
        port: key.local_port,
    }
}

/// Maps a native timestamp to the monotonic lookup clock using a nearby sample.
/// Future or invalid timestamps do not establish historical ownership.
pub fn instant_from_sample(
    timestamp: Duration,
    sampled: Duration,
    now: Instant,
) -> Option<Instant> {
    if timestamp.is_zero() {
        return None;
    }
    now.checked_sub(sampled.checked_sub(timestamp)?)
}

/// Converts Linux `bpf_ktime_get_ns` (`CLOCK_MONOTONIC`) to the lookup clock.
#[cfg(target_os = "linux")]
pub fn monotonic_event_time(nanos: u64) -> Option<Instant> {
    let mut sample = std::mem::MaybeUninit::<libc::timespec>::uninit();
    let now = Instant::now();
    // SAFETY: clock_gettime initializes the pointed-to timespec on success.
    if unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, sample.as_mut_ptr()) } != 0 {
        return None;
    }
    // SAFETY: the successful call initialized the complete timespec.
    let sample = unsafe { sample.assume_init() };
    let sampled = Duration::new(
        u64::try_from(sample.tv_sec).ok()?,
        u32::try_from(sample.tv_nsec).ok()?,
    );
    instant_from_sample(Duration::from_nanos(nanos), sampled, now)
}

/// Converts a BPF capture's Unix timestamp to the monotonic lookup clock.
#[cfg(target_os = "macos")]
pub fn realtime_event_time(timestamp: Duration) -> Option<Instant> {
    let now = Instant::now();
    let sampled = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?;
    instant_from_sample(timestamp, sampled, now)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn delayed_events_keep_capture_time_and_invalid_times_are_rejected() {
        let now = Instant::now();
        let sample = Duration::from_secs(100);
        assert_eq!(
            instant_from_sample(Duration::from_secs(98), sample, now),
            now.checked_sub(Duration::from_secs(2))
        );
        assert_eq!(
            instant_from_sample(sample + Duration::from_nanos(1), sample, now),
            None
        );
        assert_eq!(instant_from_sample(Duration::ZERO, sample, now), None);
    }

    /// PKTAP and kernel-context records can lack a PID. That is no evidence
    /// the socket changed hands, so the known owner must still answer.
    #[test]
    fn an_event_without_a_pid_keeps_the_known_owner() {
        let source = EndpointOwnerSource::default();
        let key = FlowKey {
            protocol: netmetrics_core::Protocol::Udp,
            local_addr: "127.0.0.1".parse().unwrap(),
            local_port: 50_000,
            remote_addr: "127.0.0.1".parse().unwrap(),
            remote_port: 53,
        };
        let now = Instant::now();
        let first = now.checked_sub(Duration::from_millis(20)).unwrap();
        let later = now.checked_sub(Duration::from_millis(10)).unwrap();
        source.record(key, 42, first);
        source.record(key, 0, later);
        source.observe(key, 0, later);
        source.drained();
        assert_eq!(
            netmetrics_core::endpoint_owner::endpoint_owner_at(
                key.protocol,
                local_endpoint(key),
                now,
                Duration::from_secs(1),
            ),
            netmetrics_core::EndpointOwner::Resolved(42)
        );
    }
}
