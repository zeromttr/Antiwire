use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use antiwire_capture::{FlowTuple, Transport};
use antiwire_events::{ActiveApplicationSample, ActiveConnectionCounter, ActiveConnectionSample};
use netmetrics_core::Protocol;
use parking_lot::Mutex;

use crate::store::FlowStore;
use crate::tracker::FlowTracker;

/// Reports live socket counts by querying the host OS at read time.
#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct OsActiveConnectionCounter;

impl ActiveConnectionCounter for OsActiveConnectionCounter {
    fn active_connections_count(&self) -> ActiveConnectionSample {
        let sample = netmetrics::active_connection_count();
        ActiveConnectionSample {
            count: sample.count,
            stale: sample.stale,
        }
    }
}

/// OS socket count plus the flow tracker's view of which applications own them.
pub struct TrackerActiveConnectionCounter<S: FlowStore> {
    tracker: Arc<FlowTracker<S>>,
    rates: Mutex<RateSampler>,
}

impl<S: FlowStore> TrackerActiveConnectionCounter<S> {
    #[must_use]
    pub fn new(tracker: Arc<FlowTracker<S>>) -> Self {
        Self {
            tracker,
            rates: Mutex::new(RateSampler::default()),
        }
    }
}

impl<S: FlowStore + Send + Sync + 'static> ActiveConnectionCounter
    for TrackerActiveConnectionCounter<S>
{
    fn active_connections_count(&self) -> ActiveConnectionSample {
        OsActiveConnectionCounter.active_connections_count()
    }

    fn active_application_count(&self) -> Option<u32> {
        Some(self.tracker.active_application_count())
    }

    fn active_applications(&self) -> Option<Vec<ActiveApplicationSample>> {
        let apps = self.tracker.active_applications();
        let rates = self.rates.lock().sample(
            Instant::now(),
            apps.iter()
                .map(|app| (app.key.as_str(), app.total_sent, app.total_received)),
        );
        Some(
            apps.into_iter()
                .map(|app| {
                    let (upload_rate, download_rate) =
                        rates.get(&app.key).copied().unwrap_or((0, 0));
                    ActiveApplicationSample {
                        app_name: app.app_name,
                        app_path: app.app_path,
                        connection_count: app.connection_count,
                        download_rate,
                        upload_rate,
                        top_destinations: app.top_destinations,
                        destination_count: app.destination_count,
                        newest_opened_at: app.newest_opened_at.unix_timestamp(),
                    }
                })
                .collect(),
        )
    }

    fn application_flows(&self, app_path: &str) -> Option<Vec<FlowTuple>> {
        Some(
            self.tracker
                .application_flows(app_path)
                .into_iter()
                .map(|key| FlowTuple {
                    transport: match key.protocol {
                        Protocol::Tcp => Transport::Tcp,
                        Protocol::Udp => Transport::Udp,
                    },
                    local: SocketAddr::new(key.local_addr, key.local_port),
                    remote: SocketAddr::new(key.remote_addr, key.remote_port),
                })
                .collect(),
        )
    }
}

/// Shortest window a rate is measured over. Queries closer together (two
/// clients polling, say) reuse the last rates instead of dividing a few
/// milliseconds of traffic into a noisy spike.
const MIN_RATE_WINDOW: Duration = Duration::from_secs(1);

/// (sent, received) or (upload, download) per application key.
type ByteTotals = HashMap<String, (u64, u64)>;

/// Turns running per-application byte totals into bytes-per-second rates by
/// differencing successive samples.
#[derive(Debug, Default)]
pub(crate) struct RateSampler {
    baseline: Option<(Instant, ByteTotals)>,
    /// (upload, download) bytes per second from the last measured window.
    rates: ByteTotals,
}

impl RateSampler {
    /// Records `totals` of (key, sent, received) taken at `now` and returns
    /// (upload, download) rates per key. A key seen for the first time has no
    /// rate yet; a total that went down (a flow re-attributed away) reads as 0.
    pub(crate) fn sample<'a>(
        &mut self,
        now: Instant,
        totals: impl Iterator<Item = (&'a str, u64, u64)>,
    ) -> HashMap<String, (u64, u64)> {
        let current: HashMap<String, (u64, u64)> = totals
            .map(|(key, sent, received)| (key.to_owned(), (sent, received)))
            .collect();

        let Some((then, previous)) = &self.baseline else {
            self.baseline = Some((now, current));
            return HashMap::new();
        };
        let elapsed = now.saturating_duration_since(*then);
        if elapsed < MIN_RATE_WINDOW {
            return current
                .keys()
                .filter_map(|key| self.rates.get(key).map(|rate| (key.clone(), *rate)))
                .collect();
        }

        let secs = elapsed.as_secs_f64();
        let per_second = |delta: u64| -> u64 {
            // Rates are display values; whole bytes per second are plenty.
            #[allow(
                clippy::cast_possible_truncation,
                clippy::cast_sign_loss,
                clippy::cast_precision_loss
            )]
            let rate = (delta as f64 / secs).round() as u64;
            rate
        };
        self.rates = current
            .iter()
            .filter_map(|(key, (sent, received))| {
                let (old_sent, old_received) = previous.get(key)?;
                Some((
                    key.clone(),
                    (
                        per_second(sent.saturating_sub(*old_sent)),
                        per_second(received.saturating_sub(*old_received)),
                    ),
                ))
            })
            .collect();
        self.baseline = Some((now, current));
        self.rates.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_sample_has_no_rates_then_rates_follow_the_window() {
        let mut sampler = RateSampler::default();
        let start = Instant::now();
        assert!(sampler
            .sample(start, [("app", 0, 0)].into_iter())
            .is_empty());

        let rates = sampler.sample(
            start + Duration::from_secs(2),
            [("app", 2_000, 10_000)].into_iter(),
        );
        assert_eq!(rates.get("app"), Some(&(1_000, 5_000)));
    }

    #[test]
    fn a_new_application_waits_one_window_for_its_rate() {
        let mut sampler = RateSampler::default();
        let start = Instant::now();
        sampler.sample(start, [("old", 0, 0)].into_iter());
        let rates = sampler.sample(
            start + Duration::from_secs(1),
            [("old", 100, 100), ("new", 5_000, 5_000)].into_iter(),
        );
        assert_eq!(rates.get("old"), Some(&(100, 100)));
        assert_eq!(rates.get("new"), None);
    }

    #[test]
    fn close_queries_reuse_the_last_rates() {
        let mut sampler = RateSampler::default();
        let start = Instant::now();
        sampler.sample(start, [("app", 0, 0)].into_iter());
        sampler.sample(
            start + Duration::from_secs(2),
            [("app", 400, 800)].into_iter(),
        );
        let rates = sampler.sample(
            start + Duration::from_millis(2_050),
            [("app", 900_000, 900_000)].into_iter(),
        );
        assert_eq!(rates.get("app"), Some(&(200, 400)));
    }

    #[test]
    fn a_falling_total_reads_as_zero_not_a_wraparound() {
        let mut sampler = RateSampler::default();
        let start = Instant::now();
        sampler.sample(start, [("app", 10_000, 10_000)].into_iter());
        let rates = sampler.sample(
            start + Duration::from_secs(1),
            [("app", 4_000, 12_000)].into_iter(),
        );
        assert_eq!(rates.get("app"), Some(&(0, 2_000)));
    }
}
