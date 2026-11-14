use crate::collector::{BackendFactory, Collector};
use netmetrics_core::MetricsError;
use serde::{Deserialize, Serialize};

const MAX_FLOW_CAPACITY: usize = 262_144;
const MAX_INGRESS_CAPACITY: usize = 262_144;
const MAX_DRAIN_BATCH_SIZE: usize = 65_536;
const MAX_CONSUMER_BATCH_SIZE: usize = 65_536;

/// Complete collector configuration.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct CollectorConfig {
    /// ETW session name or eBPF pin namespace.
    pub session_name: String,
    /// Native trace buffer sizing hint.
    pub buffer_mb: u32,
    /// Maximum number of active flow rows.
    pub max_flows: usize,
    /// Ignore flows where either endpoint is loopback.
    pub ignore_loopback: bool,
    /// Retain exited process identity for deferred attribution.
    pub process_grace_ms: u64,
    /// Enable the platform DNS side channel.
    pub dns_hints: bool,
    /// Capacity of the non-blocking native data ingress channel. Lifecycle events receive a
    /// small additional bounded reserve so byte bursts cannot displace them.
    pub ingress_capacity: usize,
    /// Maximum native events processed before the collector checks timers and
    /// drains another bounded batch.
    pub ingress_drain_batch_size: usize,
    /// Maximum events delivered in one consumer call.
    pub batch_size: usize,
    /// Maximum delay before pending byte deltas are published.
    pub coalesce_interval_ms: u64,
    /// Flush one flow early after this many pending bytes; zero disables it.
    pub coalesce_byte_threshold: u64,
    /// Native fallback and interface sampling interval.
    pub poll_interval_ms: u64,
    /// Delay before restarting a failed native session.
    pub watchdog_backoff_ms: u64,
    /// Interval between immutable flow snapshot publications.
    pub snapshot_interval_ms: u64,
    /// Cadence for process/DNS maintenance and cumulative drop reporting.
    pub maintenance_interval_ms: u64,
    /// Default lifetime assigned to DNS hints without a native TTL.
    pub dns_ttl_ms: u64,
}

impl Default for CollectorConfig {
    fn default() -> Self {
        Self {
            session_name: "netmetrics".to_owned(),
            buffer_mb: 32,
            max_flows: 65_536,
            ignore_loopback: true,
            // Antiwire overrides this with antiwire-tuning `PROCESS_STOP_RETENTION_MS`.
            process_grace_ms: 120_000,
            dns_hints: false,
            ingress_capacity: 8_192,
            ingress_drain_batch_size: 1_024,
            batch_size: 256,
            coalesce_interval_ms: 250,
            coalesce_byte_threshold: 1024 * 1024,
            poll_interval_ms: 1_000,
            watchdog_backoff_ms: 500,
            snapshot_interval_ms: 250,
            maintenance_interval_ms: 250,
            dns_ttl_ms: 60_000,
        }
    }
}

impl CollectorConfig {
    pub(crate) fn validate(&self) -> Result<(), MetricsError> {
        if self.session_name.trim().is_empty() {
            return Err(MetricsError::InvalidConfig(
                "session_name must not be empty".to_owned(),
            ));
        }
        if self.session_name.encode_utf16().count() > 240 {
            return Err(MetricsError::InvalidConfig(
                "session_name must be at most 240 UTF-16 code units".to_owned(),
            ));
        }
        #[cfg(windows)]
        validate_windows_session_name(&self.session_name, self.dns_hints)?;
        if !(1..=1024).contains(&self.buffer_mb) {
            return Err(MetricsError::InvalidConfig(
                "buffer_mb must be between 1 and 1024".to_owned(),
            ));
        }
        for (name, value, maximum) in [
            ("max_flows", self.max_flows, MAX_FLOW_CAPACITY),
            (
                "ingress_capacity",
                self.ingress_capacity,
                MAX_INGRESS_CAPACITY,
            ),
            (
                "ingress_drain_batch_size",
                self.ingress_drain_batch_size,
                MAX_DRAIN_BATCH_SIZE,
            ),
            ("batch_size", self.batch_size, MAX_CONSUMER_BATCH_SIZE),
        ] {
            if !(1..=maximum).contains(&value) {
                return Err(MetricsError::InvalidConfig(format!(
                    "{name} must be between 1 and {maximum}"
                )));
            }
        }
        for (name, value) in [
            ("coalesce_interval_ms", self.coalesce_interval_ms),
            ("poll_interval_ms", self.poll_interval_ms),
            ("watchdog_backoff_ms", self.watchdog_backoff_ms),
            ("snapshot_interval_ms", self.snapshot_interval_ms),
            ("maintenance_interval_ms", self.maintenance_interval_ms),
            ("dns_ttl_ms", self.dns_ttl_ms),
        ] {
            if value == 0 {
                return Err(MetricsError::InvalidConfig(format!(
                    "{name} must be non-zero"
                )));
            }
        }
        Ok(())
    }
}

/// Fluent collector configuration.
#[must_use = "a collector builder has no effect until build() is called"]
#[derive(Default)]
pub struct CollectorBuilder {
    config: CollectorConfig,
    pub(crate) backend_factory: Option<BackendFactory>,
}

impl std::fmt::Debug for CollectorBuilder {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CollectorBuilder")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl CollectorBuilder {
    /// Starts a builder with production defaults.
    pub fn new() -> Self {
        Self::default()
    }

    /// Replaces all configuration fields at once.
    pub fn config(mut self, config: CollectorConfig) -> Self {
        self.config = config;
        self
    }

    /// Sets the native session name.
    pub fn session_name(mut self, value: impl Into<String>) -> Self {
        self.config.session_name = value.into();
        self
    }

    /// Sets the native trace buffer hint.
    pub fn buffer_mb(mut self, value: u32) -> Self {
        self.config.buffer_mb = value;
        self
    }

    /// Sets the active-flow memory cap.
    pub fn max_flows(mut self, value: usize) -> Self {
        self.config.max_flows = value;
        self
    }

    /// Enables or disables loopback filtering.
    pub fn ignore_loopback(mut self, value: bool) -> Self {
        self.config.ignore_loopback = value;
        self
    }

    /// Sets the process attribution grace period.
    pub fn process_grace_ms(mut self, value: u64) -> Self {
        self.config.process_grace_ms = value;
        self
    }

    /// Enables or disables DNS hint collection.
    pub fn dns_hints(mut self, value: bool) -> Self {
        self.config.dns_hints = value;
        self
    }

    /// Sets the bounded native ingress capacity.
    pub fn ingress_capacity(mut self, value: usize) -> Self {
        self.config.ingress_capacity = value;
        self
    }

    /// Sets the bounded native batch drained per collector iteration.
    pub fn ingress_drain_batch_size(mut self, value: usize) -> Self {
        self.config.ingress_drain_batch_size = value;
        self
    }

    /// Sets the maximum consumer batch size.
    pub fn batch_size(mut self, value: usize) -> Self {
        self.config.batch_size = value;
        self
    }

    /// Sets the timer-driven byte flush interval.
    pub fn coalesce_interval_ms(mut self, value: u64) -> Self {
        self.config.coalesce_interval_ms = value;
        self
    }

    /// Sets the early byte flush threshold.
    pub fn coalesce_byte_threshold(mut self, value: u64) -> Self {
        self.config.coalesce_byte_threshold = value;
        self
    }

    /// Sets fallback and interface polling cadence.
    pub fn poll_interval_ms(mut self, value: u64) -> Self {
        self.config.poll_interval_ms = value;
        self
    }

    /// Sets failed-session restart delay.
    pub fn watchdog_backoff_ms(mut self, value: u64) -> Self {
        self.config.watchdog_backoff_ms = value;
        self
    }

    /// Sets immutable snapshot publication cadence.
    pub fn snapshot_interval_ms(mut self, value: u64) -> Self {
        self.config.snapshot_interval_ms = value;
        self
    }

    /// Sets the cadence for collector maintenance and drop reporting.
    pub fn maintenance_interval_ms(mut self, value: u64) -> Self {
        self.config.maintenance_interval_ms = value;
        self
    }

    /// Validates configuration and constructs a stopped collector.
    ///
    /// # Errors
    ///
    /// Returns [`MetricsError::InvalidConfig`] when a required capacity or
    /// interval is zero, the session name is invalid, or the ETW buffer hint
    /// is outside its supported range.
    pub fn build(self) -> Result<Collector, MetricsError> {
        self.config.validate()?;
        Ok(Collector::new(self.config, self.backend_factory))
    }
}

#[cfg(windows)]
fn validate_windows_session_name(name: &str, dns_enabled: bool) -> Result<(), MetricsError> {
    netmetrics_core::EtwLoggerNames::derive(name, dns_enabled)
        .map(drop)
        .map_err(MetricsError::InvalidConfig)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_valid() {
        CollectorBuilder::new().build().expect("default collector");
        let config = CollectorConfig::default();
        assert_eq!(config.process_grace_ms, 120_000);
        assert_eq!(config.ingress_drain_batch_size, 1_024);
        assert_eq!(config.maintenance_interval_ms, 250);
    }

    #[test]
    fn rejects_zero_memory_and_queue_bounds() {
        for config in [
            CollectorConfig {
                max_flows: 0,
                ..CollectorConfig::default()
            },
            CollectorConfig {
                ingress_capacity: 0,
                ..CollectorConfig::default()
            },
            CollectorConfig {
                ingress_drain_batch_size: 0,
                ..CollectorConfig::default()
            },
            CollectorConfig {
                batch_size: 0,
                ..CollectorConfig::default()
            },
            CollectorConfig {
                maintenance_interval_ms: 0,
                ..CollectorConfig::default()
            },
        ] {
            assert!(matches!(
                CollectorBuilder::new().config(config).build(),
                Err(MetricsError::InvalidConfig(_))
            ));
        }
    }

    #[test]
    fn rejects_capacities_that_can_exhaust_collector_memory() {
        for config in [
            CollectorConfig {
                max_flows: MAX_FLOW_CAPACITY + 1,
                ..CollectorConfig::default()
            },
            CollectorConfig {
                ingress_capacity: MAX_INGRESS_CAPACITY + 1,
                ..CollectorConfig::default()
            },
            CollectorConfig {
                ingress_drain_batch_size: MAX_DRAIN_BATCH_SIZE + 1,
                ..CollectorConfig::default()
            },
            CollectorConfig {
                batch_size: MAX_CONSUMER_BATCH_SIZE + 1,
                ..CollectorConfig::default()
            },
        ] {
            assert!(matches!(
                CollectorBuilder::new().config(config).build(),
                Err(MetricsError::InvalidConfig(_))
            ));
        }
    }

    #[cfg(windows)]
    #[test]
    fn rejects_windows_session_names_that_overflow_derived_etw_names() {
        let config = CollectorConfig {
            session_name: "a".repeat(190),
            ..CollectorConfig::default()
        };
        assert!(matches!(
            CollectorBuilder::new().config(config).build(),
            Err(MetricsError::InvalidConfig(_))
        ));

        let config = CollectorConfig {
            session_name: "valid\0invalid".to_owned(),
            ..CollectorConfig::default()
        };
        assert!(matches!(
            CollectorBuilder::new().config(config).build(),
            Err(MetricsError::InvalidConfig(_))
        ));
    }
}
