//! Live active-connection count surface for dashboard stats.

/// Last-known socket count plus whether that value is stale or missing.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ActiveConnectionSample {
    /// Present when a count has been sampled. `None` is unavailable, not zero.
    pub count: Option<u32>,
    /// True when `count` is last-known after a failed refresh.
    pub stale: bool,
}

impl ActiveConnectionSample {
    /// A live sample that should be shown as current.
    #[must_use]
    pub const fn fresh(count: u32) -> Self {
        Self {
            count: Some(count),
            stale: false,
        }
    }

    /// Last-known value after a refresh failed.
    #[must_use]
    pub const fn stale(count: u32) -> Self {
        Self {
            count: Some(count),
            stale: true,
        }
    }
}

/// One application owning live connections, with current rates.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ActiveApplicationSample {
    pub app_name: String,
    pub app_path: String,
    pub connection_count: u32,
    /// Bytes per second since the previous sample; zero on first sighting.
    pub download_rate: u64,
    pub upload_rate: u64,
    /// Busiest destinations first, at most three.
    pub top_destinations: Vec<String>,
    pub destination_count: u32,
    /// Unix seconds when the newest live connection opened.
    pub newest_opened_at: i64,
}

/// Reports how many connections are currently open in the flow tracker.
pub trait ActiveConnectionCounter: Send + Sync {
    fn active_connections_count(&self) -> ActiveConnectionSample;

    /// Distinct applications owning at least one live connection. `None`
    /// means this counter cannot attribute connections, not that none exist.
    fn active_application_count(&self) -> Option<u32> {
        None
    }

    /// Applications owning live connections. `None` means this counter
    /// cannot attribute connections, not that none exist.
    fn active_applications(&self) -> Option<Vec<ActiveApplicationSample>> {
        None
    }

    /// Live flows of the application at `app_path`. `None` means this counter
    /// cannot attribute connections, not that the application has none.
    fn application_flows(&self, _app_path: &str) -> Option<Vec<antiwire_capture::FlowTuple>> {
        None
    }
}

/// Default no-op counter for tests without a running flow tracker.
#[cfg(any(test, feature = "test-support"))]
#[derive(Debug, Default)]
pub struct ZeroActiveConnectionCounter;

#[cfg(any(test, feature = "test-support"))]
impl ActiveConnectionCounter for ZeroActiveConnectionCounter {
    fn active_connections_count(&self) -> ActiveConnectionSample {
        ActiveConnectionSample::fresh(0)
    }
}
