use std::error::Error;
use std::fmt::{Display, Formatter};

/// Errors returned by collector construction and lifecycle operations.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MetricsError {
    /// A configuration field is outside its supported range.
    InvalidConfig(String),
    /// The collector was started more than once.
    AlreadyRunning,
    /// The requested operation requires a running collector.
    NotRunning,
    /// A platform backend could not start or continue.
    Backend(String),
    /// A collector worker panicked.
    ThreadPanic,
}

impl Display for MetricsError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidConfig(message) => write!(formatter, "invalid configuration: {message}"),
            Self::AlreadyRunning => formatter.write_str("collector is already running"),
            Self::NotRunning => formatter.write_str("collector is not running"),
            Self::Backend(message) => write!(formatter, "backend error: {message}"),
            Self::ThreadPanic => formatter.write_str("collector worker panicked"),
        }
    }
}

impl Error for MetricsError {}
