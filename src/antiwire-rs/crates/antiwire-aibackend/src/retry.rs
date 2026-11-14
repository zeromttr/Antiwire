//! Retry budget and the Python SDK's backoff formula.
//!
//! Jitter uses a thread-local xorshift generator so this crate does not pull
//! another `rand` version. `deny.toml` rejects multiple versions of `rand`.

use std::cell::Cell;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::error::Error;

/// Retry behavior for one client or one call.
///
/// Defaults match the Python SDK: 2 retries after the first attempt, backoff
/// from 0.5s to 5s with 0.25 jitter, retry on 408, 429, and 5xx, honor
/// `Retry-After`, and stop after a 30s budget.
#[derive(Debug, Clone, PartialEq)]
pub struct RetryPolicy {
    /// Retries after the initial attempt. Zero disables retries.
    pub max_retries: u32,
    /// First backoff delay in seconds. Zero disables backoff.
    pub backoff_initial: f64,
    /// Maximum backoff delay in seconds. Zero disables backoff.
    pub backoff_max: f64,
    /// Fraction of each backoff delay that may be subtracted, from 0 to 1.
    pub backoff_jitter: f64,
    /// Honor `Retry-After` and `retry-after-ms`, capped by `backoff_max`.
    pub respect_retry_after: bool,
    /// Retry connection failures.
    pub retry_connection_errors: bool,
    /// Retry timeouts. Checked before [`Self::retry_connection_errors`].
    pub retry_timeouts: bool,
    /// Total time for the call, including the first attempt and delays.
    /// `None` disables the budget.
    pub budget: Option<Duration>,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self::new()
    }
}

impl RetryPolicy {
    /// Python SDK defaults.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            max_retries: 2,
            backoff_initial: 0.5,
            backoff_max: 5.0,
            backoff_jitter: 0.25,
            respect_retry_after: true,
            retry_connection_errors: true,
            retry_timeouts: true,
            budget: Some(Duration::from_secs(30)),
        }
    }

    /// Rejects non-finite backoff values, jitter outside 0..=1, and a zero budget.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Client`](crate::Error::Client) when a field is out of range.
    pub fn validate(&self) -> Result<(), Error> {
        if !self.backoff_initial.is_finite() || self.backoff_initial < 0.0 {
            return Err(Error::client(
                "backoff_initial must be a non-negative, finite number of seconds.",
            ));
        }
        if !self.backoff_max.is_finite() || self.backoff_max < 0.0 {
            return Err(Error::client(
                "backoff_max must be a non-negative, finite number of seconds.",
            ));
        }
        if !self.backoff_jitter.is_finite() || !(0.0..=1.0).contains(&self.backoff_jitter) {
            return Err(Error::client(
                "backoff_jitter must be between zero and one.",
            ));
        }
        if self.budget.is_some_and(|budget| budget.is_zero()) {
            return Err(Error::client(
                "timeout must be a positive, finite number of seconds.",
            ));
        }
        Ok(())
    }

    pub(crate) fn is_retryable(&self, error: &Error) -> bool {
        match error {
            Error::Timeout { .. } => self.retry_timeouts,
            Error::Connection { .. } => self.retry_connection_errors,
            Error::Api(api) => crate::retry::status_retryable(api.status),
            Error::Client(_) => false,
        }
    }

    pub(crate) fn delay_after(&self, error: &Error, attempt_number: u32) -> Duration {
        if self.respect_retry_after {
            if let Error::Api(api) = error {
                if let Some(retry_after) = api.retry_after {
                    return retry_after
                        .min(duration_from_seconds(self.backoff_max).unwrap_or(Duration::MAX));
                }
            }
        }
        let seconds = backoff_delay(
            attempt_number,
            self.backoff_initial,
            self.backoff_max,
            self.backoff_jitter,
            jitter_unit(),
        );
        duration_from_seconds(seconds).unwrap_or(Duration::ZERO)
    }

    pub(crate) fn budget_exhausted(&self, elapsed: Duration, delay: Duration) -> bool {
        self.budget
            .is_some_and(|budget| elapsed.saturating_add(delay) >= budget)
    }
}

pub(crate) fn status_retryable(status: u16) -> bool {
    status == 408 || status == 429 || (500..600).contains(&status)
}

/// Python `_backoff`: `min(exponential, round(exponential * (1 - random * jitter), 3))`.
pub(crate) fn backoff_delay(
    attempt: u32,
    initial: f64,
    maximum: f64,
    jitter: f64,
    random_unit: f64,
) -> f64 {
    if initial == 0.0 || maximum == 0.0 {
        return 0.0;
    }
    let exponent = i32::try_from(attempt.saturating_sub(1)).unwrap_or(i32::MAX);
    let cap_exponent = maximum.log2() - initial.log2();
    let mut exponential = if f64::from(exponent) >= cap_exponent {
        maximum
    } else {
        initial * 2f64.powi(exponent)
    };
    if !exponential.is_finite() {
        exponential = maximum;
    }
    let random_unit = random_unit.clamp(0.0, 1.0);
    let delay = exponential * (1.0 - random_unit * jitter);
    round_millis(delay).min(exponential)
}

fn round_millis(value: f64) -> f64 {
    if !value.is_finite() || value.abs() >= 1e15 {
        return value;
    }
    let scaled = value * 1000.0;
    if !scaled.is_finite() {
        return value;
    }
    scaled.round_ties_even() / 1000.0
}

fn duration_from_seconds(seconds: f64) -> Option<Duration> {
    if seconds.is_finite() && seconds >= 0.0 {
        Duration::try_from_secs_f64(seconds).ok()
    } else {
        None
    }
}

fn jitter_unit() -> f64 {
    thread_local! {
        static STATE: Cell<u64> = const { Cell::new(0) };
    }
    STATE.with(|state| {
        let mut bits = state.get();
        if bits == 0 {
            bits = seed_state(state.as_ptr().addr() as u64);
        }
        // xorshift64*
        bits ^= bits << 13;
        bits ^= bits >> 7;
        bits ^= bits << 17;
        state.set(bits);
        unit_from_bits(bits)
    })
}

#[allow(clippy::cast_precision_loss)]
fn unit_from_bits(bits: u64) -> f64 {
    let mantissa = bits >> 11;
    // The top 53 bits are exactly representable in an `f64`.
    (mantissa as f64) / ((1_u64 << 53) as f64)
}

fn seed_state(address: u64) -> u64 {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| {
            u64::try_from(elapsed.as_nanos()).unwrap_or(u64::MAX)
        });
    let seed = nanos ^ address ^ 0xA076_1D64_78BD_642F;
    if seed == 0 {
        0x9E37_79B9_7F4A_7C15
    } else {
        seed
    }
}

#[cfg(test)]
#[allow(clippy::float_cmp)]
mod tests {
    use super::{backoff_delay, jitter_unit, status_retryable, RetryPolicy};
    use crate::error::{ApiError, ApiErrorKind, Error, ErrorBody};
    use std::time::Duration;

    fn api_error(retry_after: Option<Duration>) -> Error {
        Error::Api(Box::new(ApiError {
            status: 429,
            kind: ApiErrorKind::RateLimit,
            message: String::new(),
            body: ErrorBody::Empty,
            request_id: None,
            retry_after,
            endpoint: String::new(),
            field_path: None,
        }))
    }

    #[test]
    fn backoff_matches_python_formula() {
        let samples = [(1, 0.5), (2, 1.0), (3, 2.0), (4, 4.0), (5, 5.0), (20, 5.0)];
        for (attempt, expected) in samples {
            assert_eq!(backoff_delay(attempt, 0.5, 5.0, 0.25, 0.0), expected);
        }
        assert_eq!(backoff_delay(1, 0.5, 5.0, 0.25, 1.0), 0.375);
        assert_eq!(backoff_delay(1, 0.0, 5.0, 0.25, 0.0), 0.0);
        assert_eq!(backoff_delay(1, 0.5, 0.0, 0.25, 0.0), 0.0);
        assert_eq!(backoff_delay(1, 0.5, 0.0006, 0.0, 0.0), 0.0006);
    }

    #[test]
    fn jitter_stays_inside_the_python_bounds() {
        for _ in 0..64 {
            let delay = backoff_delay(1, 0.5, 5.0, 0.25, jitter_unit());
            assert!(
                (0.375..=0.5).contains(&delay),
                "delay {delay} outside [0.375, 0.5]"
            );
        }
    }

    #[test]
    fn defaults_and_validation() {
        let policy = RetryPolicy::default();
        assert_eq!(policy.max_retries, 2);
        assert_eq!(policy.backoff_initial, 0.5);
        assert_eq!(policy.backoff_max, 5.0);
        assert_eq!(policy.backoff_jitter, 0.25);
        assert!(policy.respect_retry_after);
        assert_eq!(policy.budget, Some(Duration::from_secs(30)));
        assert!(policy.validate().is_ok());
        assert!(RetryPolicy {
            backoff_jitter: 1.1,
            ..RetryPolicy::default()
        }
        .validate()
        .is_err());
        assert!(RetryPolicy {
            backoff_initial: f64::NAN,
            ..RetryPolicy::default()
        }
        .validate()
        .is_err());
        assert!(RetryPolicy {
            budget: Some(Duration::ZERO),
            ..RetryPolicy::default()
        }
        .validate()
        .is_err());
    }

    #[test]
    fn retryable_statuses_are_a_range_check() {
        for status in [408_u16, 429, 500, 503, 599] {
            assert!(status_retryable(status), "{status}");
        }
        for status in [400_u16, 401, 403, 404, 409, 422, 302, 600] {
            assert!(!status_retryable(status), "{status}");
        }
    }

    #[test]
    fn retry_after_replaces_backoff_when_enabled() {
        let error = api_error(Some(Duration::from_secs(5)));
        assert_eq!(
            RetryPolicy::default().delay_after(&error, 1),
            Duration::from_secs(5)
        );
        let ignored = RetryPolicy {
            respect_retry_after: false,
            ..RetryPolicy::default()
        };
        let delay = ignored.delay_after(&error, 1);
        assert!(Duration::from_millis(375) <= delay && delay <= Duration::from_millis(500));
        assert!(
            RetryPolicy::default()
                .delay_after(&api_error(None), 1)
                .as_secs_f64()
                <= 0.5
        );
    }

    #[test]
    fn retry_after_obeys_the_maximum_even_without_a_budget() {
        let mut policy = RetryPolicy {
            budget: None,
            ..RetryPolicy::default()
        };
        let error = api_error(Some(Duration::MAX));
        assert_eq!(policy.delay_after(&error, 1), Duration::from_secs(5));
        policy.backoff_max = 0.125;
        assert_eq!(policy.delay_after(&error, 1), Duration::from_millis(125));
        policy.backoff_max = 0.0;
        assert_eq!(policy.delay_after(&error, 1), Duration::ZERO);
        assert_eq!(
            policy.delay_after(&api_error(Some(Duration::ZERO)), 1),
            Duration::ZERO
        );
    }

    #[test]
    fn budget_stops_before_a_delay_would_reach_it() {
        let policy = RetryPolicy::default();
        assert!(policy.budget_exhausted(Duration::from_secs(29), Duration::from_secs(2)));
        assert!(!policy.budget_exhausted(Duration::from_secs(10), Duration::from_secs(5)));
        let unlimited = RetryPolicy {
            budget: None,
            ..RetryPolicy::default()
        };
        assert!(!unlimited.budget_exhausted(Duration::from_secs(1_000), Duration::from_secs(1_000)));
    }

    #[test]
    fn classifies_retryable_errors() {
        let policy = RetryPolicy::default();
        assert!(policy.is_retryable(&api_error(None)));
        assert!(policy.is_retryable(&Error::Connection {
            message: "reset".to_owned()
        }));
        assert!(policy.is_retryable(&Error::Timeout { seconds: 1.0 }));
        assert!(!policy.is_retryable(&Error::client("no")));
        assert!(!RetryPolicy {
            retry_timeouts: false,
            ..RetryPolicy::default()
        }
        .is_retryable(&Error::Timeout { seconds: 1.0 }));
        assert!(!policy.is_retryable(&Error::Api(Box::new(ApiError {
            status: 401,
            kind: ApiErrorKind::Authentication,
            message: String::new(),
            body: ErrorBody::Empty,
            request_id: None,
            retry_after: None,
            endpoint: String::new(),
            field_path: None,
        }))));
    }
}
