//! Wall-clock helpers shared by every backend.

use std::time::{SystemTime, UNIX_EPOCH};

/// Milliseconds since the Unix epoch, or `0` if the clock reads before it.
#[must_use]
pub fn unix_now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| {
            u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
        })
}
