//! Windows `FILETIME` values: 100 ns ticks since 1601-01-01 UTC.

use std::time::{SystemTime, UNIX_EPOCH};

/// The Unix epoch as a `FILETIME` tick count.
pub(crate) const FILETIME_UNIX_EPOCH: u64 = 116_444_736_000_000_000;

/// Unix milliseconds for a `FILETIME`, or `None` when it is before 1970.
pub(crate) fn filetime_to_unix_ms(filetime: u64) -> Option<u64> {
    filetime
        .checked_sub(FILETIME_UNIX_EPOCH)
        .map(|interval| interval / 10_000)
}

/// The current time as a `FILETIME`, saturating at `i64::MAX`.
pub(crate) fn filetime_now() -> i64 {
    let unix_ticks = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_nanos() / 100);
    i64::try_from(u128::from(FILETIME_UNIX_EPOCH).saturating_add(unix_ticks)).unwrap_or(i64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filetime_before_unix_epoch_is_rejected() {
        assert_eq!(filetime_to_unix_ms(0), None);
        assert_eq!(filetime_to_unix_ms(FILETIME_UNIX_EPOCH + 10_000), Some(1));
    }

    #[test]
    fn filetime_now_round_trips_to_the_unix_clock() {
        let now = u64::try_from(filetime_now()).expect("after 1601");
        let unix_ms = filetime_to_unix_ms(now).expect("after 1970");
        assert!(unix_ms.abs_diff(netmetrics_core::unix_now_ms()) < 60_000);
    }
}
