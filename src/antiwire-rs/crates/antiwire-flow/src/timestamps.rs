//! Times as the event hubs carry them.

use time::OffsetDateTime;

/// Whole seconds since the Unix epoch; a time before it is 0.
pub(crate) fn unix_secs(value: OffsetDateTime) -> u64 {
    u64::try_from(value.unix_timestamp().max(0)).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::macros::datetime;

    #[test]
    fn times_before_the_epoch_are_zero() {
        assert_eq!(unix_secs(datetime!(1970-01-01 00:01 UTC)), 60);
        assert_eq!(unix_secs(datetime!(1969-12-31 23:59 UTC)), 0);
    }
}
