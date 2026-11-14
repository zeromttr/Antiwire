//! Conversions between protobuf timestamps and `OffsetDateTime`.

use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

pub(super) fn datetime_to_unix_secs(value: OffsetDateTime) -> u64 {
    u64::try_from(value.unix_timestamp().max(0)).unwrap_or(0)
}

pub(super) fn unix_secs_to_datetime(value: u64) -> Option<OffsetDateTime> {
    if value == 0 {
        return None;
    }
    OffsetDateTime::from_unix_timestamp(i64::try_from(value).ok()?).ok()
}

pub(super) fn time_window_from_proto(
    start: u64,
    end: u64,
) -> (Option<OffsetDateTime>, Option<OffsetDateTime>) {
    // A partially specified window still applies: dropping a start-only or
    // end-only bound here would silently widen the query to all time.
    (unix_secs_to_datetime(start), unix_secs_to_datetime(end))
}

pub(super) fn format_timestamp_rfc3339(value: OffsetDateTime) -> String {
    value.format(&Rfc3339).unwrap_or_else(|_| {
        OffsetDateTime::UNIX_EPOCH
            .format(&Rfc3339)
            .unwrap_or_default()
    })
}

pub(super) fn parse_timestamp_or_epoch(value: &str) -> OffsetDateTime {
    if value.is_empty() {
        return OffsetDateTime::UNIX_EPOCH;
    }
    OffsetDateTime::parse(value, &Rfc3339).unwrap_or(OffsetDateTime::UNIX_EPOCH)
}
