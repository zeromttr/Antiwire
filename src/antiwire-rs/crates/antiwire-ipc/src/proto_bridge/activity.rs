//! Activity bucket conversion and the activity window.

use super::timestamps::{datetime_to_unix_secs, unix_secs_to_datetime};

use antiwire_store::{ActivityBucket, ACTIVITY_BUCKET_SECONDS};
use time::OffsetDateTime;

/// Maximum activity window in days, for both `days` and explicit ranges.
/// 366 days (~17.6k 30-minute buckets) bounds the SQLite scan and IPC payload
/// while covering any realistic retention setting; longer history pages week
/// by week.
pub(super) const MAX_ACTIVITY_RANGE_DAYS: u32 = 366;

pub(crate) fn activity_bucket_to_proto(bucket: &ActivityBucket) -> antiwire_proto::ActivityBucket {
    antiwire_proto::ActivityBucket {
        bucket_start: datetime_to_unix_secs(bucket.bucket_start),
        event_count: u32::try_from(bucket.event_count).unwrap_or(u32::MAX),
        bytes_sent: bucket.bytes_sent,
        bytes_received: bucket.bytes_received,
        blocked_count: u32::try_from(bucket.blocked_count).unwrap_or(u32::MAX),
    }
}

pub(crate) fn activity_bucket_range(days: u32) -> (OffsetDateTime, OffsetDateTime) {
    let days = days.clamp(1, MAX_ACTIVITY_RANGE_DAYS);
    let now = OffsetDateTime::now_utc();
    let until = now + time::Duration::seconds(ACTIVITY_BUCKET_SECONDS);
    let since = now - time::Duration::seconds(i64::from(days) * 86_400);
    (since, until)
}

/// Resolves an `ActivityBucketsRequest` window.
///
/// An explicit `since`+`until` range pages one retained week for history
/// navigation; otherwise the legacy rolling `days` window applies. Bounds the
/// span so a malformed client cannot force an unbounded table scan or IPC
/// payload.
pub(crate) fn activity_bucket_window(
    days: u32,
    since_secs: u64,
    until_secs: u64,
) -> Result<(OffsetDateTime, OffsetDateTime), String> {
    if since_secs == 0 && until_secs == 0 {
        let days = if days == 0 { 7 } else { days };
        return Ok(activity_bucket_range(days));
    }
    if since_secs == 0 || until_secs == 0 {
        return Err("both since and until must be set together".to_owned());
    }
    let since =
        unix_secs_to_datetime(since_secs).ok_or_else(|| "invalid since timestamp".to_owned())?;
    let mut until =
        unix_secs_to_datetime(until_secs).ok_or_else(|| "invalid until timestamp".to_owned())?;
    if since >= until {
        return Err("since must be before until".to_owned());
    }
    if (until - since).whole_seconds() > i64::from(MAX_ACTIVITY_RANGE_DAYS) * 86_400 {
        return Err("requested range exceeds the 366-day maximum".to_owned());
    }
    // Tolerate sender clock skew by clamping a slightly-future `until` to the
    // same horizon the rolling window uses, instead of rejecting the query.
    let horizon = OffsetDateTime::now_utc() + time::Duration::seconds(ACTIVITY_BUCKET_SECONDS);
    if until > horizon {
        until = horizon;
        if since >= until {
            return Err("since must be before until".to_owned());
        }
    }
    Ok((since, until))
}

/// Resolves a `DeleteHistoryRequest` to the start of the history it deletes:
/// `None` for all of it.
pub(crate) fn history_deletion_start(
    request: &antiwire_proto::DeleteHistoryRequest,
) -> Result<Option<OffsetDateTime>, String> {
    if request.all {
        return Ok(None);
    }
    // Zero would mean "everything" by accident; that takes `all`.
    if request.since == 0 {
        return Err("since must be set unless all is".to_owned());
    }
    unix_secs_to_datetime(request.since)
        .map(Some)
        .ok_or_else(|| "invalid since timestamp".to_owned())
}
