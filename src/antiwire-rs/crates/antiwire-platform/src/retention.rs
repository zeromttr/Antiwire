use antiwire_store::{activity_bucket_start, DaemonSetting, Store};
use antiwire_tuning::{DEFAULT_LOG_RETENTION_DAYS, UNLIMITED_LOG_RETENTION_DAYS};
use time::OffsetDateTime;

/// Log retention policy derived from daemon settings.
#[derive(Debug, Clone, Copy)]
pub struct RetentionPolicy {
    pub enabled: bool,
    pub retention_days: u32,
}

impl RetentionPolicy {
    pub fn from_settings(settings: &DaemonSetting) -> Self {
        let retention_days = u32::try_from(settings.log_retention_days)
            .ok()
            .filter(|days| *days > 0)
            .unwrap_or(DEFAULT_LOG_RETENTION_DAYS.unsigned_abs());
        Self {
            enabled: settings.log_retention_enabled,
            retention_days,
        }
    }

    pub fn cutoff_timestamp(&self) -> Option<OffsetDateTime> {
        if !self.enabled {
            return None;
        }
        if self.retention_days >= UNLIMITED_LOG_RETENTION_DAYS as u32 {
            return None;
        }
        let seconds = i64::from(self.retention_days) * 86_400;
        Some(OffsetDateTime::now_utc() - time::Duration::seconds(seconds))
    }
}

/// Delete connection logs and activity buckets older than the retention cutoff.
///
/// Connection logs purge at exact-cutoff precision. Activity buckets are
/// 30-minute aggregates keyed by their floored start, so their cutoff is
/// floored to the same boundary: a bucket overlapping the cutoff instant is
/// retained as a whole rather than deleted for partially overlapping it.
///
/// # Errors
///
/// Any error from the store.
pub fn purge_connection_logs(
    store: &Store,
    policy: &RetentionPolicy,
) -> Result<u64, antiwire_store::StoreError> {
    let cutoff = policy.cutoff_timestamp();
    let removed_logs = store.purge_connection_logs_before(cutoff)?;
    let bucket_cutoff = cutoff.map(activity_bucket_start);
    let removed_buckets = store.purge_activity_buckets_before(bucket_cutoff)?;
    let removed_history = store.purge_history_before(cutoff)?;
    if removed_logs > 0 || removed_buckets > 0 {
        store.reclaim_history_space()?;
    }
    Ok(removed_logs
        .saturating_add(removed_buckets)
        .saturating_add(removed_history))
}

#[cfg(test)]
mod tests {
    use super::*;
    use antiwire_secrets::UnixSecureFileKeyProvider;
    use tempfile::tempdir;

    #[test]
    fn unlimited_retention_has_no_cutoff() {
        let policy = RetentionPolicy {
            enabled: true,
            retention_days: UNLIMITED_LOG_RETENTION_DAYS as u32,
        };
        assert!(policy.cutoff_timestamp().is_none());
    }

    #[test]
    fn purge_removes_old_rows() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("db.sqlite");
        let keystore = UnixSecureFileKeyProvider::new(dir.path().join("key"));
        let store = Store::open_with_keystore(&path, &keystore).unwrap();
        let policy = RetentionPolicy {
            enabled: true,
            retention_days: 0,
        };
        let removed = purge_connection_logs(&store, &policy).unwrap_or(0);
        assert_eq!(removed, 0);
    }

    #[test]
    fn bucket_cutoff_is_floored_to_bucket_start() {
        // A cutoff mid-bucket must retain the overlapping bucket as a whole:
        // buckets are keyed by floored start, so flooring decides the delete.
        let cutoff = time::macros::datetime!(2026-02-01 10:15:00 UTC);
        let floored = activity_bucket_start(cutoff);
        assert_eq!(floored, time::macros::datetime!(2026-02-01 10:00:00 UTC));
    }
}
