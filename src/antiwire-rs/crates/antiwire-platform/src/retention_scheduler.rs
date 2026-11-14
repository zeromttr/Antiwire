use std::sync::Arc;

use antiwire_store::Store;
use antiwire_tuning::{
    DNS_INFERENCE_MAX_AGE, DNS_INFERENCE_PURGE_BATCH_SIZE, DNS_INFERENCE_PURGE_WORK_INTERVAL,
    LOG_RETENTION_PURGE_BATCH_SIZE, LOG_RETENTION_PURGE_INTERVAL,
};
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tracing::warn;

use crate::retention::{purge_connection_logs, RetentionPolicy};

/// Background task that purges old logs and DNS rows on independent intervals.
pub struct RetentionScheduler {
    stop_tx: watch::Sender<bool>,
    handle: Option<JoinHandle<()>>,
}

impl RetentionScheduler {
    pub fn start(store: Arc<Store>) -> Self {
        Self::start_with_intervals(
            store,
            LOG_RETENTION_PURGE_INTERVAL,
            DNS_INFERENCE_PURGE_WORK_INTERVAL,
        )
    }

    fn start_with_intervals(
        store: Arc<Store>,
        log_interval: std::time::Duration,
        dns_interval: std::time::Duration,
    ) -> Self {
        let (stop_tx, mut stop_rx) = watch::channel(false);

        let handle = tokio::spawn(async move {
            let mut log_ticker = tokio::time::interval(log_interval);
            let mut dns_ticker = tokio::time::interval(dns_interval);
            loop {
                tokio::select! {
                    _ = dns_ticker.tick() => {
                        // DNS inference rows have their own age policy. Keep
                        // draining one bounded batch even when no DNS writes
                        // arrive, so a burst cannot create an idle backlog.
                        let batch =
                            u32::try_from(DNS_INFERENCE_PURGE_BATCH_SIZE).unwrap_or(u32::MAX);
                        loop {
                            let dns_cutoff = time::OffsetDateTime::now_utc()
                                - time::Duration::new(
                                    i64::try_from(DNS_INFERENCE_MAX_AGE.as_secs())
                                        .unwrap_or(i64::MAX),
                                    0,
                                );
                            let removed = match store.purge_expired_dns_cache(dns_cutoff, batch) {
                                Ok(removed) => removed,
                                Err(err) => {
                                    warn!(error = %err, "DNS cache retention purge failed");
                                    break;
                                }
                            };
                            if removed > 0 {
                                tracing::info!(removed, "purged expired DNS cache rows");
                            }
                            if removed < u64::from(batch) {
                                break;
                            }
                            // Every pass owns one bounded DB operation. Yield
                            // before the next pass so writers and shutdown
                            // can run between batches while a backlog drains.
                            tokio::select! {
                                () = tokio::task::yield_now() => {}
                                changed = stop_rx.changed() => {
                                    if changed.is_ok() && *stop_rx.borrow() {
                                        return;
                                    }
                                }
                            }
                        }

                    }
                    _ = log_ticker.tick() => {
                        let settings = match store.get_settings() {
                            Ok(settings) => settings,
                            Err(err) => {
                                warn!(error = %err, "retention scheduler could not load settings");
                                continue;
                            }
                        };
                        let policy = RetentionPolicy::from_settings(&settings);
                        if !policy.enabled {
                            continue;
                        }
                        loop {
                            let store = Arc::clone(&store);
                            let result = tokio::task::spawn_blocking(move || purge_connection_logs(&store, &policy)).await;
                            let removed = match result {
                                Ok(Ok(removed)) => removed,
                                Ok(Err(err)) => { warn!(error = %err, "retention purge failed"); break; }
                                Err(err) => { warn!(error = %err, "retention worker failed"); break; }
                            };
                            if removed > 0 { tracing::info!(removed, "purged expired history"); }
                            if removed < u64::from(LOG_RETENTION_PURGE_BATCH_SIZE) { break; }
                            tokio::select! {
                                () = tokio::task::yield_now() => {}
                                _ = stop_rx.changed() => return,
                            }
                        }
                    }
                    changed = stop_rx.changed() => {
                        if changed.is_ok() && *stop_rx.borrow() {
                            break;
                        }
                    }
                }
            }
        });

        Self {
            stop_tx,
            handle: Some(handle),
        }
    }

    pub fn stop(&mut self) {
        let _ = self.stop_tx.send(true);
        if let Some(handle) = self.handle.take() {
            handle.abort();
        }
    }
}

impl Drop for RetentionScheduler {
    fn drop(&mut self) {
        self.stop();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use antiwire_secrets::UnixSecureFileKeyProvider;
    use antiwire_store::DnsCacheEntry;
    use std::time::Duration;
    use tempfile::tempdir;

    #[tokio::test]
    async fn scheduler_starts_and_stops_cleanly() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("db.sqlite");
        let keystore = UnixSecureFileKeyProvider::new(dir.path().join("key"));
        let store = Arc::new(Store::open_with_keystore(&path, &keystore).unwrap());

        let mut scheduler = RetentionScheduler::start(Arc::clone(&store));
        tokio::time::sleep(Duration::from_millis(50)).await;
        scheduler.stop();
    }

    #[tokio::test]
    async fn scheduler_drains_multiple_dns_batches_without_writes() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("db.sqlite");
        let keystore = UnixSecureFileKeyProvider::new(dir.path().join("key"));
        let store = Arc::new(Store::open_with_keystore(&path, &keystore).unwrap());
        let old = time::OffsetDateTime::now_utc() - time::Duration::days(2);
        for index in 0..2_501 {
            store
                .upsert_dns_cache(&DnsCacheEntry {
                    id: format!("retention-{index}"),
                    domain: format!("old-{index}.test"),
                    last_seen: old,
                })
                .unwrap();
        }
        let mut scheduler = RetentionScheduler::start_with_intervals(
            Arc::clone(&store),
            Duration::from_secs(3600),
            Duration::from_secs(3600),
        );
        // Tokio's first interval tick is immediate. The next is an hour away,
        // so success proves full batches are drained within one activation.
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let all_removed = (0..2_501).all(|index| {
                    store
                        .get_dns_cache(&format!("retention-{index}"))
                        .unwrap()
                        .is_none()
                });
                if all_removed {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("DNS backlog must drain without further writes or ticks");
        scheduler.stop();
    }
}
