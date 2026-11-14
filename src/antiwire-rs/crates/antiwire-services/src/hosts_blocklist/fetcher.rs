//! Where blocklist downloads come from.

use antiwire_downloader::{
    DownloadClient, DownloadConfig, HostsDownloadItem, HostsDownloadOutcome,
};

/// Downloads blocklists into their cache files.
#[async_trait::async_trait]
pub trait HostsFetcher: Send + Sync {
    /// Downloads every item, returning one outcome per item. An outcome of
    /// `Ok(false)` means the cache was already current.
    async fn fetch(&self, items: &[HostsDownloadItem]) -> Vec<HostsDownloadOutcome>;
}

/// Downloads over HTTP from each list's mirrors, a few lists at a time.
pub struct HttpHostsFetcher {
    client: DownloadClient,
}

impl HttpHostsFetcher {
    /// # Panics
    ///
    /// Panics if the TLS backend cannot be initialized.
    #[must_use]
    pub fn new() -> Self {
        Self {
            client: DownloadClient::new(),
        }
    }
}

impl Default for HttpHostsFetcher {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl HostsFetcher for HttpHostsFetcher {
    async fn fetch(&self, items: &[HostsDownloadItem]) -> Vec<HostsDownloadOutcome> {
        self.client
            .download_hosts_batch(
                items,
                &DownloadConfig::default(),
                antiwire_tuning::HOSTS_MAX_PARALLEL_DOWNLOADS,
            )
            .await
    }
}
