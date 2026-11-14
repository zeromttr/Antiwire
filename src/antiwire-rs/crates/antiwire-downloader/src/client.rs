use std::time::Duration;

use antiwire_http::{Destinations, HttpClient, HttpClientBuilder};

/// Overall deadline for one download. A mirror that drips bytes just fast
/// enough to dodge the idle timeout still gives the slot back after this.
const DOWNLOAD_DEADLINE: Duration = Duration::from_secs(30 * 60);

/// Shared HTTP client for blocklist and database downloads.
pub struct DownloadClient {
    pub(crate) inner: HttpClient,
}

impl DownloadClient {
    /// Client for blocklist sync.
    ///
    /// Custom blocklist URLs may point at a server on the user's own network,
    /// so private addresses are allowed. Loopback, link-local and cloud
    /// metadata addresses are not, on the first request or any redirect.
    ///
    /// # Panics
    ///
    /// Panics if the TLS backend cannot be initialized.
    #[allow(clippy::new_without_default)]
    #[must_use]
    pub fn new() -> Self {
        Self::with_destinations(Destinations::PublicAndPrivate)
    }

    /// Client for fixed downloads from the internet, such as the `GeoIP`
    /// database, which never need to reach the local network.
    ///
    /// # Panics
    ///
    /// Panics if the TLS backend cannot be initialized.
    #[must_use]
    pub fn public_only() -> Self {
        Self::with_destinations(Destinations::Public)
    }

    /// Client that can reach the loopback servers tests stand up.
    #[cfg(test)]
    pub(crate) fn for_local_tests() -> Self {
        Self::with_destinations(Destinations::PublicPrivateAndLoopback)
    }

    fn with_destinations(destinations: Destinations) -> Self {
        let inner = HttpClientBuilder::new("antiwire-downloader/0.1.0")
            .destinations(destinations)
            // Custom lists and some mirrors are served over plain HTTP; an
            // HTTPS mirror still cannot redirect to HTTP.
            .https_only(false)
            .max_redirects(10)
            .connect_timeout(Duration::from_secs(10))
            .timeout(DOWNLOAD_DEADLINE)
            .build()
            .expect("download HTTP client");
        Self { inner }
    }
}
