//! HTTP download helpers for Antiwire blocklist synchronization.

mod client;
mod error;
mod gunzip;
mod hosts;
mod limited_reader;
mod raw;
mod response;
mod writer;

use std::path::{Path, PathBuf};
use std::time::Duration;

use antiwire_policy::HostsParserMode;
pub use client::DownloadClient;
pub use error::DownloadError;
pub use gunzip::gunzip_file;
pub use hosts::hashed_cache_needs_revalidation;

/// Limits and timeout for one download.
#[derive(Debug, Clone)]
pub struct DownloadConfig {
    pub max_bytes: u64,
    pub idle_timeout: Duration,
}

impl Default for DownloadConfig {
    fn default() -> Self {
        Self {
            max_bytes: antiwire_tuning::HOSTS_MAX_DOWNLOAD_BYTES as u64,
            idle_timeout: antiwire_tuning::HOSTS_DOWNLOAD_IDLE_TIMEOUT,
        }
    }
}

/// One hosts blocklist download target.
#[derive(Debug, Clone)]
pub struct HostsDownloadItem {
    pub name: String,
    pub urls: Vec<String>,
    pub hash_urls: Vec<String>,
    pub dest_path: PathBuf,
    pub parser_mode: HostsParserMode,
}

/// Result of one item in a batch download.
#[derive(Debug)]
pub struct HostsDownloadOutcome {
    pub name: String,
    pub result: Result<bool, DownloadError>,
}

impl DownloadClient {
    /// Downloads multiple hosts blocklists concurrently (bounded by `max_parallel`).
    pub async fn download_hosts_batch(
        &self,
        items: &[HostsDownloadItem],
        config: &DownloadConfig,
        max_parallel: usize,
    ) -> Vec<HostsDownloadOutcome> {
        hosts::download_hosts_batch(self, items, config, max_parallel).await
    }

    /// Downloads a raw (non-hosts-list) file to disk, streamed with no line
    /// parsing so binary content such as a gzip archive is preserved verbatim.
    /// The file is committed only when its SHA-256 equals `sha256`; on a
    /// mismatch the existing destination is left untouched.
    ///
    /// # Errors
    ///
    /// Returns [`DownloadError`] when the HTTP request fails, the stream stalls
    /// past `config.idle_timeout`, or the response exceeds `config.max_bytes`,
    /// and [`DownloadError::HashMismatch`] when the digest differs.
    pub async fn download_verified_file(
        &self,
        url: &str,
        dest_path: &Path,
        config: &DownloadConfig,
        sha256: &[u8; 32],
    ) -> Result<(), DownloadError> {
        raw::download_file(&self.inner, url, dest_path, config, Some(sha256)).await
    }

    /// Reads a small response body into memory, such as release metadata.
    ///
    /// # Errors
    ///
    /// Returns [`DownloadError`] when the request fails, stalls past
    /// `config.idle_timeout`, or the body exceeds `config.max_bytes`.
    pub async fn fetch_bytes(
        &self,
        url: &str,
        config: &DownloadConfig,
    ) -> Result<Vec<u8>, DownloadError> {
        hosts::fetch_limited_bytes(&self.inner, url, config, config.max_bytes).await
    }
}
