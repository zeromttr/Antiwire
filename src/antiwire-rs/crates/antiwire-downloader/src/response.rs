//! Sending a download request and reading its body within the configured limits.

use antiwire_http::{HttpRequestBuilder, HttpResponse};
use futures_util::StreamExt;
use tokio::io::AsyncRead;
use tokio_util::io::StreamReader;

use crate::error::DownloadError;
use crate::limited_reader::ByteLimitedReader;
use crate::DownloadConfig;

/// Sends `request` and returns a successful response.
///
/// # Errors
///
/// [`DownloadError::IdleTimeout`] when no response arrives within
/// `config.idle_timeout`, or the request or status error otherwise.
pub(crate) async fn send(
    request: HttpRequestBuilder,
    config: &DownloadConfig,
) -> Result<HttpResponse, DownloadError> {
    match tokio::time::timeout(config.idle_timeout, request.send()).await {
        Ok(result) => Ok(result?.error_for_status()?),
        Err(_) => Err(DownloadError::IdleTimeout),
    }
}

/// The body of `response` as a reader that fails once more than `max_bytes`
/// have been read. Callers still time each read against the idle timeout.
pub(crate) fn limited_body(
    response: HttpResponse,
    max_bytes: u64,
) -> ByteLimitedReader<impl AsyncRead + Unpin> {
    let byte_stream = response
        .bytes_stream()
        .map(|result| result.map_err(std::io::Error::other));
    ByteLimitedReader::new(StreamReader::new(byte_stream), max_bytes)
}
