/// Result type for DNS operations that can fail with a [`DnsError`].
pub type Result<T> = std::result::Result<T, DnsError>;

/// Errors returned by the DNS resolver.
#[derive(Debug, thiserror::Error)]
#[cfg_attr(test, derive(Clone))]
pub enum DnsError {
    /// An upstream resolver returned an error or could not be reached.
    #[error("upstream resolver error: {0}")]
    Upstream(String),
    /// The DNS configuration was invalid.
    #[error("invalid DNS configuration: {0}")]
    Config(String),
    /// A client query was malformed or otherwise unacceptable.
    #[error("invalid query: {0}")]
    InvalidQuery(String),
    /// Binding a DNS socket failed.
    #[error("failed to bind dns socket: {0}")]
    Bind(String),
    /// Encoding a DNS message failed.
    #[error("failed to encode dns message: {0}")]
    Encode(String),
    /// The DNS listener task terminated unexpectedly.
    #[error("dns listener task failed: {0}")]
    Runtime(String),
    /// Reading or saving DNS state in the settings store failed.
    #[error("dns settings store failed: {0}")]
    Store(String),
    /// Shutdown has stopped the resolver for good; it is not started again.
    #[error("the DNS resolver has shut down")]
    ShutDown,
}

impl From<antiwire_store::StoreError> for DnsError {
    fn from(error: antiwire_store::StoreError) -> Self {
        Self::Store(error.to_string())
    }
}

impl From<antiwire_dns_redirect::RedirectError> for DnsError {
    fn from(error: antiwire_dns_redirect::RedirectError) -> Self {
        // A restore that was not confirmed is retried; the rest are the
        // redirect record's.
        if error.is_retryable() {
            Self::Runtime(error.to_string())
        } else {
            Self::Store(error.to_string())
        }
    }
}
