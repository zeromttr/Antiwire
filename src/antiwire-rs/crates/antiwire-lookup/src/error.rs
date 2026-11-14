/// Failure while reading an official registration record.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The input was empty or not a hostname.
    #[error("domain must be a hostname without a scheme or path")]
    InvalidDomain,

    /// The registry answered and has no registration for this name.
    #[error("no registration found for {0}")]
    NotFound(String),

    /// The registry asked the client to slow down.
    #[error("registry rate limited the lookup")]
    RateLimited,

    /// IANA lists neither an HTTPS RDAP service nor a WHOIS server for the TLD.
    #[error("no official RDAP or WHOIS server for .{0}")]
    NoAuthority(String),

    /// The bootstrap file or the registry record could not be read.
    #[error("registration lookup failed: {0}")]
    Transport(String),

    /// The registry responded, but the record was not a usable RDAP or WHOIS document.
    #[error("registry returned an unreadable record")]
    Malformed,
}

impl From<antiwire_http::HttpError> for Error {
    fn from(error: antiwire_http::HttpError) -> Self {
        Self::Transport(error.to_string())
    }
}
