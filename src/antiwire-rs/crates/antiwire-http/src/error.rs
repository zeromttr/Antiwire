//! Errors from building clients, checking destinations and reading responses.

use reqwest::{StatusCode, Url};

use crate::resolver::PolicyRefused;

/// A failure in a request made through this crate.
///
/// Every variant reduces URLs to `scheme://host[:port]` (credentials, path,
/// query, and fragment removed) and strips unredacted URLs from underlying
/// transport errors so secrets carried in URLs cannot leak into logs.
#[derive(Debug, thiserror::Error)]
pub enum HttpError {
    /// The URL, resolved address, or redirect target is not allowed by this
    /// client's policy.
    #[error("request to {url} refused: {reason}")]
    Refused { url: String, reason: String },
    /// The response body is larger than the caller allows.
    #[error("response body exceeds the {limit}-byte limit")]
    BodyTooLarge { limit: u64 },
    /// The request exceeded its configured timeout.
    #[error("{}", format_timeout(url.as_deref()))]
    Timeout { url: Option<String> },
    /// The request failed in transport, or the server answered with an error
    /// status.
    #[error("{}", format_request_error(url.as_deref(), source))]
    Request {
        url: Option<String>,
        #[source]
        source: reqwest::Error,
    },
}

impl HttpError {
    pub(crate) fn refused(url: &Url, reason: impl Into<String>) -> Self {
        Self::Refused {
            url: redacted(url),
            reason: reason.into(),
        }
    }

    /// A URL that does not parse is not echoed back: it may still hold a secret.
    pub(crate) fn unparseable(error: &impl std::fmt::Display) -> Self {
        Self::Refused {
            url: "(unparseable URL)".to_owned(),
            reason: format!("invalid URL: {error}"),
        }
    }

    pub(crate) fn timeout(url: &Url) -> Self {
        Self::Timeout {
            url: Some(redacted(url)),
        }
    }

    /// Converts a `reqwest::Error`, stripping its unredacted URL and promoting
    /// [`PolicyRefused`] resolver rejections into [`Self::Refused`].
    pub(crate) fn from_reqwest(error: reqwest::Error, fallback_url: Option<&Url>) -> Self {
        let shown_url = error
            .url()
            .map(redacted)
            .or_else(|| fallback_url.map(redacted));
        if let Some(reason) = find_policy_refusal(&error) {
            return Self::Refused {
                url: shown_url.unwrap_or_else(|| "(unknown URL)".to_owned()),
                reason,
            };
        }
        Self::Request {
            url: shown_url,
            source: error.without_url(),
        }
    }

    /// Whether the request failed because a timeout elapsed.
    #[must_use]
    pub fn is_timeout(&self) -> bool {
        matches!(self, Self::Timeout { .. })
            || matches!(self, Self::Request { source, .. } if source.is_timeout())
    }

    /// HTTP status code when the error came from an unsuccessful status.
    #[must_use]
    pub fn status(&self) -> Option<StatusCode> {
        match self {
            Self::Request { source, .. } => source.status(),
            _ => None,
        }
    }
}

/// Reduces `url` to `scheme://host[:port]`, omitting userinfo, path, query,
/// and fragment so tokens carried in any of those parts never reach logs.
pub(crate) fn redacted(url: &Url) -> String {
    match (url.host_str(), url.port()) {
        (Some(host), Some(port)) => format!("{}://{host}:{port}", url.scheme()),
        (Some(host), None) => format!("{}://{host}", url.scheme()),
        (None, _) => format!("{}:(no host)", url.scheme()),
    }
}

fn format_timeout(url: Option<&str>) -> String {
    match url {
        Some(url) => format!("request to {url} timed out"),
        None => "request timed out".to_owned(),
    }
}

fn format_request_error(url: Option<&str>, source: &reqwest::Error) -> String {
    match url {
        Some(url) => format!("{source} ({url})"),
        None => source.to_string(),
    }
}

fn find_policy_refusal(error: &(dyn std::error::Error + 'static)) -> Option<String> {
    let mut current = error.source();
    while let Some(source) = current {
        if let Some(refused) = source.downcast_ref::<PolicyRefused>() {
            return Some(refused.0.clone());
        }
        current = source.source();
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refusals_do_not_repeat_secrets_from_the_url() {
        let url = Url::parse(
            "https://user:hunter2@hooks.example.com:8443/services/T1/B2/SECRET?token=abc#frag",
        )
        .expect("url");
        let message = HttpError::refused(&url, "not allowed").to_string();
        assert!(
            message.contains("https://hooks.example.com:8443"),
            "{message}"
        );
        for secret in [
            "user", "hunter2", "services", "SECRET", "token", "abc", "frag",
        ] {
            assert!(!message.contains(secret), "{secret} leaked: {message}");
        }

        let file_url = Url::parse("file:///Users/alice/secret.key").expect("file url");
        let file_msg = HttpError::refused(&file_url, "unsupported scheme").to_string();
        assert!(file_msg.contains("file:(no host)"), "{file_msg}");
        assert!(!file_msg.contains("secret.key"), "{file_msg}");

        let unparseable = Url::parse("http://[bad").expect_err("invalid");
        let message = HttpError::unparseable(&unparseable).to_string();
        assert!(!message.contains("[bad"), "{message}");
    }

    #[test]
    fn timeout_errors_redact_secrets_and_report_is_timeout() {
        let url = Url::parse("https://user:pass@api.example.com/hook/SECRET?k=v").expect("url");
        let error = HttpError::timeout(&url);
        assert!(error.is_timeout());
        let shown = format!("{error} / {error:?}");
        assert!(shown.contains("https://api.example.com"), "{shown}");
        for secret in ["user", "pass", "SECRET", "k=v"] {
            assert!(!shown.contains(secret), "{secret} leaked: {shown}");
        }
    }
}
