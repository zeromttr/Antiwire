//! Errors from building clients, checking destinations and reading responses.

use reqwest::Url;

/// A failure in a request made through this crate.
#[derive(Debug, thiserror::Error)]
pub enum HttpError {
    /// The URL is not one this client may request: an unsupported scheme, plain
    /// HTTP where HTTPS is required, or an address the destination policy refuses.
    ///
    /// `url` has its credentials, query and fragment removed, so the error can
    /// be logged without the secrets a URL sometimes carries.
    #[error("request to {url} refused: {reason}")]
    Refused { url: String, reason: String },
    /// The response body is larger than the caller allows.
    #[error("response body exceeds the {limit}-byte limit")]
    BodyTooLarge { limit: u64 },
    /// The request failed in transport, or the server answered with an error.
    #[error(transparent)]
    Request(#[from] reqwest::Error),
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
}

/// `url` without credentials, query or fragment.
fn redacted(url: &Url) -> String {
    let mut shown = url.clone();
    let _ = shown.set_username("");
    let _ = shown.set_password(None);
    shown.set_query(None);
    shown.set_fragment(None);
    shown.into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refusals_do_not_repeat_secrets_from_the_url() {
        let url =
            Url::parse("https://user:hunter2@hooks.example.com/in?token=abc#frag").expect("url");
        let message = HttpError::refused(&url, "not allowed").to_string();
        assert!(
            message.contains("https://hooks.example.com/in"),
            "{message}"
        );
        for secret in ["user", "hunter2", "token", "abc", "frag"] {
            assert!(!message.contains(secret), "{secret} leaked: {message}");
        }

        let unparseable = Url::parse("http://[bad").expect_err("invalid");
        let message = HttpError::unparseable(&unparseable).to_string();
        assert!(!message.contains("[bad"), "{message}");
    }
}
