//! Environment resolution for the `TypeSafe` client.

use antiwire_http::reqwest;
use std::time::Duration;

use crate::error::Error;

/// Environment variable for the API key.
pub const API_KEY_ENV: &str = "TYPESAFE_API_KEY";
/// Environment variable for the API base URL.
pub const BASE_URL_ENV: &str = "TYPESAFE_BASE_URL";
/// Environment variable for the default model.
pub const DEFAULT_MODEL_ENV: &str = "TYPESAFE_DEFAULT_MODEL";

/// Default API root.
pub const DEFAULT_BASE_URL: &str = "https://api.typesafe.ai";
/// Default model name.
pub const DEFAULT_MODEL: &str = "jev-latest";
/// Default per-request timeout.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(10);

pub(crate) struct Settings {
    pub(crate) api_key: String,
    pub(crate) base_url: String,
    pub(crate) model: String,
    pub(crate) timeout: Duration,
}

impl std::fmt::Debug for Settings {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Settings")
            .field("api_key", &"<redacted>")
            .field("base_url", &self.base_url)
            .field("model", &self.model)
            .field("timeout", &self.timeout)
            .finish()
    }
}

pub(crate) fn process_env(name: &str) -> Option<String> {
    std::env::var(name).ok()
}

fn env_value(env: &dyn Fn(&str) -> Option<String>, name: &str) -> Option<String> {
    env(name)
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
}

pub(crate) fn resolve_settings(
    api_key: Option<String>,
    base_url: Option<String>,
    model: Option<String>,
    timeout: Option<Duration>,
    env: &dyn Fn(&str) -> Option<String>,
) -> Result<Settings, Error> {
    let api_key = match api_key {
        Some(key) => key,
        None => env_value(env, API_KEY_ENV).ok_or_else(|| {
            Error::client(format!(
                "No API key was provided. Pass api_key or set the {API_KEY_ENV} environment variable."
            ))
        })?,
    };
    let base_url = normalize_base_url(&match base_url {
        Some(url) => url,
        None => env_value(env, BASE_URL_ENV).unwrap_or_else(|| DEFAULT_BASE_URL.to_owned()),
    })?;
    let model = match model {
        Some(model) => model,
        None => env_value(env, DEFAULT_MODEL_ENV).unwrap_or_else(|| DEFAULT_MODEL.to_owned()),
    };
    let timeout = timeout.unwrap_or(DEFAULT_TIMEOUT);
    if timeout.is_zero() {
        return Err(Error::client(
            "timeout must be a positive, finite number of seconds.",
        ));
    }
    Ok(Settings {
        api_key,
        base_url,
        model,
        timeout,
    })
}

/// API root a [`crate::ClientBuilder`] without an explicit `base_url` connects to.
///
/// Callers that only need the endpoint (for example, its hostname) should use
/// this rather than keeping their own copy of the URL.
#[must_use]
pub fn resolved_base_url() -> String {
    resolve_base_url(&process_env)
}

fn resolve_base_url(env: &dyn Fn(&str) -> Option<String>) -> String {
    env_value(env, BASE_URL_ENV)
        .and_then(|url| normalize_base_url(&url).ok())
        .unwrap_or_else(|| DEFAULT_BASE_URL.to_owned())
}

fn normalize_base_url(base: &str) -> Result<String, Error> {
    let trimmed = base.trim_end_matches('/');
    let parsed = reqwest::Url::parse(trimmed)
        .map_err(|_| Error::client(format!("invalid base URL: {base}")))?;
    if parsed.cannot_be_a_base() {
        return Err(Error::client(format!("invalid base URL: {base}")));
    }
    // Every request carries the API key, so it only travels unencrypted to a
    // server on this machine, such as a local mock.
    match parsed.scheme() {
        "https" => {}
        "http" if is_loopback(&parsed) => {}
        _ => {
            return Err(Error::client(format!(
                "the API base URL must use HTTPS: {base}"
            )))
        }
    }
    Ok(trimmed.to_owned())
}

/// Whether `base_url` names this machine, which only a local mock does.
pub(crate) fn is_loopback_base(base_url: &str) -> bool {
    reqwest::Url::parse(base_url).is_ok_and(|url| is_loopback(&url))
}

fn is_loopback(url: &reqwest::Url) -> bool {
    let Some(host) = url.host_str() else {
        return false;
    };
    let host = host.trim_start_matches('[').trim_end_matches(']');
    host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback())
}

#[cfg(test)]
mod tests {
    use super::{
        is_loopback_base, normalize_base_url, process_env, resolve_settings, API_KEY_ENV,
        BASE_URL_ENV, DEFAULT_BASE_URL, DEFAULT_MODEL, DEFAULT_MODEL_ENV, DEFAULT_TIMEOUT,
    };
    use std::sync::Mutex;
    use std::time::Duration;

    #[test]
    fn explicit_values_win_over_environment_and_defaults() {
        let settings = resolve_settings(
            Some(" explicit ".to_owned()),
            Some("https://example.test/prefix///".to_owned()),
            Some("call-model".to_owned()),
            Some(Duration::from_secs(3)),
            &|name| Some(format!("env-{name}")),
        )
        .expect("settings");
        assert_eq!(settings.api_key, " explicit ");
        assert_eq!(settings.base_url, "https://example.test/prefix");
        assert_eq!(settings.model, "call-model");
        assert_eq!(settings.timeout, Duration::from_secs(3));
    }

    #[test]
    fn missing_values_fall_through_env_then_defaults() {
        let settings = resolve_settings(None, None, None, None, &|name| match name {
            API_KEY_ENV => Some(" from-env ".to_owned()),
            BASE_URL_ENV => Some("  ".to_owned()),
            _ => None,
        })
        .expect("settings");
        assert_eq!(settings.api_key, "from-env");
        assert_eq!(settings.base_url, DEFAULT_BASE_URL);
        assert_eq!(settings.model, DEFAULT_MODEL);
        assert_eq!(settings.timeout, DEFAULT_TIMEOUT);
    }

    #[test]
    fn resolved_base_url_matches_builder_resolution() {
        assert_eq!(super::resolve_base_url(&|_| None), DEFAULT_BASE_URL);
        assert_eq!(
            super::resolve_base_url(&|name| {
                (name == BASE_URL_ENV).then(|| " https://env.example/root/ ".to_owned())
            }),
            "https://env.example/root"
        );
        assert_eq!(
            super::resolve_base_url(&|_| Some("not a url".to_owned())),
            DEFAULT_BASE_URL
        );
    }

    #[test]
    fn whitespace_environment_values_are_ignored() {
        let error = resolve_settings(None, None, None, None, &|name| {
            (name == API_KEY_ENV).then(|| "   ".to_owned())
        })
        .expect_err("missing key");
        assert!(error.to_string().contains(API_KEY_ENV));
    }

    #[test]
    fn zero_timeout_is_rejected() {
        let error = resolve_settings(
            Some("key".to_owned()),
            None,
            None,
            Some(Duration::ZERO),
            &|_| None,
        )
        .expect_err("zero timeout");
        assert!(error.to_string().contains("positive, finite"));
    }

    #[test]
    #[allow(unsafe_code)]
    fn builder_reads_process_environment() {
        static ENV_LOCK: Mutex<()> = Mutex::new(());
        let _guard = ENV_LOCK.lock().expect("env lock");
        let previous = [
            (API_KEY_ENV, std::env::var(API_KEY_ENV).ok()),
            (BASE_URL_ENV, std::env::var(BASE_URL_ENV).ok()),
            (DEFAULT_MODEL_ENV, std::env::var(DEFAULT_MODEL_ENV).ok()),
        ];
        set_env(API_KEY_ENV, Some("env-key"));
        set_env(BASE_URL_ENV, Some("https://env.example/root/"));
        set_env(DEFAULT_MODEL_ENV, Some("env-model"));
        let settings = resolve_settings(None, None, None, None, &process_env).expect("env");
        for (key, value) in previous {
            set_env(key, value.as_deref());
        }
        assert_eq!(settings.api_key, "env-key");
        assert_eq!(settings.base_url, "https://env.example/root");
        assert_eq!(settings.model, "env-model");
    }

    fn set_env(key: &str, value: Option<&str>) {
        match value {
            Some(value) => {
                // SAFETY: `ENV_LOCK` is held, and these tests are the only
                // writers of the TypeSafe variables in this process.
                #[allow(unsafe_code)]
                unsafe {
                    std::env::set_var(key, value);
                }
            }
            None => {
                // SAFETY: `ENV_LOCK` is held, and these tests are the only
                // writers of the TypeSafe variables in this process.
                #[allow(unsafe_code)]
                unsafe {
                    std::env::remove_var(key);
                }
            }
        }
    }

    /// The API key travels with every request, so plain HTTP is refused unless
    /// the server is on this machine.
    #[test]
    fn plain_http_base_url_is_only_accepted_for_loopback() {
        assert!(normalize_base_url("http://api.example.com").is_err());
        assert!(normalize_base_url("http://192.168.1.5:8080").is_err());
        assert!(normalize_base_url("ftp://api.example.com").is_err());
        for local in [
            "http://127.0.0.1:9000",
            "http://localhost:9000",
            "http://[::1]:9000",
        ] {
            assert!(normalize_base_url(local).is_ok(), "{local}");
            assert!(is_loopback_base(local), "{local}");
        }
        assert!(normalize_base_url("https://api.example.com/").is_ok());
        assert!(!is_loopback_base("https://api.example.com"));
    }
}
