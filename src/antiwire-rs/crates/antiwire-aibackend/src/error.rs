//! SDK errors, server message extraction, and `Retry-After` parsing.

use antiwire_http::reqwest;
use std::fmt;
use std::time::Duration;

use reqwest::header::HeaderMap;
use serde_json::{Map, Value};
use thiserror::Error;
use time::format_description::well_known::Rfc2822;
use time::OffsetDateTime;

const MAX_ERROR_BODY_LENGTH: usize = 200;

/// Failure returned by [`TypeSafeClient`](crate::TypeSafeClient).
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Error {
    /// The request was rejected before it was sent, or the client was misconfigured.
    #[error("{0}")]
    Client(String),

    /// The server returned an HTTP error, or a successful body failed validation.
    #[error(transparent)]
    Api(Box<ApiError>),

    /// The request failed without an HTTP response.
    #[error("Connection error: {message}")]
    Connection {
        /// Transport error text.
        message: String,
    },

    /// The request exceeded its timeout.
    #[error("Request timed out (timeout={seconds}).")]
    Timeout {
        /// Configured timeout, in seconds.
        seconds: f64,
    },
}

impl Error {
    pub(crate) fn client(message: impl Into<String>) -> Self {
        Self::Client(message.into())
    }

    /// The HTTP error, when this failure came from a response.
    #[must_use]
    pub fn api(&self) -> Option<&ApiError> {
        match self {
            Self::Api(error) => Some(error),
            _ => None,
        }
    }

    /// Whether the failure is a timeout.
    #[must_use]
    pub fn is_timeout(&self) -> bool {
        matches!(self, Self::Timeout { .. })
    }
}

/// An unsuccessful HTTP response, or a success body that failed validation.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct ApiError {
    /// HTTP status code. Validation failures use the success status, usually 200.
    pub status: u16,
    /// Status class, or [`ApiErrorKind::InvalidResponse`].
    pub kind: ApiErrorKind,
    /// Server or validation message, without the status prefix.
    pub message: String,
    /// Decoded response body.
    pub body: ErrorBody,
    /// `x-typesafe-request-id`, when the server sent one.
    pub request_id: Option<String>,
    /// Parsed `Retry-After` / `retry-after-ms` delay.
    pub retry_after: Option<Duration>,
    /// `METHOD url` without user info, query, or fragment.
    pub endpoint: String,
    /// Dotted field path for [`ApiErrorKind::InvalidResponse`].
    pub field_path: Option<String>,
}

impl fmt::Display for ApiError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let status_message = if self.message.is_empty() {
            self.status.to_string()
        } else {
            format!("{} {}", self.status, self.message)
        };
        let with_endpoint = if self.endpoint.is_empty() {
            status_message
        } else {
            format!("{}: {status_message}", self.endpoint)
        };
        if let Some(request_id) = &self.request_id {
            write!(formatter, "{with_endpoint} (request_id={request_id})")
        } else {
            write!(formatter, "{with_endpoint}")
        }
    }
}

impl std::error::Error for ApiError {}

/// How an HTTP status maps onto an SDK error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ApiErrorKind {
    /// 400.
    BadRequest,
    /// 401.
    Authentication,
    /// 403.
    PermissionDenied,
    /// 404.
    NotFound,
    /// 422.
    UnprocessableEntity,
    /// 429.
    RateLimit,
    /// 5xx.
    Internal,
    /// Any other HTTP status.
    Other,
    /// The status was successful, but the body did not match the response type.
    InvalidResponse,
}

/// Body carried on an [`ApiError`].
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub enum ErrorBody {
    /// Empty body, or JSON `null`.
    Empty,
    /// Response text that was not JSON.
    Text(String),
    /// Decoded JSON value.
    Json(Value),
}

pub(crate) fn kind_for_status(status: u16) -> ApiErrorKind {
    match status {
        400 => ApiErrorKind::BadRequest,
        401 => ApiErrorKind::Authentication,
        403 => ApiErrorKind::PermissionDenied,
        404 => ApiErrorKind::NotFound,
        422 => ApiErrorKind::UnprocessableEntity,
        429 => ApiErrorKind::RateLimit,
        500..=599 => ApiErrorKind::Internal,
        _ => ApiErrorKind::Other,
    }
}

pub(crate) fn http_error(
    status: u16,
    bytes: &[u8],
    headers: &HeaderMap,
    endpoint: &str,
) -> ApiError {
    let body = decode_error_body(bytes);
    ApiError {
        status,
        kind: kind_for_status(status),
        message: message_from_body(&body),
        body,
        request_id: header_text(headers, "x-typesafe-request-id"),
        retry_after: parse_retry_after(headers, OffsetDateTime::now_utc())
            .and_then(duration_from_millis),
        endpoint: endpoint.to_owned(),
        field_path: None,
    }
}

pub(crate) fn invalid_response(
    status: u16,
    bytes: &[u8],
    request_id: Option<String>,
    endpoint: &str,
    field_path: &str,
) -> ApiError {
    ApiError {
        status,
        kind: ApiErrorKind::InvalidResponse,
        message: format!("Invalid response data at '{field_path}'."),
        body: decode_error_body(bytes),
        request_id,
        retry_after: None,
        endpoint: endpoint.to_owned(),
        field_path: Some(field_path.to_owned()),
    }
}

pub(crate) fn header_text(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(ToOwned::to_owned)
}

pub(crate) fn decode_error_body(bytes: &[u8]) -> ErrorBody {
    if bytes.is_empty() {
        return ErrorBody::Empty;
    }
    match serde_json::from_slice::<Value>(bytes) {
        Ok(Value::Null) => ErrorBody::Empty,
        Ok(value) => ErrorBody::Json(value),
        Err(_) => ErrorBody::Text(String::from_utf8_lossy(bytes).into_owned()),
    }
}

fn message_from_body(body: &ErrorBody) -> String {
    if let Some(message) = extract_message(body) {
        return message;
    }
    if matches!(body, ErrorBody::Empty) {
        return "status code (no body)".to_owned();
    }
    truncate(&fallback_raw(body))
}

fn extract_message(body: &ErrorBody) -> Option<String> {
    let extracted = match body {
        ErrorBody::Text(text) | ErrorBody::Json(Value::String(text)) => Some(text.clone()),
        ErrorBody::Json(Value::Object(map)) => extract_object(map),
        ErrorBody::Empty | ErrorBody::Json(_) => None,
    };
    extracted.filter(|text| !text.is_empty())
}

fn extract_object(map: &Map<String, Value>) -> Option<String> {
    if let Some(Value::String(text)) = map.get("error") {
        return Some(text.clone());
    }
    if let Some(nested) = map.get("error").and_then(Value::as_object) {
        if let Some(Value::String(text)) = nested.get("message") {
            return Some(text.clone());
        }
    }
    if let Some(Value::String(text)) = map.get("message") {
        return Some(text.clone());
    }
    match map.get("detail") {
        Some(Value::String(text)) => Some(text.clone()),
        Some(Value::Object(nested)) => nested
            .get("message")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned),
        Some(Value::Array(entries)) => detail_list(entries),
        _ => None,
    }
}

fn detail_list(entries: &[Value]) -> Option<String> {
    let mut parts = Vec::new();
    for entry in entries {
        let Some(object) = entry.as_object() else {
            continue;
        };
        let Some(message) = object.get("msg").and_then(Value::as_str) else {
            continue;
        };
        let path = object.get("loc").map(format_loc).unwrap_or_default();
        if path.is_empty() {
            parts.push(message.to_owned());
        } else {
            parts.push(format!("{path}: {message}"));
        }
    }
    if parts.is_empty() {
        None
    } else {
        Some(parts.join("; "))
    }
}

fn format_loc(location: &Value) -> String {
    let Some(items) = location.as_array() else {
        return String::new();
    };
    items
        .iter()
        .map(loc_item)
        .filter(|item| item != "body")
        .collect::<Vec<_>>()
        .join(".")
}

fn loc_item(value: &Value) -> String {
    match value {
        Value::String(text) => text.clone(),
        Value::Number(number) => number.to_string(),
        Value::Bool(flag) => flag.to_string(),
        Value::Null => "null".to_owned(),
        other => other.to_string(),
    }
}

fn fallback_raw(body: &ErrorBody) -> String {
    match body {
        ErrorBody::Empty => String::new(),
        ErrorBody::Text(text) | ErrorBody::Json(Value::String(text)) => text.clone(),
        ErrorBody::Json(value) => serde_json::to_string(value).unwrap_or_default(),
    }
}

fn truncate(raw: &str) -> String {
    let mut chars = raw.chars();
    let mut out = String::new();
    for _ in 0..MAX_ERROR_BODY_LENGTH {
        match chars.next() {
            Some(ch) => out.push(ch),
            None => return out,
        }
    }
    if chars.next().is_some() {
        out.push('…');
    }
    out
}

/// `Retry-After` delay in milliseconds.
///
/// `retry-after-ms` is checked first. Numeric `Retry-After` is seconds. A
/// non-numeric `Retry-After` is an HTTP-date.
pub(crate) fn parse_retry_after(headers: &HeaderMap, now: OffsetDateTime) -> Option<f64> {
    const CANDIDATES: &[(&str, f64)] = &[("retry-after-ms", 1.0), ("retry-after", 1000.0)];
    for (name, multiplier) in CANDIDATES {
        let Some(raw) = header_text(headers, name) else {
            continue;
        };
        match parse_header_f64(&raw) {
            Ok(value) if value.is_finite() && value >= 0.0 => {
                let delay = value * multiplier;
                if delay.is_finite() {
                    return Some(delay);
                }
            }
            Ok(value) if value.is_finite() && *name == "retry-after" => return None,
            Err(()) if *name == "retry-after" => {
                if let Some(delay) = http_date_delay_ms(&raw, now) {
                    return Some(delay);
                }
            }
            Ok(_) | Err(()) => {}
        }
    }
    None
}

fn parse_header_f64(raw: &str) -> Result<f64, ()> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Ok(0.0);
    }
    trimmed.parse::<f64>().map_err(|_| ())
}

fn http_date_delay_ms(raw: &str, now: OffsetDateTime) -> Option<f64> {
    let parsed = OffsetDateTime::parse(raw.trim(), &Rfc2822).ok()?;
    let delta_nanos = parsed
        .unix_timestamp_nanos()
        .saturating_sub(now.unix_timestamp_nanos());
    if delta_nanos <= 0 {
        return Some(0.0);
    }
    Some(nanos_to_ms(delta_nanos))
}

#[allow(clippy::cast_precision_loss)]
fn nanos_to_ms(nanos: i128) -> f64 {
    (nanos as f64) / 1_000_000.0
}

fn duration_from_millis(millis: f64) -> Option<Duration> {
    if !millis.is_finite() || millis < 0.0 {
        return None;
    }
    Duration::try_from_secs_f64(millis / 1000.0).ok()
}

#[cfg(test)]
mod tests {
    use super::{
        decode_error_body, http_error, kind_for_status, message_from_body, parse_retry_after,
        ApiErrorKind, ErrorBody,
    };
    use antiwire_http::reqwest;
    use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
    use serde_json::json;
    use time::format_description::well_known::Rfc2822;
    use time::OffsetDateTime;

    fn message_of(body: &[u8]) -> String {
        message_from_body(&decode_error_body(body))
    }

    fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for (name, value) in pairs {
            let name = HeaderName::from_bytes(name.as_bytes()).expect("header name");
            map.insert(name, HeaderValue::from_str(value).expect("header"));
        }
        map
    }

    #[test]
    fn extracts_messages_in_python_order() {
        assert_eq!(
            message_of(br#"{"error":"error","message":"message","detail":"detail"}"#),
            "error"
        );
        assert_eq!(
            message_of(br#"{"error":{"message":"nested error"},"message":"message"}"#),
            "nested error"
        );
        assert_eq!(
            message_of(br#"{"message":"message","detail":"detail"}"#),
            "message"
        );
        assert_eq!(message_of(br#"{"detail":"detail"}"#), "detail");
        assert_eq!(
            message_of(br#"{"detail":{"message":"nested detail"}}"#),
            "nested detail"
        );
        assert_eq!(
            message_of(
                br#"{"detail":[{"loc":["body","questions","q","score","criteria",0],"msg":"Invalid"},{"msg":"Missing"},{}]}"#
            ),
            "questions.q.score.criteria.0: Invalid; Missing"
        );
        assert_eq!(message_of(b"plain text"), "plain text");
        assert_eq!(
            message_of(br#"{"unexpected":true}"#),
            r#"{"unexpected":true}"#
        );
    }

    #[test]
    fn empty_error_string_falls_back_to_raw_body() {
        let body = br#"{"error":"","message":"ignored"}"#;
        assert_eq!(message_of(body), r#"{"error":"","message":"ignored"}"#);
    }

    #[test]
    fn empty_and_non_object_bodies() {
        assert_eq!(message_of(b""), "status code (no body)");
        assert_eq!(message_of(b"null"), "status code (no body)");
        assert_eq!(message_of(b"[]"), "[]");
        assert_eq!(message_of(b"42"), "42");
        let mut lossy = b"not JSON: ".to_vec();
        lossy.push(0xff);
        assert_eq!(message_of(&lossy), "not JSON: \u{fffd}");
    }

    #[test]
    fn long_plain_text_is_kept_and_unstructured_json_is_truncated() {
        let plain = "x".repeat(201);
        assert_eq!(message_of(plain.as_bytes()), plain);
        let raw = format!(r#"{{"unknown":"{}"}}"#, "x".repeat(201));
        let message = message_of(raw.as_bytes());
        assert_eq!(message.chars().count(), 201);
        assert!(message.ends_with('…'));
        assert!(message.starts_with(r#"{"unknown":"xxx"#));
    }

    #[test]
    fn status_kind_mapping() {
        assert_eq!(kind_for_status(400), ApiErrorKind::BadRequest);
        assert_eq!(kind_for_status(401), ApiErrorKind::Authentication);
        assert_eq!(kind_for_status(403), ApiErrorKind::PermissionDenied);
        assert_eq!(kind_for_status(404), ApiErrorKind::NotFound);
        assert_eq!(kind_for_status(422), ApiErrorKind::UnprocessableEntity);
        assert_eq!(kind_for_status(429), ApiErrorKind::RateLimit);
        assert_eq!(kind_for_status(500), ApiErrorKind::Internal);
        assert_eq!(kind_for_status(599), ApiErrorKind::Internal);
        assert_eq!(kind_for_status(408), ApiErrorKind::Other);
        assert_eq!(kind_for_status(302), ApiErrorKind::Other);
    }

    #[test]
    fn http_error_includes_request_id_and_retry_after() {
        let error = http_error(
            429,
            br#"{"detail":{"message":"Server explanation"}}"#,
            &headers(&[
                ("x-typesafe-request-id", "req_123"),
                ("retry-after-ms", "125"),
            ]),
            "GET https://api.typesafe.ai/v1/models",
        );
        assert_eq!(error.kind, ApiErrorKind::RateLimit);
        assert_eq!(
            error.retry_after,
            Some(std::time::Duration::from_millis(125))
        );
        assert_eq!(
            error.to_string(),
            "GET https://api.typesafe.ai/v1/models: 429 Server explanation (request_id=req_123)"
        );
        assert_eq!(
            error.body,
            ErrorBody::Json(json!({"detail": {"message": "Server explanation"}}))
        );
    }

    #[test]
    fn parses_retry_after_numbers() {
        let now = OffsetDateTime::from_unix_timestamp(1_000_000).expect("timestamp");
        let cases = [
            (vec![], None),
            (vec![("retry-after", "bad")], None),
            (vec![("retry-after", "-1")], None),
            (
                vec![("retry-after-ms", "NaN"), ("retry-after", "1.5")],
                Some(1500.0),
            ),
            (
                vec![("retry-after-ms", "-1"), ("retry-after", "2")],
                Some(2000.0),
            ),
            (vec![("retry-after", "")], Some(0.0)),
            (vec![("retry-after-ms", "inf")], None),
            (
                vec![("retry-after-ms", "bad"), ("retry-after", "2")],
                Some(2000.0),
            ),
            (vec![("retry-after", "1e308")], None),
            (
                vec![("retry-after-ms", "0"), ("retry-after", "50")],
                Some(0.0),
            ),
            (vec![("retry-after-ms", "125")], Some(125.0)),
        ];
        for (pairs, expected) in cases {
            assert_eq!(
                parse_retry_after(&headers(&pairs), now),
                expected,
                "{pairs:?}"
            );
        }
    }

    #[test]
    fn parses_http_date_retry_after() {
        let now = OffsetDateTime::from_unix_timestamp(1_000_000).expect("timestamp");
        let future = (now + time::Duration::seconds(10))
            .format(&Rfc2822)
            .expect("format");
        let past = (now - time::Duration::seconds(10))
            .format(&Rfc2822)
            .expect("format");
        assert_eq!(
            parse_retry_after(&headers(&[("retry-after", &future)]), now),
            Some(10_000.0)
        );
        assert_eq!(
            parse_retry_after(&headers(&[("retry-after", &past)]), now),
            Some(0.0)
        );
    }
}
