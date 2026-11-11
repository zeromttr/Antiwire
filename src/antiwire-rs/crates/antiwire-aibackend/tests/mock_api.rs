//! Mock-server coverage for the public client.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use antiwire_aibackend::{
    Answer, ApiErrorKind, CallOverrides, Choice, Error, JsonContent, Noul, Questions, RetryPolicy,
    Score, TypeSafeClient,
};
use serde::Deserialize;
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;

#[derive(Clone)]
struct Recorded {
    method: String,
    path: String,
    headers: HashMap<String, String>,
    body: Vec<u8>,
}

struct MockReply {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
    delay: Duration,
}

struct Mock {
    base_url: String,
    requests: Arc<Mutex<Vec<Recorded>>>,
    handle: JoinHandle<()>,
}

impl Drop for Mock {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

impl Mock {
    async fn start(handler: impl Fn(&Recorded) -> MockReply + Send + Sync + 'static) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let address = listener.local_addr().expect("addr");
        let requests = Arc::new(Mutex::new(Vec::new()));
        let recorded = Arc::clone(&requests);
        let handler = Arc::new(handler);
        let handle = tokio::spawn(async move {
            loop {
                let Ok((socket, _)) = listener.accept().await else {
                    break;
                };
                let recorded = Arc::clone(&recorded);
                let handler = Arc::clone(&handler);
                tokio::spawn(async move {
                    let _ = read_request(socket, &recorded, handler.as_ref()).await;
                });
            }
        });
        Self {
            base_url: format!("http://{address}"),
            requests,
            handle,
        }
    }

    fn requests(&self) -> Vec<Recorded> {
        self.requests.lock().expect("requests").clone()
    }
}

async fn read_request(
    mut socket: TcpStream,
    recorded: &Mutex<Vec<Recorded>>,
    handler: &(impl Fn(&Recorded) -> MockReply + Send + Sync),
) -> std::io::Result<()> {
    let request = read_http(&mut socket).await?;
    recorded.lock().expect("requests").push(request.clone());
    let reply = handler(&request);
    if !reply.delay.is_zero() {
        tokio::time::sleep(reply.delay).await;
    }
    write_http(&mut socket, &reply).await
}

async fn read_http(socket: &mut TcpStream) -> std::io::Result<Recorded> {
    let mut buf = Vec::new();
    let mut tmp = [0_u8; 2048];
    let header_end = loop {
        let read = socket.read(&mut tmp).await?;
        if read == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "eof before headers",
            ));
        }
        buf.extend_from_slice(&tmp[..read]);
        if let Some(position) = buf.windows(4).position(|window| window == b"\r\n\r\n") {
            break position;
        }
    };
    let header_text = String::from_utf8_lossy(&buf[..header_end]);
    let mut lines = header_text.split("\r\n");
    let mut request_line = lines.next().unwrap_or("").split_whitespace();
    let method = request_line.next().unwrap_or("").to_owned();
    let path = request_line.next().unwrap_or("").to_owned();
    let mut headers = HashMap::new();
    for line in lines {
        if let Some((name, value)) = line.split_once(':') {
            headers.insert(name.trim().to_ascii_lowercase(), value.trim().to_owned());
        }
    }
    let content_length = headers
        .get("content-length")
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(0);
    let body_at = header_end + 4;
    while buf.len() < body_at + content_length {
        let read = socket.read(&mut tmp).await?;
        if read == 0 {
            break;
        }
        buf.extend_from_slice(&tmp[..read]);
    }
    let body = buf
        .get(body_at..body_at + content_length)
        .unwrap_or_default()
        .to_vec();
    Ok(Recorded {
        method,
        path,
        headers,
        body,
    })
}

async fn write_http(socket: &mut TcpStream, reply: &MockReply) -> std::io::Result<()> {
    let mut head = format!(
        "HTTP/1.1 {} status\r\nconnection: close\r\ncontent-length: {}\r\n",
        reply.status,
        reply.body.len()
    );
    for (name, value) in &reply.headers {
        head.push_str(name);
        head.push(':');
        head.push(' ');
        head.push_str(value);
        head.push_str("\r\n");
    }
    head.push_str("\r\n");
    socket.write_all(head.as_bytes()).await?;
    socket.write_all(&reply.body).await?;
    socket.flush().await
}

#[allow(clippy::needless_pass_by_value)]
fn json_reply(status: u16, body: Value, headers: &[(&str, &str)]) -> MockReply {
    MockReply {
        status,
        headers: headers
            .iter()
            .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
            .collect(),
        body: serde_json::to_vec(&body).expect("json"),
        delay: Duration::ZERO,
    }
}

fn client(base_url: &str, retry: RetryPolicy, timeout: Duration) -> TypeSafeClient {
    TypeSafeClient::builder()
        .api_key("test-key")
        .base_url(base_url)
        .model("jev-latest")
        .timeout(timeout)
        .retry(retry)
        .header("X-Team", "default")
        .build()
        .expect("client")
}

fn fast_retry() -> RetryPolicy {
    RetryPolicy {
        backoff_initial: 0.0,
        backoff_max: 0.0,
        ..RetryPolicy::default()
    }
}

fn question() -> Questions<'static> {
    Questions::new().ask(
        "billing",
        Noul::new().instructions(JsonContent::text("Is this about billing?")),
    )
}

fn sample_response() -> Value {
    json!({
        "model": "jev-latest",
        "usage": {"input_tokens": 12, "output_tokens": 3},
        "answers": {
            "billing": {"type": "noul", "noul": 0.98},
            "tone": {
                "type": "choice",
                "choice": "friendly",
                "confidence": 0.9,
                "probabilities": {"friendly": 0.9, "hostile": 0.1}
            },
            "quality": {
                "type": "score",
                "score": 1.7,
                "confidence": 0.8,
                "legend": {"0": "bad", "1": "ok", "2": "great"},
                "probabilities": {"0": 0.1, "1": 0.1, "2": 0.8}
            }
        }
    })
}

#[tokio::test]
async fn happy_path_sends_protected_headers_and_parses_answers() {
    let mock = Mock::start(|request| {
        assert_eq!(request.method, "POST");
        assert_eq!(request.path, "/v1/systemone");
        assert_eq!(
            request.headers.get("authorization").map(String::as_str),
            Some("Bearer test-key")
        );
        assert_eq!(
            request.headers.get("accept").map(String::as_str),
            Some("application/json")
        );
        assert_eq!(
            request.headers.get("content-type").map(String::as_str),
            Some("application/json")
        );
        assert!(request
            .headers
            .get("user-agent")
            .is_some_and(|value| value.starts_with("antiwire-aibackend/")));
        assert_eq!(
            request.headers.get("x-typesafe-sdk"),
            request.headers.get("user-agent")
        );
        assert!(request
            .headers
            .get("x-typesafe-runtime")
            .is_some_and(|value| value.starts_with("rust (")));
        assert!(!request.headers.contains_key("x-typesafe-retry-count"));
        assert_eq!(
            request.headers.get("x-team").map(String::as_str),
            Some("call")
        );
        json_reply(
            200,
            sample_response(),
            &[("x-typesafe-request-id", "req-happy")],
        )
    })
    .await;
    let sdk = client(&mock.base_url, fast_retry(), Duration::from_secs(2));
    let questions = Questions::new()
        .ask(
            "billing",
            Noul::new().instructions(JsonContent::text("Is this about billing?")),
        )
        .ask(
            "tone",
            Choice::new()
                .instructions(JsonContent::text("Tone?"))
                .option_null("friendly")
                .option_null("hostile"),
        )
        .ask(
            "quality",
            Score::new()
                .criterion_text("bad")
                .criterion_text("ok")
                .criterion_text("great"),
        );
    let overrides = CallOverrides::default()
        .header("Authorization", "must-not-win")
        .header("x-team", "call")
        .header("x-typesafe-retry-count", "99");
    let response = sdk
        .system_one_with(
            &JsonContent::text("I was charged twice."),
            &questions,
            &overrides,
        )
        .await
        .expect("system one");
    assert_eq!(response.request_id(), Some("req-happy"));
    assert_eq!(response.model, "jev-latest");
    match response.get("billing") {
        Some(Answer::Noul(answer)) => assert!((answer.noul - 0.98).abs() < 1e-9),
        other => panic!("billing answer: {other:?}"),
    }
    assert_eq!(
        response.choices().next().expect("choice").1.choice,
        "friendly"
    );
    let score = response.scores().next().expect("score").1.score;
    assert!((score - 1.7).abs() < 1e-9);
    let sent: Value = serde_json::from_slice(&mock.requests()[0].body).expect("body");
    assert_eq!(sent["model"], "jev-latest");
    assert_eq!(
        sent["questions"]["tone"]["criteria"]["friendly"],
        Value::Null
    );
}

#[tokio::test]
async fn maps_401_429_and_500() {
    for (status, kind) in [
        (401, ApiErrorKind::Authentication),
        (429, ApiErrorKind::RateLimit),
        (500, ApiErrorKind::Internal),
    ] {
        let mock = Mock::start(move |_| {
            json_reply(
                status,
                json!({"message": "nope"}),
                &[
                    ("x-typesafe-request-id", "req-status"),
                    ("retry-after-ms", "125"),
                ],
            )
        })
        .await;
        let sdk = client(
            &mock.base_url,
            RetryPolicy {
                max_retries: 0,
                ..fast_retry()
            },
            Duration::from_secs(2),
        );
        let error = sdk.models().list().await.expect_err("status");
        let api = error.api().expect("api");
        assert_eq!(api.status, status);
        assert_eq!(api.kind, kind);
        assert_eq!(api.message, "nope");
        assert_eq!(api.request_id.as_deref(), Some("req-status"));
        assert_eq!(api.retry_after, Some(Duration::from_millis(125)));
        assert_eq!(mock.requests().len(), 1);
        assert!(error.to_string().contains("req-status"));
    }
}

#[tokio::test]
async fn retries_server_errors_and_sends_retry_count() {
    let attempts = Arc::new(Mutex::new(0_u32));
    let seen = Arc::clone(&attempts);
    let mock = Mock::start(move |_| {
        let mut count = seen.lock().expect("count");
        *count += 1;
        let attempt = *count;
        drop(count);
        if attempt < 3 {
            json_reply(
                503,
                json!({"message": format!("attempt {attempt}")}),
                &[("retry-after-ms", "0")],
            )
        } else {
            json_reply(200, json!({"models": []}), &[])
        }
    })
    .await;
    let sdk = client(&mock.base_url, fast_retry(), Duration::from_secs(2));
    let response = sdk.models().list().await.expect("recovered");
    assert!(response.models.is_empty());
    let headers = mock
        .requests()
        .iter()
        .map(|request| request.headers.get("x-typesafe-retry-count").cloned())
        .collect::<Vec<_>>();
    assert_eq!(
        headers,
        vec![None, Some("1".to_owned()), Some("2".to_owned())]
    );
    assert_eq!(*attempts.lock().expect("count"), 3);
}

#[tokio::test]
async fn honors_retry_after() {
    let seen = Arc::new(Mutex::new(Vec::<Instant>::new()));
    let stamps = Arc::clone(&seen);
    let mock = Mock::start(move |_| {
        stamps.lock().expect("stamps").push(Instant::now());
        let attempt = stamps.lock().expect("stamps").len();
        if attempt == 1 {
            json_reply(
                429,
                json!({"message": "slow"}),
                &[("retry-after-ms", "300")],
            )
        } else {
            json_reply(200, sample_response(), &[])
        }
    })
    .await;
    let sdk = client(
        &mock.base_url,
        // The server's delay is honoured up to `backoff_max`, so the cap sits
        // above it; a zero initial backoff keeps the wait the server's.
        RetryPolicy {
            backoff_initial: 0.0,
            backoff_max: 1.0,
            ..RetryPolicy::default()
        },
        Duration::from_secs(2),
    );
    sdk.system_one(&JsonContent::text("x"), &question())
        .await
        .expect("recovered");
    let stamps = seen.lock().expect("stamps");
    assert_eq!(stamps.len(), 2);
    assert!(stamps[1].duration_since(stamps[0]) >= Duration::from_millis(200));
}

#[tokio::test]
async fn per_call_timeout_overrides_the_client_timeout() {
    let mock = Mock::start(|_| MockReply {
        status: 200,
        headers: Vec::new(),
        body: serde_json::to_vec(&sample_response()).expect("json"),
        delay: Duration::from_millis(500),
    })
    .await;
    let sdk = client(
        &mock.base_url,
        RetryPolicy {
            max_retries: 0,
            ..fast_retry()
        },
        Duration::from_secs(5),
    );
    let started = Instant::now();
    let error = sdk
        .system_one_with(
            &JsonContent::text("x"),
            &question(),
            &CallOverrides {
                timeout: Some(Duration::from_millis(150)),
                ..CallOverrides::default()
            },
        )
        .await
        .expect_err("timeout");
    assert!(error.is_timeout(), "{error}");
    assert!(started.elapsed() < Duration::from_millis(1_500));

    let slow_client = client(
        &mock.base_url,
        RetryPolicy {
            max_retries: 0,
            ..fast_retry()
        },
        Duration::from_millis(100),
    );
    slow_client
        .system_one_with(
            &JsonContent::text("x"),
            &question(),
            &CallOverrides {
                timeout: Some(Duration::from_secs(2)),
                ..CallOverrides::default()
            },
        )
        .await
        .expect("longer override wins");
}

#[tokio::test]
async fn drops_unknown_answers_and_keeps_them_in_the_raw_body() {
    let body = json!({
        "model": "test",
        "usage": {"input_tokens": 1, "output_tokens": 1},
        "answers": {
            "billing": {"type": "noul", "noul": 0.4},
            "mystery": {"type": "aurora", "value": 3}
        }
    });
    let mock =
        Mock::start(move |_| json_reply(200, body.clone(), &[("x-typesafe-request-id", "req-9")]))
            .await;
    let response = client(&mock.base_url, fast_retry(), Duration::from_secs(2))
        .system_one(&JsonContent::text("x"), &question())
        .await
        .expect("response");
    assert!(response.get("mystery").is_none());
    assert!(matches!(response.get("billing"), Some(Answer::Noul(_))));
    assert!(std::str::from_utf8(response.raw_body())
        .expect("utf8")
        .contains("aurora"));
}

#[tokio::test]
async fn extra_body_overrides_model_and_appends_fields() {
    let mock = Mock::start(|_| json_reply(200, sample_response(), &[])).await;
    let mut extra = serde_json::Map::new();
    extra.insert("model".to_owned(), json!("override-model"));
    extra.insert("beam_width".to_owned(), json!(4));
    extra.insert("nullable".to_owned(), Value::Null);
    client(&mock.base_url, fast_retry(), Duration::from_secs(2))
        .system_one_with(
            &JsonContent::text("hi"),
            &question(),
            &CallOverrides {
                model: Some("call-model"),
                extra_body: Some(&extra),
                ..CallOverrides::default()
            },
        )
        .await
        .expect("response");
    let sent: Value = serde_json::from_slice(&mock.requests()[0].body).expect("body");
    assert_eq!(
        sent,
        json!({
            "state": "hi",
            "model": "override-model",
            "questions": {"billing": {"type": "noul", "instructions": "Is this about billing?"}},
            "beam_width": 4,
            "nullable": null
        })
    );
}

#[tokio::test]
async fn lists_models() {
    let mock = Mock::start(|request| {
        assert_eq!(request.method, "GET");
        assert_eq!(request.path, "/v1/models");
        assert!(request.body.is_empty());
        json_reply(
            200,
            json!({"models": [{
                "name": "jev-latest",
                "description": "General-purpose system one model.",
                "release_date": "2026-09-15",
                "context_window": 128_000
            }]}),
            &[],
        )
    })
    .await;
    let response = client(&mock.base_url, fast_retry(), Duration::from_secs(2))
        .models()
        .list()
        .await
        .expect("models");
    assert_eq!(response.models.len(), 1);
    assert_eq!(response.models[0].name, "jev-latest");
    assert_eq!(response.models[0].release_date, "2026-09-15");
    assert!(std::str::from_utf8(response.raw_body())
        .expect("utf8")
        .contains("context_window"));
}

#[tokio::test]
async fn system_one_into_decodes_a_caller_type() {
    #[derive(Debug, Deserialize)]
    struct ModelOnly {
        model: String,
    }
    let mock = Mock::start(|_| json_reply(200, sample_response(), &[])).await;
    let decoded: ModelOnly = client(&mock.base_url, fast_retry(), Duration::from_secs(2))
        .system_one_into(&JsonContent::text("x"), &question())
        .await
        .expect("into");
    assert_eq!(decoded.model, "jev-latest");
}

#[test]
fn debug_output_does_not_include_the_api_key() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    runtime.block_on(async {
        let mock = Mock::start(|_| json_reply(200, json!({"models": []}), &[])).await;
        let sdk = client(&mock.base_url, fast_retry(), Duration::from_secs(2));
        let rendered = format!("{sdk:?}");
        assert!(!rendered.contains("test-key"));
        assert!(rendered.contains(&mock.base_url));
        let error = sdk
            .system_one(&JsonContent::text("x"), &Questions::new())
            .await
            .expect_err("empty questions");
        assert!(matches!(error, Error::Client(_)));
        assert_eq!(mock.requests().len(), 0);
    });
}
