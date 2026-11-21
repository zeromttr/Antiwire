//! Redirects are checked hop by hop, like the request that started them.

use antiwire_http::{header, Destinations, HttpClient, HttpError, Method, StatusCode};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Answers every connection with a redirect to `location`.
async fn redirect_server(location: impl Fn(&str) -> String + Send + Sync + 'static) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let address = listener.local_addr().expect("address");
    let base = format!("http://{address}");
    let own = base.clone();
    tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            let mut request = [0_u8; 1024];
            let _ = socket.read(&mut request).await;
            let target = location(&own);
            let response = format!(
                "HTTP/1.1 302 Found\r\nLocation: {target}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            );
            let _ = socket.write_all(response.as_bytes()).await;
        }
    });
    format!("{base}/start")
}

fn local_client() -> HttpClient {
    HttpClient::builder("antiwire-test")
        .destinations(Destinations::PublicPrivateAndLoopback)
        .https_only(false)
        .max_redirects(3)
        .build()
        .expect("client")
}

#[tokio::test]
async fn a_redirect_to_a_metadata_address_is_refused() {
    let url = redirect_server(|_| "http://169.254.169.254/latest/meta-data/".to_owned()).await;
    let error = local_client()
        .get(&url)
        .expect("start is allowed")
        .send()
        .await
        .expect_err("redirect refused");
    assert!(matches!(error, HttpError::Refused { .. }), "{error}");
    assert!(!error.to_string().contains("meta-data"), "{error}");
}

#[tokio::test]
async fn a_redirect_loop_stops_at_the_limit() {
    let url = redirect_server(|own| format!("{own}/again")).await;
    let error = local_client()
        .get(&url)
        .expect("start is allowed")
        .send()
        .await
        .expect_err("too many redirects");
    assert!(matches!(error, HttpError::Refused { .. }), "{error}");
    assert!(
        error.to_string().contains("more than 3 redirects"),
        "{error}"
    );
}

#[tokio::test]
async fn a_redirect_to_another_scheme_is_refused() {
    let url = redirect_server(|_| "file:///etc/passwd".to_owned()).await;
    let error = local_client()
        .get(&url)
        .expect("start is allowed")
        .send()
        .await
        .expect_err("non-http redirect refused");
    assert!(matches!(error, HttpError::Refused { .. }), "{error}");
    assert!(!error.to_string().contains("passwd"), "{error}");
}

/// The redirect target must not learn the URL that sent the client there; it
/// can carry tokens in its query.
#[tokio::test]
async fn a_redirect_does_not_send_a_referer() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let address = listener.local_addr().expect("address");
    let (seen_tx, seen_rx) = tokio::sync::oneshot::channel::<String>();
    tokio::spawn(async move {
        // First request: redirect. Second: record what arrived.
        if let Ok((mut socket, _)) = listener.accept().await {
            let mut request = [0_u8; 2048];
            let _ = socket.read(&mut request).await;
            let response = format!(
                "HTTP/1.1 302 Found\r\nLocation: http://{address}/next\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            );
            let _ = socket.write_all(response.as_bytes()).await;
        }
        if let Ok((mut socket, _)) = listener.accept().await {
            let mut request = [0_u8; 2048];
            let read = socket.read(&mut request).await.unwrap_or(0);
            let _ = seen_tx.send(String::from_utf8_lossy(&request[..read]).into_owned());
            let _ = socket
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                .await;
        }
    });

    let response = local_client()
        .get(&format!("http://{address}/start?token=secret"))
        .expect("allowed")
        .send()
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::OK);
    let second = seen_rx.await.expect("second request").to_ascii_lowercase();
    assert!(second.starts_with("get /next"), "{second}");
    assert!(!second.contains("referer"), "{second}");
}

/// Cross-origin redirects (here distinct loopback ports) strip both default and
/// per-request custom auth headers while keeping safe content-negotiation
/// headers.
#[tokio::test]
async fn cross_origin_redirect_strips_custom_and_default_auth_headers() {
    let target = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind target");
    let target_addr = target.local_addr().expect("target addr");
    let (seen_tx, seen_rx) = tokio::sync::oneshot::channel::<String>();
    tokio::spawn(async move {
        if let Ok((mut socket, _)) = target.accept().await {
            let mut request = [0_u8; 2048];
            let read = socket.read(&mut request).await.unwrap_or(0);
            let _ = seen_tx.send(String::from_utf8_lossy(&request[..read]).into_owned());
            let _ = socket
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                .await;
        }
    });

    let start_url = redirect_server(move |_| format!("http://{target_addr}/landed")).await;

    let mut defaults = header::HeaderMap::new();
    defaults.insert(
        "x-default-token",
        header::HeaderValue::from_static("default-secret"),
    );
    let client = HttpClient::builder("antiwire-test")
        .destinations(Destinations::PublicPrivateAndLoopback)
        .https_only(false)
        .max_redirects(3)
        .default_headers(defaults)
        .build()
        .expect("client");

    let response = client
        .get(&start_url)
        .expect("allowed")
        .header(header::AUTHORIZATION, "Bearer auth-secret")
        .header("x-api-key", "key-secret")
        .header(header::ACCEPT, "application/json")
        .send()
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::OK);

    let landed = seen_rx.await.expect("landed request").to_ascii_lowercase();
    assert!(landed.starts_with("get /landed"), "{landed}");
    assert!(landed.contains("accept: application/json"), "{landed}");
    for leaked in [
        "default-secret",
        "x-default-token",
        "auth-secret",
        "authorization",
        "key-secret",
        "x-api-key",
    ] {
        assert!(!landed.contains(leaked), "{leaked} leaked: {landed}");
    }
}

/// A cross-origin 307 redirect must not replay a POST body to another origin.
#[tokio::test]
async fn cross_origin_307_does_not_replay_request_body() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    let other_port = addr.port().wrapping_add(1).max(1);
    tokio::spawn(async move {
        if let Ok((mut socket, _)) = listener.accept().await {
            let mut request = [0_u8; 1024];
            let _ = socket.read(&mut request).await;
            let response = format!(
                "HTTP/1.1 307 Temporary Redirect\r\nLocation: http://127.0.0.1:{other_port}/steal\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            );
            let _ = socket.write_all(response.as_bytes()).await;
        }
    });

    let url = antiwire_http::Url::parse(&format!("http://{addr}/submit")).expect("url");
    let error = local_client()
        .request(Method::POST, url)
        .expect("allowed")
        .body("sensitive-payload")
        .send()
        .await
        .expect_err("cross-origin 307 with body must be refused");
    assert!(matches!(error, HttpError::Refused { .. }), "{error}");
}

/// Transport errors strip credentials, path tokens, and query secrets from both
/// Display and Debug output.
#[tokio::test]
async fn transport_errors_redact_url_secrets() {
    // Bind and immediately drop a port so connecting fails deterministically.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    drop(listener);

    let url = format!("http://user:hunter2@{addr}/services/T1/B2/PATHSECRET?token=QUERYSECRET");
    let error = local_client()
        .get(&url)
        .expect("allowed")
        .send()
        .await
        .expect_err("connection refused");
    let formatted = format!("{error} / {error:?}");
    for secret in ["user", "hunter2", "PATHSECRET", "QUERYSECRET"] {
        assert!(!formatted.contains(secret), "{secret} leaked: {formatted}");
    }
}
