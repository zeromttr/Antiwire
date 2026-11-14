//! Redirects are checked hop by hop, like the request that started them.

use antiwire_http::{Destinations, HttpClient};
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
    assert!(error.is_redirect(), "{error}");
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
    assert!(error.is_redirect(), "{error}");
}

/// `reqwest` does not follow a redirect to a non-HTTP scheme at all; the
/// redirect itself comes back as the response.
#[tokio::test]
async fn a_redirect_to_another_scheme_is_not_followed() {
    let url = redirect_server(|_| "file:///etc/passwd".to_owned()).await;
    let response = local_client()
        .get(&url)
        .expect("start is allowed")
        .send()
        .await
        .expect("the redirect response");
    assert_eq!(response.status(), reqwest::StatusCode::FOUND);
    assert_eq!(response.url().as_str(), url);
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
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    let second = seen_rx.await.expect("second request").to_ascii_lowercase();
    assert!(second.starts_with("get /next"), "{second}");
    assert!(!second.contains("referer"), "{second}");
}
