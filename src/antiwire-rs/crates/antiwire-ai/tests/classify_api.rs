//! The classifier sends Jev's seven nouls and reads the probabilities back.

use std::sync::{Arc, Mutex};

use antiwire_ai::{AiBackend, DomainUse, Error, RegistrationEvidence, YES_THRESHOLD};
use antiwire_aibackend::TypeSafeClient;
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

#[tokio::test]
async fn classifies_a_domain_with_jev_nouls() {
    let body = Arc::new(Mutex::new(Vec::new()));
    let recorded = Arc::clone(&body);
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let address = listener.local_addr().expect("addr");
    let server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.expect("accept");
        let request = read_http(&mut socket).await.expect("request");
        *recorded.lock().expect("body") = request;
        let response = json!({
            "model": "jev-1.13.0",
            "usage": {"input_tokens": 40, "output_tokens": 7},
            "answers": {
                "advertising": {"type": "noul", "noul": 0.93},
                "tracking": {"type": "noul", "noul": 0.81},
                "telemetry": {"type": "noul", "noul": 0.04},
                "analytics": {"type": "noul", "noul": 0.22},
                "malicious": {"type": "noul", "noul": 0.01},
                "security_fraud": {"type": "noul", "noul": 0.08},
                "cryptomining": {"type": "noul", "noul": 0.02},
                "tunnel": {"type": "noul", "noul": 0.04}
            }
        });
        write_json(&mut socket, &response).await.expect("write");
    });

    let client = TypeSafeClient::builder()
        .api_key("test-key")
        .base_url(format!("http://{address}"))
        .model("not-jev")
        .build()
        .expect("client");
    let assessment = AiBackend::from_client(client)
        .classify_domain("Ads.Example.COM.")
        .await
        .expect("assessment");
    server.await.expect("server");

    assert_eq!(assessment.domain, "ads.example.com");
    assert_eq!(assessment.model, "jev-1.13.0");
    let flagged = assessment
        .above(YES_THRESHOLD)
        .map(|(use_, _)| use_)
        .collect::<Vec<_>>();
    assert_eq!(flagged, vec![DomainUse::Advertising, DomainUse::Tracking]);
    assert!((assessment.score(DomainUse::Malicious) - 0.01).abs() < 1e-9);

    let sent: Value = serde_json::from_slice(&body.lock().expect("body")).expect("json");
    assert_eq!(sent["model"], "jev-latest");
    assert_eq!(sent["state"]["domain"], "ads.example.com");
    for id in [
        "advertising",
        "tracking",
        "telemetry",
        "analytics",
        "malicious",
        "security_fraud",
        "cryptomining",
        "tunnel",
    ] {
        let question = &sent["questions"][id];
        assert_eq!(question["type"], "noul", "{id}");
        assert!(question["instructions"]
            .as_str()
            .is_some_and(|text| text.contains("`domain`")));
        assert!(question["criteria"]["true"].is_string());
        assert!(question["criteria"]["false"].is_string());
    }
}

#[tokio::test]
async fn advanced_check_sends_registration_state_and_twelve_nouls() {
    let body = Arc::new(Mutex::new(Vec::new()));
    let recorded = Arc::clone(&body);
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let address = listener.local_addr().expect("addr");
    let server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.expect("accept");
        let request = read_http(&mut socket).await.expect("request");
        *recorded.lock().expect("body") = request;
        let mut answers = serde_json::Map::new();
        for id in [
            "advertising",
            "tracking",
            "telemetry",
            "analytics",
            "malicious",
            "security_fraud",
            "cryptomining",
            "tunnel",
            "newly_registered",
            "registry_hold",
            "hidden_registrant",
            "abusive_registrar",
        ] {
            answers.insert(id.to_owned(), json!({"type": "noul", "noul": 0.1}));
        }
        write_json(
            &mut socket,
            &json!({"model": "jev-1.13.0", "usage": {}, "answers": answers}),
        )
        .await
        .expect("write");
    });
    let evidence = RegistrationEvidence {
        domain: "Example.COM".to_owned(),
        source: "rdap".to_owned(),
        registrar: Some("Reserved".to_owned()),
        registrar_id: Some("376".to_owned()),
        statuses: vec!["client delete prohibited".to_owned()],
        registered_at: None,
        expires_at: None,
        redacted: true,
        dnssec: Some(true),
    };
    let advanced = AiBackend::from_client(
        TypeSafeClient::builder()
            .api_key("test-key")
            .base_url(format!("http://{address}"))
            .build()
            .expect("client"),
    )
    .classify_domain_advanced(&evidence)
    .await
    .expect("advanced");
    server.await.expect("server");
    assert_eq!(advanced.assessment.domain, "example.com");
    assert!((advanced.hidden_registrant - 0.1).abs() < 1e-9);
    let sent: Value = serde_json::from_slice(&body.lock().expect("body")).expect("json");
    assert_eq!(sent["state"]["registration_age"], "unknown");
    assert_eq!(sent["state"]["redacted"], true);
    assert!(sent["state"].get("registrant_name").is_none());
    assert_eq!(sent["questions"].as_object().expect("questions").len(), 12);
}

#[tokio::test]
async fn missing_noul_is_incomplete_and_urls_are_rejected() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let address = listener.local_addr().expect("addr");
    let server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.expect("accept");
        let _ = read_http(&mut socket).await;
        write_json(
            &mut socket,
            &json!({
                "model": "jev-latest",
                "usage": {},
                "answers": {"advertising": {"type": "noul", "noul": 0.5}}
            }),
        )
        .await
        .expect("write");
    });
    let backend = AiBackend::from_client(
        TypeSafeClient::builder()
            .api_key("test-key")
            .base_url(format!("http://{address}"))
            .build()
            .expect("client"),
    );
    let error = backend
        .classify_domain("https://ads.example")
        .await
        .expect_err("url");
    assert!(matches!(error, Error::InvalidDomain));
    let error = backend
        .classify_domain("ads.example")
        .await
        .expect_err("incomplete");
    assert!(matches!(
        error,
        Error::Incomplete {
            category: "tracking"
        }
    ));
    server.await.expect("server");
}

#[test]
fn saved_key_backend_rejects_blank_keys_and_uses_the_backend_endpoint() {
    let timeout = std::time::Duration::from_secs(1);
    assert!(matches!(
        AiBackend::with_api_key("  ", timeout),
        Err(Error::MissingApiKey)
    ));
    let backend = AiBackend::with_api_key(" saved-key ", timeout).expect("backend");
    assert_eq!(backend.client().base_url(), antiwire_ai::endpoint());
}

async fn read_http(socket: &mut tokio::net::TcpStream) -> std::io::Result<Vec<u8>> {
    let mut buf = Vec::new();
    let mut tmp = [0_u8; 4096];
    let header_end = loop {
        let read = socket.read(&mut tmp).await?;
        if read == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "eof",
            ));
        }
        buf.extend_from_slice(&tmp[..read]);
        if let Some(position) = buf.windows(4).position(|window| window == b"\r\n\r\n") {
            break position;
        }
    };
    let headers = String::from_utf8_lossy(&buf[..header_end]);
    let length = headers
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse::<usize>().ok())
                .flatten()
        })
        .unwrap_or(0);
    let body_at = header_end + 4;
    while buf.len() < body_at + length {
        let read = socket.read(&mut tmp).await?;
        if read == 0 {
            break;
        }
        buf.extend_from_slice(&tmp[..read]);
    }
    Ok(buf
        .get(body_at..body_at + length)
        .unwrap_or_default()
        .to_vec())
}

async fn write_json(socket: &mut tokio::net::TcpStream, body: &Value) -> std::io::Result<()> {
    let payload = serde_json::to_vec(body).expect("json");
    let head = format!(
        "HTTP/1.1 200 OK\r\nconnection: close\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n",
        payload.len()
    );
    socket.write_all(head.as_bytes()).await?;
    socket.write_all(&payload).await?;
    socket.flush().await
}
