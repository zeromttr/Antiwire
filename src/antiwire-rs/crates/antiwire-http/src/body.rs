//! Reading response bodies without trusting the server about their size.

use bytes::Bytes;

use crate::client::HttpResponse;
use crate::error::HttpError;

/// Reads the whole body of `response`, refusing more than `limit` bytes.
///
/// A declared `Content-Length` over the limit is refused before anything is
/// read, and an undeclared or understated length is cut off as soon as the
/// limit is passed, so a hostile or broken server cannot make the caller
/// buffer an unbounded body.
///
/// # Errors
///
/// Returns [`HttpError::BodyTooLarge`] past the limit, or [`HttpError::Request`]
/// when reading fails.
pub async fn read_limited(response: HttpResponse, limit: u64) -> Result<Bytes, HttpError> {
    read_limited_vec(response, limit).await.map(Bytes::from)
}

/// Reads the body of `response` as text, refusing more than `limit` bytes.
///
/// Invalid UTF-8 is replaced with U+FFFD rather than rejected, as `reqwest`'s
/// own `text()` does for a UTF-8 body. Valid UTF-8 reuses the buffer without
/// copying; invalid UTF-8 replacement is also bounded by `limit` so adversarial
/// binary input cannot expand past the cap.
///
/// # Errors
///
/// As [`read_limited`].
pub async fn read_text_limited(response: HttpResponse, limit: u64) -> Result<String, HttpError> {
    let body = read_limited_vec(response, limit).await?;
    decode_utf8_lossy_limited(body, limit)
}

async fn read_limited_vec(mut response: HttpResponse, limit: u64) -> Result<Vec<u8>, HttpError> {
    if response
        .content_length()
        .is_some_and(|length| length > limit)
    {
        return Err(HttpError::BodyTooLarge { limit });
    }
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        let total = u64::try_from(body.len().saturating_add(chunk.len())).unwrap_or(u64::MAX);
        if total > limit {
            return Err(HttpError::BodyTooLarge { limit });
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

fn decode_utf8_lossy_limited(raw: Vec<u8>, limit: u64) -> Result<String, HttpError> {
    match String::from_utf8(raw) {
        Ok(text) => Ok(text),
        Err(error) => {
            let bytes = error.into_bytes();
            let mut out = String::new();
            for chunk in bytes.utf8_chunks() {
                let valid = chunk.valid();
                let replacement = if chunk.invalid().is_empty() {
                    0
                } else {
                    '\u{FFFD}'.len_utf8()
                };
                let next_len = out
                    .len()
                    .saturating_add(valid.len())
                    .saturating_add(replacement);
                if u64::try_from(next_len).unwrap_or(u64::MAX) > limit {
                    return Err(HttpError::BodyTooLarge { limit });
                }
                out.push_str(valid);
                if !chunk.invalid().is_empty() {
                    out.push('\u{FFFD}');
                }
            }
            Ok(out)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Destinations, HttpClient};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// Serves one response; `declared` is the Content-Length sent, if any.
    async fn serve(body: Vec<u8>, declared: Option<usize>) -> String {
        serve_with(body, declared, "").await
    }

    /// As [`serve`], with extra header lines, each ending in CRLF.
    async fn serve_with(body: Vec<u8>, declared: Option<usize>, extra: &'static str) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let address = listener.local_addr().expect("address");
        tokio::spawn(async move {
            if let Ok((mut socket, _)) = listener.accept().await {
                let mut request = [0_u8; 1024];
                let _ = socket.read(&mut request).await;
                let length = declared.map_or_else(String::new, |length| {
                    format!("Content-Length: {length}\r\n")
                });
                let head = format!("HTTP/1.1 200 OK\r\n{length}{extra}Connection: close\r\n\r\n");
                let _ = socket.write_all(head.as_bytes()).await;
                let _ = socket.write_all(&body).await;
            }
        });
        format!("http://{address}/")
    }

    fn local_client() -> HttpClient {
        HttpClient::builder("antiwire-test")
            .destinations(Destinations::PublicPrivateAndLoopback)
            .https_only(false)
            .build()
            .expect("client")
    }

    async fn fetch(url: &str) -> HttpResponse {
        local_client()
            .get(url)
            .expect("allowed")
            .send()
            .await
            .expect("response")
    }

    #[test]
    fn lossy_utf8_decoding_bounds_replacement_expansion() {
        assert_eq!(
            decode_utf8_lossy_limited(b"hello".to_vec(), 5).expect("valid"),
            "hello"
        );
        assert_eq!(
            decode_utf8_lossy_limited(b"hi\xff".to_vec(), 5).expect("fits"),
            "hi\u{FFFD}"
        );
        let error = decode_utf8_lossy_limited(vec![0xff; 10], 10)
            .expect_err("30-byte replacement exceeds 10-byte limit");
        assert!(matches!(error, HttpError::BodyTooLarge { limit: 10 }));
    }

    #[tokio::test]
    async fn reads_a_body_within_the_limit() {
        let url = serve(b"hello".to_vec(), Some(5)).await;
        let text = read_text_limited(fetch(&url).await, 5).await.expect("body");
        assert_eq!(text, "hello");
    }

    #[tokio::test]
    async fn refuses_a_declared_length_over_the_limit() {
        let url = serve(vec![b'x'; 64], Some(64)).await;
        let error = read_limited(fetch(&url).await, 16)
            .await
            .expect_err("too large");
        assert!(
            matches!(error, HttpError::BodyTooLarge { limit: 16 }),
            "{error}"
        );
    }

    #[tokio::test]
    async fn cuts_off_an_undeclared_body_over_the_limit() {
        let url = serve(vec![b'x'; 4096], None).await;
        let error = read_limited(fetch(&url).await, 1024)
            .await
            .expect_err("too large");
        assert!(
            matches!(error, HttpError::BodyTooLarge { limit: 1024 }),
            "{error}"
        );
    }

    /// A compressed body is counted after decompression, so a small gzip bomb
    /// cannot expand past the limit.
    #[tokio::test]
    async fn a_compressed_body_is_limited_after_decompression() {
        use std::io::Write as _;

        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::best());
        encoder
            .write_all(&vec![0_u8; 4 * 1024 * 1024])
            .expect("compress");
        let compressed = encoder.finish().expect("finish");
        assert!(compressed.len() < 64 * 1024, "{}", compressed.len());

        let length = compressed.len();
        let url = serve_with(compressed, Some(length), "Content-Encoding: gzip\r\n").await;
        let error = read_limited(fetch(&url).await, 64 * 1024)
            .await
            .expect_err("too large once decompressed");
        assert!(matches!(error, HttpError::BodyTooLarge { .. }), "{error}");
    }

    /// A loopback test server is reachable only when the policy allows it.
    #[tokio::test]
    async fn the_default_policy_cannot_reach_a_local_server() {
        let url = serve(b"secret".to_vec(), Some(6)).await;
        let client = HttpClient::builder("antiwire-test")
            .https_only(false)
            .build()
            .expect("client");
        assert!(client.get(&url).is_err());

        let by_name = url.replace("127.0.0.1", "localhost");
        let error = client
            .get(&by_name)
            .expect_err("localhost is refused before anything is sent");
        assert!(matches!(error, HttpError::Refused { .. }), "{error}");
    }
}
