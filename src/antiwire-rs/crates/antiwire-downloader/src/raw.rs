use std::path::Path;

use sha2::{Digest, Sha256};
use tokio::io::AsyncReadExt;

use crate::error::{map_stream_io_error, DownloadError};
use crate::response::{limited_body, send};
use crate::writer::AtomicWriter;
use crate::DownloadConfig;

/// Streams `url` to `dest_path`. With `expected_sha256`, the body is hashed as
/// it is written and the file is committed only if it matches; otherwise the
/// staged file is dropped and the existing destination is left untouched.
pub(crate) async fn download_file(
    client: &antiwire_http::HttpClient,
    url: &str,
    dest_path: &Path,
    config: &DownloadConfig,
    expected_sha256: Option<&[u8; 32]>,
) -> Result<(), DownloadError> {
    if let Some(parent) = dest_path.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }

    let request = client
        .get(url)?
        .header(antiwire_http::reqwest::header::ACCEPT_ENCODING, "identity");
    let response = send(request, config).await?;
    let writer = AtomicWriter::new(dest_path.to_path_buf());

    let result = async {
        let mut limited = limited_body(response, config.max_bytes);
        let mut buf = vec![0_u8; 64 * 1024];
        let mut hasher = expected_sha256.map(|_| Sha256::new());

        loop {
            match tokio::time::timeout(config.idle_timeout, limited.read(&mut buf)).await {
                Ok(Ok(0)) => break,
                Ok(Ok(read)) => {
                    if let Some(hasher) = hasher.as_mut() {
                        hasher.update(&buf[..read]);
                    }
                    writer
                        .write(buf[..read].to_vec())
                        .await
                        .map_err(DownloadError::from)?;
                }
                Ok(Err(error)) => {
                    let limit_exceeded = limited.limit_exceeded();
                    return Err(map_stream_io_error(error, limit_exceeded, config.max_bytes));
                }
                Err(_) => return Err(DownloadError::IdleTimeout),
            }
        }

        if let (Some(hasher), Some(expected)) = (hasher, expected_sha256) {
            if hasher.finalize().as_slice() != expected {
                return Err(DownloadError::HashMismatch);
            }
        }
        writer.commit().await.map_err(DownloadError::from)?;
        Ok(())
    }
    .await;

    writer.complete(result).await
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use super::download_file;
    use crate::client::DownloadClient;
    use crate::DownloadConfig;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    async fn drain_http_request(socket: &mut tokio::net::TcpStream) {
        let mut buf = [0_u8; 1024];
        loop {
            let read = socket.read(&mut buf).await.expect("read request chunk");
            if read == 0 || buf[..read].windows(4).any(|window| window == b"\r\n\r\n") {
                break;
            }
        }
    }

    async fn spawn_http_server<F>(handler: F) -> String
    where
        F: Fn() -> Vec<u8> + Send + Sync + 'static,
    {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("local addr");
        tokio::spawn(async move {
            if let Ok((mut socket, _)) = listener.accept().await {
                drain_http_request(&mut socket).await;
                let body = handler();
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = socket.write_all(response.as_bytes()).await;
                let _ = socket.write_all(&body).await;
            }
        });
        format!("http://{addr}/")
    }

    #[tokio::test]
    async fn download_file_writes_raw_bytes() {
        let binary = Arc::new((0..=255_u8).cycle().take(5000).collect::<Vec<u8>>());
        let body = Arc::clone(&binary);
        let url = spawn_http_server(move || (*body).clone()).await;

        let dir = tempfile::tempdir().expect("tempdir");
        let dest = dir.path().join("blob.bin");
        let client = DownloadClient::for_local_tests();
        let config = DownloadConfig {
            max_bytes: 1024 * 1024,
            idle_timeout: Duration::from_secs(5),
        };

        download_file(&client.inner, &url, &dest, &config, None)
            .await
            .expect("download");

        let content = tokio::fs::read(dest).await.expect("read");
        assert_eq!(content, *binary);
    }

    #[tokio::test]
    async fn download_file_aborts_when_size_limit_exceeded() {
        let url = spawn_http_server(|| vec![b'x'; 128]).await;
        let dir = tempfile::tempdir().expect("tempdir");
        let client = DownloadClient::for_local_tests();
        let dest = dir.path().join("big.bin");
        let config = DownloadConfig {
            max_bytes: 16,
            idle_timeout: Duration::from_secs(5),
        };

        let error = download_file(&client.inner, &url, &dest, &config, None)
            .await
            .expect_err("size limit");
        assert!(matches!(error, crate::DownloadError::SizeLimitExceeded(16)));
    }

    #[tokio::test]
    async fn download_file_idle_timeout_fails_on_stall() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("local addr");
        tokio::spawn(async move {
            if let Ok((mut socket, _)) = listener.accept().await {
                drain_http_request(&mut socket).await;
                let partial =
                    "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n5\r\nhello";
                let _ = socket.write_all(partial.as_bytes()).await;
                tokio::time::sleep(Duration::from_millis(300)).await;
            }
        });

        let dir = tempfile::tempdir().expect("tempdir");
        let client = DownloadClient::for_local_tests();
        let url = format!("http://{addr}/");
        let dest = dir.path().join("stall.bin");
        let config = DownloadConfig {
            max_bytes: 1024,
            idle_timeout: Duration::from_millis(100),
        };

        let error = download_file(&client.inner, &url, &dest, &config, None)
            .await
            .expect_err("stall");
        assert!(matches!(error, crate::DownloadError::IdleTimeout));
    }

    #[tokio::test]
    async fn download_file_preserves_underlying_io_error() {
        let url = spawn_http_server(|| vec![b'y'; 128]).await;
        let dir = tempfile::tempdir().expect("tempdir");
        let blocking_file = dir.path().join("not_a_dir");
        tokio::fs::write(&blocking_file, b"obstacle")
            .await
            .expect("write");
        let dest = blocking_file.join("subfile.bin");

        let client = DownloadClient::for_local_tests();
        let config = DownloadConfig {
            max_bytes: 1024,
            idle_timeout: Duration::from_secs(5),
        };

        let error = download_file(&client.inner, &url, &dest, &config, None)
            .await
            .expect_err("should fail with io error");
        match error {
            crate::DownloadError::Io(err) => {
                assert_ne!(
                    err.kind(),
                    std::io::ErrorKind::BrokenPipe,
                    "underlying OS error was masked by BrokenPipe: {err:?}"
                );
            }
            other => panic!("expected DownloadError::Io, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn verified_download_commits_only_a_matching_body() {
        use sha2::{Digest, Sha256};

        let body = b"verified database".to_vec();
        let digest: [u8; 32] = Sha256::digest(&body).into();
        let served = body.clone();
        let url = spawn_http_server(move || served.clone()).await;
        let dir = tempfile::tempdir().expect("tempdir");
        let dest = dir.path().join("db.gz");
        let client = DownloadClient::for_local_tests();
        let config = DownloadConfig {
            max_bytes: 1024,
            idle_timeout: Duration::from_secs(5),
        };

        download_file(&client.inner, &url, &dest, &config, Some(&digest))
            .await
            .expect("matching download");
        assert_eq!(tokio::fs::read(&dest).await.expect("read"), body);
    }

    #[tokio::test]
    async fn verified_download_mismatch_keeps_the_existing_file() {
        let url = spawn_http_server(|| b"tampered".to_vec()).await;
        let dir = tempfile::tempdir().expect("tempdir");
        let dest = dir.path().join("db.gz");
        tokio::fs::write(&dest, b"previous").await.expect("seed");
        let client = DownloadClient::for_local_tests();
        let config = DownloadConfig {
            max_bytes: 1024,
            idle_timeout: Duration::from_secs(5),
        };

        let error = download_file(&client.inner, &url, &dest, &config, Some(&[0_u8; 32]))
            .await
            .expect_err("mismatch");
        assert!(matches!(error, crate::DownloadError::HashMismatch));
        assert_eq!(tokio::fs::read(&dest).await.expect("read"), b"previous");
        let leftovers = std::fs::read_dir(dir.path()).expect("list").count();
        assert_eq!(leftovers, 1, "the staged file must be removed");
    }
}
